#include "pktana/tracer/capture.hpp"

#include "pktana/tracer/util.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#if __has_include(<pcap/pcap.h>)
#include <pcap/pcap.h>
#else
#include <pcap.h>
#endif

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace pktana::tracer {

namespace {

#if defined(_WIN32)
struct WinsockGuard {
    WinsockGuard() {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
    }

    ~WinsockGuard() {
        WSACleanup();
    }
};
#endif

#if defined(_WIN32)
using inet_ntop_fn = const char* (*)(int, const void*, char*, socklen_t);
constexpr inet_ntop_fn k_inet_ntop = pcap_inet_ntop;
#else
constexpr auto k_inet_ntop = inet_ntop;
#endif

}  // namespace

CaptureSession::~CaptureSession() {
    if (handle_ != nullptr) {
        pcap_close(static_cast<pcap_t*>(handle_));
        handle_ = nullptr;
    }
}

std::vector<NetworkInterface> CaptureSession::list_interfaces() {
#if defined(_WIN32)
    WinsockGuard winsock;
#endif
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* all = nullptr;

    if (pcap_findalldevs(&all, errbuf) == -1) {
        throw std::runtime_error(std::string("pcap_findalldevs failed: ") + errbuf);
    }

    std::vector<NetworkInterface> interfaces;
    for (pcap_if_t* device = all; device != nullptr; device = device->next) {
        NetworkInterface entry;
        entry.name = device->name != nullptr ? device->name : "";
        entry.description = device->description != nullptr ? device->description : "";

        std::ostringstream addresses;
        for (pcap_addr_t* addr = device->addresses; addr != nullptr; addr = addr->next) {
            if (addr->addr == nullptr) {
                continue;
            }

            char host[PCAP_ERRBUF_SIZE]{};
            if (addr->addr->sa_family == AF_INET) {
                auto* sin = reinterpret_cast<sockaddr_in*>(addr->addr);
                if (k_inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host)) != nullptr) {
                    if (!addresses.str().empty()) {
                        addresses << ", ";
                    }
                    addresses << host;
                }
            }
        }
        entry.addresses = addresses.str();
        interfaces.push_back(std::move(entry));
    }

    pcap_freealldevs(all);
    return interfaces;
}

void CaptureSession::open(const std::string& device, const std::string& filter) {
#if defined(_WIN32)
    WinsockGuard winsock;
#endif
    char errbuf[PCAP_ERRBUF_SIZE]{};
    auto* handle = pcap_open_live(device.c_str(), 65535, 1, 1000, errbuf);
    if (handle == nullptr) {
        throw std::runtime_error(std::string("pcap_open_live failed: ") + errbuf);
    }

    if (!filter.empty()) {
        bpf_u_int32 net = 0;
        bpf_u_int32 mask = 0;
        if (pcap_lookupnet(device.c_str(), &net, &mask, errbuf) == -1) {
            net = 0;
            mask = 0;
        }

        struct bpf_program program {};
        if (pcap_compile(handle, &program, filter.c_str(), 1, mask) == -1) {
            pcap_close(handle);
            throw std::runtime_error(
                std::string("pcap_compile failed: ") + pcap_geterr(handle));
        }

        if (pcap_setfilter(handle, &program) == -1) {
            pcap_freecode(&program);
            pcap_close(handle);
            throw std::runtime_error(
                std::string("pcap_setfilter failed: ") + pcap_geterr(handle));
        }
        pcap_freecode(&program);
    }

    handle_ = handle;
}

void CaptureSession::run(std::size_t count, bool verbose) {
    if (handle_ == nullptr) {
        throw std::runtime_error("capture session is not open");
    }

    auto* handle = static_cast<pcap_t*>(handle_);
    const auto link_type = pcap_datalink(handle);

    std::size_t captured = 0;
    while (count == 0 || captured < count) {
        pcap_pkthdr* header = nullptr;
        const u_char* packet = nullptr;
        const int result = pcap_next_ex(handle, &header, &packet);
        if (result == 0) {
            continue;
        }
        if (result == -1) {
            throw std::runtime_error(std::string("pcap_next_ex failed: ") + pcap_geterr(handle));
        }
        if (result == -2) {
            break;
        }

        ++captured;
        const auto timestamp = header->ts;
        const auto packet_len = static_cast<std::size_t>(header->caplen);

        PacketSummary summary;
        if (link_type == DLT_EN10MB && packet_len >= 14) {
            summary = decode_packet(packet, packet_len);
        } else {
            summary.length = packet_len;
            summary.one_line = "non-Ethernet frame (link type " + std::to_string(link_type) + ")";
        }

        std::cout << "#" << captured << " "
                  << timestamp.tv_sec << "." << timestamp.tv_usec << " "
                  << summary.length << "B "
                  << summary.one_line;

        if (verbose && summary.ipv4.has_value()) {
            const auto& ip = summary.ipv4.value();
            std::cout << " ttl=" << static_cast<int>(ip.ttl)
                      << " id=" << ip.identification;
        }
        std::cout << '\n';
    }
}

PacketSummary decode_packet(const std::uint8_t* data, std::size_t length) {
    PacketSummary summary;
    summary.length = length;

    if (length < 14) {
        summary.one_line = "truncated Ethernet frame";
        return summary;
    }

    EthernetHeader eth;
    eth.destination_mac = format_mac(data);
    eth.source_mac = format_mac(data + 6);
    eth.ether_type = static_cast<std::uint16_t>((data[12] << 8) | data[13]);
    eth.ether_type_name = ether_type_name(eth.ether_type);
    summary.ethernet = eth;

    std::size_t offset = 14;
    if (eth.ether_type == 0x8100 && length >= offset + 4) {
        eth.ether_type = static_cast<std::uint16_t>((data[offset + 2] << 8) | data[offset + 3]);
        eth.ether_type_name = ether_type_name(eth.ether_type);
        offset += 4;
    }

    std::ostringstream line;
    line << eth.source_mac << " > " << eth.destination_mac << " "
         << eth.ether_type_name;

    if (eth.ether_type == 0x0800 && length >= offset + 20) {
        const auto* ip = data + offset;
        Ipv4Header ipv4;
        ipv4.version = static_cast<std::uint8_t>((ip[0] >> 4) & 0x0F);
        ipv4.ihl = static_cast<std::uint8_t>(ip[0] & 0x0F);
        ipv4.dscp = static_cast<std::uint8_t>(ip[1] >> 2);
        ipv4.total_length = static_cast<std::uint16_t>((ip[2] << 8) | ip[3]);
        ipv4.identification = static_cast<std::uint16_t>((ip[4] << 8) | ip[5]);
        ipv4.ttl = ip[8];
        ipv4.protocol = ip[9];
        ipv4.protocol_name = protocol_name(ipv4.protocol);
        ipv4.source = format_ipv4(ip + 12);
        ipv4.destination = format_ipv4(ip + 16);
        summary.ipv4 = ipv4;

        line << " " << ipv4.source << " > " << ipv4.destination
             << " proto=" << ipv4.protocol_name;

        const std::size_t ip_header_len = static_cast<std::size_t>(ipv4.ihl) * 4;
        const std::size_t transport_offset = offset + ip_header_len;
        if (length >= transport_offset + 4) {
            TransportHeader transport;
            transport.source_port = static_cast<std::uint16_t>(
                (data[transport_offset] << 8) | data[transport_offset + 1]);
            transport.destination_port = static_cast<std::uint16_t>(
                (data[transport_offset + 2] << 8) | data[transport_offset + 3]);

            if (ipv4.protocol == 6) {
                transport.protocol = "TCP";
                line << " " << transport.source_port << " > " << transport.destination_port
                     << " [TCP]";
            } else if (ipv4.protocol == 17) {
                transport.protocol = "UDP";
                line << " " << transport.source_port << " > " << transport.destination_port
                     << " [UDP]";
            } else if (ipv4.protocol == 1) {
                transport.protocol = "ICMP";
                line << " [ICMP]";
            }
            summary.transport = transport;
        }
    } else if (eth.ether_type == 0x0806) {
        line << " [ARP]";
    }

    summary.one_line = line.str();
    return summary;
}

}  // namespace pktana::tracer
