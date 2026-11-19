#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace pktana::tracer {

struct EthernetHeader {
    std::string destination_mac;
    std::string source_mac;
    std::uint16_t ether_type = 0;
    std::string ether_type_name;
};

struct Ipv4Header {
    std::uint8_t version = 0;
    std::uint8_t ihl = 0;
    std::uint8_t dscp = 0;
    std::uint16_t total_length = 0;
    std::uint16_t identification = 0;
    std::uint8_t ttl = 0;
    std::uint8_t protocol = 0;
    std::string protocol_name;
    std::string source;
    std::string destination;
};

struct TransportHeader {
    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;
    std::string protocol;
};

struct PacketSummary {
    std::size_t length = 0;
    std::optional<EthernetHeader> ethernet;
    std::optional<Ipv4Header> ipv4;
    std::optional<TransportHeader> transport;
    std::string one_line;
};

struct NetworkInterface {
    std::string name;
    std::string description;
    std::string addresses;
};

class CaptureSession {
public:
    CaptureSession() = default;
    ~CaptureSession();

    CaptureSession(const CaptureSession&) = delete;
    CaptureSession& operator=(const CaptureSession&) = delete;

    static std::vector<NetworkInterface> list_interfaces();

    void open(const std::string& device, const std::string& filter = "");
    void run(std::size_t count, bool verbose);

private:
    void* handle_ = nullptr;
};

PacketSummary decode_packet(const std::uint8_t* data, std::size_t length);

}  // namespace pktana::tracer
