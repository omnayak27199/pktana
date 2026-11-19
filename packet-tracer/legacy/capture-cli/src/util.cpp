#include "pktana/tracer/util.hpp"

#include <iomanip>
#include <sstream>

namespace pktana::tracer {

std::string format_mac(const std::uint8_t* bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) {
            out << ':';
        }
        out << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return out.str();
}

std::string format_ipv4(const std::uint8_t* bytes) {
    std::ostringstream out;
    out << static_cast<int>(bytes[0]) << '.'
        << static_cast<int>(bytes[1]) << '.'
        << static_cast<int>(bytes[2]) << '.'
        << static_cast<int>(bytes[3]);
    return out.str();
}

std::string protocol_name(std::uint8_t protocol) {
    switch (protocol) {
        case 1:
            return "ICMP";
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        case 41:
            return "IPv6";
        case 47:
            return "GRE";
        case 50:
            return "ESP";
        case 51:
            return "AH";
        default:
            return "IP/" + std::to_string(protocol);
    }
}

std::string ether_type_name(std::uint16_t ether_type) {
    switch (ether_type) {
        case 0x0800:
            return "IPv4";
        case 0x0806:
            return "ARP";
        case 0x86DD:
            return "IPv6";
        case 0x8100:
            return "VLAN";
        default: {
            std::ostringstream out;
            out << "0x" << std::hex << std::setw(4) << std::setfill('0') << ether_type;
            return out.str();
        }
    }
}

std::string format_bytes(std::uint64_t bytes) {
    if (bytes >= 1'000'000'000ULL) {
        std::ostringstream out;
        out << std::fixed << std::setprecision(2)
            << (static_cast<double>(bytes) / 1'000'000'000.0) << " GB";
        return out.str();
    }
    if (bytes >= 1'000'000ULL) {
        std::ostringstream out;
        out << std::fixed << std::setprecision(2)
            << (static_cast<double>(bytes) / 1'000'000.0) << " MB";
        return out.str();
    }
    if (bytes >= 1'000ULL) {
        std::ostringstream out;
        out << std::fixed << std::setprecision(2)
            << (static_cast<double>(bytes) / 1'000.0) << " KB";
        return out.str();
    }
    return std::to_string(bytes) + " B";
}

std::string trim_copy(const std::string& value) {
    const auto start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

}  // namespace pktana::tracer
