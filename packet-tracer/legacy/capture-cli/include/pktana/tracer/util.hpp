#pragma once

#include <cstdint>
#include <string>

namespace pktana::tracer {

std::string format_mac(const std::uint8_t* bytes);
std::string format_ipv4(const std::uint8_t* bytes);
std::string protocol_name(std::uint8_t protocol);
std::string ether_type_name(std::uint16_t ether_type);
std::string format_bytes(std::uint64_t bytes);
std::string trim_copy(const std::string& value);

}  // namespace pktana::tracer
