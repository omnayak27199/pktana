#include "pktana/tracer/capture.hpp"
#include "pktana/tracer/util.hpp"
#include "pktana/tracer/version.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

void print_usage() {
    std::cout
        << "pktana-tracer — cross-platform packet tracer (macOS / Windows)\n\n"
        << "Usage:\n"
        << "  pktana-tracer list\n"
        << "  pktana-tracer capture <interface> [--count N] [--filter EXPR] [--verbose]\n"
        << "  pktana-tracer decode <hex-bytes>\n"
        << "  pktana-tracer version\n\n"
        << "Examples:\n"
        << "  pktana-tracer list\n"
        << "  pktana-tracer capture en0 --count 20 --filter \"tcp port 443\"\n"
        << "  pktana-tracer capture \"\\Device\\NPF_{GUID}\" --verbose\n";
}

bool flag_present(const std::vector<std::string>& args, const std::string& name) {
    for (const auto& arg : args) {
        if (arg == name) {
            return true;
        }
    }
    return false;
}

std::string flag_value(const std::vector<std::string>& args, const std::string& name) {
    for (std::size_t i = 0; i + 1 < args.size(); ++i) {
        if (args[i] == name) {
            return args[i + 1];
        }
    }
    return "";
}

int cmd_list() {
    const auto interfaces = pktana::tracer::CaptureSession::list_interfaces();
    if (interfaces.empty()) {
        std::cout << "No capture interfaces found.\n";
        return 0;
    }

    std::cout << "Available interfaces:\n";
    for (const auto& iface : interfaces) {
        std::cout << "  " << iface.name;
        if (!iface.description.empty()) {
            std::cout << "  (" << iface.description << ")";
        }
        if (!iface.addresses.empty()) {
            std::cout << "  [" << iface.addresses << "]";
        }
        std::cout << '\n';
    }
    return 0;
}

int cmd_capture(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        print_usage();
        return 1;
    }

    const std::string device = args[1];
    const std::string filter = flag_value(args, "--filter");
    const std::string count_text = flag_value(args, "--count");
    const bool verbose = flag_present(args, "--verbose");

    std::size_t count = 0;
    if (!count_text.empty()) {
        count = static_cast<std::size_t>(std::stoul(count_text));
    }

    pktana::tracer::CaptureSession session;
    session.open(device, filter);
    std::cout << "Capturing on " << device;
    if (!filter.empty()) {
        std::cout << " filter=\"" << filter << "\"";
    }
    std::cout << "...\n";

    session.run(count, verbose);
    return 0;
}

int parse_hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

int cmd_decode(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        print_usage();
        return 1;
    }

    std::vector<std::uint8_t> bytes;
    const std::string hex = pktana::tracer::trim_copy(args[1]);
    for (std::size_t i = 0; i < hex.size();) {
        while (i < hex.size() && hex[i] == ' ') {
            ++i;
        }
        if (i >= hex.size()) {
            break;
        }

        if (i + 1 >= hex.size()) {
            std::cerr << "Invalid hex input\n";
            return 1;
        }

        const int high = parse_hex_nibble(hex[i]);
        const int low = parse_hex_nibble(hex[i + 1]);
        if (high < 0 || low < 0) {
            std::cerr << "Invalid hex input\n";
            return 1;
        }

        bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
        i += 2;
    }

    const auto summary = pktana::tracer::decode_packet(bytes.data(), bytes.size());
    std::cout << summary.one_line << '\n';
    return 0;
}

int cmd_version() {
    std::cout << "pktana-tracer " << PKTANA_TRACER_VERSION << '\n';
    std::cout << "version: "
              << PKTANA_TRACER_VERSION_MAJOR << "."
              << PKTANA_TRACER_VERSION_MINOR << "."
              << PKTANA_TRACER_VERSION_PATCH << '\n';
#if defined(PKTANA_TRACER_PLATFORM_MACOS)
    std::cout << "platform: macOS\n";
#elif defined(PKTANA_TRACER_PLATFORM_WINDOWS)
    std::cout << "platform: Windows\n";
#else
    std::cout << "platform: other\n";
#endif
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    std::vector<std::string> args;
    args.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    if (args.size() < 2) {
        print_usage();
        return 1;
    }

    const std::string command = args[1];
    try {
        if (command == "list") {
            return cmd_list();
        }
        if (command == "capture") {
            return cmd_capture(args);
        }
        if (command == "decode") {
            return cmd_decode(args);
        }
        if (command == "version" || command == "--version" || command == "-V") {
            return cmd_version();
        }

        std::cerr << "Unknown command: " << command << '\n';
        print_usage();
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << '\n';
        return 1;
    }
}
