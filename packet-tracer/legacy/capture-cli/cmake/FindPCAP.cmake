# Find libpcap (macOS) or Npcap/WinPcap SDK (Windows).
#
# Environment variables:
#   NPCAP_ROOT  - path to Npcap SDK on Windows (contains Lib/ and Include/)
#
# vcpkg users can install libpcap and rely on CMAKE_PREFIX_PATH.

find_path(PCAP_INCLUDE_DIR
    NAMES pcap/pcap.h pcap.h
    HINTS
        "$ENV{NPCAP_ROOT}/Include"
        "$ENV{NPCAP_ROOT}/include"
        /opt/homebrew/opt/libpcap/include
        /usr/local/opt/libpcap/include
)

find_library(PCAP_LIBRARY
    NAMES pcap wpcap
    HINTS
        "$ENV{NPCAP_ROOT}/Lib/x64"
        "$ENV{NPCAP_ROOT}/Lib"
        "$ENV{NPCAP_ROOT}/lib"
        /opt/homebrew/opt/libpcap/lib
        /usr/local/opt/libpcap/lib
)

if(WIN32)
    find_library(PCAP_PACKET_LIBRARY
        NAMES Packet
        HINTS
            "$ENV{NPCAP_ROOT}/Lib/x64"
            "$ENV{NPCAP_ROOT}/Lib"
    )
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    PCAP
    DEFAULT_MSG
    PCAP_LIBRARY PCAP_INCLUDE_DIR
)

if(PCAP_FOUND AND NOT TARGET PCAP::PCAP)
    add_library(PCAP::PCAP UNKNOWN IMPORTED)
    set_target_properties(PCAP::PCAP PROPERTIES
        IMPORTED_LOCATION "${PCAP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
    )
    if(WIN32 AND PCAP_PACKET_LIBRARY)
        set_property(
            TARGET PCAP::PCAP
            APPEND PROPERTY
            IMPORTED_LINK_INTERFACE_LIBRARIES "${PCAP_PACKET_LIBRARY}"
        )
    endif()
endif()

mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY PCAP_PACKET_LIBRARY)
