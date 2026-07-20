#!/bin/bash
# pktana automatic installation script
set -euo pipefail

PKTANA_VERSION="v0.6.0"

if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    OS=${ID:-}
    OS_VERSION_ID=${VERSION_ID:-}
else
    echo "Cannot detect OS. Exiting."
    exit 1
fi

echo "🔍 pktana installer"
echo "----------------------------------------"
echo "Release: ${PKTANA_VERSION}"

if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    echo "Detected $OS. Installing dependencies and building from source..."

    sudo apt-get update
    sudo apt-get install -y libpcap-dev curl git gcc

    if ! command -v cargo &> /dev/null; then
        echo "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # shellcheck source=/dev/null
        source "$HOME/.cargo/env" || true
    fi

    BUILD_DIR=$(mktemp -d)
    cd "$BUILD_DIR"
    echo "Cloning repository..."
    git clone --depth 1 --branch "${PKTANA_VERSION}" https://github.com/omnayak27199/pktana.git
    cd pktana

    echo "Compiling pktana..."
    cargo build --release --features pcap,tui,ai

    sudo cp target/release/pktana /usr/local/bin/
    echo "✅ Successfully installed pktana to /usr/local/bin/pktana"
    echo ""
    echo "========================================="
    echo "Start the web UI:    pktana web 8080"
    echo "Install AI analysis: pktana ai install"
    echo "Check AI status:     pktana ai st"
    echo "========================================="

elif [[ "$OS" == "centos" || "$OS" == "rhel" || "$OS" == "rocky" || "$OS" == "almalinux" ]]; then
    echo "Detected $OS ${OS_VERSION_ID}. Installing RPM..."

    # Pick el7 vs el9 RPM from major version (e.g. 7.x → el7, 8/9 → el9).
    MAJOR="${OS_VERSION_ID%%.*}"
    if [[ "$MAJOR" == "7" ]]; then
        EL_TAG="el7"
    else
        EL_TAG="el9"
    fi

    RPM_NAME="pktana-${PKTANA_VERSION#v}-1.${EL_TAG}.x86_64.rpm"
    RPM_URL="https://github.com/omnayak27199/pktana/releases/download/${PKTANA_VERSION}/${RPM_NAME}"

    echo "Downloading: ${RPM_URL}"
    TMP_RPM="$(mktemp --suffix=.rpm)"
    # Avoid dnf URL quirks with spaces/special chars; download then install locally.
    curl -fL --retry 3 --retry-delay 2 -o "$TMP_RPM" "$RPM_URL"
    if command -v dnf &> /dev/null; then
        sudo dnf install -y "$TMP_RPM"
    else
        sudo yum install -y "$TMP_RPM"
    fi
    rm -f "$TMP_RPM"
    echo "✅ Successfully installed pktana!"
else
    echo "Unsupported OS: $OS"
    echo "Please build manually from source."
    exit 1
fi
