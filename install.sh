#!/bin/bash
# pktana automatic installation script
set -e

VERSION="v0.3.1"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS. Exiting."
    exit 1
fi

echo "🔍 pktana installer"
echo "----------------------------------------"

if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    echo "Detected $OS. Installing dependencies and building from source..."
    
    sudo apt-get update
    sudo apt-get install -y libpcap-dev curl git gcc
    
    if ! command -v cargo &> /dev/null; then
        echo "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    fi
    source "$HOME/.cargo/env" || true
    
    BUILD_DIR=$(mktemp -d)
    cd "$BUILD_DIR"
    echo "Cloning repository..."
    git clone https://github.com/omnayak27199/pktana.git
    cd pktana
    
    echo "Compiling pktana..."
    cargo build --release --features pcap,tui
    
    sudo cp target/release/pktana /usr/local/bin/
    echo "✅ Successfully installed pktana to /usr/local/bin/pktana"

elif [[ "$OS" == "centos" || "$OS" == "rhel" || "$OS" == "rocky" || "$OS" == "almalinux" ]]; then
    echo "Detected $OS. Installing RPM..."
    RPM_URL="https://github.com/omnayak27199/pktana/releases/download/${VERSION}/pktana-${VERSION#v}-1.el9.x86_64.rpm"
    sudo dnf install -y "$RPM_URL"
    echo "✅ Successfully installed pktana!"
else
    echo "Unsupported OS: $OS"
    echo "Please build manually from source."
    exit 1
fi