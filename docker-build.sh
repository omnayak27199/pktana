#!/bin/bash
# pktana Docker build environment script
set -e

if [ -z "$1" ]; then
    echo "Usage: ./docker-build.sh <command|os>"
    echo ""
    echo "Commands:"
    echo "  ls, list, show     Show active/saved sessions"
    echo "  kill <os>          Kill and remove a session (or 'all')"
    echo ""
    echo "OS Options (creates or attaches to a session):"
    echo "  el9                (RHEL/Rocky/Alma 9 - builds RPM)"
    echo "  el7                (RHEL/CentOS 7 - builds RPM)"
    echo "  ubuntu22           (Ubuntu 22.04 - builds binary)"
    echo "  ubuntu24           (Ubuntu 24.04 - builds binary)"
    echo "  debian12           (Debian 12 - builds binary)"
    exit 1
fi

COMMAND="$1"

if [ "$COMMAND" = "ls" ] || [ "$COMMAND" = "list" ] || [ "$COMMAND" = "show" ]; then
    echo "📦 pktana build sessions:"
    docker ps -a --filter "name=pktana-build-" --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
    exit 0
fi

if [ "$COMMAND" = "kill" ] || [ "$COMMAND" = "rm" ]; then
    TARGET="$2"
    if [ -z "$TARGET" ]; then
        echo "Usage: ./docker-build.sh kill <os|all>"
        exit 1
    fi
    if [ "$TARGET" = "all" ]; then
        IDS=$(docker ps -a -q --filter "name=pktana-build-")
        if [ -n "$IDS" ]; then
            docker rm -f $IDS >/dev/null
            echo "✅ All sessions killed."
        else
            echo "No sessions found."
        fi
    else
        docker rm -f "pktana-build-$TARGET" >/dev/null 2>&1 || echo "Session pktana-build-$TARGET not found."
        echo "✅ Session $TARGET killed."
    fi
    exit 0
fi

OS="$1"
CONTAINER_NAME="pktana-build-$OS"

case "$OS" in
    rocky9|el9)
        IMAGE="rockylinux:9"
        INSTALL_DEPS="dnf install -y epel-release dnf-plugins-core && dnf config-manager --set-enabled crb && dnf install -y --allowerasing gcc libpcap-devel openssl-devel pkgconf-pkg-config perl-core rpm-build make git curl"
        BUILD_CMD="make pktana OS_TYPE=el9"
        ;;
    centos7|el7)
        IMAGE="centos:7"
        INSTALL_DEPS="sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-* && sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-* && yum install -y gcc libpcap-devel openssl-devel pkgconfig perl-IPC-Cmd perl-Data-Dumper rpm-build make git curl"
        BUILD_CMD="make pktana OS_TYPE=el7"
        ;;
    ubuntu22)
        IMAGE="ubuntu:22.04"
        INSTALL_DEPS="apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y gcc libpcap-dev libssl-dev pkg-config make git curl dpkg-dev fakeroot ca-certificates build-essential"
        BUILD_CMD="cargo build --release --features pcap,tui && cargo install cargo-deb --locked && cd crates/pktana-cli && cargo deb --no-build --no-strip --output ../../dist/pktana_${VERSION:-0.6.0}_amd64_${OS}.04.deb && cd ../.. && mkdir -p dist && tar -czf dist/pktana-${VERSION:-0.6.0}-${OS}.04-x86_64.tar.gz -C target/release pktana && ls -la dist/"
        ;;
    ubuntu24)
        IMAGE="ubuntu:24.04"
        INSTALL_DEPS="apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y gcc libpcap-dev libssl-dev pkg-config make git curl dpkg-dev fakeroot ca-certificates build-essential"
        BUILD_CMD="cargo build --release --features pcap,tui && cargo install cargo-deb --locked && cd crates/pktana-cli && cargo deb --no-build --no-strip --output ../../dist/pktana_${VERSION:-0.6.0}_amd64_${OS}.04.deb && cd ../.. && mkdir -p dist && tar -czf dist/pktana-${VERSION:-0.6.0}-${OS}.04-x86_64.tar.gz -C target/release pktana && ls -la dist/"
        ;;
    debian12)
        IMAGE="debian:12"
        INSTALL_DEPS="apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y gcc libpcap-dev libssl-dev pkg-config make git curl dpkg-dev fakeroot ca-certificates build-essential"
        BUILD_CMD="cargo build --release --features pcap,tui && cargo install cargo-deb --locked && cd crates/pktana-cli && cargo deb --no-build --no-strip --output ../../dist/pktana_${VERSION:-0.6.0}_amd64_${OS}.deb && cd ../.. && mkdir -p dist && tar -czf dist/pktana-${VERSION:-0.6.0}-${OS}-x86_64.tar.gz -C target/release pktana && ls -la dist/"
        ;;
    *)
        echo "Unsupported OS option: $OS"
        exit 1
        ;;
esac

if docker ps -a --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"; then
    if ! docker ps --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"; then
        echo "🔄 Starting stopped session: $CONTAINER_NAME..."
        docker start "$CONTAINER_NAME" > /dev/null
    fi
    echo "🚀 Attaching to existing session: $CONTAINER_NAME..."
    echo "   (To rebuild, you can manually run: $BUILD_CMD)"
    docker exec -it "$CONTAINER_NAME" bash
    exit 0
fi

echo "🚀 Creating new session: $CONTAINER_NAME (Image: $IMAGE)"

# Detect SELinux/podman so the bind mount works on Rocky/RHEL hosts
MOUNT_OPTS=""
if [ -x "$(command -v getenforce)" ] && [ "$(getenforce 2>/dev/null)" != "Disabled" ]; then
    MOUNT_OPTS=":Z"
fi

# Start the container in the background so it stays alive after exiting the shell
docker run -d --name "$CONTAINER_NAME" -v "$(pwd):/workspaces/pktana${MOUNT_OPTS}" -w /workspaces/pktana "$IMAGE" tail -f /dev/null > /dev/null

# Execute the setup, build, and drop into an interactive shell
docker exec -it "$CONTAINER_NAME" bash -c "
    set -e

    echo '=================================================='
    echo '🔧 Installing OS dependencies for $IMAGE...'
    echo '=================================================='
    $INSTALL_DEPS
    
    echo '=================================================='
    echo '🦀 Installing Rust...'
    echo '=================================================='
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source \$HOME/.cargo/env
    
    echo '=================================================='
    echo '🏗️ Building pktana...'
    echo '=================================================='
    $BUILD_CMD

    echo '=================================================='
    echo '✅ Build complete! You are now inside the session.'
    echo '   (Type \"exit\" to detach. The container will keep running.)'
    echo '   (Use \"./docker-build.sh ls\" and \"./docker-build.sh kill\" to manage.)'
    echo '=================================================='
    bash
"
