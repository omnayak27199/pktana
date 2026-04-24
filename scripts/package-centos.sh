#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
PACKAGE_DIR="${DIST_DIR}/pktana-linux-amd64"
VERSION="0.1.0"

cd "${ROOT_DIR}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is not installed on this build machine" >&2
  exit 1
fi

echo "Building release binary..."
cargo build --release -p pktana-cli --features pcap,tui

rm -rf "${PACKAGE_DIR}"
mkdir -p "${PACKAGE_DIR}"

cp "${ROOT_DIR}/target/release/pktana" "${PACKAGE_DIR}/pktana"
cp "${ROOT_DIR}/README.md" "${PACKAGE_DIR}/README.md"
cp "${ROOT_DIR}/deploy/centos/install.sh" "${PACKAGE_DIR}/install.sh"

chmod +x "${PACKAGE_DIR}/pktana" "${PACKAGE_DIR}/install.sh"

mkdir -p "${DIST_DIR}"
tar -czf "${DIST_DIR}/pktana-linux-amd64.tar.gz" -C "${DIST_DIR}" "pktana-linux-amd64"

echo
echo "Created package:"
echo "  ${DIST_DIR}/pktana-linux-amd64.tar.gz"

RPM_SOURCE_DIR="${DIST_DIR}/rpm-src/pktana-${VERSION}"
rm -rf "${RPM_SOURCE_DIR}"
mkdir -p "${RPM_SOURCE_DIR}"

cp "${ROOT_DIR}/target/release/pktana" "${RPM_SOURCE_DIR}/pktana"
cp "${ROOT_DIR}/README.md" "${RPM_SOURCE_DIR}/README.md"

tar -czf "${DIST_DIR}/pktana-${VERSION}.tar.gz" -C "${DIST_DIR}/rpm-src" "pktana-${VERSION}"

echo
echo "Created RPM source archive:"
echo "  ${DIST_DIR}/pktana-${VERSION}.tar.gz"
