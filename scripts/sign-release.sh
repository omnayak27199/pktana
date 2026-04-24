#!/usr/bin/env bash
# scripts/sign-release.sh — GPG-sign the built RPM and generate a checksum file.
#
# Usage:
#   scripts/sign-release.sh               (signs latest RPM in dist/)
#   scripts/sign-release.sh <PATH>.rpm    (signs a specific RPM)
#
# Requires:
#   gpg key in your keyring with the name configured in ~/.rpmmacros
#   rpm-sign package installed:  dnf install -y rpm-sign
#
# One-time setup:
#   gpg --full-generate-key                 # generate a key if you don't have one
#   gpg --list-secret-keys --keyid-format LONG
#   echo '%_gpg_name Your Name' >> ~/.rpmmacros
#   rpmsign --addsign path/to/package.rpm

set -euo pipefail

RPM_PATH="${1:-$(ls dist/rpmbuild/RPMS/x86_64/pktana-*.rpm 2>/dev/null | sort -V | tail -1)}"

if [[ -z "${RPM_PATH}" ]]; then
    echo "ERROR: no RPM found. Run 'make pktana' first." >&2
    exit 1
fi

if [[ ! -f "${RPM_PATH}" ]]; then
    echo "ERROR: file not found: ${RPM_PATH}" >&2
    exit 1
fi

echo "==> Signing: ${RPM_PATH}"
rpmsign --addsign "${RPM_PATH}"

echo "==> Verifying signature..."
rpm --checksig "${RPM_PATH}"

CHECKSUM_FILE="${RPM_PATH%.rpm}.sha256"
sha256sum "${RPM_PATH}" > "${CHECKSUM_FILE}"
echo "==> SHA256: $(cat "${CHECKSUM_FILE}")"
echo "==> Checksum written to: ${CHECKSUM_FILE}"
