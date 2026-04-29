#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
VERSION="0.3.1"
RPMROOT="${DIST_DIR}/rpmbuild"
SPEC_FILE="${ROOT_DIR}/deploy/centos/pktana.spec"
SOURCE_TARBALL="${DIST_DIR}/pktana-${VERSION}.tar.gz"

cd "${ROOT_DIR}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is not installed on this build machine" >&2
  exit 1
fi

if ! command -v rpmbuild >/dev/null 2>&1; then
  echo "error: rpmbuild is not installed on this build machine" >&2
  echo "hint: install rpm-build on CentOS/RHEL and rerun this script" >&2
  exit 1
fi

echo "Preparing release artifacts..."
"${ROOT_DIR}/scripts/package-centos.sh"

rm -rf "${RPMROOT}"
mkdir -p "${RPMROOT}/BUILD" "${RPMROOT}/RPMS" "${RPMROOT}/SOURCES" "${RPMROOT}/SPECS" "${RPMROOT}/SRPMS"

cp "${SOURCE_TARBALL}" "${RPMROOT}/SOURCES/"
cp "${SPEC_FILE}" "${RPMROOT}/SPECS/"

echo "Building RPM..."
rpmbuild \
  --define "_topdir ${RPMROOT}" \
  -ba "${RPMROOT}/SPECS/pktana.spec"

echo
echo "RPM artifacts:"
find "${RPMROOT}/RPMS" "${RPMROOT}/SRPMS" -type f | sort
