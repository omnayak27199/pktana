# Version and release are injected by the Makefile via --define.
# Defaults below are used only when building this spec file directly.
%{!?pkg_version: %global pkg_version 0.1.0}
%{!?pkg_release: %global pkg_release 1}

# The binary is pre-compiled; disable debuginfo/debugsource sub-packages.
%global debug_package %{nil}

Name:           pktana
Version:        %{pkg_version}
Release:        %{pkg_release}%{?dist}
Summary:        Linux-first packet analyzer CLI

License:        MIT
URL:            https://github.com/example/pktana
BuildArch:      x86_64
Source0:        %{name}-%{version}.tar.gz

# ---- runtime dependencies ------------------------------------------------
# libpcap is required for live packet capture.
# DNF/YUM will install it automatically before this package is installed.
Requires:       libpcap >= 1.5

%description
pktana is a Linux-first packet analyzer written in Rust.
It supports live capture (via libpcap) as well as offline PCAP file analysis.
This package installs the pktana CLI binary.

%prep
%setup -q

%build
# The release binary is pre-compiled by the Makefile before rpmbuild runs.
# There is nothing to compile inside this spec.

%install
mkdir -p %{buildroot}/usr/local/bin
install -m 0755 pktana %{buildroot}/usr/local/bin/pktana

mkdir -p %{buildroot}/usr/share/doc/%{name}
install -m 0644 README.md %{buildroot}/usr/share/doc/%{name}/README.md

%files
/usr/local/bin/pktana
/usr/share/doc/%{name}/README.md

%changelog
* Fri Apr 24 2026 Omprakash <omprakash@example.com> - 0.1.0-1
- Initial RPM package
