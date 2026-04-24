# -------------------------------------------------------
# pktana top-level Makefile
#
# Usage:
#   make pktana          – build binary + RPM (reads release.conf)
#   make binary          – build the Rust release binary only
#   make clean           – remove all generated artifacts
# -------------------------------------------------------

# Load version / release / OS settings from release.conf
include release.conf

DIST_DIR  := dist
RPMROOT   := $(DIST_DIR)/rpmbuild
SPEC_SRC  := deploy/centos/pktana.spec
BINARY    := target/release/pktana
TARBALL   := $(DIST_DIR)/pktana-$(VERSION).tar.gz

# ---- top-level targets --------------------------------

.PHONY: pktana binary clean

## Build binary + RPM package
pktana: _check-tools $(TARBALL)
	@echo ""
	@echo "==> Building RPM  $(VERSION)-$(RELEASE).$(OS_TYPE) ..."
	@rm -rf $(RPMROOT)
	@mkdir -p $(RPMROOT)/BUILD \
	           $(RPMROOT)/RPMS \
	           $(RPMROOT)/SOURCES \
	           $(RPMROOT)/SPECS \
	           $(RPMROOT)/SRPMS
	@cp $(TARBALL)  $(RPMROOT)/SOURCES/
	@cp $(SPEC_SRC) $(RPMROOT)/SPECS/pktana.spec
	rpmbuild \
	  --define "_topdir  $(CURDIR)/$(RPMROOT)" \
	  --define "pkg_version $(VERSION)" \
	  --define "pkg_release $(RELEASE)" \
	  --define "dist .$(OS_TYPE)" \
	  -ba $(RPMROOT)/SPECS/pktana.spec
	@echo ""
	@echo "==> RPMs are ready:"
	@find $(RPMROOT)/RPMS $(RPMROOT)/SRPMS -name '*.rpm' | sort

## Build the Rust release binary only
binary: _check-cargo $(BINARY)

$(BINARY):
	@echo "==> Compiling pktana (debug check) ..."
	cargo build --features pcap -p pktana-cli
	@echo "==> Compiling pktana (release) ..."
	cargo build --release --features pcap -p pktana-cli

$(TARBALL): $(BINARY)
	@echo "==> Creating source tarball for rpmbuild ..."
	@rm -rf $(DIST_DIR)/rpm-src/pktana-$(VERSION)
	@mkdir -p $(DIST_DIR)/rpm-src/pktana-$(VERSION)
	@cp $(BINARY)   $(DIST_DIR)/rpm-src/pktana-$(VERSION)/pktana
	@cp README.md   $(DIST_DIR)/rpm-src/pktana-$(VERSION)/README.md
	tar -czf $(TARBALL) -C $(DIST_DIR)/rpm-src pktana-$(VERSION)
	@echo "    $(TARBALL)"

## Remove all generated files
clean:
	rm -rf $(DIST_DIR) target

# ---- internal sanity checks ---------------------------

.PHONY: _check-tools _check-cargo _check-rpmbuild

_check-tools: _check-cargo _check-rpmbuild

_check-cargo:
	@command -v cargo >/dev/null 2>&1 || { \
	  echo "error: cargo not found – install Rust from https://rustup.rs"; \
	  exit 1; \
	}

_check-rpmbuild:
	@command -v rpmbuild >/dev/null 2>&1 || { \
	  echo "error: rpmbuild not found"; \
	  echo "hint:  yum install rpm-build   (el7)"; \
	  echo "hint:  dnf install rpm-build   (el9)"; \
	  exit 1; \
	}
