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

.PHONY: pktana binary clean check fmt clippy test help all

.DEFAULT_GOAL := help

## Show help message
help:
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  pktana Makefile - Complete Build System"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo ""
	@echo "Main targets:"
	@echo "  make pktana    - ✅ Build EVERYTHING (recommended)"
	@echo "                   → Format code"
	@echo "                   → Run clippy linter"
	@echo "                   → Run all tests"
	@echo "                   → Compile release binary"
	@echo "                   → Create RPM package"
	@echo ""
	@echo "  make clean     - 🧹 Remove all build artifacts"
	@echo ""
	@echo "Individual steps:"
	@echo "  make check     - Run all code quality checks"
	@echo "  make fmt       - Format code with rustfmt"
	@echo "  make clippy    - Run clippy linter (strict mode)"
	@echo "  make test      - Run all tests"
	@echo "  make binary    - Build release binary only"
	@echo ""
	@echo "Quick start:"
	@echo "  make pktana    ← This does everything you need!"
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

## Build everything (alias for pktana)
all: pktana

## Build binary + RPM package (runs all checks first)
pktana: check $(TARBALL)
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
	@echo ""
	@echo "✅ BUILD SUCCESSFUL - All checks passed!"

## Run all code quality checks
check: _check-tools fmt clippy test
	@echo "✅ All checks passed!"

## Format all code
fmt:
	@echo "==> Running cargo fmt ..."
	cargo fmt --all

## Run clippy linter
clippy:
	@echo "==> Running clippy ..."
	cargo clippy --all-targets --features pcap,tui -- -D warnings

## Run tests
test:
	@echo "==> Running tests ..."
	cargo test --all --features pcap,tui

## Build the Rust release binary only
binary: _check-cargo $(BINARY)

$(BINARY):
	@echo "==> Compiling pktana (debug check) ..."
	cargo build --features pcap,tui -p pktana-cli
	@echo "==> Compiling pktana (release) ..."
	cargo build --release --features pcap,tui -p pktana-cli

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
	@echo "==> Cleaning all build artifacts ..."
	rm -rf $(DIST_DIR) target
	cargo clean
	@echo "✅ Clean complete!"

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
