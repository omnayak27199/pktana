# pktana-tracer — single-command build
#
# Usage:
#   make            build release binary (default)
#   make clean      remove build artifacts
#   make version    print project version
#   make run        build then show --version

VERSION := $(shell tr -d ' \t\r\n' < VERSION)
BUILD_DIR := build
CMAKE_BUILD_TYPE ?= Release
CMAKE_GENERATOR ?=

ifeq ($(OS),Windows_NT)
    BINARY := $(BUILD_DIR)/Release/pktana-tracer.exe
    CMAKE_ARGS := -A x64
    BUILD_ARGS := --config Release
else
    BINARY := $(BUILD_DIR)/pktana-tracer
    CMAKE_ARGS :=
    BUILD_ARGS :=
endif

.PHONY: all build clean version run help

.DEFAULT_GOAL := build

help:
	@echo "pktana-tracer $(VERSION)"
	@echo ""
	@echo "  make            build release binary"
	@echo "  make clean      remove build directory"
	@echo "  make version    print version from VERSION file"
	@echo "  make run        build and run pktana-tracer version"

all: build

version:
	@echo $(VERSION)

build: $(BINARY)

$(BINARY): CMakeLists.txt VERSION $(shell find include src cmake -type f 2>/dev/null)
	@command -v cmake >/dev/null 2>&1 || { echo "error: cmake not found"; exit 1; }
	cmake -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) $(CMAKE_GENERATOR) $(CMAKE_ARGS)
	cmake --build $(BUILD_DIR) --parallel $(BUILD_ARGS)
	@echo ""
	@echo "Built $(BINARY) (v$(VERSION))"

run: build
	$(BINARY) version

clean:
	rm -rf $(BUILD_DIR)
