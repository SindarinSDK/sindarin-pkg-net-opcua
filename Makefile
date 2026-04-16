# Sindarin Net OPC UA Package

.PHONY: setup test build

%.sn: %.sn.c
	@:

ifeq ($(OS),Windows_NT)
    PLATFORM := windows
    EXE_EXT  := .exe
else
    UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)
    ifeq ($(UNAME_S),Darwin)
        PLATFORM := darwin
    else
        PLATFORM := linux
    endif
    EXE_EXT :=
endif

BIN_DIR      := bin
SN           ?= sn
SRC_SOURCES  := $(wildcard src/*.sn) $(wildcard src/native/*.sn.c) $(wildcard src/native/*.h)
RUN_TESTS_SN := .sn/sindarin-pkg-test/src/execute.sn
RUN_TESTS    := $(BIN_DIR)/run_tests$(EXE_EXT)

# open62541 on Windows requires several Windows system libraries. MSVC-style
# #pragma comment(lib, ...) autolink is ignored by clang targeting mingw,
# so add them explicitly to LDFLAGS.
ifeq ($(PLATFORM),windows)
    PLATFORM_LDFLAGS := -liphlpapi -lws2_32 -lcrypt32 -lbcrypt -ladvapi32 -luser32
else
    PLATFORM_LDFLAGS :=
endif

setup:
	@$(SN) --install
ifeq ($(OS),Windows_NT)
	@powershell -ExecutionPolicy Bypass -File scripts/install.ps1
	@powershell -ExecutionPolicy Bypass -File scripts/gen_test_certs.ps1
else
	@bash scripts/install.sh
	@bash scripts/gen_test_certs.sh
endif

test: setup $(RUN_TESTS)
	@SN_CFLAGS="-I$(CURDIR)/libs/$(PLATFORM)/include $(SN_CFLAGS)" \
	 SN_LDFLAGS="-L$(CURDIR)/libs/$(PLATFORM)/lib $(PLATFORM_LDFLAGS) $(SN_LDFLAGS)" \
	 $(RUN_TESTS) --parallel 4 --run-timeout 180 --verbose

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(RUN_TESTS): $(RUN_TESTS_SN) $(SRC_SOURCES) | $(BIN_DIR)
	@SN_CFLAGS="-I$(CURDIR)/libs/$(PLATFORM)/include $(SN_CFLAGS)" \
	 SN_LDFLAGS="-L$(CURDIR)/libs/$(PLATFORM)/lib $(PLATFORM_LDFLAGS) $(SN_LDFLAGS)" \
	 $(SN) $(RUN_TESTS_SN) -o $@ -l 1

VCPKG_ROOT ?= $(CURDIR)/vcpkg
TRIPLET    ?= $(if $(filter windows,$(PLATFORM)),x64-mingw-static,$(if $(filter aarch64,$(shell uname -m 2>/dev/null)),arm64,x64)-$(if $(filter darwin,$(PLATFORM)),osx,linux))
ARCH       ?= $(if $(filter aarch64,$(shell uname -m 2>/dev/null)),arm64,x64)
VERSION    ?= local

build:
	@if [ ! -x "$(VCPKG_ROOT)/vcpkg" ] && [ ! -x "$(VCPKG_ROOT)/vcpkg.exe" ]; then \
	    echo "Bootstrapping vcpkg..." && \
	    git clone --depth=1 https://github.com/microsoft/vcpkg.git "$(VCPKG_ROOT)" && \
	    "$(VCPKG_ROOT)/bootstrap-vcpkg.sh" -disableMetrics; \
	fi
	"$(VCPKG_ROOT)/vcpkg" install --triplet=$(TRIPLET) --x-install-root=vcpkg/installed
	mkdir -p libs/$(PLATFORM)/lib libs/$(PLATFORM)/include
	find vcpkg/installed/$(TRIPLET)/lib -maxdepth 1 -name "*.a" -exec cp {} libs/$(PLATFORM)/lib/ \;
	cp -r vcpkg/installed/$(TRIPLET)/include/* libs/$(PLATFORM)/include/
	echo "$(VERSION)" > libs/$(PLATFORM)/VERSION
	echo "$(PLATFORM)" > libs/$(PLATFORM)/PLATFORM
