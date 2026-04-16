#!/bin/bash
# Sindarin native library installer for Linux/macOS
# Downloads versioned binaries from S3 to ./libs/{os}
# Name and version are read from sn.yaml in the package root
# Caches archives in ~/.sn-cache/downloads/ to avoid re-downloading

set -e

S3_BUCKET="cryosharp-sindarin-pkg-binaries"
S3_REGION="eu-west-2"
BASE_DIR="$(pwd)/libs"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

write_status() {
    local message="$1"
    local type="${2:-info}"

    case "$type" in
        "info")    echo -e "${CYAN}${message}${NC}" ;;
        "success") echo -e "${GREEN}${message}${NC}" ;;
        "warning") echo -e "${YELLOW}${message}${NC}" ;;
        "error")   echo -e "${RED}${message}${NC}" ;;
        *)         echo "$message" ;;
    esac
}

detect_os() {
    local os
    os="$(uname -s)"
    case "$os" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        *)
            write_status "Unsupported operating system: $os" "error"
            exit 1
            ;;
    esac
}

detect_arch() {
    if [ -n "$SN_LIBS_ARCH" ]; then
        echo "$SN_LIBS_ARCH"
        return
    fi

    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)    echo "x64" ;;
        aarch64|arm64)   echo "arm64" ;;
        *)
            write_status "Unsupported architecture: $arch" "error"
            exit 1
            ;;
    esac
}

get_download_tool() {
    if command -v curl &> /dev/null; then
        echo "curl"
    elif command -v wget &> /dev/null; then
        echo "wget"
    else
        write_status "Neither curl nor wget found. Please install one of them." "error"
        exit 1
    fi
}

download_file() {
    local url="$1"
    local output="$2"
    local tool
    tool=$(get_download_tool)

    if [ "$tool" = "curl" ]; then
        curl -fSL "$url" -o "$output"
    else
        wget -q "$url" -O "$output"
    fi
}

read_yaml_field() {
    local field="$1"
    local value
    value=$(grep "^${field}:" sn.yaml 2>/dev/null | head -1 | sed "s/^${field}:[[:space:]]*//")

    if [ -z "$value" ]; then
        write_status "Failed to read '${field}' from sn.yaml" "error"
        exit 1
    fi

    echo "$value"
}

install_libs() {
    local pkg_name="$1"
    local os="$2"
    local arch="$3"
    local version="$4"

    local archive_name="${pkg_name}-v${version}-${os}-${arch}.tar.gz"
    local download_url="https://${S3_BUCKET}.s3.${S3_REGION}.amazonaws.com/${pkg_name}/v${version}/${archive_name}"

    local cache_dir="${HOME}/.sn-cache/downloads"
    local cached_archive="${cache_dir}/${archive_name}"

    if [ -f "$cached_archive" ]; then
        write_status "Using cached ${archive_name}"
    else
        write_status "Downloading ${pkg_name} v${version} for ${os}-${arch}..."
        mkdir -p "$cache_dir"
        if ! download_file "$download_url" "$cached_archive"; then
            write_status "Download failed" "error"
            rm -f "$cached_archive"
            exit 1
        fi
    fi

    local temp_dir
    temp_dir=$(mktemp -d)
    trap "rm -rf '$temp_dir'" EXIT

    write_status "Extracting to ${INSTALL_DIR}..."

    if [ -d "$INSTALL_DIR" ]; then
        rm -rf "$INSTALL_DIR"
    fi
    mkdir -p "$INSTALL_DIR"

    local extract_dir="${temp_dir}/extracted"
    mkdir -p "$extract_dir"
    tar -xzf "$cached_archive" -C "$extract_dir"

    local contents
    contents=$(ls -A "$extract_dir")
    local count
    count=$(echo "$contents" | wc -l)

    if [ "$count" -eq 1 ] && [ -d "${extract_dir}/${contents}" ]; then
        mv "${extract_dir}/${contents}"/* "$INSTALL_DIR/" 2>/dev/null || true
        mv "${extract_dir}/${contents}"/.[!.]* "$INSTALL_DIR/" 2>/dev/null || true
    else
        mv "${extract_dir}"/* "$INSTALL_DIR/" 2>/dev/null || true
        mv "${extract_dir}"/.[!.]* "$INSTALL_DIR/" 2>/dev/null || true
    fi

    write_status "Successfully installed ${pkg_name} v${version} to ${INSTALL_DIR}" "success"
}

main() {
    local pkg_name
    pkg_name=$(read_yaml_field "name")
    local version
    version=$(read_yaml_field "version")

    write_status "${pkg_name} - native library installer"
    write_status "========================================"

    local os
    os=$(detect_os)
    local arch
    arch=$(detect_arch)
    write_status "Detected OS: ${os} (${arch})"
    write_status "Package version: v${version}"

    INSTALL_DIR="${BASE_DIR}/${os}"

    install_libs "$pkg_name" "$os" "$arch" "$version"

    echo ""
    write_status "Installation complete!" "success"
}

main "$@"
