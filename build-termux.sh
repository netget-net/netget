#!/usr/bin/env bash
#
# Build NetGet for Android/Termux
#
# This script provides multiple methods for building NetGet for Android:
#   1. Using `cross` tool (easiest, requires Docker)
#   2. Using Android NDK (requires NDK installation)
#   3. Instructions for building in Termux on device
#
# Usage:
#   ./build-termux.sh [--method cross|ndk|help] [--target aarch64|armv7|x86_64]
#

set -euo pipefail

# Default values
METHOD="auto"
TARGET="aarch64-linux-android"
RELEASE="--release"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --method)
            METHOD="$2"
            shift 2
            ;;
        --target)
            case $2 in
                aarch64)
                    TARGET="aarch64-linux-android"
                    ;;
                armv7)
                    TARGET="armv7-linux-androideabi"
                    ;;
                x86_64)
                    TARGET="x86_64-linux-android"
                    ;;
                *)
                    echo -e "${RED}Error: Invalid target '$2'. Use: aarch64, armv7, or x86_64${NC}"
                    exit 1
                    ;;
            esac
            shift 2
            ;;
        --debug)
            RELEASE=""
            shift
            ;;
        --help|help)
            METHOD="help"
            shift
            ;;
        *)
            echo -e "${RED}Error: Unknown argument '$1'${NC}"
            echo "Usage: $0 [--method cross|ndk|help] [--target aarch64|armv7|x86_64] [--debug]"
            exit 1
            ;;
    esac
done

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

show_help() {
    cat <<EOF
NetGet Android/Termux Build Script

METHODS:
  1. cross    - Use cross tool (easiest, requires Docker)
  2. ndk      - Use Android NDK (requires NDK installation)
  3. termux   - Show instructions for building in Termux
  4. auto     - Automatically detect best method (default)

TARGETS:
  - aarch64   - ARM64 (most modern Android devices) [default]
  - armv7     - ARMv7 (older Android devices)
  - x86_64    - x86_64 (emulators and x86 tablets)

EXAMPLES:
  # Build using cross (recommended)
  ./build-termux.sh --method cross

  # Build using Android NDK
  ./build-termux.sh --method ndk

  # Build for ARMv7 devices
  ./build-termux.sh --target armv7

  # Build debug version
  ./build-termux.sh --debug

  # Show Termux instructions
  ./build-termux.sh --method termux

FEATURES:
  Every protocol that builds on Android is compiled in, including:
  ✓ TCP, UDP, HTTP, HTTP/2, HTTP/3, DNS, DHCP, NTP
  ✓ SSH, SMTP, IMAP, FTP, Telnet, IRC, XMPP
  ✓ MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch
  ✓ MQTT, AMQP, gRPC, WebSocket, Kafka
  ✓ OAuth2, SAML, OpenID, JSON-RPC
  ✓ WireGuard, OpenVPN, Tor, VPN protocols
  ✓ And many more...

  Excluded protocols (require hardware/system features):
  ✗ Bluetooth BLE (needs BlueZ or Android API)
  ✗ NFC (needs PC/SC or Android API)
  ✗ USB (needs USB/IP or Android API)
  ✗ Raw packet capture (needs libpcap and root)
  ✗ OSPF (needs raw sockets and root)

OUTPUT:
  Binary will be in: target/${TARGET}/release/netget
  or: target/${TARGET}/debug/netget (if --debug)

For more information, see docs/guides/TERMUX_INSTALL.md
EOF
}

build_with_cross() {
    print_header "Building with cross tool"

    # Check if cross is installed
    if ! command -v cross &> /dev/null; then
        print_error "cross tool not found"
        echo ""
        echo "Install with:"
        echo "  cargo install cross --git https://github.com/cross-rs/cross"
        echo ""
        echo "Note: cross requires Docker to be running"
        exit 1
    fi

    print_info "Target: $TARGET"
    print_info "Mode: ${RELEASE:-debug}"
    print_info "Features: mcp-stdio,sqlite,libpcap (every protocol is compiled in)"
    echo ""

    print_info "Building with cross..."
    cross build $RELEASE \
        --target "$TARGET" \
        --no-default-features \
        --features mcp-stdio,sqlite,libpcap

    print_success "Build complete!"
    echo ""
    echo "Binary location:"
    if [ -n "$RELEASE" ]; then
        echo "  target/$TARGET/release/netget"
    else
        echo "  target/$TARGET/debug/netget"
    fi
}

build_with_ndk() {
    print_header "Building with Android NDK"

    # Check if NDK is configured
    if [ -z "${ANDROID_NDK_HOME:-}" ]; then
        print_error "ANDROID_NDK_HOME not set"
        echo ""
        echo "Install Android NDK:"
        echo "  1. Download from: https://developer.android.com/ndk/downloads"
        echo "  2. Extract to a directory (e.g., ~/android-ndk)"
        echo "  3. Set environment variable:"
        echo "     export ANDROID_NDK_HOME=~/android-ndk"
        echo "  4. Update .cargo/config.toml with NDK toolchain paths"
        echo ""
        exit 1
    fi

    # Check if .cargo/config.toml has NDK paths configured
    if grep -q "^# linker =" .cargo/config.toml 2>/dev/null; then
        print_warning ".cargo/config.toml has commented NDK paths"
        print_info "Uncomment and update linker/ar paths in .cargo/config.toml"
        echo ""
    fi

    print_info "NDK location: $ANDROID_NDK_HOME"
    print_info "Target: $TARGET"
    print_info "Mode: ${RELEASE:-debug}"
    print_info "Features: mcp-stdio,sqlite,libpcap (every protocol is compiled in)"
    echo ""

    print_info "Building with cargo..."
    cargo build $RELEASE \
        --target "$TARGET" \
        --no-default-features \
        --features mcp-stdio,sqlite,libpcap

    print_success "Build complete!"
    echo ""
    echo "Binary location:"
    if [ -n "$RELEASE" ]; then
        echo "  target/$TARGET/release/netget"
    else
        echo "  target/$TARGET/debug/netget"
    fi
}

show_termux_instructions() {
    print_header "Building in Termux (on Android device)"

    cat <<EOF

Building NetGet directly in Termux is the simplest method if you have
access to an Android device.

SETUP (one-time):
  1. Install Termux from F-Droid (NOT from Play Store):
     https://f-droid.org/en/packages/com.termux/

  2. Open Termux and update packages:
     $ pkg update && pkg upgrade

  3. Install Rust and required tools:
     $ pkg install rust git clang binutils make perl cmake protobuf

     Note: make, perl, cmake, and protobuf are needed for compiling OpenSSL and other dependencies from source

  4. Clone NetGet repository:
     $ git clone https://github.com/yourusername/netget.git
     $ cd netget

BUILD:
  $ cargo build --release \\
      --no-default-features \\
      --features mcp-stdio,sqlite,libpcap

  This will compile natively on your Android device.
  Binary will be in: target/release/netget

INSTALL OLLAMA (for LLM support):
  $ pkg install ollama
  $ ollama serve &
  $ ollama pull qwen3-coder:30b

RUN:
  $ ./target/release/netget --ollama-endpoint http://localhost:11434

NOTES:
  - Compilation takes 10-30 minutes on mobile devices
  - Requires ~3GB free storage
  - Uses ~2GB RAM during compilation
  - Works on Android 7.0+ (API level 24+)
  - Most protocols will work, but privileged ports (<1024) require root

For more details, see docs/guides/TERMUX_INSTALL.md

EOF
}

auto_detect_method() {
    print_header "Auto-detecting best build method"

    # Check for cross
    if command -v cross &> /dev/null; then
        print_success "Found: cross tool"
        return 0
    fi

    # Check for NDK
    if [ -n "${ANDROID_NDK_HOME:-}" ]; then
        print_success "Found: Android NDK at $ANDROID_NDK_HOME"
        return 1
    fi

    # No build tools found
    print_warning "No Android build tools detected"
    echo ""
    echo "Recommended: Install cross tool"
    echo "  cargo install cross --git https://github.com/cross-rs/cross"
    echo ""
    echo "Alternative: Install Android NDK"
    echo "  https://developer.android.com/ndk/downloads"
    echo ""
    echo "Or: Build in Termux on Android device"
    echo "  ./build-termux.sh --method termux"
    echo ""
    exit 1
}

# Main execution
case "$METHOD" in
    help)
        show_help
        ;;
    cross)
        build_with_cross
        ;;
    ndk)
        build_with_ndk
        ;;
    termux)
        show_termux_instructions
        ;;
    auto)
        auto_detect_method
        if [ $? -eq 0 ]; then
            METHOD="cross"
            build_with_cross
        else
            METHOD="ndk"
            build_with_ndk
        fi
        ;;
    *)
        print_error "Unknown method: $METHOD"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
