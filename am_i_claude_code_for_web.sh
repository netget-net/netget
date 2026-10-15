#!/bin/bash

# Script to detect if running in Claude Code for Web environment
# Checks multiple environment variables in order of reliability

detect_claude_code_web() {
    # Primary detection method
    if [ "$CLAUDE_CODE_REMOTE" = "true" ]; then
        echo "✓ Running in Claude Code for Web (detected via CLAUDE_CODE_REMOTE=true)"
        return 0
    fi

    # Secondary detection method
    if [ "$CLAUDE_CODE_REMOTE_ENVIRONMENT_TYPE" = "cloud_default" ]; then
        echo "✓ Running in Claude Code for Web (detected via CLAUDE_CODE_REMOTE_ENVIRONMENT_TYPE=cloud_default)"
        return 0
    fi

    # Tertiary detection methods
    if [ "$CLAUDE_CODE_ENTRYPOINT" = "remote" ]; then
        echo "✓ Running in Claude Code for Web (detected via CLAUDE_CODE_ENTRYPOINT=remote)"
        return 0
    fi

    if [ "$IS_SANDBOX" = "yes" ]; then
        echo "✓ Running in Claude Code for Web (detected via IS_SANDBOX=yes)"
        return 0
    fi

    # Not detected
    echo "✗ Not running in Claude Code for Web (local environment)"
    return 1
}

# Run detection
detect_claude_code_web
exit_code=$?

# Print additional guidance based on result
if [ $exit_code -eq 0 ]; then
    echo ""
    echo "⚠️  IMPORTANT: System Dependencies NOT Available"
    echo ""
    echo "Protocols are not Cargo features: every protocol is compiled in. What this"
    echo "environment lacks is the system libraries behind five features:"
    echo "  • libpcap      (arp, datalink, isis, lldp, cdp, stp, eapol)  - libpcap-dev"
    echo "  • bluetooth    (bluetooth-ble*)                               - libdbus-1-dev"
    echo "  • pcsc         (NFC client)                                   - libpcsclite-dev"
    echo "  • libusb       (usb-* virtual devices)                        - libusb-1.0-0-dev"
    echo "  • libsmbclient (SMB client)                                   - libsmbclient-dev"
    echo ""
    echo "✓ RECOMMENDED BUILD COMMAND (every protocol that needs no system library):"
    echo "  ./cargo-isolated.sh build --no-default-features --features mcp-stdio,mcp-http,sqlite"
    echo ""
    echo "❌ UNSAFE: the default features and --all-features need those libraries"
    echo "  ./cargo-isolated.sh build  # Will fail here"
    echo ""
    echo "📖 For detailed information, see:"
    echo "  • COMPILATION_ERROR_REPORT.md - Full error analysis"
    echo "  • CLAUDE.md - Claude Code for Web Environment section"
else
    echo ""
    echo "ℹ️  The default build links five system libraries (see AGENTS.md):"
    echo ""
    echo "  macOS:          brew install samba libusb pkgconf cmake"
    echo "  Ubuntu/Debian:  sudo apt-get install libpcap-dev libdbus-1-dev libusb-1.0-0-dev libpcsclite-dev libsmbclient-dev pkg-config cmake"
    echo "  Fedora:         sudo dnf install libpcap-devel dbus-devel libusb1-devel pcsc-lite-devel libsmbclient-devel pkgconf-pkg-config cmake"
    echo ""
    echo "Then build with:"
    echo "  ./cargo-isolated.sh build"
fi

exit $exit_code
