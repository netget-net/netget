# NetGet for Android/Termux - Installation Guide

This guide covers installing and running NetGet on Android devices using Termux.

## Quick Start

**TL;DR**: Install Termux from F-Droid, install Rust and Ollama, build NetGet with `android-termux` feature.

```bash
# In Termux on Android
pkg install rust ollama clang binutils git make perl cmake protobuf
git clone https://github.com/yourusername/netget.git && cd netget
cargo build --release --no-default-features --features android-termux
./target/release/netget
```

---

## Table of Contents

- [Requirements](#requirements)
- [Installation Methods](#installation-methods)
  - [Method 1: Build in Termux (Recommended)](#method-1-build-in-termux-recommended)
  - [Method 2: Cross-Compile from Desktop](#method-2-cross-compile-from-desktop)
- [Ollama Setup](#ollama-setup)
- [Running NetGet](#running-netget)
- [Supported Protocols](#supported-protocols)
- [Android Limitations](#android-limitations)
- [Troubleshooting](#troubleshooting)

---

## Requirements

### Device Requirements
- **Android Version**: 7.0+ (API level 24+)
- **Architecture**: ARM64 (aarch64) recommended, ARMv7 also supported
- **Storage**: 3GB free space for full build
- **RAM**: 2GB+ recommended (4GB+ for Ollama)

### Software Requirements
- **Termux**: Install from [F-Droid](https://f-droid.org/en/packages/com.termux/) (NOT Play Store version)
- **Network**: WiFi or cellular data for package downloads

**⚠️ IMPORTANT**: Do NOT use Termux from Google Play Store. It is outdated and incompatible. Use F-Droid version only.

---

## Installation Methods

### Method 1: Build in Termux (Recommended)

This is the easiest method - build NetGet directly on your Android device.

#### Step 1: Install Termux

1. Download Termux from F-Droid:
   - Open https://f-droid.org/en/packages/com.termux/ on your Android device
   - Tap "Download APK"
   - Install the APK (you may need to allow installation from unknown sources)

2. Open Termux and grant storage permissions (if prompted)

#### Step 2: Update Packages

```bash
pkg update && pkg upgrade
```

Press `Y` when asked to continue.

#### Step 3: Install Build Tools

```bash
pkg install rust clang binutils git make perl cmake protobuf
```

This installs:
- `rust`: Rust compiler and cargo
- `clang`: C compiler (needed for some dependencies)
- `binutils`: Assembler and linker
- `git`: Version control
- `make`: Build automation (required for OpenSSL compilation)
- `perl`: Scripting language (required for OpenSSL compilation)
- `cmake`: Build system generator (required for some dependencies)
- `protobuf`: Protocol Buffers compiler (required for etcd, gRPC)

**Note**: `make`, `perl`, `cmake`, and `protobuf` are needed because NetGet compiles OpenSSL and other dependencies from source (vendored) to avoid Android system library compatibility issues.

#### Step 4: Clone NetGet

```bash
cd ~
git clone https://github.com/yourusername/netget.git
cd netget
```

#### Step 5: Build NetGet

```bash
cargo build --release \
  --no-default-features \
  --features android-termux
```

**Compilation time**: 10-30 minutes depending on your device.

**Storage used**: ~2-3GB in `target/` directory.

**Success**: You should see "Finished release [optimized] target(s)" when complete.

#### Step 6: Verify Installation

```bash
./target/release/netget --version
```

You should see: `netget 0.1.0`

### Method 2: Cross-Compile from Desktop

Build NetGet on your desktop computer and transfer to Android device.

#### Option A: Using `cross` (Easiest)

```bash
# On your desktop (macOS/Linux/Windows with WSL)

# Install cross tool
cargo install cross --git https://github.com/cross-rs/cross

# Build for Android ARM64
./build-termux.sh --method cross --target aarch64

# Transfer binary to Android device
adb push target/aarch64-linux-android/release/netget /data/local/tmp/
```

#### Option B: Using Android NDK

```bash
# On your desktop

# 1. Install Android NDK
#    Download from: https://developer.android.com/ndk/downloads
#    Extract to ~/android-ndk

# 2. Set environment variable
export ANDROID_NDK_HOME=~/android-ndk

# 3. Update .cargo/config.toml with NDK paths (see comments in file)

# 4. Build for Android
./build-termux.sh --method ndk --target aarch64

# 5. Transfer binary to Android
adb push target/aarch64-linux-android/release/netget /data/local/tmp/
```

#### Transfer to Termux

```bash
# On Android in Termux
cd ~
cp /data/local/tmp/netget ~/netget-bin
chmod +x ~/netget-bin
./netget-bin --version
```

---

## Ollama Setup

NetGet requires an LLM (Ollama) for protocol behavior control.

### Option 1: Local Ollama in Termux (Recommended)

```bash
# Install Ollama in Termux
pkg install ollama

# Start Ollama server (in background)
ollama serve &

# Pull a model (choose one based on your device RAM)
# For 4GB RAM devices:
ollama pull qwen3-coder:14b

# For 6GB+ RAM devices:
ollama pull qwen3-coder:30b

# For 8GB+ RAM devices:
ollama pull qwen3-coder:70b

# Verify Ollama is running
curl http://localhost:11434/api/tags
```

**Note**: First model download may take 10-60 minutes depending on model size and network speed.

### Option 2: Remote Ollama Server

If your Android device doesn't have enough RAM, connect to Ollama on another machine:

```bash
# Run NetGet with remote Ollama endpoint
./target/release/netget --ollama-endpoint http://192.168.1.100:11434
```

Replace `192.168.1.100` with your desktop/server IP address.

**On remote server**:
```bash
# Start Ollama to listen on all interfaces
OLLAMA_HOST=0.0.0.0:11434 ollama serve
```

---

## Running NetGet

### Basic Usage

```bash
# Start NetGet with default Ollama endpoint (localhost:11434)
./target/release/netget

# Start with remote Ollama
./target/release/netget --ollama-endpoint http://192.168.1.100:11434

# Start with custom model
./target/release/netget --model qwen3-coder:14b

# Enable debug logging
./target/release/netget --log-level debug
```

### Terminal UI Controls

- **Shift+Enter**: Multi-line input
- **Ctrl+L**: Change log level
- **Ctrl+W**: Web search (if enabled)
- **Ctrl+C**: Exit

### Opening Servers

In NetGet prompt, use natural language:

```
> Start an HTTP server on port 8080 that serves a simple homepage

> Open a MySQL server on port 3307 with a database of products

> Run an SSH server on port 2222 with password authentication

> Create a DNS server on port 5353 that resolves example.com to 1.2.3.4
```

### Connecting from Other Devices

Once a server is running, you can connect from other devices on the same network:

```bash
# From another device on WiFi

# Get your Android device's IP
# In Termux: ip addr show wlan0

# Example connections:
curl http://192.168.1.50:8080          # HTTP server
mysql -h 192.168.1.50 -P 3307 -u root  # MySQL server
ssh -p 2222 user@192.168.1.50          # SSH server
dig @192.168.1.50 -p 5353 example.com  # DNS server
```

---

## Supported Protocols

The `android-termux` feature includes **66+ pure-Rust protocols**:

### Networking
✓ TCP, UDP, HTTP, HTTP/2, HTTP/3, DNS, DoT, DoH
✓ DHCP, BOOTP, NTP, mDNS, SNMP, IGMP
✓ WebRTC, SIP, VoIP

### Remote Access
✓ SSH, SFTP, SSH Agent, Telnet, VNC

### Messaging & Email
✓ SMTP, IMAP, POP3, IRC, XMPP

### Databases
✓ MySQL, PostgreSQL, Redis, MongoDB
✓ Cassandra, Elasticsearch, DynamoDB
✓ etcd, ZooKeeper

### Message Queues
✓ MQTT, AMQP (RabbitMQ), Kafka, SQS

### File Transfer
✓ WebDAV, NFS, SMB, FTP, SFTP

### Proxies & Anonymity
✓ SOCKS5, HTTP Proxy
✓ Tor (relay and directory)

### API Protocols
✓ gRPC, JSON-RPC, XML-RPC, GraphQL
✓ OpenAPI, REST, WebSocket

### Cloud & DevOps
✓ S3, Kubernetes, Docker Registry
✓ Git, SVN, Mercurial, NPM, PyPI, Maven

### Authentication
✓ OAuth2, SAML, OpenID Connect, LDAP

### IoT & P2P
✓ MQTT, CoAP, BitTorrent (tracker, DHT, peer)
✓ Bitcoin P2P protocol

### Other
✓ Syslog, WHOIS, RSS, IPP (printing)
✓ Ollama API, OpenAI API, MCP

---

## Android Limitations

### What DOESN'T Work on Android/Termux

The following protocols are **excluded** from `android-termux` feature because they require system libraries or hardware not available on Android:

❌ **Bluetooth BLE** (15+ protocols)
- Requires BlueZ (Linux) or Android Bluetooth API
- Not available in Termux without Android app integration

❌ **NFC** (smart cards, tags)
- Requires PC/SC library (not on Android)
- Needs Android NFC API for real hardware access

❌ **USB** (keyboard, mouse, serial, etc.)
- Requires USB/IP kernel module
- Needs Android USB Host API for real devices

❌ **Raw Packet Capture** (DataLink, ARP)
- Requires libpcap and root access
- Android restricts raw socket access

❌ **OSPF Routing**
- Requires raw sockets (IP protocol 89)
- Needs root/CAP_NET_RAW capability

❌ **STUN/TURN** (NAT traversal protocols)
- Uses old nix-0.8.1 crate incompatible with modern Rust
- WebRTC data channels still work (uses different implementation)

❌ **WireGuard/OpenVPN** (VPN protocols)
- Platform-specific implementations not gated for Android
- defguard_wireguard_rs only supports Linux/macOS/FreeBSD/NetBSD
- Use SOCKS5, HTTP Proxy, or Tor instead for privacy/tunneling

❌ **SMB Client** (with native library)
- Requires libsmbclient (native C library)
- Pure-Rust SMB server still works

### Android-Specific Restrictions

1. **Privileged Ports (<1024)**
   - Normal apps can't bind to ports <1024
   - Use high ports: HTTP on 8080, DNS on 5353, SSH on 2222, etc.
   - Root devices can use privileged ports

2. **Network Permissions**
   - Termux has INTERNET permission by default
   - Some VPN protocols (WireGuard, OpenVPN) may not work without VPN permission
   - Android may show "NetGet is using your VPN" notification

3. **Background Execution**
   - Android may kill background processes to save battery
   - Use wake locks or keep Termux in foreground
   - Consider using Termux:Boot for auto-start

4. **Storage Access**
   - Termux has access to its own directory (`$HOME`)
   - External storage requires `termux-setup-storage` permission

---

## Troubleshooting

### Build Issues

**Problem**: `error: linker 'cc' not found`
```bash
# Solution: Install clang
pkg install clang
```

**Problem**: `error: failed to run custom build command for 'foo'`
```bash
# Solution: Install build dependencies
pkg install binutils make
```

**Problem**: Out of memory during compilation
```bash
# Solution 1: Use debug build (faster, no optimizations)
cargo build --no-default-features --features android-termux

# Solution 2: Build in release mode with fewer parallel jobs
cargo build --release --no-default-features --features android-termux -j 1
```

**Problem**: No space left on device
```bash
# Solution: Clean build artifacts
cargo clean

# Or: Use external SD card storage
cd /sdcard
mkdir netget-build
cd netget-build
```

**Problem**: `Could not find directory of OpenSSL installation`
```bash
# This should NOT happen with android-termux feature (uses vendored OpenSSL)
# If you see this error:

# Solution 1: Verify you're using the android-termux feature
cargo build --no-default-features --features android-termux

# Solution 2: Install make and perl (required for OpenSSL compilation)
pkg install make perl

# Solution 3: Check Cargo.toml has dep:openssl-sys in android-termux feature
grep "openssl-sys" Cargo.toml

# Explanation: NetGet compiles OpenSSL from source (vendored) to avoid
# Android system library issues. This requires make and perl during build.
```

**Problem**: `No such file or directory` for NDK path (e.g., `/Users/matus/android-ndk/...`)
```bash
# This means you're trying to use cross-compilation settings in Termux
# The NDK is ONLY for cross-compiling FROM desktop TO Android
# In Termux, you build NATIVELY - no NDK needed!

# WRONG (tries to cross-compile, needs NDK):
cargo build --target aarch64-linux-android --no-default-features --features android-termux

# CORRECT (native build, no NDK needed):
cargo build --release --no-default-features --features android-termux

# Explanation:
# - When building IN Termux, cargo automatically detects you're on Android
# - It builds natively for your device's architecture
# - The .cargo/config.toml NDK paths are ignored
# - DO NOT use the --target flag when building in Termux!
```

**Problem**: `Could not find 'protoc'` (Protocol Buffers compiler)
```bash
# Error message:
# "Failed to compile proto files: Could not find `protoc`"
# "Try installing `protobuf-compiler` or `protobuf`"

# Solution: Install protobuf package
pkg install protobuf

# Verify installation:
protoc --version

# Then retry build:
cargo build --release --no-default-features --features android-termux

# Explanation:
# - etcd and gRPC protocols require Protocol Buffers (protoc) at build time
# - protoc compiles .proto files into Rust code
# - This is a build-time dependency, not runtime
```

### Runtime Issues

**Problem**: `Cannot bind to port 80: Permission denied`
```bash
# Solution: Use high port
# Instead of:  HTTP on port 80
# Use:         HTTP on port 8080
```

**Problem**: `Ollama connection refused`
```bash
# Check if Ollama is running
pgrep ollama

# If not running, start it
ollama serve &

# Verify it's listening
curl http://localhost:11434/api/tags
```

**Problem**: `Address already in use`
```bash
# Find what's using the port
netstat -tulpn | grep :8080

# Kill the process
kill -9 <PID>
```

**Problem**: Cannot connect from other devices
```bash
# 1. Check Android firewall (usually none in Termux)
# 2. Verify IP address
ip addr show wlan0

# 3. Test locally first
curl http://localhost:8080

# 4. Ensure server is bound to 0.0.0.0 (all interfaces)
# Not just 127.0.0.1 (localhost only)
```

### Performance Issues

**Problem**: Ollama is slow on mobile
```bash
# Solution 1: Use smaller model
ollama pull qwen3-coder:7b

# Solution 2: Use remote Ollama server
./netget --ollama-endpoint http://192.168.1.100:11434

# Solution 3: Enable scripting mode (no LLM for simple responses)
# Configure in prompt or config file
```

**Problem**: High battery drain
```bash
# Solution 1: Stop Ollama when not in use
pkill ollama

# Solution 2: Use power-efficient models
ollama pull gemma2:2b  # Very small model

# Solution 3: Connect to remote Ollama instead of local
```

---

## Advanced Configuration

### Custom Config File

Create `~/.netget/config.toml`:

```toml
# Default Ollama endpoint
ollama_endpoint = "http://localhost:11434"

# Default model
model = "qwen3-coder:14b"

# Log level (trace, debug, info, warn, error)
log_level = "info"

# Log file location
log_file = "/data/data/com.termux/files/home/.netget/netget.log"
```

### Auto-Start on Boot

Using Termux:Boot:

1. Install Termux:Boot from F-Droid
2. Create `~/.termux/boot/start-netget`:
   ```bash
   #!/data/data/com.termux/files/usr/bin/sh
   termux-wake-lock
   ollama serve &
   sleep 10
   ~/netget/target/release/netget --log-file ~/netget.log &
   ```
3. Make executable: `chmod +x ~/.termux/boot/start-netget`
4. Reboot device to test

---

## Performance Tips

1. **Use smaller models** for mobile: `qwen3-coder:7b` or `gemma2:2b`
2. **Enable scripting mode** for simple protocols (reduces LLM calls)
3. **Close unused servers** to save resources
4. **Use remote Ollama** for resource-intensive workloads
5. **Build with `--release`** for 2-3x faster runtime
6. **Keep Termux in foreground** to prevent Android from killing it

---

## Next Steps

- Try the quick start example
- Read the main README.md for protocol examples
- Check out protocol-specific docs in `/docs`
- Join the community for support (link TBD)

---

## Comparison: Termux vs Native Android App

| Feature | Termux Binary (This Guide) | Native Android App |
|---------|----------------------------|-------------------|
| **Installation** | Build yourself | APK from Play Store |
| **UI** | Terminal (TUI) | Native Android UI |
| **Protocols** | 70+ (pure Rust) | All 50+ (with BLE/NFC/USB) |
| **Complexity** | Low (2-4 weeks) | Very High (6-12 months) |
| **Permissions** | Terminal access | Granular app permissions |
| **Hardware Access** | Limited | Full (BLE, NFC, USB) |
| **Background Execution** | Manual wake locks | Native foreground service |
| **Distribution** | Manual transfer | Play Store |
| **Users** | Developers, power users | End users |

**Current Status**: Termux binary (this guide) is ready to use. Native Android app is planned (see `docs/archive/ANDROID_NATIVE_PLAN.md`).

---

## FAQ

**Q: Can I run NetGet on rooted Android?**
A: Yes, and you'll have access to privileged ports and raw sockets. Most protocols work without root.

**Q: Does this work on ChromeOS?**
A: Yes, if your Chromebook supports Linux apps (Crostini) or Android apps (via Play Store).

**Q: Can I build for Android x86 emulator?**
A: Yes, use `--target x86_64` with the build script.

**Q: How much battery does this use?**
A: Depends on Ollama usage. Idle servers: minimal. Active LLM inference: significant (use remote Ollama).

**Q: Can I use a different LLM provider?**
A: NetGet currently supports Ollama only. OpenAI support is planned.

**Q: Is this safe to run on my phone?**
A: NetGet servers listen on network ports - ensure you trust the LLM and users on your network.

---

## Changelog

- **2025-11-16**: Initial Termux support added
  - Created `android-termux` feature with 70+ protocols
  - Build script and documentation

---

## Contributing

Found a bug? Have suggestions? See CONTRIBUTING.md (TBD).

---

## License

See LICENSE file in repository.
