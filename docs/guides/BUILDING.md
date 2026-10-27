# Building NetGet

For a prebuilt binary, use `npx -y @smotana/netget` or download a
[release](https://github.com/netget-net/netget/releases).

## System libraries

The default Rust build uses packet capture, Bluetooth, PC/SC, USB, SMB, and the embedded
llama.cpp runtime. Install the native dependencies before building:

```bash
# macOS (libpcap, PC/SC and CoreBluetooth ship with the OS)
brew install samba libusb pkgconf cmake

# Debian / Ubuntu
sudo apt-get install build-essential pkg-config cmake libclang-dev libssl-dev libltdl-dev \
    libpcap-dev libdbus-1-dev libusb-1.0-0-dev libpcsclite-dev libsmbclient-dev

# Fedora
sudo dnf install gcc gcc-c++ make pkgconf-pkg-config cmake clang-devel openssl-devel libtool-ltdl-devel \
    libpcap-devel dbus-devel libusb1-devel pcsc-lite-devel libsmbclient-devel

# Arch
sudo pacman -S --needed base-devel cmake clang openssl libpcap dbus libusb pcsclite smbclient
```

Install the crate (the package is `netget-tool`, the executable is `netget`):

```bash
cargo install --locked netget-tool
```

To build without those system-library integrations or the embedded model runtime:

```bash
cargo install --locked netget-tool --no-default-features --features mcp-stdio,mcp-http,sqlite
```

## Source checkout

```bash
git clone https://github.com/netget-net/netget.git
cd netget
./cargo-isolated.sh build --release
./target/release/netget
```

Read [contributor instructions](../../AGENTS.md) for build isolation, current features,
testing, and protocol implementation conventions. See the [documentation index](../README.md)
for platform notes and component guides.
