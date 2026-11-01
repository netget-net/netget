## Install

`npx -y @smotana/netget` (or `npm install -g @smotana/netget`) picks the right plain binary
below. `cargo install --locked netget-tool` builds every protocol, including the ones no archive
carries. Details: [docs/guides/INSTALL.md](https://github.com/netget-net/netget/blob/master/docs/guides/INSTALL.md).

## What each archive contains

Every archive carries every protocol its platform can build, plus MCP (stdio and HTTP) and
SQLite. The difference is the protocols that link a system library:

| Archive | Packet capture¹ | Bluetooth LE² | NFC client³ | Needs at run time |
|---|---|---|---|---|
| `netget-aarch64-apple-darwin`, `netget-x86_64-apple-darwin` | yes | yes | yes | nothing beyond macOS |
| `netget-x86_64-unknown-linux-gnu`, `netget-aarch64-unknown-linux-gnu` | no | no | no | glibc ≥ 2.35, zlib |
| `netget-x86_64-unknown-linux-gnu-full`, `netget-aarch64-unknown-linux-gnu-full` | yes | yes | yes | glibc ≥ 2.35, zlib, libpcap, libdbus-1, libpcsclite |
| `netget-x86_64-unknown-linux-musl` | no | no | no | nothing (static) |
| `netget-x86_64-pc-windows-msvc` | no | no | no | nothing |

¹ ARP, DataLink, LLDP, CDP, STP, EAPOL and IS-IS servers; ARP, DataLink and IS-IS clients.
² The `bluetooth_ble` server and its 16 profile servers, and the Bluetooth LE client.
³ PC/SC.

On Linux those protocols are only in the `-full` archives, which npm does not install. Their
libraries on Debian/Ubuntu: `sudo apt-get install libpcap0.8 libdbus-1-3 libpcsclite1`.

No archive carries the USB/IP virtual devices (`libusb`), the SMB client (`libsmbclient`) or
the embedded llama.cpp runtime (`--embedded-model`); `cargo install` does.
