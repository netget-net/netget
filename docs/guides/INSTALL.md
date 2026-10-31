# Installing NetGet

| Path | Command | What you get |
|---|---|---|
| npm (recommended) | `npx -y @smotana/netget` or `npm install -g @smotana/netget` | The release binary for your platform (table below) |
| GitHub release | download `netget-<target>.tar.gz` / `.zip` from [Releases](https://github.com/netget-net/netget/releases) | The same binaries; `SHA256SUMS` lists their checksums |
| Cargo | `cargo install --locked netget-tool` | Every protocol, built from source ([system libraries](BUILDING.md)) |
| Docker | `docker build -t netget .` in a checkout | The glibc Linux release feature set; see [Docker](#docker) |
| Homebrew | not published yet | `packaging/homebrew/netget.rb` is a draft formula for a future tap |

The crate is `netget-tool` (crates.io's `netget` is an unrelated project); the command is
`netget` everywhere.

## What each release binary contains

Every binary carries every protocol its platform can build, plus MCP over stdio and HTTP and the
model's SQLite databases. They differ only in the protocols that link a system library:

| Release archive | npm package | Packet capture¹ | Bluetooth LE² | NFC client³ | Needs at run time |
|---|---|---|---|---|---|
| `netget-aarch64-apple-darwin` | `@smotana/netget-darwin-arm64` | yes | yes | yes | nothing beyond macOS |
| `netget-x86_64-apple-darwin` | `@smotana/netget-darwin-x64` | yes | yes | yes | nothing beyond macOS |
| `netget-x86_64-unknown-linux-gnu` | `@smotana/netget-linux-x64` | yes | yes | yes | glibc ≥ 2.35, zlib, libpcap, libdbus-1, libpcsclite |
| `netget-aarch64-unknown-linux-gnu` | `@smotana/netget-linux-arm64` | yes | yes | yes | glibc ≥ 2.35, zlib, libpcap, libdbus-1, libpcsclite |
| `netget-x86_64-unknown-linux-musl` | `@smotana/netget-linux-x64-musl` | no | no | no | nothing (static) |
| `netget-x86_64-pc-windows-msvc` | `@smotana/netget-win32-x64` | no | no | no | nothing |

¹ `libpcap`: the ARP, DataLink, LLDP, CDP, STP, EAPOL and IS-IS servers and the ARP, DataLink
and IS-IS clients.
² `bluetooth`: the `bluetooth_ble` server, its 16 profile servers (keyboard, mouse, beacon,
remote, battery, heart rate, thermometer, environmental, proximity, gamepad, presenter, file
transfer, data stream, cycling, running, weight scale) and the Bluetooth LE client. On Linux
they talk to BlueZ (`bluetoothd`) over D-Bus.
³ `pcsc`: the NFC client, through PC/SC (`pcscd` on Linux).

No release binary carries the USB/IP virtual devices (`libusb`), the SMB client
(`libsmbclient`) or the embedded llama.cpp runtime (`--embedded-model`). Windows also lacks the
Unix-only protocols (pty, Unix sockets, raw sockets). `cargo install --locked netget-tool`
builds all of them where the platform allows; `netget --mcp` → `list_protocols` names what a
given binary has.

The glibc Linux libraries, by distribution:

```bash
sudo apt-get install libpcap0.8 libdbus-1-3 libpcsclite1     # Debian / Ubuntu
sudo dnf install libpcap dbus-libs pcsc-lite-libs            # Fedora
sudo pacman -S --needed libpcap dbus pcsclite                # Arch
```

Without them the glibc binary does not start (`error while loading shared libraries`). On a
minimal x86_64 system or container where installing them is not an option, use the static musl
binary instead: download `netget-x86_64-unknown-linux-musl.tar.gz` from the release and run it
directly, or set `NETGET_BINARY` to it so `npx @smotana/netget` uses it. (The
`@smotana/netget-linux-x64-musl` npm package declares `libc: musl`, so npm installs it only on
musl systems such as Alpine, where the launcher picks it automatically.)

The packet-capture protocols need raw-socket privileges at run time (root, or `CAP_NET_RAW` and
`CAP_NET_ADMIN` on Linux); NetGet refuses to start them otherwise and says why.

## Docker

The repository's `Dockerfile` builds the glibc Linux release feature set on Debian bookworm and
runs it as an unprivileged user. No image is published; build it yourself:

```bash
docker build -t netget .
docker run --rm -p 18040:18040 -e NETGET_MCP_TOKEN="$(openssl rand -hex 32)" netget
```

The default command is `--mcp-http 18040 --listen-addr 0.0.0.0`; a non-loopback MCP endpoint
requires the bearer token. Protocol servers bind `127.0.0.1` unless `start_server` is given
`host: "0.0.0.0"`, and each needs its port published (`-p`). For a model, add
`--ollama-url http://host.docker.internal:11434` (or `--openai-url` and `--model` with
`NETGET_API_KEY`), or `--llm-agent` to have the MCP caller answer requests. `netget.log` and any
`append_to_log` files land in `/data`; mount a volume there to keep them. The Dockerfile's
header covers privileged protocols.

## LLM backend

Manual, static and scripted responses need no model. For model-driven responses run
[Ollama](https://ollama.com) locally (the default, `http://localhost:11434`) or pass
`--openai-url` and `--model` for any OpenAI-compatible endpoint, with the key in
`NETGET_API_KEY`.
