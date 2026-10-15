# NetGet

**LLM-Controlled Network Protocol Server & Client**

NetGet is a Rust CLI application exposing 283 network protocols, with server and client roles controlled by an LLM (via Ollama). Instead of hardcoding protocol logic, NetGet provides the network stack while the LLM constructs raw protocol datagrams or high-level responses based on natural language instructions.

```bash
# Start a MySQL server that reads schema from files
netget "act as MySQL server, read schema.json for database structure"

# Start an SSH server with custom authentication
netget "SSH server on port 2222, allow users alice and bob"

# Connect as HTTP client to test an API
netget "connect to https://api.example.com as HTTP client"
```

## Why NetGet?

**Traditional Approach**: Hardcode protocol behavior
```rust
match command {
    "USER" => send("331 Password required\r\n"),
    "PASS" => send("230 Logged in\r\n"),
    // ... hundreds of lines of rigid logic
}
```

**NetGet's Approach**: Instruct the LLM in natural language
```bash
> act as an HTTP server, serve /data.txt with content 'hello', 404 everything else
```

The LLM handles the protocol details — status lines, headers, authentication exchanges —
without any code changes.

## Key Features

### 🌐 283 Network Protocols

Both server and client modes for:

**Core Transport**
- TCP, UDP, HTTP, HTTP/2, HTTP/3, TLS, DataLink

**Application Protocols**
- SSH, FTP, DNS, DHCP, SMTP, IMAP, MySQL, PostgreSQL, Redis
- MQTT, Kafka, gRPC, WebSocket, WebDAV, NFS, SMB
- WireGuard, Tor; IPSec and OpenVPN are honeypots, not working VPNs

> **Maturity varies a lot.** Most protocols are `Experimental` — LLM-authored and not
> human-reviewed. Run `netget --mcp` and call `list_protocols` for each protocol's current
> state, or read its `metadata()`. A few specifics worth knowing: FTP has no data connection,
> so `LIST`/`RETR`/`STOR` cannot complete against a real client; OpenVPN is a control-plane
> honeypot — a real `openvpn` binary completes the TLS control channel and the key method 2
> exchange, but `PUSH_REQUEST` is never answered, no data-channel keys are derived and there is
> no TUN device, so it observes clients and never carries traffic.

**IoT & Hardware**
- Bluetooth Low Energy (15+ GATT services: keyboard, mouse, heart rate, etc.)
- USB/IP (keyboard, mouse, serial, mass storage, FIDO2, smart card)

**Routing & Infrastructure**
- BGP, OSPF, IS-IS, RIP, mDNS, SNMP, NTP, Syslog

**Specialized**
- OAuth2, SAML, OpenID Connect, MCP, JSON-RPC, XML-RPC
- BitTorrent (tracker, DHT, peer), OpenAPI, Kubernetes, etcd

See the `/docs` command in the TUI for full protocol details and metadata.

### 🤖 LLM-Driven Intelligence

- **Tool Calling**: LLM can read files and search the web before responding
- **Scripting Mode**: Use Python/JavaScript for deterministic protocol logic (0 LLM calls)
- **Scheduled Tasks**: Time-based automation at global, server, or connection scope
- **Memory**: LLM maintains conversation history across requests

### 🖥️ Rich Terminal Interface

**Rolling Terminal UI** with sticky footer:
- **Three-column layout**: Active servers | Active clients | Status & stats
- **Natural scrolling**: Output flows into your terminal's scrollback buffer
- **Multi-line input**: Shift+Enter for complex commands
- **Command history**: Up/down arrows with persistent storage
- **Log levels**: Ctrl+L to toggle ERROR/WARN/INFO/DEBUG/TRACE
- **Web search**: Ctrl+W to enable LLM web search capability

## Quick Start

### Prerequisites

1. **Install Ollama** (LLM runtime)
   ```bash
   curl https://ollama.ai/install.sh | sh
   ollama pull qwen3-coder:30b  # or another model
   ```

2. **Install Rust** (latest stable)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

### Installation

**Option 1: npm (prebuilt binary, no Rust needed)**

```bash
# Run directly (downloads the binary for your platform on first use)
npx @smotana/netget

# Or install globally
npm i -g @smotana/netget
netget
```

Prebuilt binaries cover macOS (arm64/x64), Linux (x64/arm64 glibc, x64 musl), and Windows x64. They need no system library: on Linux and Windows they leave out the few protocols that link one (packet capture, Bluetooth LE, the NFC client, USB devices, the SMB client); macOS ships those libraries, so its binaries include them. Tarballs are also on [GitHub Releases](https://github.com/netget-net/netget/releases).

**Option 2: cargo (every protocol)**

The crate is `netget-tool` (crates.io's `netget` is an unrelated project); the command it installs is `netget`. Every protocol is compiled in — there are no per-protocol features. The default build links five system libraries and builds llama.cpp (which needs cmake and libclang), so install those first:

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

cargo install --locked netget-tool
```

Without those libraries, leave out the protocols that need them (and the embedded llama.cpp):

```bash
cargo install --locked netget-tool --no-default-features --features mcp-stdio,mcp-http,sqlite
```

**Option 3: Build from source**

```bash
git clone https://github.com/netget-net/netget.git
cd netget
cargo build --release          # same system libraries as Option 2
```

### Run Your First Server

```bash
# Start Ollama
ollama serve

# Start NetGet
./target/release/netget

# In the NetGet prompt, type:
> listen on port 8080 via HTTP, serve a page that says "Hello World"
```

Now visit `http://localhost:8080` in your browser!

## Architecture

NetGet uses an event-driven architecture where all network events flow through a central event handler that coordinates with the LLM:

```
┌─────────────────────────────────────────────────────────┐
│                   Rolling Terminal UI                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │  Active  │  │  Active  │  │  Connection Info &   │  │
│  │  Servers │  │  Clients │  │  Stats               │  │
│  └──────────┘  └──────────┘  └──────────────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │         Status / Activity Log (Scrolling)        │  │
│  └──────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Input: > your commands here (Shift+Enter)       │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                            │
         ┌──────────────────┴──────────────────┐
         ▼                                     ▼
┌──────────────────┐               ┌──────────────────────┐
│  Network Layer   │               │   LLM Integration    │
│  • TCP/UDP       │◄─────────────►│  • Ollama Client     │
│  • TLS           │               │  • Tool Calling      │
│  • Raw Sockets   │               │  • Scripting         │
│  • USB/IP        │               │  • Web Search        │
│  • Bluetooth     │               │                      │
└──────────────────┘               └──────────────────────┘
```

### Key Modules

- **`cli/`** - Terminal UI (rolling output, sticky footer, input handling)
- **`server/<protocol>/`** - Protocol server implementations
- **`client/<protocol>/`** - Protocol client implementations
- **`protocol/`** - Protocol registry and metadata
- **`llm/`** - Ollama integration and prompt engineering
- **`llm/actions/`** - LLM action system (user-triggered and network-triggered)
- **`events/`** - Event coordination between network, LLM, and UI
- **`state/`** - Application state management

### Design Principles

1. **Decentralized Protocol Registry**: Each protocol implements traits independently (no central switch statements except in startup)
2. **Dual Logging**: All logs go to both tracing macros (→ `netget.log`) and status channel (→ TUI)
3. **State Machine**: Per-connection state (Idle → Processing → Accumulating) prevents concurrent LLM calls
4. **Every Protocol In Every Build**: No per-protocol Cargo features; only the platform (browser, Windows) and five system-library features decide what is compiled
5. **No Protocol Storage**: Protocols don't store data—LLM returns everything via actions/scripts/static responses

## Usage Examples

### Server Examples

#### HTTP Server with Dynamic Content
```bash
> listen on port 8080 via HTTP
> For /api/time return JSON with current timestamp
> For /api/random return a random number between 1 and 100
```

#### MySQL Server with Schema File
```bash
# Create schema file first
$ cat > schema.json <<EOF
{
  "database": "shop",
  "tables": [
    {"name": "products", "columns": ["id", "name", "price"]},
    {"name": "users", "columns": ["id", "email", "created_at"]}
  ]
}
EOF

> act as MySQL server, read schema.json for database structure
> Answer SELECT queries based on the schema
```

#### SSH Server with Custom Behavior
```bash
> SSH server on port 2222
> Allow password authentication for user "admin" with password "secret"
> When user runs "date", return current date and time
> When user runs "fortune", return a random fortune cookie message
```

#### DNS Server with Dynamic Responses
```bash
> DNS server on port 5353
> For *.local domains, return 127.0.0.1
> For *.dev domains, return 192.168.1.100
> For google.com, return 8.8.8.8
```

### Client Examples

#### HTTP Client Testing API
```bash
> connect to https://api.github.com as HTTP client
> Send GET request to /users/octocat
> Show me the response headers and body
```

#### Redis Client Session
```bash
> connect to 127.0.0.1:6379 as Redis client
> Send: SET mykey "Hello World"
> Send: GET mykey
> Send: INCR counter
```

#### TCP Client for Protocol Testing
```bash
> connect to localhost:25 as TCP client
> This is an SMTP server, try sending an email
```

### Advanced Features

#### Tool Calling (File Reading)
```bash
> act as HTTP server on port 8000
> For /config, read config.json and return it as JSON
> For /users, read users.csv and return it formatted as HTML table
```

The LLM will automatically call `read_file()` when handling requests.

#### Web Search Integration
```bash
# Enable web search
Ctrl+W

> act as HTTP server on port 80
> If you receive a request you don't understand, search for the HTTP RFC
```

The LLM can search the web for protocol documentation, RFCs, or any other information.

#### Scripting Mode (Zero LLM Calls)
```bash
> listen on port 3000 via HTTP
> Use JavaScript scripting mode for responses
> For /api/time return: { "time": new Date().toISOString() }
> For /health return: { "status": "ok" }
```

Scripting mode is deterministic and makes zero LLM calls after setup.

#### Scheduled Tasks
```bash
> listen on port 22 via SSH
> Schedule a task every 60 seconds to broadcast "System health check complete"
> Schedule a task after 300 seconds to close all idle connections
```

Tasks can be scoped to global (any server), server-specific, or connection-specific.

### Managing Connections

```bash
> status                    # Show all active servers and clients
> close server 1            # Close specific server
> close client 2            # Close specific client
> close all                 # Close everything
> model llama3.3:70b        # Switch to different LLM model
```

## Control NetGet from Another LLM (MCP)

NetGet can run as a [Model Context Protocol](https://modelcontextprotocol.io) server,
exposing its protocol-server management as MCP tools. This lets an MCP client such as
Claude Desktop or Claude Code start and drive network protocol servers directly.

### STDIO transport (Claude Desktop / Claude Code)

Quickest path — npm prebuilt binary:

```bash
claude mcp add netget -- npx -y @smotana/netget --mcp
```

Or build from source (`mcp-stdio` is a default feature):

```bash
./cargo-isolated.sh build --release

# Run as an MCP server over stdin/stdout
netget --mcp
```

Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "netget": {
      "command": "npx",
      "args": ["-y", "@smotana/netget", "--mcp", "--model", "qwen3-coder:30b"]
    }
  }
}
```

(For a source build, set `"command"` to the binary path instead. First `npx` run downloads the package, so the initial MCP startup takes longer.)

### HTTP transport (remote / web clients)

```bash
# mcp-http is a default feature
./cargo-isolated.sh build --release

# Serve MCP over HTTP/SSE (bind address from --listen-addr, default 127.0.0.1)
netget --mcp-http 8080          # endpoint: http://127.0.0.1:8080/mcp

# Any non-loopback bind requires a bearer token
NETGET_MCP_TOKEN=$(openssl rand -hex 32) netget --mcp-http 8080 --listen-addr 0.0.0.0
```

With a token set — `NETGET_MCP_TOKEN`, or `--mcp-token <TOKEN>` — every request must carry
`Authorization: Bearer <TOKEN>`. Binding `--listen-addr` to anything but a loopback address
is refused without one; without a token the endpoint admits loopback `Host`/`Origin` only.
Prefer the environment variable: a `--mcp-token` argument is visible to every local user in
the process table.

### Exposed tools

`list_protocols`, `start_server`, `stop_server`, `list_servers`, `server_status`,
`get_status`, `set_model`, `get_protocol_docs`, `update_server_instruction`, `stop_all`,
and for debugging: `list_access_logs` (recent requests) / `get_access_log` (full
request + response for one entry).

The protocol servers you start through MCP are driven by NetGet's own configured LLM
(local Ollama, or an OpenAI-compatible endpoint via `--openai-url`/`--api-key`). The
MCP client controls NetGet through the tools above; it does not supply the model.

## Testing

NetGet has comprehensive test coverage with both unit tests and end-to-end tests.

### Unit Tests (No Ollama Required)

```bash
./cargo-isolated.sh test --lib
```

Tests protocol parsing, registry, metadata, and core utilities.

### E2E Tests (Ollama Required)

```bash
# Start Ollama first
ollama serve
ollama pull qwen3-coder:30b

# Run one protocol's E2E tests (every protocol is compiled in; select by module path)
./cargo-isolated.sh test --test server -- server::tcp::e2e_test

# Run all of a protocol's tests (server + client)
./cargo-isolated.sh test --test server --test client -- server::http:: client::http::
```

**E2E Test Philosophy**:
- **Black-box testing**: Tests use real clients (curl, mysql CLI, ssh clients, etc.)
- **LLM budget**: Each test suite limited to < 10 LLM calls via aggressive caching
- **Prompt-driven**: Tests validate that LLM interprets prompts correctly
- **Localhost only**: All tests run on 127.0.0.1/::1 for privacy

### Test Organization

- **Unit tests**: `tests/base_stack_test.rs` (registry parsing, etc.)
- **Protocol E2E**: `tests/server/<protocol>/e2e_test.rs`, `tests/client/<protocol>/e2e_test.rs`
- **Documentation**: Each protocol has TWO `CLAUDE.md` files:
  - `src/server/<protocol>/CLAUDE.md` - Implementation details
  - `tests/server/<protocol>/CLAUDE.md` - Test strategy

## Building

### System Dependencies

Every protocol is compiled into every build; there are no per-protocol Cargo features. Five
features link a system library (all on by default, Unix only), and `embedded-llm` builds
llama.cpp:

| Feature | Library | Protocols |
|---|---|---|
| `libpcap` | libpcap (ships with macOS) | arp, datalink, isis, lldp, cdp, stp, eapol |
| `bluetooth` | D-Bus/BlueZ on Linux; CoreBluetooth on macOS | bluetooth-ble* |
| `pcsc` | pcsclite (ships with macOS) | the NFC client |
| `libusb` | libusb | the usb-* virtual devices |
| `libsmbclient` | libsmbclient (Homebrew `samba`) | the SMB client |
| `embedded-llm` | cmake and a C++ compiler | in-process llama.cpp |

The install commands for each platform are under Installation above.

### Build Strategies

```bash
# Everything (needs the libraries above)
./cargo-isolated.sh build

# Everything that needs no system library
./cargo-isolated.sh build --no-default-features --features mcp-stdio,mcp-http,sqlite
```

**Claude Code for Web** has none of the five libraries:
```bash
./am_i_claude_code_for_web.sh
./cargo-isolated.sh build --no-default-features --features mcp-stdio,mcp-http,sqlite
```

### Build Performance Notes

- **sccache**: NetGet uses sccache for caching compiled artifacts
- **No per-protocol features**: every build compiles every protocol; narrow test runs with
  filters (`--test server -- server::tcp::`), not features
- **Isolated builds**: `./cargo-isolated.sh` uses session-specific target directory to avoid conflicts
- **Parallel builds**: Multiple instances can build concurrently; `./cargo-isolated.sh` serialises access to the shared `target/`

### Cargo Isolated Scripts

```bash
./cargo-isolated.sh build                     # Build with isolated target dir
./cargo-isolated.sh test --test server -- server::http::   # Test one protocol
./cargo-isolated.sh run -- --debug            # Run with debug logging
./cargo-isolated.sh --print-last              # View last build/test output
./cargo-isolated-kill.sh                      # Kill all isolated builds (not system cargo!)
```

Output is automatically logged to `./tmp/netget-<command>-{PPID}.log`.

## Configuration

### LLM Model Selection

**Change at runtime** (recommended):
```bash
> model qwen3-coder:30b
> model llama3.3:70b
> model codestral:latest
```

**Default model**: `qwen3-coder:30b` (configured in `src/state/app_state.rs`)

### Ollama URL

Default: `http://localhost:11434`

To change, edit `src/llm/client.rs`:
```rust
pub fn default() -> Self {
    Self::new("http://your-ollama-host:11434")
}
```

### Log Levels

- **Runtime**: Press `Ctrl+L` to cycle through ERROR → WARN → INFO → DEBUG → TRACE
- **Startup**: `netget --debug` enables debug logging to `netget.log`

### History

Command history is persisted to `~/.netget_history` across sessions.

## Protocol Implementation

### Adding a New Server Protocol

See `CLAUDE.md` for the full 12-step checklist. Quick overview:

1. Add feature to `Cargo.toml`
2. Implement server in `src/server/<protocol>/mod.rs`
3. Implement actions in `src/server/<protocol>/actions.rs`
4. Register in `protocol/registry.rs` (feature-gated)
5. Add match arm in `cli/server_startup.rs` (feature-gated)
6. Write E2E test in `tests/server/<protocol>/e2e_test.rs`
7. Document in `src/server/<protocol>/CLAUDE.md` and `tests/server/<protocol>/CLAUDE.md`

### Adding a New Client Protocol

Similar to server, but:
- Implement in `src/client/<protocol>/mod.rs` and `actions.rs`
- Register in `protocol/client_registry.rs`
- Add match arm in `cli/client_startup.rs`
- See `CLIENT_PROTOCOL_FEASIBILITY.md` for protocol evaluation criteria

## Advanced Topics

### Multi-Instance Collaboration

- Use `./cargo-isolated.sh` for per-session build isolation
- Use `--llm-max-concurrent` (with `--llm-queue-timeout` and `--llm-max-queued`) to bound LLM concurrency
- Use git worktrees for concurrent development branches
- Never use `pkill cargo`—use `./cargo-isolated-kill.sh` instead

### Efficient Iteration

Build/test logging is automatic. Analyze all errors before rebuilding:

```bash
# Build and pipe last 50 lines
./cargo-isolated.sh build | tail -50

# Analyze ALL errors from saved log
./cargo-isolated.sh --print-last | grep "error\[E"

# Fix ALL issues at once, then rebuild once
./cargo-isolated.sh build | tail -50
```

This saves 10-20 minutes per development cycle vs fixing one error at a time.

### Protocol-Specific Documentation

Each protocol has detailed documentation:

- **Implementation**: `src/server/<protocol>/CLAUDE.md` or `src/client/<protocol>/CLAUDE.md`
  - Library choices, architecture, LLM integration, limitations
- **Testing**: `tests/server/<protocol>/CLAUDE.md` or `tests/client/<protocol>/CLAUDE.md`
  - Test strategy, LLM call budget, runtime, known issues

**Always read both before modifying a protocol.**

## Troubleshooting

### Ollama Connection Failed
```
Error: Failed to connect to Ollama
```
**Fix**: Ensure Ollama is running: `ollama serve`

### Model Not Found
```
Error: Model not found
```
**Fix**: Pull the model: `ollama pull qwen3-coder:30b`

### Port Already in Use
```
Error: Address already in use
```
**Fix**: Choose a different port or kill the process using that port.

### Build Fails with Missing Libraries
```
error: failed to run custom build command for `dbus`
```
**Fix**: Install the system libraries (see Installation), or build without them:
`--no-default-features --features mcp-stdio,mcp-http,sqlite` leaves out only the protocols
that link one.

## Performance Considerations

- **LLM latency**: Each network event may trigger an LLM call (can be slow)
- **Scripting mode**: For deterministic protocols, use Python/JavaScript scripting (zero LLM calls)
- **Caching**: Connection state machine prevents concurrent LLM calls on same connection
- **LLM concurrency**: `--llm-max-concurrent` bounds in-flight model calls; requests above it queue rather than being dropped

**Use case**: NetGet is ideal for protocol testing, security research, learning, and development. Not recommended for production high-throughput servers.

## Contributing

NetGet is an experimental project exploring LLM-controlled networking. Contributions welcome!

**Ideas for enhancement**:
1. New protocol implementations
2. Better prompt engineering for existing protocols
3. Scripting mode templates for common protocols
4. Performance optimizations (caching, connection pooling)
5. Additional tool calling capabilities
6. Protocol fuzzing and security testing features

## Files Created

NetGet creates the following files:
- **`netget.log`** - Application logs (only with `--debug` flag)
- **`~/.netget_history`** - Command history (always created)
- **`./tmp/netget-*.log`** - Build/test logs from `cargo-isolated.sh`

## License

MIT

## Acknowledgments

- Built with [Tokio](https://tokio.rs/) for async runtime
- Terminal UI powered by [Crossterm](https://github.com/crossterm-rs/crossterm)
- LLM integration via [Ollama](https://ollama.ai/)
- 283 protocol features, built on best-in-class Rust crates
