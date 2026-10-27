# NetGet Architecture Documentation

## Overview

NetGet is designed with a clear separation of concerns:
- **TCP/IP Stack**: Handles low-level networking (connections, packets)
- **LLM Integration**: Provides protocol intelligence and decision-making
- **UI Layer**: Interactive terminal interface for user control
- **Event System**: Coordinates all components

## Design Philosophy

### LLM as Protocol Engine

Traditional network applications hardcode protocol logic:

```rust
// Traditional approach
match command {
    "USER" => send("331 Password required\r\n"),
    "PASS" => send("230 Logged in\r\n"),
    // ... hundreds of lines
}
```

NetGet's approach:

```rust
// NetGet approach
let response = llm.ask("User sent: USER anonymous. What should FTP server respond?");
send(response);
```

**Benefits:**
- Any protocol can be implemented via natural language instructions
- Protocol behavior adapts to user requirements
- No code changes needed for protocol modifications

### Event-Driven Architecture

All system events flow through a central event system:

```
User Input ──┐
             ├──> EventHandler ──> LLM ──> Network
Network ─────┘
```

**Event Types:**
1. **NetworkEvent**: Connection, data received/sent, errors
2. **UserCommand**: Listen, connect, close, status
3. **Tick**: Periodic updates
4. **Shutdown**: Clean termination

## Component Details

### CLI Module (`src/cli/`)

**Purpose**: Rolling terminal interface with sticky footer

**Architecture:**
```
┌─────────────────────────────────────────────────┐
│                                                 │
│         Scrolling Output Region                 │
│   (LLM responses, logs, server events)          │
│   Scrolls naturally into terminal's scrollback  │
│                                                 │
│                                                 │
├─────────────────────────────────────────────────┤ Sticky Footer
│ Status Bar: Model | Scripting | Web Search     │
│ Input Field: User commands (multi-line)         │
└─────────────────────────────────────────────────┘
```

**Key Files:**
- `rolling_tui.rs`: Main TUI event loop and rendering
- `sticky_footer.rs`: Footer component (status bar + input)
- `input_state.rs`: Multi-line input with history
- `server_startup.rs`: Protocol server spawning logic

**Rendering Flow:**
```
Terminal Input ─> Event ─> handle_event() ─> EventHandler
                                  │
                                  ▼
Status Channel ─> print_output_line() ─> Scrolling Region
                                  │
                                  ▼
                           footer.render() ─> Sticky Footer
```

### Server Module (`src/server/`)

**Purpose**: Protocol server implementations

**Structure:**
- New protocols: `src/server/<protocol>/mod.rs` and `actions.rs`
- Legacy protocols: `src/server/tcp.rs`, `http.rs`, `udp.rs`, `datalink.rs`

**Protocol Organization:**
```
src/server/
├── imap/
│   ├── mod.rs        # Server implementation
│   └── actions.rs    # LLM action handlers
├── ssh/
│   ├── mod.rs
│   └── actions.rs
├── ldap/
│   ├── mod.rs
│   └── actions.rs
├── tcp.rs           # Legacy TCP protocol
├── http.rs          # Legacy HTTP protocol
└── mod.rs           # Module exports
```

#### Example Server Structure
```rust
pub struct ImapServer {
    listener: TcpListener,
    state: Arc<AppState>,
    status_tx: UnboundedSender<String>,
}
```

**Responsibilities:**
- Bind to port and listen
- Accept new connections
- Spawn connection handlers
- Send network events to event system

#### Connection (`connection.rs`)
```rust
pub struct Connection {
    pub id: ConnectionId,
    pub remote_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub stream: TcpStream,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}
```

**Features:**
- Unique connection IDs
- Statistics tracking
- Connection lifecycle management

#### Packet (`packet.rs`)
```rust
pub struct Packet {
    pub connection_id: ConnectionId,
    pub data: Bytes,
    pub timestamp: DateTime<Utc>,
    pub direction: PacketDirection,
}
```

**Purpose:**
- Represents network packets
- Tracks direction (RX/TX)
- Timestamps for logging

### Protocol Module (`src/protocol/`)

**Important**: This module does NOT implement protocols!

```rust
pub enum ProtocolType {
    Ftp,
    Http,
    Custom,
}
```

**Purpose:**
- Type definitions only
- Protocol hint for LLM prompts
- User can select protocol type

**Why no implementations?**
- All protocol logic is LLM-generated
- Keeps codebase minimal
- Maximum flexibility

### State Module (`src/state/`)

**Purpose**: Global application state management

#### AppState (`app_state.rs`)

```rust
pub struct AppState {
    mode: Mode,                        // Server/Client/Idle
    protocol_type: ProtocolType,       // FTP/HTTP/Custom
    local_addr: Option<SocketAddr>,    // Listening address
    connections: HashMap<...>,         // Active connections
    instructions: Vec<String>,         // User instructions history
    ollama_model: String,              // Current LLM model
}
```

**Thread Safety:**
- Wrapped in `Arc<RwLock<T>>`
- Multiple components can read/write safely
- Async-friendly

**Key Methods:**
```rust
async fn get_mode() -> Mode
async fn set_protocol_type(ProtocolType)
async fn add_instruction(String)
async fn get_summary() -> String  // For LLM context
```

### LLM Module (`src/llm/`)

#### OllamaClient (`client.rs`)

```rust
pub struct OllamaClient {
    base_url: String,
    client: reqwest::Client,
}
```

**Methods:**
```rust
async fn generate(&self, model: &str, prompt: &str) -> Result<String>
async fn is_available(&self) -> bool
async fn list_models(&self) -> Result<Vec<String>>
```

**Features:**
- REST API communication with Ollama
- Non-streaming generation (for simplicity)
- Error handling

#### PromptBuilder (`prompt.rs`)

**Purpose**: Generate context-aware prompts for LLM

**Prompt Types:**

1. **Data Received Prompt**
```
You are controlling a network server.

Mode: Server
Protocol: FTP
User Instructions:
- Serve file data.txt with content 'hello'

Event: Data Received
Data: USER anonymous\r\n

What data should be sent back?
```

2. **Connection Established Prompt**
```
New connection established.
Should any initial data be sent? (e.g., FTP welcome)
```

3. **Status Prompt**
```
Provide human-readable explanation of this event.
```

**Prompt Engineering Considerations:**
- Include all relevant context
- Clear instructions for expected output format
- Examples of proper responses
- Explicit handling of edge cases

### Events Module (`src/events/`)

#### Event Types (`types.rs`)

```rust
pub enum AppEvent {
    Network(NetworkEvent),
    UserCommand(UserCommand),
    Tick,
    Shutdown,
}

pub enum NetworkEvent {
    Listening { addr },
    Connected { connection_id, remote_addr },
    Disconnected { connection_id },
    DataReceived { connection_id, data },
    DataSent { connection_id, data },
    Error { connection_id, error },
}

pub enum UserCommand {
    Listen { port, protocol },
    Connect { addr, protocol },
    Close,
    AddFile { name, content },
    Status,
    ChangeModel { model },
    Raw { input },
}
```

#### EventHandler (`handler.rs`)

**Central coordination point**

```rust
pub struct EventHandler {
    state: AppState,
    llm: OllamaClient,
    connections: HashMap<ConnectionId, TcpStream>,
}
```

**Event Processing Flow:**

```
AppEvent ──> handle_event()
              │
              ├─> Network ──> handle_network_event()
              │                 │
              │                 ├─> Ask LLM for response
              │                 └─> Send data to connection
              │
              └─> UserCommand ──> handle_user_command()
                                   │
                                   ├─> Update state
                                   └─> Apply configuration
```

**LLM Integration Points:**

Every network event involving data triggers LLM:

```rust
// Connection established
let prompt = PromptBuilder::build_connection_established_prompt(...);
let response = llm.generate(&model, &prompt).await?;
if response != "NO_RESPONSE" {
    tcp::send_data(stream, response.as_bytes()).await?;
}

// Data received
let prompt = PromptBuilder::build_data_received_prompt(...);
let response = llm.generate(&model, &prompt).await?;
match response.trim() {
    "CLOSE_CONNECTION" => close_connection(),
    "NO_RESPONSE" => {},
    data => send_data(data),
}
```

## Data Flow

### Complete Request-Response Cycle

```
1. Client sends TCP packet
         │
         ▼
2. TcpServer receives data
         │
         ▼
3. NetworkEvent::DataReceived sent to channel
         │
         ▼
4. EventHandler receives event
         │
         ▼
5. EventHandler builds LLM prompt:
   - Current state
   - Protocol type
   - User instructions
   - Received data
         │
         ▼
6. LLM processes prompt, generates response
         │
         ▼
7. EventHandler parses LLM response
         │
         ▼
8. Send data via TcpStream
         │
         ▼
9. Update UI with status
         │
         ▼
10. Client receives response
```

## Concurrency Model

### Async Runtime: Tokio

**Main Task:**
- UI rendering loop
- User input polling
- Event dispatching

**Background Tasks:**
- TCP listener (accepts connections)
- Per-connection handlers (read data)

**Communication:**
- Channels (`mpsc::unbounded_channel`)
- No shared mutable state (except via `Arc<RwLock<T>>`)

### Task Spawning

```rust
// Spawn listener
tokio::spawn(async move {
    loop {
        let (stream, addr) = tcp_server.accept().await?;
        // Spawn per-connection handler
        tokio::spawn(handle_connection(stream, addr, ...));
    }
});
```

## Error Handling

### Strategy

1. **Network Errors**: Log and continue
2. **LLM Errors**: Show in UI, don't crash
3. **User Errors**: Display helpful message
4. **Critical Errors**: Graceful shutdown

### Error Propagation

```rust
// Result types throughout
pub async fn handle_event(...) -> Result<bool>

// Error context
.context("Failed to send data")?

// Logging
error!("LLM error: {}", e);
```

## State Management

### Centralized State

All state in `AppState`:
- Single source of truth
- Thread-safe access via RwLock
- Async-friendly

### State Updates

```rust
// Read
let mode = state.get_mode().await;

// Write
state.set_protocol_type(ProtocolType::Ftp).await;

// Complex update
state.update_connection_stats(id, bytes_sent, bytes_received, ...).await;
```

## Testing Strategy

### Unit Tests (Future)

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_user_command_parsing() {
        let cmd = UserCommand::parse("listen on port 21 via ftp");
        assert!(matches!(cmd, UserCommand::Listen { port: 21, .. }));
    }
}
```

### Integration Tests (Future)

```rust
#[tokio::test]
async fn test_ftp_session() {
    // Start server
    // Connect with FTP client
    // Verify LLM generates correct responses
}
```

## Performance Characteristics

### Bottlenecks

1. **LLM Latency**: Each event waits for LLM response
   - Typical: 500ms-5s per request
   - Mitigated by async/await (non-blocking)

2. **Single Connection Processing**: Events processed sequentially
   - Multiple connections handled concurrently
   - Each connection's events are sequential

### Optimizations (Future)

1. **Response Caching**: Cache common protocol responses
2. **Batching**: Group multiple requests to LLM
3. **Streaming**: Use streaming LLM API
4. **Parallel Processing**: Multiple LLM instances

## Security Considerations

### Current State

- No authentication
- No encryption (plain TCP)
- No input validation (LLM decides)
- Local use only

### Future Security

- TLS/SSL support
- Rate limiting
- Input sanitization
- Firewall integration

## Extensibility

### Adding New Protocol Types

```rust
// In src/protocol/mod.rs
pub enum ProtocolType {
    Ftp,
    Http,
    Smtp,  // Add this
    Custom,
}
```

No other code changes needed - LLM handles it!

### Adding New Event Types

```rust
// In src/events/types.rs
pub enum NetworkEvent {
    // ... existing events
    Timeout { connection_id, duration },  // Add this
}

// In src/events/handler.rs
NetworkEvent::Timeout { connection_id, duration } => {
    // Handle timeout
}
```

### Custom LLM Backends

```rust
// Create trait
pub trait LLMBackend {
    async fn generate(&self, prompt: &str) -> Result<String>;
}

// Implement for different backends
impl LLMBackend for OllamaClient { ... }
impl LLMBackend for OpenAIClient { ... }
```

## Debugging

### Logging

```bash
# Enable debug logs
RUST_LOG=debug ./cargo-isolated.sh run

# Specific module
RUST_LOG=netget::events=trace ./cargo-isolated.sh run
```

### Network Debugging

```bash
# Monitor traffic
sudo tcpdump -i lo0 port 2121

# Packet inspection
wireshark
```

### LLM Debugging

```rust
// In src/llm/client.rs
debug!("Prompt: {}", prompt);
debug!("Response: {}", response);
```

## Deployment

### Development
```bash
./cargo-isolated.sh run
```

### Production
```bash
./cargo-isolated.sh build --release
./target/release/netget
```

### Docker (Future)
```dockerfile
FROM rust:latest
WORKDIR /app
COPY . .
RUN ./cargo-isolated.sh build --release
CMD ["./target/release/netget"]
```

## Conclusion

NetGet's architecture prioritizes:
- **Simplicity**: Only TCP/IP stack in code
- **Flexibility**: LLM handles all protocol logic
- **Modularity**: Clear component boundaries
- **Extensibility**: Easy to add features
- **User Control**: Natural language configuration

The LLM-centric design enables rapid protocol experimentation without code changes.
