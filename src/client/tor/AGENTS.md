# Tor Client Implementation

## Overview

The Tor client enables NetGet to make anonymous connections through the Tor network using the Arti library (a pure Rust
implementation of Tor).

## It does not reach the internet by default (read this first)

`arti_client::TorClient::create_bootstrapped()` contacts the **real Tor directory authorities
before it ever looks at the requested address** - measured at 14 seconds in an unguarded run.
So merely *opening* a Tor client made outbound connections to third parties, whatever
destination the caller asked for, in a tool that binds loopback everywhere else. It also made
the client impossible to exercise offline: the whole-registry startup smoke test carried a
named exclusion for Tor rather than run it.

`connect()` now refuses unless the caller states where to bootstrap from
(`bootstrap_target()` in `mod.rs`):

| `directory_server` | `allow_public_tor_network` | Outcome |
|---|---|---|
| set | unset/false | bootstrap from that directory (normally a local `tor_relay`) |
| unset | `true` | bootstrap from the public Tor directory authorities, logged at WARN |
| unset | unset/false | **`Err`**, naming both parameters and saying why - the default |
| set | `true` | **`Err`**: contradictory, and guessing is how a "local test" reaches the internet |

Deferring the bootstrap until "a request needs the network" was considered and rejected:
`connect()` is *given* the destination, so the need is immediate and the bootstrap would happen
milliseconds later anyway, with the failure surfacing somewhere with worse reporting than
`connect()`'s `Err`. Laziness would hide the reach, not prevent it. The property worth having
is that the reach is a decision the caller made.

Pinned by `tests/client/tor/test.rs`, including a `connect()` that must refuse in under 3s -
anything near 14s means it contacted a directory authority before refusing. The smoke test's
`CLIENT_SKIPS` is now empty and Tor is swept like every other client.

## The model's answer is executed (August 2026)

Two of the three LLM call sites asked the model what to do and threw the answer away — the
defect class described in the root CLAUDE.md under "Known systemic issues". Both are fixed:

| Event | Was | Now |
|---|---|---|
| `tor_connected` | `Ok(_) => trace!("LLM called successfully")` | actions executed against the circuit |
| `tor_bootstrap_complete` | `if let Err(e) = call_llm_for_client(..)` — no success arm at all | actions executed; no circuit exists yet, so the directory verbs are the ones that can act and a `send_tor_data` is refused **out loud** |
| `tor_data_received` | executed (correct) | executed through the same shared function |

Three things this changed beyond "the answer is used":

- **`disconnect` now actually disconnects.** It used to `break` the `for action in actions`
  loop and nothing else, so it stopped executing the rest of that one answer and went straight
  back to reading. The model could not close a Tor client at all. `apply_actions` returns
  `true` and the read loop breaks on it.
- **The `tor_connected` call moved inside the read-loop task**, after
  `register_command_channel`. It needs the write half to carry out what the model answers
  with, and per the root CLAUDE.md a manual `*` routing rule parks this call until a human
  answers — the dashboard's `[ send ]` has to reach the client for the whole park, which it
  could not when the call preceded registration.
- **The directory verbs live in one function** (`run_directory_action`), not inlined in the
  read loop, so the bootstrap path can reach them. That is the point: `tor_bootstrap_complete`
  reports `relay_count` and `valid_after` precisely so the model can query the consensus it
  just learned about, and until now every such query was discarded.

No depth bound is needed. Reporting a directory result raises no event, and the only recursive
path — `tor_data_received` → action → more data — is driven one iteration at a time by the read
loop, the same shape as `datalink`.

**Not proven end-to-end.** `tests/client/tor/e2e_test.rs` is `#[ignore]`d because arti needs a
full real consensus that `tor_relay` cannot serve, so there is no test in which a real peer
observes these actions on the wire. `tests/client/tor/apply_actions_test.rs` pins the executor's
contract directly instead — the disconnect return, the loud refusal with no circuit, and a
rejected verb reaching the operator. Treat the wire behaviour as unverified.

## Library Choice

**Arti** (`arti-client` v0.36)

- Official Tor Project implementation in Rust
- Pure Rust (no C dependencies)
- Production-ready (v1.0.0 released)
- Full async/await support with Tokio integration
- Supports regular connections and onion services (.onion addresses)

**Why Arti:**

- Mature and well-maintained by Tor Project
- Safer than C Tor due to memory safety
- Native Tokio integration (AsyncRead + AsyncWrite)
- Simpler API than alternative libraries
- Supports all Tor features we need: exit nodes, onion services, circuit isolation

## Architecture

### Connection Flow

1. **Bootstrap**: Create `TorClient` and bootstrap consensus documents from directory authorities
2. **Circuit Building**: Arti automatically builds circuits through 3+ relays
3. **Connection**: Use `TorClient::connect(target)` to establish anonymized stream
4. **Data Exchange**: Read/write through `DataStream` (implements AsyncRead/AsyncWrite)
5. **LLM Integration**: Call LLM on connection and data received events

### Key Components

- `TorClient` (from arti): Main client instance, manages circuits and connections
- `DataStream` (from arti): Individual anonymized connection (like TcpStream)
- `run_circuit`: the session loop over one open circuit, generic over the stream halves

### Batching (what arrives while the model is answering)

The circuit is read on a registered task of its own (`client/inbound_queue.rs`, shared with
the other proxied byte-stream clients), feeding a bounded queue of reads (32). The answering
loop takes one read per model call with batching off, and with batching on joins everything
already waiting into one payload, as the `tcp` client does. Declared `BatchingMode::On`.
This replaced an Idle/Processing/Accumulating machine that could never leave Idle — the loop
read, called the model and wrote in sequence — and "cleared" a queue nothing filled: nothing
was lost, but what arrived during a call merged in the kernel buffer, so batching off and on
could not be told apart. A `disconnect` the model returns now ends the session (it used to
break only the loop over that answer's actions). Test: `tests/client/tor/batching_test.rs`.

`run_circuit` is `pub` and generic over the stream halves for that test: a real circuit needs a
full Tor bootstrap, so the test drives the same loop over a plain local socket.

## LLM Integration

### Events

1. **`tor_connected`**: Triggered when connection established through Tor
    - Parameters: `target` (destination address)
    - LLM can send initial data or wait for response

2. **`tor_data_received`**: Triggered when data received from destination
    - Parameters: `data`, `encoding` (`"utf8"` or `"hex"`), `data_length`
    - Printable ASCII arrives as itself; anything else arrives hex-encoded and `encoding` says
      so. Handing `data` and `encoding` straight back to `send_tor_data` reproduces the
      received bytes exactly. It used to carry `data_hex` only, so even a plain HTTP response
      reached the model as hex it had to decode in its head.
    - LLM decides how to respond (send data, wait for more, disconnect)

### Actions

**Async Actions** (user-initiated):

- `send_tor_data(data, encoding?)`: Send a payload to the destination
- `disconnect`: Close the circuit

**Sync Actions** (response to events):

- `send_tor_data(data, encoding?)`: Send a payload in response to received data
- `wait_for_more`: Queue current data and wait for more before responding

### `data` and `encoding`, and what happened to `data_hex`

`send_tor_data` declares two parameters: `data`, the payload, and `encoding`, which is
`"utf8"` (the default when omitted) or `"hex"`. **Nothing is sniffed.** `"48656c6c6f"` is a
perfectly good five-byte payload and a perfectly good ten-character one, and only the sender
knows which it meant — the `send_tcp_data` rule in the root CLAUDE.md, applied here.

It used to declare a single `data_hex` field, so the static-mode startup example showed
`GET / HTTP/1.1` and a `Host:` header as 74 hex characters: a request the model could not
read, could not point at another host or path, and could not check.

Backward compatibility is a decision, not an accident:

| sent | outcome |
|---|---|
| `data` (+ optional `encoding`) | the declared path |
| `data_hex` alone | still decoded as hex — an existing static handler or stored prompt keeps working |
| **both** | **refused**, naming both fields and saying that neither takes precedence |
| neither | refused, naming `data` |

`data_hex` is deliberately **not** advertised any more: re-declaring it would put hex back in
the model's vocabulary, which is the whole thing this change removed. It is executed, not
documented, and `tests/client/tor/action_test.rs` pins every row of that table — including
that a `data` of `"deadbeef"` with `encoding` absent goes out as those eight characters.

### LLM Prompt Example

```
You are controlling a Tor client connected to example.com:80.
Your instruction: "Send HTTP GET request for / and analyze response"

Available actions:
- send_tor_data: Send a payload ('data', plus 'encoding' when it is binary)
- disconnect: Close connection
- wait_for_more: Wait for more data

Event: tor_connected
Target: example.com:80

What action do you take?
```

## Directory Query Capabilities (NEW)

The Tor client can now query the Tor network directory (consensus) for relay information using Arti's experimental API.

### Arti Integration

Uses Arti's `experimental-api` feature to access the directory manager:
- `tor_client.dirmgr()` - Access directory manager
- `dirmgr.netdir()` - Get current network directory (NetDir)
- `netdir.relays()` - Iterate over all relays in consensus

### Dependencies

- `tor-dirmgr` v0.36 - Directory manager types
- `tor-netdir` v0.36 - Network directory queries and relay iteration

### Directory Actions

**get_consensus_info** - Get consensus metadata:
```json
{
  "type": "get_consensus_info"
}
```
Returns: relay_count, valid_after, fresh_until, valid_until timestamps

**list_relays** - List all relays (with limit):
```json
{
  "type": "list_relays",
  "limit": 50
}
```
Returns: Array of RelayInfo (nickname, fingerprint, flags, etc.)

**search_relays** - Filter relays by criteria:
```json
{
  "type": "search_relays",
  "flags": ["Guard", "Exit", "Fast"],
  "nickname": "example",
  "limit": 20
}
```
Returns: Matching relays with specified flags and/or nickname pattern

### RelayInfo Structure

Each relay returned contains:
- `nickname`: Relay nickname (string)
- `fingerprint`: RSA identity fingerprint (string)
- `flags`: Array of flags (Guard, Exit, Fast, Stable, Running, Valid)
- `is_guard`: Boolean flag indicators
- `is_exit`, `is_fast`, `is_stable`, `is_running`, `is_valid`

### Events

**`tor_bootstrap_complete`**: Triggered after consensus downloaded
- Parameters: `relay_count`, `valid_after`
- LLM can immediately query directory information

### Use Cases

1. **Network Analysis**: Analyze Tor network topology and relay distribution
2. **Relay Research**: Study relay flags, bandwidth, and availability
3. **Circuit Planning**: Choose specific relays before building circuits (future enhancement)
4. **Testing**: Verify consensus format and relay data from `tor_relay` server (via BEGIN_DIR)
5. **Monitoring**: Track relay count and consensus validity times

### Implementation Details

**State Storage**: `ArtiClient` instances stored in `AppState` after bootstrap
- Enables directory queries without active connection
- Stored by client_id for per-client consensus access

**Query Methods** (in `TorClient`):
- `get_netdir()` - Returns `Arc<NetDir>` from Arti's directory manager
- `query_relays()` - Filters relays using `RelayFilter` criteria
- `get_consensus_info()` - Extracts consensus metadata (relay count, validity)

**Filter Criteria** (`RelayFilter`):
- `flags`: Required relay flags (e.g., ["Guard", "Exit"])
- `nickname_pattern`: Substring match on nickname
- `limit`: Maximum results to return

### Limitations

- **Requires experimental-api**: Arti's directory access API may change in future versions
- **Read-only**: Cannot modify consensus or inject relay data
- **No signature control**: Arti automatically verifies consensus signatures
- **Consensus staleness**: Directory queries reflect Arti's cached consensus (updated hourly)

### Example Usage

**Query consensus after bootstrap**:
```
open_client tor "example.com:80" "After connecting, list all exit relays in the network"
```

**LLM Flow**:
1. Event: `tor_bootstrap_complete` (relay_count: 7234)
2. LLM Action: `search_relays` with flags: ["Exit", "Fast"]
3. Result: 1523 exit relays
4. LLM analyzes relay distribution, chooses exit node criteria

**Network analysis without connection**:
```
open_client tor "unused:80" "Don't connect anywhere. Just analyze the Tor network: show distribution of guard vs exit relays, and report the top 10 fastest relays"
```

## Tor-Specific Features

### Onion Services

The client automatically supports `.onion` addresses:

```rust
TorClient::connect("exampleonion3sd.onion:80").await?
```

Arti handles:

- Hidden service descriptor lookups
- Introduction point connections
- Rendezvous point circuits

### Circuit Isolation

Arti provides automatic circuit isolation:

- Each `TorClient` instance uses isolated circuits
- For additional isolation, use `TorClient::isolated_client()`
- Prevents traffic correlation between different connections

### Exit Node Selection

Currently uses Arti's default exit node selection:

- Weighted by bandwidth and flags
- Avoids bad exits (via consensus)
- Future enhancement: LLM control via `StreamPrefs`

### DNS Resolution

All DNS resolution happens through Tor:

- Prevents DNS leaks
- `connect()` accepts hostname:port, not IP addresses
- DNS queries sent through exit node

## Limitations

1. **Bootstrap Time**: Initial connection takes 10-30 seconds to fetch consensus
    - Mitigated: Arti caches consensus between runs
    - Future: Show bootstrap progress to user

2. **Performance**: Tor adds latency (3+ hops)
    - Typical latency: 100-500ms
    - Bandwidth: Limited by slowest relay

3. **No Direct Circuit Control**: Arti abstracts circuit management
    - Can't manually select specific relays
    - Can't force circuit rebuild (yet)
    - Exit node selection uses Arti's defaults

4. **Text by default, hex on request**: the LLM writes a payload into `data` and says how to
   read it with `encoding`
    - Same pattern as the TCP client's `send_tcp_data`
    - Text protocols (HTTP, IRC, …) are written and read as themselves
    - Binary payloads use `"encoding": "hex"`, explicitly, never by detection

5. **No Bridge Support Yet**: No pluggable transport support in this implementation
    - Arti supports bridges, but not exposed in our API
    - Future enhancement

6. **Connection Identification**: No true local address
    - Returns dummy `127.0.0.1:0` as local_addr
    - Tor connections don't have real local sockets

## Security Considerations

### What Tor Provides

- **Anonymity**: Hides client IP from destination
- **Untraceability**: Difficult to link multiple connections
- **Censorship Resistance**: Can access blocked sites

### What Tor Doesn't Provide

- **End-to-End Encryption**: Use HTTPS/TLS on top of Tor
- **Traffic Content Privacy**: Exit nodes can see unencrypted traffic
- **Malware Protection**: Tor doesn't scan for malware
- **DNS Security**: Exit node handles DNS (use DoH on top of Tor for more privacy)

### LLM Considerations

- LLM has full control over data sent through Tor
- LLM can leak identity through application-layer data (e.g., including real IP in HTTP headers)
- Instruction should emphasize privacy if needed

## Testing Strategy

See `tests/client/tor/AGENTS.md` for testing details.

### Local Testing

1. **Arti Bootstrap**: First run downloads ~1-3MB consensus
2. **Test Destinations**: Use public test sites or local onion services
3. **LLM Budget**: Keep bootstrap time in mind (doesn't count toward LLM calls)

### Public Test Sites

- `check.torproject.org`: Verifies you're using Tor
- `httpbin.org`: HTTP testing (accessible through Tor)
- DuckDuckGo onion: `duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion`

### Local Testing with tor_relay

**SUCCESS**: Arti CAN now bootstrap from a localhost Tor relay with BEGIN_DIR support!

**Solution**: The `directory_server` startup parameter allows bootstrapping from a local `tor_relay` server:

```rust
// Works: Bootstrap from local tor_relay
TorClient::connect_with_llm_actions(
    "example.com:80",
    llm_client,
    app_state,
    status_tx,
    client_id,
    Some(startup_params_with_directory_server)  // e.g., "127.0.0.1:9001"
).await?
```

**How It Works**:
1. Arti connects to local `tor_relay` via TLS (OR protocol)
2. Creates Tor circuit using CREATE2/ntor handshake
3. Sends BEGIN_DIR cell to request directory over circuit
4. `tor_relay` responds with consensus document via DATA cells
5. Arti parses consensus and completes bootstrap

**Architecture**:
- `tor_relay` speaks OR protocol (Arti's `FallbackDir` requirement met ✅)
- Directory documents served OVER circuits via BEGIN_DIR
- Matches real Tor architecture (directory authorities work this way)
- Fully local testing without internet access

**Status**:
- ✅ Circuit creation works
- ✅ BEGIN_DIR cell handling works
- ✅ Consensus served correctly
- ⚠️  Arti bootstrap may fail on signature validation (consensus uses dummy signature)

**Testing**:
```json
{
  "type": "open_client",
  "protocol": "Tor",
  "remote_addr": "example.com:80",
  "startup_params": {
    "directory_server": "127.0.0.1:9001"
  }
}
```

**Alternative**: for the real Tor network, opt in explicitly. Omitting both parameters is
refused, not defaulted - see *It does not reach the internet by default* above:
```json
{
  "type": "open_client",
  "protocol": "Tor",
  "remote_addr": "example.com:80",
  "startup_params": {
    "allow_public_tor_network": true
  }
}
```

## Future Enhancements

1. **Bootstrap Progress**: Show directory fetch progress to user
2. **Bridge Support**: Add pluggable transport configuration
3. **Circuit Control**: Expose circuit rebuild, exit node selection via StreamPrefs
4. **Onion Service Hosting**: Add server-side onion service support
5. **Persistent Identity**: Maintain client identity across restarts
6. **Hidden Service Client Auth**: Support client authentication for private onion services

## Dependencies

- `arti-client` v0.36: Main Tor client library
- `tor-rtcompat` v0.36: Runtime compatibility layer (Tokio integration)

Both are official Tor Project crates, actively maintained.

## References

- [Arti Documentation](https://tpo.pages.torproject.net/core/doc/rust/arti_client/)
- [Tor Protocol Specification](https://spec.torproject.org/)
- [Onion Services](https://community.torproject.org/onion-services/)
