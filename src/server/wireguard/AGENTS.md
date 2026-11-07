# WireGuard VPN Server Implementation

## Overview

A WireGuard VPN server that stands up a real tunnel by delegating **entirely** to `defguard_wireguard_rs`. This is the
closest thing NetGet has to a working VPN - OpenVPN (`src/server/openvpn/`) runs a real control channel but carries no
traffic, and IPSec (`src/server/ipsec/`) is a parse-and-log honeypot - but read the honesty note below before treating
it as a reference implementation.

**Status**: `DevelopmentState::Experimental` (was Stable, then Beta - see below)
**Privileges**: `PrivilegeRequirement::Root` (interface creation needs root / CAP_NET_ADMIN, and on macOS the external
`wireguard-go` binary in PATH)
**Protocol Spec**: [WireGuard White Paper](https://www.wireguard.com/papers/wireguard.pdf)
**Port**: UDP 51820 (default)

### Honesty note: this is a thin wrapper, and Experimental - not Beta, and certainly not Stable

NetGet implements **none** of the WireGuard protocol itself - no Noise_IK handshake, no ChaCha20-Poly1305, no packet
parsing. All of it lives in the platform backend that `defguard_wireguard_rs` drives: the kernel module on
Linux/FreeBSD/Windows, and the **external `wireguard-go` binary on macOS** (`wgapi_userspace.rs` does
`Command::new("wireguard-go")` and talks to it over `/var/run/wireguard/<iface>.sock`). NetGet only generates a
keypair, configures the interface, polls it every 5s, and applies LLM peer actions.

It was demoted from `Stable` to `Beta` because the project's rule for `Stable` is "real spec compliance, **validated
against a real client**", and this protocol has **never** been validated end-to-end against any real WireGuard client.
It cannot be, in CI or unprivileged: creating the interface needs root, and on macOS also `wireguard-go` installed.
That is the same defect that got `tor_relay` and `openvpn` demoted - claiming a rating the evidence doesn't support.

**That demotion undershot, and it is now `Experimental`.** "Never validated against a real client" is also precisely
what rules out **Beta** ("human-reviewed, works against real clients"), so the same evidence that took Stable away
took Beta with it, and nobody noticed for months. The Stable rating had additionally rested on a test that mocked a
`wireguard_packet_received` event and a `log_packet` action **that do not exist in this protocol**, all `#[ignore]`d
behind root so the mismatch never surfaced. When you demote for missing evidence, check which ratings that evidence
actually supports rather than stepping down one notch by reflex.

**Design defect (addressed): the reactive-only authorization model was backwards for WireGuard.** A WireGuard
responder decrypts the initiator's static public key from the handshake and **drops the handshake if that key is not
already a configured peer**. But NetGet only learns of a peer by polling `read_interface_data()` *after* it appears -
and an unconfigured peer never appears. With no user-triggered action to pre-add a peer, `wireguard_peer_connected`
could effectively never fire for a genuinely new peer, so the entire LLM authorize/reject flow was unreachable in
practice; it worked only for peers configured out-of-band.

**Fix:** the `wireguard_add_peer` user-triggered (async) action pre-authorizes a peer's public key + allowed IPs on the
live interface *before* it connects, so a subsequent handshake from that key is accepted and the peer then appears /
`wireguard_peer_connected` fires. It reaches the running `WireguardServer` through `execute_action_with_state` + a
handle registered in `spawn` (the same live-instance pattern `usb-fido2` uses; see `src/state/server_handles.rs`).
Fail-closed: with no `wireguard_add_peer` call, no peer is configured and the handshake is dropped by the backend - the
existing safe default is unchanged, this is not accept-all.

**Still unverified (why this stays Experimental).** The pre-add path's config mutation and executor wiring are
unit-tested without a backend (`build_peer_config`, the `wireguard_add_peer` executor). What has NOT been run here - no
root, and macOS lacks the external `wireguard-go` binary - is a real client actually completing a handshake against a
pre-added key, `wireguard_peer_connected` firing for it, and the event's exact timing relative to config-vs-handshake
(defguard may surface a configured-but-not-yet-handshaked peer). Earning `Stable` requires proving that end to end
(a `boringtun` in-process initiator was evaluated as that driver and deliberately not adopted; see
`tests/server/wireguard/e2e_test.rs`) plus a transport-packet exchange.

## Library Choices

### defguard_wireguard_rs v0.7

**Why chosen**:

- Multi-platform unified API (Linux kernel, macOS userspace, Windows kernel, FreeBSD kernel)
- Production-ready Rust library with active maintenance
- Handles all crypto (Curve25519, ChaCha20Poly1305, BLAKE2s)
- Automatic TUN interface creation and management
- Built-in peer monitoring and statistics

**What it provides**:

- `WGApi` - Platform-specific WireGuard API (Kernel on Linux/FreeBSD/Windows, Userspace on macOS)
- `Key` - Curve25519 keypair generation and management
- `Peer` - Peer configuration with allowed IPs, endpoints, keepalive
- `InterfaceConfiguration` - Interface setup with addresses, port, MTU
- `read_interface_data()` - Peer connection status and statistics

**Why not alternatives**:

- `boringtun` - Userspace only, more complex integration
- Manual crypto - WireGuard crypto is complex, library handles it correctly
- Native CLI (`wg`, `wg-quick`) - Violates NetGet architecture (external dependencies)

## Architecture Decisions

### TUN Interface Creation

Platform-specific interface naming:

- **Linux/FreeBSD**: `netget_wg0` (kernel WireGuard)
- **macOS**: `utun10` (wireguard-go userspace)
- **Windows**: `netget_wg0` (kernel WireGuard)

Server assigns itself `10.20.30.1` on the VPN subnet `10.20.30.0/24`.

### Peer Monitoring Loop

Spawns async task that polls `read_interface_data()` every 5 seconds:

- Detects new peer connections (peers appear when handshake succeeds)
- Updates connection stats (bytes sent/received, last handshake time, endpoint)
- Tracks peer disconnections (peers disappear from interface data)
- Integrates with NetGet's connection tracking UI

### Keypair Management

Server generates Curve25519 keypair on startup:

```rust
let private_key = Key::generate();
let public_key = private_key.public_key();
```

Public key displayed to user for client configuration. Peers authenticate with their own public keys.

### State Machine

WireGuard handles its own state machine internally. NetGet tracks:

- **Peer tracking**: `HashMap<String, ConnectionId>` mapping public keys to connection IDs
- **Connection state**: Active when peer appears in interface data, Closed when removed
- **Max peers**: 100 peer limit to prevent resource exhaustion

## LLM Integration

### Event flow

The monitoring loop (`monitor_peers`) polls `read_interface_data()` every 5 seconds. The first time a peer appears it:

1. Registers a `ConnectionState` in `AppState`
2. Builds a `wireguard_peer_connected` `Event`
3. Calls `crate::llm::action_helper::call_llm(...)`

`call_llm` tries any configured script/static event handler first and only performs a real LLM call when none is
configured, so a scripted WireGuard server costs zero model calls. Exactly one event is raised per peer connect (not
per poll), so LLM traffic is bounded by peer churn.

The returned `raw_actions` are applied to the live interface in `handle_peer_connected`.

### Async Actions (User-triggered)

**`wireguard_add_peer`** - pre-authorize a peer by adding its public key + allowed IPs (optional endpoint) to the live
interface *before* it connects. This is the action that makes the authorize flow reachable (see the design-defect note
above). Parameters: `public_key` (required), `allowed_ips` (required, CIDR list), `endpoint` (optional). It reaches the
running server via `Server::execute_action_with_state`, which looks up the `Arc<WireguardServer>` registered in `spawn`
with `AppState::register_server_handle` and calls `add_peer()`. Fail-closed: a malformed key, an invalid/empty
`allowed_ips`, or a missing server all return `Err` rather than configuring anything. On the stateless path
(`execute_action`, no server context) it errors rather than silently succeeding.

`list_peers` / `remove_peer` / `get_server_info` are still **not** advertised: the same live-instance pattern could now
carry them, but they were dead no-ops (they returned `NoAction` with no data) and are left unadvertised rather than
half-built.

### Sync Actions (raised by `wireguard_peer_connected`)

1. **authorize_peer**: (re)configure the peer with specific allowed IPs via `wgapi.configure_peer()`
    - Parameters: `public_key` (required), `allowed_ips` (required, CIDR list), `endpoint`, `message`
    - Defaults to the event's own public key / allowed IPs if omitted
2. **reject_peer**: remove the peer from the interface (same effect as `disconnect_peer`)
3. **set_peer_traffic_limit**: **NOT ENFORCED** - logged only. No tc/iptables configuration is performed.
4. **disconnect_peer**: remove the peer from the interface, tearing down its tunnel

### Decision logging on the peer-connected event

`handle_peer_connected` emits one stable `decision=` token per event so the outcomes cannot be
confused with each other in the log (the `radius` separation, applied here):

| token | meaning |
|---|---|
| `model_authorize` / `model_reject` | the model changed the interface (and `*_failed` when the change itself errored) |
| `model_authorize_invalid` | an `authorize_peer` with no usable `allowed_ips`, ignored |
| `model_no_action` | the model deliberately answered with nothing — "leave the peer as-is" |
| `fail_closed_llm_error` | the LLM call errored; no decision was produced (logged at ERROR, with a `category=overloaded\|unavailable` classification from `crate::utils::WireFailure`) |

**Nothing is written to the peer on failure, and that is correct.** WireGuard has no error
frame, and the peer's handshake has already completed in the backend before the event fires, so
no peer is blocked waiting for an answer. The peer is also *not* removed on an LLM error: it is
only on the interface because an explicit earlier `wireguard_add_peer` authorized its key
(unconfigured keys are dropped by the backend), so tearing it down would convert a backend
hiccup into a VPN outage for an already-authorized peer. The full error goes to the file log and
the TUI status stream only — never to the wire.

### Event Types

- `wireguard_peer_connected`: peer completed its handshake and appeared on the interface

Data fields: `public_key`, `endpoint`, `allowed_ips`, `server_public_key`, `listen_port`.

**Important**: WireGuard performs its Noise handshake inside the kernel (or wireguard-go) backend. NetGet observes
peers *after* the handshake succeeds and therefore **cannot gate a handshake before it completes**. `authorize_peer`
sets post-connection policy; `disconnect_peer`/`reject_peer` remove a peer that already got on. A `wireguard_peer_request`
event was previously declared but never emitted by any code path - it has been removed rather than left as a false promise.

## Connection Management

### Peer Detection

Peers detected when they appear in `interface_data.peers` after successful handshake:

```rust
for (pub_key, peer) in interface_data.peers.iter() {
    // The `peers` guard is taken and dropped around each lookup, never held across the
    // LLM call or a WireGuard API call below - add_peer/remove_peer take the same locks.
    if !known {
        let connection_id = ConnectionId::new(app_state.get_next_unified_id().await);
        // ... insert, then add_connection_to_server(server_id, conn_state)
    } else {
        app_state.update_connection_stats(server_id, connection_id, rx, tx, None, None).await;
    }
}
```

### Stats Tracking

Each peer connection tracked with:

- `bytes_sent`: Total transmitted bytes (from `peer.tx_bytes`)
- `bytes_received`: Total received bytes (from `peer.rx_bytes`)
- `last_handshake`: Timestamp of last handshake
- `endpoint`: Client's UDP endpoint (IP:port)
- `allowed_ips`: VPN IP addresses assigned to peer

### Cleanup

Disconnected peers removed when they disappear from interface data:

```rust
for peer_key in disconnected_peers {
    if let Some(connection_id) = peers.remove(&peer_key) {
        app_state.close_connection_on_server(server_id, connection_id).await;
    }
}
```

### No inbound size bound to declare

NetGet opens no socket for WireGuard. The UDP listen port is handed to
`defguard_wireguard_rs`, which configures the kernel module (Linux) or `wireguard-go`
(macOS), and that backend is what receives and decrypts every datagram. The only thing NetGet
reads is `read_interface_data()` — peer keys, endpoints and byte counters from the local
backend, never bytes a peer chose. So `metadata()` declares no `max_inbound_bytes`, and
`tests/max_inbound_bytes_declaration_test.rs` lists `wireguard` beside the BLE profiles as a
protocol with no read loop of its own, with that reason. There is no bound + 1 test because
there is no NetGet read for one to reach, and this server cannot be started unprivileged here
anyway.

## State Management

### Server State

```rust
pub struct WireguardServer {
    _interface_name: String,
    wgapi: Arc<RwLock<WGApi<Backend>>>,  // Kernel or Userspace based on OS
    _private_key: String,
    public_key: String,
    listen_port: u16,
    peers: Arc<RwLock<HashMap<String, ConnectionId>>>,
}
```

### Protocol Connection Info

`ProtocolConnectionInfo` is a generic `serde_json::Value` wrapper (`src/state/server.rs`), not an enum with a
per-protocol variant, and this server stores `ProtocolConnectionInfo::empty()` for a peer - the peer's public key,
endpoint and allowed IPs reach the model through the `wireguard_peer_connected` event instead. (This section used to
show a `ProtocolConnectionInfo::Wireguard { .. }` variant; no such variant has ever existed.)

## Limitations

### Requires Elevated Privileges

- **Linux/FreeBSD**: Root or `CAP_NET_ADMIN` capability
- **macOS**: root **and** an external `wireguard-go` binary on `PATH` - defguard's userspace backend shells out to it
  (`Command::new("wireguard-go")`) and talks to it over `/var/run/wireguard/<iface>.sock`. It is not bundled with the
  Rust library and nothing installs it for you; without it the server cannot start at all
- **Windows**: Administrator privileges

### Network Configuration

- **No automatic routing**: Server doesn't configure IP forwarding or NAT
- **Static subnet**: Always uses `10.20.30.0/24`
- **No IPv6**: Currently IPv4-only
- **No dynamic IP assignment**: LLM must manually assign IPs via `allowed_ips`

### Platform-Specific Behaviors

- **macOS**: Uses userspace wireguard-go (slower but works without kernel module)
- **Linux**: Uses kernel WireGuard (fastest, requires kernel 5.6+ or module)
- **Windows**: Uses kernel WireGuard (requires WireGuard driver installed)

### Peer Management

- **Max 100 peers**: Hard-coded limit, enforced in `add_peer` only
- **No traffic limiting**: `set_peer_traffic_limit` is logged but never enforced
- **No QoS**: All peers treated equally
- **Up to 5s detection latency**: peers are discovered by polling, not by handshake callback

### Task Lifecycle

The monitoring task's `JoinHandle` is registered with `AppState::register_server_task()`, so `stop_server` aborts it.
Note that `register_server_task` stores a *single* handle per server - a protocol that needs several long-lived loops
must combine them into one task (e.g. `tokio::select!`) rather than calling it twice.

## Examples

### Server Startup

```
netget> Start a WireGuard VPN server on port 51820
```

LLM response:

```json
{
  "actions": [
    {
      "type": "notify_operator",
      "message": "Starting WireGuard VPN server on UDP port 51820. Generating keypair and creating TUN interface..."
    }
  ]
}
```

Server output:

```
[INFO] Starting WireGuard VPN server on 0.0.0.0:51820 (full VPN tunnel support)
[INFO] Server public key: xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
[INFO] Creating interface: netget_wg0
[INFO] Interface created successfully
[INFO] Interface listening on UDP port 51820
[INFO] VPN subnet: 10.20.30.0/24
→ WireGuard VPN server ready on 0.0.0.0:51820
[INFO] Clients can connect using server public key: xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
```

### Peer Connection

When peer connects, monitoring loop detects it:

```
[INFO] New WireGuard peer connected: xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
```

LLM can authorize with allowed IPs:

```json
{
  "actions": [
    {
      "type": "authorize_peer",
      "peer_public_key": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
      "allowed_ips": ["10.20.30.2/32"]
    },
    {
      "type": "notify_operator",
      "message": "Peer authorized with VPN IP 10.20.30.2"
    }
  ]
}
```

### Client Configuration

Clients configure using server's public key:

```ini
[Interface]
PrivateKey = <client_private_key>
Address = 10.20.30.2/32

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = <server_ip>:51820
AllowedIPs = 0.0.0.0/0  # Route all traffic through VPN
```

## References

- [WireGuard White Paper](https://www.wireguard.com/papers/wireguard.pdf)
- [defguard_wireguard_rs Documentation](https://docs.rs/defguard_wireguard_rs/)
- [WireGuard Protocol Spec](https://www.wireguard.com/protocol/)
- [Curve25519](https://cr.yp.to/ecdh.html)
- [ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439)
