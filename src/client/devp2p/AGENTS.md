# devp2p client (Ethereum dialler)

**Status**: `DevelopmentState::Experimental`. Two independent servers drive it in tests that
fail rather than skip — go-ethereum 1.17 serving a chain it sealed, and reth 2.7 in `--dev`
mode — with the model's requests asserted by what the real node answered. Nobody has reviewed
it, and the `devp2p` pair job had not run in CI when this was written.

Same feature (`devp2p`) and the same wire code as the server (`crate::server::devp2p::*`):
after the handshake both ends of a devp2p session speak the same protocol, so the actions and
most events are the server's (`crate::server::devp2p::actions`).

## Connect

`remote_addr` is an **enode URL** (`enode://<128 hex>@host:port`; `?discport=` ignored) — the
handshake needs the node's public key, so a bare `host:port` is refused. `connect()` does TCP
(10 s) and `session::establish` as the initiator (handshake + Hello, 10 s), then returns; the
model is never consulted inside it, so a parked manual answer cannot stall creation. Startup
parameters are the server's: `node_private_key`, `client_id`, and the Status defaults.

## Status

go-ethereum and reth send their Status as soon as Hello is done; the session waits
`STATUS_WAIT` (1.5 s) for it and raises `eth_status` either way — with `peer_status`, or with
`peer_status: null` when the peer waits for ours (another NetGet node does: its server waits for
the dialler). Requests the model gives alongside `eth_send_status` are held until both
Statuses are exchanged. A Status on another network or genesis is logged; the peer decides.

## Running

The reader task (`session::read_loop`) answers Ping. The session task owns the model turns
(`call_llm_for_client`, client `event_handlers` first), the injected commands
(`send_to_client`), a Ping every 15 s, and request timeouts. Events are the server's
session events plus `devp2p_error` (an action refused — the model is told once, and what it
answers then is carried out without a further error event) and `devp2p_disconnected`.
Follow-up chains stop at `MAX_FOLLOWUP_DEPTH` (8): a request's answer is one turn deeper than
the turn that asked.

Received headers are decoded with their computed hashes and checked against the question:
`matches_request` (the numbers, or the first hash) and `linked` (each names the previous as
parent). More items than were asked for is a protocol breach (Disconnect, never shown to the
model).

## Failing closed

`eth_status` with no answer → Disconnect `subprotocol_error`; answered without
`eth_send_status` → Disconnect `useless_peer` (`decision=model_reject`); a peer request still
owed after the model's turn → Disconnect `subprotocol_error`
(`decision=fail_closed_unanswered`). Malformed messages and the bounds behave as on the server
(`src/server/devp2p/AGENTS.md`).

## Not implemented

Discovery (the peer is named by its enode), snap, body validation against
`transactionsRoot`, eth/66–67 and eth/70+.
