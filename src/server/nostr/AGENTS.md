# Nostr Relay Implementation

A Nostr relay: NIP-01 over WebSocket, and the NIP-11 relay information document on a plain
HTTP GET. The model is the relay's policy and its archive — it decides which published events
are taken and which events answer a subscription. NetGet owns everything NIP-01 makes
mechanical: ids, signatures, filters, framing, subscription bookkeeping.

**State**: Beta (see Maturity). **Privilege**: `None`. **Well-known port**: none — see
below. **Stack**: `ETH>IP>TCP>HTTP>WS>NOSTR`. **Feature**: `nostr` (`tokio-tungstenite`,
`secp256k1`, `sha2`).

## Library choice

- **WebSocket**: the HTTP head and the RFC 6455 upgrade are hand-written in `http.rs`, because
  the same URL answers NIP-11 to a GET carrying `Accept: application/nostr+json`, so the head
  has to be read before anything knows whether it is a WebSocket at all. The upgraded socket is
  handed to `tokio_tungstenite::WebSocketStream::from_partially_read` (0.21, the version
  `websocket` uses) for framing, masking, pings and the closing handshake — the `websocket`
  server's approach.
- **Ids and signatures**: `sha2` for the id, `secp256k1` 0.29 for BIP-340 Schnorr — the same
  crate and version `bitcoin` already links, so the tree carries one curve library.
- **No Nostr crate.** NIP-01's surface is small, and the parts that must be exact (the id
  serialisation, filter matching) are pure functions in `wire.rs` the tests drive directly.
  That also keeps the evidence honest: the peers the tests drive (nak, rust-nostr) share no
  protocol code with this server.

## Files

| File | What it holds |
|---|---|
| `mod.rs` | accept loop, request head, the upgrade/NIP-11/browser dispatch, the WebSocket session (reader, model worker, writer), the failure texts, `FrameWriter` for the peer handle |
| `http.rs` | head parsing, upgrade validation, the 101, HTTP responses with CORS, the NIP-11 document |
| `wire.rs` | NIP-01: the three id serialisations, `verify_event`, `RelayKey` (sign), filters and `select_events`, `parse_client_message` and its refusals, relay message rendering, the model's events |
| `subscriptions.rs` | per-connection open subscriptions (`ConnShared`) and the relay-wide connection set used for live delivery (`Relay`) |
| `actions.rs` | the `Protocol`/`Server` impls, six actions, `nostr_event` and `nostr_req`, the `answer_with` texts |

## Spec subset

**HTTP, one request head per connection:**

| Request | Answer |
|---|---|
| `GET` with `Upgrade: websocket` (RFC 6455 §4.2.1 checks) | `101`, then NIP-01 |
| a bad upgrade | `400` / `405` / `426` (+ `Sec-WebSocket-Version: 13`) / `505`, `decision=fail_closed_bad_upgrade` |
| `GET` with `Accept: application/nostr+json` | NIP-11 document (`application/nostr+json`, CORS headers), `decision=relay_info` |
| `OPTIONS` | `204` with the CORS headers NIP-11 requires |
| any other `GET` | `200 Please use a Nostr client to connect.` (nostr-rs-relay's page) |
| any other method | `405` |

The NIP-11 document is built from startup parameters and the relay's own limits, never the
model: `name` (`relay_name`), `description` (`relay_description`), `supported_nips`
(default `[1, 11]`), `self` (the relay's signing pubkey), `software`, `version`, and
`limitation` {`max_message_length`, `max_subscriptions`, `max_filters`, `max_subid_length`,
`max_event_tags`, `auth_required: false`, `payment_required: false`}.

**NIP-01, client → relay:** `EVENT`, `REQ`, `CLOSE`. **Relay → client:** `EVENT`, `OK`,
`EOSE`, `CLOSED`, `NOTICE`.

**Answered by NetGet, no model call:**

| Message | Answer | `decision=` |
|---|---|---|
| not JSON, not an array, no verb, too deep | `NOTICE invalid: …` | `fail_closed_malformed` |
| `COUNT`, `AUTH`, any other verb | `NOTICE error: unsupported message type …` | `fail_closed_unsupported` |
| a binary frame | `NOTICE invalid: …` | `fail_closed_malformed` |
| `EVENT` with a malformed field | `OK <id> false invalid: …` (or `NOTICE` when no usable id) | `fail_closed_invalid_event` |
| `EVENT` whose id is not the hash of its content | `OK <id> false invalid: event id does not match …` | `fail_closed_invalid_id` |
| `EVENT` whose signature does not verify | `OK <id> false invalid: signature does not verify` | `fail_closed_invalid_signature` |
| `REQ` with an empty or over-long id | `NOTICE` / `CLOSED invalid: …` | `fail_closed_bad_subscription_id` |
| `REQ` with no filter, a malformed filter | `CLOSED invalid: …` | `fail_closed_bad_filter` |
| `REQ` with more than 10 filters | `CLOSED invalid: …` | `fail_closed_too_many_filters` |
| `REQ` past 20 open subscriptions | `CLOSED rate-limited: …` | `fail_closed_too_many_subscriptions` |
| a message past 64 waiting for the model | `OK false rate-limited: …` / `CLOSED rate-limited: …` | `fail_closed_queue_full` |
| `CLOSE` | nothing; the subscription is gone | `subscription_closed` |

A `REQ` reusing an open id replaces it (NIP-01). Filter keys NIP-01 does not define (`search`)
are shown to the model and not matched on; they must be scalars or flat arrays.

**Not implemented:** NIP-42 `AUTH`, NIP-45 `COUNT`, replaceable / parameterised-replaceable /
ephemeral kind semantics, NIP-13 proof-of-work checks (the model may still refuse with `pow:`),
NIP-40 expiration. Prefix matching on `ids`/`authors` (removed from NIP-01) is not supported;
they must be full 64-character hex.

## The id serialisation — where the implementations disagree

For text with no C0 control other than `\n \r \t`, every implementation serialises the id input
the same way. For text with one (U+0008, U+000C, U+0001…), three forms are in use, and this was
measured with nak rather than assumed:

| Form | `\b` `\f` | other C0 | Who |
|---|---|---|---|
| JSON | `\b` `\f` | `\u00xx` | `serde_json`, nostr-tools, rust-nostr |
| NIP-01 read literally | `\b` `\f` | raw | the spec text |
| go-nostr | raw | raw | nak 0.20.7 (and so go-nostr clients) |

`verify_event` accepts an id under any of the three and computes the extra two only when the
text contains such a character. This admits no event its author did not sign: each form is an
injective escaping whose decoding is the original text, so two different events cannot share a
serialisation, and the signature is over the id. Events NetGet signs use the JSON form, and
`parse_supplied_event` drops those characters from what the model supplies, so every client
computes the same id for them.

## What the model sees and controls

**`nostr_event`** `{id, pubkey, kind, created_at, tags (first 50), tag_count, content (first 4096
bytes), content_truncated, answer_with}` — only ever an event whose id and signature verified.
Answers: `accept_nostr_event {}` → `OK true ""` and delivery to every open subscription it
matches, on every connection (the publisher's own included), with the author's own id and
signature; `reject_nostr_event {reason}` → `OK false <reason>`. The reason keeps a NIP-01 prefix
(`duplicate: pow: blocked: rate-limited: invalid: restricted: error:`) if it has one, otherwise
`blocked:` is added. The event's `answer_with` and the action's example say that after the
prefix the reason is the message the instructions give the author, in their exact words: told
to refuse adverts "telling the author that adverts are not allowed", llama3.1:8b wrote reasons
of its own ("blocked: advertisement", "blocked: Advert") five runs in five (real-model eval,
seed 42), and replayed with that sentence five seeds in five used the operator's words.

**`nostr_req`** `{subscription_id, filters (as sent), relay_pubkey, answer_with}`. Answers:
`send_nostr_events {events: [{kind, content, tags?, created_at?}], subscription_id?}` → NetGet
signs each with the relay key, keeps those the REQ's filters select, sends them, then `EOSE`;
`close_nostr_subscription {reason, subscription_id?}` → `CLOSED <reason>` (default prefix
`restricted:`) and no `EOSE`.

**Why the model's events are signed by the relay, not by their nominal authors.** A model cannot
produce a BIP-340 signature — it is 64 bytes of arithmetic over a secret key — and every Nostr
client drops an event whose signature does not verify. The only signature NetGet can make is
with a key it holds, so the events the model serves are published *as the relay*: `pubkey` is the
relay's (a fresh key per start, or `relay_secret_key`), and NIP-11's `self` names it. A client
that filters on `authors` for anyone else therefore receives nothing the model wrote, and the
`answer_with` text says so rather than letting the model try.

**Filtering** (`wire::select_events`): an event is sent when it matches at least one filter
(`ids`, `authors`, `kinds`, `since`, `until`, `#<letter>` — ANDed within a filter). For the answer
to the REQ itself, each filter contributes at most its `limit`, newest `created_at` first, ties
by lowest id (NIP-01's order); the events go out in the model's order. Events pushed later
(`send_nostr_events` with a `subscription_id`, e.g. from the dashboard) are not limited.

`send_nostr_notice {message}` sends a `NOTICE`; `close_connection` closes with `1000`.

The registry's instance has no connection and returns `send_nostr_events` as a validated
`Custom` result; the per-connection instance (`NostrProtocol::for_connection`) signs and renders.

## No storage

Nothing is kept past the moment it is used. `subscriptions.rs` holds the ids and filters of
subscriptions that are open *now* — what NIP-01 makes a relay responsible for, so that `CLOSE`
costs no model call, the model's events can be held to the filters that asked for them, and an
accepted event reaches live subscribers. An accepted event is delivered and forgotten; a later
REQ gets only what the model supplies.

## Failure behaviour

Failure is an answer; silence would leave a publisher waiting, and accepting would be fail-open.

| What failed | Event | Subscription | `decision=` |
|---|---|---|---|
| backend overloaded | `OK false rate-limited: the relay is at capacity, retry later` | `CLOSED` same text | `fail_closed_llm_error category=overloaded` |
| backend down / any other error | `OK false error: the relay could not decide on this event` | `CLOSED error: the relay could not answer this subscription` | `fail_closed_llm_error category=unavailable` |
| the model answered nothing | `OK false error: the relay made no decision on this event` | `EOSE` (no events is an honest answer) | `model_silent` |
| the model answered with actions that fail | the same `OK false` | the same `CLOSED` | `fail_closed_bad_action` |
| a subscription closed or replaced while the model answered | — | its events are dropped | `stale_answer_dropped` |

The texts are fixed literals; the error goes to the log only. Successes log `model_answer`
(with the number of events sent) and `model_reject`. The connection stays open in every case.

## Bounds

| Bound | Value | Why | Enforced by |
|---|---|---|---|
| message and frame | 128 KiB (`MAX_MESSAGE_BYTES`, `max_inbound_bytes`) | strfry's default; a note is hundreds of bytes | tungstenite's `max_message_size`/`max_frame_size`; the peer is closed `1009` |
| connections | 256 | the house default | `accept_bounded`, HTTP `503` + `Retry-After: 30` |
| request head | 16 KiB, 30 s (`handshake_timeout_secs`) | a real upgrade is under 2 KiB and sent at once | `431` / `408` |
| idle | 600 s (`idle_timeout_secs`), Ping at half | a subscription may sit silent; only a peer that stops answering Pings is closed, `1001`. Never while a message is being answered (a model call, a `manual` rule) — twice the 300 s manual window, as `websocket` | `watch_idle_with_probe` |
| subscriptions per connection | 20 | each is state and a live-delivery check per accepted event | `ConnShared::open` |
| filters per REQ | 10 | each is shown to the model | `parse_client_message` |
| subscription id | 64 characters | NIP-01 | `parse_client_message` |
| tags per event | 2000 | strfry's `maxNumTags` | `verify_event`, `parse_supplied_event` |
| events per answer | 500 | each is a signature | `parse_supplied_events` |
| messages waiting for the model | 64 per connection | the worker answers one at a time | a bounded queue; past it `rate-limited:` |
| JSON nesting | 128 | `serde_json`'s recursion limit, on in this tree (no crate enables `unbounded_depth` at any feature set: `cargo tree -e features --all-features -i serde_json`) | a depth bomb is `NOTICE invalid: message is nested too deeply` |

Is 128 enough? For stack safety, yes — `serde_json` fails the parse at depth 128 without
recursing further, so 60 000 levels in a 128 KiB message cost a parse error. What reaches the
model is bounded far tighter: tags must be arrays of strings, filter values scalars or flat
arrays, so nothing deeper than three levels survives the schema checks.

The reader, the model worker and the writer are three futures inside the connection's own
tracked task (`spawn_server_task`), so `stop_server` aborting that task ends all three; the
permit is held for the task's life.

## Peer handle

Registered after the upgrade. `FrameWriter` turns each rendered relay message the injected
action produces into one text frame, and a shutdown into a close frame (`1000`), so the
dashboard's `[ message ]` (`send_nostr_notice`, `send_nostr_events` with a `subscription_id`,
`close_nostr_subscription`) and `[ disconnect ]` work.

## Well-known port

None, and `nostr` is in `NO_WELL_KNOWN_PORT`: relays are `ws://`/`wss://` URLs on HTTP's ports,
no NIP assigns one, and the implementations disagree — `strfry.conf` `port = 7777`,
nostr-rs-relay's `config.toml` `port = 8080`. The startup examples use 7777.

## Wireshark

No `nostr` dissector (`tshark -G protocols`). Decoded as `http`; after the `101` Wireshark's own
`websocket` dissector takes the stream (text payload shown as `data-text-lines`). The pcap
oracle in `real_client_test.rs` asserts both directions dissect as `websocket`.

## Maturity

**Beta**, on two independent clients completing real sessions:

- **nak** 0.20.7 (Go; go-nostr and coder/websocket — nothing shared with this server's framing,
  JSON or crypto) publishes and reads the `OK`, reads a rejection's reason, subscribes and
  receives exactly the events the filters allow while verifying every id and signature itself,
  streams a live event published by another nak, and reads NIP-11.
- **rust-nostr** 0.45.1 through `nostr-sdk` (its own NIP-01 types, filters and signature
  checks) publishes and fetches.

Both tests fail rather than skip when the client is absent; the suite passed three runs in a
row at `--test-threads=100`, and `scripts/beta_evidence_table.py --check` is green with nostr's
peers read as `nak` and `python3 nostr_sdk`. The pcap oracle reads a recorded nak session clean
and dissected as `websocket` both ways.

What the rating covers is the surface above — NIP-01 and NIP-11 — not NIPs this relay does not
implement. Known limits a user should weigh: the model's events are authored by the relay key;
nothing is stored, so a client that publishes and then queries sees only what the model chooses
to supply; NIP-42 and NIP-45 are absent. rust-nostr's WebSocket layer is tungstenite, like the
server's, so it is protocol evidence only; nak carries the framing evidence.

## Browser interoperability

`web/test/nostr_browser.mjs` starts a native relay and drives it through real Chromium's
WebSocket and fetch APIs. A page on another localhost origin reads NIP-11 under browser CORS,
subscribes through EVENT/EOSE, publishes a nak-signed note, receives live delivery, checks that
a tampered note gets OK false, and completes the WebSocket close handshake. `nak verify`
independently checks the relay's returned event signature. The test fails if the native nostr
binary, nak, Playwright or Chromium is unavailable; `web/README.md` has the command.
