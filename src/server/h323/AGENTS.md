# H.323 servers: gatekeeper (`H323-Gatekeeper`) and endpoint (`H323`)

Two server protocols under one feature, `h323`, plus the codecs the H.323 client
(`src/client/h323`) shares:

- **`H323-Gatekeeper`** — H.225.0 RAS on UDP (well-known port 1719). Discovery, registration,
  admission, location, disengage, unregistration. `.connectionless()`, `.answers_on_failure()`.
- **`H323`** — the called side of H.225.0 call signalling: Q.931 over TPKT on TCP (well-known
  port 1720, which is above 1023 and needs no privilege), with fastStart and tunnelled H.245.

Rust owns the encoding (PER, Q.931, TPKT), call references and identifiers, time-to-live,
retransmissions, H.245 procedures and every bound. The model owns policy: who may use the
gatekeeper, who registers under which aliases, which calls are admitted and routed where, and
whether a call is answered, rejected, left ringing or forwarded.

## Why hand-written, and how

PER has no tags: to reach a message's tenth field a decoder has to understand the nine before
it, so a hand-written walker per message would have meant transcribing several hundred types.
Instead `scripts/h323_asn1_schema.py` parses the ITU's own ASN.1 modules — H323-MESSAGES
(H.225.0 12/2009), H235-SECURITY-MESSAGES and MULTIMEDIA-SYSTEM-CONTROL (H.245 v15), as
Wireshark redistributes them — and emits `schema.rs`: a table of `per::Ty` values, only the
types reachable from `RasMessage`, `H323-UserInformation`, `MultimediaSystemControlMessage` and
`OpenLogicalChannel`. `per.rs` interprets that table in both directions, to and from JSON.
`schema.rs` is generated (`// @generated`, skipped by rustfmt); regenerate it rather than
editing it, and check it reproduces: the script's header names the pinned inputs.

What the generator keeps is only what changes an ALIGNED PER encoding (OPTIONAL, extension
markers, SIZE and value ranges, permitted alphabets). WITH COMPONENTS is not PER-visible and is
dropped. Parameterized types (`SIGNED{}`, `ENCRYPTED{}`, `HASHED{}`) become `Ty::Opaque`: an
H.235 token is an extension addition in every message NetGet handles, so it is stepped over by
its open-type length and reported as `{"_opaque_octets": n}`; in a root position the decode
stops with an error naming it.

## Files

| File | What |
|---|---|
| `per.rs` | ALIGNED PER reader/writer over `schema.rs`; the bounds below |
| `schema.rs` | generated tables (see above) |
| `q931.rs` | TPKT (RFC 1006) and the H.225.0 profile of Q.931 (2-octet User-user IE length) |
| `h225.rs` | transport/alias addresses, endpoint types, RAS and UUIE envelopes as JSON |
| `h245.rs` | fastStart offer/answer and `H245Session` (TCS, MSD, OLC, CLC, RTD, EndSession, user input) |
| `call.rs` | one call-signalling leg (CRV, call/conference ids, tunnelled H.245, RTP sockets); shared with the client |
| `gatekeeper.rs` | the RAS server |
| `endpoint.rs` | the call-signalling server |
| `actions.rs` | both protocols' events, actions, metadata |

## What the model sees and does

Aliases are strings `kind:value` (`h323-ID:alice`, `dialledDigits:1001`, `url-ID:…`,
`email-ID:…`, `transportID:ip:port`); the model may write bare values (digits become
`dialledDigits`, anything else `h323-ID`).

Gatekeeper events: `h323_gatekeeper_request` (GCF/GRJ), `h323_registration_request` (RCF with
aliases and time-to-live / RRJ), `h323_admission_request` (ACF with a destination — a registered
alias or `ip:port` — and bandwidth / ARJ), `h323_location_request` (LCF/LRJ). The ARQ and LRQ
events list which destination aliases are registered here, with their addresses.

NetGet answers without the model: keep-alive RRQ for a live registration (refresh; unknown
endpoint → RRJ `fullRegistrationRequired`), URQ, DRQ, BRQ (up to `max_bandwidth`), IRR with
`needResponse` (IACK), RAI (RAC), an ARQ from an unregistered endpoint (ARJ
`callerNotRegistered`), and a retransmitted request: the remembered answer again, or RIP while
the model is still deciding. An unknown request is answered XRS.

Endpoint events: `h323_setup` (numbers, aliases, display, the caller's endpoint and vendor, its
fastStart proposals, whether it tunnels H.245) → any of `h323_call_proceeding`, `h323_alerting`,
`h323_connect` (codec preference, display), `h323_release_complete` (Q.850 cause, H.225.0
reason), `h323_forward_call` (Facility `callForwarded` + Release Complete
`facilityCallDeflection`). `h323_user_input` (DTMF over H.245) → `h323_release_complete` or
nothing. The operator can inject the same actions into a live call (peer handle).

On Connect NetGet answers the caller's fastStart in the first G.711 codec both sides have (the
caller's transmit channel gets this side's RTP/RTCP; its receive channel is accepted as
proposed), and opens tunnelled H.245 (TerminalCapabilitySet + MasterSlaveDetermination in the
Connect). `H245Session` acknowledges the peer's TCS and MSD (H.245 C.2 decision rule, terminal
type 50), acknowledges its OpenLogicalChannel with this side's media address, opens one G.711
channel towards it, and ends the call on EndSessionCommand. H.245 messages it does not handle
are logged and dropped.

## Failing closed

Nothing here confirms or connects on its own.

- Gatekeeper: backend failure → the matching reject with `resourceUnavailable` (overloaded) or
  `undefinedReason`, `decision=fail_closed_llm_*`; an answer with no confirm/reject →
  `undefinedReason`, `decision=model_silent`; an action that cannot be carried out (an alias
  another endpoint holds, a destination that is not registered) → the matching reject,
  `decision=fail_closed_bad_action`; too many requests already with the model →
  `resourceUnavailable`, `decision=fail_closed_in_flight_cap`.
- Endpoint: backend failure → Release Complete cause 41 (42 when overloaded); no call-control
  action → cause 31 (`model_silent`); alerting with no Connect → cause 19 after
  `RING_TIMEOUT`; a malformed message, a message before Setup or for another call reference →
  cause 111 / 81, `decision=protocol_error`.

## Bounds

| Bound | Where |
|---|---|
| PER nesting depth 40 (`MAX_PER_DEPTH`); H.225.0 GenericData and H.245 GenericParameter are recursive | `per.rs` |
| PER values per decode 20 000 (`MAX_PER_NODES`); fragmented lengths refused; normally-small > 63 refused; every declared length checked against what is present before anything is allocated | `per.rs` |
| TPKT 16 KiB (`MAX_TPKT`), 64 IEs per message | `q931.rs` |
| RAS datagram 4096 octets | `gatekeeper.rs` |
| 256 registrations, 512 admitted calls, 64 requests with the model at once, 256 remembered answers (30 s) | `gatekeeper.rs` |
| time-to-live 1–3600 s | `gatekeeper.rs` |
| 256 connections (`accept_bounded`), 15 s to the Setup, 1 h of signalling silence, 2 min of ringing | `endpoint.rs` |
| 256 H.245 messages per call, 64 user-input entries, 32 user-input events | `h245.rs`, `endpoint.rs` |

## Not implemented

- Gatekeeper-routed call model (ACF always names the destination; the gatekeeper never carries
  signalling), alternate gatekeepers, LRQ forwarding to neighbours.
- H.235 security: tokens are stepped over, never checked or produced.
- A separate H.245 TCP channel. With neither fastStart nor tunnelling the call still connects
  at the Q.931 level, with no media negotiated.
- Codecs other than G.711 (µ-law, A-law, 64 kbit/s). NetGet binds the RTP/RTCP pair it
  advertises and counts what arrives; it sends no media and decodes none.
- H.450 supplementary services, overlap sending, multiple calls per connection
  (`multipleCalls` is always false; a second Setup is refused with `newConnectionNeeded`).

## Evidence

`tests/server/h323/AGENTS.md`. In short: H323Plus (`simph323`) and ooh323c (Asterisk's
`chan_ooh323`) register with the gatekeeper and call the endpoint; tshark's h225/q931/h245
dissectors read every message from a live capture. Experimental: nobody has reviewed the H.245
subset or the generated schema against the specifications, there is no fuzz target for the PER
decoder, and the pair job had not run in CI when this landed.
