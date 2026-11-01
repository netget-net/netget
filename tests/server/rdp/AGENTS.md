# RDP Server (negotiation slice) E2E Tests

Three tests in `test.rs`, all driving the real `netget` binary with a raw TCP client that speaks
the [MS-RDPBCGR] X.224 connection negotiation directly.

## Honesty about the client

**No real RDP client was available.** `xfreerdp`/FreeRDP and Microsoft `mstsc` could not be
installed in this environment (`brew install freerdp` was unavailable), so the handshake is **not**
driven by a real client. The tests instead send a genuine, correctly-framed X.224 Connection
Request and assert the **exact literal bytes** of the Connection Confirm against
[MS-RDPBCGR]-derived values. This proves the framing of the negotiation exchange; it does **not**
prove a real client proceeds past it (it cannot — the slice stops before MCS/GCC). This is weaker
evidence than a rendered session and is labelled as such here and in `metadata().notes`.

## Strategy

**Assert exact bytes.** `expected_confirm(neg_type, flags, payload)` builds the 19-byte Connection
Confirm the server must emit, and the test compares it byte-for-byte. Swapping the little-endian
`selectedProtocol`/`failureCode` encoding, or the TPKT length, fails the comparison.

**Prove the request parser.** `test_rdp_negotiation_response_tls` matches the event on
`cookie_username == "neo"`, so the test fails if the CR parser did not extract the `mstshash`
routing token. The request also carries an RDP_NEG_REQ offering TLS|HYBRID.

**Two failure paths, kept distinct.**
- `test_rdp_fails_closed_on_no_answer` answers with only `notify_operator` (no protocol output); the
  server must fail closed with a server-forced `NEG_FAILURE(SSL_REQUIRED_BY_SERVER)`.
- `test_rdp_model_rejects_connection` has the model deliberately reject with
  `NEG_FAILURE(HYBRID_REQUIRED_BY_SERVER)`. Same PDU shape, model-chosen code — the structurally
  distinct rejection path.

**Event rules before the instruction rule**, so `on_instruction_containing("rdp")` does not answer
the network event.

## LLM call budget

**Total: 6** (3 tests × 1 startup + 1 connection-request event). Every rule is `expect_calls(1)`.

## Not covered

Everything past negotiation: MCS/GCC, the security exchange (TLS/CredSSP/RC4), capability
exchange, licensing, and any bitmap/desktop output. No real client interoperability. Binds to
`127.0.0.1` only.
