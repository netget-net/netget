# Gemini tests

Run everything:

```bash
./cargo-isolated.sh test --no-default-features --features gemini --test server -- gemini:: --test-threads=100
```

## Strategy

The evidence is `real_client_test.rs`, which points the Python Gemini client library `ignition`
at the server and asserts on what it parsed. Everything else uses a rustls client that accepts any
certificate (Gemini is trust-on-first-use) and exists for what a well-behaved client never sends,
for the bounds, and for the failure paths.

Most suites start the server in process through `ServerForm` with a static or Python script
handler and a dead model endpoint. `e2e_test.rs` and one case in `real_client_test.rs` use the
spawned binary with the mock model.

## Files

| File | What it proves | Model calls |
|---|---|---|
| `common.rs` | helpers: in-process server; `CAPSULE_SCRIPT`, a deterministic Python capsule whose home page uses every gemtext line type, including a text line starting with `=>` and a preformatted line starting with ` ``` `; `HOME_PAGE`, what it must render to; an accept-anything TLS client; `Recorder`, a TCP relay that records the first connection byte for byte | — |
| `real_client_test.rs` | ignition parses: the home page (`20`, meta with `lang=en`, body byte-exact) — through the recorder, with the **pcap oracle** (Wireshark's TLS dissector) clean over the captured bytes; `10`, a percent-decoded query answered with `20`, `11`, `31`, `44`, `51` in one run that re-validates the TOFU pin each time; and a page a **mocked model** wrote. Fails, never skips, without python3/ignition. | 2 (mocked case) |
| `e2e_test.rs` | one request reaches the mocked model with `host`, `path` and the decoded `query` (`+` kept); eight malformed requests (`https://`, `gopher://`, relative, scheme-less, BOM, userinfo, fragment, no host) are answered `53`/`59` by NetGet with no model call (the mock's counts) and no body. The request rule also requires the event's `answer_with` to name the visitor's answer, so it matches only when the hint reaches the model | 2 |
| `answer_with_test.rs` | the hint for a first request (the path named against the home page, one action, the 51 as a literal action before the page, the prompt alone, the instructions' words) and for an answered prompt; no page example carries the old "Welcome" / "A capsule served by NetGet."; a `text` line carrying a `url` renders as the text and then its link | 0 |
| `wire_test.rs` | proptests: every gemtext line keeps the type the model chose under a spec-derived classifier, and preformatted blocks balance; a response header is always `<status> <meta>` with 1–1024 bytes of single-line meta and a body only after 2x; percent-decoding inverts encoding. Fixed cases for request validation (1024 vs 1025), invalid escapes (`%+1` stays literal), defaults, a CRLF in meta, bad statuses, `lang`, link URLs. | 0 |
| `connection_bounds_test.rs` | 1024-byte URL answered, 1025 → `59` with no handler; a newline-less flood → `59`; no ClientHello → closed at `handshake_timeout_secs` with no bytes; handshaked and silent → closed at `first_byte_timeout_secs` (a different number); a `manual`-parked request outlives both; the 257th connection is closed with no bytes and the slot returns | 0 |
| `llm_failure_test.rs` | dead backend → `40`/`41` + `decision=fail_closed_llm_error`, no leaked error text; empty handler → `40` + `decision=model_silent`; a model `52` with a body → `52 Gone`, no body, `decision=model_reject` | 0 |
| `peer_inject_test.rs` | on a request parked for a human, `send_to_peer` writes a rendered gemtext page (its `# not a heading` text line defused) and `close_connection` ends the connection | 0 |

## How each guard was shown to matter

One mutated build with all of these removed, then restored:

| Guard removed | Test that failed, and how |
|---|---|
| the size checks in `read_request` and `parse_request` | `a_1024_byte_url…` (1025-byte URL answered `20`), `a_request_with_no_newline…` (no response in 10 s) |
| the handshake `timeout` | `a_peer_that_never_starts…` (socket still held after 45 s) |
| the request-line `timeout` | `a_handshaked_peer…` (no close within 55 s) |
| the connection cap (limiter ×1000) | `the_connection_past_the_cap…` (over-cap peer neither handshaken nor closed) |
| the text-line escape in `plain()` | `every_line_keeps_its_type` (a `>` text line classified as a quote), the ignition home page, peer inject |
| the ` ``` ` defuse inside blocks | the ignition home page (the block closed early) |
| body-only-after-2x | the fixed rendering test, `a_model_refusal…` (`52` carried a body) |
| meta sanitisation | `a_response_header…` (minimal case: meta `"A\ra"`) |

And separately: flipping one byte of a recorded server chunk makes the pcap oracle fail with
`Expert Info [Warn] Ignored Unknown Record`, so the oracle is not vacuous. Removing the close
**linger** made no test fail in six runs — see the server CLAUDE.md.

## Notes

- `ignition` stores its TOFU pins in `.known_hosts` in the working directory by default; the
  driver points it at a temporary file per test, and asserts a pin was written.
- ignition prints a `CryptographyDeprecationWarning` on stderr with the installed `cryptography`;
  harmless.
- CI's `registry-audit` installs `ignition-gemini==1.0.0` with pip and runs
  `gemini::real_client_test` in its evidence loop.
