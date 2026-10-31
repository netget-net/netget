# Gemini Protocol Implementation

Gemini (gemini://) capsule over TLS. The model writes the capsule: which status each URL
gets, the gemtext pages, input prompts, redirects and failures. NetGet writes every byte of
framing.

**State**: Beta (see Maturity). **Privilege**: `None` — the well-known port is 1965.
**Stack**: `ETH>IP>TCP>TLS>GEMINI`. **Feature**: `gemini` (`rustls`, `tokio-rustls`,
`rustls-pemfile`, `rcgen` — the same optional set `tls` and `http` use).

## Library choice

TLS is `tokio-rustls` 0.26 on the `ring` provider, built by `tls_cert_manager` (shared with
`tls`, `dot`, `doh`, `http`). No Gemini crate: the protocol is one request line and one header
line, and the parts worth getting exactly right — header shape, meta bounds, gemtext line
types — are ~400 lines of pure functions in `wire.rs` that the tests can hammer directly.

The certificate is a fresh rcgen self-signed one for `localhost` (365 days) unless the operator
gives `cert_path` and `key_path` (both or neither — one alone is a startup error). Self-signed is
normal for Gemini: clients trust on first use. A fresh one per start means a TOFU client that
pinned the previous run's certificate will refuse the next one; give `cert_path`/`key_path` for a
capsule that must keep its identity.

## Files

| File | What it holds |
|---|---|
| `mod.rs` | accept loop, TLS handshake, request read, the model call, the failure responses, linger |
| `wire.rs` | `parse_request`, `percent_decode`, `render_response`, `GemtextLine` + `render_gemtext`, `gemtext_mime`, `leading_status`, the status table |
| `actions.rs` | the `Protocol`/`Server` impls, the five actions, the `gemini_request` event |

## Spec subset

One connection, one exchange: TLS 1.2/1.3 handshake → one request line (`<absolute URL>\r\n`;
a bare `\n` is tolerated) → `<status> <meta>\r\n` → a body only for 2x → `close_notify` → close.

**Refused by NetGet, before the model, with fixed text:**

| Request | Response | Log |
|---|---|---|
| URL over 1024 bytes, or 1026 bytes buffered without a newline | `59 Request too long` | `decision=fail_closed_request_too_long` |
| begins with U+FEFF | `59 Request must not begin with a BOM` | `decision=refused_bad_request` |
| not an absolute URL (`/path`, `host/path`) | `59 Request is not an absolute URL` | `refused_bad_request` |
| userinfo | `59 URL must not contain userinfo` | `refused_bad_request` |
| fragment | `59 URL must not contain a fragment` | `refused_bad_request` |
| no host | `59 URL has no host` | `refused_bad_request` |
| any other scheme (`https://`, `gopher://`) | `53 Proxy request refused` | `refused_proxy_request` |

**Not implemented:** the host is not compared with the certificate or any configured name — it
is handed to the model, which may serve several "capsules" by host or refuse with `53` itself.
No client certificate is requested or read, so `60`–`62` are available to the model but nothing
backs them.

## What the model sees and controls

**Event** `gemini_request {url, host, path, query, answer_with}` — `url` as sent; `path` as it
appears in the URL (not decoded), `/` when empty; `query` percent-decoded (only `%XX`; `+` stays a
plus, since a Gemini query is not form encoding) and stripped of control characters other than
newline and tab, or `null` when there is no `?`.

`answer_with` (`actions::answer_with_for_request`) says which single response this request takes.
With no query: it names the path against the home page ("the visitor asked for /nowhere (not
the home page, which is /)"), says exactly one action is sent, looks the path up first and gives
the 51 as a literal action, `{"type": "send_gemini_response", "status": 51, "meta": "Not
found"}`; then `send_gemini_input` alone when the instructions say the page asks for something
first; otherwise a page whose words are the instructions' own, word for word. With a query: the
visitor answered the prompt with it, so send the page that follows. Two real-model eval misses
(llama3.1:8b, seed 42) are why: told "/guestbook asks the visitor for their name before showing
anything", the model sent a page reading "What is your name?" and *then* `send_gemini_input` —
and only the first is sent — five runs in five; told "serve a home page titled Welcome to the
NetGet capsule", it sent `send_gemtext`'s example page ("Welcome", "A capsule served by
NetGet.") first and the right page second, four runs in five. The page examples are now
placeholders (`"<page title>"`, `"<a paragraph>"`, `/<path>`), and the descriptions say so.

The path-against-home and literal-51 parts were added after a first version (the same hint
without them) fixed those two cases and broke a third: told "only the home page exists", the
model served the home page for /nowhere four runs in five. Measured, 5 runs each: home-page
1/5 → 5/5, ask-for-input 0/5 → 5/5, not-found 5/5 → 1/5 with the first version and 4/5 with the
shipped one (its miss is a 20 page titled "Page not found").

| Action | Renders |
|---|---|
| `send_gemtext {lines:[{type, text, url?, alt?}], lang?}` | `20 text/gemini; charset=utf-8[; lang=…]` + the rendered page |
| `send_gemini_response {status, meta?, body?}` | any defined status; `body` only after a 2x |
| `send_gemini_input {prompt, sensitive?}` | `10`, or `11` when sensitive |
| `send_gemini_redirect {url, permanent?}` | `30`, or `31` when permanent |
| `close_connection` | close without answering (the peer then gets the silent-model `40`) |

### NetGet does the framing; the model cannot

* **Status** must be one of 10, 11, 20, 30, 31, 40–44, 50–53, 59, 60–62; anything else is refused
  by the executor.
* **Meta** is one line (control characters → spaces, trimmed), at most 1024 bytes, and never
  empty: an empty meta takes the status's default (`51 Not found`, `20 text/gemini…`). Some
  clients split the header on whitespace and fail outright on a bare `51\r\n`. `30`/`31` need a
  meta with no whitespace, `44` a number of seconds.
* **Body only after 2x.** A body given with any other status is dropped (and logged at WARN): a
  client would otherwise read it as part of the stream after a failure.
* **Gemtext line types cannot be forged.** A `text` line that would begin with `=>`, `#`, `*`,
  `>` or ` ``` ` gets one leading space, which is the least change that keeps the words and loses
  the misreading (gemtext has no escape character). Headings, list items and link labels are one
  line (newlines → spaces). Quotes and preformatted blocks keep their lines; inside a block, a
  line beginning with ` ``` ` gets a leading space so it cannot close the block. Link URLs may not
  contain whitespace. `lang` is written only if it is a BCP 47 list.
* **A `text` line carrying a `url` keeps its link.** It is rendered as the text line and then a
  link line to that URL, labelled with the line's `alt` (or, with no `alt`, the text alone becomes
  the link's label). Told "serve a home page titled Welcome to the NetGet capsule, with a link to
  /about", llama3.1:8b wrote the link as `{"type": "text", "text": "…", "url": "/about", "alt":
  "Learn more"}` in two runs of five (real-model eval, seed 42), and the page went out with the URL
  silently dropped.
* **One response per connection.** If the model produced several, the first is sent and the rest
  are logged.

## Failure behaviour

`FailureMode::Answers`. The specification's own temporary-failure codes:

| Cause | Response | Log |
|---|---|---|
| backend overloaded (`WireFailure::Overloaded`) | `41 backend at capacity, retry later` | `decision=fail_closed_llm_error category=overloaded` |
| any other backend failure | `40 request could not be processed` | `decision=fail_closed_llm_error category=unavailable` |
| the handler/model produced no response | `40 request could not be processed` | `decision=model_silent` |

`41 SERVER UNAVAILABLE` is defined as "unavailable due to overload or maintenance" — exactly the
Overloaded category, and a client backs off. Every other failure is transient but not overload,
which is `40 TEMPORARY FAILURE`. `42 CGI ERROR` was rejected: it describes a dynamic-content
process dying and would put an implementation detail in the client's face; `44 SLOW DOWN`
requires a wait in seconds nothing knows. A permanent failure (5x) would be false — nothing was
wrong with the request. A model 1x/2x/3x logs `decision=model_answer`, a model 4x–6x
`decision=model_reject`.

## Bounds

| Bound | Value | Override | Why |
|---|---|---|---|
| `MAX_REQUEST_BYTES` (= `max_inbound_bytes`) | 1026 (1024-byte URL + CRLF) | — | The spec's "the URI MUST NOT exceed 1024 bytes". Checked while reading (a flood without newline stops at 1026) and again on the parsed line. |
| `HANDSHAKE_TIMEOUT` | 60 s | `handshake_timeout_secs` | A peer that connects and sends no ClientHello; real clients finish in a round trip. |
| `FIRST_BYTE_TIMEOUT` | 300 s | `first_byte_timeout_secs` | A handshaked peer that sends no request. 300 s is the `manual` window, for NetGet's own TLS client waiting on its operator. Lower it for a public capsule. |
| `MAX_CONNECTIONS` | 256 | — | House default. The peer past it is closed **before** the handshake with no bytes: a plaintext `41` would be a malformed TLS record, not a refusal (the `dot`/`doh` reasoning). |

There is no idle bound because there is no idle phase: every response ends the connection. Both
deadlines wrap reads only, so a request parked for a human is closed by neither.

After the response the server sends `close_notify`, then reads and discards what the peer
already sent for at most 2 s / 64 KiB before dropping the socket, so the TCP close is a FIN and
not an RST that could destroy an unread response. **Unlike `dict`'s identical linger, no test
here fails without it** — removing it left the 64 KiB-flood and 1025-byte tests green six runs
in a row on macOS — so it is kept on the DICT evidence and the RST semantics, not on a Gemini
measurement.

## Peer handle

Registered after the handshake (there is no channel a reply could use before it) and before the
request is read, so the operator can answer a parked request from `[ message ]` with any of the
actions above, then `[ disconnect ]`.

## Wireshark

This Wireshark build has no gemini dissector (`tshark -G protocols` lists none), so
`src/tui/wireshark.rs` maps `gemini` to `tls`. `tests/server/gemini/real_client_test.rs` relays
the real client's connection through a recorder and runs the pcap oracle over it with the TLS
dissector — which proves the records are well-formed TLS and that nothing was written outside
TLS, not that the Gemini inside is right (ignition's parse is the evidence for that).

## Maturity

Beta, promoted after the whole suite (21 tests, the real-client file included) passed three
consecutive runs at `--test-threads=100` and `scripts/beta_evidence_table.py --check` stayed
green with `python3 ignition` as the peer. The evidence is `tests/server/gemini/real_client_test.rs`: the Python client
library `ignition` 1.0.0 (MPL-2.0, `pip install ignition-gemini`), driven as a subprocess —
TLS through CPython's `ssl` (OpenSSL, not rustls), TOFU pinning into a temporary known-hosts
file (re-validated on every later request in the same run), and its own header/body parser. It
asserts ignition's parsed class, status, meta and body for 10, 11, 20 (with `lang`), 31, 44 and
51, a percent-decoded query round trip, and a page written by a mocked model. It fails, never
skips, when `python3` or `ignition` is missing.

`amfora` is installed here but is an interactive TUI with no batch mode, and `gemget` is not
installed, which is why the evidence is a library rather than a binary. The raw-socket suites use
a rustls client, which is the server's own TLS stack; `scripts/beta_evidence_table.py` therefore
lists `rustls`/`tokio_rustls` as circular — correct, and not what any rating rests on.

What Beta does not cover: one client (a second — `gemget`, or Go's `go-gemini` — is Stable's
condition 1); the pcap oracle sees TLS records only, not the Gemini inside; no fuzz target;
browser-style clients (Lagrange, amfora) have not been pointed at it by hand.

File-backed certificate startup explicitly selects rustls ring before loading, so
library callers with both crypto-provider features enabled do not panic. The
Gemini client pair test covers this path with a temporary trusted certificate.
