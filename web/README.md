# NetGet in the browser

The demo page (`site/demo.html`, served at netget.net/demo.html) runs NetGet itself: the dashboard,
the protocol servers and the LLM plumbing, compiled to `wasm32-unknown-unknown`. This
directory holds the build script and the headless tests; the code is in `crates/`.

## What runs where

| Piece | Native | Browser |
|---|---|---|
| Executor (`tokio::spawn`, timers) | tokio runtime | the JS event loop — `crates/netget-tokio-wasm` |
| Sockets (`tokio::net`) | the kernel | a virtual loopback in the same crate: TCP `bind` claims a port in a table and `connect` hands the listener an in-memory duplex; UDP `bind` claims a port and `send_to` delivers a datagram to the socket bound on that port |
| Terminal | crossterm on a tty | xterm.js; `crates/netget-web/src/backend.rs` emits ANSI, keys arrive as DOM `KeyboardEvent`s, `crates/netget-crossterm-wasm` supplies crossterm's *types* |
| LLM | Ollama / OpenAI over HTTP | `LlmBackend::Bridge` (`src/llm/bridge.rs`): every request goes to the page as JSON; the page answers with Chrome's built-in model (the Prompt API), a WebLLM model, or the visitor through a form |
| Clocks | std | `performance.now()` / `Date.now()` via `crate::utils::clock` |

The protocol servers are compiled **unchanged**. On
wasm32 the names `tokio` and `crossterm` resolve to the shim crates
(`extern crate … as` in `src/lib.rs`), which is what keeps the `#[cfg]` count in protocol
code at zero. Everything platform-bound that the servers do not need — the rolling TUI,
process spawning for scripts, reqwest, termbg, socket2, ollama-rs — is gated with
`#[cfg(not(target_arch = "wasm32"))]`. The HTTP-family *clients* are in the browser build
too: there they speak HTTP through `src/client/http_fetch/transport.rs` (hyper's client over
the virtual loopback) instead of reqwest; see below.

## Build

```bash
rustup target add wasm32-unknown-unknown
rustup component add llvm-tools            # llvm-ar, for ring's C objects (see below)
cargo install wasm-bindgen-cli --version "$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/^version = "\(.*\)"/\1/p')"
./web/build.sh                              # -> site/demo/pkg/ (gitignored)
node web/test/smoke.mjs                     # headless end-to-end check of the bundle
python3 web/test/page_composer.py           # the real page in headless Chromium (Playwright; not in CI)
cd site && python3 -m http.server 8000      # then open http://localhost:8000/demo.html
./site/deploy.sh                            # publish: S3 + CloudFront, see site/AGENTS.md
```

`web/build.sh --dev` skips optimisation (seconds instead of a minute, ~5x the size).

Two things the script handles that are easy to lose an hour to:

- **`wasm-bindgen` must match `Cargo.lock` exactly**; the script refuses to run otherwise.
- **macOS `ar` writes a broken archive for wasm objects** ("not a mach-o file" from
  `ranlib`), which surfaces at *link* time as `undefined symbol: ring_core_0_17_14__…`. ring
  is in the build because the `http` feature pulls rustls/rcgen (unused in the browser but
  compiled). The script points cargo at `llvm-ar`; if ring was already built with the wrong
  archiver, `cargo clean -p ring --target wasm32-unknown-unknown --release` once.

## The page's contract (`crates/netget-web`)

`new NetGet({cols, rows, onOutput, onLlm, model, theme})` boots everything. Then:

- `key(json)`, `mouse(json)`, `text(str)`, `resize(cols, rows)` — terminal input.
- `set_model(name)` — the model named in every request and in the dashboard's status bar
  (`llm: …`); `set_models(json)` sets what `/model` lists and should include it.
- `set_llm_handler(fn)` — `fn(requestJson) -> Promise<replyJson | object>`. A request is
  `{id, kind: "generate" | "chat", model, messages: [{role, content}], tools: [...],
  actions: [...]}`. A reply is `{content?, tool_calls?: [{name, arguments}], reasoning?,
  prompt_tokens?, completion_tokens?}` or `{error}`. `reasoning` is the thinking a model that
  reasons natively wrote before its answer (the page sends Qwen3's `<think>` block); NetGet
  never parses it, and forwards it to the status channel as `[REASONING]` lines, so the
  dashboard's stream shows it (`∴ …`) exactly as it shows an Ollama model's `thinking`.

  `actions` is every action the prompt offers, as data: `{name, description, tool, generic,
  parameters: [{name, type, description, required, choices?}], example, schema}`
  (`netget::llm::bridge::offered_action` documents each field). It is the only structured
  description a network event's request has — that path deliberately sends no native
  `tools` — and each `example` is one the action's own executor accepts. Nothing on the
  Ollama/OpenAI wire carries it.
- `start_server(json, cb)` — `cli::management::ServerForm`, the same path the dashboard's
  own form and MCP use.
- `start_client(json, cb)` — `cli::management::ClientForm`, as the dashboard's form and MCP
  `start_client`: `{"protocol":"http","remote_addr":"127.0.0.1:8090","instruction":"..."}`;
  `cb` gets `{id}` or `{error}`. `connect_client_to_server(serverId, cb)` is the dashboard's
  `[ + <proto> client ]` itself (`tui::actions::client_form_for_server` and the form's apply,
  default routing included); `cb` gets `{id, protocol, remote_addr}` or `{error}`. It inherits
  an OpenAPI server's spec, sets OAuth2's local endpoints, and uses explicit HTTP for local
  package registries and OIDC. If credentials are missing, it opens a focused form in the
  dashboard terminal and returns `{configuration_required, protocol, form_opened: true}`.
  Fill `client_id` and any needed `client_secret`, then use the form's `[ Apply ]` button;
  `clients(cb)` exposes the created client. Cancel leaves the server running without a client.
  `send_to_client(id, actionJson, cb)` is the client card's `[ send ]`
  (`AppState::send_to_client`); `cb` gets the `ClientSendOutcome` as serde writes it
  (`{"Executed":{"detail":"http_request GET / -> 200 (5 byte body)"}}`, …) or `{error}`.
  `clients(cb)` lists `{id, protocol, remote_addr, status}`.
- `connect(port, onData, onClose) -> id`, `send(id, bytes)`, `close(id)` — a TCP client on
  the virtual network; `udp_open(onDatagram) -> id`, `udp_send(id, port, bytes)`,
  `udp_close(id)` — a UDP one. `listening_ports()`, `bound_udp_ports()` and `servers(cb)`
  describe what is there.

`site/js/demo.js` is the page, and the demo on it is Telnet only: three machines. On a wide
screen the Telnet client and the model sit side by side, the same height (the Telnet terminal
fills whatever the model panel makes the row, and never holds it open), with the dashboard
below them at full width; on a narrow one they stack as Telnet, dashboard, model. The
dashboard's terminal is 13px wherever 80 columns fit; narrower, the dashboard stacks its own
two columns (`src/tui/render/mod.rs`, from 40 columns up) and the page picks the largest font
that fits 48 columns — 10.5px on a 390px phone, where squeezing in 80 columns meant 6.5px. The page
around them carries no step list or notes: each machine's header names it in one line
("NetGet in your browser via WASM", "Mock Telnet client connected to NetGet", "Source
LLM used by NetGet"), and no loading banner shifts the page while the bundle loads (the
banner element shows only an error). Nothing needs a click: once the Telnet terminal exists it
takes focus, unless the visitor has already focused something else, and its cursor is drawn
from the start (xterm.js draws none until a terminal's first focus, so the page sets the
pinned 5.5.0's `coreService.isCursorInitialized` itself). The dashboard has no extra
listening-status row or keyboard-help footer.

- About a second after `new NetGet(...)` the page calls `start_server` for a Telnet server on
  2323 with the instruction "Provide life coaching services over Telnet." and one `llm`
  rule on typed lines asking for a short `send_telnet_line` answer. A static rule with no actions handles
  `telnet_connection_opened`, so connecting or reconnecting makes no model request.
  `send_first` does not suppress Telnet's connect event; the static rule is what skips the LLM.

  The bridge carries optional structured event metadata (`server_id`, `connection_id`,
  protocol, event type/data and a token stable across retries); the LLM panel reads the typed
  line from it rather than from prompt prose.

  About a second later the Telnet terminal `connect()`s to it. The terminal reads as a shell session:
  a `$ ` prompt, `telnet localhost 2323` typed out so that it finishes as the client connects,
  then telnet(1)'s own `Trying 127.0.0.1...` / `Connected to localhost.` / `Escape character
  is '^]'.`; when the server hangs up, `Connection closed by foreign host.` and the prompt
  again, where Enter types the command again and reconnects. The client is line-mode: it
  edits and echoes the line locally (always; it refuses every option the server offers) and
  sends it whole on Enter. The model panel stays idle until the visitor sends a line;
  that `telnet_message_received` event is the first model request.
- Requests are answered one at a time and only the current one is on screen: the composer
  (below) while the visitor is the model, and what the model writes while a model answers.
  Its output streams into the LLM panel as it is generated (Prompt API `promptStreaming`,
  WebLLM's `stream: true` deltas), in fixed-height blocks that follow the newest line and
  scroll without a scrollbar, so the panel does not grow. A model that reasons natively
  (`thinks: true` in `WEBLLM_MODELS`: Qwen3 1.7B and 4B) gets a "Thinking…" block with its
  `<think>` text, then the answer; once answered the block folds to "Thought for N s ▸" and
  opens again on a click. Every other model (Gemini Nano, Qwen2.5, Llama 3.2, Hermes) shows
  its answer alone: it is not asked to explain itself, because a prompted explanation is not
  reasoning and would be mislabelled as such. `site/js/thinking.js` does the split. A model's
  answered request stays on screen, marked "answered in N s", until the next request
  replaces it; one the visitor answered goes idle at once.
- The model control is one `<select>` at the top of the LLM machine's panel. Where
  `LanguageModel.availability()` answers `available`, `downloadable` or `downloading`, its
  first option is the browser's built-in model, by name: "Gemini Nano · Chrome built-in",
  or "Phi-4-mini · Edge built-in" when the user agent says Edge (the API does not name its
  model; Edge's flag-gated Aion-1.0-Instruct cannot be told apart). Below 600px wide the
  labels say only what tells the options apart, so they fit the select on a phone ("Gemini
  Nano · built in", "Qwen2.5 3B · 2 GB", "Qwen3 1.7B · thinks · 1 GB", "… · cached").
  Then the WebLLM models
  (`WEBLLM_MODELS`), each with its download size (the weights in the model's
  `ndarray-cache.json`; WebLLM's prebuilt config gives only VRAM) and "thinks" for Qwen3, or
  "downloaded" once WebLLM's
  `hasModelInCache` says so; without WebGPU they are listed disabled. The last option is
  "Respond on behalf of LLM": chosen, the visitor answers every request even with a model loaded
  (which stays loaded, so choosing it again is immediate). The default is the built-in model,
  else the first WebLLM model, else "Respond on behalf of LLM"; a choice made in the select,
  including that one, is kept in `localStorage` (`netget-demo-model`) and restored on the
  next visit.
  Choosing a model that is on this device (the built-in model `available`, or a cached WebLLM
  model) loads it and switches with no click; one that needs a download shows one button
  naming it and its size. The built-in model's download also starts on the visitor's first
  `pointerdown` or `keydown` anywhere on the page but the select (Chrome requires a user
  activation for it, and `create()` is called synchronously inside that handler so the
  activation counts), with `monitor`'s `downloadprogress` as the bar.

  Who answers a request (`route()` in `demo.js`): the model answering now, if there is one;
  otherwise, while the selected model is **on its way** — being looked for in the cache,
  starting (`LanguageModel.create()`), loading from the cache, or downloading once the
  visitor asked — the request **waits for it**, shown in the LLM panel as "waiting for Gemini
  Nano" / "Downloading Chrome built-in Gemini Nano… 40%", and goes to it the moment it is ready;
  otherwise (a model that needs a click to download, one that failed, or "Respond on behalf of LLM")
  the visitor answers. Connecting stays idle; if the visitor sends a line before the
  selected model finishes loading, that message waits for the model. If the load fails, a request that waited goes to
  the composer with the reason. A model already answering keeps answering while another
  loads. The status line under the select says which of these applies, in one short line
  ("Ready: Chrome built-in Gemini Nano", "WebLLM Qwen3 1.7B: not downloaded").

  The wait is bounded on the page, deliberately below NetGet's own bounds. NetGet waits for
  the page's answer to one request for `LLM_TIMEOUT` (900 s, `crates/netget-web/src/lib.rs`)
  and then fails it closed. It hands the page one request at a time (the rate
  limiter's single permit), so a second network request waits behind the first for at most
  the limiter's queue timeout (300 s) and then fails. So a request waits for a loading model
  for `MODEL_WAIT_MS` (two minutes) and then goes to the visitor, with a note saying so. A model
  that becomes ready later still takes over any request the visitor has not started on, as it
  does when a download the visitor asked for finishes.

  On a switch the page calls `set_model` with the name of whoever answers. A WebLLM model
  that stops answering because another model took over is unloaded; the built-in model's
  session is kept, so switching back to it is immediate. The WebLLM runtime (esm.run) is only
  imported once a WebLLM model is selected.
- The built-in model gets a fresh session per request (NetGet sends the whole context each
  time) and `promptStreaming()` with a `responseConstraint`: a JSON Schema of `{"actions":
  [...]}` whose items are the offered non-tool actions, `type` pinned to each name, listed
  **first**, and exactly that action's parameters after it (`additionalProperties: false`).
  The order is load-bearing: a constrained decoder writes properties in schema order, so with
  `type` listed after the parameters a model that begins with `"type"` (as every example in
  the prompt does) could only reach the actions with no required parameter. Gemini Nano,
  llama3.1:8b and qwen2.5:1.5b all answered a typed "hello" with `send_telnet_prompt` and
  `"> "` that way, Nano under a half-written key (`"prompt__"`, `"promptłe"`) that the missing
  `additionalProperties: false` let through. Chrome's
  stream yields deltas; early versions yielded the whole text so far each time, and a chunk
  that extends what came before is taken as that. A session without `promptStreaming()` is
  asked through `prompt()`. Its text goes through the composer's own
  `entriesFromEnvelope`/`buildReply`, so an answer is accepted only if the composer could have
  built it; anything else sends that one request to the composer, with the reason. WebLLM's
  text goes back as written, to NetGet's own parser and repair, less a thinking model's
  `<think>` block, which goes as the reply's `reasoning` (a block with no `<think>` in sight,
  because the template opened it in the prompt, ends at `</think>`). Qwen3 is asked with
  `extra_body: {enable_thinking: true}` (WebLLM 0.2.85's toggle; `false` prefills an empty
  think block), temperature 0.6 and top_p 0.95 (Qwen's own advice for thinking; greedy
  decoding makes it repeat itself), and `max_tokens` 1024, since its thinking is spent from the
  same budget; a reply that spends all of it without closing `<think>` is asked again with
  thinking off, and the cut-off thinking stays in the Thinking block, marked as cut off.
  Every WebLLM model is loaded with `context_window_size` 8192 (the third argument of
  `CreateMLCEngine`). The prebuilt 4096 does not hold a NetGet request: measured on the page
  with the real Qwen3 1.7B, a Telnet event's prompt is about 3900 tokens, so the connect event
  left it 169 tokens, it ran out inside `<think>` and sent no banner, and the next line's
  prompt (4146 tokens) was refused (`ContextWindowSizeExceededError`). With 8192, its thinking
  on typed lines closed within 290–390 tokens (answers in about a minute at this machine's
  5–6 tokens/s), while on the connect event it ran past 2048 without closing, which is what
  the retry without thinking is for.

The page never starts an HTTP-family server itself. The dashboard's picker lists every
compiled protocol, so a visitor can, and the hyper servers answer here (see below).

When the visitor is the model, `site/js/composer.js` starts simple wherever the preselected
action takes one free-text parameter (Telnet's `send_telnet_message`): one textarea prefilled
from the action's own example ("Hello"), Send (or Enter), and Advanced. An example whose
text ends in a line break is a line, so the field shows it without the break and puts it back
on send. Advanced opens the full form and the prompt NetGet sent; Simple folds them again.
The full form follows the dashboard's intercept composer: a picker of the offered actions (the protocol's own first
action preselected, not a `generic` one), one control per parameter by type, every field
prefilled from the action's example, "Add another action", "Answer with nothing" (`{"actions":
[]}`, a real answer), "Refuse (fail closed)", and the schema behind a disclosure. There is
no reply heading or editor selector; requests with actions always use the form. Its reply is the JSON envelope as
`content`, or `tool_calls` for a chat request whose entries are all native tools. A request
without `actions` gets a plain reply field. The top half of the file is DOM-free so
`smoke.mjs` builds the same default reply under Node; `web/test/page_composer.py` drives the
page itself in headless Chromium: the Telnet server and client come up with no clicks and
no model calls, the first typed line opens a request, the visitor answers through the simple field and through Advanced and the answers reach the Telnet terminal, the Telnet terminal takes focus on load when nothing else has it, startup and
incoming requests preserve the visitor's focus, submitting a reply never focuses a terminal, no element of
the demo has a scrollbar at 1280x800, 1440x900, 1920x1080 and 390x844, the terminal reads as
a telnet session through a hang-up and a reconnect, the removed explanatory text stays
removed, a 390x844 phone gets the short select
labels (each measured to fit) and the stacked dashboard at 10px or more, and a stub `LanguageModel` proves the Prompt API path both when the model is
`available` (named first in the select, loads by itself, answers with no composer,
constrained to the offered actions, falls back on an unparseable answer) and when it is
`downloadable` (waits for the first keypress). A stub whose `create()` the test holds for
seconds while the Telnet client sends a line proves the queue: that message shows as
waiting for the model, the composer never appears, and the model answers once `create()`
resolves; with `create()` failing instead, that request goes to the composer. "Respond on
behalf of LLM" chosen with the stub loaded sends the next request to the composer, choosing the
model again hands requests back with no new session, and the choice survives a reload. Switching is
driven against a fake WebLLM module the test serves in place of the esm.run import: an
uncached model shows its sized download button and downloads nothing unasked, switching back
re-uses the built-in session, a cached model loads with no click, and the choice survives a
reload. Streaming is driven the same way: a stub whose `promptStreaming()` holds after two
chunks shows the partial answer in the panel before the Telnet terminal has it and never a
Thinking block (its second stream yields cumulative chunks, and the answer is the same), and
the fake WebLLM's Qwen3 streams a `<think>` block, held before `</think>`, which shows in the
Thinking block with no answer yet, folds to "Thought for N s" once answered, opens on a click,
and never reaches the Telnet terminal (with the real xterm.js the test reads it in the
dashboard's stream too); the engine is asked for an 8192-token context, and a Qwen3 reply that
spends its 1024 tokens inside `<think>` is asked again with thinking off and still reaches
Telnet. `smoke.mjs` checks `site/js/thinking.js` at each point of a `<think>`
stream and that a reply's `reasoning` reaches the dashboard.
Headless Chromium has no built-in model, so the stubs are the evidence for that path;
with Chrome itself the test also checks the real `availability()` is detected and no download
starts unasked. xterm.js is stubbed unless `XTERM_DIR` points at the real files; every other
non-local request is answered by the test. `SITE_DIR` serves another layout of the page
(deploy.sh's staged copy) instead of `site/`.

## Which protocols are in the browser build

Everything `crates/netget-web/Cargo.toml` lists: 68 features, every server protocol that
compiles for wasm32 — TCP ones (telnet, http, http2, ftp, pop3, nntp, smb, vnc, rdp,
modbus, kafka, nats, stomp, memcached, whois, gopher, finger, ident, svn, mercurial, sip,
rtsp, hls, snowflake, db2, mongodb-server, saml, openid, oci-registry, npm, pypi, maven,
elasticsearch, jsonrpc, oauth2, openapi, openidconnect, bitcoin, torrent-*, tls, …) and
UDP ones (udp, dhcp, dhcpv6, bootp, tftp, snmp, syslog, coap, radius, ssdp, netbios-ns,
rtp, gtp, hsrp, wol, dc, …).

**The HTTP-family clients.** reqwest's wasm backend is the browser's `fetch`, whose futures
are not `Send` and which cannot reach the virtual loopback anyway, so on wasm32 these clients
issue their requests through `src/client/http_fetch/`: `FetchClient` is the subset of
reqwest's request API the clients use (`get`/`post`/…, `header`, `query`, `json`, `form`,
`body`, `basic_auth`, `timeout`; on the response `status`, `headers`, `text`, `json`,
`bytes`, `chunk`), backed natively by the reqwest client each protocol already builds —
unchanged on the wire — and in the browser by `transport.rs`, which writes the request with
hyper 1's `client::conn::http1` over the shim's `TcpStream`: one connection per request, the
response body read whole against a bound (8 MiB, `MAX_RESPONSE_BODY_BYTES`, unless the client
sets its own) and the exchange against the client's own timeout. **`https://` is refused** at
connect with the reason (`http_fetch::check_url`): the transport has no TLS, and nothing on
the page's network holds a certificate a client could verify. So the client logic above the
round trip is one copy on both targets. The transport compiles natively too:
`tests/client/http/transport_test.rs` drives NetGet's HTTP and TCP servers through it (body,
headers, a 404, a chunked response, the body bound, the deadline), and
`tests/client/http/fetch_client_test.rs` sends the same requests through both backends to a
recording peer and asserts the transport's request line, `Authorization`, `Content-Type`,
query and form encoding and body match reqwest's, and that a binary body survives.

Each client in the browser build is proven in the bundle by `web/test/smoke.mjs`, against
NetGet's own server of its protocol where one speaks it:

| Client | In the browser | Smoke evidence |
|---|---|---|
| `http` | yes | `[ + http client ]` on an http card connects; a model-routed client completes a model-driven GET, a `[ send ]` and a 404 against NetGet's `http` server |
| `jsonrpc` | yes | `[ + JSON-RPC client ]` on the `jsonrpc` server; `[ send ]` `add(2, 3)` → HTTP 200, and the response (`result` 5) parked on the client for the human; an `https://` endpoint refused with the reason |
| `elasticsearch` | yes | `[ + Elasticsearch client ]` on the `elasticsearch` server; `[ send ]` a `search` reaches the server's model with its index and body, and the hits it wrote are parked on the client |
| `openapi` | yes | started through `ClientForm` with the server's spec (`[ + OpenAPI client ]` cannot know the spec; the dashboard's form asks for it): the model runs `listTodos` with a query parameter against the `openapi` server, is shown the response, and `[ send ]` repeats it |
| `bitcoin` | yes | NetGet's `bitcoin` server is the P2P protocol, not Bitcoin Core's JSON-RPC, so the peer is the `http` server answering as bitcoind would: `[ send ]` `get_blockchain_info` → HTTP 200 with the result reported to the model, and `rpc_user`/`rpc_password` arriving as `Authorization: Basic` |
| `npm` | yes | `[ + npm client ]` on the `npm` server; `[ send ]` `get_package_info` → the packument the server's model wrote, parked on the client; `https://registry.npmjs.org` refused with the reason |
| `pypi` | yes | `[ + PyPI client ]` on the `pypi` server; `[ send ]` `get_package_info` → the JSON the server's model wrote, parked on the client |
| `maven` | yes | `[ + Maven client ]` on the `maven` server; `[ send ]` `download_pom` → HTTP 200, the POM the server's model wrote parked on the client |
| `http2` | yes | `[ + HTTP/2 client ]` on the `http2` server; `[ send ]` a GET over h2c with prior knowledge → the response read as `HTTP/2.0`, the model's body and header, parked on the client |
| `ollama` | yes | `[ + Ollama client ]` on the `ollama` server; `[ send ]` a generate request → the completion the server's model wrote, parked on the client |
| `oauth2` | yes | through `ClientForm` (it needs `client_id` and `token_url`, which `[ + client ]` cannot know): the model asks for a client-credentials token, the `oauth2` server's model issues one, and the token event comes back to the model; `[ send ]` repeats it; an `https://` token URL refused |
| `openidconnect` | yes | through `ClientForm` (it needs `client_id`): discovery of the `openid` provider (document and key set written by its model, issuer `http://127.0.0.1:<port>`), then a client-credentials token with the provider's expiry |
| `torrent-tracker` | yes | `[ + BitTorrent Tracker client ]` on the `torrent-tracker` server; `[ send ]` an announce → the server's bencoded reply with a **binary** compact peer list decoded on the client (`127, 0, 0, 1, 26, 225, …`) |

`http2` speaks HTTP/2 with prior knowledge through hyper's `client::conn::http2`
(`transport::exchange_response_h2`), whose connection spawns its own tasks: they go through
`transport::SpawnExecutor`, which is `tokio::spawn` as NetGet names it (the shim's, on the JS
event loop), because hyper-util's `TokioExecutor` would call the real tokio's `spawn`, which
has no runtime in the page. `tests/client/http2/h2_transport_test.rs` holds it to reqwest's
answers natively.

npm, pypi and maven default to public `https://` registries natively; in the browser build a
scheme-less address means `http://` (a server on the page's virtual network) and an explicit
`https://` one is refused with the reason, so none of them can reach the public registries
from the page. The transport reads a response whole, bounded by the client's own cap where it
has one (npm's 64 MiB tarball cap, pypi's download cap, the tracker's 1 MiB), else 8 MiB.

`oauth2` and `openidconnect` do not call reqwest themselves: their crates take the HTTP
function per request (`request_async(f)`, `discover_async(.., f)`). Natively that is still the
crates' own reqwest `async_http_client`; in the browser each client hands them `http_hook`,
which sends the crate's `HttpRequest` through `http_fetch::round_trip_parts` and returns its
`HttpResponse`. Neither crate enforces `https://` — the OAuth2 token URL and the OIDC issuer
are URLs like any other, and discovery only checks that the document names the issuer it was
fetched from — so a provider on the page's network over `http://` is honest, not a bypass.

No HTTP-family client is gated out of the browser build any more: `not(target_arch = "wasm32")`
no longer appears in `src/client/mod.rs` or the client registry.

Left out, and why (re-derive with the probe below rather than trusting this):

- **A dependency needs real sockets** (`mio` on the wasm target): dns/dot/doh/llmnr
  (hickory), ntp (rsntp), ssh/ssh-agent (russh), irc, xmpp, smtp, mysql, mongodb (client
  crate), redis, postgresql, cassandra, nfs, amqp, mqtt, stun/turn/webrtc/websocket,
  socks5, mcp, grpc/etcd (tonic), zookeeper, dynamo, quic/http3 (quinn), couchdb/openai
  (tokio `net` feature).
- **A C library**: mssql, imap, ldap, proxy/http_proxy (openssl), git (the libgit2
  binding), mdns (if-addrs).
- **A crate that assumes an OS HTTP client**: ipp, xmlrpc, webdav.
- **Raw sockets, devices, or the OS itself**: arp, icmp, ospf, datalink, isis, the link
  protocols, usb-*, bluetooth-*, nfc, pty/stdio/named_pipe/socket_file, tuntap, wireguard,
  tor, openvpn. m3ua reaches for socket2 directly.

**Compiling is not running — prove a protocol with a round trip.** The hyper servers are the
case that taught it. `http`, `http2`, `openapi`, `jsonrpc`, `oauth2`, `openid`, `ollama`,
`elasticsearch`, `npm`, `pypi`, `maven`, `yarn`, `spark`, `snowflake`, `rss`, `mercurial`,
`oci-registry`, `saml-idp`, `saml-sp` and `kubernetes-server` all compiled, bound, accepted
and logged — and until September 2026 every hyper-based one of them killed the page on the
first byte of a request: hyper's HTTP/1 dispatcher calls `T::update_date()` at the top of every
poll, whatever `auto_date_header` says, which reached `std::time::SystemTime::now()`, and on
`wasm32-unknown-unknown` that panics inside a dependency where `crate::utils::clock` cannot
reach.

The fix is a patched hyper: `vendor/hyper` is the exact crates.io source of the version
Cargo.lock pins, changed only in `src/common/date.rs` so that on wasm32-unknown-unknown the
date cache reads JavaScript's `Date.now()` (the `Date` header stays correct); the root
`Cargo.toml`'s `[patch.crates-io]` points hyper there, native builds compile upstream's code
unchanged, and `tests/vendored_hyper_patch_test.rs` fails if Cargo.lock's hyper drifts from the
vendored copy or the patch goes missing. `vendor/hyper/README.md` has the diff and how to
re-apply it on an upgrade.

**Proven by `web/test/smoke.mjs`**, with Node's own HTTP clients (`node:http`, `node:http2`)
over `NetGet.connect()` and every response model-answered: `http` (a GET and a POST with a
body, and NetGet's own `http` client against it), `openapi` (a spec-routed GET), `jsonrpc` (a
result and an error), `rss` (a rendered feed), each with a `Date` header checked to be today's,
and `http2` over prior-knowledge h2c — which is the `h2` crate rather than hyper and never
touched the date cache. NetGet's own clients add round trips to more of them (see the client
table above): `elasticsearch`, `npm`, `pypi`, `maven`, `ollama`, `oauth2` and `openid` each
answer a model-written response to NetGet's client of their protocol, as does
`torrent-tracker`, which is not hyper. `remaining_http_servers.mjs`, called by the same smoke
run, drives `yarn`, `spark`, `snowflake`, `mercurial`, `oci-registry`, `saml-idp`, `saml-sp`, and
`kubernetes-server` through Node's HTTP client with static protocol handlers. It checks each
response's protocol envelope, content type and Date header, including Snowflake POST bodies,
Mercurial's wire text, SAML metadata XML and Kubernetes list objects.

`web/test/nostr_browser.mjs` covers the native Nostr relay with real Chromium, independently
of the virtual browser network. It starts a temporary relay from `NETGET_BIN`, fetches NIP-11
from a different page origin (so browser CORS is enforced), subscribes over Chromium's native
WebSocket, publishes a signed event, checks live delivery and tampering rejection, and completes
the close handshake. `nak` signs the input and verifies the relay's returned event independently.
It requires a native binary with `nostr`, `nak` on PATH, and Playwright/Chromium; missing tools fail.

```bash
npm install --prefix /tmp/netget-browser-evidence playwright@1.57.0
node /tmp/netget-browser-evidence/node_modules/playwright/cli.js install chromium
PLAYWRIGHT_MODULE=/tmp/netget-browser-evidence/node_modules/playwright/index.mjs \
  NETGET_BIN="$PWD/target/debug/netget" node web/test/nostr_browser.mjs
```

`BROWSER_EXECUTABLE_PATH` can select an already installed Chromium. The test makes no remote
requests and uses static handlers, so it needs no model. Its temporary server is stopped and
its files removed on both success and failure.

To re-derive the list, run the probe: for each feature, `cargo check --target
wasm32-unknown-unknown --no-default-features --features tcp,udp,telnet,http,<f> --lib`
and sort the failures by where the first error lands — inside `src/client/<f>/` means the
client can be gated and the server kept; anywhere else means the feature stays out until
its dependency does.

## Adding a protocol to the browser build

1. Add its feature in `crates/netget-web/Cargo.toml`.
2. `cargo check -p netget-web --target wasm32-unknown-unknown`. Anything that uses only
   `tokio::net::{TcpListener, TcpStream, UdpSocket}`, `tokio::io`, `tokio::sync` and
   `tokio::time` compiles as is. Multicast joins and socket options are accepted and
   ignored by the virtual network. Anything that shells out or opens files compiles but
   fails at runtime.
3. `std::time::Instant` and `SystemTime` are already `crate::utils::clock::*` throughout
   `src/`; keep new code on that alias. On wasm the shim's `Instant` is its own type, so a
   stray `std::time::Instant` is a **compile** error there, not a runtime panic. A
   *dependency* calling `SystemTime::now()` is the one this does not cover — that is a
   runtime panic, found only by a round trip (hyper's date cache was the case; see above).
4. The virtual `TcpStream` supports `peek`, so the first-byte deadline the hyper-based
   servers take before `serve_connection` compiles and behaves the same way here: it reads,
   holds what it read in a pushback buffer, and the next read returns those bytes first. See
   `crates/netget-tokio-wasm/tests/tcp_peek_test.rs`.
5. Build, then extend `web/test/smoke.mjs` or the page with a client for it.

### CPU-only browser regression mode

`NETGET_CPU_ONLY=1 python3 web/test/page_composer.py` disables Chromium GPU,
compositing, software rasterizer, WebGPU and on-device-model features. Every page
starts with unavailable real GPU/model APIs before installing plain-JavaScript
scenario fixtures. External page requests are intercepted, and the real Prompt
API probe is skipped. This validates DOM/composer/model-selection behavior without
GPU discovery, inference or model downloads. Build the current WASM first for
Rust/browser integration coverage; `CARGO_TARGET_DIR` is supported by `web/build.sh`.

The virtual network bounds TCP pending accepts at 128; connecting waits for a
slot before allocating a duplex pair. UDP retains at most 128 queued datagrams
plus a peeked datagram and drops new arrivals at capacity. Its receive/peek/
readiness state is serialized under one lock, and all receive variants honor a
connected peer. The shim's native integration tests need neither a browser nor
real sockets.
