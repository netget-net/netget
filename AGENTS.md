# NetGet — LLM-Controlled Network Protocol Server & Client

Rust CLI where an LLM (Ollama or any OpenAI-compatible endpoint) drives ~116 network
protocols as servers and ~90 as clients. NetGet owns the network stack; the LLM decides
what to say on the wire, either by reasoning per-request or via deterministic handlers.

Three ways to run it: interactive TUI (default), headless (`--mcp` / `--mcp-http`, see
`src/mcp_stdio/AGENTS.md`), and non-interactive one-shot (`src/cli/non_interactive.rs`).

A non-interactive run (a prompt, `--load`, `--server`, `--client`) serves **every** server it
started until all have stopped or Ctrl+C, keeps a clients-only run alive while any client is
connected, and exits **non-zero** if anything it was asked to start failed. `--run-for <SECS>`
and `--exit-after-events <N>` end it with status 0; the event count is the access log's
monotonic total (`AppState::access_log_total`), so it counts every handled event on every
instance whoever answered it. `tests/non_interactive_run_limits_test.rs` drives the binary.

**The interactive TUI is the full-screen ratatui dashboard (`src/tui/`)**, the only
interactive UI — the rolling-terminal TUI that used to sit behind `--legacy-tui` was removed
in September 2026, and the scheduled-task tick it owned lives in `src/cli/tasks.rs`.
`src/tui/AGENTS.md` is the design document; the short version:

- **Left column is every instance, always visible.** A scrollable canvas of **cards**: each
  server and client with its summary line (status glyph, id, protocol, address, live peers,
  a 30-second sparkline, a **driver badge**), the requests parked for you, a facts line, its
  **buttons as an aligned grid**, and its sections — `peers` (each peer with its own buttons
  and its requests beneath), `rules` (each rule with delete / ↑ / ↓ beside it), `config`;
  `send` and `connections` for a client. Under every peer and every client connection sits
  the **conversation on it** — one row per message in, one per message out, oldest first,
  each opening the full entry — with `[ send message ]` beneath, and `[ + <proto> client ]`
  at the foot of a server's peers. Nothing is selected or drilled into: ↑/↓ walk every row,
  ←/→ walk a row's buttons (and fold / unfold a section), Enter acts, letters act on the card
  under the cursor. One `+ new server or client` row at the foot opens a picker listing
  both kinds together. A server entry names the port it will start on — its **well-known
  port** ("starts on well-known port 6379"), or why not ("well-known port 53 needs root;
  starting on an OS-assigned port", "… is in use; …") — resolved by `protocol::default_port`
  when the picker opens and again on Enter, and the create form's `port` field is pre-filled
  with that number and says where it came from.
- **Right column is one stream.** Machine events derived from snapshot diffs (instances
  starting, peers connecting, every request with its answer, questions parked for you —
  Enter opens the thing a line names), the `[LEVEL]` log lines, and the conversation (what
  you typed, the model's reasoning and replies, command output) are one timeline, with the
  input box at the bottom. Tab hops between the two columns and does nothing else.
- **Manual first, model optional.** The **driver** (`driver.rs`) is one word for an
  instance's wildcard rule: `MANUAL` (every unmatched event parks for you), `LLM` (no
  wildcard; the instruction answers), `SILENT` (`*` → static, no actions), `RULES` (a custom
  wildcard). `m`, or `[ driver: … ]` in the bar, cycles MANUAL → LLM → SILENT as a hot
  handler-table swap that keeps every specific rule. The rules tab edits the table inline
  (add / edit open the routing modal; delete / move apply headlessly through the same
  `RoutingModel`). Instances created here default to `*` → manual.

Everything applies through `cli::management`'s `ServerForm`/`ClientForm`/`update_*`, so
validation and the hot-apply vs restart split are identical to the LLM and MCP paths. The forms
submit only *changed* fields — re-sending an unchanged port or host reads as a change and forces
a needless restart. A startup parameter's declared `default` (`ParameterDefinition::default`) is
pre-filled as its value, marked `(default)`, and counts as unchanged on create as well as edit,
so an untouched default is never submitted and the new instance's `startup_params` records only
what the operator chose.

**Every action is an `InstanceAction`** (`cards.rs`), executed by `actions::run` whether it
came from a letter (`x` stop, `e` edit, `r` rules, `m` driver, `c` connect a client to a
server, `n` send through a client, `w` wireshark, `d` docs, `a` new instance), from a button,
from a click, or from Enter on a row (a peer unfolds its requests; a request opens its full
request/response; a rule edits it; a config row opens the form; a verb opens the composer on
its parameters; a parked request opens the answer modal). Esc returns to the chat box. No
modal requires a chord: every button is a Tab stop, and the text editor's Tab leaves the text
for `[ Accept ]` / `[ Cancel ]`.

A server's live peer carries `[ message ]` and `[ disconnect ]` on its own row where the
protocol registered a peer handle (`server/peer_support.rs`; `tcp` and `telnet` have);
`[ disconnect ]` runs its `close_connection` through the same handle (half-close + marked
closed at once, because a peer that never reads — our own client parked on a manual question
— would otherwise stay "live" after you hung up). Without a handle the buttons stay, disabled,
and say why. A peer whose request is parked is flagged on its own row, in the list badge
(`⚠1`), in the overview's first line, in the feed and in the status bar — which is clickable
and opens the oldest one.

**Answering a parked request is the composer, not a JSON box.** The intercept modal offers three
things: `[ Compose answer… ]` opens `ComposerModel::for_intercept` — pick one of the protocol's
actions from a list, fill its parameters as fields (a `bool` parameter is a checkbox: Enter or
Space flips it), Send resolves the intercept and closes both modals; `[ Answer with nothing ]`
resolves with zero actions (acknowledge, say nothing — a real answer, distinct from a timeout);
`[ Fail closed ]` refuses. Raw JSON is still one button away inside the composer, and for an
intercept it accepts an array so a multi-action answer is possible; it is never the starting
point.

Stopping is immediate: only the bulk actions (stop all, quit) still confirm.

`tests/dashboard_frame_test.rs` renders whole frames into ratatui's `TestBackend` — the way to
see what a layout change does to a populated screen without a pty, and the place to assert on
it. The pty snapshots in `tests/terminal_snapshot/` prove the real binary paints.

**`[ wireshark ]`** (`w`, a button on every card, and a `[ View in Wireshark ]` button on the
create/edit form so the capture can be running *before* the instance starts) opens a modal with a paste-ready
`wireshark -k …` / `tshark -l …` line, plus the pieces separately: interface, BPF capture filter,
display filter and a `-d` decode-as clause. NetGet writes no pcap; `src/tui/wireshark.rs` is a
pure table of NetGet protocol → transport + Wireshark dissector name, and every name in it was
checked against `tshark -d` / `-Y`. Three traps it encodes: `isis` is an Ethernet-only BPF keyword
and is rejected on loopback; `drda` (db2) is heuristic-only and not in the `tcp.port` decode-as
table; `ipp` is reached through `http`. A protocol missing from the table is treated as plain TCP
(correct for everything in the registry that is not UDP, raw or off-network), and the off-network
families (USB, BLE, NFC, pty/pipe/stdio) get an explanation of where to look instead of a command.

## Protocol inventory — always query, never trust a list

Protocol lists in docs go stale within weeks. Get ground truth from the registry:

```bash
# Every registered server protocol + maturity + implementation note
grep -n "register(Arc::new" src/protocol/server_registry.rs
grep -rn "DevelopmentState::" src/server/<protocol>/actions.rs   # that protocol's own claim

# At runtime (authoritative — reflects compiled-in features)
netget --mcp   # then call list_protocols / get_protocol_docs
```

Maturity lives in each protocol's `metadata()` (`ProtocolMetadataV2`, `src/protocol/metadata.rs`):

- **Stable** — **four as of 30 September 2026: `coap`, `dns`, `modbus` and `smb`.** Before
  16 September 2026 there were none, and three protocols had held the rating and lost it, each
  for the same reason: nobody had said what it required, so "Stable" meant whoever set it felt
  good about the code. The bar below is what replaced that, and these four are the ones
  measured against it rather than against a feeling. Each carries its own justification in
  `metadata()` — read `e2e_testing` and `notes` there, and the "Maturity: the six conditions"
  section at the foot of each `src/server/<p>/CLAUDE.md`, before quoting any of the ratings:
  each says in as many words that the rating covers the evidence for the surface the server
  *implements*, which in every case is a subset of the specification.

  **One condition was false for `coap` when that pass began, and how it broke generalises.**
  `fuzz/fuzz_targets/coap_message.rs` had not compiled since `0996d00f` made
  `CoapMessage::encode` fallible — hours after the target was written — so "a fuzz target
  exists and has run clean" was a claim about a file rather than an execution. **No CI job
  builds `fuzz/` at all**; it is deliberately its own workspace (nightly toolchain, libFuzzer
  runtime), so `cargo check` at the repository root never sees it. Condition 3 is therefore the
  one most likely to be silently false for any protocol. Rebuild before believing it:

  ```bash
  cd fuzz && rustup run nightly-2025-12-04 cargo fuzz build <target>
  ```

  (`cargo +nightly fuzz` fails on this machine: asdf's shims precede `~/.cargo/bin` on `PATH`,
  so `cargo` is not the rustup proxy and `+toolchain` is read as a subcommand name.)

  A protocol is Stable when **all six** hold. Each one exists because its absence produced a
  false Stable rating here:

  1. **Two independent third-party clients** complete a real session, in tests that *fail*
     rather than skip when the client is absent. Two, not one, because one client can agree
     with one bug — and independent of the server's own library, which is the circular case
     that made `ssh`/russh look like evidence.
  2. **The pcap oracle is green** over its wire traffic (`tests/helpers/pcap_oracle.rs`). An
     independent dissector reading the bytes catches what agreement between our encoder and
     our decoder cannot.
  3. **A fuzz target exists and has run clean** (`fuzz/`), with a corpus that includes a depth
     bomb — without one, a coverage-guided fuzzer never explores nesting and runs green
     forever against the class it exists for.
  4. **Every declared bound has a test**: max message size, idle timeout, connection cap,
     recursion depth. A bound nobody tested is a comment.
  5. **Its two `AGENTS.md` files were verified against source in the current pass**, not
     inherited. `ssh`'s said "there is no E2E test" while eleven existed.
  6. **No `#[ignore]` and no skip-when-missing gate in its suite.**

  **Cheapest candidates, re-derived 16 September 2026 against condition 1 — which is the one
  that eliminates almost everything.** Three protocols held conditions 1, 2, 3 and 6 that day:
  `coap` (libcoap's `coap-client` plus the coap-lite/coap Rust codecs), `modbus` (tokio-modbus
  plus libmodbus's `mbpoll`) and `dns` (ISC `dig` plus Knot `kdig`). Each names two independent
  clients in its own `e2e_testing`, each has a `tests/server/<p>/` file using `pcap_oracle`, each
  has a fuzz target with a corpus, and no suite has an `#[ignore]` or a skip gate. What was left
  for them was condition 4 (a test per declared bound) and condition 5 (both `AGENTS.md` files
  re-verified against source). **All three went the rest of the way and are Stable** — `coap`
  and `dns` on 16 September, `modbus` on 26 September 2026. `smb` followed on 30 September
  2026 from Beta, with conditions 1, 3 and 4 made true in the pass rather than found true.

  Things those passes turned up which are worth carrying to whatever comes next:

  - **Condition 4 is where the declared number turns out to be the wrong number.** `coap`
    declared `.max_inbound_bytes(MAX_PAYLOAD_LEN)`, which bounds what the server *writes*;
    nothing bounded the inbound path at all. The generic `bound + 1` probe could not catch it
    because it reaches servers over `TcpStream::connect` and skips every UDP protocol. Check
    which direction a declared bound actually governs, not just that something enforces it.
  - **Condition 5 turns up fail-silents, because the false doc claim is usually a promise the
    code does not keep.** `dns`'s CLAUDE.md said a query is answered SERVFAIL when the model
    "returned nothing usable"; `call_llm` returns `Ok` in exactly that case, so the one clause
    the sentence existed for was the one that wrote nothing at all. Read the doc's failure
    section as a list of assertions to test, not as description.
  - **Condition 1 can be true of a sample rather than the surface.** `modbus` had two clients
    for weeks, but neither issued FC 2, 5 or 15 and one never issued FC 16, while `metadata()`
    named FC 2 as decoded. Count the verbs each client drives against the verbs the server
    implements. The same pass found condition 2 satisfied by exception frames alone — the
    success paths were read by a client library that never showed the test the bytes.
  - **A client drives only what its CLI exposes, so count what it sends, not what it runs.**
    `smb`'s real-client tests print every command each client put on the wire with every
    NTSTATUS it was answered with. That showed smbclient never sending the LOGOFF its docs
    claimed, and `rm` showed a delete arriving as an ordinary CREATE (`FILE_DELETE_ON_CLOSE`)
    that the model approved without knowing. The same pass found a compound reply too large
    for one 24-bit Direct TCP frame panicking the connection task — a bound on what the server
    *writes*, the coap direction again.
  - **Condition 4 finds defects, not just missing tests.** Testing that a closed connection
    returns its cap slot found that a Modbus connection closed for a framing error kept its
    slot as long as the peer held its end open: `close` shut the write half from another task
    and the reader never learned. A bound the test removal cannot move — `MAX_BUFFERED` was
    checked at a second site that could never fire — is a comment, and was removed.

  **Nine protocols now have two clients and still fail conditions 2 or 3**, which is worth knowing
  before picking the next one: `doh`, `dot`, `etcd`, `grpc`, `postgresql` and `websocket` have
  neither a pcap-oracle test nor a fuzz target; `mongodb` has a fuzz target
  (`fuzz_targets/bson_document.rs`) and no oracle; `mqtt` and `kafka` have the oracle and no
  fuzz target. (`redis` was in that last group until `fuzz_targets/resp_frame.rs` landed in
  September 2026.) A fuzz target with a depth-bomb corpus is the cheaper of the two to
  add. Derive this rather than trusting it — and note that fuzz targets are named after the
  *decoder*, not the protocol, so read each target's `use` lines rather than grepping its name:

  ```bash
  grep -rln pcap_oracle tests/server/<p>/ ; grep -ln "<p>\|<decoder crate>" fuzz/fuzz_targets/*.rs
  ```

  This line used to name `whois`, `gopher`, `finger`, `dns`, `http`, `tcp`, `ntp` and `redis` as
  the cheapest candidates. Every one of them rests on a **single** client, so none of them is
  one step from Stable — they are one *client* from even being eligible. The list was written
  against the other five conditions and skipped the first, which is the expensive one.

  The three demotions are worth reading before setting this on anything, because each one is a
  different way the bar above can be failed while the rating looks earned. `tor_relay` and
  `openvpn` went first. `wireguard` was the last, demoted August 2026: NetGet implements none
  of the WireGuard protocol itself (it orchestrates `defguard_wireguard_rs`, which needs root and,
  on macOS, an external `wireguard-go` binary), so it cannot be started or handshaked in this
  environment at all, and its Stable rating rested on a test that mocked a `wireguard_packet_received`
  event and a `log_packet` action **that do not exist**, all `#[ignore]`d behind root so the
  mismatch never surfaced. The bar for Stable is a test that a real independent peer completed a
  real exchange — treat any Stable claim without one as this same bug.

  **That demotion undershot, and the correction is the useful lesson.** `wireguard` was moved
  Stable→Beta on the grounds that it had never been validated against a real client — but that
  is *also* the definition of Beta, so the same evidence ruled Beta out and nobody noticed for
  months. It is now Experimental. When you demote for missing evidence, check which ratings that
  evidence actually supports rather than stepping down one notch by reflex.
- **Beta** — human-reviewed, works against real clients (60 protocols as of 30 September 2026:
  49 plus nine new servers that each arrived Beta on a real client — `dict`, `gemini`,
  `prometheus`, `docker`, `vault`, `beanstalkd`, `zabbix`, `gearman`, `bolt` — less `modbus`,
  which went to Stable, plus `nostr`, a new relay that
  arrived Beta on nak and rust-nostr's `nostr-sdk`, and `nsq` (`to_nsq`, `nsq_tail`) and `otlp`
  (`otel-cli`, `telemetrygen`), new servers that arrived Beta the same day; re-derive, the count drifts every pass —
  `python3 scripts/beta_evidence_table.py --check` prints it).

  **Do not read the rest of this section as the list. Generate it:**

  ```bash
  python3 scripts/beta_evidence_table.py            # every Beta, with its peer
  python3 scripts/beta_evidence_table.py --all      # every protocol
  python3 scripts/beta_evidence_table.py --experimental-with-evidence   # candidates
  ```

  For each protocol it prints, from source, the third-party binaries and crates the tests
  actually drive, which of those the server itself also imports (circular), which are
  `optional = true`, how many tests are `#[ignore]`d, and whether any test prints a skip
  message and returns success anyway. It separates what a script can be sure of (no
  independent peer, a skip-and-pass gate, every test ignored — `--check` fails on these)
  from what needs a human (a shared peer, an optional dependency — both have accepted
  exceptions, see `quic`/quinn below). The prose that follows is history and reasoning;
  the table is the fact. `ollama` joined in September 2026: `ollama-rs` is
  pointed at NetGet's own Ollama server and deserialises our `/api/tags`, `/api/generate` and
  `/api/chat` envelopes for itself. It is an unconditional dependency rather than an
  `optional = true` one, so unlike `amqp`'s `lapin` the evidence actually runs where the gate
  runs; and it is not circular, because this server frames with hyper and serde_json and never
  touches the crate — the quinn precedent, not the tokio-tungstenite one. The original ten are
  `dns`, `doh`, `dot`, `http`, `ntp`, `openai`, `snmp`, `tcp`, `udp`, `whois`; August 2026 added
  fourteen that are each driven by the protocol's own third-party client in a test that is **not**
  `#[ignore]`d — `amqp` (lapin), `cassandra` (scylla), `coap` (coap-lite), `imap` (async-imap),
  `ldap` (ldap3), `mongodb` (official driver), `mssql` (tiberius), `mysql` (mysql_async, and since September 2026 the real `mysql` CLI too — see below),
  `postgresql` (tokio-postgres), `redis` (redis-rs), `sqs` (aws-sdk-sqs), `webdav`
  (reqwest_dav), `zookeeper` (zookeeper-async). Each protocol's `metadata()` names its client.
  **August 28 2026 added two more**: `npm` (the real npm CLI — `npm view` resolves the packument
  and `npm install` unpacks the served tarball into `node_modules/`) and `mqtt` (rumqttc, taken
  through CONNECT → SUBSCRIBE → SUBACK → PUBLISH and back to the broker's own PUBLISH).
  **August 29 2026 added five more, all of which already had the evidence** and were sitting at
  Experimental only because nobody had re-read it: `etcd` (etcd-client), `modbus`
  (tokio-modbus), `quic` (quinn), `mdns` (mdns-sd) and `dynamo` (aws-sdk-dynamodb). Two of
  those were on the "not promoted" list below for reasons that had gone stale — `etcd` was
  listed as having only generic-HTTP evidence when its test drives the official `etcd_client`,
  and `modbus` as having "no independent peer at all" when its test is literally named
  `test_modbus_reads_writes_and_exceptions_against_tokio_modbus`. **Re-derive this list before
  trusting it in either direction**: it under-rates as readily as it over-rates.
  **August 30 2026 added four more** (`rss` is the fourth — see below) from a sweep of the
  remaining ~104 Experimental servers:
  `git` (the real `git` binary clones over Smart HTTP, then `git fsck --full` validates the pack
  and `git show HEAD:README.md` asserts exact blob bytes), `s3` (rust-s3 0.37 `Bucket`, path-style
  — ListObjects/GetObject/PutObject/HeadObject/DeleteObject, each pinned to `expect_calls(1)`
  through a retry helper, so a response rust-s3 rejected would retry and fail the count), and
  `webrtc` (a webrtc-rs 0.11 `RTCPeerConnection` completes ICE + DTLS + SCTP and a message is
  asserted to have crossed the data channel in both directions). `git` was on the
  generic-HTTP-client list below and had stopped being true.

  Checked and *not* promoted in the same pass, with the reason: `xmpp` (its own test says
  `tokio_xmpp::Client` cannot complete its connect), `bitcoin` (the `bitcoin` crate is used as a
  codec, not as a peer completing a session — the `dhcp` situation), `vnc` (no third-party
  client; the apparent import was netget's own path), `bgp` and `torrent_dht` and `xmlrpc`
  (codecs and parsers rather than clients). **`grpc` was on that list and is now Beta** —
  grpcurl, which is grpc-go, completes a unary call and reads back an error status, in two
  tests that hard-fail rather than skip. Getting there meant fixing the defect the Go client
  found; see the trailers entry below.

  **September 16 2026 added four more, and three of them cost a bug fix first.**
  `stun` (stuntman's `stunclient`, which must un-XOR our XOR-MAPPED-ADDRESS against the cookie
  and its own transaction id — both the static zero-LLM encoder and the action encoder are
  covered, and only the first had ever faced anything third-party), `sip` (sipsak, which exits
  0 only after matching Via+branch, Call-ID and CSeq — the correlation a dissector cannot
  check), `torrent_tracker` (aria2c decoded our **compact** peer list and dialled both peers out
  of it, which is the branch a real swarm always takes and a stride or byte-order error loses),
  and `grpc` and `etcd` on the trailers fix.

  **`etcd` was demoted and re-promoted in the same week, and the round trip is the lesson.**
  Its Beta rested on `etcd-client`, which is tonic; tonic accepts a `grpc-status` in the initial
  HEADERS beside a DATA body, and the gRPC specification does not. `etcdctl` — grpc-go — could
  not complete a **single** RPC carrying a body. `grpc` had the identical defect, found the same
  day by grpcurl. In both servers the *error* path was accidentally correct, because an empty
  body makes it Trailers-Only, so **only the success path was broken and the failure paths were
  the ones the tests asserted on**. Both now emit real trailing HEADERS and both keep
  Trailers-Only for errors, and each has a second, stricter client asserting it. The shape to
  remember: **one client agreeing is not "works against real clients"** — it is the
  `mysql`/`mysql_async` situation, where the rating rested on the only implementation lenient
  enough to tolerate the bug until a second client was pointed at it.

  The August 30 sweep of the rest turned up four more near-misses, and the reasons are worth
  keeping because each looks like evidence until you read it:

  - **A real client behind a skip-when-missing gate is not evidence** — this entry listed
    `oci_registry` (crane), `maven` (mvn, and additionally `#[ignore]`d) and `websocket`
    (websocat). Each printed `SKIP: … is not installed` and returned `Ok(())`, so on a runner
    without the binary it was a silent pass. `npm`'s real-CLI test is the shape to copy: it
    **fails** when npm is absent, saying in as many words that skipping "would leave NPM's
    maturity rating resting on nothing". `kubernetes` took that path in September 2026; **the
    other three followed on September 15 2026 and are all Beta now**, along with `memcached`
    and `rtsp`. The price is that the binary has to exist wherever the suite runs, so
    `registry-audit` installs crane, websocat, ffmpeg, libmemcached-tools, maven, npm,
    freeradius-utils, dig, curl, pip, openvpn and tor.

    **An `#[ignore]` for "run manually" is the same gate with better manners** — nothing ever
    runs it, so the rating rests on a test that has never executed. `rtsp`'s ffprobe test and
    `hls`'s curl test were both in that state while `metadata()` cited them; both now run.
  - **`#[ignore]`d, however good the reason** — `bluetooth_ble` (btleplug is a real BLE central
    and the suite is verified passing by hand, but all three tests claim the machine's single
    adapter and are ignored so a 100-thread run does not deadlock on it) and `tor_relay`
    (`tests/server/tor_integration` drives the official `tor` binary and is `#[ignore]`d).
  - **Circular: the "peer" is the same crate the server frames with** — `webrtc_signaling` and
    `websocket` are both driven by `tokio-tungstenite`, which is what their servers use.
    `tests/server/websocket/e2e_test.rs` states the rule in its own header and hand-writes a raw
    RFC 6455 client instead. For `webrtc_signaling` there is no way out: the layer NetGet
    actually authors is an ad-hoc JSON relay schema, so no third-party implementation of it
    exists or could. (`webrtc` itself is *not* this case in the way that matters — the peer is
    webrtc-rs in the opposite role completing a real ICE/DTLS/SCTP handshake, which is the
    already-accepted `quic`/quinn precedent, and what it validates is NetGet's own signalling,
    admission and data-channel plumbing. Browser interop remains unproven and is what a human
    should check before it goes past Beta.)
  - **A client hand-written inside the test is not a third-party client** — `usb/serial` and
    `usb/smartcard` are driven by `tests/helpers/usbip_client.rs`, which speaks USB/IP from the
    wire format deliberately (no macOS USB/IP client exists). Same class as `dhcp`'s in-test RFC
    2131 decoder: an independent reading of the spec, not an independent implementation.
    `torrent_tracker` was the same shape via `serde_bencode` and is now Beta on aria2c.

  `openvpn` is a fifth case and a different one: its real-client test is **not** ignored and
  **does** hard-fail when the binary is missing, the system `openvpn` 2.x accepts our
  `P_CONTROL_HARD_RESET_SERVER_V2` and goes on to send a TLS ClientHello, and the test asserts
  both. It stays Experimental anyway, on its own metadata's reasoning: the server implements
  only the front of the protocol, so no client can use it as a VPN, and "works against real
  clients" would be a false claim whatever the test shows. Do not promote it on the test alone.

  Deliberately **not** promoted despite an audit suggesting them: anything whose only evidence is
  a generic HTTP client (`reqwest` proves an HTTP server answers, not that the protocol on top is
  right — `couchdb`, `openapi`, `spark`, `xmlrpc`, `yarn`,
  `jsonrpc`, `oauth2`, `saml_sp`, `proxy`, `http2`); anything with no independent peer at
  all (`named_pipe`, `pty`, `socket_file`, `stdio`).

  **`memcached` was on that second list and it had stopped being true.** libmemcached 1.0.18's
  `memcat`, `memstat` and `memping` — a separate C implementation, run as subprocesses and
  never linked — drive it in `tests/server/memcached/real_client_test.rs`. They sat behind a
  skip gate, which is why the list said "no independent peer"; the two are different failures
  and conflating them is how a protocol stays under-rated. `memcat` is picky in exactly the
  right place: it reads the byte count out of the `VALUE` header and then reads that many
  bytes, so a wrong count is an empty result rather than a pass. It is Beta.

  **The generic-HTTP rule needs one qualification that cost a scan a false positive**: it rules
  out a client for a protocol layered *on* HTTP, not for a protocol that *is* HTTP. `curl`
  against `gopher://` is a real Gopher client; `curl` against an HLS playlist proves the
  transport and nothing above it. `scripts/beta_evidence_table.py` derives the difference from
  `stack_name()` — `ETH>IP>TCP>HTTP` is HTTP, `ETH>IP>TCP>HTTP>Maven` is not.

  **`ssh` has now been wrong in BOTH directions inside six weeks, and the second error is
  the more instructive.** It was first listed as Beta "driven by russh" — russh is the
  server's own library, so that was the circular case, and the demotion to Experimental
  was right about *that*. But the demotion then asserted that no third-party client
  completes a session, and the tests never used russh: they use `ssh2`, a binding to the
  **C libssh2**, which shares no line of code with it.
  `tests/server/ssh/test.rs::test_sftp_basic_operations` completes the transport handshake,
  password auth, the SFTP subsystem, `opendir`/`readdir`, `open`+`read` and `lstat`, with
  the file's bytes and declared size asserted exactly — not `#[ignore]`d, no skip gate.
  That is the exact bar `actions.rs`'s own comment set for promotion.

  The false claim traced to **one stale comment** in that test file saying libssh2 "has
  timing/compatibility issues with russh server". It described a *test* bug — libssh2 is
  blocking, and running it on the Tokio runtime the in-process mock also needs deadlocks
  the two — fixed long before by moving every libssh2 call onto `spawn_blocking`. The
  comment outlived the fix and was quoted verbatim in `metadata()` and in
  `src/server/ssh/AGENTS.md` as the reason for the rating. `ssh` is Beta.

  **Check what a test drives, not what the server links.** The demotion read `russh` in
  `src/` and never looked for `ssh2::Session` in `tests/`. That is a two-minute grep, and
  it is the one `scripts/beta_evidence_table.py` now does for every protocol.

  `radius` was listed as having **no independent peer at all**, which is the opposite
  error: `tests/server/radius/real_client_test.rs` drives FreeRADIUS `radclient`, and
  radclient verifies our Response Authenticator, so it checks the one thing that
  matters. That test now hard-fails when radclient is absent, and `radius` is Beta.

  **`rss` was on that list for circular evidence and is now Beta**, by the fix the list itself
  prescribed. The server builds its XML with the `rss` crate's `ChannelBuilder` and the test
  parsed the result back with the `rss` crate, so it asserted only that one crate round-trips
  through itself. `feed-rs` 2 is now a dev-dependency and does the parsing: it recognises the
  feed as `FeedType::RSS2` and the test asserts channel title/description/language, three
  entries, the first entry's title and link, that its RFC 2822 `pub_date` became a real
  timestamp, and its categories. RSS has no session — fetch-and-parse *is* the protocol — so an
  independent reader is the strongest evidence the protocol admits. (The same note claimed the
  `rss` test "currently fails"; it passes.)

  **`mqtt` was on this list for a reason that was wrong twice over** and is now Beta. The claim
  was "whose rumqttc tests are all `#[ignore]`d": in fact the four pub/sub tests were inside a
  `/* … */` block, so nothing compiled them and `--include-ignored` could never have run them,
  and the rumqttc test that *does* run was never ignored. Their "MQTT broker not yet
  implemented" markers were left over from a placeholder the broker had long replaced. **Check
  whether an `#[ignore]` is even reachable before believing what it says** — a stale marker
  inside dead code held a working protocol at Experimental for months.

  `dhcp` and `wireguard` were removed for the same reason — neither has a third-party
  peer. dhcp's own metadata says no real DHCP client can be pointed at it (dhclient/ipconfig bind
  UDP/68, need root, and cannot target an ephemeral loopback port), so its peer is an in-test RFC
  2131 decoder: an independent reading of the spec, but not an independent implementation.

  Re-derive this list rather than trusting it; the counts drift.

  **`mysql` was the worked example of one client agreeing with one bug, and it is now the
  worked example of fixing that.** Found in September 2026 by pointing the real CLI at it
  rather than by reading: the server offered `mysql_native_password`, whose client plugin
  MySQL 9.0 deleted, so `mysql` 9.x failed with `ERROR 2059 … cannot be loaded` and the Beta
  rating rested entirely on `mysql_async` being more permissive than the client a user would
  reach for. The server now offers `caching_sha2_password` — **which authenticates nothing;
  it is a statement about packets, and `src/server/mysql/caching_sha2.rs` says so in its first
  paragraph** — and `tests/server/mysql/real_client_test.rs` drives the real CLI through a
  session, so there are two independent clients.

  Two things from that repair generalise:

  - **Reverting the obvious line did not reproduce the failure.** The greeting was not what
    the client died on; it answers a greeting it cannot honour by naming its own plugin, and
    dies on the `AuthSwitchRequest` that follows. A regression test that asserted on the
    plugin name would have been green against the bug.
  - **A protocol's own suite is what catches the collateral damage.** Injecting one packet
    beneath `opensrv-mysql` meant wrapping the writer, which silently stopped vectored writes
    and split every packet in two. Only the pre-existing raw-socket test in
    `packet_limit_test.rs` could see it — every real client reassembles.

  **And check that the mechanism giving the evidence its force actually covers every verb the
  rating names.** `s3`'s Beta rests on each operation being pinned to `expect_calls(1)` through
  a `retry` helper — the point being that a response rust-s3 *rejects* makes it retry, which
  breaks the count. But `head_object` and `delete_object` were issued **outside** that helper,
  with their errors swallowed into a `println!("[INFO] …")`, so those two verbs were named in
  the Beta claim while asserted by nothing. The rating was right; two fifths of its evidence
  was decorative.
- **The client bar is the mirror of the Beta bar above, and it is genuinely different.** Written
  down 16 September 2026, because 97 of 98 clients sit at Experimental and nothing in this file
  said what the ninety-eighth had that the others did not.

  A server proves itself against a third-party **client**. A client proves itself against a
  third-party **server** — never NetGet's own server of the same protocol. That is the
  circular-evidence case this section names for `ssh`/russh, wearing the other hat: pointing
  NetGet's redis client at NetGet's redis server proves the two agree, which is what they were
  both written to do.

  A client is **Beta** when all four hold:

  1. **The peer is a real third-party server** — a binary (`nats-server`, `redis-server`,
     `postgres`, `mysqld`, `mosquitto`, `nginx`, `sshd`, `unbound`) or a third-party crate in
     server role, and **not the crate NetGet's client is built on**. That last clause is what
     disqualifies `tls`: its test is driven by a `tokio_rustls::TlsAcceptor` while NetGet's TLS
     client *is* a `tokio_rustls::TlsConnector`, so the exchange proves that rustls interoperates
     with rustls. Contrast `quic`/quinn and `webrtc`/webrtc-rs, accepted on the server side:
     there NetGet authors real protocol logic above the crate and the crate is transport. Where
     the crate **is** the protocol, using it at both ends measures nothing.
  2. **The test fails rather than skips when the peer is absent**, naming the binary and how to
     install it. `npm`'s reasoning, which `nats`' test states in as many words. A
     skip-when-missing gate is a silent pass, so a rating resting on one rests on nothing
     wherever the suite actually runs — and `#[ignore]` fails this the same way, because
     unreachable evidence is not evidence however good the reason for parking it.
  3. **A real session, not a connect.** The client completes the protocol's own exchange —
     authenticate, ask, parse the answer — rather than proving that a socket opened.
  4. **The client acts on the model's answer, asserted on the wire.**
     `tests/client_event_wiring_test.rs` exists because six clients asked the model what to do
     and discarded the reply, and that defect is silent: the client connects, reports success and
     does nothing. Asserting that the LLM was *called* does not cover it. Asserting the effect of
     an action the model produced does.

  **Applied 16 September 2026: nothing was promoted, and `nats` remains the only Beta client.**
  That is the finding rather than a failure to find one. Five *servers* had been sitting at
  Experimental with the evidence already in the tree, and the same was expected here; it is not
  the case. The clients fall into four groups and only one is near the bar:

  - **Circular** — the overwhelming majority, ~60 protocols. `redis`, `postgresql`, `mysql`,
    `mongodb`, `imap`, `ftp`, `irc`, `http`, `whois` and the rest drive NetGet's own server of the
    same protocol. Several more (`jsonrpc`, `openapi`, `bitcoin`, `elasticsearch`, `rss`) drive
    NetGet's *HTTP* server, which is same-project **and** generic HTTP — two disqualifications.
  - **Real peer, unreachable evidence** — `mqtt` (Mosquitto in Docker), `smtp` (Python `smtpd`),
    `ssh` (an external `sshd`), `smb`, `xmpp`, `ldap`, `s3`, `dynamodb`, `sqs`, `tor`. Each names
    a genuine third-party server and **every one of those tests is `#[ignore]`d**, so none of it
    runs. These are the cheapest promotions available, and the work is un-ignoring them — which
    means standing the peer up wherever the suite runs.
  - **Real peer, wrong peer** — `tls` (rustls at both ends, above) and `oauth2` (an `axum`
    router, which is generic HTTP and is in `beta_evidence_table.py`'s own `INFRASTRUCTURE` set).
  - **Public internet** — `dot`, `git`, `npm`, `pypi`, `maven`, `ntp` reach real third-party
    servers and are `#[ignore]`d for the right reason: this file requires localhost only. A local
    mirror would turn these into evidence; the public endpoint never will.

  **What is installed on this machine**, so the remaining cost is a number rather than a guess:
  `nats-server` (already in use), `redis-server` (valkey), `mosquitto`, `etcd`, `postgres`,
  `mysqld`, `nginx`, `sshd`, `httpd`, `unbound`, `smbd`, `tor`, `openvpn`, `slapd` (under
  openldap's `libexec`) and libmemcached's tools. Missing, for the list above: `vsftpd`,
  `memcached`, `mongod`, and a MinIO or LocalStack for the AWS clients.

  **Applied again 26 September 2026: `mqtt`, `redis`, `etcd` and `http` are Beta — five Beta
  clients, 93 Experimental.** The difference from the first pass is that the peers were stood up
  rather than found: `tests/helpers/real_server.rs` (`RealServer`) spawns a third-party server on
  a loopback port in a temp dir of its own, waits for its own "listening" log line, kills its
  process group on drop and **fails naming the brew formula and the Ubuntu package** when the
  binary is absent. Each client then has `tests/client/<p>/real_server_test.rs`: Mosquitto with
  `mosquitto_sub`/`mosquitto_pub`, a real `redis-server` read back with `redis-cli`, the official
  Go `etcd` read back with `etcdctl`, and nginx asserted through its own access log. Every one
  asserts condition 4 from the server's side of the wire, and every one was checked by mutation
  — emptying the loop over the model's actions fails it. CI now installs those servers
  (`registry-audit`, plus `redis-server` and `nginx` in the blocking `test` job, because `redis`
  and `http` are in `CI_FEATURES` and their real-server tests run there), and
  `tests/real_client_evidence_is_run_test.rs` scans `tests/client/` as well as `tests/server/`,
  so a client suite that drives a real server and runs in no CI job fails the build. Before that
  extension the one Beta client's own evidence, `nats`, ran in no CI job at all.

  Two findings from it are worth carrying to the next client:

  - **A real server finds framing bugs a same-project one agrees with.** The redis client read
    replies **line by line**, so `GET k` → `$5\r\nhello\r\n` reached the model as two events,
    `"$5"` and `"hello"`, and it split commands on whitespace, so `SET k "a b"` stored `"a`.
    NetGet's own Redis server never exposed either: the tests against it asserted only that the
    model was called. `src/client/redis/resp.rs` now reads one whole RESP2/RESP3 reply per event
    (depth, declared size and element count bounded — without the depth bound a 40 KB reply
    aborts the process on a stack overflow) and splits the way `redis-cli` does.
  - **Match each mocked reply on its parsed content, and put the most specific rule first.** A
    rule matched on `reply_type` and `value` is what turns "the reply was split" into a failure
    rather than an extra LLM call; and nginx's echo quoting the previous response back made a
    looser rule answer both responses until the follow-up depth cap stopped the loop.

  **Seventeen as of 15 October 2026 (17 Beta — re-derive with `--side client`).**
  Since the thirteen below: `kafka`, `dns` and `rdp` arrived Beta with the protocol-expansion
  pairs, `spark` against a real Apache Spark's live driver UI and History Server, and `yarn`
  against a real Hadoop ResourceManager and NodeManager. `ssh` went
  the other way on 2 October 2026: its SFTP operations shipped without a second independent SFTP
  server, pcap oracle or fuzz target, and its `metadata()` says so.

  **Thirteen as of 26 September 2026 (13 Beta, 89 Experimental).**
  `memcached`, `coap`, `modbus` and `radius` are new clients that arrived Beta against memcached,
  libcoap's `coap-server`, a pymodbus device and FreeRADIUS. The paragraphs below are how the
  count got to nine first.

  **The same day's second half made it nine: `postgresql`, `mysql`, `ldap` and `ssh` are Beta —
  nine Beta clients, 89 Experimental.** The peers are the PostgreSQL server (`initdb` +
  `postgres`, read back with `psql`), Oracle's `mysqld` (`--initialize-insecure`, read back with
  the `mysql` CLI), OpenLDAP's `slapd` (a temp-dir `slapd.conf`, seeded with `ldapadd`, read back
  with `ldapsearch`) and OpenSSH's `sshd` run **unprivileged** (a temp-dir `sshd_config`,
  `ssh-keygen` keys, public-key auth as the current user — an unprivileged sshd can log in no one
  else and check no password). `RealServer` grew `setup_command` for the data directory a server
  needs before it will start, and `graceful_stop`, because a SIGKILLed postmaster leaks a System
  V shared memory segment and macOS allows 32. CI installs all four in `registry-audit` only
  (none is in `CI_FEATURES`), and unloads Ubuntu's AppArmor profiles for `mysqld` and `slapd`,
  which confine them to their packaged paths.

  Every one of the four had defects NetGet's own servers had never shown, which is the point of
  the exercise and worth expecting of the next client:

  - **A result that did not say what it was.** MySQL reported the *row count* as
    `affected_rows`, so an `INSERT` read as affecting nothing; LDAP's one response event for add,
    modify and delete named neither the operation nor the DN; SSH's output event did not name
    its command. A mock matched on the server's own answer (`affected_rows` 1, `last_insert_id`
    1, `operation` add) is what caught each.
  - **A real server's normal sequence breaking a loop written against our own.** The SSH client
    stopped reading at the channel's EOF; OpenSSH sends `exit-status` *after* EOF, so every exit
    status was lost.
  - **A refusal that raised nothing.** A search slapd answered with `noSuchObject` ended the LDAP
    chain silently, and an attribute written as a plain string (`{"cn": "Ada"}`) was dropped
    from an add. Both reached the model only once the server said no.
  - **Chains that were one step deep, or unbounded.** PostgreSQL executed the model's answer to
    a result and dropped that query's rows, so create → insert → select → act was impossible;
    LDAP and SSH followed the chain with no bound at all. All three now follow it and stop at
    `MAX_FOLLOWUP_DEPTH` 4, as MySQL already did, and each bound has a test that fails without
    it — the LDAP one counts the searches in slapd's own log.

  **Do not read the four groups above as the list — generate them:**

  ```bash
  python3 scripts/beta_evidence_table.py --side client --all   # table + the four-way split
  python3 scripts/beta_evidence_table.py --side client --check # exit 1 on a defective Beta
  ```

  `--side client` landed 16 September 2026 and applies the bar above rather than the server one:
  it detects **self-served** (a test that builds a `ServerForm`, calls `start_netget_server` or
  sends an `open_server` action — the peer is NetGet's own server) and treats `#[ignore]`d
  evidence as disqualifying rather than as a review flag, attributing peers **per file** so a
  peer named only in tests that never run is reported as unreachable. Its first run agreed with
  the hand audit and sharpened it: 62 self-served rather than "~60", **zero** protocols in the
  "real peer, evidence runs" group, and `mqtt` alone in "real peer, unreachable". What no scan
  can check is condition 4 — that the client acts on the model's answer — and the script says so
  instead of implying it passed. It reads a server spawned through `RealServer::builder("<bin>")`
  as a binary peer, since the helper, not the test file, is what spawns it. Re-derived
  26 September 2026 after the promotions above: Beta 9, Experimental 89 — 55 self-served, 9
  wrong peer, 25 with no peer, and none left in either "real peer" group.
- **Experimental** — LLM-authored or newly implemented, not fully reviewed. The overwhelming
  majority (107 of the 158 `src/server/*/actions.rs` the script below walks, re-derived
  16 September 2026). Note the script
  reports one `NONE`: `src/server/http_common/actions.rs`, which is a shared response helper
  with no `impl Protocol` and no registry entry, so it declares no state correctly.
- **Incomplete** — hidden from the LLM entirely (`is_available_to_llm()` returns false). **None
  remain — but that claim was false for months and nobody noticed, which is the useful part.**
  The `nfc` *client* sat at `Incomplete` until September 2026, so the model could not see it at
  all, while this section said none remained. The lesson is that `Incomplete` is invisible by
  construction: nothing surfaces it, no test fails, and the protocol simply never appears in a
  tool list. It is now a ratchet — `tests/no_protocol_is_hidden_from_the_model_test.rs` reads
  the source tree, so it holds at the six-protocol CI gate as well as at `--all-features`, and
  its allow-list is empty. Note it matches `.state(...)` specifically: every occurrence in
  `src/docs.rs` and the TUI is a `match` arm rendering the variant, and a bare substring search
  reports all of them.

  The last *deliberate* one, `bluetooth_ble_beacon`, was a platform limit rather than unfinished
  work, and was resolved by making the platform explicit rather than by hiding the protocol:
  - A beacon *is* its advertising payload, and `CBPeripheralManager.startAdvertising:` accepts
    only `CBAdvertisementDataLocalNameKey` and `CBAdvertisementDataServiceUUIDsKey`; every other
    key is documented as ignored, so macOS cannot emit one and no CoreBluetooth binding would
    change that. Linux/BlueZ can, via `org.bluez.LEAdvertisement1`'s
    `ManufacturerData`/`ServiceData` registered on `org.bluez.LEAdvertisingManager1`.
  - It is now `Experimental`, implemented on Linux with `bluer` (already in the tree as
    `ble-peripheral-rust`'s Linux backend, so no second D-Bus stack), and `spawn()` returns a
    clear `Err` naming the reason on every other platform. **Hiding a protocol is not the same
    as refusing to start it**: hidden, the model never learns why; refused, the user gets
    `ServerStatus::Error` with the CoreBluetooth key that makes it impossible.
  - Its payload construction is pure and exhaustively unit-tested against literal spec bytes;
    its BlueZ transport has never been compiled or run on Linux. `metadata().notes` says both,
    which is what `Experimental` is for.

Twelve protocols left `Incomplete` in August 2026 — `amqp`, `bgp`, `kafka`, `nfc`, `openvpn`,
`turn`, `usb/serial`, `usb/smartcard`, `vnc`, `webdav`, `webrtc`, `zookeeper`. Each was verified
against a **real client** where one exists (`lapin`, `reqwest_dav`, `zookeeper-async`, `webrtc-rs`
as a peer, a real `openvpn` 2.7.4 binary, two UDP sockets proving TURN relays a payload), and
against an **independent codec or RFC-derived literal bytes** where none does (BGP via
`netgauze`, Kafka via `kafka-protocol`'s client-side codecs). Each `metadata()` note says which,
and what is still untested.

Derive these rather than trusting the counts, which drift. **Match the fully-qualified form
too** — roughly half the protocols write `crate::protocol::metadata::DevelopmentState::X`, and a
pattern anchored on the bare `DevelopmentState::` silently reports them as declaring nothing.
An earlier version of this section claimed four USB protocols declared no state for exactly that
reason; all four declare one:

```bash
python3 - <<'EOF'
import re, pathlib
from collections import Counter
rows=[]
for f in sorted(list(pathlib.Path('src/server').glob('*/actions.rs'))
              + list(pathlib.Path('src/server').glob('*/*/actions.rs'))):
    # Two declaration forms: the builder's `.state(X)` and a struct literal's `state: X`.
    # Only one protocol uses the literal today (the ospf CLIENT), but a pattern that knows
    # only about the builder reports it as declaring nothing — and that same blind spot was
    # a real hole in tests/no_protocol_is_hidden_from_the_model_test.rs until September 2026.
    m=re.search(r'(?:\.state\(|state:\s*)\s*(?:crate::protocol::metadata::)?DevelopmentState::([A-Za-z]+)',
                f.read_text(errors='ignore'))
    rows.append((m.group(1) if m else 'NONE', str(f)))
print(Counter(r[0] for r in rows))
EOF
```

Treat `Experimental` as "compiles and has a test", not "works". Before assuming a protocol
behaves, check what it actually offers the model — and check it two ways, because one grep
lies in both directions:

```bash
grep -A3 "fn get_sync_actions" src/server/<p>/actions.rs | grep -c 'vec!\[\]'  # hollow?
grep -cE "DnsProtocol|BluetoothBle::" src/server/<p>/actions.rs                # or delegating?
grep -c "\.with_actions(" src/server/<p>/actions.rs                            # reachable at all?
```

An empty `get_sync_actions()` is fine if the protocol **delegates** — `doh` and `dot` forward
`DnsProtocol`'s set verbatim, so the model sees the full DNS vocabulary. It is a trap if it
does not. And actions can be declared yet unreachable: `call_llm` builds the model's tool list
from `event.event_type.actions`, so a protocol whose event types never call `.with_actions(...)`
leaves the model unable to answer at all. That was found in 17 protocols, is now fixed
everywhere, and is guarded two ways: `EventType::with_no_actions()` marks the deliberate case,
anything else logs at ERROR and falls back, and `tests/event_action_declarations_test.rs` fails
the build on any new occurrence across every registered protocol.

**That guard had a hole worth remembering, because it inverted the whole point.**
`audit_event_action_declarations` early-returned when `get_sync_actions()` was empty, on the
reasoning that a protocol advertising nothing is withholding nothing. It is backwards: offering
the model *no* vocabulary is the worst case, not the exempt one. `usb-fido2` had zero sync
actions, zero LLM integration and three events the model could not answer, and
`cargo test --features usb-fido2,tcp` reported **3 passed**. The rule now fails that case; re-run
at `--all-features` it flagged exactly `usb-fido2` and produced no false positives across the
other 115, and delegation is unaffected because `doh`/`dot` return a non-empty set of their own.
The `registry-audit` CI job runs these audits at `--all-features` for that reason — every other
job compiles 6 of 116, so a registry-walking test is only as wide as its feature set.

**A fourth variant: an event can be declared and never emitted.** Declaring actions on it then
buys nothing, because it never fires. The USB family was the live case and is now fixed —
`usb_*_detached`, `usb_msc_read`, `usb_msc_write`, `usb_keyboard_led_status` and the
`usb_serial_*` events all have real emit sites. Two of those repairs are worth knowing about,
because the protocols were more broken than "an event does not fire": `usb-mouse`'s
`handle_connection` took the socket as `_stream` and dropped it, ran no USB/IP session at all and
parked on `sleep(u64::MAX)`, while a complete handler sat unwired in `handler.rs`; and every
`usb-keyboard` action demanded `connection_id.as_u64()` while events report `"conn-2"`, so no
value the model could send would ever have worked. Check the emit side, not just the declaration:

```bash
grep -rn "_EVENT" src/server/<p>/mod.rs   # which events does the server actually raise?
```

**A fifth variant, on the client side, and it was the widest of all: `call_llm_for_client` built
its tool list from `get_async_actions()` alone.** It read neither `get_sync_actions()` nor
`event.event_type.actions`. **53 of the 91 registered clients** had at least one action the model
could never see — 11 hiding something protocol-specific (`irc`'s send_privmsg/notice/raw, `nfc`'s
send_apdu, `icmp`'s send_echo_request, whose async list was empty outright) and 42 hiding
`wait_for_more`, so no stream client could say "that response was partial". TFTP declared
`send_ack` sync-only, so every DATA block came back `Unknown Action` and every transfer stalled
at block 1.

**Clients union; servers narrow — and that asymmetry is deliberate.** A server has two LLM entry
points, so its async/sync split is real and `ssh_auth` can legitimately narrow to
`ssh_auth_decision`. A client has one: `call_llm_for_client` serves both the initial instruction
(`event: None`) and every network event, so no client *can* express a narrowing. Hence
`client_llm_action_set(...)` = async ∪ sync ∪ the firing event's actions. The tree confirms the
split was never meaningful there — 85 of 91 clients attach no actions to any event type, and ~40
duplicated their whole list into both methods purely to work around this.

`tests/event_action_declarations_test.rs` now walks **both** registries, and additionally
round-trips each advertised name through the protocol's own executor — which caught a sixth
variant, *advertised but unexecutable* (`ssh_agent/modify_instruction`,
`pop3/modify_pop3_instruction`, and four more that were removed as unimplementable). A static
declaration check cannot find those.

The whole `bluetooth_ble_*` family was a third variant: `BluetoothBle::spawn_with_llm_actions`
hardcodes `BluetoothBleProtocol` when it calls `call_llm`, so all sixteen profiles' own actions
and events were unreachable regardless of what they declared. Fifteen now delegate explicitly.
`bluetooth_ble_beacon` took the other exit: it no longer goes through the base at all, so it
calls `call_llm` with its own protocol and its own actions really are the ones offered and
executed. That is the only way a profile can own a vocabulary — delegate the base's, or stop
using the base.

Per-protocol docs: `src/server/<protocol>/CLAUDE.md` and `tests/server/<protocol>/CLAUDE.md`.
**Read both before modifying a protocol.** Note that these files are frequently more
aspirational than the code — verify claims against the source.

## Architecture

**Modules**: `cli/` (TUI, startup, args) · `server/<protocol>/` · `client/<protocol>/` ·
`protocol/` (registries, metadata, spawn context) · `state/` (app state) · `llm/` (backends,
prompting, actions) · `events/` (coordination) · `scripting/` (deterministic handlers) ·
`mcp_stdio/` (MCP server) · `easy/` (simplified layer for small models).

**Decentralization (CRITICAL)**: no centralized per-protocol logic. Each protocol implements
traits independently. The only legitimate central touchpoints are:

- `protocol/server_registry.rs` / `protocol/client_registry.rs` — one `register()` line
- `Cargo.toml` — the protocol's dependencies (no feature; see "Protocols are not Cargo features")
- `src/server/mod.rs` / `src/client/mod.rs` — one `pub mod`
- `tests/server/mod.rs` / `tests/client/mod.rs` — one `pub mod` (see the footgun below)

### Protocols are not Cargo features (CRITICAL)

**Never add a Cargo feature for a protocol.** Since October 2026 every protocol compiles into
every build of every platform that can build it; `#[cfg(feature = "<protocol>")]` does not
exist anywhere, and a new one is a defect. crates.io caps a crate at 300 features, NetGet had
297, and a per-protocol feature list also hid protocols from whoever forgot to name one.

What gates a protocol is the platform, written as a target cfg:

| The protocol builds on | Gate (`#[cfg(...)]` on its `pub mod`, `register()` and test module) | Its dependencies go in |
|---|---|---|
| every target, browser included | none | `[dependencies]` |
| native targets, not the browser (real sockets, processes, C libraries) | `not(target_arch = "wasm32")` | `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` |
| Unix only (raw sockets, pty, Unix pipes) | `unix` | `[target.'cfg(unix)'.dependencies]` |
| Unix, linking a system library | `all(unix, feature = "<lib>")` | `[target.'cfg(unix)'.dependencies]`, `optional = true`, listed in that feature |

The only features are the five system libraries (`libpcap`, `bluetooth`, `pcsc`, `libusb`,
`libsmbclient`, all default-on) and optional capabilities (`mcp-stdio`, `mcp-http`,
`embedded-llm`, `sqlite`, `gpu`, `vendored-openssl`, `terminal-snapshot`). A protocol that
needs a new system library gets a new library feature, named after the library, not after
the protocol. Tests never gate on the browser (integration tests do not build for wasm32), so
under `tests/` only `unix` and the library features appear.

Add the protocol to `ALL_KNOWN_PROTOCOLS` / `ALL_KNOWN_CLIENT_PROTOCOLS` with what it needs
("a native build (not the browser)", "the `libpcap` feature, on Unix", …) — that string is
what the "not compiled into this build" error tells the user.

`cli/server_startup.rs` and `cli/client_startup.rs` are **fully generic** — they look the
protocol up in the registry and call `spawn(ctx)` / `connect(ctx)`. There is no
per-protocol match statement. Do not add one.

**`ProtocolConnectionInfo`** (`state/server.rs`) is a generic `serde_json::Value` wrapper,
not an enum. Adding a protocol does not require touching it.

**Connection I/O**: split `TcpStream` with `tokio::io::split()` (never clone). Never hold a
`Mutex`/`RwLock` guard across an `.await` that performs I/O or an LLM call — acquire, copy
out what you need, drop the guard in an inner scope, then await.

**Per-connection state machine** (Idle → Processing → Accumulating) prevents concurrent LLM
calls on one connection and queues data arriving mid-call. Note: `state/machine.rs` defines a
generic `StateMachine<S>` that **nothing uses** — every protocol hand-rolls its own copy.
Copy the TCP implementation (`src/server/tcp/mod.rs`) as the reference.

**Actions**: protocols implement `ProtocolActions` (`src/llm/actions/protocol_trait.rs`) with
async actions (user-triggered) and sync actions (network-event-triggered), in
`src/server/<protocol>/actions.rs`. Clients implement `Client` (`llm/actions/client_trait.rs`).

**Handling modes** — a matched `event_handlers` rule decides who answers:
1. **Script handler** — inline Python/JS, runs in-process, no LLM call
2. **Static handler** — fixed actions, no LLM call
3. **Manual handler** — the event parks (`src/state/intercepts.rs`) and a **human** composes
   the answer at the dashboard; no answer within `timeout_secs` (default 300) **fails closed**
   through the same path as an LLM failure. The dashboard shows parked events as
   "⚠ waiting for YOUR answer" rows. Instances created interactively through the dashboard
   default to a `*` → manual rule — the human is there, driving; instances the model creates
   through its own tools get no such default. **Dashboard-created clients refine this**: the
   `*` → manual rule is preceded by one zero-action static rule per connect event (each
   `<proto>_connected` id the client's registry entry declares), so establishing a connection is
   "answered with nothing" and does not park — several clients handle their connect event inline
   in `connect()`, so parking it would stall creation itself. Everything after the connect
   handshake still falls through to `*` → manual. **Servers get the same treatment for the events
   they raise on every connection** — `EventType::raised_on_every_connection()`, today
   `telnet_connection_opened` — one zero-action static rule each, then `*` → manual. Without the
   rule a person would be asked about every connection before its first message. `tcp` and
   `tls` raise their connect event only with `send_first`: raising it everywhere was measured to
   cost a model call per connection and to make a small model greet clients nobody asked it to.
4. **LLM** — one model round-trip per event (the fallback when no rule matches)

Scripts and static handlers are the right default for deterministic behavior (echo, canned
responses, routing). Reserve the LLM for responses that genuinely require reasoning.

A caveat manual handlers exposed: several clients handle their `*_connected` event inline in
`connect()` before returning, so a parked connect event delays creation until answered — the
command channel must therefore register **before** that call (`tcp` and `telnet` do), or
`[ send ]` reads "no command channel" for the whole park.

### Action & event design rules (CRITICAL)

**Never put raw bytes or base64 in action parameters or event data.** Models cannot reliably
produce or parse them. Use structured fields: `{"method": "GET", "path": "/", "headers": {…}}`,
not `{"data": "SGVsbG8="}`.

**If an action does document a hex or encoded field, the executor must actually decode it.**
TCP had a bug of exactly this shape and it is worth knowing as the reference case (fixed in
`d70bb5b5`): `send_tcp_data` was documented in three places as accepting "text or hex-encoded
binary", but its executor did `data.as_bytes()` and never decoded hex, so a model following the
documentation put literal ASCII on the wire. Inbound data *was* hex-encoded when non-printable,
making the round-trip asymmetric — an echo server could not echo. The fix was an explicit
`encoding` field (`"utf8"` default, `"hex"`) on both directions rather than sniffing, because
`"48656c6c6f"` is simultaneously valid text and valid hex and only the sender knows which it
means. When you touch a protocol, verify its documented encoding matches its executor.

**Protocols must not implement storage** — no databases, filesystems, or persistence written
into a protocol's Rust implementation. The LLM supplies all data via actions, scripts, static
responses, or server memory. MySQL has no tables; the model answers every query.

The sanctioned exception is the generic SQLite facility (`src/state/sqlite.rs`, feature
`sqlite`, included in `all-protocols` and therefore in default builds). The LLM can call
`create_database` / `execute_sql` / `list_databases` / `delete_database` at runtime, scoped to
a server, a client, or globally. The point of the rule is that storage is a *generic runtime
capability the model opts into*, never something a protocol hardcodes. Two caveats worth
knowing: `create_database` defaults to **file-backed**, writing `./netget_db_<name>.db` into
the process's working directory, and server/client-scoped databases are deleted when their
owner closes while global ones persist.

### Privilege model

`ProtocolMetadataV2::privilege_requirement` declares `None` / `PrivilegedPort(u16)` /
`RawSockets` / `Root`, checked against `SystemCapabilities` (`src/privilege.rs`) in
`server_startup.rs` before spawn, which now gates on `PrivilegeRequirement::is_met_by()` alone
and detects capabilities by actually probing (a `SOCK_RAW` socket, `/dev/bpf*`, `geteuid()`)
rather than inferring. Both were broken until this pass — the probe used `pcap::Device::list()`,
which any unprivileged user can call, so the check never fired for anything.

Declare `privilege_requirement` on any new protocol that needs raw sockets, a TUN device, or a
port below 1024. Two failure modes to avoid:

- **A `PrivilegedPort` above 1023 can never fire.** `svn` declared `PrivilegedPort(3690)`, which
  read as protection and was dead code. Declare `None` if the default port is unprivileged.

**The port itself is `well_known_port`, not `PrivilegedPort`.** Every socket server declares
`.well_known_port(n)` / `.well_known_udp_port(n)` / `.well_known_sctp_port(n)` in `metadata()` —
IANA's number, or where IANA has none the default the protocol's own specification or reference
implementation documents (Elasticsearch 9200, `hg serve` 8000), never 8080 standing in for HTTP.
It is what a server starts on when the caller names no port (picker, create form, `ServerForm`,
MCP `start_server`, `open_server`, `--server`), through one function,
`protocol::default_port::default_port_for_server`: 1024 and above as is, below 1024 only when
`can_bind_privileged_ports`, and a port already held on the bind address falls back to an
OS-assigned one — each fallback said out loud. **An explicit port, `0` included, is never
replaced.** `tests/well_known_port_declaration_test.rs` requires every server to declare one or
sit in its `NO_WELL_KNOWN_PORT` list with the reason (link layer, devices, pipes, the generic
`tcp`/`udp`, and application protocols carried on plain HTTP), and requires every
`PrivilegedPort(n)` to equal the declared port and the transport to match `stack_name()`.

**The host is the caller's too, and so is exposing a server.** With no host a server binds
`127.0.0.1`; an explicit host — `0.0.0.0` and `::` included — is bound as given, on every
binding path. That is a deliberate decision of the maintainer's (October 2026), not an
oversight to tighten: the legacy path that ~240 servers still take used to build its address
from `127.0.0.1` "for security" and silently drop the host, so a request to expose a server on
the LAN quietly bound loopback. A host that is not an address (or `localhost`) is refused, never
replaced. `tests/legacy_host_binding_test.rs` holds both halves.
- **A test can start an entirely different protocol and still pass.** `ospf`'s three e2e
  tests pass `"base_stack": "UDP"`, which `open_server` renames to `protocol` — so what
  starts is the **generic UDP server**, not `src/server/ospf/`. The mocked event is
  `udp_datagram_received` and the mocked action `send_udp_response`, both the UDP server's;
  no test in the tree mocks `ospf_hello` or any other OSPF event. The test builds
  OSPF-shaped bytes, the mock hands OSPF-shaped bytes back, a UDP server relays them, and
  `assert_eq!(buf[1], 1)` asserts a constant the test itself wrote. The
  `"application_protocol": "OSPF"` sitting alongside is read by nothing in `src/`.
  **Check which server a test actually starts before believing what it covers.**

  If you want the real thing — a declared `transport: "udp"` startup parameter that routes
  through the protocol's *own* code so the whole event → LLM → action → frame path runs
  unprivileged — copy `lldp`, `stp`, `cdp`, `eapol`, `vrrp`, `ndp`, `rawip` or `tuntap`.
  Those genuinely implement it; `ospf` never did, despite its `Cargo.toml` comment having
  claimed so for a long time.

- **Don't claim more than you need.** `ospf` declared `Root` when it wants `CAP_NET_RAW`, which
  would refuse to start on a capability-only process that could in fact run it.

There is no variant for *device* access — Bluetooth adapters, USB, NFC readers. Those seventeen
protocols sit at `None` because every other option would be a lie; see IMPROVEMENTS item 60.

Startup must report failure. `spawn()` has to await readiness and return `Err` so
`server_startup` sets `ServerStatus::Error`. ARP, DataLink and ICMP used fire-and-forget
`spawn_blocking` and sat in `Running` having captured nothing — a server that lies about being
up is worse than one that refuses to start.

`get_dependencies()` / `ProtocolDependency` (`src/protocol/dependencies.rs`) is plumbed, and as
of September 2026 the default **derives** from `privilege_requirement` rather than being empty —
so the old claim here that "no protocol overrides it, so the mechanism does nothing" is no longer
true in either half.

What the September audit found is more useful than the gap it was sent to close: **most of what
looks like a runtime dependency is not one.** `libpcap` and `libsmbclient` are linked at load
time, so the process could not start for a check to fire; `protoc` is `build.rs` only. Devices
have no honest probe, which is why `DeviceAccess` derives nothing. Exactly two were real and
undeclared, and both are declared now — the **gRPC client**'s `protoc` (the server declared it;
the client running the identical `Command::new("protoc")` did not) and **wireguard-go** on macOS.

So before declaring a dependency, ask whether it can actually be *missing at runtime on a
process that started*. If not, the declaration is decoration.

**Startup enforces them, narrowly.** Every `start_*` path (server and client, `_from_action` and
`_by_id`) calls `dependencies::startup_blocker`, which refuses only a `SystemLibrary`/`ToolInPath`
the probe **established** is absent (`DependencyStatus::Missing`), before anything is
registered, naming it with its install hint. A probe that cannot answer (`Unknown` — no `PATH`
to search, no loader query on the platform) is logged and let through. A dependency that only
some configurations need is expressed with `startup_dependencies(startup_params)`: gRPC drops
`protoc` for a pre-compiled descriptor set.

## Adding a server protocol

1. `src/server/<protocol>/mod.rs` — server loop, dual logging, connection tracking, register
   the accept-loop `JoinHandle` via `AppState::register_server_task()` (required for
   `stop_server` to actually release the socket)
2. `src/server/<protocol>/actions.rs` — implement `ProtocolActions`: `metadata()` (state +
   privilege + `well_known_port`), `get_startup_parameters()`, async/sync actions,
   `get_event_types()`, `execute_action()`
3. `src/server/<protocol>/CLAUDE.md` — implementation notes, library choice, limitations
4. `src/server/mod.rs` — `pub mod`, with a platform gate only if it cannot build everywhere
5. `src/protocol/server_registry.rs` — `register()` (same gate) and its `ALL_KNOWN_PROTOCOLS` row
6. `Cargo.toml` — its dependencies as plain (non-optional) dependencies, in the target table
   for the platforms that build it. **No feature.** See "Protocols are not Cargo features".
7. `tests/server/<protocol>/e2e_test.rs` — mocked E2E (see Testing)
8. `tests/server/<protocol>/CLAUDE.md` — strategy, mock expectations, LLM call budget
9. **`tests/server/mod.rs` — add `pub mod <protocol>;`** (see footgun below)

Client protocols follow the same shape against `client_registry.rs`, `src/client/mod.rs`,
`tests/client/mod.rs`, and the `Client` trait. Consult `CLIENT_PROTOCOL_FEASIBILITY.md` first.
Clients are less finished than servers, but the blanket claim that their `JoinHandle` is never
stored is **stale** — `register_client_task` now has ~80 of 85 adopters (`bgp`, `ssh_agent` and
others among them). Check the specific client rather than assuming. Where it does bite, the
subtler form is worth knowing: aborting a task does **not** abort tasks it spawned, so BGP's
keepalive timer kept the socket alive after `remove_client()` even though the read loop was
registered. Register every task you spawn, not just the top one.

Two client-side gaps closed recently, both worth knowing before you touch a client:

- **Clients accept injected actions.** `AppState::send_to_client(client_id, action, timeout)`
  executes an action inside a running client's connection loop and returns a
  `ClientSendOutcome` (`src/state/client_handles.rs`). Until this existed, `Client::execute_action`
  was reachable *only* from inside each client's own loop, and only the LLM could produce an
  action for it — nothing, not even a scheduled task, could put bytes on the wire on demand.
  A client opts in with a ~25-line diff: `command_support::register_command_channel` plus a
  `tokio::select!` arm calling `handle_stream_client_command` (`src/client/command_support.rs`).
  **103 clients are wired as of 26 September 2026** — this paragraph said "`tcp` and `telnet`" for
  a long time after that stopped being true. Non-adopters simply never register (the dashboard
  greys out `[send]`); `grep -rl 'register_command_channel(' --include=mod.rs src/client` is
  the count. The channel is **bounded** — "client busy" backpressure is correct for
  user-initiated sends, unlike the unbounded status channels.
- **Client `event_handlers` are dispatched.** They were stored, validated and round-tripped for a
  long time while `get_client_event_handler_config` had *zero* callers, so every client event
  went to the LLM regardless. `try_execute_client_event_handler`
  (`src/llm/event_handler_executor.rs`) now mirrors the server dispatcher and is wired at the one
  choke point every client protocol uses — `client/llm_budget.rs::call_llm_for_client` — **before**
  the budget debit, so a deterministic handler costs no LLM budget. Its `Handled` variant returns
  raw action JSON rather than an `ExecutionResult`, because only the client's own loop owns the
  socket. Scripts get a client-shaped `ScriptInput` (`client` set, `server` absent and
  skip-serialized, so server scripts see byte-identical input).

**Startup parameters**: every key a caller may pass must be declared in
`get_startup_parameters()`. `StartupParams::new` and all `get_*` accessors return
`Result<_, StartupParamError>` (`src/protocol/spawn_context.rs`), and params are validated
*before* `add_server`, so an undeclared key or wrong-typed value produces a clean error naming
the key and listing the allowed ones, and leaves no half-registered server behind. They used to
panic, which over MCP killed the per-request task before it could reply — the caller hung with
no error and the server stuck in `Starting`. Propagate the error with `?`; never `unwrap()` it.

Two related traps when declaring parameters: a parameter that is declared but never read is
dead weight the model will try to use (nine were found in the cloud protocols alone), and a
parameter read but never declared is rejected at startup. Both are worth a grep when you touch
`get_startup_parameters()`.

**Declare `default` where the code falls back to a fixed value** — every read deadline
(`first_byte_timeout_secs`, `idle_timeout_secs`, `handshake_timeout_secs`) and size cap does.
Point it at the constant the code uses, `default: Some(json!(super::IDLE_TIMEOUT.as_secs()))`,
so the form, `get_protocol_docs` and the model's prompt show the number the server will actually
use; a literal copy drifts the first time someone tunes the constant.
`tests/startup_param_defaults_test.rs` refuses a literal (source scan, every feature set) and a
default that does not parse as its `type_hint` or sits on a required parameter (registry walk,
compiled protocols only). `default: None` is right where omitting the parameter switches a
feature off or derives the value from something else — no single number describes that.

## Testing

Black-box and prompt-driven: the LLM (or a mock of it) interprets an instruction, and tests
validate the result with real protocol clients.

**Tests define expected behavior. When a test fails, fix the implementation, not the test.**
"The test passes but the implementation doesn't work" means you are not done. Only change a
test when its expectation is genuinely wrong.

### Test location policy (CRITICAL)

**All tests live in `tests/`. Never add `#[cfg(test)] mod tests` to `src/`.** Tests reach
internals via `use netget::` public APIs; make items public or refactor if needed.

**This policy is currently satisfied — there are zero violations.** Verified September 2026:
no `#[cfg(test)] mod tests` and no `mod tests` of any kind exists under `src/`.

**The derivation command this section used to give is wrong, and produced five false
positives** — it matched *doc comments quoting the policy*, in `bluetooth_ble/mod.rs`,
`bluetooth_ble_beacon/mod.rs`, `etcd/mod.rs`, `grpc/mod.rs` and `oci_registry/actions.rs`.
Every one of those lines is prose explaining why the code does **not** have a test module.
This section then asserted the opposite of what the code did, in both directions over time,
which is a good argument for the anchored form:

```bash
# Real test modules only. The naive `grep -rln "#\[cfg(test)\]"` matches the comments too.
grep -rnE '^[[:space:]]*#\[cfg\(test\)\]' src/ --include='*.rs'
grep -rnE '^[[:space:]]*(pub )?mod tests' src/ --include='*.rs'
```

Both return nothing today. If either starts returning something, that is a real violation.

### The mod.rs footgun (CRITICAL)

`tests/server.rs` and `tests/client.rs` only compile submodules explicitly declared in
`tests/server/mod.rs` / `tests/client/mod.rs`. **A test directory that exists on disk but is
not declared is silently never compiled and never run — no error, no warning.**

This was the single largest hole in the suite — **15 of 116 server test dirs and 61 of 83
client test dirs were orphaned**, including complete, correctly-gated E2E suites for `arp`,
`whois`, `bitcoin`, `igmp`, `tls`, `sip`, and every USB protocol. All 76 are now declared, and
the `orphaned-tests` job in `.github/workflows/ci.yml` fails the build if it happens again.
Verify locally with:

```bash
comm -23 <(ls -d tests/server/*/ | sed 's|tests/server/||;s|/||' | sort) \
         <(grep -oE "pub mod [a-z0-9_]+" tests/server/mod.rs | awk '{print $3}' | sort)
```

Note `$3`, not `$2`: `grep -oE "pub mod <name>"` yields three fields and `$2` is the literal
word `mod`, so the version this file carried until now reported every directory as orphaned.

### Mocks

Default mode needs no Ollama. `tests/helpers/mock_ollama.rs` runs a real in-process axum
server implementing `/api/chat`, `/api/generate`, `/api/tags`. Configure with `.with_mock()`
and **always finish with `server.verify_mocks().await?`** — without it the test asserts
nothing about LLM interaction. An unmatched request returns HTTP 500 with a clear error, and
`verify_calls()` dumps full call history on mismatch.

**Call `wait_for_mocks(30)` before `verify_mocks()`.** A protocol exchange finishes with the
last LLM call it provokes, which is exactly what the expectations describe, so waiting on
them waits on the exchange. Suites used to sleep a fixed 1–2s and then verify, which is
enough alone and not when a hundred run together. It returns quietly on timeout —
`verify_mocks` remains the thing that asserts, and it names the rule that fell short.
`wait_for_any(&[needles], secs)` does the same job for output assertions.

**Rules are first-match-wins, and two rules on the same event with no way to tell them apart
is the most common mistake in this repo.** The first answers every occurrence and the second
reports zero calls; if the first answers with an action that produces the same event again,
it loops until something else stops it (99 calls, in one case). To express "then", use ONE
rule with `respond_with_actions_from_event` that branches on the event — a GET after a delete
returns count 0, a PUT response names the key it just wrote, an IMAP reply carries the tag.

**A response generator may carry state between calls, but only because it is now rendered
once per request.** `to_response_string` used to be called twice — once to build the routing
diagnostics and once for the reply — so a stateful closure advanced two steps per request and
answered the first request with the second answer. That cost real debugging time; it is fixed,
and worth not reintroducing.

**Check the event id and the action name against the protocol, not against the neighbouring
suite.** Whole suites were mocked against events their server never raises (`http_request` for
Elasticsearch, which raises `elasticsearch_request`), fields the event does not carry
(`uri` where it is `path`, and vice versa for HTTP/2), and actions the protocol cannot execute
(`send_http_response` to an OpenAPI server). None of these fail loudly: the rule simply never
matches, the request falls through to a real LLM call, the server answers an error, and the
failure surfaces two steps later on a different expectation.

UDP-style protocols (DNS, STUN, NTP, DHCP, BOOTP, TFTP…) **must** use
`.respond_with_actions_from_event()` to echo the client's random transaction/query ID back.
Static mocks with hardcoded IDs cause client timeouts. See `tests/server/dns/AGENTS.md`.

```rust
.on_event("dns_query")
.and_event_data_contains("domain", "example.com")
.respond_with_actions_from_event(|e| serde_json::json!([{
    "type": "send_dns_a_response",
    "query_id": e["query_id"].as_u64().unwrap_or(0),   // ← must be dynamic
    "domain": "example.com", "ip": "93.184.216.34"
}]))
.expect_calls(1)
```

Keep each suite under ~10 LLM calls: reuse servers, bundle scenarios, prefer script mode.
Bind to localhost only (127.0.0.1 / ::1); never contact external endpoints.

### Running tests

```bash
# Single protocol: select its suite by module path (every protocol is compiled in)
./cargo-isolated.sh test --test server -- server::tcp::e2e_test --test-threads=100

# Full sweep: the top-level targets in batches (each test binary links every protocol,
# ~870 MB; all ~230 at once is ~200 GB), then the protocol suites.
CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 scripts/test_batches.sh > /tmp/sweep.txt 2>&1
./cargo-isolated.sh test --test server --test client -- --test-threads=32 >> /tmp/sweep.txt 2>&1
```

**Never build every test target at once.** With every protocol in every build, each of the
~230 test binaries is ~870 MB unoptimised (debug info off), so a plain `cargo test` needs
~200 GB and filled this machine's disk in October 2026. `scripts/test_batches.sh` builds ten
at a time and deletes each batch's executables; CI's `test` job runs it, split five ways with
`SHARD=i/5` (`TARGETS` names an explicit list, as the `ratchets` job does, and anything after
`--` goes to every test binary).

**Checking the library alone peaks at ~12 GB of memory** (clippy, measured October 2026), which
is most of a 16 GB hosted runner. The heavy CI jobs add 16 GB of swap first; without it the
runner does not fail, it "loses communication with the server".

**`--test-threads=100` is right for one protocol and wrong for the whole tree**, and the
failure is not a test failure. `--all-features` builds ~29 test binaries that each link the
whole 137-protocol library; at 100 threads the run was **killed by the OS for memory pressure**
on a 96 GB machine (September 2026). "3GB+ RAM", which this section used to say, is off by an
order of magnitude. At 32 threads the same sweep is **172 targets, 3768 passed, 0 failed**.

**Redirect the sweep to a file and parse the file.** Two sweeps were mis-read in one day
because of how their output was handled, and both nearly got reported as clean:

- One died at `ld: write() failed, errno=28 (No space left on device)` while linking, **exited
  0**, and produced zero `test result` lines. Six concurrent `--all-features` target dirs is
  ~150 GiB; a seventh filled the disk.
- The other was piped through `tail -30`, which discarded almost every result line — it read as
  "29 targets, 154 passed" where the truth was 171 targets and 17 failures.

So: parse for a **non-zero target count** and a plausible total, never grep only for failures,
and never truncate the stream you are about to measure.

**Use `--test-threads=32` for a whole-tree or combined-feature suite; 100 is useful for
targeted stress runs.** If a test hangs, fix the hang rather than serializing the suite.

`./test-e2e.sh <protocol>` runs mocked; `./test-e2e.sh --use-ollama <protocol>` uses a real model.

### CI reality

`release.yml` builds every target's binaries on release tags and manual dispatch (macOS with the
`libpcap`, `bluetooth` and `pcsc` features, whose libraries ship with the OS; Linux and Windows
with no system-library feature).
`ci.yml` is the PR/push-to-master gate; `fuzz.yml` remains an on-demand search.
`protocol-pairs.yml` (the third-party interoperability jobs) runs only by hand or when
`release.yml` calls it before publishing; it no longer runs on every push or pull request.
Its `only` input runs a single job by id — `gh workflow run protocol-pairs.yml --ref <branch>
-f only=<job>` — which is how a new or changed pair is checked without the other hundred.
The jobs marked *manual* below likewise run only on a manual dispatch of `ci.yml`: push
changes that touch a protocol, then run the workflow (Actions → Run workflow) to get them.

| Job | Blocking | What it does |
|---|---|---|
| `lint` | yes | Formatting and correctness/suspicious clippy lints over the library and every compiled test target |
| `test` | yes | Six jobs: every top-level test target split five ways (`eval::probe_check::` skipped — it drives each eval protocol's real client), and the `CI_PROTOCOL_TESTS` suites (tcp, http, dns, udp, redis, finger) out of `tests/server` and `tests/client`; every protocol compiles, only those run |
| `ratchets` | yes | Whole-tree source checks, server/client Beta evidence declarations, fuzz target compilation |
| `smb-evidence` | yes, *manual* | The SMB server suite, including bounds, both independent clients, and the packet oracle |
| `wasm-web` | yes | Browser bundle build and smoke exchanges |
| `orphaned-tests` | yes | Fails if a test directory on disk is undeclared in `mod.rs` |
| `clippy-wide` | **no** (`continue-on-error`), *manual* | Clippy with the default features, the system-library protocols included |
| `registry-audit` | **no** (`continue-on-error`), *manual* | Registry audits and all-feature real-client/server evidence, with their external peers installed |

The broad registry audit has separate compilation and execution budgets, a five-minute
limit per evidence group, and a summary/artifact step that preserves partial results after
an interrupted evidence step. Each group must run at least one passing test. Its job still
reports green on test failures, so **a green PR is not evidence the audit passed**: inspect
the evidence summary and step outcome. SMB's Stable evidence has a separate blocking job.

Derive the current job list from `.github/workflows/ci.yml` instead of trusting a remembered
count (matrix shards create multiple job executions):

```bash
python3 -c "import yaml; d=yaml.safe_load(open('.github/workflows/ci.yml')); \
  [print(k, 'advisory' if v.get('continue-on-error') else 'BLOCKING') for k,v in d['jobs'].items()]"
```

**There is no per-feature build check any more, because there are no protocol features.** It
used to exist because a protocol that compiled only alongside others went unnoticed: `tor` did
not compile *at any feature set* in September 2026 while every CI run was green. With every
protocol in every build, `lint` and `test` compile all of them on every push; the system-library
protocols are compiled by `clippy-wide` and `registry-audit`, which install those libraries.

**Putting a check on a nightly cron is the wrong shape**, and the distinction generalises to
anything else you are tempted to move off the commit: `fuzz`, `nightly-soak` and
`nightly-eval` are *searches and measurements*, which return no verdict about any particular
commit and so suit a nightly cadence. A compile check is a *gate* — it answers yes or no about
the commit in front of it — so it belongs on the commit.

**In fact none of the three is on a cron any more**: `fuzz.yml`, `nightly-soak.yml` and
`nightly-eval.yml` are all `workflow_dispatch` only, so between dispatches nothing runs them at
all. Dispatch them by hand after changing the surface they cover. That is the right cadence for
a search, but it has a cost worth knowing, because `fuzz.yml`'s own header records paying it:
`coap_message.rs` stopped compiling hours after it was written and stayed broken for weeks,
while the Stable bar's "a fuzz target exists and has run clean" was being satisfied by a target
that could not build. The fix was not to put the search on a cron — it was to have `ratchets`
do `cargo check --manifest-path fuzz/Cargo.toml --all-targets` on every PR. **Separate the
search from the check it depends on, and gate the check.**

### Terminal (PTY) tests

`tests/terminal_snapshot/` drives the real binary through a pty. Four traps cost a full debugging
pass each, and all four present as *product* bugs:

- **Write to the right end.** Bytes written to the pty **master** are delivered to the child as
  keystrokes; bytes written to the **slave** are what appears on the terminal. A test setting up
  "pre-existing screen content" on the master is typing it into the chat box.
- **`write_all` is unsafe once anything has set `O_NONBLOCK`.** A capture that drains until quiet
  has to; afterwards a write can return `EAGAIN` part-way and be abandoned, and `Pty`'s `Write`
  impl reports the short write as success. The symptom is a *truncated command*, which looks
  exactly like a UI dropping keystrokes. Retry against a deadline.
- **Never wait on a fixed sleep.** A 33-character command took ~1.3s to land in the old
  rolling TUI and longer under `--test-threads`. Wait for the condition (`PtyScreen::wait_until`
  keeps one vt100 parser for the whole test), then let the frame settle.
- **A capture that builds a fresh vt100 `Parser` from only the bytes read in that call is not
  idempotent.** Calling it twice renders the second from a blank screen. Polling needs one parser
  fed for the whole wait.

Also: `snapshot_util::assert_snapshot` **creates** a missing snapshot and passes. A new test is
therefore green on its first run whatever it captured — review the file before trusting it.

### Whole-tree source ratchets

Four tests scan **all** 136 server and 91 client protocols by reading source, so they hold at
any feature set — including the 6-protocol CI gate, where a registry-walking test only ever
sees what that build compiled. Each carries a baseline that **may only shrink**, and three of
the four have reached zero (re-derived 16 September 2026 — the figures here read 6 clients, 20
params and 18 examples for months after the work that removed them, so **read the baseline out
of the test file**, not out of this table):

| Test | Catches | Baseline |
|---|---|---|
| `client_event_wiring_test` | a client that asks the model and cannot act on the answer — including `if let Err(..)` with no success arm, `Ok(ClientLlmResult { .., .. })` dropping actions, `Ok(_) =>`, and count-and-log | **empty** (all three lists) |
| `event_emit_sites_test` | an `EventType` declared and never raised (the USB/BLE/imap defect) | **empty**, both trees |
| `startup_param_drift_test` | a startup parameter declared and read by nothing — an advertised knob that does nothing when turned | **4 params** |
| `executable_examples_test` | an action whose own `example` its own `execute_action` refuses — the shape the model copies | **empty** |
| `event_action_declarations_test` | actions the model can never see, and advertised names the executor cannot run | — |
| `well_known_port_declaration_test` | a server with no declared well-known port and no stated reason; a `PrivilegedPort(n)` or transport disagreeing with it | `NO_WELL_KNOWN_PORT` — finished answers, not a queue |
| `startup_param_defaults_test` | a declared parameter `default` written as a literal instead of the constant the code uses (the type check is a registry walk) | **empty** |

A third check worth understanding: `event_action_declarations_test` probes each advertised
name with a bare `{"type": name}`, which finds *unknown action* but can never find a wrong
**field**, because it never sends one. `executable_examples_test` sends the declared example
itself, and that is what caught `ospf` advertising `list_neighbors`/`list_lsdb` with no
executor arm, and `tor_relay_log` advertised under a comment claiming the executor "has always
handled it" when there was no arm at all.

**A source-reading ratchet must know both ways metadata is declared, and which direction it
fails in when it does not.** `ProtocolMetadataV2` is usually built through the builder
(`.state(…)`, `.connectionless()`, `.deliberately_silent()`, `.max_inbound_bytes(…)`), but it
can also be built by struct literal, where the same declarations read `state: …`,
`connectionless: true` and so on. One protocol does that today, `src/client/ospf/actions.rs`.

Ask which way a missed match fails:

- **`no_protocol_is_hidden_from_the_model_test` failed the dangerous way** and was fixed in
  September 2026. It looked only for `.state(…Incomplete)`, so a protocol hidden from the model
  in the literal form would have passed. Hidden is invisible by construction, so nothing else
  would have caught it either.
- **The other three fail the safe way.** `connectionless_audit_test`,
  `failure_mode_declaration_test` and `max_inbound_bytes_declaration_test` each require a
  declaration to be *present*, so an unrecognised form reads as "declares nothing" and is
  flagged. A false positive costs a reader five minutes; a miss costs months.

Two lessons from building them, both about false positives rather than misses. **Detect at the
right nesting depth**: an `Ok(_) => {}` catch-all on an inner `match protocol.execute_action(..)`
is correct and everywhere, and a substring version of that check flagged `ntp` and `tor` while
they executed the model's actions perfectly well. And **for a build-failing check, prefer the
conservative rule**: the strict version of the startup-param scan flagged 57 client parameters,
of which many were read through `get_protocol_field` or a helper — a false positive trains
people to edit the baseline instead of the code.

The gate is deliberately not `--all-features`: that needs system libraries the runner does not
install (`protoc`, `libpcap`, `dbus`, `libusb`, `pcsclite`). So **the CI feature set covers 6 of
116 protocols** — a green PR says nothing about the other 110. Run the relevant tests yourself
before claiming done.

## Building

`./cargo-isolated.sh` wraps cargo with sccache, disabled incremental, stable path remapping,
and automatic logging. Despite the name it now uses the **shared `target/` directory** —
concurrent runs from different sessions contend on the same lock, so serialize your builds.

Logs land in `./tmp/netget-<command>-<PPID>.log`; the path is printed on each run.

```bash
./cargo-isolated.sh --print-last                     # whole log
./cargo-isolated.sh --print-last | grep "error\[E"   # all compile errors at once
./cargo-isolated.sh --print-last | grep -B2 -A5 "^error:"
./cargo-isolated.sh --print-last | grep -A5 "FAILED"
```

**Fix every error in one pass.** Builds cost 10s-2min; rebuilding after each individual fix
wastes hours. Build once, extract the full error list from the log, fix all of it, rebuild once.

Every build compiles every protocol, so there is no faster single-protocol build. What
features change is the system libraries: `--no-default-features --features mcp-stdio,sqlite`
builds without libpcap, D-Bus, libusb, PC/SC, libsmbclient and llama.cpp (no cmake), which is
the build to use where those are not installed. Narrow a *test run* with filters
(`--test server -- server::tcp::`), not features.

Kill stuck builds with `./cargo-isolated-kill.sh`, never `pkill cargo`.

**Write the clippy lint groups qualified: `-D clippy::correctness`, not `-D correctness`.** The
bare form is deprecated and rustc says so:

```
warning: lint name `correctness` is deprecated and may not have an effect in the future
```

"May not have an effect" is the part that matters — a local check written the bare way can go
quiet without failing, and then a finding CI would block on reads as clean on the machine where
the code was written. CI already uses the qualified form in both its clippy jobs; this file's own
table did not, which is how several passes in this repository ran the deprecated one.

```bash
cargo clippy --all-targets -- -D clippy::correctness -D clippy::suspicious
```

`--all-targets` is not optional either: without it the ~200 test files are outside the gate.


### Reclaiming disk: agent worktrees are where the space is, and pruning them has a trap

`/Users/matus/dev/cargo-clean-all.sh` walks `~/dev`, runs `cargo clean` on every Rust project,
**and** reclaims `.claude/worktrees/*/target` — which is usually the bigger half. Measured
16 September 2026: 52 GiB across 23 worktrees in 8 repos, against which the top-level projects
were a rounding error. `--prune` additionally removes a worktree whose branch is merged.

Two things about that worth keeping:

- **`git worktree remove` keeps the branch.** Only the working copy goes, so nothing committed
  is lost and the commits stay reachable. That makes worktree directories the cheapest large
  reserve on the machine, and nobody reclaims them.
- **Check for a live process before removing one, not just that the branch is merged.** During a
  full-disk recovery a worktree was pruned while a `cargo fuzz` run from it was still going. The
  binary was already mapped, so it survived — orphaned at PPID 1, burning half a core for **five
  hours** against a corpus directory that no longer existed, while the same session was
  investigating load-sensitive test flakes on a machine it had quietly oversubscribed.

- **And `pgrep -f` on the path is not that check.** The script's `worktree_is_busy` used it
  alone, and it was measured on 16 September 2026 against **six agents demonstrably building in
  their worktrees**: it matched **none** of them. An agent runs `cargo` after cd-ing in, so the
  absolute path never appears in any command line, and a compile is mostly rustc children
  invoked with relative paths. The guard read as a safety net and was close to a no-op — which
  is the same class as the ratchets in this file that counted a token instead of the thing.

  It now also treats a worktree as busy when its own, its `target/`'s or its `.git`'s mtime is
  within `WORKTREE_ACTIVE_MINUTES` (default 60). Recency is what actually tracks activity. Two
  notes if you write the check by hand: `find -newermt '-60 minutes'` is **not** portable — BSD
  find does not parse the relative form and silently matches nothing, failing open — so compare
  `stat -f %m` (BSD) or `stat -c %Y` (GNU) against `date +%s`. And "merged" is trivially true of
  a branch with no commits on it, so a freshly created agent worktree reads as merged; only the
  recency signal distinguishes it from an abandoned one.

- **Err toward leaving it alone.** Being wrong in that direction costs disk. Being wrong the
  other way destroys work in progress, and the machine is routinely running half a dozen agents.

### `target/` will fill the disk, and it fails in a way that wastes an hour

**Watch `df` during any session that builds several different feature sets.** `target/debug/deps`
reached **130 GB in 27,587 files** in one session here — Cargo never garbage-collects test
binaries from feature permutations, and each `--all-features` test binary links the whole
136-protocol library. Pruning by age does not help: ~17,000 of those files were from that day.
`cargo clean --profile dev` is the remedy, and it keeps `target/release`.

Two things make this expensive rather than merely annoying:

- **It does not present as a disk problem.** The first symptom was a linker line buried in a
  19,000-line log — `ld: write() failed, errno=28 (No space left on device)` — after which the
  sweep reported `exit code 0` having run **zero** tests. An earlier sweep in the same session
  produced 18 "failures" that were pure artefacts. **A sweep that reports no `test result` lines
  did not run; check the log tail before believing any count.**
- **At literally zero bytes free you cannot recover in-session.** Every tool call needs to write
  its output file, so `df`, `ls` and `cargo clean` all fail with ENOSPC and the only way out is
  the operator freeing space by hand. Leave headroom rather than discovering the floor.

### The installed binary — `/Users/matus/bin/netget`

The maintainer's `netget` on `PATH` lives at `/Users/matus/bin/netget` and **must always have every
protocol compiled in.** That is the default feature set, release — **NOT `--all-features`** (see
the footgun below). After any change that adds a protocol or affects the compiled surface,
rebuild and reinstall:

```bash
./cargo-isolated.sh build --release && \
  cp target/release/netget /Users/matus/bin/.netget.new && \
  mv -f /Users/matus/bin/.netget.new /Users/matus/bin/netget   # atomic; safe if netget is running
```

**Check that the binary answers `--mcp`.** Until September 2026 this command built
`all-protocols` without `mcp-stdio`, which produced a binary answering `--mcp` with `Error: MCP
STDIO mode requires the 'mcp-stdio' feature` — exactly how the maintainer runs it. MCP is in the
default set now, but nothing would catch its removal: the build succeeds, the binary starts, and
only the one invocation that matters fails. Smoke-test the installed binary over its own MCP
surface rather than trusting `--version`:

```bash
printf '%s\n%s\n%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}' \
 '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_protocols","arguments":{}}}' \
 | timeout 45 /Users/matus/bin/netget --mcp 2>&1 | head -c 300
```

The atomic `mv` matters: the maintainer runs `netget --mcp` interactively, and overwriting the
file in place can fail with `ETXTBSY` while it is running. Rename swaps the inode instead — the
live process keeps the old image, the new binary takes effect on next launch. **Never kill the
running `netget` to install** — the rename never needs it stopped.

**`--all-features` vs the default — they are NOT interchangeable.** `--all-features` is a Cargo
built-in that turns on *every* feature in `Cargo.toml`: the default set plus **`gpu`** (GPU stats
via `gfxinfo`), `vendored-openssl` and the test-only `terminal-snapshot`. The default is the
curated "everything, and only things safe to run" set — it includes `embedded-llm` (dormant
unless `--embedded-model` is passed) but **not** `gpu`. Use `--all-features` for a compile check
(`cargo check --all-features`) and the default for a binary you run.

**The `gpu` crash this section used to describe is fixed, and the description of it was wrong in
every detail worth acting on.** It said the feature "initializes a Metal context at startup" that
crashes "the instant the TUI renders". It is not Metal and not startup: `gpu` pulls in `gfxinfo`,
whose macOS `MacGpuInfo::load_pct()` over-releases a `CFDictionary`, and the extra `CFRelease`
raises `EXC_BREAKPOINT`/SIGTRAP inside CoreFoundation. `SystemStatsMonitor::get_stats` is the only
caller and the since-removed rolling TUI was the only caller of *that*, on a one-second interval —
so the crash landed a second or two **after** the first paint, only there, and never in the
dashboard. `src/system_stats.rs` now compiles the `gfxinfo` call out on macOS
(`cfg(all(feature = "gpu", not(target_os = "macos")))`) and reports `N/A`, which is what the
operator saw anyway wherever the stat was unsupported. Linux and Windows are unaffected.

The stack is worth keeping because it is not catchable: the crash is inside a `Drop`, so there is
no fallible call to wrap and `catch_unwind` cannot see it. It surfaced only because
`tests/terminal_snapshot` is the one suite that *runs the TUI*, and only once those tests were
pointed at the rolling TUI — before that they exercised the dashboard and never touched the path.

**Every panic is logged, as of September 2026** (`src/panic_log.rs`), installed from
`init_logging` so it covers `--mcp`, `--mcp-http`, `--simple` and the non-interactive runner as
well as the TUI, and chaining to whatever hook it replaced so the dashboard's terminal-restore
still runs. Before it, a panic inside `tokio::spawn` was written **nowhere** — nothing awaits a
connection task's `JoinHandle`, so the `JoinError` carrying the panic was dropped, which is why
all three historical instances were found by reading code rather than by grepping. If you see
"the server stays Running and the peer hangs", `grep PANIC netget.log` now answers it.

The TUI installs a native-crash terminal restorer (`src/cli/crash_restore.rs`): a
SIGSEGV/SIGABRT/SIGTRAP from a C/ObjC library bypasses Rust's `Drop`/panic machinery, so without it
a crash leaves the shell wedged in raw mode. The handler restores cooked mode + cursor before the
process dies. It is a safety net, not a licence to ship a crashing binary — fix the crash too.

### System libraries, and what builds without them

Detect Claude Code for Web with `./am_i_claude_code_for_web.sh` or
`[ "$CLAUDE_CODE_REMOTE" = "true" ]`. The default features link five system libraries, each
behind a feature of its own; derive the current list from `[features]` rather than this copy:

| Feature | Library (Debian / Homebrew) | Protocols |
|---|---|---|
| `libpcap` | `libpcap-dev` / ships with macOS | `arp`, `datalink`, `isis`, `lldp`, `cdp`, `stp`, `eapol` |
| `bluetooth` | `libdbus-1-dev` / CoreBluetooth ships with macOS | all `bluetooth-ble*` |
| `pcsc` | `libpcsclite-dev` / ships with macOS | the NFC client |
| `libusb` | `libusb-1.0-0-dev` / `libusb` | the `usb-*` virtual devices |
| `libsmbclient` | `libsmbclient-dev` / `samba` | the SMB client |

`embedded-llm` (default) builds llama.cpp and needs `cmake`, a C++ compiler and libclang (bindgen;
`libclang-dev` / `clang-devel` / `clang`, Xcode's command-line tools on macOS). The protobuf
compiler is **not** a requirement any more: `build.rs` uses `protoc-bin-vendored` unless
`PROTOC` names one.

```bash
# Everything that needs no system library
./cargo-isolated.sh build --no-default-features --features mcp-stdio,mcp-http,sqlite
```

## The website — netget.net

**The site does not deploy itself. Nothing watches this repository; a merge to master
publishes nothing.** `site/` is the landing page and `./site/deploy.sh` is the only way it
reaches netget.net — run it whenever you change anything under `site/`, or the live page
stays at whatever the last person uploaded.

```bash
./site/deploy.sh        # needs AWS_PROFILE=smotana, which the script exports itself
```

It publishes `site/` to the `netget.net` S3 bucket and invalidates the CloudFront distribution,
so a deploy is live within seconds. `css/`, `js/` and `demo/` go up under a content-hashed
`v/<hash>/` prefix (immutable) and `index.html` (`no-cache`) is rewritten to point there, so a
browser never pairs one deploy's JavaScript with another's `.wasm` — which fixed-URL week-long
caching did, breaking the demo with `wasm.<export> is not a function`. `DRY_RUN=1` changes
nothing; `STAGE_DIR=<dir>` keeps the staged copy to test. Details in `site/AGENTS.md`.

Two things about it are load-bearing:

- **`site/` is public and so is `docs/`, which this entry denied for months.** Only `site/` is
  uploaded by `deploy.sh`, and a new file there is a new public URL — that half is right. But
  the claim that `docs/` "used to be served … and is not any more" was **false when written and
  is false now**: `gh api repos/netget-net/netget/pages` reports Pages still enabled,
  `build_type: legacy`, source `master:/docs`, status `built`. Every push to master rebuilds it
  and all 32 files under `docs/` are live at `https://smotanacom.github.io/netget/<name>.html`.
  Verified by fetching three of them: 200 each.

  Nothing leaked — the repository is **public** (`visibility: public`), so those files are
  already readable on github.com, and a scan of `docs/` for credentials found only placeholders
  (`<r2-secret-key>`, `YOUR_ORG_NAME`, `ACCOUNT_ID`, `minioadmin`, and AWS's own documentation
  example key). The hazard is this sentence rather than the content: anyone reading it would
  reasonably put something in `docs/` believing it goes nowhere.

  **Why nobody noticed: the site root is a 404.** Only the individual pages resolve, so from the
  front door it looks dead. There is no workflow file to remove — `build_type: legacy` means
  GitHub's own builder, driven by a repository setting.
- **`deploy.sh` excludes itself and every `*.md`.** `site/AGENTS.md` names the bucket,
  distribution and OAC IDs; the first run of the script published it before the exclusion
  existed. `--delete` skips excluded paths too, so removing such a file from the bucket is a
  manual `aws s3 rm`.

Hosting is S3 + CloudFront (private bucket, OAC, ACM cert, DNS at Porkbun) — the same shape as
the maintainer's other static sites. It replaced GitHub Pages for the landing page — the
stated reason was that Pages "cannot serve a private repository", which does not hold today
since the repository is public, so treat that as history rather than as a constraint. Pages
itself was never turned off; see the `docs/` note above. `site/AGENTS.md` has the resource IDs,
the DNS records and how to change them.

## Browser build (wasm32) — the landing-page demo

netget.net runs NetGet itself in the page: the dashboard, every server protocol that compiles
for `wasm32-unknown-unknown` (68 features, TCP and UDP; the list is
`crates/netget-web/Cargo.toml`, the exclusions and the probe that derives them are in
`web/README.md`) and the LLM plumbing, built by `./web/build.sh`, page in `site/`.
`web/README.md` is the operating manual; what matters for anyone touching the tree:

- **Protocol code is compiled unchanged.** On wasm32 the names `tokio` and `crossterm` mean
  the shim crates `crates/netget-tokio-wasm` and `crates/netget-crossterm-wasm`, bound at the
  crate root with `extern crate … as` in `src/lib.rs`. The tokio shim re-exports real tokio's
  `sync`/`io`/macros and supplies `spawn` (the JS event loop), `time` (`setTimeout`), and
  `net` — a **virtual loopback**: `TcpListener::bind` claims a port in a table,
  `TcpStream::connect` hands the listener an in-memory duplex, `UdpSocket::bind` claims a
  port and `send_to` delivers a datagram to whoever is bound there. A protocol that only
  uses `tokio::net`, `tokio::io`, `tokio::sync` and `tokio::time` needs no `#[cfg]` at all;
  `process`/`fs`/`signal` compile and fail at runtime. What keeps a protocol out is a
  *dependency* that wants real sockets (`mio`), a C library, or a device.
- **Cargo forbids one dependency name resolving to different packages per target**, which is
  why the shims are *not* `tokio = { package = … }` renames in a target table. Same-source
  dependencies with different features per target are fine; that is how `syntect`,
  `ratatui` and `tui-textarea` differ between the two `[target.'cfg(…)'.dependencies]`
  tables.
- **`std::time::Instant::now()` and `SystemTime::now()` panic on wasm32, and the compiler
  cannot tell you.** Use `crate::utils::clock::{Instant, SystemTime, UNIX_EPOCH}` (std on
  native; on wasm the tokio shim's `performance.now()` clock, offset ten years so
  `Instant::now() - window` in the rate limiter cannot underflow on a fresh page). All of
  `src/` is converted; keep new code on the alias. Because the shim's `Instant` is its own
  type, a stray `std::time::Instant` in anything the browser build compiles is a compile
  error there, which is the check. `std::process::id()` is the same kind of trap:
  `clock::process_id()`. A **dependency** reading the clock is the case no alias covers, and
  hyper was one: its HTTP/1 dispatcher refreshes a `Date` cache from `SystemTime::now()` on
  every poll, so every hyper server killed the page on its first request. The root
  `Cargo.toml` patches hyper with `vendor/hyper` — the exact locked crates.io source, changed
  only in `src/common/date.rs` under `cfg(all(target_arch = "wasm32", target_os = "unknown"))`
  to read `js_sys::Date::now()`; native builds compile upstream's code.
  `vendor/hyper/README.md` has the diff and the upgrade steps, and
  `tests/vendored_hyper_patch_test.rs` fails if Cargo.lock's hyper stops being that copy.
- **The LLM backend is `LlmBackend::Bridge`** (`src/llm/bridge.rs`): every request the client
  would have sent over HTTP is a `BridgeRequest` on a channel — full messages, tools, model,
  and `actions`: every action the prompt offers, with parameters, schema and example — and
  the page answers it with Chrome's built-in model (the Prompt API, constrained to the
  offered actions), a WebLLM model, or the visitor ("You are the model" in the select, or a
  model that needs a download click; a request waits for a model that is loading, at most
  two minutes, rather than going to the visitor), who answers through `site/js/composer.js`: pick an offered action, edit fields prefilled from
  its example, send (Raw JSON stays one tab away). The demo itself is Telnet only and starts
  by itself (server, then client); `web/README.md` has the page's behaviour. Network events carry no native `tools`, so `actions`
  is the only structured list they have; the Ollama/OpenAI wire never carries it. The
  Ollama/OpenAI backends (`reqwest`, `ollama-rs`) are `#[cfg(not(target_arch = "wasm32"))]`;
  the circuit breaker deliberately ignores the bridge, since a slow person is not an outage.
  `tests/llm_bridge_test.rs` pins the mapping natively (including a real TCP server's event
  offering its actions with examples); `web/test/smoke.mjs` drives the real bundle under Node
  (dashboard paints, `start_server`, connect, model round-trip, bytes back, the
  composer's default reply accepted, the HTTP-family clients — `http`, `jsonrpc`,
  `elasticsearch`, `openapi`, `bitcoin`, `npm`, `pypi`, `maven`, `torrent-tracker`, `ollama`,
  `http2` (h2c through hyper's HTTP/2 client), and `oauth2` and `openidconnect` (their crates'
  HTTP hook handed the transport), each through `[ + <proto> client ]` or `ClientForm`
  and a `[ send ]` against NetGet's own server of its protocol (bitcoin's JSON-RPC against
  the `http` server), the response checked on the client — and Node's `node:http`/`node:http2` clients against the `http`, `openapi`,
  `jsonrpc`, `rss` and `http2` servers over `NetGet.connect()`, `Date` headers checked) and
  CI's `wasm-web` job runs both. In the browser those clients issue their requests through
  `src/client/http_fetch` (`FetchClient`: reqwest natively, unchanged; hyper's HTTP/1.1 client —
  HTTP/2 with prior knowledge for `http2` — over the virtual loopback on wasm32, `https://`
  refused with the reason); no client is gated out of the browser build
  for being reqwest-based any more, and `web/README.md` lists each with its smoke evidence.
  `web/test/page_composer.py` drives the page in headless Chromium and is run by hand.
- **The dashboard loop is generic** (`event_loop::run_loop` over any ratatui `Backend` and any
  `Stream` of crossterm events); the web crate's backend emits ANSI into xterm.js and its
  input translates DOM `KeyboardEvent`s. The scheduled-task ticker (`src/cli/tasks.rs`) is
  compiled for wasm too; it uses `utils::clock`.
- **Building on macOS needs `llvm-ar`** (`rustup component add llvm-tools`): the system `ar`
  writes a broken archive for ring's wasm objects and the failure shows up only at link time
  as `undefined symbol: ring_core_…`. `web/build.sh` handles it; if ring was already built
  wrong, `cargo clean -p ring --target wasm32-unknown-unknown --release` once. ring is there
  because `http` pulls rustls/rcgen, which now build with `default-features = false` and the
  `ring` provider — the `aws-lc-rs` default is a C library that does not build for wasm.
- **Publishing is the site's own `./site/deploy.sh`, and the bundle is not built by it.**
  `./web/build.sh` writes `site/demo/pkg/` (gitignored, ~17 MB of wasm, 5.7 MB gzipped);
  `deploy.sh` refuses to run without it and uploads the `.wasm` with
  `Content-Type: application/wasm` so browsers can compile it while it streams. Build, run
  the smoke test, then deploy. CI's `wasm-web` job builds and smoke-tests the bundle on every
  PR but publishes nothing, like everything else in this repository.

## MCP surface

`--mcp` (stdio) and `--mcp-http PORT` expose tools sharing the TUI's code paths. See
`src/mcp_stdio/AGENTS.md`.

**Five of the six gaps this section used to list have been fixed, and it kept claiming them.**
Re-verified September 2026 against `src/mcp_stdio/`:

| Former gap | Status |
|---|---|
| No client tools | **Fixed** — `start_client`, `list_clients`, `client_status`, `stop_client` all exist in `tools.rs` |
| `start_server` cannot pass `interface` / `mac_address` / `scheduled_tasks` / `initial_memory` / `feedback_instructions` | **Fixed** — all are tool params and are passed through |
| `send_first` accepted as `_send_first` and ignored on every path | **Fixed** — `params.send_first` is passed and folded into `startup_params`, though only where the protocol declares it |
| `get_protocol_docs` returns TUI docs describing an uninvokable API | **Fixed** — `docs.rs` is MCP-shaped and mentions neither `open_server` nor `base_stack` |
| `stop_server`/`stop_all` skip `cleanup_server_tasks()` | **Fixed** — teardown moved inside `AppState::remove_server`, pinned by `tests/mcp_stop_cleanup_test.rs` |

**Everything the dashboard's buttons do is a tool too** — `send_to_client`, `send_to_peer`,
`disconnect_peer`, `list_intercepts`, `answer_intercept` (`[]` = answer with nothing) and
`fail_intercept`. Each validates the action `type` against the target's own set before handing
it to a running loop; `server_status` lists connection ids and which accept `send_to_peer`.
There is no `dismiss_intercept` tool on purpose: dismissing *is* failing closed. Details in
`src/mcp_stdio/AGENTS.md` ("Driving by hand").

**Two remain:**

- **Unknown action names in `event_handlers` are still accepted at startup** — only the
  handler's *shape* is validated. They are no longer silent at runtime, though:
  `executor.rs` logs at ERROR and records a failure.
- **No state persists across process restarts**, which is by design.

**The lesson is about this file, not about MCP.** A "current gaps" list is the part of any
document that rots first, and rotting toward *understating* the code is the dangerous
direction: it tells the next person a capability is missing, so they build around an absence
that is not there. Re-derive such a list before trusting it, and prefer stating how to check
over stating what is true.

A long-running `netget --mcp` process keeps executing its original binary image after a
rebuild. When behavior contradicts the source, confirm which build is actually running before
concluding there's a bug.

## Logging

**Dual logging everywhere**: tracing macros (`error!`/`warn!`/`info!`/`debug!`/`trace!`) →
`netget.log`, and `status_tx.send()` → TUI/MCP status stream. Levels: ERROR critical, WARN
non-fatal, INFO lifecycle, DEBUG summaries, TRACE full payloads.

Every status/event channel is an **unbounded** `mpsc` — there is no backpressure anywhere.
Don't add high-frequency per-byte messages to these channels.

## Scheduled tasks

Three scopes: **Global** (any server), **Server** (auto-cleaned on close), **Connection**
(auto-cleaned on close). Create via the `open_server` action's `scheduled_tasks` array or the
`schedule_task` action; add `connection_id` for connection scope. Parameters: `task_id`,
`recurring`, `interval_secs`/`delay_secs`, `instruction`. Use connection scope only for
long-lived connections (SSH, WebSocket); short-lived request/response protocols should use
server scope.

## Multi-instance collaboration

Assume other agents work in this repo concurrently.

- **Never `git add -A`, `git add .`, `git add -u`, or `git commit -a`.** Stage explicit paths
  only — `git add <path> && git commit -m …`, listing every file. This is not style: a broad
  `git add` sweeps up whatever other agents have half-written, and a half-written change
  committed without its other half breaks `master` for everyone.

  It has happened three times. Twice it broke the build: once landing a caller without its
  callee (`CertificateCache::new` gaining a third argument in `proxy/mod.rs` while
  `proxy/cert_cache.rs` stayed uncommitted), once landing 24 import swaps without the module
  they imported. The third time, a `git add -u` intended for a documentation cleanup swept
  fourteen source files from five different agents into a commit titled "docs: remove 46
  one-off session and status reports" — it happened to compile, but the history now
  misattributes that work.

  **`git add -u` counts.** It stages every tracked modification in the tree, which during
  parallel work is everyone's. The `-u` flag reads as narrower than `-A` and is not.

- **Staging explicit paths is NOT enough — pass the paths to `git commit` too.** This is the
  fourth incident and the subtlest: `git add <paths> && git commit -m ...` stages what you
  listed and then commits **the whole index**, including anything another agent staged and had
  not yet committed. In August 2026 that swept a *deletion* of `src/server/usb/smartcard/crypto.rs`
  — staged by an agent mid-edit — into an unrelated BGP-client commit, leaving HEAD referencing
  a module whose file was gone. It took a follow-up revert to repair.

  Use the pathspec form, which commits only those paths regardless of what else is staged:

  ```bash
  git add <paths> && git commit <paths> -m "..."     # or: git commit -- <paths>
  ```

  And check before you commit, because the index is shared state:

  ```bash
  git diff --cached --name-only     # must list only your files
  ```

- **The pathspec form protects against a dirty INDEX, not a dirty WORKING TREE — and for a
  shared file that distinction is the whole problem.** `git commit <pathspec>` commits the
  *working-tree* content of those paths. So if another agent has `Cargo.toml` mid-edit and you
  name `Cargo.toml`, you commit **their uncommitted hunks along with yours**. Three agents hit
  this independently in one session, on `Cargo.toml`, both registries and both test `mod.rs`
  files. The rule above reads as complete protection and is not.

  For a file only you touched, the pathspec form is fine. For a **shared** file, rebuild its
  blob from `HEAD` plus only your own lines and stage that, leaving the working tree alone so
  the other agent's edits survive:

  ```bash
  # HEAD-based patch of just your hunks, applied to the index only
  git diff HEAD -- <shared-file> > /tmp/mine.patch   # then edit down to your hunks
  git apply --cached /tmp/mine.patch
  git diff --cached --name-only    # must list only your files
  git diff --cached -- <shared-file>   # must show only your lines
  git commit -m "..."              # no pathspec: the index is already exactly right
  ```

  `git hash-object` + `git update-index --cacheinfo` achieves the same thing when the file is
  easier to reconstruct than to patch. Either way, **verify `git diff --cached` before
  committing** — that is the only step that actually catches the mistake.

- **Even the patch-the-index method races, because the index is shared. Under heavy concurrency,
  commit through a PRIVATE index.** The fifth incident (August 2026, a wave of ~10 concurrent
  agents): three agents each staged only their own hunks correctly via `git apply --cached`, and
  were *still* swept — because in the window between their staging and their `git commit`, another
  agent's bare `git commit` (no pathspec) committed the whole shared index, carrying the first
  agent's staged files into the second agent's commit. `git diff --cached` was clean when they
  checked it; the race happened after. Several new protocols landed misattributed inside
  unrelated commits this way. It compiled and nothing was lost, but the branch ref also got
  rewound twice, orphaning commits.

  The shared `.git/index` is the contended resource. Give yourself a private one with
  `GIT_INDEX_FILE` so no other agent's commit can see or sweep your staging:

  ```bash
  export GIT_INDEX_FILE=$(mktemp /tmp/idx-<your-task>.XXXX)
  git read-tree HEAD                      # seed the private index from HEAD
  git add -- <your paths>                 # stages into the PRIVATE index only
  git diff --cached --name-only           # must list only your files
  T=$(git write-tree)
  C=$(git commit-tree "$T" -p HEAD -m "feat(x): ...")   # GPG: add -S
  git update-ref refs/heads/master "$C" HEAD            # CAS: fails if master moved — then retry
  unset GIT_INDEX_FILE
  ```

  Two cautions. (1) `commit-tree`+`update-ref` is the one legitimate use of `update-ref` — but it
  must be a compare-and-swap against the `HEAD` you built on (the third arg), so it *fails* rather
  than clobbering if master advanced; on failure, re-read HEAD and rebuild. Never `update-ref`
  without the old-value CAS argument — an unconditional one is the force-move that got flagged as a
  security violation. (2) This only serializes *your* commit's atomicity; it does not order you
  against other agents. When two agents both target `master`, the CAS makes the loser retry — which
  is correct. If your harness gives each agent its own **worktree** (separate `.git` index and
  working tree both), that is strictly better and none of this is needed — prefer it for any agent
  expected to commit under contention. But worktrees branched from a stale base still cost a
  re-apply for anything touching hot central files (`action_helper.rs`, the `CommonAction` enum,
  `executor.rs`), so isolation moves the cost from *corruption* to *merge*, it does not remove it.
- **Shared files** (`Cargo.toml`, both registries, `server/mod.rs`, `client/mod.rs`, both test
  `mod.rs` files, `state/server.rs`): use `Edit`, add incrementally, never overwrite wholesale.
- **Give scratchpad files a name unique to you.** Two agents independently wrote `mod.rs.bak`
  into the shared session scratchpad; one clobbered the other, and restoring "the" backup put
  one protocol's source into another protocol's file. Prefix every scratch file with your task.
- **Never revert a dirty working-tree file you did not demonstrably write** — no
  `git checkout -- <path>`, `git restore`, or overwrite to "tidy up" an edit that looks
  half-finished. You cannot tell your own abandoned work from another agent's work in progress,
  and the tree is routinely mid-edit for several agents at once. An unverified edit left in the
  tree is a far smaller problem than deleted work. This happened: a batch of subagents died
  mid-task leaving three modified files, and the reflex to restore a clean tree wiped edits that
  may not have been theirs. They survived only because `git diff > patch` had been run first.
  If you truly must clear a path, save `git diff -- <path>` to a uniquely named scratch file
  **first** and say so — but prefer leaving it alone and reporting it.
- **Don't fan out a large agent wave while the API is failing.** If agents start returning
  "stalled" or the tool-permission classifier times out, stop and wait instead of launching the
  next slice. Three waves were attempted during one degraded period and burned **~9.8M tokens to
  return 5 usable results**; the dead agents also left half-written files in the shared tree for
  someone else to trip over.

  Two diagnoses that looked obvious and were both **wrong**, recorded so they are not re-tried:
  (1) *a cold `target/` making agents queue on the build lock* — warming the cache first changed
  nothing; (2) *agents blocking >180s inside `cargo check` with no output* — a rewritten wave that
  forbade cargo entirely still lost 28 of 29 agents. The stall is in the agent infrastructure, not
  in what the agents were asked to do, so **rewriting the task does not rescue it — only waiting
  does.** The tell is uniformity: when nearly every agent dies with the same "no progress for
  180000ms" on all 6 retries while one or two trivial ones succeed, that is the platform, not the
  prompt.
- **Pause and report** if you hit an error in code you did not modify. It is almost always
  another agent mid-edit; retry rather than "fixing" their file.
- **Verify HEAD, not the working tree.** During parallel work the working tree is routinely
  mid-edit and its failures belong to nobody. Check the committed state in a throwaway
  worktree: `git worktree add --detach <tmp> HEAD && cargo check --all-features` with its own
  `CARGO_TARGET_DIR`. Remove the worktree afterwards.
- **`--ollama-lock` does nothing, and its plumbing is now gone.** The flag is parsed into
  `Args::ollama_lock` and **read by nothing**. It used to be threaded through six hops that each
  made it look implemented — `AppState::new_with_options`'s second parameter, the
  `ollama_lock_enabled` field, `get_ollama_lock_enabled()`, `create_llm_client(args,
  lock_enabled)` and `OllamaClient::new_with_options(url, lock_enabled)`, whose body was
  `Self::new(base_url)` under a comment saying locking is "handled at a different layer". Nothing
  in `src/` was that layer and no `ollama.lock` was ever created. All six are deleted; the flag
  stays accepted and inert so `--ollama-lock` in an existing script is not a hard clap error.
  The harness no longer passes it — it used to go to *every* spawned binary, which is why the
  whole e2e suite looked as though it serialised LLM access across processes. **Don't reason
  about concurrency from it**: `--llm-max-concurrent`, `--llm-queue-timeout` and
  `--llm-max-queued` are the real bounds. `tests/ollama_lock_is_a_noop_test.rs` fails if the old
  claims come back, if an `ollama.lock` appears, or if anything in `src/` reads the field again.
- Concurrent `git` work should use worktrees.
- **Do not run a full sweep while anything else is building.** `tests/examples` and
  `tests/terminal_snapshot` *spawn `target/debug/netget`*, and `target/` is shared with every
  other agent and with your own narrow-feature builds. A concurrent build replaces that binary
  mid-run, and the sweep then reports things like `Protocol 'SOCKS5' exists but is not compiled
  into this build` for protocols that are in fact compiled, or hangs a pty snapshot test. Those
  are contention artefacts, not regressions — check for other `cargo test` processes before
  believing a binary-spawning failure.
- Never `pkill cargo`; use `./cargo-isolated-kill.sh`.
- The user runs `netget --mcp` interactively. **Never kill netget processes.**

## Known systemic issues

Read before assuming a subsystem is sound:

- **Clients that ask the model what to do and then throw the answer away.** The single most
  common client defect, found in six protocols in one pass and fixed in all of them. It has
  three shapes, and none of them fails loudly — the client connects, reports success, and
  does nothing:
  - *Discarded outright.* `etcd` counted the actions and logged the count. `turn` logged
    "initial LLM call returned 1 actions" and dropped them, so a client told to allocate a
    relay never put a byte on the wire. `datalink` made no connected-event call at all.
  - *Run through a deliberately non-notifying path.* `elasticsearch` and `http2` executed
    follow-ups with a core that raises no event, so the chain was one step deep: a `search`
    issued in reply to an index confirmation ran and its hits went nowhere.
  - *Event declared and never emitted.* `imap` advertised `imap_mailbox_selected`,
    `imap_search_results` and `imap_message_fetched`; nothing raised any of them, so the
    model got one turn on connect and then went deaf.

  The reason these persist is that the honest fix looks impossible at first: action → event
  → action is genuinely self-referential, and an `async fn` that awaits itself has an
  infinitely-sized future (E0391). **The answer is a depth bound, not silence.** Box the
  recursive call — and name `+ Send` explicitly on the boxed type if it is awaited inside a
  `tokio::spawn`, which inference will not give you — then cap it (`MAX_FOLLOWUP_DEPTH`,
  4–8). Where the cycle already passes through a queue or a separate task, as in
  `datalink`'s pcap loop, no boxing is needed at all: the chain continues by itself.

  When you touch a client, check what it does with `result.actions`. `let _ =`, a bare
  `debug!` of `.len()`, or a comment explaining why the model's answer is not needed are all
  the same bug.

- **A literal IP still goes through the system resolver, and it can block for seconds.**
  `reqwest` hands the URL host to its DNS resolver unconditionally, and `hyper-util`'s
  `GaiResolver` does not special-case a dotted quad — so `http://127.0.0.1:11434` performs a
  real `getaddrinfo("127.0.0.1")`. On macOS that goes through libinfo to mDNSResponder, one
  system-wide daemon, which serialises under concurrency: **measured at 8.25 seconds** with
  ~100 processes asking at once. Use
  `crate::llm::ollama_client::client_for_endpoint{,_with_timeout}`, which applies the override
  when — and only when — the host parses as an `IpAddr`. A hostname is left alone; resolving it
  is the resolver's job.

  Two traps this produced, both worth knowing:
  - **The override is gated on that parse, so extracting the host must be right.** A first
    version stripped only the scheme, leaving `127.0.0.1:54321`, which does not parse — so the
    bypass silently did not engage and the symptom was unchanged. `host_of` and
    `tests/literal_ip_dns_bypass_test.rs` exist for exactly that.
  - **It presents as "the machine is loaded".** The failing test showed a healthy server that
    had never been spoken to. What settled it was one raw `TcpStream::connect` next to the
    failing request: 464µs and the server logged the accept, while reqwest's own connect had
    not arrived 8 seconds later. **When a client times out against a healthy server, prove
    which step is stuck before blaming the environment** — an earlier pass concluded "external
    machine load" and closed the investigation with the bug still there.

- **More test threads is not the fix for a starved runtime here.** `--test-threads=100` already
  oversubscribes a 12-core box; giving one test `flavor = "multi_thread", worker_threads = 4`
  made the same failure go from 2/6 to **7/8**. Measure before adding workers.

- **The FIRST `reqwest::Client` in a process is expensive, and this entry named the wrong
  reason for a long time.** It said the cost was the rustls stack and the platform root store,
  read from the keychain through Security.framework. **Measured September 2026: that is wrong
  in every part.** The TLS backend is irrelevant (`use_rustls_tls()` measured *slower*, 699 ms
  vs 657 ms), and **no root store is loaded at build time at all** — that happens at handshake.
  So `tls_built_in_root_certs(false)` buys nothing, and the old advice sent people straight at
  it.

  The real mechanism is the **system-proxy probe**. `reqwest`'s `system-proxy` feature is on by
  default, so every `build()` calls `hyper_util`'s `Matcher::from_system()`, which on macOS
  opens an `SCDynamicStore` session against **configd** — one system-wide daemon, exactly the
  shape of the mDNSResponder serialisation above, a different daemon. Measured at 100
  concurrent processes: first build **657 ms p50**, with `.no_proxy()` **0.090 ms**.

  It is **per-process, paid once**: the second client in the same process costs ~0.3 ms at any
  concurrency, which is why a per-endpoint client cache was measured and *rejected* rather than
  built. Build it once rather than per request (`doh`, `http` and `openapi` all rebuilt it every
  time) — but do not reach for `spawn_blocking` or a cache without measuring first, because on
  these numbers neither is warranted.

  `src/llm/ollama_client.rs`'s `configured_for_endpoint` applies `.no_proxy()` **only** for
  loopback hosts. That is also a correctness fix: `hyper_util`'s macOS reader never consults
  `kSCPropNetProxiesExceptionsList`, so with a proxy configured a request to
  `http://127.0.0.1:11434` went **to that proxy**. `tests/llm_endpoint_proxy_bypass_test.rs`
  shows it from the wire. Note the consequence: a loopback target no longer honours
  `HTTP_PROXY`.

  **The `doh` client finding below is attributed to the keychain and should be re-checked
  against this** — the same 657 ms proxy probe was present in every one of those processes and
  is the better candidate.

- **A client that loses its target must fail, never fall back to the real service.** The
  DynamoDB client took the address as `_remote_addr` and dropped it, so with no explicit
  `endpoint_url` the AWS SDK resolved its default — `https://dynamodb.<region>.amazonaws.com` —
  and signed with whatever ambient credentials the machine had. **A client the operator pointed
  at localhost issued real reads and writes against real AWS**, and that is the shape of the
  protocol's own startup examples. The S3 client had the mirror image: it read its parameters
  from `protocol_data`, which nothing populates before `connect()`, so every client signed with
  empty credentials and was pinned to `us-east-1`.

  Any client wrapping a vendor SDK inherits that SDK's defaults, and those defaults point at
  production. Read the target, and if it is missing, **refuse to connect** — do not let a
  library's fallback decide where NetGet's traffic goes.

  Related and worth knowing: **no server in the cloud family validates any signature**, and
  none puts `Authorization` / `X-Amz-Date` into the event either, so the model cannot make that
  decision on their behalf — every request is served unconditionally. Snowflake shows the model
  `has_auth_token` as a **boolean that is true for any token**, including one the server never
  issued. That is fine for a mock, but it must be said out loud rather than implied away.

- **A startup parameter is printed wherever the instance is described, so a secret in one is a
  secret in the log.** The `open_client` summary and the executor's DEBUG action line both
  printed startup parameters verbatim — RADIUS shared secrets, MQTT and LDAP passwords among
  them — until September 2026; `src/utils/redact.rs` now masks credential-named keys at both.
  Name a new secret-bearing parameter so the redactor recognises it, and assert in a test that
  the secret appears in no event and nothing NetGet printed, as the RADIUS client's does. A
  secret the model itself put in an `open_client` action is still in the model's own output,
  which the LLM layer logs at DEBUG (a preview) and TRACE (in full).

- **A recursive parser without a depth bound kills the whole process, and `tokio::spawn`
  cannot save you.** A Rust stack overflow is a `SIGSEGV` against the guard page, not a panic —
  so unlike the swallowed-panic class above, there is nothing to catch and no task to lose in
  isolation: the entire NetGet process dies. Three protocols had this, all reachable
  **pre-authentication**. AMQP's field tables are recursive and cost the peer **five bytes per
  level**, so one 128 KiB frame bought ~26 000 levels; NATS recursed once per blank line, and
  8 KB of newlines is a single `read`. Both are now bounded (`MAX_FIELD_TABLE_DEPTH = 32`;
  real tables are depth 2), and the AMQP bound was verified by *removing* it and watching the
  test binary abort with `stack overflow`. **If a decoder can call itself, it needs a counter.**

  **Six protocols have now had this, and bencode was the cheapest: ~1 KB on the wire.**
  `serde_bencode` 0.2 has no depth limit anywhere, and one byte (`l` or `d`) opens a level —
  measured at 1 000 levels to kill a 2 MiB tokio worker and 9 215 to kill the 8 MiB main
  thread. The DHT server took those bytes from an **unauthenticated UDP socket**.

  **A typed decode is no safer than a raw `Value`**, which is the part worth remembering:
  serde's derive skips unknown fields through `IgnoredAny`, and that lands straight back in
  `deserialize_any`. Deriving `Deserialize` onto a shallow struct does *not* bound nesting.
  `src/utils/bencode.rs` walks the bytes iteratively before any decode, and is shared because
  four call sites across three protocols under two Cargo features need it.

  **`redis` was the seventh (September 2026), and it hid under a size cap.** `redis-protocol`
  6.0's `resp2::decode` recurses once per nested array and `*1\r\n` opens a level in four bytes,
  so 400 KB — far under the server's 64 MiB `MAX_PENDING_FRAME_BYTES` — killed the process from
  one unauthenticated connection. **A byte cap is not a depth cap.** `src/utils/resp.rs` walks
  the frame iteratively first (depth 32, declared `*N`/`$N` bounded) and follows the decoder's
  grammar exactly, which `fuzz/fuzz_targets/resp_frame.rs` checks differentially.

  **`mongodb` was the eighth, found the same day by asking the same question of its decoder.**
  `bson` 3.0 converts a raw document recursively with no limit, seven bytes a level, and a
  **debug** build dies at 284 levels — 2 KB. `src/utils/bson_depth.rs` scans first (depth 64,
  below MongoDB's own 100 because of that per-level stack cost) and answers MongoDB's own
  `Overflow` error. **Check the crate, not its reputation**: an official, widely used decoder
  had the same hole as the hand-written ones.

- **Bound the *declared* size, not the remainder.** NATS's `HPUB` limit was applied to
  `total − header`, leaving `header` unbounded — and `header == total` passes every check with
  a zero-length body. `HPUB x 4000000000 4000000000` is thirty bytes on the wire and buffers
  toward 4 GB, and `usize::MAX` then overflowed the offset arithmetic. Check the number the
  peer gave you before you do arithmetic on it. Related: `Cargo.toml` has no `[profile.dev]`,
  so `overflow-checks` is **on** in debug and test builds and **off** in release — STOMP's
  `content-length: 18446744073709551615` panicked in every test build and wrapped harmlessly in
  the shipped one, which is exactly backwards from where you want to find it.

- **Check whether the client a rating depends on is compiled where the gate runs** — but check
  it properly, because this entry got its own example wrong for months. It said `lapin` is an
  `optional = true` **dev**-dependency and that AMQP's Beta therefore rested on a test the gate
  never executes. `lapin` is a plain optional entry in `[dependencies]`, turned on by the `amqp`
  feature, so it compiles wherever that feature does — the same shape as `etcd-client`. There is
  no lapin-specific hole.

  The distinction is real and worth keeping: an `optional = true` entry under
  `[dev-dependencies]` is never built by a job that does not enable it, which is the same hole
  as a skip-when-missing gate wearing different clothes. Verify which section the entry is in
  before claiming it:

  ```bash
  awk '/^\[/{sec=$0} /^<crate> ?=/{print sec": "$0}' Cargo.toml
  ```

  What *is* true of AMQP is true of 110 other protocols: the blocking `test` job compiles six
  features, so it runs none of their evidence. `registry-audit` compiles everything and is
  `continue-on-error`, so a green PR is not evidence that any of it passed. That is the general
  gap, not a property of lapin.

- **`nfsserve` 0.10.2 has a pre-auth remote DoS, and the fix is a guard on our side of the
  socket.** It resizes buffers from a wire-supplied 31/32-bit length with no cap, so a
  **~40-byte unauthenticated** `MOUNTPROC3_MNT` carrying a `dirpath` length of `0xFFFFFFFF`
  asks for gigabytes. A second path amplifies: `path_to_id` calls `lookup()` per `/`-separated
  component and every `lookup` here is one LLM round-trip, so two bytes on the wire buy a model
  call.

  `NFSTcpListener` owns its own `accept()` loop, so **there is no seam inside the crate** —
  which is what made this look unfixable. NetGet now binds the public listener itself and runs
  `nfsserve` on a loopback-only ephemeral port behind `src/server/nfs/guard.rs`, which decides
  every RPC record from the length the peer *announced*, before anything is read or allocated
  for it (2 MiB per fragment and per record, 64 fragments, 256 connections). `path_to_id` is
  overridden with a 32-component bound. A refusal is answered in NFS's own vocabulary — an
  accepted reply with `accept_stat = GARBAGE_ARGS` carrying the call's own xid — and logged
  `decision=fail_closed_*`. **Not** a `WireFailure` string: the record layer has no free-text
  field, so there is nothing to put one in.

  Still exposed: the XDR decoder inside an admitted record is bounded rather than validated,
  the loopback backend is reachable by other local processes, and there is no per-connection
  idle timeout. `tests/server/nfs/dos_guard_test.rs` covers both paths from the wire, and both
  bounds were verified by removing them.

- **`xmlrpc` 0.15 can be stack-overflowed by the reply to the first call, and `Transport` is
  the seam that fixes it.** `Parser::parse_value` → `parse_value_inner` → `parse_value`
  recurses with no depth counter and the crate caps neither body nor nesting, so ~20 bytes per
  `<value><array><data>` level buys a `SIGSEGV` against the guard page — not a panic, so
  `spawn_blocking` cannot contain it and the whole process dies.

  `src/client/xmlrpc/AGENTS.md` recorded this as unfixable because "`Request::call` with a
  custom `Transport` takes a `reqwest` 0.11 `RequestBuilder`". **That is a provided impl of the
  trait, not its signature.** `xmlrpc::Transport` is public with an associated `Stream: Read`
  and anything may implement it. Reading a provided impl as the interface is the mistake worth
  remembering — it held a one-line-away fix shut for months. NetGet now serialises with
  `write_as_xml`, fetches with its own reqwest 0.12 client, refuses at 8 MiB while streaming,
  measures element depth with quick-xml and refuses past 256, then hands the crate a
  `PrefetchedTransport` over the screened bytes so parsing and fault handling are unchanged.

  The body cap alone is **not** sufficient and it is worth knowing why: at ~20 bytes a level
  even 1 MiB buys ~50 000 frames. Depth is the guard; size is the backstop.
  `tests/client/xmlrpc/response_guard_test.rs` was verified by removing the depth bound, at
  which point the test binary aborts with `fatal runtime error: stack overflow` rather than
  failing — the same way the AMQP field-table bound was checked. Its second half asserts a
  three-level reply still parses, because a guard that refused everything would pass the first
  assertion.

- **Fail-open defaults are the most dangerous pattern in this codebase.** When the LLM returns
  nothing usable, a protocol must not fall through to a permissive default. OAuth2 did: no
  action meant a hardcoded authorization code, a hardcoded access token, and introspection
  answering `{"active": true}` for *every* bearer token — so an LLM outage silently issued
  credentials, and a model's explicit denial was indistinguishable from silence and became an
  approval. Its own CLAUDE.md documented this as a feature ("ensures the server always responds
  correctly"). Default to refusal, and make the model's rejection path structurally distinct
  from its no-answer path. `radius` is the worked example of the shape to copy: nothing in its
  `actions.rs` can synthesise an Access-Accept, accept and reject share no code path, and a
  no-answer logs `decision=fail_closed_*` while a model denial logs `decision=model_reject` —
  distinguishable in the log *and* on the wire. Its regression test asserts the fail-closed
  packet is also correctly *signed*, because a denial the client discards as corrupt is just a
  timeout.
- **One client's leniency is one protocol's bug, and the tests will all be green.** Two gRPC
  servers here — `etcd` and `grpc` — put `grpc-status` in the *initial* HEADERS and then sent a
  DATA frame, so the stream ended with no trailing HEADERS at all. That is not gRPC. tonic
  tolerates it; grpc-go refuses outright, so `etcdctl` and `grpcurl` could not complete a single
  successful call. Both are fixed (a two-frame body: the message, then `Frame::trailers`), and
  both keep the Trailers-Only shape for errors, where the status legitimately rides in the
  initial headers.

  Three things are worth carrying to the next protocol:
  - **The failure path can be accidentally correct while the success path is broken.** An error
    has an empty body, which makes it Trailers-Only by construction — so every `llm_failure` and
    `unanswered_request` test passed, and those were the ones doing the asserting.
  - **A test can hold a defect in place by asserting it.** `test_grpc_unary_rpc_basic` checked
    `grpc-status: 0` *on the initial headers*. It was reqwest, which exposes no trailers API, so
    it could not have checked the right place even if someone had wanted to.
  - **"We have no second client to test against" is a task, not a conclusion.** Both files said
    grpc-go "may not" accept this and that nobody should touch it without a Go client. Installing
    one took a minute and answered it.
- **A tokio blocking API called from async context, with the panic swallowed by `tokio::spawn`.**
  Found three times: `block_on` inside `UsbInterfaceHandler::handle_urb` (usb-msc, usb-fido2) and
  `tokio::sync::Mutex::blocking_lock()` in SMB's connection task. The failure mode is identical
  and nasty — the task panics, `tokio::spawn` swallows it, the server stays `Running`, the log
  shows the operation *succeeding*, and the peer hangs. In SMB every SESSION_SETUP killed its own
  connection the moment the LLM approved the login. If a synchronous callback needs an async
  result, restructure so the sync side parks the request and an async task feeds the answer back
  (usb-fido2 does this over CTAPHID `KEEPALIVE`); do not bridge with `block_on`.
- Byte-index string truncation (`&s[..N]` guarded only by `s.len() > N`) panicked on multi-byte
  UTF-8 at the cut point, on LLM output and event descriptions. Fixed in `b9aa1058` —
  `src/utils/truncate.rs` has char-boundary helpers; use `truncate_for_log` rather than slicing.
  `src/protocol/log_template.rs` was the important one (`c1515188`): being shared
  infrastructure, it defeated protocols' own local fixes.
- **Resolved (August 2026), recorded because the claim outlived the code.** This file used to
  say `git` and `mercurial` "call `generate_with_retry` directly, bypassing the rate limiter,
  the retry/repair loop, and event-handler dispatch". They do not, and a `grep -rn
  generate_with_retry src/` now finds callers only inside `src/llm/` itself: the `git` *client*
  goes through `call_llm_for_client` (budget, limiter and client `event_handlers` all apply),
  and `src/server/git/mod.rs` and `src/server/mercurial/mod.rs` both use
  `action_helper::call_llm`. Re-run that grep before trusting any similar claim here.
- On LLM failure a protocol must not reset to Idle and write nothing, leaving the peer to hang
  until its own timeout. **Swept across all 135 server protocols in August 2026** (audit found
  64 defective: 54 silent, 4 leaking the error onto the wire, 6 mixed). 44 now answer with a
  `crate::utils::WireFailure` category; copy `http` (503 + `Retry-After` vs 500) or `tcp`
  (half-close, so the peer reads EOF) when you touch a new one. Re-derive rather than trusting
  this: grep `LLM error` in `src/server/*/mod.rs` and check whether the following ~18 lines
  write anything.

  **Some protocols are deliberately silent and must stay that way, and the list is not here.**
  Each declares it in `metadata()` with `.deliberately_silent()` and its reason beside the call;
  a protocol that answers declares `.answers_on_failure()`. `tests/failure_mode_declaration_test.rs`
  holds the list and requires **every connectionless server** to declare one or the other — on
  a datagram protocol a failure arm that writes nothing is silence by default, and fifteen servers
  sat there undeclared while the prose list here named `radius` and five BLE profiles, all of
  which answer (Access-Reject, ATT Unlikely Error). Derive it:
  `grep -rln 'deliberately_silent()' src/server`.
  The rule is that **a fabricated reply is worse than silence when every reply the protocol
  defines is a positive assertion.** `openvpn` is the case to remember: its only pre-TLS server
  message is `P_CONTROL_HARD_RESET_SERVER_V2`, and sending it *is* admitting the peer — so
  "fixing the silence" there would turn a backend outage into an authentication bypass. ARP
  would write a fabricated MAC into the requester's neighbour cache; OSPF/IGMP/RIP/BOOTP/DHCP
  have no error frame at all. Where the wire cannot carry the distinction, the **log** must:
  tag `decision=model_reject` / `model_silent` / `fail_closed_llm_error` as `radius` does.
- **A static handler with an empty `actions` array DOES suppress the LLM call — but until
  September 2026 nothing in this repository had shown that, including the test this section
  cited.** The claim is now measured; the story of how it was not is the more useful half.

  The question began as an unexplained observation — seen in
  `tests/server/xmpp/peer_inject_test.rs` under full-suite load, where a probe on the `call_llm`
  error branch fired with `{"type":"static","actions":[]}` on a `*` pattern and stopped firing
  when only that JSON became `[{"type":"wait_for_more"}]`. Every candidate mechanism had been
  ruled out by inspection, correctly: there was no mechanism, because there was no defect.

  `tests/empty_static_handler_test.rs` answers it directly — point NetGet at a mock model that
  **records every call it receives**, and count, across cases differing only in the routing
  table:

  | routing | LLM calls |
  |---|---|
  | no handler at all (control) | non-zero |
  | `{"type":"static","actions":[]}` | **0** |
  | `{"type":"static","actions":[{"type":"wait_for_more"}]}` | **0** |

  **That control had never passed.** Not once, from the commit that introduced the file
  (`74dbb7f4`) until it was fixed. The cause had nothing to do with routing: the harness
  configures no model, so `ensure_model_selected` fell through to auto-selection — which was
  hardcoded to `http://localhost:11434` and ignored the endpoint the `AppState` was built with.
  Every event *did* reach the LLM path and then failed closed at
  `decision=fail_closed_llm_error … error=Failed to ensure model is selected`, before any
  request was issued to the mock. So the mock recorded zero in **all three** cases, for two
  unrelated reasons, and the two rows expecting zero passed. This section's own sentence —
  "the control is the part that makes the zeros mean anything; without it they are
  indistinguishable from a mock the server never tried to reach" — described the file's actual
  state and was read as a description of its design.

  Three things generalise, and the first is the one to carry everywhere:

  - **Put the control in the same test as the claim it licenses.** They were three
    `#[tokio::test]`s, so the run read `7 passed; 1 failed` with both headline claims green —
    exactly backwards. A dead control must take its dependants down with it, and that is
    cheaper to encode than to remember. The file is now one test: control first, as a
    precondition.
  - **A hardcoded endpoint fails silently at the configured one.** `ensure_model_selected` now
    takes the endpoint (`AppState::get_ollama_url()`), and errors name the host. The defect was
    real beyond the test: `--mcp`/`--mcp-http`, `netget --client … --connect …` and the
    dashboard each set the model only `if let Some(model) = configured_model`, so
    `--ollama-url http://gpu-box:11434` with no `--model` auto-selected against **localhost** —
    failing closed while a healthy backend sat idle, or picking a model name the remote endpoint
    does not have. Its signature is that the configured backend logs **no request at all**, so
    `tests/model_selection_endpoint_test.rs` counts `/api/tags` hits on a mock: only that
    distinguishes "asked the right host and it said no" from "asked a different host". Nine
    in-process tests already pinned a model to work around this; a workaround repeated nine
    times is a bug report.
  - **Servers and clients have separate dispatchers, so a server measurement says nothing about
    a client rule.** This section concluded that **`src/tui/modal/form.rs`'s zero-action
    `<proto>_connected` rule works** on the strength of the table above — but that table is
    `try_execute_event_handler` (server) and form.rs's rule is a *client* rule, answered by
    `try_execute_client_event_handler` with its own `Static` arm and its own caller
    (`client/llm_budget.rs::call_llm_for_client` vs `action_helper::call_llm`). Nothing makes
    the two agree. The rule **does** work — `the_dashboards_client_connect_rule_keeps_the_event_off_the_model`
    now measures the shipped routing on the client side, with its own control — but that was
    established by measuring it, not by the server table.

  Both assertions were verified by breaking the mechanism: making each dispatcher's `Static`
  arm return `FallbackToLlm` turns the relevant zero into a 1, and restoring the hardcoded
  endpoint reproduces the dead control and takes the suppression claims down with it. A zero
  nobody has tried to turn into a one is not evidence.

  The earlier advice to prefer `wait_for_more` over an empty list is unnecessary — though
  harmless, and `wait_for_more` still reads more clearly where the protocol declares it.
- **`ServerForm::create` substitutes a default instruction** (`"You are a {protocol} server.
  Handle requests appropriately."`) whenever `instruction` is `None` — see
  `src/cli/management.rs`. Any non-empty instruction makes `operator_wants_dynamic` true, so a
  test built with `..Default::default()` **does consult the model**, whatever its comments claim.
  Two `peer_inject` tests documented "Zero LLM calls" while doing the opposite, and passed only
  because the old fail-open swallowed the resulting error. Pass `instruction: Some(String::new())`
  when you want a genuinely model-free server.
- **Answering the peer is not a licence to tell it anything.** Fixing the silence above
  introduced the opposite defect across ~25 protocols at once: each interpolated the error into
  the reply, so a plain `telnet` session printed `[netget] cannot answer right now: ✗  LLM
  failed to generate valid response after retries.` — netget's own retry machinery, verbatim, on
  a stranger's terminal. Backend URLs, model names, file paths, serde and prost messages and
  `anyhow` context chains all reached the wire this way. It spread because each protocol was
  written by copying its neighbour.

  The rule is **the peer gets a category, the log gets the error**. `crate::utils::wire_failure`
  (`WireFailure::{Overloaded, Unavailable}`) classifies an error and returns `&'static str`
  — deliberately, because a helper returning `String` is one `format!` away from leaking again.
  Keep the two categories distinct: protocols map them onto different codes (503 vs 500, RESP
  `LOADING` vs `ERR`, MySQL 1205 vs 1105, gRPC `UNAVAILABLE` vs `INTERNAL`) so a client backs
  off rather than recording a permanent fault. `smtp` was the one protocol that already had
  this right — byte-literal replies, nothing interpolated. `tests/wire_failure_test.rs` fails
  the build if any of the leaked idioms reappear under `src/server/`.
- Related and now fixed, but worth knowing as the reference case: the rate limiter used to
  `try_acquire` for `RequestSource::Network` and bail on contention, so at the shipped default
  of `--llm-max-concurrent 1` any request overlapping an in-flight LLM call was **discarded** —
  two simultaneous `curl`s were enough — while the flag's help text promised "sequential
  processing". Network requests now wait for a permit, bounded by `--llm-queue-timeout`
  (default 120s) and `--llm-max-queued` (default 128), and both bounds fail with a typed
  `RateLimitError` that `crate::llm::is_overload_error` detects. It survived for so long
  because `tests/helpers/netget.rs` passes `--llm-max-concurrent 1000` to every E2E test, so
  the shipped value was exercised by no test at all; `tests/llm_concurrency_default_test.rs`
  now runs with the flag omitted entirely.
- **The rolling TUI's slash-command popup destroyed visible output; the TUI is gone.** The
  defect (a footer painted over the scroll region with no push-up, measured on the byte stream)
  lived in `sticky_footer.rs`, which was deleted with the `--legacy-tui` mode in September 2026.
  The dashboard renders whole frames into the alternate screen and never had it.
- **The 10-second idle sweep is for connectionless protocols only — declare it.**
  `AppState::cleanup_old_connections` (ticked by the TUI and the MCP loop) evicts any connection
  whose `last_activity` is older than 10s. It exists for UDP/raw/link-level servers, whose
  per-remote-address entries nothing ever closes. It used to run over **every** server, so any
  idle TCP-style connection — a telnet peer parked >10s for a human's manual answer, a BGP
  session between keepalives — was removed from state and drawn as `(closed)` while its socket
  was alive, and every later stat update and the real close targeted an entry that was gone.
  **The opposite error is worse, and TFTP had it.** Declaring `.connectionless()` on a UDP
  protocol that carries a *transfer* is actively harmful: a transfer is idle for the whole of
  an LLM call, so the sweep evicted live transfers out from under themselves. "UDP" is not the
  test — **"has no connection concept" is.** DNS, mDNS, SSDP and LLMNR answer one datagram and
  forget you; TFTP, DHCP-style leases and anything with a session do not. If a peer's next
  packet has to be understood in the light of its last one, it is not connectionless, whatever
  transport it rides on.

  It now runs only where `ProtocolMetadataV2::connectionless` is set (`.connectionless()` on the
  builder; the 22 UDP/raw servers declare it). A new connectionless protocol that forgets the
  flag leaks idle entries until its server stops — mild; the old default was the dangerous one.
  Connection-oriented servers should still call `update_connection_stats` on every read and
  write: it is what the rail's `↓/↑` counters and connection-scoped task prompts read.
- **Per-connection tasks are tracked now, and the reason it took a sweep is the useful part.**
  `stop_server` used to release the listening socket and leave every open connection running —
  still reading, still calling the model, still answering, on a server the operator had stopped.
  It *looked* stopped: port free, instance gone from state. `AppState::spawn_server_task` /
  `spawn_client_task` spawn and register in one call, and 145 sites across 113 server protocols and 2 clients were
  converted to them in September 2026. `tests/stop_server_stops_connections_test.rs` is the
  contract (asserted from the **peer's** side, which is the only vantage that distinguishes a
  live connection from an aborted one) and `tests/detached_task_drift_test.rs` is the ratchet.
  It reads **every `.rs` file** of each protocol directory in both trees, not only `mod.rs`: a
  `mod.rs`-only scan passed a probe spawn placed in `http2/h2_server.rs`, the same blind spot
  `tcp_server_bounds_ratchet_test.rs` had. Widening it found no existing site — every spawn
  outside a `mod.rs` is bound to a `let` and registered, aborted on exit, or held in
  `usb/guard.rs`'s `AbortOnDrop`. The shared `src/server/peer_support.rs` is outside the
  population; its one spawn (the injected-command task) ends when its channel closes, which
  `remove_server` and each protocol's close path cause by dropping the peer handle.

  **Every call must end `.await`.** An unawaited `spawn_server_task` constructs the future and
  never polls it, so the task never runs at all — and that compiles, because an unawaited future
  is a warning rather than an error. Two of the three sites in the original TCP conversion had
  this, and the existing suite stayed green because those tests did not depend on the task.
  Build with `-D unused_must_use`; the compiler is the only thing that finds it.

  What is still detached, and why: the per-connection **writer** tasks (`amqp`, `mqtt`,
  `websocket`, `webrtc`, `webrtc_signaling`, `bgp`) are `.await`ed on the exit path so they need
  a `JoinHandle`, and they already end when the registered reader is aborted and drops their
  channel; `bluetooth_ble`'s radio dispatcher is process-wide by design; and the USB/IP session
  tasks and `postgresql`'s pgwire task are awaited inside a `select!`, so they are children of a
  registered connection task that **aborting does not reach** — that gap is real and stated
  rather than quietly closed.
- `AppState` is one global `RwLock` over everything — a throughput ceiling, not a deadlock.
- **The root markdown clutter is gone** — the ~50 one-off session/status reports this entry used
  to warn about were deleted. Ten files remain and all are durable: `README.md`, `AGENTS.md`,
  `ARCHITECTURE.md`, `METADATA_EXAMPLES.md`, `CLIENT_PROTOCOL_FEASIBILITY.md`,
  `LICENSE_ANALYSIS.md`, `SYSTEM_DEPENDENCIES_macOS.md`, `TERMUX_INSTALL.md`,
  `PROTOCOL_MIGRATION_GUIDE.md`, `IMPROVEMENTS.md`, `PROTOCOL_ROADMAP.md` (Programmes 1 and 2,
  with the batch table and the rubric) and `PROTOCOL_QUALITY.md` (the plan after Programme 2 —
  a checkbox tracker of what is left, with measured starting points). **Do not add new
  status-report files** — that is what let the directory reach 63 in the first place. A tracker
  with checkboxes that outlives the session is not a status report; a narrative of what one
  session did is.

## Git

- Never `git stash`. Always merge with `--no-ff`. Never amend, rebase, or squash shared history.
- **Pushing to `origin` is pre-authorised in this repository — always push.** Do not stop to ask,
  and do not leave work sitting unpushed: an unpushed branch is invisible to CI, to cloud agents
  (which clone from GitHub, not from this machine), and to everyone else working here. This once
  reached **249 unpushed commits**, which silently made a scheduled cloud routine useless because
  the work it was sent to continue did not exist on the remote.
  Push after landing a logical change, i.e. at the same points "Commit as you go" describes:
  ```bash
  git push origin master
  ```
  The standing authorisation covers `master` and your own branches. It does **not** extend to
  force-pushing, deleting remote branches, or rewriting published history — those still need
  asking, because they destroy other people's work rather than publishing yours.
- Combine `git add` and `git commit` in one command chain.
- Commit as Matus Faro <matus@matus.io>, GPG-signed:
  ```bash
  git config user.name 'Matus Faro' && git config user.email 'matus@matus.io' && \
  git config commit.gpgsign true && git config user.signingkey matus@matus.io
  ```
- Conventional Commits, one logical change per commit. No co-author or bot attribution
  trailers of any kind.
- **Write the message to a file and use `git commit -F`, not `-m`.** The Bash tool runs zsh, so
  a backtick inside a `-m` string is command substitution: `` `checked` `` runs `checked`, the
  shell prints "command not found", **the commit still succeeds**, and the word is silently
  missing from the message. It happened once in September 2026 and is unfixable afterwards,
  because amending is forbidden here. Backticks are natural to reach for when naming a
  variable, which is exactly why this bites. A heredoc into a scratch file costs nothing:
  ```bash
  cat > /tmp/<your-task>-msg.txt <<'MSG'
  fix(x): ...
  MSG
  git add -- <paths> && git commit -S -F /tmp/<your-task>-msg.txt -- <paths>
  ```
  Note the quoted `<<'MSG'` delimiter — unquoted, the heredoc expands backticks too.
- **Commit as you go.** Land each logical change as soon as it is verified, rather than
  accumulating a large uncommitted tree and committing at the end. Other agents are editing this
  repo continuously: a big working tree is a merge hazard, it is what broad `git add` sweeps pick
  up, and an interrupted session loses all of it. Verify, commit, continue.
- **Verify against a clean baseline, not against "does it pass".** The suite has pre-existing
  failures, so a red run proves nothing on its own. Run the same suite at unmodified `HEAD` in a
  throwaway worktree and **diff the two failure sets** — only the difference is yours. This is
  what separates a real regression from the repo's existing red.
  **Cross-check any suspect failure by re-running it in isolation before calling it a
  regression.**

  **But do not stop there, because "load-flaky" is where real bugs hide.** Both suites are
  now green at `--test-threads=100` — client 299/0, server 799/0, several consecutive runs
  each — and every test that used to be on a list here of things that "only fail under load"
  is on it because of a defect that was found and fixed, not because the list was wrong to
  notice them. Passing in isolation told us the *deadline* was wrong; it did not tell us the
  code was fine, and three times it was not:

  - The four `doh` **client** tests failed every run at 100 threads and passed at 30. Not
    timing: raising the wait from 10s to 30s changed nothing. `Client::builder().build()`
    loads the platform root store, which on macOS reads the keychain through
    Security.framework — synchronously, serialised across processes. On the async runtime it
    parked a tokio worker long enough to stall the client's whole runtime. The tell was a
    configured 10s request timeout that never fired: a timeout that *cannot* fire means the
    future was never created.
  - `ServerForm::create` failing with "Address already in use" for `port: 0` — in zookeeper
    one run, cassandra the next. Different protocol each time, which is what gave it away:
    the shared startup path resolved port 0 by binding a probe listener and dropping it
    before the protocol bound for real.
  - Whole e2e suites waited with a fixed `sleep` and then verified. One second is enough
    alone and not when a hundred run together. `wait_for_any` and `wait_for_mocks` on the
    harnesses wait for the condition instead; every e2e suite now calls one before asserting.

  A protocol whose e2e test binds sockets and waits on a mocked model *is* timing-sensitive by
  construction, so a lone failure in a 100-thread run is still unproven until re-run. Re-run
  it — and if it reproduces at all, find the defect rather than labelling it.
