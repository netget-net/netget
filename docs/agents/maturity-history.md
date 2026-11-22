# Server maturity: every promotion and demotion, and what each taught

> Moved out of the root `AGENTS.md` on 21 November 2026, which now holds only the rules and
> a pointer here. The text is as it was written, so "this file" and "this section" mean
> the root file as it then was; dated claims are dated for a reason — re-derive before
> trusting one.

The bars themselves are checklists in the root `AGENTS.md` ("Maturity bars"). This file is
why each clause is there. Client ratings are in `client-maturity-history.md`.

Maturity lives in each protocol's `metadata()` (`ProtocolMetadataV2`,
`src/protocol/metadata.rs`). **Do not read this file as the list. Generate it:**

```bash
python3 scripts/beta_evidence_table.py            # every Beta, with its peer
python3 scripts/beta_evidence_table.py --all      # every protocol
python3 scripts/beta_evidence_table.py --check    # counts; exit 1 on a defective Beta
```

Re-derived 21 November 2026: 11 Stable, 64 Beta, 211 Experimental servers.

Contents: Stable (who holds it, the coap fuzz target, the six conditions, what the passes
found, the two-client Betas, the three demotions) · Beta (the October and November
promotions, generating the list, the near-misses, `ssh`, `mysql`, `s3`) · Experimental and
Incomplete.

## Stable

**Stable** — **eleven as of 13 November 2026: `coap`, `dns`, `modbus`, `smb`, `redis`, `dot`,
`doh`, `etcd`, `postgresql`, `websocket` and `mqtt`.** Before
16 September 2026 there were none, and three protocols had held the rating and lost it, each
for the same reason: nobody had said what it required, so "Stable" meant whoever set it felt
good about the code. The bar below is what replaced that, and these eleven are the ones
measured against it rather than against a feeling. Each carries its own justification in
`metadata()` — read `e2e_testing` and `notes` there, and the "Maturity: the six conditions"
section at the foot of each `src/server/<p>/CLAUDE.md`, before quoting any of the ratings:
each says in as many words that the rating covers the evidence for the surface the server
*implements*, which in every case is a subset of the specification.

### Condition 3 was false for `coap`: a fuzz target that did not compile

**One condition was false for `coap` when that pass began, and how it broke generalises.**
`fuzz/fuzz_targets/coap_message.rs` had not compiled since `0996d00f` made
`CoapMessage::encode` fallible — hours after the target was written — so "a fuzz target
exists and has run clean" was a claim about a file rather than an execution. **No CI job
builds `fuzz/` at all**; it is deliberately its own workspace (nightly toolchain, libFuzzer
runtime), so `cargo check` at the repository root never sees it. Condition 3 is therefore the
one most likely to be silently false for any protocol. Rebuild before believing it:

```bash
cp Cargo.lock fuzz/Cargo.lock      # as CI does: unseeded, fuzz/ resolves fresh and breaks
cd fuzz && PATH=~/.rustup/toolchains/nightly-2025-12-04-aarch64-apple-darwin/bin:$PATH \
  CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=/path/to/cc-wrapper \
  cargo fuzz build -s none <target>
```

(`cargo +nightly fuzz` fails on this machine: asdf's shims precede `~/.cargo/bin` on `PATH`,
so `cargo` is not the rustup proxy and `+toolchain` is read as a subcommand name. `rustup run
<toolchain> cargo …` is not enough either, as measured in October 2026: Homebrew's `cargo`
and `rustc` still come first on `PATH`, so the toolchain's `bin` has to be prepended. Without a
seeded lockfile `libc` resolves to a release that dropped constants `nix` 0.8.1 uses. And
macOS `ld` refuses the `crc-fast` cdylib, whose instrumented objects reference sancov hooks
only the fuzz binary defines; the wrapper is `exec cc -Wl,-undefined,dynamic_lookup "$@"`.
`src/server/redis/AGENTS.md` has the details.)

### The six conditions

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

### The first candidates, and what those passes turned up

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
- **A byte cap bounds memory, not work.** `redis` (31 October 2026) capped a frame at 64 MiB
  and its guard re-walked the unfinished frame from the start on every 4 KiB read, so one
  64 MiB line cost ~16 000 walks — minutes of a worker per unauthenticated connection, all
  inside the cap. A test of a size bound should time the walk to it, not only assert the
  refusal at the end. The same pass found `$N` capped at the buffer size, so a declared length
  just under it was accepted and could never complete: put the boundary where a frame can
  still fit, and test both sides of it.

### The two-client Betas: `etcd`, `postgresql`, `websocket`, `doh`, `dot`, `mqtt`, `kafka`

**Of the two-client Betas, only `mongodb` still fails condition 2 or 3** (re-derived
1 November 2026): it has a fuzz target (`fuzz_targets/bson_document.rs`) and no pcap-oracle
test. Seven that were in this list held conditions 1, 2, 3 and 6 that day, which left each
of them at most conditions 4 and 5 — a test per declared bound, and both `AGENTS.md` files
re-verified — from Stable; `dot`, `doh`, `etcd`, `postgresql`, `websocket`, `mqtt` and
`kafka` have since been measured (below):

- `etcd`, `postgresql` and `websocket` gained both. Their real-client tests run through
  `tests/helpers/recording_relay.rs` and the oracle reads what crossed. The targets are
  `etcd_request` (prost behind `etcd::unary_message`; `TxnRequest` recurses, so a 20 000-level
  bomb), `pgwire_frontend` (upstream pgwire's frontend decoder, 0.42.3 or later — the first
  release that does not panic on a short message — at the version and features the root
  manifest builds, with NetGet's frontend screen in front of it) and
  `websocket_session` (head parser, `deflate::negotiate`, `DeflateStream` under tungstenite).
  **`etcd` and `postgresql` went Stable on 13 November 2026**, and condition 1 was again true
  of a sample. Each "second client" shared the server's own codec: `etcd-client` is tonic
  over prost — the server's h2 and prost at both ends — and tokio-postgres decodes binary
  cells with `postgres-types`, the crate pgwire encodes them with; and neither etcd client
  issued Txn or Compact, and no PostgreSQL client bound a parameter. Python grpcio (C-core,
  upb) and psycopg 3 over libpq are the second clients now
  (`tests/server/etcd/grpcio_client_test.rs`, `tests/server/postgresql/psycopg_client_test.rs`).
  They found what the shared codecs had agreed on: the PostgreSQL model **never saw a bound
  parameter** (the statement declared none, so tokio-postgres would not bind, and psycopg's
  values were dropped), a binary `date` went out as text, and a cell that did not fit its
  column was sent as `0` or `false`; the etcd handler decided a Txn seeing only the *counts*
  of its compares and operations, the reply carried no per-operation results, and Range's
  `limit`/`keys_only`/`count_only` were ignored. Condition 4 found two bounds that bounded
  nothing in total: etcd's 1.5 MiB per request with 200 streams per connection (now a 48 MiB
  server-wide budget) and pgwire's 1 GB per unauthenticated message (now 1 MiB, screened by
  `src/server/postgresql/guard.rs` in front of pgwire, which has no seam of its own; the same
  screen answers a malformed message `FATAL 08P01`, where pgwire closes in silence or serves
  a Query with no NUL as an empty query) — and
  an etcd request whose body stopped arriving held its connection busy, so the idle bound
  never fired. **A second client that shares the server's codec is a sample of one**: count
  the libraries at both ends, not the binaries.
  **`websocket` went Stable on 13 November 2026.** Condition 1 had been true of a sample:
  the third-party clients covered a greeting, one echo and deflate's data messages, and Ping,
  both directions of the closing handshake, subprotocols and refusal were asserted only by a
  hand-written client; Python websockets, Node ws and websocat now drive every verb
  (`tests/server/websocket/real_client_test.rs`). Condition 4 found five defects: an
  **inbound queue with no bound** (a peer outrunning the model was read into memory without
  limit; the read loop now stops at 1024 messages / 8 MiB), `wait_for_websocket_data`
  joining without limit (and losing a held message), a compressed frame not held to
  `max_frame_size`, no close frame for a frame or message tungstenite refused (now
  1009/1002/1007), and a request head checked only when a read did not complete it. **A
  removal check is only as good as the test's reach**: the queue bound's first tests passed
  with the bound removed, because their `*` → `manual` rule also parked
  `websocket_connection_opened`, which is answered before the frame loop reads anything — the
  handler they meant to keep busy was never reached.
- `doh` and `dot` gained the oracle, **decrypted**: kdig writes `SSLKEYLOGFILE`, the oracle
  hands it to tshark (`PcapOracle::tls_keylog`) and `require_named("dns")` fails unless the
  DNS inside the TLS was dissected, so a TLS oracle cannot pass on the record layer alone.
  Their fuzz target was already `fuzz_targets/dns_message.rs` (`hickory_proto`'s
  `Message::from_vec`, with a `compression_pointer_loop`). **Both went Stable on 8 November
  2026**, and the pass found condition 1 had been true of one client: the "second peer" in
  each was rustls or reqwest with hickory — the server's own codec — doing the DNS, and kdig
  drove A records only. `dig +tls` / `+https` (BIND 9.20) is the second client now, and both
  read every record type. Conditions 4 and 5 found the same defect in both: each server had
  its own copy of the loop that turns the model's answer into a reply, and both broke the
  promises their failure sections made — DoT wrote nothing for an answer with no sendable
  action, DoH answered it `500` — while the DNS server, which they delegate their actions to,
  had fixed all of it. They answer through `dns::StreamQuery` now, the DNS server's own
  `Reply::resolve`/`finish`. **Delegating the vocabulary is not delegating the behaviour**:
  check what a delegating protocol does *after* the model answers. The same pass found that
  hickory's encoder does not fail at 65535 octets — it truncates, sets TC and returns `Ok` —
  so the DNS server's own TCP path sent an oversize answer as a NOERROR carrying half an
  RRset; it is SERVFAIL now. And BIND's dig writes no TLS key log (`SSLKEYLOGFILE` feeds
  `named`'s logging), so only kdig's sessions reach the oracle. `doq` (DNS over QUIC) had the
  same delegated shape and the same kind of private loop — an answer with nothing sendable
  reset the stream, several messages were merged into one, an answer past 65535 octets went
  out as a NOERROR with TC, and types other than A/AAAA/MX/TXT/CNAME/ANY were answered NOTIMP
  without asking the model, which held `send_dns_records` — and answers through
  `StreamQuery` too (8 November 2026); it is still Experimental (`src/server/doq/AGENTS.md`).
- `mqtt` and `kafka` had the oracle and gained `mqtt_packet` and `kafka_request`. Writing the
  Kafka one found that `kafka-protocol`'s gzip, zstd and lz4 decompressors have no output
  bound — a 64 KiB Produce batch inflated to 64 MiB — now `MAX_INFLATED_PRODUCE_BYTES`.
  **`mqtt` went Stable on 13 November 2026.** No 3.1.1 client had sent a QoS 1 or 2
  PUBLISH, an UNSUBSCRIBE or a PINGREQ; driving them with Mosquitto and rumqttc found the
  broker **ignoring the client's PUBREC** for its own QoS 2 PUBLISH, so a QoS 2 subscriber
  never received anything sent to it at QoS 2. Conditions 4 and 5 found `max_packet_size`
  counting a different number from the one the v5 CONNACK advertises, a second connection
  with a connected client id **not closing the first** (and a refused CONNECT erasing the
  first's routing entry), and the codec accepting a dozen things the specification says a
  broker MUST refuse (`tests/server/mqtt/protocol_rules_test.rs`).
  **`kafka` stays Beta** (13 November 2026): no third-party client sends OffsetCommit, which
  the broker implements — kcat, the Java client and franz-go all look up a coordinator
  first. The same pass found the `kafka-protocol` legacy-message recursion the fork's notes
  called "still open" reachable from one unauthenticated Produce v0–2 request — a stack
  overflow that killed the process — and the fuzz target's header claiming Kafka requests do
  not nest; compressed legacy wrappers are refused before the decoder now, and the corpus
  carries the 20 000-level bomb.

`grpc` was in this list as a two-client Beta and is no longer one: its expanded streaming
scope is Experimental. It gained the oracle (grpcurl's success and error calls) and
`grpc_message` all the same. (`redis` left the list when `fuzz_targets/resp_frame.rs` landed
in September 2026, and went Stable on 31 October 2026.) Derive this rather than trusting it — and note that
fuzz targets are named after the *decoder*, not the protocol, so read each target's `use`
lines rather than grepping its name (`dns_message.rs` covers three protocols, none of them
in its file name but `dns`):

```bash
grep -rln pcap_oracle tests/server/<p>/ ; grep -ln "<p>\|<decoder crate>" fuzz/fuzz_targets/*.rs
```

### Single-client candidates, and the three demotions

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

## Beta

**Beta** — human-reviewed, works against real clients (64 servers as of 13 November 2026, after
`etcd`, `postgresql`, `websocket` and `mqtt` went to Stable; 68 on 8 November 2026, after `smtp`, `pop3`, `tftp`, `ftp` and `doq` went to Beta and `dot` and `doh` to Stable, and 65 on 6 November after `redis` went to Stable and `profinet` and `mercurial` to Beta;
re-derive, the count drifts every pass — `python3 scripts/beta_evidence_table.py --check`
prints it). The 31 October review promoted six whose evidence was already there and already
green in their protocol-pairs.yml jobs: `kerberos` (MIT and Heimdal kinit/kvno/kgetcred),
`afp` (netatalk's afparg and Nmap's AFP library), `capnp_rpc` (pycapnp and go-capnp),
`iscsi` (libiscsi and the Linux kernel initiator), `srt` (libsrt's srt-live-transmit) and
`rsync` (the stock rsync client). What held most of them back was a note saying the pair job
"had not run in CI", written when the protocol landed and never revisited after the job
passed — check `gh run list --workflow protocol-pairs.yml` before believing one. `db2` was
checked and **not** promoted: Derby's JDBC client and IBM's CLI driver both pass, but the
server returns no result set, so a SELECT fails — the `openvpn` case below. **`profinet` is
Beta on evidence that exists only in CI**: profinet-py and pnio_dcp pass its real-peer test
in the `profinet` pair job (job 116898932856), but that test needs Linux and CAP_NET_RAW, so
it cannot run on macOS and no local check reaches the raw transport — re-run the pair job
after touching it. **`mercurial` is Beta for clone and pull**: the real `hg` 7.2.4 clones,
`hg verify`s (which recomputes every revlog node), reads back and pulls from it in
`tests/server/mercurial/real_client_test.rs`, which fails rather than skips without hg. Push,
bundle2, bookmarks and tags are not implemented, so the rating claims none of them. Running
the suites
also showed **a peer's new release can quietly stop testing anything**: Nmap 7.99 changed a
guest AFP login to DHCAST128, so `afp-ls` printed nothing, and the script the test also
named, `afp-showmount`, had never run at all on an ephemeral port.

### `smtp`, `pop3`, `tftp` and `ftp` (8–13 November 2026)

**`smtp`, `pop3` and `tftp` went to Beta on 8 November 2026, each on two clients already on
every machine** — python3's stdlib `smtplib`/`poplib` and curl for the mail protocols, curl
and the system `tftp(1)` for TFTP (`tests/server/<p>/real_client_test.rs`; each header lists
the verbs each client drives). None had a real client before. For SMTP and POP3 the clients
found the defects; TFTP's clients passed on a loopback with a fast mock, and its defects
were in what happens when a packet is late, repeated or from elsewhere, which
`tests/server/tftp/retransmit_test.rs` provokes from raw sockets. SMTP raised one model call per message line, judged the message on an
event carrying only `"."`, and `trim()`med each line before comparing it with `"."`, so a
body line `" ."` ended the message and the rest was read as commands; it now reads the
message itself (only `<CRLF>.<CRLF>` ends it, dots unstuffed, `SIZE` advertised and
enforced) and raises one event. POP3 counted the transparency dots in `RETR`'s octet count,
disagreeing with its own `LIST`, and ended `send_pop3_message` lines with a bare CR. TFTP
sent each DATA block once and died on any stray datagram, could not encode netascii, started
a second transfer for every retransmitted RRQ, bound its transfer sockets to `0.0.0.0`
whatever address it was given, and made the model write files as hex a block per call; it
now retransmits, serves a whole text file from one answer (`send_tftp_file`) and dedupes
requests. **The lesson from the mail protocols: a protocol's own raw-socket suite is written by
someone who already knows where the message ends; a real client is not. The lesson from
TFTP: a real client on loopback never loses a packet, so a lockstep protocol's evidence
also needs a test that does.**

**`ftp` followed the same day, once it had a data connection to be judged on.** It had none
(no `PASV`, `EPSV`, `PORT` or `EPRT`; `TYPE` was a reply the model made up and changed
nothing; listings and files went out on the control connection), so a real client could log
in and do nothing else. The server now answers the setup verbs and `TYPE`/`MODE`/`STRU`
itself, binds passive listeners on the configured host only, refuses a `PORT`/`EPRT` naming
any host but the client (the bounce attack), and writes the `150` … `226`/`425`/`426`
sequence around the handler's listing or file; an upload reaches the handler whole, bounded
by `max_upload_bytes`. python3's stdlib `ftplib` and curl drive it through every listing
verb, both types in both directions and all four channel kinds
(`tests/server/ftp/real_client_test.rs`), and each data-connection bound is tested from both
sides. The same pass made an unanswered FTP command `451` instead of silence, and fixed the
FTP **client** ending a command with a bare CR. **It also found the evidence ratchet matching
filters as substrings**: `tests/real_client_evidence_is_run_test.rs` accepted
`tftp::real_client_test` in the CI loop as naming `ftp::real_client_test`, so FTP's evidence
would have read as run while CI ran only TFTP's. Filters are matched whole now, and FTP's is
`server::ftp::real_client_test`, because the bare form is a substring of TFTP's in
`cargo test`'s filter too.

**`ftp` gained binary files, `REST`, `STOU`, `ABOR` and explicit FTPS on 13 November 2026**,
each driven by both clients where the client has the verb. `send_ftp_data` takes
`encoding: "utf8"|"hex"` and a binary upload reaches the handler as `upload_hex`, bounded by
`max_hex_upload_bytes`; `REST` restarts `RETR` and `STOR` in stream mode (`554` past the end);
`STOU` names the file in `150 FILE: <name>`; `AUTH TLS`, `PBSZ` and `PROT P` put the control
and every data connection on rustls, with `cert_path`/`key_path` or a generated certificate,
and ftplib's `FTP_TLS` and curl `--ssl-reqd` each verify it. **`ABOR` needed the control
connection to be readable during a transfer, and two things stood in the way.** The line
reader was not cancel-safe (a `BufReader` plus a local accumulator), so racing it against the
transfer could lose half a line; it now keeps unreturned bytes in its own buffer
(`src/server/ftp/control.rs`). And python's `ftplib.abort()` sends `ABOR\r\n` as TCP urgent
data, which makes the `\n` the urgent byte: without `SO_OOBINLINE` on the control socket the
kernel removes it and the line never ends, and even with it a read stops at the urgent mark
and tokio reads the short read as "drained", so the `\n` sits in the kernel until the client's
next command. The reader takes `ABOR\r` alone as a complete line. The same is true of any relay in between, which is
why ftplib's `ABOR` test connects directly rather than through the recording relay.

### Generating the list, and the August–September promotions

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

### Near-misses: what looks like evidence and is not

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

### `ssh`, `radius`, `rss`, `mqtt`, `dhcp`: ratings that were wrong, and why

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

### `mysql` and `s3`: one client agreeing with one bug; evidence that covers every verb

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

## Experimental

**Experimental** — LLM-authored or newly implemented, not fully reviewed. The overwhelming
majority (107 of the 158 `src/server/*/actions.rs` the script below walks, re-derived
16 September 2026). Note the script
reports one `NONE`: `src/server/http_common/actions.rs`, which is a shared response helper
with no `impl Protocol` and no registry entry, so it declares no state correctly.

## Incomplete

**Incomplete** — hidden from the LLM entirely (`is_available_to_llm()` returns false). **None
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
