# Known systemic issues

> Moved out of the root `AGENTS.md` on 21 November 2026, which now holds only the rules and
> a pointer here. The text is as it was written, so "this file" and "this section" mean
> the root file as it then was; dated claims are dated for a reason — re-derive before
> trusting one.

Read before assuming a subsystem is sound:

1. Clients that ask the model what to do and throw the answer away
2. A literal IP still goes through the system resolver
3. More test threads do not fix a starved runtime
4. The first `reqwest::Client` in a process is expensive: the system-proxy probe
5. A client that loses its target must fail, never fall back to the real service
6. A startup parameter is printed, so a secret in one is a secret in the log
7. A recursive parser without a depth bound kills the whole process
8. Bound the declared size, not the remainder
9. Is the client a rating depends on compiled where the gate runs?
10. `nfsserve`: a pre-auth DoS, and the guard on our side of the socket
11. `xmlrpc`: a reply that overflows the stack, and the `Transport` seam
12. Fail-open defaults
13. One client's leniency is one protocol's bug (gRPC trailers)
14. A tokio blocking API in async context, the panic swallowed by `tokio::spawn`
15. Byte-index string truncation
16. `generate_with_retry` called directly (resolved)
17. On LLM failure, write something — and the protocols that must stay silent
18. An empty static handler does suppress the model call; the control that never passed
19. `ServerForm::create` substitutes a default instruction
20. Answering the peer is not a licence to tell it anything (`WireFailure`)
21. The rate limiter used to discard overlapping network requests
22. The rolling TUI's popup defect (the TUI is gone)
23. The 10-second idle sweep is for connectionless protocols only
24. Per-connection tasks are tracked: what `stop_server` must end
25. `AppState` lock contention

The order is the order they were written in; several refer to the one above or below.

## 1. Clients that ask the model what to do and throw the answer away

**Clients that ask the model what to do and then throw the answer away.** The single most
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

## 2. A literal IP still goes through the system resolver

**A literal IP still goes through the system resolver, and it can block for seconds.**
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

## 3. More test threads do not fix a starved runtime

**More test threads is not the fix for a starved runtime here.** `--test-threads=100` already
oversubscribes a 12-core box; giving one test `flavor = "multi_thread", worker_threads = 4`
made the same failure go from 2/6 to **7/8**. Measure before adding workers.

## 4. The first `reqwest::Client` in a process is expensive: the system-proxy probe

**The FIRST `reqwest::Client` in a process is expensive, and this entry named the wrong
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

## 5. A client that loses its target must fail, never fall back to the real service

**A client that loses its target must fail, never fall back to the real service.** The
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

## 6. A startup parameter is printed, so a secret in one is a secret in the log

**A startup parameter is printed wherever the instance is described, so a secret in one is a
secret in the log.** The `open_client` summary and the executor's DEBUG action line both
printed startup parameters verbatim — RADIUS shared secrets, MQTT and LDAP passwords among
them — until September 2026; `src/utils/redact.rs` now masks credential-named keys at both.
Name a new secret-bearing parameter so the redactor recognises it, and assert in a test that
the secret appears in no event and nothing NetGet printed, as the RADIUS client's does. A
secret the model itself put in an `open_client` action is still in the model's own output,
which the LLM layer logs at DEBUG (a preview) and TRACE (in full).

## 7. A recursive parser without a depth bound kills the whole process

**A recursive parser without a depth bound kills the whole process, and `tokio::spawn`
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

**DNS was the ninth (October 2026), and the recursion was not on nesting at all.**
`hickory-proto` 0.24 follows a *name-compression pointer* by recursing, so a chain of pointers
each aiming two bytes back — hidden in a NULL record's RDATA — is a frame per two bytes: a
debug build dies at 1 702 hops, 3.4 KB in one UDP datagram, in five servers at once (release
frames are small enough that the longest chain the format allows still fits a 2 MiB worker).
`src/utils/dns_screen.rs` bounds the chain before every decode. NetGet is on `hickory-proto`
0.26.3 since November 2026, which follows pointers in a loop (upstream's answer to the
advisory was that 0.25 is unsupported), so the screen is belt and braces for the stack — and
still the only bound on *work*, because every name entering a chain walks all of it: a 44 KB
DNS-over-TCP message costs 0.26.3 2.7 s of a debug worker without it. **Anything a decoder
*follows* — a pointer, an offset, a reference — is depth too**, whether or not the format
looks nested, and a decoder that stopped recursing can still be made to walk.
(`docs/planning/IMPROVEMENTS.md` item 48 has the rest of that audit.)

## 8. Bound the declared size, not the remainder

**Bound the *declared* size, not the remainder.** NATS's `HPUB` limit was applied to
`total − header`, leaving `header` unbounded — and `header == total` passes every check with
a zero-length body. `HPUB x 4000000000 4000000000` is thirty bytes on the wire and buffers
toward 4 GB, and `usize::MAX` then overflowed the offset arithmetic. Check the number the
peer gave you before you do arithmetic on it. Related: `Cargo.toml` has no `[profile.dev]`,
so `overflow-checks` is **on** in debug and test builds and **off** in release — STOMP's
`content-length: 18446744073709551615` panicked in every test build and wrapped harmlessly in
the shipped one, which is exactly backwards from where you want to find it.

## 9. Is the client a rating depends on compiled where the gate runs?

**Check whether the client a rating depends on is compiled where the gate runs** — but check
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
features, so it runs none of their evidence. `registry-audit` compiles everything but runs
only on a manual extended dispatch, so a green PR is not evidence that any of it passed. That
is the general gap, not a property of lapin.

## 10. `nfsserve`: a pre-auth DoS, and the guard on our side of the socket

**`nfsserve` 0.10.2 has a pre-auth remote DoS, and the fix is a guard on our side of the
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

## 11. `xmlrpc`: a reply that overflows the stack, and the `Transport` seam

**`xmlrpc` 0.15 can be stack-overflowed by the reply to the first call, and `Transport` is
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

## 12. Fail-open defaults

**Fail-open defaults are the most dangerous pattern in this codebase.** When the LLM returns
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

## 13. One client's leniency is one protocol's bug (gRPC trailers)

**One client's leniency is one protocol's bug, and the tests will all be green.** Two gRPC
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

## 14. A tokio blocking API in async context, the panic swallowed by `tokio::spawn`

**A tokio blocking API called from async context, with the panic swallowed by `tokio::spawn`.**
Found three times: `block_on` inside `UsbInterfaceHandler::handle_urb` (usb-msc, usb-fido2) and
`tokio::sync::Mutex::blocking_lock()` in SMB's connection task. The failure mode is identical
and nasty — the task panics, `tokio::spawn` swallows it, the server stays `Running`, the log
shows the operation *succeeding*, and the peer hangs. In SMB every SESSION_SETUP killed its own
connection the moment the LLM approved the login. If a synchronous callback needs an async
result, restructure so the sync side parks the request and an async task feeds the answer back
(usb-fido2 does this over CTAPHID `KEEPALIVE`); do not bridge with `block_on`.

## 15. Byte-index string truncation

Byte-index string truncation (`&s[..N]` guarded only by `s.len() > N`) panicked on multi-byte
UTF-8 at the cut point, on LLM output and event descriptions. Fixed in `b9aa1058` —
`src/utils/truncate.rs` has char-boundary helpers; use `truncate_for_log` rather than slicing.
`src/protocol/log_template.rs` was the important one (`c1515188`): being shared
infrastructure, it defeated protocols' own local fixes.

## 16. `generate_with_retry` called directly (resolved)

**Resolved (August 2026), recorded because the claim outlived the code.** This file used to
say `git` and `mercurial` "call `generate_with_retry` directly, bypassing the rate limiter,
the retry/repair loop, and event-handler dispatch". They do not, and a `grep -rn
generate_with_retry src/` now finds callers only inside `src/llm/` itself: the `git` *client*
goes through `call_llm_for_client` (budget, limiter and client `event_handlers` all apply),
and `src/server/git/mod.rs` and `src/server/mercurial/mod.rs` both use
`action_helper::call_llm`. Re-run that grep before trusting any similar claim here.

## 17. On LLM failure, write something — and the protocols that must stay silent

On LLM failure a protocol must not reset to Idle and write nothing, leaving the peer to hang
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

## 18. An empty static handler does suppress the model call; the control that never passed

**A static handler with an empty `actions` array DOES suppress the LLM call — but until
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

## 19. `ServerForm::create` substitutes a default instruction

**`ServerForm::create` substitutes a default instruction** (`"You are a {protocol} server.
Handle requests appropriately."`) whenever `instruction` is `None` — see
`src/state/server.rs::default_server_instruction`; MCP `start_server` does the same. Any
non-empty instruction makes `operator_wants_dynamic` true, so a
test built with `..Default::default()` **does consult the model**, whatever its comments claim.
Two `peer_inject` tests documented "Zero LLM calls" while doing the opposite, and passed only
because the old fail-open swallowed the resulting error. Pass `instruction: Some(String::new())`
when you want a genuinely model-free server. The substitution applies to a handlers-only
server too, deliberately: the dashboard creates every instance with `*` → manual and no
instruction, and switching its driver to LLM must still reach the model on the 17 gated
protocols. What changed is that it is never *shown* as the operator's:
`ServerInstance::instruction_is_default` makes `list_servers` / `server_status` say
"none given — NetGet's default applies", and the dashboard card and edit form show none.

## 20. Answering the peer is not a licence to tell it anything (`WireFailure`)

**Answering the peer is not a licence to tell it anything.** Fixing the silence above
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

## 21. The rate limiter used to discard overlapping network requests

Related and now fixed, but worth knowing as the reference case: the rate limiter used to
`try_acquire` for `RequestSource::Network` and bail on contention, so at the shipped default
of `--llm-max-concurrent 1` any request overlapping an in-flight LLM call was **discarded** —
two simultaneous `curl`s were enough — while the flag's help text promised "sequential
processing". Network requests now wait for a permit, bounded by `--llm-queue-timeout`
(default 120s) and `--llm-max-queued` (default 128), and both bounds fail with a typed
`RateLimitError` that `crate::llm::is_overload_error` detects. It survived for so long
because `tests/helpers/netget.rs` passes `--llm-max-concurrent 1000` to every E2E test, so
the shipped value was exercised by no test at all; `tests/llm_concurrency_default_test.rs`
now runs with the flag omitted entirely.

## 22. The rolling TUI's popup defect (the TUI is gone)

**The rolling TUI's slash-command popup destroyed visible output; the TUI is gone.** The
defect (a footer painted over the scroll region with no push-up, measured on the byte stream)
lived in `sticky_footer.rs`, which was deleted with the `--legacy-tui` mode in September 2026.
The dashboard renders whole frames into the alternate screen and never had it.

## 23. The 10-second idle sweep is for connectionless protocols only

**The 10-second idle sweep is for connectionless protocols only — declare it.**
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

## 24. Per-connection tasks are tracked: what `stop_server` must end

**Per-connection tasks are tracked now, and the reason it took a sweep is the useful part.**
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
channel; and `bluetooth_ble`'s radio dispatcher is process-wide by design.

**A task the registered task awaits is not ended by aborting it.** The abort drops the
awaiting future, which drops the child's `JoinHandle`, and dropping a `JoinHandle` *detaches*
the task. `postgresql` (pgwire's `process_socket`, spawned separately so its panics are
contained, plus its idle watchdog) and the six USB/IP servers (the session task their
`select!` awaits) had exactly that shape, so a stopped server's sessions kept their sockets.
Each such child is now held in `utils::task_guard::AbortOnDrop` and awaited as `guard.0`.
`tests/stop_server_stops_connections_test.rs` asserts it from the peer's side, for PostgreSQL
after a completed handshake and (with `libusb`) for every USB server.

## 25. `AppState` lock contention

**`AppState` keeps most state behind one tokio `RwLock`, and per-event bookkeeping is kept
out of it.** `tests/app_state_contention_test.rs` (ignored; run it with `--ignored
--nocapture`) drives N connections through a static-handler TCP server, alone and beside
the dashboard's `build_snapshot` and MCP-style `list_servers` / `list_access_logs` polling.
It measured a ceiling of about 5 000–7 000 requests a second (debug build) reached at 16
connections, with latency then growing with the connection count: five write acquisitions
per request, and writers waiting on the lock's queue handoff far longer than anyone held it.
A 10 Hz dashboard costs nothing measurable; back-to-back readers did, because
`list_access_logs` copied the whole ring under the lock (~1 ms). Connection counters
(`update_connection_stats`), the access log and the server task registry now have locks of
their own (`tests/app_state_off_lock_test.rs` pins their consistency), and a request on that
server takes the main lock once for writing (its history entry, rendered beforehand) and
reads it three times. Readers polling back to back cost about half what they did. Model-
driven traffic never comes near the ceiling: one model call per event is far slower than
the lock. **Prefer `with_server` over `with_server_mut` for reads**, and keep anything a
protocol does per message off the write lock.
