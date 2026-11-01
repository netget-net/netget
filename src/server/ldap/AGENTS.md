# LDAP Protocol Implementation

**Status**: `DevelopmentState::Beta`, on **two** independent clients, neither of them the crate
this server frames with:

| client | what it is | file | what only it covers |
|---|---|---|---|
| `ldap3` 0.11 | a Rust LDAP client (independent of `ldap3_proto` despite the name — different project, different authors) | `tests/server/ldap/e2e_test.rs` | add, modify, delete |
| OpenLDAP `ldapsearch` | C, from the project that wrote the RFC | `tests/server/ldap/real_client_test.rs` | the rendered LDIF, every value of a multi-valued `SET OF`, the long-form BER length, the bind `diagnosticMessage`, `noSuchObject` as an exit status |

Neither is `#[ignore]`d and neither skips when something is missing: the `ldapsearch` test
**fails**, naming the install command, on a machine without the binary. One client can agree
with one bug, which is why the second exists — the `ldapsearch` test was verified non-vacuous by
breaking the encoder twice (truncating the attribute `SET OF` to its first value; forcing
`encode_ber_length` to the short form) and watching what `ldapsearch` printed change, to one
`objectClass` line and then to no LDIF at all.

Not Stable: filters and scope are parsed but not evaluated, and no third-party client has been
taken through SASL or StartTLS because neither exists here.
(This line said `Experimental` while the code said `Beta`; the code was right.)
**Privilege**: `PrivilegeRequirement::PrivilegedPort(389)` — 389 is below 1024 and is where
every LDAP client looks by default, so the preflight check in `server_startup.rs` fires rather
than letting the bind fail with a bare EPERM.

LDAPv3 (RFC 4511) over TCP, with hand-written ASN.1 BER coding — no LDAP crate. That makes this
the highest-risk parsing in the file/directory protocol group, and the section on decoding
below is the important part of this document.

## Fail-closed

LDAP decides who is who, so silence must never be consent. In `LdapSession::respond_via_llm`:

| Situation | Wire result | Logged decision |
|---|---|---|
| Model returns a BindResponse with resultCode success | that response | `decision=model_accept` |
| Model returns a BindResponse with any other code | that response | `decision=model_reject` |
| Model returns no usable action, bind | **invalidCredentials (49)** | `decision=fail_closed_no_action` |
| Model returns no usable action, add/modify/delete | **unwillingToPerform (53)** | `decision=fail_closed_no_action` |
| Model returns no usable action, search | empty-but-successful result set | `decision=fail_closed_no_action` |
| LLM call errors | **unavailable (52)**, or **busy (51)** when overloaded | `decision=fail_closed_llm_error` |

Two things make the distinction structural rather than a matter of reading bytes back:

1. `respond_via_llm` returns a `Decided` alongside the step, so the bind path can only report
   `model_accept`/`model_reject` for a response the **model itself** produced. Inferring it from
   the encoded resultCode cannot tell a model's refusal from the server's substituted one, and
   conflating those is exactly what turned an outage into an approval in OAuth2.
2. The LLM-failure codes (51/52) are deliberately different from every per-operation default.
   `unavailable` is never a success, so a backend outage can never be mistaken for a valid
   empty answer — which is the one thing the search default could otherwise be confused with.

`self.authenticated` is state the model is *shown*, not a gate NetGet enforces: the model
decides what a bound-or-not session may do. Nothing in `actions.rs` can synthesise a successful
BindResponse; only `ldap_bind_response` with an explicit `result_code` of 0 produces one.

## Connection tracking

Peers are registered with `add_connection_to_server` in the accept loop and retired with
`close_connection_on_server` when the session ends, and `record_bytes` keeps the counters and
`last_activity` current on every read and write. LDAP is connection-oriented and so does **not**
declare `.connectionless()`; the 10-second idle sweep therefore does not touch these entries,
which makes the explicit close the only thing that retires one. Before this the server
registered nothing at all: the dashboard rail showed an LDAP server with no peers while clients
were bound to it, and no connection-scoped scheduled task could be created.

## Connection bounds

Before September 2026 this server accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a connection task and an `AppState` entry
forever — for LDAP that means before any bind at all — on a server that would happily accept a
hundred more. It now declares both halves; the constants and the reasoning live beside them in
`src/server/ldap/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_MESSAGE_READ_TIMEOUT` | **300s**, override `first_byte_timeout_secs` | LDAP is client-speaks-first: nothing is sent until a BindRequest or an anonymous SearchRequest arrives, so a peer that has sent nothing has begun no session. **This was 30s and it strands NetGet's own client** — see below. |
| `IDLE_BETWEEN_MESSAGES_TIMEOUT` | 900s, override `idle_timeout_secs` | There is no interval to sit above — LDAP defines no keepalive and OpenLDAP's own `idletimeout` defaults to **0**. Fifteen minutes is safe because of a property of *this* server: it implements no control and no extended operation, so persistent search and syncrepl — the only shapes in which a client legitimately holds an LDAP connection open in silence — cannot be requested here. Every operation is request/response. |
| `MAX_CONNECTIONS` | 256 | Refusal: LDAP's own **Notice of Disconnection** (RFC 4511 §4.4.1) — an unsolicited `ExtendedResponse` on messageID 0, OID `1.3.6.1.4.1.1466.20036`, `resultCode = unavailable (52)`. `busy (51)` reads closer to the truth and is deliberately not used: §4.4.1 permits only `protocolError`, `strongerAuthRequired` and `unavailable` there, and anything else is a malformed notice. |

**The first bound was 30 seconds, and the peer it was argued about is not the peer this server
usually has.** Thirty seconds is right about a stranger holding an unauthenticated socket. It is
wrong about `src/client/ldap/mod.rs`, which opens the socket and sends **nothing**: it raises
`ldap_client_connected` and waits for the model, or for a person. The dashboard offers
`[ + ldap client ]` under a server's peers with `[ send message ]` beneath it and answers the
connect event with nothing, so that client sits at zero bytes sent for as long as the operator
takes to compose a bind — and the server dropped it while they were still looking at it. 300
seconds is the window a `manual` rule gives a human (`src/state/intercepts.rs`), which is the
number this product already uses for "how long someone might take". The cost is that a stranger
holds a socket, a task and an `AppState` row for 300s rather than 30s — still bounded, still
capped at `MAX_CONNECTIONS`, so the total exposure is unchanged and only the dwell time moved. A
listener genuinely exposed to strangers should set `first_byte_timeout_secs` low; that is what
the parameter is for.

**The deadline wraps the `read()` and nothing else.** `handle_message` may sit in an LLM
round-trip, or in a `manual` rule parked for a human at the dashboard (300s by default), for
minutes; none of that is this peer being silent, and none of it is inside the timeout. The
second bound is armed only once a complete message has actually been *handled*, not on the first
byte — a peer dripping a partial BER envelope has still begun no operation.

An idle close writes nothing: the peer is being dropped for silence rather than refused, and a
close is what every LDAP client already reads as an idle timeout. The reason lives in the log,
tagged `decision=fail_closed_idle_timeout`.

`tests/server/ldap/connection_bounds_test.rs` drives all three from the wire, including that the
Notice of Disconnection arrives byte for byte on the connection past the cap and that releasing
one admitted connection frees exactly one slot. Replacing the `tokio::time::timeout` around the
read with a bare read makes the first test hang for its whole assertion window and fail. Those
tests pass `first_byte_timeout_secs` a small value rather than waiting out the 300-second
default — a suite that waited it out would be the slowest thing in the tree, and what is being
asserted is that the deadline is applied to the read it names, not what the number should be.
`tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound is removed, and
`tests/accept_bounded_test.rs` covers the shared helper.

## No storage

There is no directory. A bind is granted or refused by the model; a search returns the entries
the model names; add, modify and delete are acknowledged and change nothing here, because
there is nothing here to change. Whether a search after an add agrees with it is the model's
memory to keep — say so in the instruction if you care.

## Decoding attacker-controlled BER

**The invariant: no index or range is used before it has been checked against the remaining
buffer.** `read_ber_element` is the only place raw input is sliced. It validates that an
element's claimed length actually fits and hands back a `value` slice that is already in
bounds; every parser above it walks `BerElement`s and never indexes the wire buffer itself.

The previous implementation did the opposite — it indexed and sliced using lengths read
straight off the wire:

```rust
let op_start = msg_start + id_bytes;
let op_tag = data[op_start];                                   // panic
let dn = String::from_utf8_lossy(&data[dn_data_start..dn_data_start + dn_bytes]); // panic
let pwd = &data[pwd_start..pwd_start + pwd_bytes];             // panic
```

Concretely, the seven-byte message `30 82 00 01 02 01 01` walked `op_start` to exactly
`data.len()` and panicked on `data[op_start]`. A panic in a connection task is silent: the task
dies, the client sees a closed socket, and the server keeps reporting `Running`.

Also bounded now:

- **Message size** — `MAX_LDAP_MESSAGE` (1 MiB). A long-form BER length can promise 4 GiB.
- **Filter nesting** — `MAX_FILTER_DEPTH` (32). `render_filter` recurses over client-supplied
  structure, so an unbounded renderer overflows the stack on a deliberately deep filter. A
  search needs no bind, so this is reachable from the first message. The pure decoders —
  `ldap_message_len`, `decode_ldap_message`, `parse_search_request` — are public so
  `fuzz/fuzz_targets/ldap_filter.rs` drives the session's own path; with the check disabled its
  60 000-level `depth_bomb` seed (~280 KB, under `MAX_LDAP_MESSAGE`) kills it with `SIGSEGV`.
- **Integer width** — `ber_integer` rejects INTEGERs wider than 8 bytes and sign-extends
  properly, rather than shifting an arbitrary number of bytes into an `i32`.

Verified by fuzzing a running server (2026-08-05): truncated headers, lengths pointing past the
buffer, a 4 GiB long-form length, empty DNs, truncated attribute lists, a 200-deep nested
filter, and 40 random-garbage messages. No panic; the server answered a valid bind afterwards.

## Message framing

Messages are framed by their BER length and reassembled across reads (`ldap_message_len` plus
a persistent buffer). The old loop treated one `read()` as exactly one message, which is wrong
in both directions:

- `ldapsearch` pipelines bind and search into one segment — the second message was discarded
  and the client hung.
- Any message split across TCP segments, or larger than the 8 KiB buffer, was rejected as
  malformed.

## Operations

| request | tag | event | response tag |
|---|---|---|---|
| BindRequest | 0x60 | `ldap_bind` | BindResponse 0x61 |
| SearchRequest | 0x63 | `ldap_search` | SearchResultEntry 0x64 + SearchResultDone 0x65 |
| ModifyRequest | 0x66 | `ldap_modify` | ModifyResponse 0x67 |
| AddRequest | 0x68 | `ldap_add` | AddResponse 0x69 |
| DelRequest | 0x4A | `ldap_delete` | DelResponse 0x6B |
| UnbindRequest | 0x42 | `ldap_unbind` | none (RFC 4511 forbids one) |
| anything else | — | — | protocolError under the matching response tag, or ExtendedResponse 0x78 |

**Add, modify and delete were dead.** The three actions `ldap_add_response`,
`ldap_modify_response` and `ldap_delete_response` were declared, had working executors and were
documented — but no request parser and no event ever produced them. `ldapadd` got a
protocolError, and worse, that error was encoded with the *BindResponse* tag whatever the
request was, so a client decoding a search or add reply saw a protocol violation rather than
the protocolError it was meant to see. Both are fixed: the operations are parsed and raised as
events, and `response_tag_for` picks the tag matching the request.

## Events

Six, each advertising exactly the actions that can answer it:

| event | data | actions |
|---|---|---|
| `ldap_bind` | `message_id`, `version`, `dn`, `password`, `auth_type`, `anonymous`, `answer_with` | `ldap_bind_response` |
| `ldap_search` | `message_id`, `base_dn`, `scope`, `filter`, `attributes`, `authenticated`, `bind_dn` | `ldap_search_response`, `close_connection` |
| `ldap_add` | `message_id`, `dn`, `attributes`, `authenticated`, `bind_dn` | `ldap_add_response`, `close_connection` |
| `ldap_modify` | `message_id`, `dn`, `changes`, `authenticated`, `bind_dn` | `ldap_modify_response`, `close_connection` |
| `ldap_delete` | `message_id`, `dn`, `authenticated`, `bind_dn` | `ldap_delete_response`, `close_connection` |
| `ldap_unbind` | `bind_dn` | none, declared with `.with_no_actions()` |

**`ldap_bind` says what kind of bind it is, and is answered by the BindResponse alone.**
`anonymous` is true for a simple bind with no DN and no password, and `answer_with`
(`actions::bind_answer_with`) names the kind of bind — anonymous, a DN with no password, a DN
with a password, or SASL, which can only be refused — says what the instructions decide it on,
and that what a later search finds is decided when the search arrives. Told "accept anonymous
connections. A search under dc=example,dc=com finds one person …", llama3.1:8b refused
`ldapsearch -x`'s anonymous bind ("anonymous bind not allowed") in every run of two real-model
eval cases (seed 42): the event showed an empty `dn` and `password` and nothing said that this is
the anonymous connection the instructions accept. Replayed with the hint, five seeds in five
accepted. `close_connection` is not offered on a bind: offered beside the BindResponse, the
model answered an anonymous bind with both four runs in five and hung up before the search
`ldapsearch` had already pipelined. A refused bind is `ldap_bind_response` with `success: false`,
after which the client closes by itself.

`ldap_unbind` used to carry `.with_actions(vec![])`, which is indistinguishable from a
forgotten action list: `call_llm` treats that as a bug and fires a `debug_assert!(false, ...)`,
so **every unbind panicked the connection task in a dev build**. `.with_no_actions()` states the
intent, and the assert no longer fires.

All three event response examples were `{"type": "placeholder", "event_id": "..."}`. The
response example is rendered verbatim into the prompt, so the model was being shown an action
named `placeholder` as the way to answer. They are now real responses, with a failure case as
an alternative example on each.

Search now reports `scope`, `filter` (rendered back to RFC 4515 text such as
`(&(objectClass=person)(cn=j*))`) and the requested `attributes`. None of them is enforced —
the model decides what matches — but it could not decide before, because it was only told the
base DN.

The search example's entry is `cn=Example Person,ou=example,dc=example,dc=org` — a stand-in
under a base nobody searches. It used to be `cn=john,ou=people,dc=example,dc=com`, and told
"there is nothing at all under dc=other,dc=com", llama3.1:8b answered that search with john
every run (`./run-eval.sh ldap`, seed 42): a plausible entry under the very base the eval's
other cases search reads as data, not as shape. `ldap_search_response` and the event's
`base_dn` now say that entries sit under the searched base, that `entries: []` with result 0
is how a search finds no one, and that the example is never data. With that, `ldap/empty-result`
went 0/3 → 5/5.

## Actions

`ldap_bind_response`, `ldap_search_response`, `ldap_add_response`, `ldap_modify_response`,
`ldap_delete_response`, `close_connection`. All carry structured fields; the BER encoding is
built here.

`wait_for_more` was removed. Messages are framed by length and reassembled by the session, and
the session only ever consumed an `ActionResult::Output` — `WaitForMore` was discarded, leaving
the client waiting for a response that would never arrive.

Result codes: 0 success, 2 protocolError, 32 noSuchObject, 49 invalidCredentials, 50
insufficientAccessRights, 53 unwillingToPerform, 68 entryAlreadyExists.

## Failure behaviour

Every operation has a default response, so a model failure never leaves the peer waiting for
its own timeout: bind defaults to invalidCredentials, search to an empty but successful result
set, and add/modify/delete to unwillingToPerform. A model that returns `close_connection` with
no response closes the connection; one that returns nothing gets the default plus a WARN.

**A model *failure* is answered differently from a model *silence*.** The defaults above all
describe an outcome the directory chose, and the search default is a **success** — resultCode 0
with no entries, which a client reads as "nothing matched". Returning one of those when the
backend is unreachable misreports an outage as a decision. So when `call_llm` returns `Err`,
`respond_via_llm` answers `unavailable` (52), or `busy` (51) when
`crate::llm::is_overload_error` says the failure was capacity exhaustion, encoded under the
response tag matching the request. Neither is ever a success. Covered by
`tests/server/ldap/llm_failure_test.rs`.

Bind success is now read structurally from the encoded BindResponse (`bind_succeeded`) rather
than by scanning the byte stream for `0x61`, which any DN or diagnostic message containing that
byte could fool.

`ldap_unbind` is raised on a detached task rather than awaited. Awaiting it delayed closing the
socket by a whole model round-trip — measured with `ldapadd` against a real model, the add was
answered promptly and the client then sat for fifteen seconds waiting for a teardown blocked on
an LLM call whose result is discarded.

## Not implemented

SASL (the mechanism is reported so it can be refused), StartTLS, LDAPS, referrals, controls,
extended operations, compare, modifyDN, abandon, schema validation, and paged results. Search
scope, filter and requested-attribute list are decoded and reported but never evaluated.

Note there are two copies of the BER *encoders* — `actions.rs` builds responses, `mod.rs`
builds defaults and errors. They agree today; if you change one, change both.

## Manual verification

```bash
./cargo-isolated.sh run --release --no-default-features --features ldap
# start on 13890 with static handlers for ldap_bind / ldap_search / ldap_add / ldap_modify /
# ldap_delete, then:

ldapsearch -x -H ldap://127.0.0.1:13890 -D "cn=admin,dc=example,dc=com" -w secret \
           -b "dc=example,dc=com" "(objectClass=person)" cn mail
ldapadd    -x -H ldap://127.0.0.1:13890 -D "cn=admin,dc=example,dc=com" -w secret -f add.ldif
ldapmodify -x -H ldap://127.0.0.1:13890 -D "cn=admin,dc=example,dc=com" -w secret -f mod.ldif
ldapdelete -x -H ldap://127.0.0.1:13890 -D "cn=admin,dc=example,dc=com" -w secret \
           "cn=testuser,dc=example,dc=com"
```

Verified 2026-08-05 against OpenLDAP's client tools: bind succeeds, the search returns both
entries with all attributes and `result: 0 Success`, and add/modify/delete all return success —
with modify's two changes decoded (`2 changes` in the log).

## Testing

`tests/server/ldap/e2e_test.rs` — 7 tests via the `ldap3` crate (bind success/failure, search,
filtered search, add, modify, delete). All pass. Note the add/modify/delete tests define no
mock for their own event and assert nothing about the result code, which is how those
operations could be entirely unimplemented while the tests stayed green.

`tests/server/ldap/real_client_test.rs` — the second client. One `ldapsearch` binary, two
sessions against one server: a bind + search whose LDIF is parsed back into entries and
attribute-value lists, and a search the model refuses with `noSuchObject`, read off
`ldapsearch`'s exit status (32). The verified-by-breaking method is in the file's own doc
comment. The manual `ldapsearch` transcript above is a transcript; this is the assertion.

## References

- [RFC 4511: LDAP Protocol](https://tools.ietf.org/html/rfc4511)
- [RFC 4515: LDAP Search Filter String Representation](https://tools.ietf.org/html/rfc4515)
- [ITU-T X.690: BER/CER/DER](https://www.itu.int/rec/T-REC-X.690)
