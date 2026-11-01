# Ident (RFC 1413) Client Implementation

The querying half of RFC 1413. NetGet connects to a host, asks *"which account owns the TCP
connection between these two ports?"*, reads one line, and closes. The server half lives in
`src/server/ident/` — **read its CLAUDE.md before touching this one**; the two documents share
a protocol and deliberately do not repeat each other.

**State**: Experimental — see "Why not Beta", and note that the server half reached the same
conclusion independently for the same structural reason.
**Privilege**: `None`. Connecting *out* to port 113 needs nothing; only listening on it would.
**Stack**: `ETH>IP>TCP>Ident`.

## Why this client exists at all, when the protocol is one line each way

An ident query is what an IRC daemon performs on **every connecting user** — it is the `~` in
`nick!~user@host`. That makes this the one client in its wave that makes an *existing* NetGet
protocol more realistic rather than adding an isolated capability: `src/server/irc/` can drive
this client on each inbound registration and behave the way a real ircd does. Nothing wires
that up today; the connection is worth knowing before someone re-derives it.

## Protocol

```
->  <server-port> , <client-port>\r\n
<-  <server-port> , <client-port> : USERID : <opsys>[,<charset>] : <userid>\r\n
<-  <server-port> , <client-port> : ERROR  : <NO-USER|INVALID-PORT|HIDDEN-USER|UNKNOWN-ERROR>\r\n
```

One exchange per connection; the server closes after answering. There is no library — no RFC
1413 crate exists on crates.io in either direction — so `mod.rs` is a hand-rolled tokio line
reader, the same shape as the server half.

## The one correctness property a client has: the port pair must match

RFC 1413 §3 has the client match a reply to its query **by the port pair**. That is not
bookkeeping. A reply carrying a different pair is an answer about somebody else's connection,
and accepting it would attribute a stranger's account to the wrong socket — silently, and in a
form indistinguishable from a correct answer.

So `session()` records the pair that went out (`PendingQuery`, shared with the command task
because either can be what puts a query on the wire) and compares it with the pair that came
back. Four situations are **all** rejected into `ident_reply_mismatch` rather than parsed into
a result, each with a distinct `reason`:

| `reason` | What happened |
|---|---|
| `port_pair_mismatch` | A well-formed reply about a different pair |
| `unsolicited` | A reply arrived with no query outstanding |
| `oversized` | The line passed `MAX_REPLY_BYTES` with no newline; refused unparsed |
| `port_pair`, `response_type`, `userid_fields`, `empty_userid`, `empty_opsys`, `error_token`, `no_response_type`, `no_addl_info` | Parse verdicts from `parse_ident_reply` |

The event carries what was asked *and* what came back, so a handler can tell the two apart. The
rejected line is included as `reply_line`, control characters stripped and truncated, for
diagnosis only.

**`parse_ident_reply` is strict on purpose.** Every field position in the grammar means
something to whoever reads the result: a `USERID` line with no userid must not become an empty
username, and an unrecognised response type must not fall through into the error-token slot.
`0` is out of range for both ports — there is no connection on port 0 to own — which is also
what stops a `0 , 0` reply from matching a query nothing sent.

**Whitespace is tolerated in both directions.** `  6193  ,  23  :  USERID  :  UNIX , US-ASCII
:  stjohns  ` parses. The grammar admits it, NetGet's own server writes `<sp> , <sp>` itself,
and rejecting it would be a gratuitous failure.

Error tokens are the four RFC 1413 names plus the `X`-prefixed implementation-defined form the
RFC reserves. Anything else is `error_token`, not free text handed to the model.

## The model's answer is carried out — including a second query

The defect the root `AGENTS.md` calls the most common client bug in this repo is a client that
asks the model what to do and then throws the answer away. Here the reply event's answer is
executed, and a follow-up `send_ident_query` **opens a fresh TCP connection**, because RFC 1413
is one exchange per connection and the server has already closed.

That follow-up then **raises its own event** and goes back through the same handler, which is
what keeps a chain alive past one step. `whois` takes the other exit — its `run_query_once`
runs a follow-up and raises nothing — and that is precisely the shape to avoid: the chain dies
after one hop and nothing says so.

The cycle is action → event → action, which is genuinely self-referential, so `handle_reply`
returns `Pin<Box<dyn Future<Output = ()> + Send>>` rather than being an `async fn` (an
`async fn` that can reach itself has an infinitely-sized future, E0391). `+ Send` is spelled
out because this is awaited inside `tokio::spawn` and inference will not supply it.
`MAX_FOLLOWUP_DEPTH` (4) bounds it — and here it bounds **real sockets**, not just recursion.

## Startup parameters

| Parameter | Read by | Notes |
|---|---|---|
| `ident_port` | `resolve_target` | Default 113. Wins over any port in `remote_addr` |
| `response_timeout_secs` | `read_reply` | Default 30; `0` falls back to the default |

**`ident_port` exists because of an asymmetry worth stating plainly.** RFC 1413 has no notion
of a configurable server port: a real identd listens on 113 and every real ident client
hardcodes 113 as the destination. So `remote_addr` for this protocol is normally *just a host*,
and the port parameter is there for a test harness or a deliberately non-standard deployment.
This is also exactly why no third-party client can validate NetGet's server, and why no
third-party server can validate this client — see below.

`resolve_target` understands `host`, `host:port`, `[::1]:port` and a bare IPv6 literal. A colon
suffix that is not a number is kept as part of the host, so the connect error names what the
caller actually typed instead of silently retargeting 113.

## Actions and events

Actions: `send_ident_query` (`server_port`, `client_port`), `wait_for_more`, `disconnect`.
Events: `ident_connected`, `ident_response_received`, `ident_error_received`,
`ident_reply_mismatch`.

`send_ident_query` yields `ClientActionResult::Custom`, not `SendData`, because the loop has to
remember which pair was asked about and bytes alone cannot carry that. `apply_action` is
therefore the single encoder, shared by the LLM path and by injected dashboard commands, which
is also why the command loop is bespoke rather than
`command_support::handle_stream_client_command` (that generic arm cannot run a `Custom` result).

### The vocabulary is declared once

`client_action_set()` is the only list. It is returned by `get_async_actions()` and also
attached to all four event types with `with_actions(...)`, so each event's own entry in the
prompt and in `get_protocol_docs` names the verbs that answer it. Both consumers of a client's
vocabulary take the union, so neither depends on the attachment:

* `client_llm_action_set` (`src/llm/actions/client_trait.rs`) unions async ∪ sync ∪ the firing
  event's actions and deduplicates by name, so the model sees each verb once. A client has one
  LLM entry point and cannot express a narrowing, which is why `get_sync_actions()` is empty
  here rather than a second copy of the list.
* `validate_static_action_names` (`src/events/handler.rs`) validates a client handler against
  `client_action_names_for_pattern` — the same union plus the matching event types' actions —
  so `{"type": "static", "actions": [{"type": "send_ident_query", …}]}` on `ident_connected`
  is accepted at creation. `tests/static_handler_action_catalog_test.rs` pins the rule for
  async-only client verbs (TCP's `disconnect`, WHOIS's `query_whois`).

## Failure behavior

There is nothing to fail *closed* about here — a client makes no assertion to anybody. An LLM
error on the connect event leaves the connection **open** rather than tearing it down, because
the operator can still inject the query from the dashboard and the command channel is
registered before that call precisely so it can be reached while a manual rule parks the event.
Anything else (timeout, peer closed first, socket error) is logged with the pair it concerned
and ends the session.

## The rule NetGet keeps on this side

The server half's rule is "NetGet invents every userid; it never reads `/etc/passwd`". The
mirror image applies here: **the port pair is the model's choice, never derived from a local
socket table**, `getpwuid`, `netstat`, or any other host state. The userid that comes back is
somebody else's account name; it is reported once, in the event, and nowhere else — not written
into memory automatically, not echoed into a status line, not used to name anything. It is an
unverified assertion by a stranger's host and the event description says so.

## Why not Beta — and why that will not change

Beta means "works against real clients", and for a client protocol it means the mirror: driven
against a real third-party **server**. There is none that can be used.

`src/server/ident/AGENTS.md` records the full search — crates.io, Homebrew, PyPI, macOS system
binaries — and the conclusion is structural rather than a matter of effort: **RFC 1413 has no
notion of a configurable port**, so no ident implementation on either side can be aimed at an
ephemeral loopback port, and 113 needs root and collides process-wide rather than being
per-test isolated. **Do not repeat that search.**

So the evidence here is same-project (NetGet's own ident server) plus peers hand-written from
the wire format inside the test — an independent reading of the spec, not an independent
implementation. That is the `dhcp` situation exactly, and by this repo's own bar it supports
Experimental and not Beta.

**What would earn Beta**: a real `identd` (oidentd, pidentd, or an ircd's `libident` lookup)
listening on port 113 on the test host, driven by this client with `ident_port: 113`, in a test
that **hard-fails when the binary is absent** rather than skipping. That needs root and a
machine-wide port, which is why it is not here. Do not add an `#[ignore]`d test against it —
`src/server/ident/AGENTS.md` says the same thing, and the root `AGENTS.md` lists
"`#[ignore]`d, however good the reason" and "a real client behind a skip-when-missing gate"
as two of the four near-misses that are not evidence.

## Not implemented

No multiple queries on one connection (RFC 1413 is one-shot). No handling of the
DES-encrypted opaque tokens some identd implementations return in place of a userid — they
parse as an ordinary `userid` string and are reported as such. No IPv6-specific behaviour
beyond whatever address the socket carries. No retry, no caching of an answer, no storage.
