# WHOIS Protocol Implementation

WHOIS (RFC 3912) server: the client sends one line, the server answers with free
text. The model decides what the registry says.

**State**: Beta — human-reviewed, verified against a real client.
**Privilege**: declares `PrivilegedPort(43)`; the preflight fires only when the
requested port is actually below 1024, so a test on port 4343 needs no
privileges. **Stack**: `ETH>IP>TCP>WHOIS`.

## Protocol

1. Client connects on TCP 43.
2. Client sends the query terminated by CRLF.
3. Server writes the response and (usually) closes.

There is nothing else to it — no versioning, no content type, no framing beyond
the line. This is why the implementation is a plain `tokio` read/write loop with
no library.

## What the model sees and controls

**Event**: `whois_query`, one per read, carrying `query` (the trimmed line).

**Actions**

| Action | Effect |
|---|---|
| `send_whois_record` | formats `Domain Name:`, then only the fields given: `Registrar:`, one `Domain Status:` per `domain_status` entry, `Registrant Name:`, `Registrant Organization:` (`registrant_organization`, alias `registrant_org`), `Admin Name:`, one line per `extra_fields` entry (at most `MAX_EXTRA_FIELDS` = 32, refused past it), one `Name Server:` per entry; CRLF-terminated |
| `send_whois_response` | free-form text; CRLF appended if missing |
| `send_error` | `Error: <message>` — the answer for a query with no record (`No match for "x.invalid"`) |
| `close_connection` | closes after the response |

No async actions: WHOIS is purely reactive.

The connection loop keeps reading after a response, so a client may send several
queries; each raises its own event. Most clients send one and close.

**This is a non-conformance, but no longer an open-ended one.** RFC 3912 says the
server closes as soon as its output is finished, and `whois(1)` reads until EOF —
so a handler that answers with `send_whois_record` alone used to leave a real
client blocked forever. It now blocks for `IDLE_AFTER_REPLY_TIMEOUT` (15s by
default, `idle_timeout_secs` to change it) and then gets EOF. Pairing the answer
with `close_connection` is still the right thing to do and is what both `send_*`
action descriptions say;
`tests/server/whois/e2e_test.rs` proves the real client is satisfied when they
are paired. The timeout is a floor under the mistake, not a substitute.

### The record prints what the model said, and only that

The real-model eval told the model to "report the registrant organisation as Example Holdings Ltd
and the domain status as clientTransferProhibited" (`whois/registrant-and-status`, 2/5 in the
committed baseline). It did — as `registrant` and `domain_status` — but the action had no field
rendering either an organisation or a status, so the status was silently dropped and the
organisation came out as `Registrant Name`. `registrant_organization` and `domain_status` are now
real fields, `extra_fields` covers any other line, and the description names them.

The same pass removed three fabrications: an omitted `registrar`, `registrant` or
`admin_contact` used to print `Example Registrar, Inc.`, `Registrant Contact` and `Admin Contact`.
A WHOIS reader takes every line at its word, so an omitted field is now omitted.
`tests/server/whois/record_fields_test.rs` pins the exact bytes, the omission, and the
`extra_fields` bound (verified by removing it).

### "No match" is `send_error`, and both descriptions say so

The eval case `whois/no-match` ("Report that no match was found for any domain ending in
.invalid") scored 2/5 at seeds 42–46. On three seeds the model answered `nothing.invalid` with a
`send_whois_record` that printed only `Domain Name: nothing.invalid`, or a status of `noMatch`,
which reads as a registered domain. When the captured prompt is replayed over seeds 1–46, the
old one-line `send_error` description ("Send error message for domain not found") lost 5 of
46. Three changes lost none: a description saying it is the answer for a query with no record,
an example message `No match for "example.invalid"`, and `send_whois_record`'s description
saying it is for a domain that has a record. An ordinary record for `example.com` stayed 46/46,
and the eval's `whois/no-match` scores 5/5 at seeds 42–46
(`eval-results/2026-11-07-gearman-whois-replay/`).
Rewording `send_error` alone, with the old example, was worse in one way: on 3 of 20 seeds the
model answered `example.com` with `No match for example.invalid`, copied from the description.

### Injection hygiene

A WHOIS **response** is free text and `send_whois_response` is deliberately
unfiltered — multi-line output is its whole purpose. A WHOIS **record** is not
free text: it is `Key: value` lines, so every single-line field of
`send_whois_record` (and `send_error`'s `message`) is stripped of control
characters first. Without that, a `registrar` of
`"Foo\r\nRegistrant Name: Bar"` forged a field the model never asserted, and
nothing reading the output — a human, or more dangerously a script grepping for
`Registrant Name:` — could tell it from a real one.

This is the line-oriented family's signature defect. What is worth recording is
the direction it was found in: **both of this server's neighbours had added the
guard independently and WHOIS, the one they were told to copy, had not** —
`gopher`'s `sanitize_field`, `finger`'s `strip_controls`, `ident`'s
`sanitize_token`.

CR, LF and tab become a space rather than vanishing (gopher's choice): deleting
them concatenates the two sides into one word, `Good RegistrarRegistrant`, which
reads as a single value and is its own small lie. The guarantee is *no forged
line*, not that the words disappear.

### Framing and bounds

A query is a **line**, not a TCP segment. Reads accumulate to a newline under
`MAX_QUERY_BYTES` (4 KiB); past that the peer gets `% netget: query too long` and
the connection closes. Waiting for bytes is bounded too:

| Bound | Default | Override | Why this number |
|---|---|---|---|
| `FIRST_QUERY_READ_TIMEOUT` | **300s** | `first_byte_timeout_secs` | The window a `manual` rule gives a human (`src/state/intercepts.rs`). **This was 30s and it strands NetGet's own client** — see below. |
| `IDLE_AFTER_REPLY_TIMEOUT` | 15s | `idle_timeout_secs` | Deliberately the *stricter* of the two, which is the reverse of every other protocol here — see below. |
| `MAX_QUERY_BYTES` | 4 KiB | — | A query is a domain, a handle or an IP; past this it is not one, and buffering it for a peer who may never send a newline is a memory hole reachable by anyone. |

**Thirty seconds was argued about a stranger, and the peer this server usually has
is not one.** `src/client/whois/mod.rs` opens the socket and sends **nothing**: it
raises `whois_client_connected` and waits for the model, or for a person. Its own
comment says as much where it registers the command channel — early, "because a
manual `*` rule can park [the connected event] for minutes - the operator must be
able to send the query while it waits". The dashboard's `[ + whois client ]`
answers that connect event with nothing and then waits for someone to type a
domain into `[ send message ]`, so the client sits at zero bytes sent for as long
as the operator takes. Thirty seconds is less than a person takes. What 300s costs
is that a stranger holds a socket and a task for 300s rather than 30s — still
bounded, and a WHOIS connection carries nothing but a `MAX_QUERY_BYTES` line
buffer. A listener genuinely exposed to strangers should set
`first_byte_timeout_secs` low.

**The idle bound was deliberately *not* raised alongside it, and the asymmetry is
the point.** Everywhere else in this tree the idle bound is the more generous of
the two; here it is the stricter, because it is not really an idle bound at all —
it is the repair for the non-conformance above. When a handler answers without
`close_connection` this bound is the only thing that ever unblocks a real
`whois(1)`. Raising it to 300 would make that rescue twenty times slower for every
real client, in exchange for a second query nobody composes by hand inside a
session the protocol says is already over. A human issuing several queries down
one socket should raise `idle_timeout_secs`, not make everyone wait.

`tests/server/whois/connection_bounds_test.rs` drives both from the wire, setting
each through its startup parameter to a small and *different* value — so a server
that read one parameter and applied it to both reads fails the second test rather
than passing it. It also asserts that a query parked for a human survives well
past both, because the deadline wraps the `read()` and not the answer.

All three bounds replace behaviour that was reachable by anyone who could open a
socket. The loop previously raised one `whois_query` event per `read()`, so a
query split across two segments produced two events carrying two fragments, and a
peer sending a byte at a time bought **one LLM call per byte** — unmetered model
work with no authentication in front of it. `tests/server/whois/line_framing_test.rs`
pins both the reassembly and the cap.

### Dashboard injection (peer handle)

Every connection registers a peer handle (`server::peer_support`) before its first
read — a WHOIS server says nothing until asked, and a manual `*` rule can park the
query, so the operator must be able to reach the connection while it waits. The
write half is an `Arc<Mutex<WriteHalf>>` shared by the session and the peer command
task; `[ message this peer ]` executes any of the actions above through the same
executor the model's go through (all wire verbs return `ActionResult::Output`, so
no Custom-result gap), and `[ disconnect this peer ]` is `close_connection`. The
handle is removed on every exit path, and `bytes_*`/`packets_*` are updated on
every read and on every write the session itself makes; bytes written by the
generic peer task are not counted (that is in `peer_support.rs`, not here).
`tests/server/whois/peer_inject_test.rs` proves it with zero LLM calls.

### Failure behavior

**This section used to say the opposite of what the code does** — that a failure
"closes the connection with nothing written". It does not, and has not for some
time. Every failure answers.

WHOIS has no status code, so the distinction lives in a `%` comment line, which
every dialect treats as a remark and no client can mistake for a record:

| Outcome | On the wire | Log |
|---|---|---|
| backend saturated | `% netget: backend at capacity, retry later` | `decision=fail_closed_llm_error category=overloaded` |
| any other backend failure | `% netget: the query could not be answered` | `decision=fail_closed_llm_error category=unavailable` |
| model answered, nothing reached the wire | `% netget: no data was produced for this query` | `decision=model_silent` |

The two failure notices are **byte literals**, not a format string, so there is no
placeholder anything derived from the error could reach. `crate::utils::WireFailure`
classifies the error and is never rendered — see the root `AGENTS.md` on the pass
that put netget's own retry message on strangers' terminals. `decision=` tokens
follow `src/server/radius/`: grep them to tell an outage from a model that chose
to say nothing.

## Not implemented

Referrals to another WHOIS server, WHOIS++ (RFC 1835), IDN, rate limiting,
access control, and any actual database — the model answers every query. Query
and response are treated as ASCII/UTF-8 text; there is no storage of any kind.

## Example prompts

```json
{"type": "open_server", "port": 43, "base_stack": "whois",
 "event_handlers": [{"event_pattern": "whois_query", "handler": {"type": "script",
   "language": "python",
   "code": "domain = event.get('query', 'unknown.com').strip()\nrespond([{'type': 'send_whois_record', 'domain': domain, 'registrar': 'Example Registrar Inc.', 'registrant': 'Example Organization', 'name_servers': ['ns1.example.com', 'ns2.example.com']}])"}}]}
```

```
WHOIS server on port 43 - respond with fake registration info for any domain,
registrar "Example Registrar", nameservers ns1/ns2.example.com.
```

```
listen on whois port 43. For example.com show full registration details; for
every other domain send_error "Domain not found".
```

## Verified

With a static `send_whois_record` handler (zero LLM calls) on 127.0.0.1 giving `registrar`,
`registrant` and two `name_servers` (no `admin_contact`, so no `Admin Name:` line):

```
$ printf 'example.com\n' | nc 127.0.0.1 PORT
Domain Name: example.com
Registrar: Example Registrar Inc.
Registrant Name: Example Org
Name Server: ns1.example.com
Name Server: ns2.example.com
```

And with the real client, which is what the `Beta` rating rests on
(`tests/server/whois/e2e_test.rs::test_whois_with_real_whois_client`):

```
$ whois -h localhost -p PORT example.com
Domain Name: example.com
Registrar: Test Registrar Inc.
Registrant Name: Test Organization
Admin Name: Test Admin
Name Server: ns1.example.com
Name Server: ns2.example.com
```

macOS's `whois(1)` **segfaults** when `-h` is given an **IP literal**
(`-h 127.0.0.1`); it does so against a plain `nc` listener too, so it is a client
bug. An earlier version of this file read that as "`-h HOST -p PORT` crashes" and
concluded the real client was unusable — it is not. `-h localhost` works, and
still resolves to loopback only.

`tests/server/whois/` is declared in `tests/server/mod.rs` and runs.
