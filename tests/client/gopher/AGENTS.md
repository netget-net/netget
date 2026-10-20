# Gopher client tests

`e2e_test.rs` — **4 tests, 10 mocked LLM calls**, no external endpoint, no
external binary. Runs in well under a second.

```bash
./cargo-isolated.sh test --no-default-features --features gopher \
    --test client -- gopher --test-threads=100
```

(`--test` takes a *target* name, so it is `--test client -- gopher`, not
`--test client::gopher::e2e_test`.)

## The peer, and what it proves

The server on the other end is **NetGet's own Gopher server**. Every wire
assertion here is therefore *same-project evidence*: it shows the two halves of
this repo agree with each other, not that either agrees with RFC 1436. The root
`AGENTS.md` names that class ("circular: the peer is the same crate the server
frames with") and it is the reason the client is rated `Experimental`. See
`src/client/gopher/AGENTS.md` for what would earn `Beta` — a third-party daemon
on loopback, hard-failing when absent, never a `SKIP:`.

It is still worth doing, because everything on **this client's own side of the
socket** is genuinely under test: menu lines becoming structured fields, a
document's doubled leading dots coming back to one, a type-7 query reaching the
wire after a tab, a type-3 item recognised whatever type was asked for — and the
one that matters most, a menu item the model picked being fetched on a **new
connection**, because Gopher closes after every reply.

## Test 1 — `browsing_follows_a_menu_item_to_a_document_and_then_to_a_refusal`

The iterative path, and the reason this suite exists. Four client turns:

1. opening turn (`event: None`) → fetch the root menu
2. `gopher_menu_received` → **follow the `0` item from the menu**
3. `gopher_document_received` → ask for `/nope`
4. `gopher_error_received` → `disconnect`

Each step needs the previous step's reply to have been raised as an event *and*
acted on. A follow-up executed through a path that raises no event gives the
model exactly one turn and then leaves it deaf — the `elasticsearch`/`http2`
defect. Delete the `Self::run_actions(...)` call in `notify` and this test fails
at step 2 with the mock reporting zero calls for `gopher_document_received`.

**The follow-up copies the menu item's `selector`, `host`, `port` and
`item_type` back verbatim** rather than hardcoding `/about.txt`. That is
deliberate: it is the contract the event promises the model, and it only holds
if the tab-separated line really became fields. `port` is asserted against the
server's actual ephemeral port, which only round-trips if the item carried it.

Also asserted here: the doubled leading period is undone (`.hidden line…`
present, `..` absent), the terminating `.` line never reaches the model, the
trailing newline does not leave a fourth blank line (`line_count == 3`), and a
**type-3 reply to a document request** raises `gopher_error_received` — the one
place the reply's own bytes overrule the requested item type.

## Test 2 — `a_type_7_search_sends_the_query_after_a_tab_and_parses_the_results`

The assertion that matters is on the **server's** view of the request: the query
has to arrive as `search_query`. NetGet's Gopher server omits that key entirely
for a plain fetch — its absence is meaningful, which its own CLAUDE.md says — so
the key being present is the proof that a tab was written. Asserting on the
client's own outgoing string would prove nothing about the wire.

## Tests 3 and 4 — the parser alone

No sockets, no model, no LLM budget. `parse_gopher_reply` is pinned on the six
outcomes the requested-item-type decision produces, including the two that are
easy to get wrong:

- a document whose first line starts with the digit `3` but has **no tab** is
  prose, not an error item (the type-3 check is structural, not a content sniff);
- a menu request whose reply contains no parseable menu line falls back to
  `Document` rather than reporting an empty menu.

These are the cheapest tests here and the ones most likely to catch a
regression, because the e2e pair only ever exercises well-formed replies.

## Mocking

One in-process mock model serves **both** halves — the client and the NetGet
server it talks to. Rules are first-match-wins, and the ordering carries weight:

| # | Rule | Calls |
|---|---|---|
| 1 | `on_event("gopher_request")` — the server, branching on `selector` inside one generator | 3 / 1 |
| 2–4 | `on_event("gopher_menu_received" \| "gopher_document_received" \| "gopher_error_received")` — the client | 1 each |
| last | `on_prompt_containing("No network event yet: the client has just started")` — the client's opening turn | 1 |

**The server is one rule branching on the selector, not three rules on
`gopher_request`.** Two rules on the same event with no way to tell them apart
is the most common mocking mistake in this repo: the first answers every
occurrence and the second reports zero calls.

**The opening turn is matched on the prompt, not the instruction.** The mock
extracts `context.instruction` from the *last user message*, and for a client's
`event: None` call that message is the literal string `Waiting for
instructions` — the system prompt, where `Your instruction:` actually lives, is
never searched. So `on_instruction_containing("<the client's instruction>")`
matches nothing at all here. `on_prompt_containing("No network event yet: the client has just started")`
is the reliable form, and it must come **last** so every event rule is tried
first.

The server's menu has to name the port it actually bound, which is not known
until after the mock is built. An `Arc<AtomicU16>` is captured by the generator
and stored once the server is up; nothing reads it before the client's first
request, which is long after.

Both e2e tests finish with `mock.wait_for_expectations(30)` and then
`mock.verify_calls()`. Waiting on the expectations waits on the exchange — the
last LLM call an exchange provokes is exactly what the expectations describe —
which is what a fixed `sleep` fails to do under `--test-threads=100`.

## Budget

7 + 3 + 0 + 0 = **10** calls, at the guideline ceiling. Adding a case belongs in
test 1's chain (it already has depth to spare against `MAX_FOLLOWUP_DEPTH` = 6)
or, better, in the parser tests, which cost nothing.

## Not covered

- The command channel (`AppState::send_to_client`). Other clients have a
  dedicated `command_channel_test.rs`; this one does not yet. The injected path
  shares `perform_fetch`/`notify` with the model path, so the wire behaviour is
  exercised — but the *reply-before-notify* ordering and the `Sent`/`Rejected`
  outcomes are not.
- `MAX_FOLLOWUP_DEPTH` being hit, `MAX_REPLY_BYTES` truncation, and a fetch
  against a host that refuses the connection.
- Anything Gopher+, TLS, or binary — none of it is implemented.
