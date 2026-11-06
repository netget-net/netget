# The 1 November "regressions" were one draw each (6 November 2026)

llama3.1:8b throughout. The question: after master gained W3 (merge `90cbc5846`:
`notify_operator` withheld beside wire answers, `set_`/`append_connection_memory` offered on
connection events, `key: value` memory lines, client history as "you did:"), three cases in
protocols W3 did not touch went from passing to failing in every run at seed 42
(`../2026-11-01-weak-spots/`):

- `dict/unknown-word` 5/5 → 0/5 (551 "Unknown database strategy")
- `prometheus/latency-histogram` 5/5 → 0/5 (bucket samples with `le` and no `_bucket` suffix)
- `lmtp/deliver-local` 10/10 → 5/10 (the one mailbox the instructions name refused)

## Bisect: W3 is the trigger

`lmtp` has an eval suite only on the W5 branch, so the bisect pair is that branch merged with
the commit before W3 (`0fbdcc7b1` + `c898adbcb`) and with W3 (`5fe498dea`, which merged
`90cbc5846`). The two trees differ by exactly W3's diff (147 files, same line counts).

| Tree | seed | dict/unknown-word | prometheus/latency-histogram | lmtp/deliver-local |
|---|---:|---:|---:|---:|
| W5 + pre-W3 (`bisect/pre-w3-seed42/`) | 42 | 5/5 | 5/5 | 5/5 |
| W5 + W3 (`bisect/w3-seed42/`) | 42 | 0/1 | 0/1 | 0/1 |
| W5 + pre-W3 (`bisect/pre-w3-seed1/`) | 1 | 0/1 | 0/1 | 0/1 |

The last row is the whole finding in one line: **the tree before W3 fails all three cases too,
at seed 1.**

## Why: one seed for every run made five runs one sample

The harness passed the same `--llm-seed` to every run, and none of these prompts carries
anything that differs run to run (no port, no connection id, no random query id), so five runs
were five identical draws. A W3 prompt change of a few hundred characters moved the seed-42
draw for each case from one side of the line to the other.

The prompts were recorded through a proxy between NetGet and Ollama (`scripts/recproxy.py`)
and replayed unchanged over twenty seeds (`scripts/replay.py`; the seed-42 replay reproduces
the harness's answer byte for byte, 551 included). Passes out of 20, seeds 1-20:

| Prompt | dict/unknown-word | prometheus/latency-histogram | lmtp/deliver-local (RCPT) |
|---|---:|---:|---:|
| before W3 | 12 | 15 | 6 |
| with W3 | 11 | 16 | **16** |

No regression; lmtp is markedly better with W3. Scoring: dict passes on code 550/552 or an
empty definitions list (what `dict(1)` prints as "No definitions found"), prometheus on a
`_bucket` suffix, lmtp on `accept: true`. `replay/tallies.txt` and `replay/logs/` have every
seed's verdict and every failing reply.

### Which part of W3, if any

Variants of the W3 prompt, each changing one thing (`scripts/variants.py`), same seeds:

| Variant | dict | prom | lmtp | sum /60 |
|---|---:|---:|---:|---:|
| before W3 | 12 | 15 | 6 | 33 |
| with W3 | 11 | 16 | 16 | 43 |
| W3, action list reverted (`show_message` back, no connection memory) | 14 | 17 | 20 | 51 |
| W3 without the connection-memory actions | 15 | 19 | 8 | 42 |
| W3 with `notify_operator` listed again | 9 | 19 | 19 | 47 |
| W3, network instructions reverted | 13 | 17 | 13 | 43 |
| W3, memory action descriptions/examples reverted | 13 | 16 | 17 | 46 |
| W3, memory partial reverted | 7 | 15 | 10 | 32 |
| W3, protocol actions listed before the common ones | 7 | 13 | 13 | 33 |
| W3 without connection memory, protocol actions first | 12 | 17 | 10 | 39 |

At 20 draws a case's rate moves by ±4 between prompts that should not matter to it, and no
variant moves all three cases the same way. Removing the connection-memory actions — the
change the regression pointed at — helps dict and prometheus and costs lmtp 8, net −1.
Listing the protocol's actions first is worse in every case. Nothing here justifies
withdrawing a W3 change, so none is withdrawn; W3's own measured wins (the BBS greeting reaching
the peer, no shared-memory leak) are left as they are.

## What was changed

1. **The harness gives each run its own seed** (base + run − 1), so N runs are N draws and a
   rerun still reproduces every one. This is the root cause of the false alarm.
2. **Prometheus reads a histogram sample with `le` and no suffix as a bucket.** All four W3
   failures in the twenty prometheus draws were exactly that shape; only a bucket carries `le`.
3. **A copied note example is sent back once.** The "login answered with nothing but
   `set_memory`" was an LDAP search (`ldap/empty-result`, seed 42, with W3): the model repeated
   the prompt back, and the parser read the reply's first JSON value — the example of
   `set_memory`, the first action listed (`users_created: alice,bob\nnext_order_id: 1043`) — as
   the whole answer. Nothing reached the peer; the search failed closed
   (`decision=fail_closed_no_action`). Over seeds 1-20 the same prompt answered correctly 20/20
   before and with W3, so this is rare; but the reply is unambiguous, and told once what it had
   sent (`replay/logs/correction-ldap2.txt`), the model answered the search in 10 of 10 seeds
   including 42 (`replay/logs/retry-sim-ldap2.txt`). NetGet now does exactly that when an
   answer to an event that offers protocol actions is nothing but note-keeping actions copied
   verbatim from their examples. A note the model wrote itself is still a whole answer.

## Before and after on the weak-spot protocols

The eleven weak-spot protocols plus `lmtp` and `rsync`, every case, five runs at seeds
42-46. **Both sides use the same seeds**: `before-master/` is master at `3b2527c6f` run once per
seed (one run each, which is what per-run seeds make the harness do in one invocation);
`after-branch/` is this branch merged with master (`3d367aa53`), `./run-eval.sh --runs 5`.
What master gained between the two changed no network-event prompt (its only prompt-snapshot
change is the operator prompt's docs gate), so the two sides differ by this branch's fixes.

| Protocol | Before | After |
|---|---:|---:|
| gopher | 15/15 | 15/15 |
| dict | 13/15 | 13/15 |
| gemini | 12/15 | 12/15 |
| ldap | 13/15 | 13/15 |
| prometheus | 11/15 | 12/15 |
| vault | 13/15 | 13/15 |
| bolt | 8/15 | 8/15 |
| pop3 | 10/10 | 10/10 |
| coap | 10/10 | 9/10 |
| websocket | 7/10 | 7/10 |
| nostr | 8/15 | 12/15 |
| lmtp | 9/10 | 9/10 |
| rsync | 10/10 | 10/10 |

**143/170 after, 139/170 before.** What moved, and why:

- `prometheus/latency-histogram` 1/5 → 2/5: the seed-42 answer (buckets with `le` and no
  suffix) now renders. The other three failures are a `_count` that disagrees with the `+Inf`
  bucket and per-bucket rather than cumulative counts (30, 10, …); both are still refused,
  correctly — each is a different number from the one the instruction gave.
- `ldap/empty-result` run 1 (seed 42) is the copied `set_memory` example: the correction fired
  (one `WARN … copied from the action list` in the run log) and the search was then answered
  with `ldap_search_response`. It scored a pass before as well, by accident: the fail-closed
  refusal also shows "no entries".
- `nostr` 8/15 → 12/15 is the client's clock, not the model: nak gives up on a subscription
  after about 7 s, and `before-master/` ran while two prompt-replay sweeps shared the model.
  `coap/not-found` −1 and `nostr/refuse-adverts` −1 are prompts that carry a random token or
  event id, so they are not the same draws on both sides.

Per case:

| Case | Before | After |
|---|---:|---:|
| `gopher/welcome-menu` | 5/5 | 5/5 |
| `gopher/text-selector` | 5/5 | 5/5 |
| `gopher/unknown-selector` | 5/5 | 5/5 |
| `dict/define-invented-word` | 5/5 | 5/5 |
| `dict/list-databases` | 5/5 | 5/5 |
| `dict/unknown-word` | 3/5 | 3/5 |
| `gemini/home-page` | 4/5 | 4/5 |
| `gemini/ask-for-input` | 5/5 | 5/5 |
| `gemini/not-found` | 3/5 | 3/5 |
| `ldap/single-person` | 5/5 | 5/5 |
| `ldap/two-people` | 4/5 | 4/5 |
| `ldap/empty-result` | 4/5 | 4/5 |
| `prometheus/queue-depth-gauge` | 5/5 | 5/5 |
| `prometheus/requests-by-status` | 5/5 | 5/5 |
| `prometheus/latency-histogram` | 1/5 | 2/5 (+1) |
| `vault/read-a-field` | 5/5 | 5/5 |
| `vault/list-keys` | 5/5 | 5/5 |
| `vault/missing-secret` | 3/5 | 3/5 |
| `bolt/people-by-name` | 3/5 | 3/5 |
| `bolt/count` | 0/5 | 0/5 |
| `bolt/syntax-error` | 5/5 | 5/5 |
| `pop3/message-count` | 5/5 | 5/5 |
| `pop3/message-subject` | 5/5 | 5/5 |
| `coap/text-resource` | 5/5 | 5/5 |
| `coap/not-found` | 5/5 | 4/5 (-1) |
| `websocket/echo` | 2/5 | 2/5 |
| `websocket/greeting` | 5/5 | 5/5 |
| `nostr/serve-notes` | 0/5 | 4/5 (+4) |
| `nostr/refuse-adverts` | 4/5 | 3/5 (-1) |
| `nostr/accept-film-note` | 4/5 | 5/5 (+1) |
| `lmtp/deliver-local` | 4/5 | 4/5 |
| `lmtp/refuse-unknown` | 5/5 | 5/5 |
| `rsync/list-modules` | 5/5 | 5/5 |
| `rsync/list-files` | 5/5 | 5/5 |
| **Total** | **139/170** | **143/170** |

What is still low and why, for whoever picks it up: `bolt/count` 0/5 (rows as `{"movies": 42}`
under the field `count(m)`, and the session sometimes ends before the query reaches the model),
`websocket/echo` 2/5 (a greeting instead of the echo), `prometheus/latency-histogram` (the two
refusals above), `dict/unknown-word` and `gemini/not-found` 3/5.

## Reproducing

```bash
python3 scripts/recproxy.py 11501 /tmp/rec &      # then point netget at --ollama-url http://127.0.0.1:11501
python3 scripts/replay.py /tmp/rec/00006-api_generate.req.json '"code"\s*:\s*55[02]' 1-20
python3 scripts/variants.py replay/prompts/dict-pre.txt replay/prompts/dict-w3.txt /tmp/v dict
python3 scripts/replay.py <req.json> <regex> 1-20 --prompt-file /tmp/v/dict-w3-noconn.txt
```
