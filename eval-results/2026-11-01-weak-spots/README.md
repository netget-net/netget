# The eval's weak spots, measured again and repaired (31 October - 1 November 2026)

llama3.1:8b, seed 42, 5 runs per instruction, the real third-party client each case names.

- `before-head/` is master at `c7f7cc4da` (31 October), before any change here. The frozen
  baseline in `../EVAL_RESULTS.md` is older (`3e2d24bd`, early October) and several protocols
  had moved since, so it is not the "before" for this work.
- `after-branch/` is the branch with its first round of fixes, before merging master, on the
  eight protocols it changed or added (bolt's and rsync's second fixes came after it).
- `after-merged/` is the branch after all its fixes **and** a merge of master (`90cbc5846`:
  `notify_operator`, per-connection memory actions on connection events), i.e. what ships.

All three are partial runs - the eleven protocols the October baseline scored lowest, plus the two
suites added here - so the top-level `latest.json` and `EVAL_RESULTS.md`, which cover all 38
protocols, are left as they are.

| Protocol | Oct baseline | Before (HEAD) | After (merged) | What changed |
|---|---:|---:|---:|---|
| prometheus | 5/15 | 15/15 | 10/15 | nothing here; the histogram case fell 5/5 → 0/5 after the merge (see below) |
| websocket | 4/10 | 2/10 | **10/10** | greeting moved into `accept_websocket`; opened event not asked when the model answered the handshake |
| coap | 5/10 | 10/10 | 10/10 | nothing (already fixed at HEAD) |
| bolt | 8/15 | 0/15 | **10/15** | rows as objects keyed by field; query hint names the first word and whether it is a Cypher clause |
| pop3 | 6/10 | 10/10 | 10/10 | nothing (already fixed at HEAD) |
| gopher | 10/15 | 15/15 | 15/15 | nothing (already fixed at HEAD) |
| nostr | 10/15 | 0/15 | **11/15** | eval probe: nak 0.21 needs `{}` on stdin; refusal reason in the instructions' own words |
| vault | 10/15 | 10/15 | **15/15** | `send_vault_not_found` offered first, with a lookup hint |
| dict | 11/15 | 15/15 | 10/15 | nothing here; unknown-word fell 5/5 → 0/5 after the merge (see below) |
| gemini | 11/15 | 13/15 | **15/15** | a text line carrying a url keeps its link |
| ldap | 11/15 | 5/15 | **14/15** | bind says what kind of bind it is; BindResponse alone offered |
| lmtp (new) | - | - | 5/10 | new suite (smtplib.LMTP); 10/10 in `after-branch/` |
| rsync (new) | - | - | **10/10** | new suite (stock rsync); a listing merges every `rsync_modules` action (5/10 in `after-branch/`, before that fix) |

Totals: before 95/150 on the eleven; after 145/170 on all thirteen (130/150 on the eleven).

**Regressions after merging master, in protocols this work did not touch.** Before the merge,
dict and prometheus scored 15/15 (`before-head/`) and lmtp 10/10 (`after-branch/`). After the
merge, each of the following moved the same way in every run, which is what a seed-pinned
prompt change does:

- `dict/unknown-word` 0/5: `send_dict_error` 551 "Unknown database strategy" for `DEFINE zebra`
  (552 no match is the answer).
- `prometheus/latency-histogram` 0/5: the `_bucket` samples carry an `le` label but no `suffix`,
  which the renderer refuses. Reading an `le`-labelled histogram sample as a bucket would fix it.
- `lmtp/deliver-local` 0/5: alice@example.com, the one mailbox the instructions name, refused.
- `bolt/count`: the login now succeeds (it was the failure before), and the rows come back as
  `{"movies": 42}` under the field `count(m)` - an object whose key is not the field, which is
  still refused.

Read each against master's prompt changes before attributing it to a description.

**These were one draw each, not regressions.** Every run here passed the same seed and none of
these prompts varies run to run, so 5/5 → 0/5 is one sample flipping. Replayed over twenty
seeds, the same prompts score 12 → 11 (dict), 15 → 16 (prometheus) and 6 → 16 (lmtp) of 20
before and after the merge; the tree before it fails all three at seed 1. See
`../2026-11-06-seed-bisect/`, where the harness now gives each run its own seed.

**A limit of the client, not the model:** nak 0.21 gives up on a subscription after about 7 s
and on a publish after about 10 s, with no option to raise either, so a nostr run whose answer
takes longer scores `client_left_before_model_answered`.
