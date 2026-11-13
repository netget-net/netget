# Two cases wording could not move, fixed in structure (13 November 2026)

llama3.1:8b (digest `46e0c10c…a666e`, re-pulled into Ollama 0.40.16 for this run) on
`127.0.0.1:11434`. `../2026-11-08-weak-cases-replay/` left two cases where no change of text
helped: `prometheus/latency-histogram` (0 of 20 replayed draws produced the histogram asked for)
and the Bolt login, refused on some draws although every Bolt instruction "accepts any login".
Both are changed here in what NetGet asks for and offers, not in how it words it.

Method as in that directory: a prompt NetGet sent is captured through a recording proxy and
replayed with only `options.seed` changed (`scripts/lane3-replay.py <req> <prompt> <scorer>
<seeds>`); the scorer reads the first JSON value of the reply, which is what NetGet's parser
executes (`scripts/lane3_scorers.py`). Replaying the 8 November captures for seeds 1–20 gave the
same answer on every seed as on 8 November, so those captures are the "before". The "after"
prompts were captured from this branch's binary (`scripts/capture.sh`: the binary behind
`recproxy.py`, driven by the eval's own client, exiting by itself with `--exit-after-events`)
and differ from the "before" prompts only in the lines this change touches.

## 1. `prometheus/latency-histogram`: NetGet adds the buckets up

"Report request latency in seconds as a histogram with buckets at 0.1, 0.5 and 1 second; 40
requests so far, 30 of them under 0.1s." The exposition format's `_bucket` lines are running
totals; the model states per-bucket counts (30, then 10, then 0) or copies the example.

The change: a histogram family (or one entry of its `samples`) may give `bucket_counts` — each
upper bound mapped to the observations in that bucket alone — with `count` and `sum`, and
`MetricFamilies::parse` turns it into the cumulative `_bucket` lines, a `+Inf` bucket and
`_count` (`src/server/prometheus/exposition.rs`, `histogram_series_samples`). `send_metrics`'s
parameter text and example show that form; cumulative `_bucket` samples still parse.

Scorer `prom_hist_ok2`: a histogram whose cumulative buckets include 0.1, 0.5 and 1, with 30 at
0.1 and a total of 40, read from either form (a `count` below the buckets' sum is refused by
NetGet and scored a miss).

| Prompt (`prom/`) | seeds 1–40 |
|---|---:|
| master (`master.txt`, cumulative `_bucket` samples in the example) | **0** |
| branch (`branch.txt`, `bucket_counts` in the example) | **35** |

On master the answers are the 8 November ones: per-bucket counts in cumulative samples
(refused as non-cumulative) or the example's 900/1010/1030. On the branch 35 answers are
`{"0.1": 30, "0.5": …, "1": …}` with `count` 40. The five misses: two copied the example's
900/110/20 under a `count` of 40 (refused: the count is below the buckets' sum), one put
`bucket_counts` inside a `samples` entry with the example's counts (that shape is now accepted;
its numbers are still refused), one wrote bare values, and one (seed 9) is a valid histogram
with 20 rather than 30 under 0.1s.

## 2. The Bolt login: only the two answers are offered

Every Bolt eval instruction begins "Act as a Neo4j graph database that accepts any login".
`bolt_authenticate` offered seven actions: `accept_bolt_login`, `reject_bolt_login`,
`close_connection`, and the memory, connection-memory and log actions every network event
carries, with the prompt's section on memory. Scorer `bolt_login_accept`: the first wire action
is `accept_bolt_login`.

| Login prompt (`bolt/`) | count | people-by-name | syntax-error |
|---|---:|---:|---:|
| master | 36/40 | 34/40 | 36/40 |
| p1: `answer_with` quotes the instruction's login sentence | 38/40 | 39/40 | — |
| n1: memory, log and close actions removed (hand-made) | 40/40 | 40/40 | — |
| np1: both | 40/40 | 40/40 | — |
| **branch (captured)** | **40/40** | **40/40** | **40/40** |

Master's refusals copy `reject_bolt_login`'s example message, invent one ("The server does not
have a configured password"), or answer with `set_memory` alone. The change:
`EventType::decision_only` (`src/protocol/event_type.rs`). `call_llm` offers such an event its
own actions and no common ones, and the prompt drops the memory section and the two memory
lines in the event instructions (`prompts/network_request/`); `bolt_authenticate` is declared
with it and no longer offers `close_connection`. Prompts for every other event are unchanged
(the captured branch query prompt is byte-identical to master's).

The syntax-error column is the count case's prompt with that case's instruction substituted
(`bolt/mk_syntax.py`; the instruction is the only per-case text in a login prompt). Control for
the other direction — that a narrower prompt does not make the model admit everyone — is the
same substitution with "accepts only the user alice; refuse every other login" for user
`neo4j`: refused 40 of 40 on master and 40 of 40 on the branch (`tally40-login-onlyalice-*`).

## Files

`prom/` and `bolt/` hold the captured requests (`*.req.json`), prompts (`*.txt`) and one
`tally40-*.txt` per replay (a line per seed, the actions of every miss, and a `TALLY` line).
`bolt/run-v1.sh` and `bolt/run-branch.sh` ran the Bolt replays; `scripts/bolt_variants.py`
made n1, p1 and np1. The scripts use `/tmp/netget-r3-l4/` paths for their inputs and outputs.
