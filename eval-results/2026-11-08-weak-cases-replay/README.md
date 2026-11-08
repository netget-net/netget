# The weakest eval cases, replayed over seeds (8 November 2026)

llama3.1:8b (digest `46e0c10c…a666e`) on Ollama at `127.0.0.1:11434`. Another agent had
`gemma4:31b-mlx` loaded on the same Ollama for part of both full runs, so per-call latency was
higher than in the 7 November baseline. Both full runs used the lane build flags
`--no-default-features --features mcp-stdio,mcp-http,sqlite,terminal-snapshot`. No prompt
depends on those features.

## 1. The full eval on master

`before-master/` is the harness's own output for master `795d97443`, five runs per case at
seeds 42–46, all 41 protocols: **500 of 540 runs passed (92.6%)**. The committed baseline in
`../latest.json` (488/540) predated the gearman and whois fixes, which account for 9 of the 12
runs' difference (`gearman` 4/10 → 10/10, `whois` 12/15 → 15/15). The run went through a recording proxy (`scripts/recproxy.py` in
`../2026-11-06-seed-bisect/`), so every prompt NetGet sent was captured. The harness passes no
`--ollama-url` to a real model, so `scripts/lane3-run-rm.sh` ran the test binary directly with
`CARGO_BIN_EXE_netget` pointing at a wrapper that adds `--ollama-url` for the proxy.

Failing cases, worst first (passes of 5): `bolt/count` 0; `prometheus/latency-histogram` 2;
`dict/unknown-word`, `gemini/not-found`, `mysql/server-version`, `ftp/working-directory`,
`docker/ps-all-includes-stopped`, `vault/missing-secret`, `bolt/people-by-name`,
`nostr/refuse-adverts` 3; sixteen more at 4.

## 2. Replays

Each case directory (`bolt/`, `dict/`, `ftp/`, `docker/`, `prom/`) holds the captured request
(`*.req.json`), the captured prompt (`*-master.txt` or `master.txt`), each variant's spec and
prompt, the `run*.sh` that replayed them and one `tally-*.txt` per replay (one line per seed,
the actions of every failing answer, and a `TALLY` line).

Each captured prompt was replayed with only `options.seed` changed
(`scripts/lane3-replay.py <req> <prompt> <scorer> <seeds>`). The scorer reads the first JSON
value of the reply, which is what NetGet's parser executes; the scorers are in
`scripts/lane3_scorers.py`. Variant prompts are the captured prompt with exact string
replacements (`scripts/lane3-variant.py`, the `*.json` spec beside each variant). Replaying
seed 42 reproduces the harness's answer, and four requests at once gave the same answers as one
at a time. `scripts/lane3-caps.py` lists and dumps captured prompts. The scripts use `/tmp`
paths for their inputs and outputs.

### bolt/count: "It holds exactly 42 Movie nodes", `RETURN count(m) AS movies`

Two decisions fail. The login is refused on some seeds although the instruction accepts any
login; the query's column is misnamed on most.

| Login prompt (pass = `accept_bolt_login`) | count, seeds 1–20 | people-by-name, seeds 1–20 |
|---|---:|---:|
| master | 18 | 16 |
| `password_configured` removed from the event | 17 | 15 |
| `answer_with` says no password is configured, so none is wrong | 17 | 18 |
| both | 18 | 17 |

No login variant moves beyond the ±4 that prompts which should not matter already show, so the
login is unchanged. The seed-42–46 runs happened to draw three refusals in five.

| Query prompt (pass = fields exactly the column and the right rows) | count | people-by-name |
|---|---:|---:|
| master ("fields are the names after RETURN") | 3 | 17 |
| **q1: "fields are exactly [\"movies\"] - the column names after RETURN, an AS alias where there is one -"** | **15** | **18** |
| q2: q1 plus "each record an array with one value per field" | 12 | 20 |

On master 13 of the 20 count answers named the column `count(m)` or `count`. Under q1 every
answer named it `movies`; its five strict failures wrote the value as the string `"42"`, which
cypher-shell prints and the eval accepts. The two people-by-name failures under q1 had no JSON at
all. q1 is the change made: `actions::return_columns` reads the columns off the final top-level
`RETURN`, and the hint names them.

### dict/unknown-word: "You only know words that begin with the letter q", `DEFINE * zebra`

Pass = `send_dict_error` 552, or `send_dict_definitions` with no definitions.

| Prompt | Seeds 1–40 | What the eval accepts (550 too) |
|---|---:|---:|
| master | **0** (25 × 550, 10 × 551, 5 × 501) | 25 |
| v1: `send_dict_error`'s code list starts with 552 and says `*` and `!` are never unknown | 32 | — |
| **v2: the DEFINE event says a word with no definition is 552** | **38** | **38** |
| both | 30 | — |

550 is the error action's example code. dict(1) prints "No definitions found" after a 550 as
well, which is why the eval passed 3 of 5, but 550 tells the client `*` is an unknown database.
v2 is the change made. Regression: defining a known word (`dict/define-invented-word`'s prompt)
stayed at 20 of 20 under v2.

### ftp/working-directory: the PASS after a 331

Both failing runs answered `PASS` with the `331` they had just sent for `USER`, word for word, so
the client never logged in. Pass = a `230`.

| PASS prompt | after seed 43's 331, seeds 1–40 | after seed 42's 331, seeds 1–20 |
|---|---:|---:|
| master ("230 if the login succeeds, 530 if it does not") | 25 | 14 |
| f1: "... The password has now been sent, so never 331 again" (seeds 1–20) | 17 | — |
| **f2: "one reply to the password: 230 ..., 530 ... - not the 331 that answered USER"** | **35** | **18** |

f2 is the change made.

### docker/ps-all-includes-stopped

Not a description problem: the executor refused `"created": ""`, which the model writes for
every example field the instruction does not mention, and the whole `docker ps -a` failed with
it. 3 of 20 replayed answers carry a blank `created` or `id`. A blank value now reads as the
field left out.

### prometheus/latency-histogram: investigated, unchanged

"40 requests so far, 30 of them under 0.1s" with buckets at 0.1, 0.5 and 1. Pass = an
executor-valid histogram with `le=0.1` 30 and a total of 40. Master, and two variants spelling
out that buckets are cumulative (in the parameter text, and in the event description), scored
**0 of 20** each: the model either copies the example's 900/1010/1030 or writes per-bucket counts
(30, 10, 0). The eval's 2 of 5 passes are valid histograms with the example's numbers. No text
change was found that helps, so none is made.

After the eval below, both other seeds' PASS prompts (45 and 46, whose runs failed on the branch)
were replayed too: master 13 and 11 of 20, f2 18 and 18. Over the four histories f2 answers 230
on 89 draws in 100 and master on 63.

## 3. The eval with the changes

`after-branch/` is the harness's output for the branch at `9f7d41a58` (master `c2630e4fb` plus
the four changes), run the same way, also through the proxy: **508 of 540 (94.1%)**, against
500 on master. It is the new `../latest.json` and `../EVAL_RESULTS.md`.
`scripts/lane3-compare.py before-master/latest.json after-branch/latest.json` prints the table.

| Case | Master | Branch | |
|---|---:|---:|---|
| `bolt/count` | 0/5 | 2/5 | both query answers named `movies`; seeds 43, 45, 46 still lose the login |
| `bolt/people-by-name` | 3/5 | 4/5 | seed 43 loses the login |
| `dict/unknown-word` | 3/5 | **5/5** | every DEFINE answered 552 |
| `docker/ps-all-includes-stopped` | 3/5 | **5/5** | |
| `ftp/anonymous-login` | 4/5 | 5/5 | |
| `ftp/working-directory` | 3/5 | 3/5 | seeds 43 and 44 now pass; 45 and 46 repeat USER's 331 (see the replay above) |
| `dns/a-record`, `dns/nxdomain` | 4/5 each | 5/5 each | untouched; a different draw |
| `http/permanent-redirect` | 5/5 | 4/5 | untouched; seed 42 answered with no actions |
| `nostr/refuse-adverts` | 3/5 | 2/5 | untouched; the refusal text differs |
| **Total** | **500/540** | **508/540** | |

Every other case scored the same. The untouched cases that moved are run-to-run variation: their
action and event text did not change, but some prompts carry per-run values (a port in a URL, a
query id), and the two runs had different load on Ollama. Net of those (+2 −2), the four changes
account for the +8.
