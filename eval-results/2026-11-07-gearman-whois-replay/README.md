# gearman/unknown-function-fails and whois/no-match, replayed over seeds (7 November 2026)

llama3.1:8b (digest `46e0c10c…a666e`) on Ollama 0.40.15. In the per-run-seed baseline
(`../EVAL_RESULTS.md`, seeds 42–46), `gearman/unknown-function-fails` scored 0/5 and
`whois/no-match` 2/5. Each prompt was captured from a master build (`c58e47f99`; `src/` matches
`9df0a08ea`) through `../2026-11-06-seed-bisect/scripts/recproxy.py`, with the eval's own
instruction and client: `gearman -f translate hello`, `printf 'nothing.invalid\r\n' | nc`. Each
prompt was then replayed with only `options.seed` changed. The seed-42 replay reproduces the
harness's answer (`send_gearman_error unknown_function …`, and a record holding only
`Domain Name: nothing.invalid`).

`prompts/` has the four captured requests. `scripts/mkvariants.py`, `mkwhois.py` and
`mkoctober.py` derive the variant prompts from them. `scripts/replay2.py <req> <prompt> <mode>
<a-b>` scores the first JSON value of each reply, which is what NetGet's parser executes.
`tallies/` has one line per seed. The `unk-*.txt` files were scored with the seed-bisect
`replay.py` and a regex that requires the first outcome type to be `fail_gearman_job` or
`send_gearman_exception`. The `s2-`, `s3-` and `s4-` files used `replay2.py`.

## Gearman: told "only reverse; any other function must fail", asked for `translate`

Pass means the first outcome action is `fail_gearman_job` or `send_gearman_exception`. The
client did not enable exceptions, so both reach it as `WORK_FAIL`, which prints "Job failed".

| Prompt | Seeds 1–20 | Seeds 21–40 |
|---|---:|---:|
| master | 4 | 2 |
| master with the October (`3e2d24bd`) shared sections around the same gearman actions (`mkoctober.py`; approximate) | 5 | — (1/5 at 42–46) |
| `send_gearman_error`'s `code` no longer names `unknown_function` | 5 | — |
| … and its description says it is for a server condition, not an unknown function, and that the client exits 0 on it | 14 | 15 |
| … and `fail_gearman_job`'s description reworded | 9 | — |
| … and the event description names `fail_gearman_job` for an unknown function | 10 | — |
| only the event description changed | 7 | — |
| **`send_gearman_error` not offered on the event** | **18** | **19** |
| not offered, plus the reworded fail and event descriptions | 15 | — |

On master, 33 of the 40 answers were `send_gearman_error`, and one was empty. The October
framing scores about the same as master, so October's 5/5 at seed 42 is not evidence that the
shared prompt regressed. The case was marginal on both. Not offering the action is the only
change that moves it decisively, and it is the change made. The gearman CLI exits 0 on
`ERROR`, so offering it as a job's answer was a trap regardless of the prompt.

For a regression check, the same captured instruction was asked for `reverse stressed`. Pass is
stricter than the eval here: `complete_gearman_job`'s result must contain "desserts". The eval
also accepts a `WORK_DATA` carrying it, and most of the failures below are that shape. Scores
out of 20: master 11, not offered 9, not offered plus the reworded text 11, every description
change 10, the description changes without the event text 12. That is no movement beyond the
±4 that prompts which should not matter already show (see the seed-bisect README).

## WHOIS: told "Report that no match was found for any domain ending in .invalid. Answer anything else with an ordinary record."

| Prompt | `nothing.invalid` no match, seeds 1–20 | seeds 21–46 | `example.com` record, seeds 1–20 | seeds 21–46 |
|---|---:|---:|---:|---:|
| master | 19 | 22 | 20 | 26 |
| `send_error` described as the no-record answer, with `No match for "example.invalid"` quoted in the description | 20 | — | **17** | — |
| … and its example message is `No match for "example.invalid"` | 20 | 26 | 20 | 26 |
| … description plus `send_whois_record` described as "for a domain that has one; for a query with no match use send_error" | 20 | — | 20 | — |
| **all three** | **20** | **26** | **20** | **26** |

Master fails on 5 of 46 seeds, and three of them are 42, 45 and 46, which is why the baseline
read 2/5. The rewording alone, with the old `Domain not found in database` example, answered
`example.com` on three seeds with `No match for example.invalid`, copied from the description.
Changing the example as well removed that. All three changes are made.

## The eval with both changes

`eval-after/` is the harness's own output for `gearman` and `whois`: five runs per case at seeds
42–46, from a build of this branch with the lane flags `--no-default-features --features
mcp-stdio,mcp-http,sqlite,terminal-snapshot`. Neither prompt depends on those features. Before is
the per-run-seed baseline in `../latest.json`, at the same seeds.

| Case | Before | After |
|---|---:|---:|
| `gearman/reverse-text` | 4/5 | 5/5 |
| `gearman/unknown-function-fails` | 0/5 | **5/5** |
| `whois/registrar-line` | 5/5 | 5/5 |
| `whois/registrant-and-status` | 5/5 | 5/5 |
| `whois/no-match` | 2/5 | **5/5** |
| **Total** | **16/25** | **25/25** |
