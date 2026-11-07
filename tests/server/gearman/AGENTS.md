# Gearman tests

Run everything:

```bash
./cargo-isolated.sh test --no-default-features --features gearman --test server -- gearman:: --test-threads=100
```

## Strategy

The evidence is `real_client_test.rs`, which points the gearmand project's own `gearman` and
`gearadmin` at the server and asserts on what they printed and how they exited (`gearman` exits 1
on `WORK_FAIL`). One exchange is recorded through a relay and read by Wireshark's `gearman`
dissector. Everything else is NetGet reading bytes NetGet wrote.

Most suites start the server **in process** through `ServerForm` with a static, Python script or
`manual` handler and a dead model endpoint. `e2e_test.rs` and one case in `real_client_test.rs`
use the spawned binary with the mock model.

## Files

| File | What it proves | Model calls |
|---|---|---|
| `common.rs` | helpers: in-process server, a raw peer reading packets (`read_response`) and admin lines, `WORKER_SCRIPT` (`reverse` with status + data + result, `describe` echoing priority/fg-bg/bytes, `explode` raising, anything else failing), the recording relay | — |
| `real_client_test.rs` | `gearman -f reverse` prints `partial:`, `dlrow olleh` and `50% Complete`, and the pcap oracle reads the exchange clean; `-I`/`-L`/default reach the model as high/low/normal; an unknown function and an exception (no exceptions option) exit 1 `Job failed`; `-b` prints nothing and the job still runs; `--ping`; `gearadmin --status` shows a parked job as `reverse 1 1 0`, `--workers` `.`, `--server-version` `netget-…`, and `GET_STATUS` from another connection sees it running; `gearman -w` is refused rather than left waiting; and a **mocked model** writes a result. Fails, never skips, without the binaries. | 2 (mocked case) |
| `e2e_test.rs` | mocked model: `SUBMIT_JOB_HIGH` with a NUL in the workload (the model sees 18 bytes, 3 words), `H:netget:1`, `WORK_STATUS` from an action naming its handle, `WORK_COMPLETE` from one that does not; `GET_STATUS` after completion is `0 0 0 0`; `OPTION_REQ exceptions` then `WORK_EXCEPTION`; NetGet's own `ECHO_RES` (NUL kept), `unknown_option`, `SET_CLIENT_ID` silence, `invalid_arguments`, `SUBMIT_JOB_SCHED` refused, the admin lines, and a `CAN_DO` refused and closed — none costing a model call | 3 |
| `wire_test.rs` | proptests: any packet round-trips with the last argument's NULs kept; any declared size past 1 MiB refused; every model answer renders and reads back for any handle and payload; the parsers never panic. Tables: all six submit variants' priority/background, argument errors, worker/unsupported classification, `ERROR` validation, the admin protocol (a tab in a function name cannot add a column) | 0 |
| `connection_bounds_test.rs` | exactly 1 MiB answered; a header declaring 1 MiB + 1 refused `ERROR too_large` with 48 KiB of unread body behind it, then EOF, and no handler; 1024-byte admin line answered, 1025 and a newline-less flood refused `ERR LINE_TOO_LONG`; non-`\0REQ` closed unanswered; first-byte deadline; idle deadline (a different number); a `manual`-parked job outlives both; the 257th connection closed with no bytes, slot returns | 0 |
| `llm_failure_test.rs` | dead backend → `WORK_FAIL` (and a fixed `WORK_EXCEPTION` text once exceptions are on) + `decision=fail_closed_llm_error`, no leaked error text; empty handler → `WORK_FAIL` + `model_silent`; progress only → progress then `WORK_FAIL` + `fail_closed_unfinished`; an answer for another handle → `WORK_FAIL` + `fail_closed_mismatched_reply`; an `ERROR` from a rule sent + `model_reject`; the job event offers the model no `send_gearman_error` while the sync set keeps it; data after `WORK_COMPLETE` dropped. Each checks, with an `ECHO_REQ`, that nothing follows the outcome. | 0 |
| `peer_inject_test.rs` | a parked job completed from `send_to_peer` with its `job_handle`; `close_connection` reaches the client as EOF | 0 |

## How each guard was shown to matter

Removed together in one mutated build, then restored (`linger` separately):

| Guard removed | Test that failed, and how |
|---|---|
| the declared-size check in `parse_header` | `a_packet_of_exactly_the_limit…` (no answer in 10 s), the proptest |
| both admin line checks | `an_admin_line_of_the_limit…` (1025 bytes answered `UNKNOWN_COMMAND`) |
| read deadlines (→ 3600 s) | `a_peer_that_says_nothing…`, `an_answered_peer…` (never closed) |
| the connection cap (×1000) | `the_connection_past_the_cap…` |
| the handle check | `an_answer_for_another_job…` (`WORK_COMPLETE H:elsewhere:9` reached the client) |
| the exception→fail rule | real client: `gearman -f explode` exited **0** |
| the closing `WORK_FAIL` (silent and unfinished answers) | both tests: no outcome within 30 s — the client would wait forever |
| closing after a worker packet | e2e: the connection stayed open |
| `linger` | `a_packet_of_exactly_the_limit…`: `ConnectionReset`, 4 of 4 runs |

## Notes

- `gearman`/`gearadmin` are at `/opt/homebrew/bin` here (`brew install gearman`); CI's
  `registry-audit` installs Ubuntu's `gearman-tools` and runs `gearman::real_client_test`.
- `gearman` prints `WORK_DATA` and `WORK_COMPLETE` payloads back to back with no separator, and
  the `WORK_STATUS` percentage after them.
