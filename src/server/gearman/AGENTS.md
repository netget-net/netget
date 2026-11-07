# Gearman Job Server Implementation

Gearman job server (gearmand 1.1's protocol). The model is the worker for every function:
a client submits a job, NetGet answers `JOB_CREATED` with its own handle, and the model's answer
becomes the job's progress, partial output and outcome. NetGet writes every byte of framing.

**State**: Beta (see Maturity). **Privilege**: `None` — the well-known port is 4730.
**Stack**: `ETH>IP>TCP>Gearman`. **Feature**: `gearman` (no dependencies).

## Library choice

None. The binary protocol is a 12-byte header and NUL-separated arguments, the admin protocol
is lines; `wire.rs` is pure functions. No maintained Rust crate implements the server side.

## Files

| File | What it holds |
|---|---|
| `mod.rs` | accept loop, the in-flight job table (`Jobs`), the session loop, `run_job` (the model's answer → packets), `Framer` (packets and admin lines on one connection) |
| `wire.rs` | `parse_header`, `encode`/`response`, `split_args`, `parse_request`, the packet renderers, `read_response`, `error`, the admin parser and renderers |
| `actions.rs` | the `Protocol`/`Server` impls, the seven actions (six offered on the job event), `Work`, the `gearman_job_submitted` event |

## Spec subset

A leading `\0` byte says a binary packet follows; anything else is an admin line. One
connection may mix them.

| Request | Answered by | Response |
|---|---|---|
| `SUBMIT_JOB`, `_HIGH`, `_LOW` | NetGet, then the model → `gearman_job_submitted {function, unique_id, workload, workload_bytes, priority, background: false, job_handle}` | `JOB_CREATED`, then `WORK_STATUS`/`WORK_DATA`… and exactly one of `WORK_COMPLETE`, `WORK_FAIL`, `WORK_EXCEPTION`, `ERROR` |
| `SUBMIT_JOB_BG`, `_HIGH_BG`, `_LOW_BG` | the same, `background: true` | `JOB_CREATED` only; the model's answer is logged |
| `GET_STATUS` | NetGet, from the jobs in flight | `STATUS_RES handle known running num den` (`0 0 0 0` once a job is answered) |
| `ECHO_REQ` | NetGet | `ECHO_RES` with the same data |
| `OPTION_REQ exceptions` | NetGet | `OPTION_RES`; the connection then receives `WORK_EXCEPTION` as such |
| `OPTION_REQ` anything else | NetGet | `ERROR unknown_option` |
| `SET_CLIENT_ID` | NetGet | nothing (as gearmand) |
| worker packets: `CAN_DO`, `CANT_DO`, `RESET_ABILITIES`, `PRE_SLEEP`, `GRAB_JOB*`, `WORK_*` from a client … | NetGet | `ERROR not_supported`, then close |
| `SUBMIT_JOB_SCHED`/`_EPOCH`, reduce jobs, `GET_STATUS_UNIQUE`, unknown types, a `\0RES` packet | NetGet | `ERROR not_supported` |
| wrong argument count, empty or >512-byte function, >64-byte unique id | NetGet | `ERROR invalid_arguments` |
| admin `status` | NetGet | `FUNCTION\tTOTAL\tRUNNING\tAVAILABLE_WORKERS` per function with jobs in flight, then `.` |
| admin `workers` | NetGet | `.` — no worker connections exist; the model is not one |
| admin `version` | NetGet | `OK netget-<version>` |
| admin `maxqueue`, `shutdown` | NetGet | `ERR NOT_SUPPORTED …` — they change server state |
| any other admin line | NetGet | `ERR UNKNOWN_COMMAND Unknown+server+command` |

**Worker connections are refused on purpose.** The model is the worker; a real worker that
registered here would sleep forever waiting for a job NetGet never queues for it. The `gearman
-w` CLI reports `GEARMAN_ERROR` and exits.

**What NetGet keeps**: the jobs in flight (handle, function, last progress) for `GET_STATUS`
and admin `status`, and a per-server handle counter (`H:netget:<n>`). A job leaves the table
when its answer is written. Nothing is queued and nothing is stored.

## What the model sees and controls

| Action | Renders |
|---|---|
| `complete_gearman_job {result}` | `WORK_COMPLETE handle result` — the `gearman` CLI prints the result |
| `fail_gearman_job` | `WORK_FAIL handle` — the CLI prints `Job failed` and exits 1 |
| `send_gearman_status {numerator, denominator}` | `WORK_STATUS` (numerator ≤ denominator) |
| `send_gearman_data {data}` | `WORK_DATA` — printed ahead of the result |
| `send_gearman_exception {text}` | `WORK_EXCEPTION`, or `WORK_FAIL` if the client did not enable exceptions (gearmand's rule) |
| `send_gearman_error {code, text}` | `ERROR code text` — code `[A-Za-z0-9_]{1,64}`, text without NUL. **Not offered on `gearman_job_submitted`**; static rules and the dashboard can send it |
| `close_connection` | close after the answer |

**`ERROR` is not offered to the model as a job's answer.** The `gearman` CLI exits 0 on an
`ERROR` packet, so a job refused that way reads as a success. When ERROR was offered (its `code`
parameter even named `unknown_function` as an example), llama3.1:8b, told "only reverse; any
other function must fail", answered `translate` with `send_gearman_error` on 33 of 40 seeds
(seeds 1–40, the captured prompt replayed). With the action removed from the event, it failed
the job on 37 of 40. With the descriptions reworded and the action still offered, it failed the
job on 29 of 40. `send_gearman_error` stays in `get_sync_actions()`, so a static rule may name it
(`llm_failure_test.rs`), and so may an action sent from the dashboard.

Every job action takes an optional `job_handle`. Answering the event, it may be omitted: the
executor returns the answer structured (`ActionResult::Custom "gearman_work"`) and the loop
renders it with the job's handle. Given, the executor renders the whole packet — which is what a
`[ message ]` injected from the dashboard needs — and the loop checks the handle is the job's.

### The loop enforces one outcome per foreground job

* Packets are written in the model's order until the first outcome (`WORK_COMPLETE`, `WORK_FAIL`,
  `WORK_EXCEPTION`, `ERROR`); anything after it is dropped and logged.
* An answer naming another handle, or a packet that is not a job answer →
  `WORK_FAIL`, `decision=fail_closed_mismatched_reply`.
* Progress without an outcome → the progress, then `WORK_FAIL`,
  `decision=fail_closed_unfinished` — the client would otherwise wait forever.
* Nothing at all → `WORK_FAIL`, `decision=model_silent`.

## Failure behaviour

`FailureMode::Answers`. A backend failure on a foreground job answers `WORK_FAIL` (the CLI exits
1), or `WORK_EXCEPTION` with the fixed text `job server backend unavailable` / `… at capacity` for
a client that enabled exceptions; `decision=fail_closed_llm_error category=…`. `ERROR` is **not**
used for failures: the `gearman` CLI exits **0** on an `ERROR` packet (measured), so it would read
as success. A model `WORK_COMPLETE` is `decision=model_answer`; a model fail/exception/error is
`decision=model_reject`. Background jobs write nothing after `JOB_CREATED` whatever happens; the
decision is logged with `background=true`. No error text reaches the peer.

## Bounds

| Bound | Value | Override | Why |
|---|---|---|---|
| `MAX_PACKET_BYTES` (= `max_inbound_bytes`) | 1 MiB | — | gearmand has no small limit because it queues workloads for workers; here the workload is a model prompt. Judged from the header's declared size before allocation; over it: `ERROR too_large`, close, `decision=fail_closed_too_large`. |
| argument count | per packet type | — | `split_args` splits on the first `n − 1` NULs only; the last argument keeps its own, so a body of 65,536 NULs is three arguments, not 65,537. |
| function / unique | 512 / 64 bytes | — | libgearman's own `GEARMAN_FUNCTION_MAX_SIZE` and `GEARMAN_MAX_UNIQUE_SIZE`. |
| `MAX_ADMIN_LINE` | 1024 incl. LF | — | Over it, or 1024 bytes with no newline: `ERR LINE_TOO_LONG`, close. |
| `FIRST_BYTE_TIMEOUT` | 300 s | `first_byte_timeout_secs` | The CLI writes at once; 300 s is the `manual` window for a NetGet TCP client parked on its operator. |
| `IDLE_TIMEOUT` | 300 s | `idle_timeout_secs` | Between messages, and between reads of a message that has started. A client waiting for its job's outcome is not idle — the deadline wraps reads, not the model. |
| `MAX_CONNECTIONS` | 256 (house default) | — | The peer past the cap is closed with no bytes (a packet it did not ask for would be misread). |

A binary message whose magic is not `\0REQ`/`\0RES` is closed unanswered
(`decision=fail_closed_bad_magic`). **Every close lingers** (2 s / 64 KiB), so an `ERROR` written
just before closing over unread input is not destroyed by an RST.

## Peer handle

Registered at connect: a job parked for a human can be answered from the dashboard with an action
that names its `job_handle`, or the connection closed.

## Wireshark

`gearman` is Wireshark's own dissector (`tshark -G protocols` lists it; decode-as
`tcp.port==N,gearman`). `real_client_test.rs` runs the pcap oracle over a real `gearman`
exchange recorded through a relay, and it is clean.

## Maturity

Beta. Evidence: `tests/server/gearman/real_client_test.rs` drives the gearmand project's own
`gearman` and `gearadmin` (libgearman, C++; not linked; the server uses no Gearman library) and
asserts on what they printed and how they exited — a job's data, result and progress, the
priority each flag chose, exit 1 on failure, a background job, `--ping`, the admin `status`,
`workers` and `version` with a job in flight, a refused worker, and a result written by a mocked
model; Wireshark's own `gearman` dissector reads a recorded exchange clean. It is not
`#[ignore]`d and fails, never skips, without the binaries; CI's `registry-audit` installs
Ubuntu's `gearman-tools` and runs it. The `gearman_packet` fuzz target has run clean. Promoted
after the whole suite (28 tests) passed three consecutive runs at `--test-threads=100` and
`scripts/beta_evidence_table.py --check` stayed green with `gearman` and `gearadmin` as the
peers.

What Beta does **not** cover, and what Stable would need: `gearman` and `gearadmin` are one
implementation (libgearman) — a second independent client, such as the Python `gearman` package
or the Go `mikespook/gearman-go`, is condition 1; workers are refused rather than served.
