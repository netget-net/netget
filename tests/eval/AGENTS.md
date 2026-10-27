# `tests/eval/` — the real-model eval harness

**What it measures:** whether a real model, reading a protocol's own action
descriptions and parameter docs, can serve a plain-English operator instruction.

**Why nothing else measures that:** every other suite in this repository drives
a **mock** model whose answers the test author wrote. A mocked E2E proves the
plumbing carries a correct answer from the model to the wire. It says nothing
about whether the model can *produce* one — and "an LLM drives the protocol" is
NetGet's whole premise. Before this existed, every action description, every
`example` and every startup-parameter blurb in the tree was unmeasured.

Run it: `./run-eval.sh` (see `--help`). Output: `eval-results/latest.json` and
`eval-results/EVAL_RESULTS.md`, regenerated together.

## This is not a gate, and must not become one

`tests/eval.rs` skips unless `NETGET_USE_OLLAMA=1`. It fails only when the
**harness** could not run — no Ollama, no model, no cases compiled in, or every
attempted case erroring before the model was asked. A low score is a finding
about an action description, not a broken build, and `NETGET_EVAL_MIN_RATE`
exists for anyone who wants a floor but is off by default.

The job is `.github/workflows/nightly-eval.yml`, deliberately outside `ci.yml`
and dispatched by hand rather than run on a cron.

## How it is put together

| File | What it owns |
|---|---|
| `case.rs` | `EvalCase`, `Probe`, `Expect`, and the `Independence` label |
| `suites.rs` | the instruction sets, one function per protocol, feature-gated |
| `probe.rs` | spawning the third-party client and reading it until idle |
| `classify.rs` | turning a failed run into a named diagnosis with evidence |
| `runner.rs` | the run loop, repetitions and complete run records |
| `scoring.rs` | pure outcome scoring, including harness-error precedence |
| `report.rs` | the JSON and the Markdown |
| `probe_check.rs` | each case's own probe and `Expect`, against a **mocked** model that answers correctly after 5 s — proves the harness before the model is blamed |

The server is started by `helpers::llm_live::LiveRequestTest`, which runs
`netget --server <proto> --port N "<instruction>"` — **no model call at setup**.
So the only unpredictable step in a run is the model answering the network
event. Setup correctness is a separate question with its own tests in
`tests/llm_live/`; chaining the two would make every failure ambiguous.

## The rules a new instruction set must obey

1. **Never name an action, a parameter or an event in an instruction.** Write
   what an operator would type. The moment an instruction says
   `send_http_response`, what is under test stops being the description and
   becomes the model's ability to copy.
2. **Drive it with a real third-party client where one exists**, and label the
   evidence honestly when one does not. `Probe::client` is a real client;
   `Probe::generic` is `nc` and says so in the results. A pass carried by a byte
   pipe and a pass carried by `dig` are not the same evidence, and this repo has
   been burned by conflating them before.
3. **Never skip silently.** A missing binary is `client-missing`; a protocol no
   installed client can reach is `EvalCase::unavailable` with the reason. A skip
   that reads as a pass is the exact defect `docs/planning/PROTOCOL_QUALITY.md` catalogues in
   the rest of the suite (19 files that print `SKIP` and return `Ok(())`).
4. **Check what the client observed**, not what netget logged — except for
   one-way protocols (syslog), where `Expect::executed_action` is the only
   observable. That check sees **only netget's `Executing action` lines**, never
   the whole log, and the reason is a false pass it already produced: netget
   dumps a rejected model reply into the log verbatim, so a whole-log search
   matched `{"type": "ignore_syslog_message"}` inside a reply that had been
   *thrown away*, and syslog scored 3/3 having executed nothing. The model
   naming an action and netget running it are different events.

## Determinism: a pinned seed, and still a rate

Every run passes `--llm-seed` (default 42; `--seed` / `NETGET_EVAL_SEED`, `none`
for an unpinned run) and, when asked, `--llm-temperature` (`--temperature` /
`NETGET_EVAL_TEMPERATURE`). netget sends both in Ollama's `options` object
(`src/llm/ollama_client.rs`, `SamplingOptions`), and sends neither when the
flags are absent — `tests/llm_sampling_options_test.rs` pins that from the wire.

**A pinned seed pins the sampler, not the run.** Ollama draws the same tokens for
the same prompt, but each run's prompt carries its own client port, connection
id and, for DNS/LDAP-style protocols, a random query or message id — one
differing token changes every token drawn after it. So each instruction still
runs N times (default 3) against a **fresh netget process and a fresh server**,
the published number is passes/runs with every verdict listed, and each case
reports `verdicts_agree` (every run reached the same verdict) and
`actions_agree` (every run executed byte-identical actions). The Markdown has a
Reproducibility section with the totals. `actions_agree` undercounts by design
for anything that must echo a random id.

`--out DIR` (`NETGET_EVAL_OUT_DIR`) writes the two artefacts into `DIR` instead
of over the committed baseline — use it for a one-protocol rerun.

## Traps already paid for

Each of these cost a debugging pass and every one presented as a model failure.

- **`nc` closes the socket when its stdin reaches EOF.** Writing the payload and
  dropping the handle hangs up before the model is asked: netget logged
  `TCP received 11 bytes` and `Connection closed` 300µs apart. `Probe::generic`
  sets `hold_stdin`, and `probe.rs` streams until idle instead of calling
  `wait_with_output`.
- **macOS `whois` segfaults when `-p` follows `-h`** — exit 139, zero bytes sent.
  No argument order reaches a loopback port, so whois is driven with `nc`.
  Worth knowing because `whois` is counted among the installed real clients in
  `docs/planning/PROTOCOL_QUALITY.md`.
- **The shared helpers' Ollama checks used to be too tight to survive
  back-to-back model calls, and that is fixed.** `check_ollama_available`
  (`tests/helpers/netget.rs`) built a fresh `reqwest::Client` and gave
  `http://localhost:11434/api/tags` **2 seconds**; `ensure_model_available` did
  the same with 5. Both paid the keychain cost of building the client and the
  mDNSResponder cost of `localhost`, and both ran while Ollama was still
  finishing the previous case — five of eleven cases in the first smoke run were
  refused against a healthy Ollama. They now share one client built through
  `client_for_endpoint` against `127.0.0.1` and allow `OLLAMA_PROBE_TIMEOUT`
  (`tests/helpers/common.rs`). `runner.rs` still polls `/api/tags` first, because
  a bound is one attempt and a sweep needs a poll.
- **`./test-e2e.sh --use-ollama` was broken** and is fixed in the same pass: it
  appended `-- --use-ollama`, which libtest rejects outright
  (`error: Unrecognized option: 'use-ollama'`), so the binary exited before any
  test ran. The env var was always the mechanism.
- **The idle settle killed `ipptool` two seconds into every model call.**
  `probe.rs` calls a response complete after two quiet seconds *following the
  first byte*, and `ipptool -v` prints the request it is about to send before
  sending it — so the first byte came before the exchange, the client was
  killed mid-wait, the IPP server saw the connection drop, the model call was
  abandoned with it, and all ten runs scored `model_answered_with_no_actions`
  (0/10 in the September 2026 baseline). `Probe::until_exit()` makes a client's
  exit the only completion signal; `ipptool` uses it. The classifier now names
  this shape — asked, never answered, client gone before its own timeout — as
  `client_left_before_model_answered` instead of blaming the model.
- **The same settle cut off `ldapsearch` and `ftp`**, both of which talk between
  model calls (`ldap_bind: Success (0)` before the search; `-v` narrating each
  FTP reply). Both use `until_exit()`. And **`curl telnet://` buffers its output
  when stdout is a pipe**, so every telnet run sat for the full `--max-time`
  (233s) whatever the model did; the probe passes `-N`.
- **An exited client's last output was left in the pipe.** The loop notices an
  exit between two 250ms reads, so whatever the client wrote last — for
  `ipptool`, the whole response — could arrive after the read that timed out
  and never be read. The run then looked like a client that printed nothing
  past the request echo. The probe now drains both pipes after an exit.
- **`}}` is not a placeholder.** `copied_example_placeholder` matched any `}}`
  on an `Executing action` line, which is how every nested JSON object ends —
  an IPP attribute group or an HTTP header map was reported as a copied
  `{{…}}` template. It now requires `{{` followed by a name.
- **A `"…\n\` continuation in a Rust string eats Python's indentation.** The
  continuation drops the next line's leading whitespace, so the greenstalk
  probe raised `IndentationError` before connecting and all 15 beanstalkd runs
  scored `event_never_reached_model`. Multi-line scripts are raw strings
  (`r#"…"#`).
- **A client that writes to stderr before the exchange is killed by the
  settle.** ignition (Python's `CryptographyDeprecationWarning` during the TLS
  handshake) and cypher-shell (the JVM's `ThreadPriorityPolicy` warning at
  startup) each printed a first byte and then waited for the model; two quiet
  seconds later the probe killed them, and gemini and bolt scored 0/15 each as
  `client_left_before_model_answered`. Both use `until_exit()`, and both give up
  on their own well inside the probe timeout (ignition's `timeout=230`,
  cypher-shell once the query is answered or refused — it has no connection
  timeout flag, and needs none: the Java driver waited out every model call).
- **A client with a short built-in timeout cannot measure a model at all.**
  Every libmemcached tool (`memcat`, `memstat`, `memping`) gives up at a 5s
  poll timeout it has no option to raise — `memcat` printed `Error on
  motd(NOT FOUND)` at 5.01s against a listener that answered at 8s — and
  `mbpoll`'s `-o` is capped at 10s. Model answers take 5-90s. `memcached` is
  driven with pymemcache and `modbus` with pymodbus instead, both with
  `timeout=230`. Before adding a client, run it against a listener that
  accepts and never answers and time how long it waits; `probe_check.rs`'s 5s
  mock cannot see a 10s limit.
- **A client that retries on its own turns one question into several model
  calls.** libmosquitto sends a second CONNECT when no CONNACK arrives within
  the keepalive (measured at 61s with the default 60), so `mosquitto_sub` runs
  with `-k 300`. libcoap retransmits a Confirmable request after ~2s and the
  CoAP server has no dedup cache, so `coap-client` sends Non-confirmable
  (`-N`) and waits `-B 230`. sipsak resends OPTIONS on T1 doubling (5s, 15s,
  35s, 75s at T1=5000) and the SIP server answers every copy with its own model
  call, so it runs with `--timer-t1=10000`; one resend inside a slow answer is
  still possible, which is why its probe checks allow two calls. `snmpget`
  runs `-r 0`.
- **websocat hangs up at stdin EOF**, like `nc`, before the model has answered
  the message it sent, so its probe holds stdin open.
- **A Python probe's library is not checked the way a binary is.**
  `binary_available` sees `python3`, not `pymemcache`, `pymodbus`,
  `greenstalk` or `ignition` (all `pip install`ed into the Homebrew Python
  3.10), so a missing module is a `ModuleNotFoundError` in the client output
  and an `event_never_reached_model` run rather than `client-missing`. The
  standard-library clients (`smtplib`, `poplib`, `imaplib`, `nntplib`) need
  nothing; `nntplib` was removed in Python 3.13.
- **So every probe is checked against a mocked model first.**
  `probe_check.rs` takes a published case by id — instruction, probe and
  `Expect` unchanged — and answers its event correctly after 5 s, longer than
  the settle. It requires the model to have been asked (`expect_calls`), the
  probe to have waited, and the case's own `Expect` to accept the answer; each
  of the three defects above fails it, and was checked by putting it back. Add
  a check for every new case. The tests use `NetGetConfig::with_forced_mock()`
  because `run-eval.sh` runs the same binary with `NETGET_USE_OLLAMA=1`, which
  otherwise sends a mocked test to the real model.
- **Never let a harness bug score against the model.** A bad regex in an
  `Expect` returns `HARNESS: …` and receives verdict `error` with failure mode
  `harness_error`. Captured probe output that exceeds its limit receives verdict
  `error` with failure mode `probe_output_limit`, before checking even a matching
  retained prefix. Both paths preserve captured model evidence and the runner
  retains client output, command, exit status and executed-action diagnostics.
  `eval_probe_classification_test` checks these paths without executing a probe
  or contacting a model.

## The two findings the first sweep produced

Both are about *prompts*, which is what this harness exists to measure, and
neither is visible to a mocked test.

1. **`valid_actions_rejected_as_unparseable`, 29 of the first 30 runs.** The
   model named the right action with the right parameters and netget threw the
   reply away, because `ActionResponse::from_str` (`src/llm/actions/mod.rs`)
   strips a *leading* ``` fence and nothing trailing, then requires
   `serde_json::from_str` to consume the whole string — with no fallback before
   it bails with `Invalid JSON`. Small models append an explanation after the
   JSON constantly. Every failed run is therefore also asked a counterfactual —
   *would the first JSON value in this reply have executed?* — and the report
   carries both numbers. Without that, one defect hides every description
   problem behind a flat 0%.

   Related: `generate_with_format`'s `format` argument has exactly one caller
   (`conversation.rs:1642`) and it always passes `None`, so Ollama's
   JSON-constrained output mode is never used. That is deliberate per its own
   comment (some models do not support it), which is why the parser is the
   better fix — it also covers the Bridge and OpenAI backends.

2. **`copied_example_content`.** Told "serve a menu whose first item is labelled
   Welcome to NetGet", the model emitted all four items of `send_gopher_menu`'s
   declared `example` — "Welcome to the gopher hole", "About this server",
   "Files", "Search the archive" — and none of the requested label. This is the
   `{{event.xid}}` placeholder defect wearing better clothes: a placeholder at
   least looks wrong on the wire, whereas an example full of plausible prose
   does not, so it wins against the operator's own instruction.

   `classify.rs` names this automatically by reading the protocol's declared
   examples out of the registry and looking for their distinctive string values
   in the executed action — **excluding anything the instruction itself
   contains**, since a value the operator asked for is not evidence of copying.
   An `example` is the strongest prompt a protocol has; whatever it contains is
   what a small model will send.

   **That diagnosis did not fire on any run until 26 September 2026**, for two
   reasons at once: it looked the protocol up with the registry's exact-key
   `get("smtp")` while the registry is keyed `"SMTP"`, and it parsed the
   executor's `Executing action` line as JSON when the executor writes it with
   `{:?}` — serde_json's Debug form, `Object {"type": String("send_x"), …}`.
   Every copied example was scored `wrong_content`, including the gopher case
   above. It now resolves the name the way `--server` does, reads the Debug
   form, and skips the example's own `type` (an action's name is in every use
   of it). `copied_example_is_found_in_the_executor_debug_line` pins it; the
   lookup, the Debug parse and the `type` skip were each checked by putting
   the old code back. One limit remains: a long value
   the *event* supplied — an SNMP OID, a key name — also matches when it
   appears in the example, so read the evidence before quoting the label.

## What the eleven suites added on 26 September 2026 found

`smtp`, `pop3`, `imap`, `nntp`, `memcached`, `mqtt`, `coap`, `modbus`, `snmp`,
`sip` and `websocket`, 25 cases, llama3.1:8b, seed 42, 5 runs each: **30 of 125
runs passed**, and every case either passed 5/5 or failed 5/5. The six that
passed are `pop3/message-count`, `memcached/get-value`, `mqtt/refuse-client-id`,
`coap/text-resource`, `modbus/holding-registers` and `sip/available`. Every
failure was checked against the run's client output and executed actions;
none is the harness (each case's probe passes against a correct mock). That run
predates the classifier fix above, so its copied examples are labelled
`wrong_content` in its JSON.

- **Examples copied instead of the instruction**, the dominant shape:
  `send_smtp_greeting`'s "mail.example.com ESMTP Service Ready" in place of the
  requested banner; `send_snmp_response`'s "System Description" and "hostname"
  (with both OIDs, so a one-OID `snmpget` got two varbinds); the memcached
  stats example verbatim with no `version`; `accept_websocket`'s `"chat"`
  subprotocol, which websocat never offered, so the executor refuses it and the
  handshake is a 503; CoAP's `41.2` in an invented 2.05 body where 4.04 was
  asked for.
- **One action reused for every command of a session.** SMTP answered EHLO and
  MAIL with the 220 greeting; NNTP answered CAPABILITIES with the 200 greeting,
  so nntplib raises before the command under test is sent; IMAP answered
  CAPABILITY with a bare tagged OK (twice), which imaplib rejects.
- **A multi-line answer without its body.** POP3 `RETR` answered with a bare
  `+OK` leaves poplib waiting for the terminating dot until its timeout; IMAP
  `SELECT` without `* n EXISTS` makes `select()` return `[None]`.
- **The refusal half of an instruction ignored**: RCPT for another domain
  accepted, an out-of-range Modbus read answered with zeros, a busy SIP phone
  answering 200, an unknown NNTP group answered 501 instead of 411, a missing
  memcached key answered with a different key's value (pymemcache raises
  `KeyError`), and the MQTT retained message never published after the SUBACK.

## Adding a protocol

1. A function in `suites.rs` returning 2–5 `EvalCase`s, `#[cfg(feature = "…")]`.
2. Add the protocol to `ALL_PROTOCOLS` in `run-eval.sh` (it validates against
   that list before spending a minute on a build).
3. Validate the client invocation against a bare listener **before** running the
   eval — confirm it connects and sends bytes. Finding out through a 90-second
   model call is how the `whois` and `nc` traps above were found, and each cost
   a full pass. Note that server-speaks-first protocols (mysql, ftp) send
   nothing to a silent listener; that is expected, not a probe bug.
4. A test per case in `probe_check.rs`: the mocked answer a correct model
   would give. Run it (`./cargo-isolated.sh test --no-default-features
   --features <p> --test eval -- probe_check`) before the first real-model run.
