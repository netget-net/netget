# Reverse-Shell Listener (emulation)

**Status**: `DevelopmentState::Experimental` — newly implemented, not yet human-reviewed against
a wide range of operator tooling, but every declared event fires, every declared action is
reachable, and the E2E suite asserts model-supplied output on the wire from a raw TCP client.

Default port is arbitrary (commonly 4444/1337 in labs); unprivileged, so `privilege_requirement`
is `None`.

## What this is, and what it is not

This protocol **emulates the operator side of a reverse shell** for authorized red-team
engagements, CTF challenges and teaching labs. NetGet is the listener an operator connects *back*
to (the classic `nc -lvnp 4444` catcher), and the LLM role-plays the shell on the compromised
host — deciding the banner, the prompt, and the output of each command the operator types.

It is an *emulation*, in exactly the same sense as every other NetGet protocol: NetGet
impersonates a service without being one. Concretely:

- **NetGet never executes the operator's commands on this host.** There is no `std::process`,
  no `sh -c`, no filesystem access anywhere in `mod.rs` or `actions.rs`. The output the operator
  sees is fictional text the model produced. Grep proves it:

  ```bash
  grep -rn "Command::new\|process::\|std::fs\|sh -c" src/server/reverse_shell/   # → no matches
  ```

- The capability to run real commands already exists, separately, through the **scripting
  layer** (`src/scripting/`, see the top-level `AGENTS.md`). That layer is **opt-in and
  unsandboxed** — a script handler runs in-process with NetGet's privileges. This protocol does
  not invoke it and does not add a "really execute" mode. If an operator wires a script handler
  onto `reverse_shell_command` that shells out, that is the pre-existing, documented,
  unsandboxed escape hatch, not something this protocol grants.

The maintainer's framing was: "allow the LLM to call any command line — you can already do so
with scripting. Add prompting on how a reverse shell should be set up." This protocol is that
first-class, honestly-documented surface: a listener where the model plays the shell, rather
than a scripting trick.

### Why this is a legitimate feature

A reverse-shell *listener* is a standard pentest/CTF construct, and impersonating network
services is NetGet's entire purpose. Emulating the victim end is useful for training operators,
building CTF challenges, and studying tooling behaviour without a real compromised host. Because
the model supplies fictional output and nothing is executed, the emulation is also the safe
default.

## Wire model

There is no protocol framing — an operator connects with a plain TCP client (`nc`, `ncat`,
`socat`) and types. The server:

1. Raises `reverse_shell_session_opened` once on connect. The model may greet with a prompt.
2. Buffers raw bytes into newline-terminated lines. Each line (CR stripped) raises
   `reverse_shell_command` with `{command, first_command, empty}`.

One connection is handled **strictly sequentially**: the model call for one line completes
before the next line is read. RFB-style buffering — the kernel holds input that arrives during a
call. This is the same discipline the per-connection state machine enforces (no concurrent LLM
call on one connection); a raw line-oriented shell does not need the Idle/Processing/Accumulating
machine because reads are already serialized by the loop.

**Batching (`BatchingMode::On`).** Complete lines wait in a small queue in `ShellConnection::run`.
With batching on, before each call the loop also takes whatever the socket already holds
without waiting (a zero-deadline read) and answers up to `MAX_BATCH_EVENTS` queued lines in
one `call_llm_batch`, newest as trigger — commands typed during the previous answer, or a
pasted block. Off, one line per call as before. Only the session's first line carries
`first_command: true`. The `MAX_LINE_LEN` bound still closes the session, after the lines
completed before it are answered. Test: `tests/server/reverse_shell/batching_test.rs`.

Bytes are split with `tokio::io::split()`; the write half is an `Arc<Mutex<WriteHalf>>`. The
accept-loop `JoinHandle` is registered with `AppState::register_server_task()` so `stop_server`
releases the socket. A connection is removed from the server view on every exit path.

## Dashboard injection (peer handle + counters)

Each live connection registers a **peer handle** (`peer_support::register_peer_channel` +
`spawn_peer_command_task`) right after it is added, sharing the same `Arc<Mutex<WriteHalf>>` the
reader writes through, so the dashboard's `[ message this peer ]` / `[ disconnect this peer ]`
rows work. Every wire verb returns `Output`/`CloseConnection` (no `ActionResult::Custom`), so the
generic peer task encodes an injected `send_shell_output` / `send_shell_prompt` /
`end_shell_session` exactly as the model's would be — **no bespoke arm is needed**. The handle is
removed on every exit path via the single cleanup in `handle_connection` (EOF, read error,
oversize line, `end_shell_session`, and the fail-closed no-answer path all funnel through it).

`[ disconnect this peer ]` injects `{"type":"close_connection"}`, which is **not** an LLM-facing
verb but has an explicit `execute_action` arm mapping it to `ActionResult::CloseConnection` (FIN);
without that arm the generic peer task would answer "Unknown action".

`update_connection_stats` is called on every read (bytes/packets in) and every reader write
(bytes/packets out), so the rail's `↓ ↑` move and `last_activity` refreshes. Injected writes go
through the peer task and do not touch the counters (matches the tcp/ftp reference).

## Events — both fire

| Event | Raised when | Actions offered |
|---|---|---|
| `reverse_shell_session_opened` | operator connects | send_shell_prompt, send_shell_output, no_shell_output, end_shell_session |
| `reverse_shell_command` | a newline-terminated line arrives | send_shell_output, send_shell_prompt, no_shell_output, end_shell_session |

## Actions

| Action | Effect |
|---|---|
| `send_shell_output` | write fictional command output (`output`); optional `append_prompt`/`prompt` re-prints the prompt |
| `send_shell_prompt` | write just the prompt (`prompt`, default `"$ "`) |
| `no_shell_output` | print nothing for this command; session stays open |
| `end_shell_session` | close the connection (emit a farewell with send_shell_output first) |

There are **no async (user-triggered) actions**: the server keeps no addressable connection
registry, so one would have nothing to talk to.

## Structured parameters, no raw bytes

Everything is plain text. `output` and `prompt` are UTF-8 strings sent verbatim; the model
includes its own `\n`. There is no base64 or hex field anywhere — models cannot reliably produce
or parse those, and a shell transcript is text by nature.

## Fail-closed behaviour

The four outcomes are kept structurally distinct (`Outcome` / `FailClosed` in `mod.rs`):

- **output / close** — the model decided what to print and whether to end the session.
- **`no_shell_output`** — the model explicitly decided to print nothing; the session stays open.
  It is offered on **both** events. It used not to be offered on `reverse_shell_session_opened`,
  whose description nevertheless invites the model to "stay silent and wait for their first
  command" — and since `call_llm` builds the tool list from the event, the only way to say that
  was to answer with zero actions, which is `NoUsableAnswer` and drops the session. Following
  the documentation hung up on the operator before a byte was typed
  (`test_silent_greeting_keeps_the_session`).
- **no usable answer** (`FailClosed::NoUsableAnswer`) — the call succeeded but every action
  failed or produced nothing. Logged at WARN with `decision=fail_closed_no_answer`.
- **LLM error** (`FailClosed::LlmError`) — the call itself returned `Err`. Logged at ERROR with
  the full error and `decision=fail_closed_llm_error_overloaded` or
  `…_llm_error_unavailable`, classified by `crate::utils::WireFailure`.

These last two used to share one `no_answer` flag, which made a backend outage
indistinguishable in the log from a model answering with junk. They are now separate variants
with separate `decision=` tags, alongside `decision=model_end_session` for a deliberate
`end_shell_session` — the same three-way separation `src/server/radius/` keeps.

Both fail-closed cases write **one line** to the operator and then shut the socket down (FIN):

```text
\r\n[netget] backend at capacity, retry later\r\n     # Overloaded
\r\n[netget] request could not be processed\r\n        # Unavailable / no usable answer
```

A bare FIN on a shell transcript is indistinguishable from the far-end implant dying, which
sends the operator hunting the wrong problem; the category line removes that ambiguity, and the
two wordings let a transient outage be told from a permanent one even though a raw shell stream
has no status code.

**The line is `WireFailure::text()` and nothing else.** No error text, no backend URL, no model
name, no `anyhow` chain — those go to `tracing::error!` and the status stream. `text()` returns
`&'static str` precisely so nothing derived from an error can be returned from it; see
`src/utils/wire_failure.rs` and the guard in `tests/wire_failure_test.rs`.

Equating "no answer" with "empty output but keep going" would be the fail-open shape that bit
OAuth2: an LLM outage would look like a working, silent shell. Instead an outage drops the
session, which is honest.

## Attacker/operator-controlled input

- The line accumulator is capped at `MAX_LINE_LEN` (64 KiB); a peer that never sends a newline
  cannot grow it without bound. A longer line closes the connection.
- Operator bytes are decoded with `String::from_utf8_lossy`, which cannot fail, so malformed
  input cannot abort the task.

## Limitations

- No PTY semantics: no terminal echo, no line editing, no job control, no ANSI handling beyond
  whatever text the model emits. Operators using a cooked-mode client (`nc`) see their own input
  echoed locally by their terminal, not by the server.
- Two events per keystroke is not a concern here (input is line-buffered, one event per line),
  but a chatty prompt still costs one model round-trip per command. Prefer a script or static
  handler for deterministic CTF challenges.
- No authentication and no allow-listing of who may connect — bind to localhost or a controlled
  lab network.

## Manual verification

```bash
./cargo-isolated.sh run --no-default-features --features reverse-shell,tcp --release
# prompt: "reverse-shell listener on port 4444 emulating a compromised ubuntu box"
nc 127.0.0.1 4444
# then type: whoami   ->  model prints e.g. "www-data"
```

## Connection bounds

Before September 2026 this listener accepted without limit and bounded no read in time, so a peer
that connected and said nothing held a socket, a task and an `AppState` entry forever. It now
declares both halves; the constants and the reasoning live beside them in
`src/server/reverse_shell/mod.rs`.

| Bound | Value | Why this number |
|---|---|---|
| `FIRST_COMMAND_READ_TIMEOUT` | 120s | Two minutes rather than a machine protocol's thirty seconds, because the peer is a person at `nc`: the session opens with a model-written banner and prompt, and they read it before typing. The banner is generated and written before the read loop starts, so this bound measures only the time from a prompt being on their screen to the first key. |
| `IDLE_BETWEEN_COMMANDS_TIMEOUT` | 900s | A shell's own idle convention is `TMOUT`, which hardening baselines set to 900 seconds — so this is the number an operator already expects a shell session to be reclaimed at, and long enough that reading a long listing, or stepping away mid-engagement, does not cost the session. |
| `MAX_CONNECTIONS` | 256 | Refusal: **a plain notice line**, `\r\n[netget] too many connections\r\n`. There is no framing to refuse in, but there is a terminal on the other end, so a plain line reaches the one audience that exists. It is deliberately netget's own voice rather than a shell-looking error: the emulated shell never got as far as existing, and a fabricated shell message would assert something about a session that was declined. |

**There is no NetGet reverse-shell client**, so this bound has no peer of ours to strand — the
fourth exemption in `PROTOCOL_QUALITY.md`'s three-state test; the peer is a person at `nc`,
which is what the two minutes already argue for.

**The deadline wraps the read and nothing else.** The session-opened consultation happens before
the loop, and the LLM round-trip and a `manual` rule parking a command for a human
(`src/state/intercepts.rs`, 300s by default) happen after bytes have already been read.

`tests/server/reverse_shell/connection_bounds_test.rs` drives all three from the wire: a silent peer is
closed at the first bound, a connection whose answer is parked for a human is not closed at all,
and the connection past `MAX_CONNECTIONS` is answered with the refusal above and then a clean
EOF. Each was verified by removing the thing it tests — the deadline, the busy marking, the cap —
and watching it fail. `tests/tcp_server_bounds_ratchet_test.rs` fails the build if either bound
is removed from the source, and `tests/accept_bounded_test.rs` covers the shared cap mechanism
itself, including that a busy connection is never reported as idle.
