# Model behaviour: what the model is offered, what it does with it, and the measurements

> Moved out of the root `AGENTS.md` on 21 November 2026, which now holds only the rules and
> a pointer here. The text is as it was written, so "this file" and "this section" mean
> the root file as it then was; dated claims are dated for a reason — re-derive before
> trusting one.

Each mechanism here exists because a small model (llama3.1:8b) was measured doing the wrong
thing with the obvious design. The numbers are the argument; re-measure before changing
one. Eval data is under `eval-results/`.

## Memory has two scopes

**Memory has two scopes, and the difference is a privacy boundary.** `set_memory` /
`append_memory` write the instance's memory, one string every connection's prompt reads and
that outlives them all — data the model stored, counters, settings. `set_connection_memory` /
`append_connection_memory` write `ServerInstance::connection_memory`, shown above one
connection's events only (`AppState::render_connection_memory`) and dropped when it closes;
they are offered on a server event that arrived on a connection of a non-connectionless
protocol, and refused anywhere else rather than redirected to shared memory. They exist because
a telnet BBS (llama3.1:8b, 31 October 2026) wrote `user_name: Zed` into shared memory, so the
next peer would have been greeted as Zed. A line written `key: value` replaces the earlier line
with that key in either scope (`common::append_memory_lines`), so the same fact appended twice
reads once. `tests/connection_memory_test.rs` drives two telnet peers through the bridge.

## The client restart check

**A client that starts its instruction over is caught after the model answers, not argued out
of it before.** A client's instruction is usually a script ("Send PING, then GET mykey, then
stop sending commands") and the model is asked again on every reply; llama3.1:8b answers reply
after reply by sending the script again, in 8 of 8 seeded runs (seeds 42–49, 6 November 2026),
with both commands listed as already sent directly above the reply. The history is worded as
progress (`ExchangeHistory::render_for_client`: "you did:" under a header saying all of it is
done, and the first call with no event is recorded as `client_started`,
`tests/client_session_progress_test.rs`), and that is accurate but does not stop it; a
paragraph in the client system prompt framing the instruction as a plan under way made the
connect event come back empty or as an echoed transcript in 5 of 8 and was removed.

What does stop it is `client::restart_check`, in the one choke point every client calls
(`llm_budget::call_llm_for_client_inner`), between the model's answer and the wire:

- The client's **opening** is the wire actions of its first model answer that sent anything
  (`wait_for_more` sends nothing); a new instruction clears it.
- A model answer to an event that **begins with the opening's first actions**, verbatim and in
  order (`PING; GET mykey` again, or `PING` alone), is held, and the model is asked one
  question offering `skip_repeat` or `send_again` (a budgeted call, `Event: client_restart_check`).
- `send_again` must name a `trigger`, and NetGet checks it instead of trusting the choice: the
  word must appear, as whole words, in the instruction **and** in the event's values ("each time
  the server answers AGAIN" and the message `AGAIN`). A bare yes/no was measured and was not
  enough — the model said "send again" to a PONG. An unfounded trigger counts as `skip_repeat`.
- On `skip_repeat` the repeated actions are dropped and the rest of the answer is sent. When
  nothing is left — the whole answer was the restart — the model is asked once more for the same
  event, told the lines or commands the opening sent are done and must not be sent again while
  its action is still the way to send anything new, and that answer is sent without any opening
  action. Without
  this second turn a conversation stalls: a quiz client that answered question 1 with "hello"
  again fell silent in 6 of 8 runs.
- A question that cannot be asked or answered (budget spent, model error, unreadable answer)
  sends the answer as it was. History records what was actually sent.

It is a per-client setting, `restart_check` (on by default; `ClientForm`, `open_client`, MCP
`start_client`/`update_client`, `--restart-check on|off` with `--client`,
`ConversationOverrides`, hot-applied). It knows no protocol: it compares JSON actions the
client's own model produced. **What it costs, and the parameter says so wherever it is
offered:** a repeat the instruction names no trigger for — a retry the model decides on by
itself after an error the instruction does not mention — is dropped. A client whose
instruction relies on self-initiated retries or repeats must be started with
`restart_check: false` (`--restart-check off`).

Measured with llama3.1:8b, seeds 42–49, each run 60 s (`--load`, `--llm-seed`, `batching: false`,
servers answered by script handlers), check off → on (6 November), and on again on 7 November
after the telnet client's action descriptions and the asked-again wording below changed:

| Case | Off | On | On, 7 November |
|---|---|---|---|
| redis: "Send PING, then GET mykey, then stop sending commands." — exactly PING, GET on the wire | 0 of 8 (the script again on every reply until the run ended) | 7 of 8 (the eighth sent a literal `STOP`; nothing restarted) | 8 of 8 (7 of 8 that day with the old asked-again wording; the eighth sent `quit`) |
| telnet, legitimate repeats: "Send PING. Each time the server answers AGAIN, send PING again. When it answers DONE, disconnect." — exactly 3 PINGs | 0 of 8 (seven sent 4–14 PINGs, DONE ignored; one never sent its first) | 7 of 8 (the eighth never sent its first PING, off or on) | 8 of 8 (8 of 8 with the old wording too) |
| telnet quiz (conversational): "Say hello, then answer each question… When it says BYE, disconnect." — extra hellos on the wire / reached the last question / model answered question 1 | 105 / 1 of 8 / 7 of 8 | 19 / 3 of 8 / 8 of 8 | 0 / 2 of 8 / 7 of 8 (the eighth answered with JSON that does not parse; most runs stop at question 2, answered "2") |

One quiz number goes the other way, and why matters: the answer to question 1 reached the
server as a line in 7 of 8 runs off and 4 of 8 on. In the four the model answered with the
telnet client's `send_text`, which sends no line ending; off, the restarted `hello` line that
followed it happened to end the line (`Parishello`). That was the model picking the wrong
telnet action, not the check, and the check made it likelier: the question asked again said
`send_command {"command":"hello"}` was "not to be sent again", and the model read the *action*
as spent (22 of 30 replayed seeds answered with `send_text`). It now says the lines or commands
are done and the action is still the way to send anything new
(`restart_check::continue_instruction`, whose doc comment has the replays: a client told to
disconnect on `DONE` did so on 10 of 20 seeds instead of 0, and the redis client sent a new
command on 1 of 80 instead of 7). The telnet client's action
descriptions now name `send_command` as the way to answer anything and `send_text` as not for
answers; with the check on, question 1 then reached the server as a line in 7 of 8 runs (3 of
8 on the same day's master; the eighth answered with JSON that does not parse).
`src/client/telnet/AGENTS.md` has the measurement. A measurement of conversation over telnet
should still read the model's actions, not only the server's lines.

A scripted client is still better written as a script or static handler (`--client-handlers`),
which costs no model call at all. `tests/client_restart_check_test.rs` drives the mechanism
through the bridge backend.

## `notify_operator`

**`notify_operator` is a note on the operator's screen and is never offered beside a wire
answer.** It was `show_message`, and offered beside `send_telnet_line` it was taken for the
reply: a BBS greeting went to the operator and the peer saw nothing. `show_message` is still
accepted everywhere an action is read (model answers, handlers, `.netget` files) and rewritten
to the current name; a server event that offers protocol actions leaves it out of the list
(`common::network_event_common_actions_for`), though a model that names it anyway is executed,
not retried (`tests/notify_operator_test.rs`).

## Decision events (`EventType::decision_only`)

**A decision event is offered its own answers and nothing else.** An event declared
`EventType::decision_only` (Bolt's login) gets no memory, connection-memory or log action from
`call_llm`, and its prompt has no memory section. Over 40 replayed seeds for each of the three
Bolt eval instructions, llama3.1:8b refused "accepts any login" on 14 of 120 draws with those
actions beside accept and refuse (quoting the instruction's login sentence in the event still
left 3 of 80), and on none of 120 without them, while an instruction refusing the user was
still refused 40 of 40 (`eval-results/2026-11-13-structural-cases/`). Use it where the event is
one yes/no question, not where the model should be able to remember something about the peer.
