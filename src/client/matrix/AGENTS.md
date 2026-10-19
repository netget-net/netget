# Matrix client

The Matrix client-server API v3 over hyper HTTP/1.1, one connection per request, so the same
code builds for wasm32.

## Session

1. `connect()` logs in with `m.login.password` (`user`, `password`, optional `device_id`). A
   refusal fails the connect, naming the errcode and never the password.
2. A first `/sync?timeout=0` gives the batch to follow and the joined rooms. Its timeline is
   not replayed: what happened before login is not news. Its pending invites are raised.
3. Three tasks, all registered with `register_client_task`:
   - the **syncer** long-polls `/sync` (`SYNC_WAIT` 25 s) and raises events;
   - the **dispatcher** asks the handler about each event;
   - the **session** performs actions from the handler and from `send_to_client`.
4. Ending aborts the syncer and dispatcher, then logs out.

## Events

- `matrix_connected {user_id, device_id, joined_rooms}`
- `matrix_message {room_id, sender, event_type, content, event_id}`: others' non-state events;
  its own are skipped.
- `matrix_invite {room_id, sender, room_name}`
- `matrix_member {room_id, user_id, membership}`: others' membership changes.
- `matrix_response {operation, status, result, errcode?, error?}`: the answer to every action
  except a send that succeeds, which is only logged (`matrix_sent`), so a chatty handler does
  not get a model call per message it sends.

## Actions

`matrix_create_room{name, topic, invite}`, `matrix_join{room}`, `matrix_send{room_id, body |
content, msgtype, event_type}`, `matrix_invite`, `matrix_leave`, `matrix_messages{room_id,
limit}`, `disconnect`. `actions::request` validates every one before anything is sent (room ids
start with `!`, user ids are full ids), so an injected bad action is `Rejected` locally.
Transaction ids are `ng<random>.<n>`, unique per session.

A handler chain stops after `MAX_FOLLOWUP_DEPTH` (8). Answers are capped at 4 MiB.

Not implemented: end-to-end encryption, media, registration, SSO.

## Batching

`BatchingMode::On`. What `/sync` raises (messages, invites, membership) and the answers to the
handler's own requests reach the model through the dispatcher's queue; with batching on the
dispatcher drains everything that arrived during the previous call (up to `MAX_BATCH_EVENTS`)
into one `call_llm_for_client_batch` call, with it off one event per call. A batch's
follow-ups are as deep as its deepest event. `tests/client/matrix/batching_test.rs` is the
off/on pair.
