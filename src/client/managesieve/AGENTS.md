# ManageSieve client — Experimental

Uses `src/server/managesieve/proto.rs`. Reads the greeting's capabilities, requires SASL PLAIN,
logs in with an initial response (`user`, `password`, optional `authorize_as`) and reports
`managesieve_connected` (implementation, Sieve extensions, every capability). One command at a
time: list, get, put, check, set_active, delete, rename, have_space; scripts go as
non-synchronizing literals. Each answer is `managesieve_response` with the status, response code
(e.g. NONEXISTENT, ACTIVE, QUOTA/MAXSIZE), the server's message (a script's compiler errors),
and the script list or script text. `disconnect` sends LOGOUT. No STARTTLS.

## Batching (what arrives while the model is answering)

The session task runs the model's actions one after another while the dispatcher task is still
asking the model about the first result, so with several commands in one answer (or an injected
one) the later results queue in the dispatcher's event channel during that call. With batching
on the dispatcher drains everything waiting (up to `MAX_BATCH_EVENTS`) into one
`call_llm_for_client_batch` call, one `managesieve_response` event each; with it off, one call per result.
Each result names its own command, so answering them together loses nothing. Declared
`BatchingMode::On`. Test: `tests/client/managesieve/batching_test.rs`.
