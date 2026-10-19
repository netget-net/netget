# WAMP client — Experimental

Connects `ws://remote_addr` + `path` offering `wamp.2.json`, sends HELLO for `realm` with the
caller, callee, publisher and subscriber roles (and `authid` when given), and fails unless the
router answers WELCOME (an ABORT's reason is the error). Events: `wamp_welcome`, `wamp_reply`
(the router's answer to each subscribe, unsubscribe, publish, call, register, unregister),
`wamp_event`, `wamp_invocation`, `wamp_left`. Actions: `wamp_subscribe` (exact, prefix,
wildcard), `wamp_unsubscribe` and `wamp_unregister` by name, `wamp_publish`, `wamp_call`,
`wamp_register`, `wamp_yield` / `wamp_error` (the given invocation, or the oldest unanswered),
`wamp_goodbye`, `disconnect`. An invocation the handler leaves unanswered is answered
`wamp.error.unavailable`, so a caller never hangs on NetGet.

**Batching.** The session loop hands every router message to a dispatcher task over a bounded
queue (256). With batching off the dispatcher answers one event per call; with batching on (the
declared default) it takes every event already waiting (up to `MAX_BATCH_EVENTS`) and answers
them in one call through `call_llm_for_client_batch`, the newest the trigger. Every
`wamp_invocation` in the batch is still answered: an answer naming its invocation answers that
one, each answer naming none answers the oldest still unanswered (as `perform` does), and any
left over get `wamp.error.unavailable`. `tests/client/wamp/batching_test.rs` drives both against
a minimal router written in the test, an invocation among the batched events, batching off as
the control.
