# H.323 client (an endpoint that places calls)

Uses the server's codecs and call leg as the calling side: `src/server/h323/per.rs`,
`src/server/h323/q931.rs`, `src/server/h323/h225.rs`, `src/server/h323/h245.rs` and
`src/server/h323/call.rs`.

## Connect

`remote_addr` is a gatekeeper's RAS address (`mode: gatekeeper`) or an endpoint's call
signalling address (`mode: endpoint`); `mode: auto` (the default) means gatekeeper on port 1719,
endpoint otherwise. The client binds a RAS socket and a call signalling listener on the address
its route to the remote uses.

With a gatekeeper, `connect()` runs GRQ (unless `discover: false`; a GCF's `rasAddress` becomes
the gatekeeper's address) and RRQ with the configured `aliases` and `time_to_live`, without
consulting the model. It fails only when the gatekeeper does not answer at all (three tries,
3 s each, RequestInProgress honoured up to 30 s); a GRJ or RRJ is a result, reported in
`h323_client_ready`.

## Running

`h323_client_ready` → the model's actions: `h323_place_call` (destination alias, number or
`ip:port`; codec; display), `h323_hangup`, `h323_register`, `h323_unregister`.

A call: ARQ when registered (an alias destination needs a registration; `ip:port` can be called
without one) → TCP connect → Setup with fastStart proposals for each codec (a channel each way)
and `h245Tunnelling: true` → the callee's messages, each decoded. Results:
`h323_call_connected` (fastStart's codec and the callee's RTP address, H.245 state, the ACF),
`h323_call_released` (by remote/local/connection, Q.850 cause, H.225.0 reason, how far it got,
RTP packets received, the DRQ answer), `h323_call_forwarded`, `h323_call_failed` (admission,
connect or signalling stage, with the ARJ reason). After Connect the client opens tunnelled
H.245 if the callee has not.

Background: a keep-alive RRQ at three quarters of the time-to-live; an IRQ from the gatekeeper
is answered with IRR, its URQ with UCF (and `h323_registration` with `gatekeeper_urq`). A call
arriving on the registered call signalling address is refused with Release Complete cause 21.
When the session ends it releases its call and unregisters.

The command channel takes the same four actions from the dashboard or MCP.

## Failing closed

An action the model gives that cannot be carried out is logged
`decision=fail_closed_bad_action` and reported as `h323_error`; nothing is sent for it. A
backend failure is logged `decision=fail_closed_llm_*` and nothing is sent. A call the model
never hangs up ends when the callee releases it, the connection closes, or — unanswered —
after `ANSWER_TIMEOUT` (cause 19). A message for another call reference releases the call with
cause 81. Follow-up chains stop at `MAX_FOLLOWUP_DEPTH` (6).

## Not implemented

One call at a time. No H.235, no separate H.245 channel, G.711 only, no media sent. Incoming
calls are refused rather than offered to the model. Cleanup (Release Complete, URQ) runs when the
session ends on its own or its command channel closes; an aborted task sends nothing.
