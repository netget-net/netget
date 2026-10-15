# M3UA client — an ASP with SCCP, TCAP, MAP and CAMEL

NetGet as an **ASP** on one association with an SGP (or an SGW/IPSP peer). The codec, transport
and the whole SS7 dialogue engine are the server's (`src/server/m3ua/`: `codec.rs`,
`transport.rs`, `sccp.rs`, `tcap.rs`, `ber.rs`, `map.rs`, `cap.rs`, `ss7.rs`, `ss7_actions.rs`);
this directory is the connect sequence, the session loop and the model's turns.

**Status**: `Experimental` — see `src/server/m3ua/AGENTS.md` "Maturity"; the same evidence and
the same gap apply.

## Connect

Rust opens the association (`transport::connect`: SCTP by default, the labelled lab TCP transport
with `transport: "tcp"`; `local_port` binds the near end, which SIGTRAN peers configured with a
fixed remote port require — jSS7's server associations do), sends ASPUP (with `asp_identifier`
if set) and ASPAC (loadshare, `routing_context` if set) and waits up to 15 s for each ACK. NTFY
on the way is collected and reported; BEAT is answered; an ERR fails the connect with the SGP's
error code named. Then `m3ua_connected` is raised and the model opens dialogues.

Addressing comes from startup parameters: `opc`/`dpc`/`network_indicator` for the MTP label,
`local_ssn`/`remote_ssn` and `local_gt`/`remote_gt` for the SCCP addresses (route on SSN with
point code and, if given, a GTI-4 global title). A CAMEL dialogue with no `called_address` uses
SSN 146 at both ends. New dialogues rotate the SLS.

## The model's turns

Events are raised from the session and answered by a separate dispatcher task (`run_turns`), so
the association keeps reading while the model thinks. Every action from a turn comes back to the
session with its depth; after the turn a `Done` marker lets the session hold a dialogue the far
end opened to the server's rule — still awaiting an answer means TC-U-ABORT
(`decision=model_silent`), or systemFailure if the model could not be asked
(`decision=fail_closed_llm_error`). A chain of turns stops at `MAX_FOLLOWUP_DEPTH` (8): a dialogue
remembers the depth of the turn that last sent on it, and the answer to it is raised at that
depth.

Events: `m3ua_connected`, `m3ua_map_received`, `m3ua_cap_received` (the server's shapes, plus
`tcap: "timeout"` when an opened dialogue got no answer within the idle bound), `m3ua_sgp_error`
(an ERR, or an MSU NetGet does not decode). Actions: `send_map_request` (opens a dialogue, or
invokes inside one), `send_map_result`, `send_map_error`, `send_cap_operations` (initialDP opens
a CAMEL dialogue; eventReportBCSM inside one), `send_tcap_end`, `send_tcap_abort`, `disconnect`
(ASPDN, then close), `wait_for_more`.

MAP dialogues on networkUnstructuredSsContext carry MAP-OpenInfo (destination reference = the
argument's MSISDN, origination = `local_gt`) because peers refuse a USSD TC-BEGIN without it.

## Bounds

The server's: BER depth/elements/lengths, components per message, open dialogues (1024),
dialogue idle (60 s, here on a timer), SCCP data 255 octets, no segmentation. Plus the follow-up
depth and a 64-event turn queue (`decision=turn_queue_full` when the model falls behind).

## Verification

`tests/client/m3ua/`: jSS7 as SGW over SCTP answering six dialogues built one from the last
(`real_server_test.rs`), the same through osmo-stp (`osmo_stp_test.rs`), and a canned SGP over
the lab transport for the follow-up bound, both fail-closed rows and an ERR on ASPUP
(`bounds_test.rs`). See that directory's `AGENTS.md`.
