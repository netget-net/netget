# M3UA client tests (ASP role)

Shares the server suite's helpers through `#[path]` (`support` = `ss7_support.rs`, jSS7's
captured messages; `live` = `ss7_live.rs`, the live capture, the jSS7 driver and osmo-stp). The
real-peer files are Linux-only (`mod.rs`): they need SCTP, `NETGET_JSS7_PEER` from
`tests/server/m3ua/install_peers.py`, `osmo-stp`, and a dumpcap allowed to capture on loopback.
They **fail**, not skip, without any of them. No LLM calls: a python policy is the model.

- `real_server_test::the_models_dialogues_are_answered_by_jss7_and_each_builds_on_the_last` —
  jSS7 8.0.112 as SGW (server association, which only accepts NetGet's configured `local_port`).
  The policy opens two sendRoutingInfoForSM dialogues (one MSISDN jSS7 answers unknownSubscriber);
  the decoded result's IMSI and MSC address go into an mt-forwardSM, then anyTimeInterrogation,
  a USSD string built from the returned LAC, an mo-forwardSM quoting the USSD answer, and a CAMEL
  initialDP. jSS7 prints each request decoded; the test asserts the fields that came from
  earlier answers arrived (the client acting on the model's answer, on the wire). The capture
  must show NetGet's invokes with PPID 3 and DATA off stream 0.
- `osmo_stp_test::netgets_asp_reaches_jss7_through_osmo_stp` — osmo-stp 1.6 is the SGP; NetGet
  (PC 1, RC 1) and jSS7 (PC 2, RC 2) are both its ASPs; the SRI-SM → mt-forwardSM chain crosses
  it by DPC routing.
- `bounds_test` (any host, lab TCP, a canned SGP written from RFC 4666 that replays jSS7's
  answers with transaction ids rewritten): the model's request reaches the wire and its answer
  drives the next; a model that always asks again stops at `MAX_FOLLOWUP_DEPTH`; an inbound
  dialogue the model cannot be asked about gets systemFailure; a silent model aborts it; an ERR
  on ASPUP fails the connect naming the error.

Mutation-checked: dropping the model's actions, the follow-up bound, the fail-closed answer.
