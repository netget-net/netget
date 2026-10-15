# OpenFlow switch (client)

NetGet connects to an OpenFlow 1.3 controller (default port 6653) and is the switch it
controls. It shares the controller's codec, JSON vocabulary and packet builder
(`src/server/openflow/wire.rs`, `src/server/openflow/fields.rs`,
`src/server/openflow/packet.rs`).

## What Rust answers

From the switch the startup parameters describe (`datapath_id`, `ports`, `n_tables`) and the
flow table the controller's FLOW_MODs build:

- HELLO (only 1.3 offered; a controller without 1.3 gets `HELLO_FAILED` and `connect` fails),
  FEATURES_REPLY (no buffers), ECHO both ways (a controller silent for 15 s is probed and
  dropped if it does not answer within another 15), BARRIER, GET_CONFIG/SET_CONFIG, ROLE,
  GET_ASYNC/SET_ASYNC, QUEUE_GET_CONFIG, TABLE_MOD (accepted).
- Multipart: DESC, PORT_DESC, FLOW and AGGREGATE (filtered by table, cookie, out_port and a
  non-strict match), TABLE, PORT_STATS (zero counters), empty GROUP/GROUP_DESC/METER/
  METER_CONFIG/QUEUE and zeroed GROUP_FEATURES/METER_FEATURES. FLOW replies are split into parts
  of at most 60 000 bytes of entries with `REPLY_MORE`. Anything else is `BAD_MULTIPART`.
- FLOW_MOD: validated as a switch does — match length, duplicate fields and prerequisites
  (`BAD_MATCH`), output to ports the switch has (`BAD_ACTION/BAD_OUT_PORT`), unsupported
  actions, tables that exist, forward-only `goto_table`, `TABLE_FULL` past 4 096 flows — then
  applied (add replaces an identical entry; modify and delete in strict and non-strict forms,
  delete honouring `out_port`) and reported as `openflow_flow_mod_received`.
- PACKET_OUT: in_port must be a port, CONTROLLER or LOCAL; a buffer id is `BUFFER_UNKNOWN`;
  output ports must exist. Reported as `openflow_packet_out_received` with the packet decoded.
- GROUP_MOD, METER_MOD, PORT_MOD and EXPERIMENTER are refused.

## What the model does

Actions: `openflow_packet_in` (a packet described by headers, built with checksums in Rust, sent
from one of the switch's ports), `openflow_port_status` (add/delete/modify; the port list
follows), `openflow_flow_removed` (removes an installed flow and reports it), `disconnect`.
Events: `openflow_controller_connected` (after the first FEATURES_REPLY),
`openflow_flow_mod_received`, `openflow_packet_out_received`, `openflow_error_received`,
`openflow_disconnected`. Model turns are chained up to `MAX_FOLLOWUP_DEPTH` (8); an LLM failure
logs `decision=fail_closed_llm_error` and sends nothing. `send_to_client` reaches the same
actions through the command channel.

## Tasks

A reader (whole messages), the session (owns the writer and every answer, so a slow model never
delays an ECHO_REPLY) and the model dispatcher. All three are registered client tasks.

## Not implemented

No data plane: nothing is forwarded, counters are zero, flow timeouts are recorded and not
enforced. No buffers, no groups or meters, no TLS, no auxiliary connections, OpenFlow 1.3 only.

## Maturity

Experimental. Two independent controllers drive it in `tests/client/openflow/real_server_test.rs`
(os-ken 4.2.2 and Open vSwitch's `ovs-testcontroller`), with the model's PACKET_INs asserted from
the controllers' side and tshark over both directions.
