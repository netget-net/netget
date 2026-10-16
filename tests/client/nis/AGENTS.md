# NIS client tests

No LLM calls: python chains play the model. The server suite's `support.rs` is shared through
`#[path]` (`server_support`).

## e2e_test.rs — against NetGet's own server (regression, not evidence)

- `the_chain_reads_every_kind_of_answer`: MAPLIST → MATCH → a missing key → ALL → MASTER →
  ORDER → FIRST → NEXT, with passwd, group and hosts lines parsed into fields; an injected
  match, a refused injected map name (`../passwd`), and an injected other domain (YP_NODOM).
- `a_handler_chain_stops_at_the_depth_bound`: a chain that always answers ORDER reaches the
  server exactly `MAX_FOLLOWUP_DEPTH` times.
- `finds_ypserv_through_a_portmapper_and_refuses_a_bad_domain`: NetGet's sunrpc server answers
  GETPORT; the client connects to the port it named and reports `served: false`.

## real_server_test.rs — Linux ypserv 4.2 (Linux; root or passwordless sudo, rpcbind running)

`netget_reads_ypserv_maps_through_rpcbind`: passwd.byname and group.byname built by makedbm
into `/var/yp/netget-client.test` (created and removed as root), `ypserv -d -p <port>` as root,
found through rpcbind. Every answer is checked against what makedbm stored (ORDER against its
`YP_LAST_MODIFIED`, MASTER against `-m`), and `ypserv -d`'s own log is checked for each
procedure — that is where the model's actions are seen arriving. A second client goes through a
recording relay and tshark reads both directions. Holds the server suite's program-100004 lock.
