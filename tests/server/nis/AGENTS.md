# NIS server tests

No LLM calls: the python policy in `support.rs` plays the model. It serves one domain,
`netget.test`, with passwd.byname/byuid, group.byname/bygid, hosts.byname/byaddr, netgroup and
a generic mail.aliases; other domains are refused and other maps are no_map. `broken.byname`,
`big.map` and `huge.map` exist to make the server refuse the model's answer.

`yp_raw.py` is a YP caller written from `yp.x` with python's struct module — it encodes every
call and decodes every result itself, so the e2e suite does not test NetGet's codec against
itself. It also asserts nothing follows `more=FALSE` in an ALL.

## e2e_test.rs (every platform)

- `every_procedure_over_tcp_renders_canonical_lines`: all twelve procedures; the exact lines
  for passwd (default `x`), byuid keying, group members, hosts per name, netgroup triples,
  generic values; NOKEY, NOMAP, NODOM; FIRST/NEXT/NOMORE; ALL and a failed ALL; MASTER,
  ORDER, MAPLIST.
- `udp_answers_and_domain_nonack_is_silent_for_a_refused_domain`: UDP, DOMAIN_NONACK silence,
  and an ALL too big for a datagram refused whole (YP_YPERR).
- `rpc_errors_bad_arguments_and_bounds`: PROG_MISMATCH, PROG_UNAVAIL, PROC_UNAVAIL (XFR),
  GARBAGE_ARGS for a key past YPMAXRECORD and a domain past YPMAXDOMAIN, YP_BADARGS for unusable
  names, RPC_MISMATCH; a record announcing `MAX_CALL + 1` and a call in more than
  `MAX_CALL_FRAGMENTS` fragments close the connection unread; the same call in
  `MAX_CALL_FRAGMENTS` is answered.
- `model_answers_that_would_forge_lines_or_overflow_fail_closed`: a `:` in a gecos and
  `MAX_ENTRIES + 1` entries answer YP_YPERR.
- `a_failed_model_fails_closed_and_invents_nothing`: unreachable model → YP_YPERR in every
  result type, DOMAIN false, DOMAIN_NONACK silent.
- `registers_with_a_portmapper_and_removes_itself_at_stop`: NetGet's sunrpc server as the
  portmapper sees SET for tcp and udp at the NIS port, then UNSET at stop; a refusing
  portmapper fails the start.
- `replies_through_the_pcap_oracle`: tshark's rpc/ypserv dissectors over nine TCP exchanges
  and four UDP ones, and the fields tshark read (value before key in FIRST, master, maplist).

## real_client_test.rs (Linux; root or passwordless sudo, rpcbind running)

`yp_tools_and_ypbind_read_netget`: NetGet registered with the system rpcbind; `rpcinfo -p/-t/-u`;
`ypcat -h` (ALL, `-k`, the `hosts` nickname, a missing map, a refused domain); `yppoll -h`
(DOMAIN, ORDER, MASTER over UDP); `ypbind -f <temp config>` inside `unshare --uts` (the host's
domain name is untouched); `ypwhich`, `ypmatch` (a key, two keys with `-k`, a missing key),
`ypwhich -m`, `yptest` (yp_match, yp_first, yp_next, yp_master, yp_order, yp_maplist); then the
registration is gone after stop. It holds a file lock the client suite's ypserv test also takes,
because program 100004 is one row in rpcbind. It fails rather than skips when any peer is
missing. ypbind writes `/var/yp/binding/netget.test.*`; the test removes them.

Not run on macOS: yp-tools and ypbind-mt are not packaged there (and macOS no longer ships
ypcat). The `nis` job in `protocol-pairs.yml` runs it.
