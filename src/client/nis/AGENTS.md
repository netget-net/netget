# NIS client

A YP v2 caller over one TCP connection, using the server's `src/server/nis/wire.rs` and the
portmapper's RPC codec. Replies are matched by xid; a stale reply to a timed-out call is
skipped. One call is in flight at a time, with a 10 s deadline. A transport failure ends the
session.

## Finding and binding

- `domain` (required) is the domain bound to.
- `use_portmapper`: remote_addr is a portmapper and ypserv's TCP port comes from PMAP v2
  GETPORT (100004 v2 tcp), as ypbind and `ypcat -h` do. Default: true when remote_addr's port
  is 111. Port 0 ("not registered") fails the connect.
- On connect it calls DOMAIN and raises `nis_connected {remote_addr, portmapper?, domain,
  served}`. A server that does not serve the domain is still connected; the model decides.
  It does not speak the ypbind protocol (100007).

## Actions

`nis_match {map, key}`, `nis_cat {map}` (ALL), `nis_first {map}`, `nis_next {map, key}`,
`nis_master {map}`, `nis_order {map}`, `nis_maplist`, `nis_domain`, each with an optional
`domain` (default the bound one), and `disconnect`. Map names are full names (no nickname
translation: `passwd` is `passwd.byname`). Names and keys are validated before anything is
sent.

Each answers `nis_reply {operation, domain, map?, ok, status, entry? | entries? | master? |
order? | maps? | served?, error?}`. Entries are `{key, value, fields?}`: passwd, group, hosts
and netgroup lines are parsed into fields; values are shown with control characters replaced
by spaces (`sanitize::line_field`, so a hosts line's tab reads as a space). `ok` is true for
YP_TRUE, and for a `cat` that reached the end of the stream.

## Bounds and failure

Replies ≤ `MAX_REPLY` (4 MiB) in ≤ 1024 fragments; ≤ 10 000 entries in an ALL, read in a
loop; ≤ 256 maps. A handler chain stops after `MAX_FOLLOWUP_DEPTH` (8). A failed model call
sends nothing (fail closed) and is logged.
