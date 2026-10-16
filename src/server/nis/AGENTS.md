# NIS server (ypserv)

NIS/YP version 2, ONC RPC program 100004, on TCP and UDP at one port. `wire.rs` is the YP
layer; the RPC layer (call/reply headers, AUTH_NONE/AUTH_SYS, record marking) is the
portmapper's `src/server/sunrpc/wire.rs`, shared rather than copied. The client
(`src/client/nis/`) uses the same two files.

**Security, stated plainly.** NIS has no authentication and no confidentiality. Anyone who can
reach the port can ask for every map, and a passwd entry whose password field holds a hash
serves that hash to them — the historical NIS weakness. The model decides what goes in the
password field; NetGet defaults it to `x` ("not here"). NetGet implements no securenets.

## No fixed port

ypserv has no assigned port. It binds an ephemeral one and registers it with the portmapper;
clients ask port 111. `portmapper` (`host:port`) makes NetGet do that at start — PMAP v2 SET
for 100004 v2 on tcp and udp — and fails the start if the portmapper refuses (another ypserv
already registered, say). At stop a `Registration` guard sends PMAP v2 UNSET from a thread of
its own. The target can be the system rpcbind (it accepts SET/UNSET from loopback TCP) or a
NetGet `sunrpc` server. It is on the well-known-port test's `NO_WELL_KNOWN_PORT` list.

## What Rust answers

- RPC errors: `RPC_MISMATCH` (rpc version ≠ 2), `PROG_UNAVAIL` (another program),
  `PROG_MISMATCH` 2–2 (YP v1), `PROC_UNAVAIL` (XFR, and anything past MAPLIST),
  `GARBAGE_ARGS` (XDR that does not decode, including a string past its `yp.x` bound).
- `NULL` and `CLEAR`.
- `YP_BADARGS` in the procedure's own result type for a name that decodes but is unusable:
  empty, not UTF-8, a control character, whitespace, a `/` or a leading `.` (ypserv joins
  domain and map into a path), or an empty key. Nothing refused reaches the model.
- Walking: FIRST is the first of the model's entries (`YP_NOMORE` if none); NEXT is the one
  after the given key (`YP_NOMORE` after the last, `YP_NOKEY` for a key the map lacks).
- ALL: one `ypresp_all` reply — `{more: TRUE, YP_TRUE, val, key}` per entry, then
  `{more: FALSE}`. A failure is `{more: TRUE, stat, "", ""}` then `{more: FALSE}`. Both shapes
  are what Linux ypserv 4.2 writes (captured from it with tcpdump). Note `ypresp_key_val` puts
  the **value before the key** on the wire; tshark reads it that way too.
- Rendering (`wire::entry_pairs`): passwd.byname/byuid, group.byname/bygid, hosts.byname/byaddr
  and netgroup take structured fields; any map takes `{key, value}` text. Keys are derived
  (name, uid, gid, each host name, the address). A field holding its line's separator (`:`
  in passwd/group, `,` in a member, whitespace in a host name) or a control character is
  **refused, not rewritten** — a `:` in a gecos would shift the home directory into the shell.
- Bounds: a call ≤ `MAX_CALL` (8 KiB) in ≤ `MAX_CALL_FRAGMENTS` (8), refused from the
  fragment header before anything is read; keys and values ≤ `YPMAXRECORD` (1024); domain and
  map names ≤ 64; ≤ `MAX_ENTRIES` (10 000) entries per map; ≤ `MAX_MAPS` (256) maps; a reply
  ≤ `MAX_REPLY` (4 MiB) on TCP, written in 64 KiB fragments, and ≤ 65 000 bytes on UDP. A reply
  over its limit is `YP_YPERR` whole, never cut short (a truncated map reads as complete).
  Idle TCP connections close after 120 s; at most 64 UDP calls are handled at once.

## What the model answers

Nothing is stored; every request asks again.

| Event | When | Answers |
|---|---|---|
| `nis_domain_query {domain, procedure, transport}` | DOMAIN, DOMAIN_NONACK | `nis_domain {served}` |
| `nis_match {domain, map, key, transport}` | MATCH | `nis_entries`, `nis_error` |
| `nis_map_read {domain, map, procedure, key?, transport}` | FIRST, NEXT, ALL | `nis_entries`, `nis_error` |
| `nis_map_info {domain, map, procedure, transport}` | MASTER, ORDER | `nis_map_info {master?, order?}`, `nis_error` |
| `nis_maplist {domain, transport}` | MAPLIST | `nis_maps {maps}`, `nis_error` |

`nis_error {status}` is one of no_domain, no_map, no_key, bad_args, bad_database, error. A
MATCH whose key is not among the model's entries is `YP_NOKEY`.

## Failure

A model failure (LLM error, invalid or contradictory answer, silence, entries that do not
render) answers `YP_YPERR` in the procedure's result type — never an invented entry. DOMAIN
answers false; DOMAIN_NONACK, which only ever says yes, stays silent. Each outcome is logged
`decision=model_answer|model_reject|model_silent|fail_closed_llm_error|fail_closed_invalid_reply|fail_closed_reply_too_large`.

## Not implemented

yppasswdd (100009) — not cheap enough to do honestly here; XFR/yppush; v1; securenets;
`YP_*` bookkeeping keys (ypserv hides them from FIRST/NEXT/ALL too).

## Maturity: Experimental

One client family (yp-tools and ypbind-mt share libnsl/libtirpc), on Linux only, and the pair
job had not run in CI when this landed. See `tests/server/nis/AGENTS.md`.
