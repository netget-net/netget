# SSDP / UPnP Discovery Server

SSDP (Simple Service Discovery Protocol), the discovery layer of the UPnP Device
Architecture 1.1. HTTP/1.1 syntax carried in single UDP datagrams — "HTTPU" — on
port 1900, plus the multicast groups `239.255.255.250` (IPv4) and `FF02::C`
(IPv6). The model decides which devices exist and what to advertise.

**State**: Experimental. Honestly so — see "Why not Beta" below; nothing has
validated this against a third-party UPnP control point, and no Rust one could
be pointed at it.
**Privilege**: `PrivilegeRequirement::None`. 1900 is above 1023, so declaring
`PrivilegedPort(1900)` would be dead code — the `svn`/`PrivilegedPort(3690)`
mistake. The multicast join needs no privilege on macOS or Linux.
**Stack**: `ETH>IP>UDP>SSDP`. **Connectionless**: yes, declared (see below).

Files: `message.rs` (pure HTTPU codec + the MX jitter, no I/O), `actions.rs`
(LLM vocabulary + executor), `mod.rs` (socket loop, multicast join, and the
silence rule).

## The single most important property: it says nothing when it cannot answer

**Every message SSDP defines is a positive assertion that a device exists at a
URL.** There are exactly two of them — a `HTTP/1.1 200 OK` answering an
M-SEARCH, and a `NOTIFY` — and there is no third one meaning "I don't know", no
equivalent of DNS SERVFAIL, HTTP 503 or RESP `LOADING`.

That places SSDP in the deliberately-silent class the root `AGENTS.md`
catalogues (declared in `metadata()` with `.deliberately_silent()`), and for the strongest reason on that list. A control point that
receives an advertisement caches it for `CACHE-CONTROL: max-age` seconds —
1800 by convention — and then fetches the `LOCATION` URL. So a fabricated
advertisement does not mislead one peer once; it plants a device that does not
exist in every listener's device table and points them all at a URL that
answers nothing, for half an hour.

Silence is also the *normal* outcome. UDA 1.1 §1.3.3 requires a device whose
type does not match the search target to say nothing at all, so every control
point in existence already handles it. This is the opposite of the `udp` case,
where silence is merely the least-bad option: here it is what a correct device
does most of the time.

### What is logged instead

Nothing distinguishes these cases on the wire, so the log is the only place the
distinction can live. `SsdpServer::decide` produces a `Decision`, and
`handle_request` writes it as a stable `decision=` token before acting:

| Situation | Wire result | Logged decision |
|---|---|---|
| Model returns `send_ssdp_response` | unicast 200 OK to the searcher | `decision=model_response` |
| Model returns `send_ssdp_notify` | NOTIFY to `notify_target` | `decision=model_notify` |
| Model returns `no_response` | **nothing** | `decision=model_reject` (+ `reason=`) |
| Model returns no protocol action | **nothing** | `decision=model_silent` |
| Model's action fails to render | **nothing** | `decision=fail_closed_action_error` |
| LLM call errors / times out | **nothing** | `decision=fail_closed_llm_error`, plus `category=overloaded`/`unavailable` from `WireFailure::classify` |

This is the `radius` discipline transplanted to a protocol whose safe default is
silence rather than denial. The point radius makes — that a model's *denial* and
a model's *silence* must never collapse into one another, which is what OAuth2
lost — matters here too, and is why `no_response` is an action at all rather
than an absence:

* `execute_action` returns `ActionResult::Custom { name: "ssdp_no_response" }`
  for it, **not** `ActionResult::NoAction`. `NoAction` is what `notify_operator`
  and `set_memory` return, so a `no_response` that returned it would be
  indistinguishable from a model that answered with nothing but chat.
* `WireFailure::classify` is still called on an LLM error, and its category is
  still logged — but the classification never reaches the wire. There is no
  header in an SSDP message that could carry it, and a message carrying it would
  still be a well-formed advertisement.

Three structural rules back this up, each pointable-at:

1. **Nothing in `actions.rs` can synthesise a response.** `execute_action`
   produces only what a named action asked for; there is no default and no
   fallback.
2. **`mod.rs` never invents bytes.** Every `Some(Reply)` out of `decide` came
   from an action the model named; the `None` paths write nothing.
3. **Extra results are dropped, not sent.** One datagram gets one answer. A
   model returning three responses would otherwise have three devices recorded
   in the control point's table.

## What the model sees and controls

### Events

Both are raised in `mod.rs` (`Event::new(&SSDP_MSEARCH_EVENT, …)` /
`&SSDP_NOTIFY_EVENT`), and both carry `.with_actions(...)`.

| Event | Raised when | Actions offered |
|---|---|---|
| `ssdp_msearch` | an `M-SEARCH * HTTP/1.1` datagram arrives | `send_ssdp_response`, `no_response` |
| `ssdp_notify` | a `NOTIFY * HTTP/1.1` datagram arrives | `send_ssdp_notify`, `no_response` |

A **status line** (`HTTP/1.1 200 OK`) is another device answering somebody
else's search, which arrives constantly once joined to the group. It raises no
event and is dropped at DEBUG: answering a response would be a discovery loop.
Any other method (`SUBSCRIBE`, which is GENA over TCP, or anything else) is
dropped with a WARN, said out loud so it is not mistaken for the deliberate
silence above.

`ssdp_msearch` carries `st`, `mx`, `man`, `host`, `source_address`,
`user_agent` and the full `headers` map. `ssdp_notify` carries `nt`, `nts`,
`usn`, `location`, `server`, `cache_control_max_age`, `host`, `source_address`
and `headers`.

`headers` is a **map**, never a rendered blob, per the root `AGENTS.md` rule.
`cache_control_max_age` is parsed out of the `CACHE-CONTROL` directive into a
number, because a model asked "is this still fresh?" should not have to parse a
header directive first. `mx` is likewise a number, clamped (below).

### Actions

| Action | Effect | Result variant |
|---|---|---|
| `send_ssdp_response` | unicast 200 OK back to the searcher | `Output` |
| `send_ssdp_notify` | NOTIFY to the group / `notify_target` | `Custom{ssdp_notify}` |
| `no_response` | nothing, deliberately | `Custom{ssdp_no_response}` |

`send_ssdp_notify` cannot be an `Output`: an `Output` goes back to the peer that
spoke to us, and an announcement is addressed to the whole group. That is the
entire reason it is a `Custom` — `mod.rs` routes on the name.

No async actions. An async action is dispatched on the registry's *stateless*
protocol struct, which owns no socket, so it could only return `NoAction` — an
advertised verb that silently does nothing. See "Announcing on our own
initiative" for what that costs.

Parameters are structured throughout. **There is no encoded field anywhere in
this protocol** — SSDP is text end to end, so the `send_tcp_data` hex/utf8 trap
does not arise. `extra_headers` is a name-to-value map, not a pre-rendered
header block.

### `ST` echo, and the one case it cannot cover

A response whose `ST` does not match what was searched for is silently discarded
by a control point, which looks exactly like the server being down. So when the
model omits `st`, `SsdpProtocol::resolve_st` echoes the request's search target.

That is not the server inventing an answer — the answer is the whole
advertisement, and the model already decided to send one. But it **cannot** be
done for a wildcard search: `ssdp:all` and `upnp:rootdevice` have no single
concrete answer, and the response must name the concrete type. Those two cases
return an `Err` naming the reason rather than echoing the wildcard back, which
would produce a response no control point can use.

## MX: the response jitter

UDA 1.1 §1.3.3 says a device waits a random interval between 0 and the
request's `MX` seconds before answering a multicast M-SEARCH. The point is to
spread a whole network's answers so the control point is not flooded — and it
is also what makes NetGet's traffic look like a device's rather than like a
machine answering instantly every single time.

Implemented in `message::response_delay_ms`, with two deliberate deviations:

* **`MX` is clamped to 5 seconds** (`MAX_MX_SECONDS`), which is what §1.3.2
  requires a device to do. Without the clamp, `MX: 4000000` would park a
  response task for six weeks.
* **The operator caps it** with `max_response_delay_ms` (default 1000). A
  faithful 5-second wait makes every test that touches this protocol five
  seconds slower. The actual delay is uniform over `0..=min(MX*1000, cap)`;
  a cap of `0` disables the jitter entirely.

The deadline is computed **before** the LLM call and slept to afterwards, so the
model's own latency counts *towards* the wait rather than being added on top of
it. The jitter is a floor on the response time, not a tax.

`response_delay_bound_ms` is separated from the draw specifically so the range
can be tested without a clock — a timing assertion at `--test-threads=100` is a
flake, and the property worth pinning is the bound, not the wall time.

## Multicast, and what actually fails on macOS

The join is **best effort**: a failure is a warning on both channels, never an
`Err`. A server that refused to start when the join failed would be unusable for
exactly the local testing this protocol is most often used for, and **a unicast
M-SEARCH sent straight to the port is answered whether or not the join
succeeded** — that is the whole functional surface minus the ability to overhear
the group. It is logged rather than passed over because a silent failure here
presents as "the server is up but never sees any searches", which is
indistinguishable from the server being broken.

**Measured on macOS 27 (Darwin), and the expected result was wrong:**

| Operation | Socket bound `127.0.0.1` | Socket bound `0.0.0.0` |
|---|---|---|
| `IP_ADD_MEMBERSHIP` for 239.255.255.250 (iface `127.0.0.1` or `0.0.0.0`) | **succeeds** | succeeds |
| `sendto(239.255.255.250:1900)` | **fails, `EADDRNOTAVAIL` (49)** | succeeds |

So the received wisdom that "joining a group on loopback fails on macOS" did not
hold here; what fails is *sending* to the group, because loopback carries no
multicast route. That asymmetry is why `notify_target` exists, and why the join
is not the thing standing between this server and a local test.

`multicast_interface` selects the local IPv4 address to join on; an IPv6 bind
joins `FF02::C` on interface index 0 and ignores it. Which group is used is
decided by the family actually bound, not by what was asked for.

## Startup parameters

Every one is declared in `get_startup_parameters()` and read in
`spawn_with_llm_actions`; errors propagate with `?` and are never `unwrap()`ed,
so an undeclared key or a wrong type names itself instead of killing the task
that is starting the server.

| Parameter | Default | Effect |
|---|---|---|
| `max_response_delay_ms` | 1000 | ceiling on the MX jitter; 0 answers immediately |
| `server_header` | `NetGet/1.0 UPnP/1.1 NetGet-SSDP/1.0` | default `SERVER`; an action's own `server` overrides it |
| `join_multicast` | `true` | whether to attempt the group join at all |
| `multicast_interface` | `0.0.0.0` | local IPv4 address to join on |
| `notify_target` | the group | where `send_ssdp_notify` datagrams are actually sent |

`notify_target` deserves the explanation it carries in its own description: the
`HOST` header of an announcement **always** names the multicast group whatever
this is set to, because that is what the header means — the group the
announcement is *about*, not the socket it travelled over. Overriding the target
points announcements at one listener, which is the only way to observe them from
a loopback bind (see the table above).

## Connection tracking and the idle sweep

`metadata()` declares `.connectionless()`. Each datagram is registered as its
own pseudo-connection with the peer as `remote_addr`, and nothing ever closes
those entries — so without the flag a busy port would grow the AppState
connection list without bound, exactly as `udp` does. With it,
`AppState::cleanup_old_connections` evicts entries idle for 10 seconds, which is
correct here: there is no session to interrupt. `update_connection_stats` is
called on every successful send so the rail's `↑` counter is real.

## Task registration

`spawn()` awaits the bind and returns `Err` on failure, so `server_startup` sets
`ServerStatus::Error` rather than reporting `Running` on a server that never
came up (the ARP/DataLink/ICMP defect).

Both the accept loop **and every per-datagram task** are registered with
`AppState::register_server_task`. The per-datagram registration is not
boilerplate: an M-SEARCH answer can be held back for up to
`max_response_delay_ms`, so those tasks routinely outlive the datagram that
created them, and without registration a *stopped* server could still emit an
advertisement. BGP's keepalive timer is the precedent — aborting a loop does not
abort what the loop spawned. `register_server_task` prunes finished handles on
every call, so this does not accumulate.

## Not implemented

Everything above the discovery layer:

* **No device description document.** The model supplies a `LOCATION` and
  something else must serve it. NetGet does not run an HTTP server for it, and
  does not check that anything answers there.
* **No SOAP control, no SCPD, no GENA eventing** (`SUBSCRIBE`/`NOTIFY` over
  TCP). Those are the parts of UPnP that do the actual work; this protocol is
  only how a control point finds a device in the first place.
* **No `BOOTID.UPNP.ORG` / `CONFIGID.UPNP.ORG` / `SEARCHPORT.UPNP.ORG`
  bookkeeping.** UDA 1.1 §1.2 defines a reboot/config versioning scheme; the
  model can set those headers by hand through `extra_headers`, and nothing
  maintains them.
* **No duplicate suppression and no per-search rate limiting.** A control point
  that retransmits its M-SEARCH costs another LLM call each time.
* **No storage**, deliberately: the model invents every device. There are no
  registered devices, no device table and no persistence. If a scenario needs
  one, that is what the generic SQLite facility is for.

### Announcing on our own initiative

**NetGet never announces spontaneously.** `send_ssdp_notify` is reachable only
in reply to an inbound `ssdp_notify` event, because a server has exactly two LLM
entry points and both of them are event-driven. A real UPnP device multicasts
`ssdp:alive` on boot, re-announces before `max-age` expires, and sends
`ssdp:byebye` on shutdown; none of that happens here.

This is a genuine gap, and the honest description of it is that closing it needs
a third event (a startup event, as `mdns` has) or a scheduled task with a path
back to the socket. Neither exists. It is written down here rather than papered
over with an async action that would return `NoAction`.

## Message-level details worth knowing

* **`EXT:` is not a typo.** UDA 1.1 §1.3.3 requires it in a search response with
  an *empty* value; it is a marker saying the MAN extension was understood.
* **`ssdp:byebye` carries only `HOST`, `NT`, `NTS` and `USN`** (§1.2.3). The
  executor strips `LOCATION`, `SERVER` and `CACHE-CONTROL` even when the model
  supplies them: a byebye that told the control point where to reach the device
  and how long to keep believing in it would contradict itself.
* **`DATE` is an HTTP-date ending in the literal `GMT`.** `chrono`'s
  `to_rfc2822` renders `+0000`, which is RFC 2822 and not HTTP.
* **`MAN` keeps its quotes.** A conforming M-SEARCH sends `"ssdp:discover"`
  including them; the model is shown the value verbatim so it can tell a
  conforming search from a probe that is not doing UPnP discovery. Nothing here
  rejects a non-conforming `MAN` — that is the model's call.
* **CR/LF in any model-supplied header name or value is refused**, not
  sanitised. It would let one action emit several headers or end the message
  early and append a second one — the HTTP response-splitting shape — and in
  this protocol that means injecting a second, attacker-chosen `LOCATION`. The
  mandatory header names are additionally refused inside `extra_headers`, so
  they cannot be emitted twice.
* **`LOCATION` must parse as an absolute `http`/`https` URL.** The whole meaning
  of a response is "the description document is *there*"; a LOCATION that is not
  fetchable makes the advertisement useless while still looking valid on the
  wire, which cannot be debugged from the control point's end.
* **An unknown `NTS` is refused.** UDA defines exactly three, and a control
  point ignores anything else — so an unchecked one is a silent no-op the model
  would believe had worked.
* **Bare LF is tolerated on input**, because real implementations are sloppy;
  everything emitted is strictly CRLF.
* **A datagram over `MAX_MESSAGE_LEN` (8192) is dropped, not truncated.** A
  half-message parses into plausible-looking headers, which is worse than
  nothing.

## Why not Beta

The repo's bar for Beta is "works against real clients", evidenced by a test
that drives a third-party implementation and is neither `#[ignore]`d nor
skip-when-missing. **No such test is possible for this protocol**, and the
reason is structural rather than a gap in one crate.

Every Rust SSDP client surveyed (2026-09) sends its M-SEARCH to the hardcoded
multicast group and cannot be pointed at a unicast address and an ephemeral
port:

* **`ssdp-client` 2.1.0** — the obvious candidate. Its entire public surface is
  five items, and `search(&SearchTarget, timeout, mx, ttl)` has no destination
  parameter; the destination is the inline literal `([239,255,255,250], 1900)`
  in `src/search.rs`. Discovery-client only, no responder side.
* **`rupnp` 3.0.0** — re-exports `ssdp_client::search` for discovery, so same
  answer. (Its `Device::from_url` *can* take an arbitrary URI, but that
  exercises description fetching and SOAP, which this protocol does not
  implement.)
* **`ssdp` 0.7.0** — has a real `unicast(dst_addr)` API, but sources its sockets
  from `all_local_connectors`, which filters loopback addresses out. It also
  pulls `hyper 0.10` and `time 0.1` (RUSTSEC-2020-0071).
* **`upnp-rs` 0.2.0** — has `search_once_to_device(options, SocketAddr)`
  documented as a unicast search, but it delegates to a helper that calls
  `join_multicast_v4(to_address.ip(), ...)` unconditionally with `?`, so a
  `127.0.0.1` destination fails at the join. It also hardcodes `HOST:
  239.255.255.250:1900` regardless of the destination, and would add duplicate
  `reqwest`/`pnet`/`quick-xml` stacks.
* **`cotton-ssdp` 0.1.0** — has both sides, but no caller-specified destination.

A server bound to `127.0.0.1` on an ephemeral port cannot receive a datagram
sent to the group anyway, so this is a dead end and not a missing dependency.
The two remaining options are both explicitly *not* third-party evidence under
the root `AGENTS.md`: a hand-written M-SEARCH sender inside the test (the
`dhcp` / `usbip_client` class — an independent reading of the spec, not an
independent implementation), or vendoring `ssdp-client`'s search function with
the destination parameterised, which stops being a third-party client the
moment it is edited.

**No dependency was added for this.** If a future maintainer wants to try the
description/SOAP layer instead — which would validate a *different* protocol
than this one — the line is:

```toml
rupnp = { version = "3.0", default-features = false }
```

## Example prompts

```
run an ssdp server on port 1900 pretending to be a MediaServer at
http://192.168.1.10:8080/description.xml; answer searches for MediaServer and
ssdp:all, and stay silent for anything else
```

```json
{"type": "open_server", "port": 1900, "base_stack": "ssdp",
 "startup_params": {"max_response_delay_ms": 1000},
 "event_handlers": [{"event_pattern": "ssdp_msearch", "handler": {"type": "script",
   "language": "python",
   "code": "st = event.get('st', '')\nuuid = 'uuid:9f8d2b31-4c5e-4a90-8f21-0e6f5a7c1d33'\ntarget = 'urn:schemas-upnp-org:device:MediaServer:1'\nif st in ('ssdp:all', 'upnp:rootdevice', target):\n    respond([{'type': 'send_ssdp_response', 'st': target, 'usn': uuid + '::' + target, 'location': 'http://192.168.1.10:8080/description.xml'}])\nelse:\n    respond([{'type': 'no_response', 'reason': 'not a media server search'}])"}}]}
```

Note that the script branch answers `no_response` rather than falling off the
end. Both do the same thing on the wire; the difference is that one is recorded
as `decision=model_reject` with a reason and the other as `decision=model_silent`,
and only the first tells an operator reading the log that the silence was
intended.

## References

- UPnP Device Architecture 1.1, §1 (Discovery) —
  <https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v1.1.pdf>
- UDA 1.1 §1.2 (advertisement / NOTIFY), §1.3 (search / M-SEARCH)
- The expired IETF draft `draft-cai-ssdp-v1-03`, which is where the HTTPU idea
  and the `MX`/`MAN` headers originate
- `tests/server/ssdp/AGENTS.md` — test strategy and LLM call budget
