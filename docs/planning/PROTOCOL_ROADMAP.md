# NetGet Protocol Roadmap

Durable tracking for the protocol-expansion programme started September 2026:
what we decided to build, why, and where each item stands.

**This is not a status report.** The root `CLAUDE.md` warns against adding
one-off session/status files — that is what let the root directory reach 63
markdown files. This is one file, updated *in place* as items move, and it is
meant to be edited rather than superseded. If an item lands, change its row;
do not write a new file about it. When every row here reads `landed`, fold the
durable lessons into `CLAUDE.md` and delete this file.

## Programme 2 — complete (13 September 2026)

**All 39 batches are merged and pushed.** Every server and client protocol has had
a pass against the eight-point rubric below. Roughly 200 defects were fixed. The
counts drift; re-derive rather than quoting these.

Promotions earned during the pass: `kubernetes` (server) and `ollama` to `Beta`,
each on evidence that was checked rather than taken on report. `nfc`'s client went
`Incomplete` → `Experimental` — `Incomplete` makes `is_available_to_llm()` false, so
the model could not see it at all, which contradicted the claim elsewhere that no
`Incomplete` protocols remain.

**The defect classes worth carrying forward**, in rough order of how often they
recurred and how quietly they failed:

| Class | The shape it takes |
|---|---|
| Fail-open default | An omitted field becomes an affirmative answer. NFC and usb-smartcard both defaulted an APDU status word to `90 00`, in two layers each, so an *omission approved an authentication*. |
| Narrowing cast | `as u16` on a model- or wire-supplied number. `65736 as u16 == 200`. It turned refusals into successes, and in Modbus it turned a typo into a plausible *fail-closed* answer — the first instance to land on the safety mechanism itself. |
| A test that encodes the bug | The BLE HID descriptors, the GATT UUID keying, and one bcdHID assertion were all *documented as the interface*. A green suite proves nothing when the only real parser lives on someone else's machine. |
| An advertised knob that does nothing | `send_first` in seven servers; `auto_advertise` in the BLE base; every BLE sensor profile's script-mode example, which assigned a local and printed nothing so the event fell back to the LLM. |
| A bound decided by configuration rather than by the answer | tuntap skipped its LLM budget whenever a script handler was *configured*, but the executor falls back to the model when the language is missing — so the shipped example on a box without `python3` was one uncounted model call per packet at wire rate. |
| Unbounded pre-auth input | Request bodies, URB assembly buffers, TLV walks. usb-fido2 reserved up to 64 KiB from one 64-byte packet, on unlimited channels, indefinitely. |
| A client that reaches the vendor instead of the target | The `openai` client fell back to real OpenAI with the operator's key; the `openapi` client took its base URL from a model-supplied spec ahead of the operator's address. |

Two things that made these findable and are worth keeping: **agents stayed inside
their boundaries and reported across them** (the NFC → usb-smartcard handover, the
`bluetooth_ble_presenter` ownership gap), and **every promotion was re-derived from
the evidence rather than accepted from a summary**.

## Where Programme 1 stood (4 September 2026)

**All 30 protocols have landed**: 8 servers, 8 clients, 14 root/privileged. Four
are `Beta`; the other 26 are `Experimental`, each with its *reason* recorded
rather than a hedge.

Verified after the last one landed:

| Check | Result |
|---|---|
| `--features all-protocols` compile | clean (3 pre-existing lib warnings, none in the new 30) |
| Full suite, `--test-threads=100` | **1265 server + 360 client = 1625 passed, 0 failed** |
| Six whole-tree ratchets, at `all-protocols` | 29 passed, 0 failed |
| Orphaned test directories | none, either tree |
| New `#[cfg(test)]` under `src/` | none — the five pre-existing files are unchanged |
| `cargo fmt --check` | clean tree-wide |
| `/Users/matus/bin/netget` | rebuilt with `all-protocols` and reinstalled |

**Three test-deadline defects were found only by the full sweep**, all the same
shape: asserting a condition while waiting on something that happens *earlier*.
Two in `tuntap` (waiting on an arrival counter plus a fixed 120 ms settle, then
asserting a decision) and one in `gtp` (waiting for the model to be called, then
asserting on a log line written after its answer is handled). Each passes alone
in under a second at any feature set — which is exactly why the root `CLAUDE.md`
says passing in isolation tells you the *deadline* was wrong, not that the code
is fine. No assertion was changed; only what each waits for. GTP's wire
assertions had already passed, so its protocol behaviour was provably correct
and only the log line was in flight.

One failure seen mid-sweep was **`server::webrtc::…data_channel_message_round_trip`**,
which this programme never touched (`git log` confirms) and which passed on the
final run. It is load-flaky and pre-existing, and worth someone's attention:
under load its mock expectations go unmet and it trips the
`Server dropped without calling .verify_mocks()` guard.

## Status legend

| Status | Meaning |
|---|---|
| `planned` | Specified below. Nothing exists in the tree. |
| `wired` | Feature flag, module declaration, registry entry and test-module declaration exist. No implementation. |
| `building` | An agent is implementing it right now. |
| `landed` | Committed, compiles, its own tests pass. **Not** a claim about maturity — see below. |
| `blocked` | Needs something that does not exist yet. Reason recorded in the row. |

`landed` and the protocol's `DevelopmentState` are different claims. `landed`
means the code is in. `DevelopmentState` means what the evidence supports, and
the bar for `Beta` is a **real third-party client, not `#[ignore]`d, that
fails rather than skips when the client is missing**. Read the "Protocol
inventory" section of `CLAUDE.md` before promoting anything; three protocols
have been demoted for treating a codec or a skipped test as evidence.

## Environment constraints (measured on this machine, Darwin 27, September 2026)

These decide which items can be validated locally and which cannot. Re-measure
rather than trusting them.

| Fact | Consequence |
|---|---|
| **`feth` driver present** (`net.link.fake.txstart: 1`) | `sudo ifconfig feth0 create && ifconfig feth1 peer feth0` gives a real Ethernet pair with **no hardware**. Every Tier-1 L2 protocol below can be driven end to end locally. |
| **`/dev/bpf*` present** | Capture and injection available under root. |
| **`utun` available** (5 present) | TUN endpoint is viable on macOS. |
| **Multicast on loopback: joining works, *sending* does not** | Measured on macOS 27, and it contradicts the received wisdom that the *join* fails. Bound to `127.0.0.1`, `join_multicast_v4(239.255.255.250)` **succeeds**; `sendto(239.255.255.250:1900)` fails with **`EADDRNOTAVAIL` (49)** because loopback carries no multicast route. Bound to `0.0.0.0` both work. Any multicast protocol therefore needs a unicast target parameter to be observable in a test — do not "fix" a join that is not broken. |
| **No SCTP on macOS** (no headers, no stack) | M3UA/SIGTRAN cannot use its real transport here. See its row. |
| **No `AF_CAN` on macOS** | SocketCAN is Linux-only. Linux `vcan` needs no hardware, so it is testable *there*. |
| **802.11 injection unavailable on macOS** | Monitor mode works, injection effectively does not. Rogue-AP work would be Linux + specific chipset. Deferred. |
| Installed real clients | `curl` (with gopher), `finger`, `nmblookup`, `smbclient`, `whois`, `ffmpeg`, `docker`, `openssl`, `redis-cli`. No `nmbd`/`smbd` daemon, no `nats-server`, no UPnP tools. |

**The wireguard trap applies to everything privileged here.** A protocol that
cannot be started in the environment that tests it cannot be validated, and
`CLAUDE.md` records what happened when one was rated `Stable` anyway. Prefer
the items testable on `feth`/`utun` under sudo; for the Linux-only ones, either
run them in a Linux container in CI or rate them honestly and say why.

---

## Wave 1 — text and discovery servers

Eight servers. Wiring landed in `2f599954`; each implementation is committed
separately by the agent that wrote it.

| Protocol | Feature | Module | Transport | Privilege | Validation target | Status |
|---|---|---|---|---|---|---|
| NATS | `nats` | `nats` | TCP 4222 | none | **`async-nats` 0.50, official client, non-circular (we use no NATS library)** | `landed` (`b5d451ed`) — **Beta** |
| STOMP | `stomp` | `stomp` | TCP 61613 | none | **`async-stomp` 0.6.3** drives a full session and decodes every frame itself | `landed` (`f9b4e946`) — **Beta** |
| Ident | `ident` | `ident` | TCP 113 | `PrivilegedPort(113)` | **none exists** — no RFC 1413 client anywhere takes a configurable port | `landed` (`59a3003b`) — Experimental |
| Gopher | `gopher` | `gopher` | TCP 70 | `PrivilegedPort(70)` | **`curl gopher://` — real, arbitrary port** | `landed` (`a3573323`) — **Beta** |
| Finger | `finger` | `finger` | TCP 79 | `PrivilegedPort(79)` | `finger(1)` confirmed port-locked to 79 → needs root | `landed` (`a28bf0a2`) — Experimental |
| SSDP | `ssdp` | `ssdp` | UDP 1900 mcast | none for the *server*: no Rust SSDP client can be aimed at a unicast loopback port. **This does not generalise — see the correction below** | `landed` (`5cb49c9a`) — Experimental |
| LLMNR | `llmnr` | `llmnr` | UDP 5355 mcast | none | **none** — only LLMNR crate is a responder, not a querier; real clients are Windows/systemd-resolved. Evidence is circular by construction | `landed` (`19ebd0eb`) — Experimental |
| NetBIOS-NS | `netbios-ns` | `netbios_ns` | UDP 137 | `PrivilegedPort(137)` | `nmblookup` 4.24.6 **confirmed port-locked to 137** (`nbt port=` is parsed and ignored by the client; proven with tcpdump). Its captured datagrams pin the *decode* direction; the *response* direction is unvalidated | `landed` (`2901a6e9`) — Experimental |

SSDP, LLMNR and NetBIOS-NS are in the **deliberately-silent** class: every
reply is a positive assertion (a device exists / a name maps to an address), so
on LLM failure they must emit *nothing* and record `decision=` in the log the
way `src/server/radius/` does. A fabricated answer poisons a cache.

---

## Wave 2 — clients

All eight of Wave 1 also get clients. Each reuses its server's **existing
Cargo feature**, so no new feature flags — only `src/protocol/client_registry.rs`,
`src/client/mod.rs` and `tests/client/mod.rs` entries.

**Every one of these is unprivileged even where its server is not.** Sending to
UDP 137 or 1900 from an ephemeral source port needs no privilege; only *binding*
the well-known port does.

| Client | Module | What it does | Validation target | Status |
|---|---|---|---|---|
| SSDP | `ssdp` | M-SEARCH discovery of real UPnP devices; surfaces `LOCATION` but deliberately does **not** fetch it (that would turn discovery into an outbound request to an attacker-controlled URL) | A device **emulator** is a live option — see the correction below | `landed` (`29708887`) — Experimental |
| NetBIOS-NS | `netbios_ns` | `nbtstat` equivalent — name query + node status | **Encode is byte-identical to real `nmblookup` queries** (captured with tcpdump, both `NB` and `NBSTAT`). **Decode has no independent evidence** — see the asymmetry note below | `landed` (`41c35f42`) — Experimental |
| NATS | `nats` | Joins a real NATS fabric; LLM reacts to live messages and publishes | **`nats-server` v2.14.6 routes and `async-nats` requests — independent implementations on *both* sides** | `landed` (`a982ccc1`) — **Beta** |
| Ident | `ident` | Queries a remote identd — what an IRC server does. Makes the existing `irc` server able to do genuine ident lookups | **None, structurally**: RFC 1413 has no configurable port, so nothing can be aimed at an ephemeral one | `landed` (`bec74f5d`) — Experimental |
| LLMNR | `llmnr` | Resolves a name via LLMNR multicast; collects a whole window and raises `llmnr_conflicting_responses` when responders disagree | Real Windows / systemd-resolved hosts. **`llmnr-poison` considered and declined — see below** | `landed` (`f415efb4`) — Experimental |
| STOMP | `stomp` | Same shape as NATS, against ActiveMQ/RabbitMQ | Needs a real broker. **The two assertions that would catch a buggy client past a lenient one are written down** in `src/client/stomp/AGENTS.md` | `landed` (`702eb22f`) — Experimental |
| Gopher | `gopher` | Browses gopherspace; LLM navigates menus | **`geomyidae`/`gophernicus`/`pygopherd` all bind an ordinary port and run fine on loopback** — the external-endpoint ban was never the blocker; none is installed, and a hard-fail (not skip) test would earn Beta | `landed` (`be405db9`) — Experimental |
| Finger | `finger` | Queries a remote finger daemon; **does not parse the response** (RFC 1288 specifies no format) — raw text to the model, with any scraped field marked `GUESS ONLY` | No packaged daemon anywhere (no Homebrew formula for `bsd-finger`/`fingerd`/`netkit`), but a daemon *can* bind a high port, so Beta is achievable in principle | `landed` (`e3f58a57`) — Experimental |

**Evidence can be asymmetric, and the rating must follow the weaker half.**
The NetBIOS-NS client is the worked example: its *encoder* is independently
pinned — the queries it generates are byte-identical to ones real `nmblookup`
4.24.6 puts on the wire — while its *decoder* has met no responder but our own.
It stayed `Experimental`, because Beta's claim is "works against real clients"
and the unproven direction is the one that matters. Note what was *not* done:
stepping down one notch into a rating the same evidence also rules out, which is
the `wireguard` error `CLAUDE.md` records.

Two practical notes from that work, both worth reusing: `tcpdump -i lo0` needs
only `access_bpf` group membership, not root, so capturing a real client's
datagrams is available here; and **hand-transcribing encoded NetBIOS names does
not work** — a 30-character run of `A`s was copied wrong twice, once a byte long
and once a byte short, and both failures read exactly like an encoder bug.
Generate such literals from the pcap with a script.

**Dependency decision: `llmnr-poison` was evaluated and declined (September 2026).**
It is a genuine independent LLMNR encoder — a pure function, depending only on
`anyhow` and `tokio`, so it hand-rolls the DNS wire format and shares no codec
with us. That would have broken the *codec* axis of the LLMNR client's circular
evidence. It was declined anyway, on two grounds that both have to be weighed:

- **Supply chain.** v0.1.0, published three weeks earlier, single author,
  offensive-security purpose, and its stated repository (`icedracon/llmnr-poison`)
  returns 404. A dev-dependency still executes on every developer's machine and in
  CI.
- **It would not have changed the rating.** The *same-project* axis remains — our
  own responder is still the peer — and an independent response *encoder* is not a
  running responder. The protocol stays `Experimental` either way.

A dependency that carries real risk and buys no evidence is a bad trade. If it
matures, has a real repository, and someone wants the codec axis broken, revisit
it — but the rating argument will still not hold on its own.

**A correction worth carrying, from the SSDP pair.** The server-side finding —
"no Rust SSDP crate can be aimed at a unicast loopback port" — is about crates
that *search*, i.e. control points. **It does not generalise to the client half**,
which needs a peer that *answers*, and a device replies to wherever the search
came from. So a device emulator is a live option for the client even though a
client crate was not for the server. Check which *role* a missing-peer finding
applies to before reusing it; the two halves of a protocol have different needs.

**Wave 2 is complete — all eight clients landed.** Seven are `Experimental`
because their only peer is NetGet's own server (same-project evidence: it shows
the two halves agree, not that either matches the spec). **NATS is the exception
and the template**: the official `nats-server` routes while `async-nats`
requests, so both sides are independent implementations.

A pattern worth copying from the STOMP client: rather than just recording "a real
broker would earn Beta", it wrote down **the two specific assertions a lenient
broker would let a buggy client past** — that the delivery was *acknowledged*
rather than redelivered (catching an `ACK` that quotes `message_id` instead of
the `ack` header), and that the session closed on the `RECEIPT` rather than on
the grace timeout. A "what would earn Beta" note is far more useful when it names
the assertions than when it names the software.

Client-specific rules that have bitten this repo before, from `CLAUDE.md`:

- **Do not throw away the model's answer.** The single most common client
  defect, found in six protocols in one pass: `let _ = result.actions`, a bare
  `debug!` of `.len()`, or executing follow-ups through a path that raises no
  event. Box the recursive call and cap it (`MAX_FOLLOWUP_DEPTH`, 4–8).
- **Clients union their action sets** — `client_llm_action_set` is
  async ∪ sync ∪ the firing event's actions. A client cannot express a
  narrowing, so do not try.
- Register **every** spawned task, not just the read loop (BGP's keepalive
  timer kept a socket alive after `remove_client()`).
- Adopt `command_support::register_command_channel` so the dashboard `[send]`
  works, and register it **before** any call that might park on a connect event.

---

## Wave 3 — root and privileged protocols

Thirteen protocols. This is the tier the maintainer considers most interesting,
and the tier where the wireguard trap is most dangerous.

### Tier 1 — L2 impersonation ("NetGet as a rogue switch")

All raw-Ethernet, all `PrivilegeRequirement::RawSockets`, all testable locally
on a `feth` pair under sudo. Pairs with existing `arp` / `datalink` / `isis`,
and shares their `pnet` dependency.

| Protocol | Feature | Module | Wire | What the model decides | Status |
|---|---|---|---|---|---|
| LLDP | `lldp` | `lldp` | EtherType 0x88CC, dest `01:80:C2:00:00:0E` | Chassis/port/system TLVs — impersonate a switch to its neighbour | `landed` (`5e87ba2a`) — Experimental |
| CDP | `cdp` | `cdp` | SNAP, dest `01:00:0C:CC:CC:CC` | Device model, IOS version, native VLAN — the classic recon leak | `planned` |
| STP/RSTP | `stp` | `stp` | 802.3 LLC, dest `01:80:C2:00:00:00` | Bridge priority. Claiming root bridge is a real attack | `landed` (`c4090e37`) — Experimental |
| VRRP + CARP | `vrrp` | `vrrp` | IP proto 112, mcast `224.0.0.18` | Election priority — winning it hijacks the default gateway | `landed` (`88e12101`) — Experimental |
| HSRP | `hsrp` | `hsrp` | UDP 1985, mcast `224.0.0.2` | Same, Cisco's version. **Unprivileged, so the transport genuinely executes** — no HSRP crate exists in any role; only a Cisco device is a real peer | `landed` (`28781187`) — Experimental |
| EAPOL / 802.1X | `eapol` | `eapol` | EtherType 0x888E | Authenticator role. **The strictest fail-closed design here** — see below | `landed` (`5e05313a`) — Experimental |
| Wake-on-LAN | `wol` | `wol` | UDP 9 (or EtherType 0x0842) | Whether a magic packet is honoured, and what is reported | `landed` (`4da604c9`) — Experimental |

**A design consequence LLDP surfaced, which applies to every raw-socket protocol
here.** `privilege_requirement` is a *static* property of the protocol, so a
protocol honestly declaring `RawSockets` is refused by `server_startup` on an
unprivileged host **even when started in UDP test mode**. The test transport is
therefore reachable by calling `Server::spawn` directly — which is what the
suites do, following `bluetooth_ble_beacon` — and not through
`open_server`/MCP. Declaring `None` to dodge that would be a lie about the
transport anyone actually uses, so do not. If this becomes a real obstacle, the
fix is a dynamic privilege check in `server_startup`, not a false declaration.

**VRRP/CARP and HSRP are split deliberately.** VRRP and CARP share a transport
(IP protocol 112) and semantics, so one module with a `variant` startup
parameter is honest. HSRP is UDP — a different transport — and forcing it into
the same module would mean one protocol with two socket types.

**EAPOL is the highest-value item in this tier**: with the existing `radius`
server it forms a complete NAC lab — EAPOL on the wire → RADIUS → the model
decides admission. Build it after or alongside a review of `src/server/radius/`,
whose fail-closed design it must match. An 802.1X authenticator that fails open
is an authentication bypass, which is exactly the OAuth2 defect `CLAUDE.md`
calls the most dangerous pattern in the codebase.

**Wake-on-LAN privilege note:** the UDP form listens on port 9, which is below
1024 — declare `PrivilegedPort(9)`, not `None`. `CLAUDE.md` records `svn`
declaring `PrivilegedPort(3690)`, which can never fire and read as protection
while being dead code; do not invert that mistake here.

**EAPOL is the reference implementation of fail-closed in this repo now**, and
the technique generalises to any protocol where one message *is* an authorisation.
`EAP-Success` cannot be produced except by an explicit model action, guaranteed
four ways: the registry instance holds no request context so it can encode
nothing; `send_eap_success` is refused unless the session already holds an
`EAP-Response/Identity`; the decision layer re-checks the encoded frame so a
regression in that gate is *reported* rather than served; and — the structural
one — **`eapol_eap_success_frame` and `eapol_eap_failure_frame` are eight literal
octets each and share no code**. There is deliberately no
`encode_eap_result(code, id)`, so no boolean exists that could be inverted. Every
fail-closed exit calls the failure builder directly, never the executor.

When its hand-rolled MD5 was later replaced by the `md-5` crate (`008c7261`),
the RFC 1321 and RFC 1994 vector tests were **kept and re-documented** rather
than deleted with the implementation: they no longer claim to be an oracle for
our digest, they guard our *use* of someone else's. A wrapper that feeds the
hasher the wrong buffer, drops an update, or returns the digest with the wrong
endianness would pass every other test in the file and fail those four. Deleting
vector tests along with a hand-rolled primitive is the reflex to resist.

Its own e2e suite then found a real defect the unit tests could not: the model's
`expected_password` was never recorded, so MD5 verification could never succeed.
Being fail-closed, it presented as a stuck exchange rather than a bypass — which
is the whole argument for building it that way round.

**Two lessons from HSRP worth reusing.** First, **state codes that overlap
across versions with different meanings are a silent-corruption trap**: HSRP code
`4` is *Speak* in v1 and *Standby* in v2, both valid, so a mis-decode produces a
plausible wrong answer rather than an error. The fix was to never let a state
cross a version boundary as an integer, have the model see and produce names
only, and pin it from **both** directions — a test in one direction alone passes
with the bug present.

Second, **the fail-closed logging vocabulary is protocol-shaped, not universal**.
`radius` separates `model_reject` from `model_silent` because it has an
Access-Reject to send. HSRP has no negative message at all, so a refusal and an
abstention are the same act and collapse to `model_silent`; what stays
distinguishable — and what actually matters — is that act versus every
`fail_closed_*`. Copy radius's discipline, not its exact token list.

**The single sharpest protocol finding of this programme, from VRRP.**
**CARP is byte-ambiguous with VRRPv2 and misdecodes into the most dangerous
possible message.** Its first octet is `0x21` — a valid VRRPv2 advertisement.
Its `carp_authlen` of 7 lands exactly on VRRP's count-IP-addresses octet, and
`8 + 7*4 == 36` is precisely the CARP header length, so a VRRP decoder accepts a
real CARP packet **without erroring**. Worse, `carp_advskew` of 0 lands on
VRRP's priority field — so a perfectly healthy CARP host decodes as *a master
resigning*, which is the one advertisement that provokes an immediate election.

That is why `variant` is a startup parameter and is **never sniffed**, and why
`a_carp_advertisement_misdecodes_as_a_vrrpv2_resignation` exists to pin it.
Generalise the lesson: when two protocols share a transport, check whether their
headers are *distinguishable* before writing a sniffer — and if they are not,
make the operator say which one, rather than guessing.

A real bug its own CARP e2e caught, worth knowing as a shape: `execute_action`
runs with **no server config in scope**, so it validated a CARP server's action
against the VRRP defaults and rejected `advskew` — the entire CARP path was
unreachable. Anything that validates against configuration must be given that
configuration, or it validates against the wrong thing.

### Tier 2 — IPv6

| Protocol | Feature | Module | Transport | Privilege | Status |
|---|---|---|---|---|---|
| NDP | `ndp` | `ndp` | ICMPv6, raw socket | `RawSockets` | `landed` (`ad5ebe4a`) — Experimental |
| DHCPv6 | `dhcpv6` | `dhcpv6` | UDP 547 | `PrivilegedPort(547)` | `landed` (`2724244c`) — Experimental |

Both belong to the **deliberately-silent** class for the same reason as LLMNR:
an NDP or DHCPv6 answer writes a binding into the peer's stack. Fabricating one
is cache poisoning. Fail silent, log `decision=`.

**The no-storage rule has a consequence worth generalising, which DHCPv6 found
the hard way.** NetGet holds nothing between one model call and the next — so in
any multi-message exchange where the client correlates replies on a
*server-generated* identifier, that identifier must be **deterministic**, not
random. A DHCPv6 client rejects a REPLY whose Server Identifier differs from the
ADVERTISE's, and since the two come from separate model calls with no state
between them, a randomly generated default DUID would break every four-message
exchange. The default is therefore a constant DUID-EN (enterprise 32473, IANA's
reserved documentation number), asserted byte for byte. Ask the same question of
any protocol with a handshake: *what does the peer correlate on, and can we
reproduce it without remembering anything?*

Two `dhcproto` limitations it worked around, recorded so nobody re-discovers
them: `v6::duid::Duid::link_layer` takes the link-layer address as an `Ipv6Addr`
and always writes 16 octets, so it **cannot express a DUID-LL for Ethernet**
(a real one carries a 6-octet MAC) — all four DUID forms are hand-encoded
instead; and it emits the domain search list through a `trust-dns` encoder with
**name compression on**, so a second name sharing a suffix comes back as a
pointer that a client must follow.

> **Router Advertisement was not separately selected, and is nonetheless
> implemented** — RA is ICMPv6 type 134, i.e. part of NDP, so building NDP
> properly delivered it. `send_router_advertisement` carries prefixes with L/A
> flags and both lifetimes, RDNSS (RFC 8106) and MTU, which is the whole
> `mitm6`-class capability. Every RA comes from an explicit model action; there
> is deliberately **no advertisement timer**, so nothing keeps advertising after
> the model stops answering.

**How NDP answered "independent implementation, same author is weak evidence".**
Its checksum literals came from a second one's-complement implementation written
from RFC 8200 §8.1 — which is a weak claim on its own, and it said so. So
`the_checksum_is_reproducible_by_hand` works the smallest case out arithmetically
*in its doc comment* (five addends → `0x18446` → fold → `0x8447` → `0x7bb8`), and
the two terms shown are exactly the two classic mistakes: `0x003a`, the next
header that must be 58, and `0xff04`, the destination address — which is why an
ICMPv6 checksum cannot be computed from the ICMPv6 bytes alone. A reader can
check it without running anything. Copy this wherever a magic constant is the
evidence.

### Tier 3 — become an interface

| Protocol | Feature | Module | Privilege | Status |
|---|---|---|---|---|
| TUN/TAP endpoint | `tuntap` | `tuntap` | `Root` | `landed` (`e73946b9`) — Experimental |
| Raw IP protocol-N | `rawip` | `rawip` | `RawSockets` | `landed` (`a5f40d50`) — Experimental |

**TUN/TAP is the item that changes what NetGet is** rather than adding another
protocol: it takes a real interface, and every routed IP packet becomes an
event, so any L3 service can be synthesized without implementing it.

It has one genuine design problem that must be solved before implementation,
not during: **a per-packet LLM call is hopelessly slow.** Script and static
handlers have to be the default path, with the model reserved for packets a
handler explicitly escalates. Do not ship a version that asks the model per
packet — it will look broken. `CLAUDE.md`'s note that scripts and static
handlers are "the right default for deterministic behavior" is load-bearing here.

**Raw IP protocol-N** is the generic home for protocols with no other (GRE 47,
ESP 50). Keep it genuinely generic; it must not become a per-protocol match.

**Raw IP's genericity is guarded executably, and that is the pattern to copy
whenever a rule is architectural rather than behavioural.** A comment saying "do
not branch on the protocol number" decays; `decoding_does_not_depend_on_the_protocol_number`
does not. It decodes one packet under twelve different protocol numbers and
asserts identical fields *including the payload slice*, so it fails the moment
someone adds `47 => parse_gre()`. Two numeric matches survive and are correct:
the IP **version** nibble (two header formats, not two carried protocols) and a
protocol-number→name string table, which is data rather than logic.

One honest limitation it surfaced and did not paper over: **IPv6 raw sockets do
not deliver the IP header** — the kernel strips it — so on that path the decoder
would see only the payload and drop the packet. Recorded in both its CLAUDE.md
files rather than discovered later by someone debugging live.

### Tier 4 — telecom

| Protocol | Feature | Module | Transport | Privilege | Status |
|---|---|---|---|---|---|
| GTP-C / GTP-U | `gtp` | `gtp` | UDP 2123 / 2152 | **none** — both above 1024 | `landed` (`b1642019`) — Experimental |
| M3UA / SIGTRAN | `m3ua` | `m3ua` | SCTP 2905 | none (port is high) | `landed` (`55f03bb6`) — Experimental; with SCCP, TCAP, MAP, CAMEL and an ASP client, exercised over real SCTP on Linux against Restcomm jSS7 and osmo-stp (`src/server/m3ua/AGENTS.md`) |

**GTP is the pleasant surprise of this tier**: both its ports are above 1024, so
it needs no privilege and is fully testable here. The model plays an SGW/PGW in
a mobile core. Nobody has an LLM-driven one.

**M3UA is blocked on transport, not on effort.** macOS has no SCTP stack, so its
real transport is unavailable on the machine that would test it. Three ways out,
in order of honesty:

1. Implement over SCTP, and return a clear `Err` naming the missing stack on
   platforms without it — the `bluetooth_ble_beacon` precedent. **Hiding a
   protocol is not the same as refusing to start it**: refused, the operator
   gets `ServerStatus::Error` naming the reason; hidden, nobody learns why.
2. Offer a `transport: tcp` startup parameter for lab use, marked plainly as
   **non-standard** in both the parameter description and `metadata().notes`.
   Some stacks do this; it is not the spec.
3. Userspace SCTP. `webrtc-rs` is already in the tree and carries an SCTP
   implementation, so this is not as far-fetched as it sounds — but it is a
   real project, not a side effect of this one.

Whichever is chosen, M3UA cannot be rated above `Experimental` from macOS.

**M3UA's SCTP handling is the pattern for an unavailable transport.** The
SCTP attempt is a **runtime probe, not a `cfg`**: it asks `socket2` for an
`IPPROTO_SCTP` socket and, on failure, returns an `Err` naming SCTP, RFC 4666,
the escape hatch, and the fact that the escape hatch is non-standard. Three
consequences follow, all of them wanted — the whole path compiles on macOS so it
is type-checked rather than being code nobody builds; a Linux kernel with `sctp`
unloaded is diagnosed identically to macOS; and an operator gets a sentence
rather than an errno.

Equally worth copying: **the non-standard label travels**. `"tcp (NON-STANDARD
lab transport, not SIGTRAN)"` appears in the startup-parameter description the
model reads, `metadata().notes`, the startup log, a standalone WARN, the
dashboard's `protocol_info` row, and **every event's `transport` field** — with a
test asserting each, plus that the declared default is still `"sctp"`, so a
flipped default cannot silently give an SCTP-capable host lab framing.

### Tier 5 — automotive

| Protocol | Feature | Module | Transport | Status |
|---|---|---|---|---|
| CAN bus / SocketCAN | `can` | `can` | `AF_CAN` (Linux) | `landed` (`09b6876d`) — Experimental, Linux transport never compiled |

**Two patterns from CAN worth reusing for any platform-gated protocol.**
First, its refusal test does not stop at asserting `spawn()` returns `Err` — it
then starts the same protocol on its UDP transport on the same host, which proves
the refusal is a **routing decision rather than a dead end**. An assertion that
something fails is much weaker than one showing what still works. Second, the
refusal message is a single `const` quoted verbatim by the runtime error, the
docs and the test, so the three cannot drift.

It also *removed* a startup parameter it had planned (`fd`): `CanFdSocket` reads
both classic and FD frames off one socket, so the knob would have had nothing to
do. Declining to declare a parameter is the cheap way to avoid the
declared-but-unread trap that `startup_param_drift_test` exists to catch.

An LLM-driven ECU simulator, and a genuinely underserved niche. Linux `vcan`
needs **no hardware**, so it is trivially testable on Linux and not at all on
macOS. Same rule as M3UA: implement for Linux, return a clear `Err` naming the
platform elsewhere, and rate honestly. The `socketcan` crate must be a
target-gated optional dependency so non-Linux builds do not try to compile it.

---

## Deliberately deferred

Recorded so they are not re-litigated from scratch.

| Item | Why deferred |
|---|---|
| IPv6 Router Advertisement | Not selected in the September 2026 pass. Recommended; see the Tier 2 note. |
| Transparent intercept (`pf divert-to` / nfqueue) | Most invasive thing considered. Viable but wants its own design pass. |
| Diameter | Pairs with `radius` and works over TCP here, but was not selected. |
| 802.11 rogue AP | macOS cannot inject; needs Linux plus a specific chipset. |
| IPMI/RMCP+, WinRM, DCERPC | Session crypto and IDL marshalling; the model contributes almost nothing for thousands of lines of framing. |
| Redfish | Cheap to build, but the only real clients are Python, and `CLAUDE.md` rules that a generic HTTP client is not Beta evidence — it would be permanently `Experimental`. |

## An unused validation avenue: `tshark`

**`tshark` 4.x is installed on this machine, and it dissects most of what this
programme added.** The GTP agent used it and nobody else did: it rebuilt four of
the server's own outbound packets octet-for-octet from its test assertions,
wrapped them with `text2pcap`, and dissected them. All four parsed with **zero
expert warnings**, including a PN-set/S-clear G-PDU where Wireshark found the
inner IPv4 packet only after all four optional octets — third-party confirmation
of the E/S/PN all-or-nothing rule, from an implementation that shares no code
with ours.

This validates the **encode direction only**, which is exactly the half most of
our raw-socket protocols cannot otherwise prove. It is available today for LLDP,
CDP, STP, VRRP, NDP, DHCPv6, HSRP, WoL, EAPOL and CAN.

It was deliberately **not** wired into the suite, on the reasoning that a test
needing `tshark` would skip when absent, and a skip-when-missing gate is a silent
pass rather than evidence. That reasoning is sound but the conclusion is a
choice, not a necessity: `npm`'s test shows the third option — **hard-fail when
the binary is missing**. The real trade is whether `tshark` becomes a build
requirement wherever the suite runs, exactly as `nats-server` now is. Worth
deciding deliberately rather than by default; it would move several protocols
from "codec proven only against ourselves" to "codec proven against Wireshark".

## A new build requirement: `nats-server`

The NATS **client**'s Beta rating rests on a test that spawns the real
`nats-server` binary (v2.14.6, installed September 2026) and hard-fails when it
is absent — deliberately, because a skip-when-missing gate is a silent pass and
is not evidence. **So `nats-server` must exist wherever that suite runs.**

Today this costs nothing: `ci.yml`'s `test` job builds
`tcp,http,dns,udp,redis,mcp-stdio`, which does not include `nats`, so the test
is never compiled there. **Anyone adding `nats` to the CI feature set must also
install `nats-server` in that job**, or the build will fail — correctly, and
loudly, which is the intended behaviour.

The same will apply to any protocol promoted by the "install the real client"
route: Gopher would need `geomyidae`/`gophernicus`, Finger a real daemon, LLDP
`lldpd`. That is the price of the Beta bar, and it is the right price.

## Follow-ups this programme created

Each was found by an agent working inside its own boundary, reported rather than
reached outside to fix, and is small. Do them once the waves have landed, not
during — every one touches a shared file.

**Status, 7 October 2026: all five are resolved.**
1 — `wireshark.rs` now covers every protocol named below; DHCPv6, Wake-on-LAN, EAPOL and
NDP were the last four (`1c8c5f1d`, each name checked with tshark 4.6.8; WoL is a display
filter because its dissector is heuristic). 2 — both startup gates ask
`Protocol::startup_privilege_requirement`, which LLDP, STP, CDP, EAPOL, NDP, VRRP and raw IP
relax only for their UDP test transport (`9a1a1251`, pinned by
`tests/startup_privilege_transport_test.rs`, which fails with the refusal if either gate reads
the declared requirement). 3 — `AGENTS.md` already used the right form; 236 lines in 109 other
files did not and now do (`aaea81a3`; its message says 80 files). 4 — had already been fixed:
`client_action_names_for_pattern` reads async ∪ sync ∪ the event's own actions. 5 — `stp`
had already dropped `pnet`; `rawip` declared it and used nothing, and no longer does
(`51290000`); LLDP, CDP, EAPOL and NDP use `pnet::datalink` for interface addresses.

1. **`src/tui/wireshark.rs` has no entry for any protocol added here.**
   Two concrete instances confirmed by agents: DHCPv6 (`wireshark.rs:203` has
   `"dhcp" | "bootp" => udp("dhcp")` and no `dhcpv6` arm) and Wake-on-LAN.
   Both are one-line additions. That table
   maps NetGet protocol → transport + Wireshark dissector, and a protocol missing
   from it is treated as plain TCP. That is wrong for every UDP and link-layer
   protocol in this programme. Wake-on-LAN found it (it is UDP/9 with the `wol`
   dissector, not TCP); the same applies to SSDP, LLMNR, NetBIOS-NS, HSRP, GTP,
   DHCPv6, NDP, VRRP, LLDP, CDP, STP, EAPOL and CAN. Every name added must be
   checked against `tshark -d` / `-Y`, as the existing table's entries were.
2. **The privilege gate is per-protocol, not per-transport.** Confirmed
   independently by the LLDP and STP agents. `server_startup` evaluates
   `privilege_requirement` *before* reading startup parameters, so a protocol
   honestly declaring `RawSockets` is refused on an unprivileged host **even when
   asked for its UDP test transport**. The suites work around it by calling
   `Server::spawn` directly, following `bluetooth_ble_beacon`. The fix is a
   per-transport privilege query in `server_startup`; the wrong fix is declaring
   `None`, which would lie about the transport anyone actually uses.
3. **`CLAUDE.md`'s "Running tests" example is not a valid cargo invocation, and
   this file repeated it.** It shows `--test server::tcp::e2e_test`, but `--test`
   names a test *target* — a file in `tests/` — so the target is `server` and the
   rest is a filter. Cargo lists the available targets and exits rather than
   running anything, which reads like a broken suite. The working form is:

   ```bash
   ./cargo-isolated.sh test --no-default-features --features tcp \
       --test server -- server::tcp --test-threads=100
   ```

   Every agent in this programme was briefed with the wrong form and each worked
   it out independently. Fix the example in `CLAUDE.md`.
4. **`validate_static_action_names` never reads a client's async actions.**
   Found by the Ident client agent. `src/events/handler.rs` builds its catalogue
   from `get_sync_actions()` plus event-type actions only — so any client that
   follows the "clients union, don't duplicate into both methods" rule **cannot be
   routed with a static handler**, failing with *"Unknown action … Valid actions
   for X: append_memory, …"*. **`whois` has this bug today**: its own
   `get_startup_examples()` static example cannot be created. The ~40 clients that
   appear to work do so by duplicating their whole list into `get_sync_actions()`.
   The fix is a one-line change to teach the validator to read async actions for
   clients; the local workaround is to attach the vocabulary via
   `EventType::with_actions(...)`, which is what that field is for.
5. **Trim unused feature dependencies.** `stp` declares `pnet` and does not use it
   (its codec is hand-written; `pcap` covers capture and injection). Check `lldp`,
   `cdp` and `eapol` for the same once they land — I declared all four alike when
   wiring, before knowing which would need it. A declared-but-unused dependency is
   build weight and a false signal about how a protocol works.

## Working rules for this programme

Learned from the incidents recorded in `CLAUDE.md`, and applied to every wave:

1. **Wire shared files centrally, before fanning out.** `Cargo.toml`, both
   registries, `src/server/mod.rs`, `src/client/mod.rs` and both test `mod.rs`
   files are edited by one actor only. Feature gating means an agent can build
   and test its own protocol alone even though the others do not exist yet.
2. **Each agent owns exactly two directories** and commits them through a
   private index (`GIT_INDEX_FILE`) with a compare-and-swap `update-ref`. The
   shared index races; five separate incidents are on record.
3. **Stage the waves.** Do not run twenty-plus agents at once — they serialize
   on the shared `target/` build lock, and a large wave during a degraded API
   period once burned ~9.8M tokens for 5 usable results.
4. **A validation client's licence is a dev-dependency question, not a shipping
   question.** NetGet is `AGPL-3.0-or-later` (`Cargo.toml` line 5). A test-only
   client is never linked into a distributed binary, which is the same basis on
   which the MPL-2.0 `irc` and `attohttpc` test dependencies are already here.
   `async-stomp` is EUPL-1.2 and was cleared on that ground *and* because
   EUPL-1.2's compatibility appendix names AGPL-3.0 explicitly. Escalate a
   copyleft **runtime** dependency; a dev-dependency usually just needs the
   reasoning written down.

   **`LICENSE_ANALYSIS.md` contradicts itself and the manifest** and should be
   re-derived before anyone relies on it: it claims "No copyleft obligations
   (can keep code proprietary if desired)" a few lines after answering "Can
   NetGet be closed-source? **No**", and it describes a project that is not
   AGPL. Not fixed here; recorded so the next licence question starts from the
   manifest rather than from that file.
5. **Watch `df` between waves.** `target/` reached 130 GB in one session, and at
   zero bytes free the session cannot recover — every tool call needs to write.
   `cargo clean --profile dev` is the remedy and keeps `target/release`.

---

# Programme 2 — quality pass over every protocol

Started 4 September 2026. Goal: every one of the 154 servers and 102 clients
audited and improved for robustness, failure semantics, model-facing accuracy,
lifecycle correctness, test honesty and documentation truth.

**Paused mid-flight on quota exhaustion.** Read "Where to resume" below.

## How the work is organised

39 family batches, one agent each, run in waves of about ten. Each agent works
in **its own git worktree** with a **shared `CARGO_TARGET_DIR`**
(`/Users/matus/dev/netget-shared-target`) — worktrees give git isolation, the
shared target directory stops 39 private `target/` trees refilling the disk.

**`src/tui/wireshark.rs` is deliberately excluded from every agent's boundary.**
Agents report the correct entry for their protocols; it is applied centrally.
One table edited by 39 agents is the collision this repo has already hit.

## The eight-point rubric each agent applies

1. **Robustness** — hostile input must not panic, hang or allocate without bound:
   unbounded line/message reads, missing read timeouts, byte-index slicing on a
   `&str` (use `crate::utils::truncate_for_log`), a lock guard held across an
   `.await` doing I/O or an LLM call, `block_on`/`blocking_lock()` on the async
   runtime, and library panics reachable from the wire.
2. **Failure semantics** — a `crate::utils::wire_failure` category to the peer
   (never the error text), or deliberate silence where every reply the protocol
   defines is a positive assertion; `decision=` log tags as `src/server/radius/`.
3. **Model-facing surface** — action descriptions match executor behaviour, every
   declared `example` accepted by its own executor, no raw bytes or base64,
   `.with_actions(...)` on every event, every declared event actually emitted.
4. **Startup parameters** — declared ⇄ read both ways; `?` never `unwrap()`.
5. **Lifecycle** — `spawn()` awaits readiness and returns `Err`; every spawned
   task registered; connection stats updated; `.connectionless()` where apt.
6. **Tests** — `verify_mocks()` everywhere; wait for *conditions*, never fixed
   sleeps; an `#[ignore]`d or skip-when-missing test is not evidence.
7. **Docs and honesty** — `CLAUDE.md` matches the code; **lower** any maturity
   rating the evidence does not support and say why.
8. **Wireshark** — report the entry, do not edit the file.

**Prefer removing a defect or a lie over adding a feature.** "This one is already
sound" is a good outcome; inventing work to look productive is not. Never weaken
a test to make it pass.

## Where to resume

- **Wave 1 (pilot) was in flight when quota ran out**: `mail` (smtp/imap/pop3/nntp),
  `l2raw` (arp/datalink/icmp/igmp), `db-core` (mysql/postgresql/redis/memcached).
  Their worktrees may hold committed or partial work — **check
  `git worktree list` and each worktree's log before re-running them**, and merge
  anything already committed rather than redoing it.
- The pilot existed to validate two unknowns: the worktree mechanics (where it
  lives, what branch, how commits come back) and whether the rubric yields real
  fixes rather than busywork. **Answer those before launching the remaining 36.**
- Everything after the pilot is unstarted.

## Two operational corrections learned in wave 2

**A shared `CARGO_TARGET_DIR` corrupts binary-spawning test suites.** It was the
right call for disk (39 private target trees would refill the disk), but
`tests/examples`, `tests/terminal_snapshot` and every suite that spawns
`target/debug/netget` read a binary another agent may be rebuilding *right now*.
The DNS batch saw ten client tests fail with `Client protocol 'DNS' exists but is
not compiled into this build`; all ten passed unchanged in a private target dir.

So: **share the target dir for ordinary builds, but verify binary-spawning suites
in a private one** — `CARGO_TARGET_DIR=/tmp/verify-<batch>`. Treat any
"protocol exists but is not compiled in" failure during a wave as contention
until proven otherwise; it is an artefact, not a regression.

**A blocking `std::process::Command::output()` deadlocks the in-process mock
model.** The test's current-thread runtime is shared with the mock Ollama server,
so a blocking `dig` waits for a model that cannot run until `dig` returns. It
presents as `;; connection timed out` against a perfectly healthy server. Use the
async spawn. Related: `start_netget_server` returns when startup is *parsed*, not
when the socket is bound.

## Wave 4/5 — cut short by a second session limit, work preserved

Six agents were killed mid-task on 11 September. **Every one had committed real fixes first**,
and those were merged; each agent's final in-flight edits were preserved by the supervising
session as a `wip(...)` commit at the tip of its branch and **deliberately excluded from the
merge**. The precedent for that caution is the previous wave, whose `wip` commit contained a
helper referencing a function that existed nowhere and could never have compiled.

| batch | branch | merged | unverified WIP left on branch |
|---|---|---|---|
| core-transport | `worktree-agent-a3e18a8987266e2bc` | 4 commits | `00883c69` |
| netmgmt | `worktree-agent-a49600538a485057e` | 2 commits | `6293ce0c` |
| chat | `worktree-agent-a48f49cf447d93de7` | 1 commit | `eb6cc6bb` |
| tls-vpn | `worktree-agent-a357b18f2ed735606` | 4 commits | `dd7f5d41` |
| web-aux | `worktree-agent-a09462d7c51094ccf` | 8 commits | `7d408691` |
| auth-web | `worktree-agent-aa3a5bf60938d9bda` | **none** | `07b85160` — all its work is unverified |

**To resume**: `git merge --no-ff worktree-agent-<id>` picks up the WIP too, so verify it first.
`auth-web` should simply be re-run — it committed nothing, and it is the family containing the
OAuth2 fail-open that `CLAUDE.md` names as the worst defect in the codebase's history.

**The stack-overflow class has now been found in four protocols**: AMQP, NATS and STOMP in the
messaging family, and SNMP's BER decoder here — *"one 60 KB datagram kills the whole process"*.
It is worth checking any remaining decoder that can call itself.

## The 39 batches

```
# batch-name | protocols (server+client together)
PILOT-1 mail        | smtp imap pop3 nntp
PILOT-2 l2raw       | arp datalink icmp igmp
PILOT-3 db-core     | mysql postgresql redis memcached
web-core            | http http2 http3 http_common quic
web-aux             | websocket webdav proxy http_proxy socks5
dns                 | dns doh dot mdns
db-nosql            | mongodb cassandra couchdb elasticsearch
db-cloud            | dynamo s3 sqs snowflake spark
db-enterprise       | mssql db2 oracle etcd zookeeper
messaging           | amqp mqtt kafka nats stomp
routing             | bgp ospf rip isis
redundancy          | vrrp hsrp stp lldp cdp
discovery           | ssdp llmnr netbios_ns
voip                | sip rtp rtsp hls
webrtc              | webrtc webrtc_signaling stun turn
files               | ftp tftp nfs smb
vcs                 | git svn mercurial
packages            | npm pypi maven yarn oci_registry
auth-dir            | ldap radius ssh ssh_agent
auth-web            | oauth2 openid saml_idp saml_sp eapol
tls-vpn             | tls ipsec openvpn wireguard
legacy-text         | whois finger gopher ident telnet
core-transport      | tcp udp dc reverse_shell
ipc                 | named_pipe pty stdio socket_file
rpc                 | jsonrpc xmlrpc grpc mcp
llm-api             | openai ollama openapi
chat                | irc xmpp
p2p                 | bitcoin torrent_dht torrent_peer torrent_tracker tor_relay
iot-industrial      | modbus coap can gtp m3ua
netmgmt             | snmp syslog ntp dhcp bootp dhcpv6
raw-new             | ndp rawip tuntap wol
remote-desktop      | vnc rdp
print-feed          | ipp rss
k8s                 | kubernetes
usb                 | usb (7 sub-protocols)
ble-core            | bluetooth_ble bluetooth_ble_beacon
ble-hid              | bluetooth_ble_keyboard bluetooth_ble_mouse bluetooth_ble_gamepad bluetooth_ble_presenter bluetooth_ble_remote
ble-sensors          | bluetooth_ble_battery bluetooth_ble_heart_rate bluetooth_ble_thermometer bluetooth_ble_environmental bluetooth_ble_proximity bluetooth_ble_weight_scale bluetooth_ble_cycling bluetooth_ble_running bluetooth_ble_data_stream bluetooth_ble_file_transfer
nfc                 | nfc
```

Client directories whose name differs from the server's — the batch owning the
server also owns these: `bluetooth` (ble-core), `dynamodb` (db-cloud),
`openidconnect` and `saml` (auth-web), `tor` (p2p).

## Worktree mechanics — answered, no need to re-derive

Agent worktrees live at `.claude/worktrees/agent-<id>`, each on its own branch
`worktree-agent-<id>`, branched from the master commit at launch. They are
**locked**, so `git worktree prune` will not remove them. Merge with
`git merge --no-ff <branch>` from the main tree; per-protocol directories are
disjoint, so conflicts should be limited to shared files agents were told not
to touch.

Wave 1 ran until a session limit killed all three agents mid-task. **Every one
had produced real fixes first**, and the pilot therefore did its job: it proved
the rubric finds genuine defects rather than generating busywork.

| batch | branch | verified commit | unverified WIP |
|---|---|---|---|
| mail | `worktree-agent-a26377dd9a0f3624b` | `fa9f7775` — a mutex guard in a `match` scrutinee deadlocked the NNTP client read loop | `616f818d` (smtp) |
| l2raw | `worktree-agent-ae9489544f89cd1ea` | `0ce7a3bc` — ARP: a client deadlock, a discarded model answer, a leaked capture handle, and a missing fail-closed log | `4da520ba` (icmp) |
| db-core | `worktree-agent-afc24a51591969272` | `606d33a5` — MySQL prepared statements never worked: three defects and the docs that hid them | `6430977f` (postgresql) |

**The `wip(...)` commits were made by the supervising session, not by the agents,
and were never built or tested.** They exist so the work is not lost, not because
they are believed correct. Verify before merging; treat them as a starting point.

The three named fixes are the agents' own commits and were made in the normal
way, but **none has been verified by a build in the main tree** — the session
lost its quota before that could happen. Build and test each before merging.

Note the `mail` branch also merged master into itself, so a diff against the old
base shows 249 commits; only `fa9f7775` and `616f818d` are its own work.

**Agent worktrees branch from `origin/master`, NOT from local `HEAD`. Push
before launching them.** This is the most expensive thing wave 1 taught, and it
is not obvious.

Local master was 249 commits ahead of the remote when wave 1 launched, so all
three worktrees were created at `525029e1` — a base predating every one of those
commits. The `mail` agent noticed and merged master into its worktree first,
which is why it merged back cleanly. The other two did not, and re-fixed ground
master had already covered: `687c4c7a` had made every documented example
executable, and `176fafe8`/`20f36994` had already reworked ARP. Merging them back
produced semantic conflicts between two independent fixes to the same lines —
the worst kind to resolve, because both sides are *correct* and neither is
simply newer.

The rule is now in `CLAUDE.md`: **pushing to `origin` is pre-authorised in this
repo, so push as you go.** Before launching any worktree wave, verify
`git rev-list --count origin/master..HEAD` is `0`.

**What the pilot settled:** the worktree mechanics (above), and that the rubric
yields real defects — a deadlock, a discarded answer, a resource leak and a
whole broken feature, inside three families in one short wave. The remaining 36
batches can proceed on the same pattern.

Check each with `git -C .claude/worktrees/agent-<id> log --oneline` and
`git -C .claude/worktrees/agent-<id> status` before deciding — a worktree at
base may still hold uncommitted work that is worth keeping.


# Programme 3 — complete server and client protocol expansion

Requested 1 October 2026. This is the durable implementation checklist for the researched catalogue: **52 new protocol families, 15 existing-protocol completions, and 5 explicitly separated extensions mentioned in the research**. The user authorized implementation of all items using sub-agents, with the coordinator managing integration and disk use. These are useful, documented protocol scopes; a checkbox never implies implementation of every optional part of a standard.

## Completion rules

- A top-level checkbox is checked only after the stated server/client scope is implemented, registered, documented, built, and validated. A source stub, matching homemade encoder/decoder, successful handshake alone, or a skipped test is not completion.
- Record exact test commands/results, independent peer/version, implementation limitations and commit with each finished item. Runtime maturity must reflect the evidence; checklist completion does not automatically confer Stable status.
- Rust owns framing, crypto, IDs, sequencing, bounds and timers. Structured actions/events expose decisions to script/static/manual/LLM handlers. Domain data uses existing shared state facilities, with no new protocol-specific storage engines.
- Clients include command injection, event handlers, owned-task cleanup and cancellation. Servers register all tasks, expose startup parameters and release sockets/peers on stop.
- Test an independent client against the server and the client against an independent server, as well as the NetGet pair. Where independent evidence is unavailable, leave the validation checkbox open and state the precise gap.
- New features must be wired to module/registry/known-name tables and test roots, with portable build membership decided from actual dependencies. Preserve existing protocols and unrelated working-tree changes.

## Research findings that affect implementation

The research counted 169 server registration sites and 103 client registration sites, including device profiles and partial implementations. These are source counts, not runtime counts or conformance claims. At that research snapshot, HTTP/3 had a real client but no matching server; the QUIC server handled raw streams. The generic gRPC server is unary-only and does not serve reflection. SSH already contains an SFTP server but its client lacks SFTP. Existing AMQP is 0-9-1, so AMQP 1.0 is distinct. OTLP currently has an HTTP receiver.

Redfish was previously deferred on the assumption that suitable peers were Python-only. [Gofish](https://github.com/stmcginnis/gofish) supplies an independent Go client, so that rationale should not prevent implementing it. DNP3 dependency decision resolved (October 2026): use the self-contained bounded Rust subset, with Apache-2.0 OpenDNP3 3.1.2 as an external independent test peer. No commercial Step Function library is linked or required. Current repository pins (Hickory 0.24, russh 0.45, tonic 0.12/prost 0.13) make current-library compatibility an explicit check, not an assumption.

Priority is an engineering judgment: **A** strongest general fit, **B** useful follow-on, **C** workload-specific. Effort **S/M/L** is comparative and covers both roles, a useful documented scope and interoperability tests. API profiles such as SCIM and Redfish add schema/state semantics over HTTP. Collector/exporter and peer roles count as the two natural protocol sides where client/server is not the native terminology.

## Disk and collaboration policy

Initial free space was approximately 71 GiB. The active main checkout is heavily modified by other work. After temporary-directory cleanup, source worktrees were restored from their retained Git branches under `/Users/matus/dev/netget/.protocol-expansion-20261001/`; build artifacts share `/private/tmp/netget-protocol-target-20261002`. All programme builds now run through `python3 /Users/matus/dev/netget/.protocol-expansion-20261001/run_cargo.py ...`, which serializes them, disables debug symbols/incremental compilation and limits build jobs. New builds require 30 GiB free; the guard stops only its owned build if space drops below 25 GiB.

Do not delete unrelated worktrees, artifacts, logs, source, Cargo caches or running processes. Reclaim only verified programme-owned build artifacts between builds. The coordinator checks disk before each batch and after builds. Agents commit within their assigned branches; the coordinator merges validated batches into local `master` and pushes to `origin/master`, as explicitly authorized on 2 October 2026. GitHub PRs are not part of this workflow. No duplicate per-agent target directories or full-feature build storms.

## Active assignments and progress

- Completed: **66 / 72**; **6 remain**. Completed scopes comprise forty-six new families, fifteen existing-protocol completions and five separated extensions. All remaining entries are authorized new families.
- 4 October 2026: NETCONF02, RPKI-RTR09 and RDAP17 pass every coordinator gate (roles with independent peers, shared audits, privacy, startup, standalone feature, clippy, format, module reachability) through `.protocol-expansion-20261001/validate_scope.py`, the per-scope driver that replaces the per-batch scripts. Master `4becfaf0` passed all 28 protocol-pair jobs, Browser build and the single-feature shards after two CI repairs found on first publication: gNMI's protos now vendor protobuf's well-known types (Ubuntu's protoc ships without them) and the OCI client converts its body-limit error explicitly for wasm32.
- Batch 11 (gNMI04, Diameter08, OCI62) passed every coordinator gate on 4 October 2026 at integration `11854297`: OCI 48, gNMI 13 and Diameter 32 both-role checks, native gRPC neighbours 38, gNMI seams/shared codec 39, shared audits 195, privacy 148, startup 45, standalone `gnmi` and `diameter` all-target checks, clippy (correctness, suspicious, unused_must_use), whole-tree format, module reachability (2651 files) and the protocol-pair workflow verifier. No failures and no ignored tests. Evidence: `.protocol-expansion-20261001/logs/batch11-*-h2-*.log` and `batch11-h2-*-results.json`.
- The two shared blockers were fixed without relaxing a baseline. The control-character ratchet matched the OCI client's `WWW-Authenticate` quoted-string validator (`api.rs:393`, not the Basic username at line 121, which the scan does not see), now listed as a validator with its reason; the binary's rustls provider gate names `gnmi`. The function-path form (`char::is_control`) the ratchet missed turned out to be forty-five validators; all call `utils::sanitize::has_controls` and the ratchet now matches that form (`21df3c20`).
- The SSH server ownership defect is fixed (`0cad604b`): the connection task awaits russh's `RunningSession`, and a per-connection cancellation token reaches the detached driver through the stream wrapper and races every model call. `tests/server/ssh/session_ownership_test.rs` proves live state, socket closure on stop and retirement of a parked manual authentication through libssh2; both tests fail when the session is dropped again. All 16 SSH server tests pass.
- Worker drafts superseded by integrated scopes are preserved, unmerged, as snapshot commits on their branches: NETCONF (`protocol-expansion-nut`), the RPKI-RTR codec (`protocol-expansion-statsd`) and the WebTransport vendor copy (`protocol-expansion-doq`). Diameter and RPKI-RTR peers (StayRTR 0.6.4, rtrdump, rtrclient) are restored under `.protocol-expansion-20261001/peers/`.
- Publication model: signed no-ff merges into local master and direct pushes to origin/master; no GitHub PRs. Every Cargo command goes through `run_cargo.py` (30 GiB to start, stops below 25 GiB).

## New protocol checklist

- [x] **01. DoQ** — A/M; proposed feature `doq`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc9250.html).
  - Scope: RFC 9250 DNS queries over QUIC; correct ALPN, framing, TLS validation and stream lifecycle.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.

  - Validation: 9 server and 8 client tests passed with Knot `kdig 3.6.0` and AdGuard `dnsproxy 0.85.0`. Code `e900e753`, integration merge `07339b83`. Experimental; declared server DNS record subset and no AXFR/IXFR.

- [x] **02. NETCONF** — A/L; proposed feature `netconf`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc6241.html).
  - Scope: SSH subsystem, hello/capabilities, NETCONF 1.0/1.1 framing, get/get-config/edit-config, errors and explicitly supported datastores.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 27 checks pass at 100 threads. Unchanged ncclient 0.7.1 (Paramiko 3.5.1) drives the server and the netconf 2.1.0 Python server answers the client, each over base:1.0 end-of-message and base:1.1 chunked framing; NetGet pair across every reply shape, kill-session, pinned host key, hello deadline, parked-manual removal; envelope and codec bounds. SSH netconf subsystem on russh 0.45, RFC 6241 envelopes, capability-checked datastores, handler-controlled data (no datastore in Rust); copy/delete-config, confirmed commit, url, notifications, TLS and public-key auth excluded; Experimental. Source `77458401`, CI `14f4e7d1`, published `ace1e3cd`.

- [x] **03. RESTCONF** — B/M-L; proposed feature `restconf`. [Specification/reference](https://www.rfc-editor.org/info/rfc8040/).
  - Scope: YANG-shaped HTTP resources, discovery, reads/edits, media types and protocol errors; declare modeled scope.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 5 RESTCONF test functions pass. Modeled scope: JSON (application/yang-data+json) data resources and operations, host-meta discovery, the API root, yang-library-version and an ietf-yang-library modules-state generated from the declared modules; no YANG parsing, XML, event streams, ETag or YANG Patch. The unchanged FreeCONF RESTCONF client (Go) loads the module list from NetGet, reads FreeCONF's car module, PATCHes the speed and reads it back, and invokes car:addOil. NetGet's client against the unchanged FreeCONF server reads the module, a list entry and a leaf, PATCHes and reads back, deletes an entry and gets 404 for it, and invokes car:addOil accepted and refused with FreeCONF's RFC 8040 error. FreeCONF deviates from RFC 8040 in ways the tests record rather than paper over: it serves neither the API root nor yang-library-version (the client reports their status instead of requiring them), returns list entries unwrapped and expects them so (RFC 8040 section 3.5.3 wraps them, as NetGet's handler does), and addresses a module without a top container as `module:` (now accepted). Wire tests cover paths, client against server and raw HTTP refusals (406, 415, query parameters, 405). Experimental. Source `0f2b8fab`, CI `fb3a28f7`.

- [x] **04. gNMI** — A/L; proposed feature `gnmi`. [Specification/reference](https://github.com/openconfig/reference/blob/master/rpc/gnmi/gnmi-specification.md).
  - Scope: Capabilities/Get/Set and ONCE/POLL/STREAM subscriptions, typed paths, synchronization and cancellation.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 13 both-role checks pass with unchanged pinned gNMIc 0.49.0 and grpcio peers and the NetGet pair; 38 native gRPC neighbour and 39 seam/shared-codec/wire checks also pass. Selected Capabilities/Get/transaction-wide Set and ONCE/POLL/STREAM subscriptions with typed paths/values, explicit verified TLS and native HTTP/2 bounds on TCP 9339. No YANG/device datastore, auth/reflection, SAMPLE/heartbeat, extensions or opaque values; Experimental. Source `306ffb43`/`5ed53683`, merge `94caa797`, central CI `11854297`.

- [x] **05. Redfish** — A/M; proposed feature `redfish`. [Specification/reference](https://www.dmtf.org/standards/redfish).
  - Scope: Service root, Systems/Chassis/Managers, inventory/sensors, sessions, a documented action set and tasks.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 6 test functions pass. Unchanged gofish v0.26.0 (Go) is refused a wrong password, logs in by session, reads systems (typed summaries and allowable reset types), resets through a task monitor it polls to Completed, PATCHes AssetTag and reads it back, walks chassis sensors, managers and sessions, and logs out; unchanged DMTF redfishtool 1.1.8 reads with Basic and session auth, waits on a reset and is refused a wrong password; NetGet's client logs in to, reads, patches and resets DMTF Redfish-Mockup-Server 1.3.0's public-rackmount1 mockup; HTTP rules, fail-closed logins and the NetGet pair. Plain HTTP, no $expand/$select/$filter, ETags or event subscriptions; Experimental. Source `35d3d586`, CI `2f934687`.

- [x] **06. NUT UPS management** — A/S-M; proposed feature `nut`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc9271.html).
  - Scope: UPS discovery, variables, supported authenticated operations, errors and programmable power scenarios.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.

  - Validation: 13 server and 5 client tests passed with no skips. Official NUT 2.8.4 `upsc`/`upscmd` exercised discovery, variables and authenticated instant commands; the client read independent `upsd` + `dummy-ups`. Code `444dc681` and merge `b08302d9`; 30 shared checks also passed. Combined integration validation passed (see batch evidence below).

- [x] **07. TACACS+** — B/M; proposed feature `tacacs`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc8907.html).
  - Scope: Authentication, authorization, accounting and deterministic session/secret processing.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: **17 server + 11 client checks** pass at 100 threads with unchanged nwaples/tacplus 0.0.3 and Python tacacs 2.6 SDKs, literal packet fixtures and the NetGet pair. Selected RFC8907 legacy TCP authentication (ASCII/PAP), authorization and accounting use bounded fresh sessions, secret processing and shared volatile recording before accounting SUCCESS. Printable ASCII identities, no durable AAA store, SINGLE_CONNECT and RFC9887 TLS profile excluded; Experimental. Source `a418922d`, runtime event placement `6b9ca9f5`, central registry/CI/capture `8c0e486a`; reproduction in corresponding server/client test `AGENTS.md` files.

- [x] **08. Diameter** — C/L; proposed feature `diameter`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc6733.html).
  - Scope: Base peer lifecycle plus a documented useful AAA application; typed AVPs, requests/answers and errors.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 32 both-role checks pass against unchanged go-diameter 4.5.0 and the pinned Python SDK plus the NetGet pair. Clear TCP 3868 RFC 6733 base (CER/CEA, DWR/DWA, DPR/DPA) and RFC 7155 stateless NASREQ application 1 with UTF-8 PAP. No TLS/DTLS/SCTP, routing/failover, vendor applications, accounting or stateful multi-round sessions; Experimental. Source `6c425f75`/`37acc38b`, merge `090588fb`, central CI `11854297`.

- [x] **09. RPKI to Router** — B/M; proposed feature `rpki_rtr`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc8210.html).
  - Scope: Cache/router roles, route-validation records, session and serial management, reset and incremental updates.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 18 checks pass. StayRTR 0.6.4 rtrdump (Go; v1, v0, serial delta, foreign-session Cache Reset) and RTRlib 0.8.0 rtrclient (C; Serial Notify → incremental withdrawal) against the cache; StayRTR's cache against the router (notify-driven delta, version 0); NetGet pair, RFC 8210 error codes both ways, parked-manual removal, literal-byte codec. No VRP store, ROV, SSH/TLS transports, Router Key/ASPA; Experimental. Source `533b7073`, CI `d3457253`.

- [x] **10. BMP** — B/M; proposed feature `bmp`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc7854.html).
  - Scope: Collector/exporter roles, peer up/down, route monitoring, statistics and bounded BGP payload parsing.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 5 BMP test functions pass. Unchanged GoBGP 4.9.0 (Go), peered with a second GoBGP, exports to NetGet's collector: Initiation (sysName GoBGP), Peer Up with both OPENs and the peer's port, Route Monitoring for routes added through the gobgp CLI (community and MED intact) and for a withdrawal, Statistics (adj_rib_in_routes 1 after the withdrawal), and Peer Down when the route source is killed. NetGet's exporter against unchanged gobmp 1.1.0 (Go): gobmp parses the peer up (ASNs, BGP IDs, port), announcements with AS path, origin, MED, local preference and community, the withdrawal, the statistics (prefixes_rejected_inbound 3, ads_rib_in 1), the peer down with its NOTIFICATION, and the termination; a route for a peer that is not up is refused before the wire. Wire tests cover per-peer header and distinguisher round trips, exporter-to-collector exact values for every message type, and collector refusals (no Initiation first, version 2, oversized, truncated per-peer header, a rejected router). The `bmp` feature enables `bgp` for netgauze's BGP codec; IPv4 routes only on the exporter; no Route Mirroring export; Experimental. Source `4af65899`, CI `a7a2760c`.

- [x] **11. GraphQL over HTTP** — A/M-L; proposed feature `graphql`. [Specification/reference](https://http-spec.graphql.org/draft/).
  - Scope: Runtime schema, query/mutation execution, variables, introspection and spec-shaped errors; subscriptions tracked separately below.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 6 test functions pass. Unchanged gql 4.4.0 builds its client schema from NetGet's introspection (graphql-core `build_client_schema`), validates locally and runs variables, aliases, a union with fragments, a mutation and a field error under both application/json and application/graphql-response+json; unchanged strawberry-graphql 0.330.2 answers the client's introspection, POST and GET queries, union, mutation, resolver error and validation error; HTTP rules (200/400 by media type, 405 for GET mutations, 406, 415), execution over handler data and the NetGet pair. Queries and mutations only (subscriptions are item 72), no batching, uploads or persisted queries; Experimental. Source `c5c6852d`, CI `152eb829`.

- [x] **12. Socket.IO** — A/M; proposed feature `socketio`. [Specification/reference](https://socket.io/docs/v4/socket-io-protocol/).
  - Scope: Explicit protocol revision, Engine.IO polling/WebSocket, events, namespaces, acknowledgments and disconnects.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 6 test functions pass (twice in a row). Protocol revision: Socket.IO v5 over Engine.IO v4. The reference socket.io-client 4.8.4 (JavaScript) and python-socketio 5.17.0, both unchanged, each connect over long-polling upgraded to WebSocket and over WebSocket only, emit with acknowledgements, receive broadcasts, acknowledge a server event, connect an auth-gated namespace, are refused it with bad auth and refused an unknown namespace, and are disconnected by the server; NetGet's client does the same against python-socketio's server over WebSocket and polling; wire tests cover Engine.IO errors, the two-poll error, ping timeout, rooms, peer pushes and a handler-less CONNECT_ERROR. Text packets only, no CORS, no polling-to-WebSocket upgrade in the client; Experimental. Source `347a8baf`, CI `336ff66a`.

- [x] **13. Connect RPC** — B/M-L; proposed feature `connect_rpc`. [Specification/reference](https://connectrpc.com/docs/protocol/).
  - Scope: Protobuf-defined RPC with Connect framing, structured messages and errors; gRPC-Web tracked separately below.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: **13 server + nine client checks** pass at 100 threads against pinned independent Connect-ES 2.2.0 / protobuf-es 2.16.0 Node/Fetch transports and the NetGet pair. Native binary protobuf HTTP/1.1 unary and server streaming, Connect errors/EndStream, gzip, bounded metadata, real 30-second first-byte and 120-second empty/nonempty idle limits are verified. JSON-message/GET/client-bidi/reflection/TLS/browser/CORS/pcap/fuzz claims are excluded; Experimental. Sources `9b5b9488`, refreshed `9938b6e7`; central `42cae6ca`/`8c0e486a`, explicit backpressure fixture `00af53ab`; reproduction in corresponding server/client test documents.

- [x] **14. A2A** — B/M-L; proposed feature `a2a`. [Specification/reference](https://a2a-protocol.org/latest/specification/).
  - Scope: Pin released version/binding; agent discovery, messages, tasks, streaming/cancellation as advertised.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 5 test functions pass. Unchanged a2a-sdk 1.2.1 (protocol 1.0) drives the agent as client (card resolution, direct message, streamed task in snapshot/working/artifact/completed order, GetTask, cancellation, task-not-found) and serves an echo agent to the client over the same calls; raw JSON-RPC refusals (missing and 0.3 versions, parse, envelope, unknown and push methods, unadvertised streaming, agent-role messages), handler-less -32603 and a card redirect refused. JSON-RPC binding only, no push notifications, SubscribeToTask, extended card or task store; Experimental. Source `0f995b77`, CI `ed1f40cf`.

- [x] **15. SCIM 2.0** — B/M-L; proposed feature `scim`. [Specification/reference](https://www.rfc-editor.org/info/rfc7644/).
  - Scope: User/group provisioning, discovery, CRUD/PATCH, filtering and pagination within declared capabilities.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 6 test functions pass. Unchanged scim2-tester 0.5.1 builds its models from NetGet's discovery and passes every check it runs (discovery, CRUD, PATCH add/replace/remove on every User, Enterprise and Group attribute, attribute selection on get, list and /.search) with no error; unchanged scim2-cli 0.4.0 creates, runs a compound value-path filter sorted descending, a case-insensitive filter, attribute selection, a uniqueness conflict, replace and delete; NetGet's client provisions against unchanged scim2-server 0.4.0; filter, PATCH-path, projection, refusal and NetGet pair tests. Discovery comes from RFC 7643's own schema text; Users and Groups only, no Bulk, /Me, ETags or changePassword; Experimental. Source `ac6c6131`, CI `c218e696`.

- [x] **16. ACME** — B/L; proposed feature `acme`. [Specification/reference](https://www.rfc-editor.org/info/rfc8555/).
  - Scope: Account/order/challenge/finalize/certificate workflow with deterministic JWS, nonces and certificate processing.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 6 ACME test functions pass. Unchanged lego 4.35.2 (Go, ES256) over HTTPS orders two names by http-01 that Rust fetches from lego's own solver, lists, revokes and is refused a policy-rejected order; unchanged certbot 5.8.0 (python acme, RSA/RS256) over HTTP gets a certificate by standalone http-01 and a wildcard by manual dns-01, revokes and is refused a blocked account. NetGet's client against unchanged Pebble 2.10.1 with pebble-challtestsrv registers, orders, passes http-01 validated by Pebble's VA against its responder and dns-01 via challtestsrv's DNS, finalizes, revokes (Pebble refuses a second as alreadyRevoked), is refused a blocklisted name and deactivates. Raw JWS tests cover 415/413, nonce reuse, URL mismatch, unsupported alg, forged payload, accounts, contacts, identifiers, orderNotReady, ownership, wildcard challenges, an http-01 Rust cannot fetch (handler not asked) and badCSR; no handler answer creates nothing; the NetGet pair runs over HTTPS. certbot found that rcgen's explicit basicConstraints cA FALSE is refused by python cryptography (leaves now omit it). No keyChange, EAB, pre-authorization, tls-alpn-01, OCSP/CRL, profiles or ARI; in-memory state; Experimental. Source `b4441315` (shared TLS-loader fix `d98233c3`), CI `a81818a4`.

- [x] **17. RDAP** — B/S-M; proposed feature `rdap`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc9082.html).
  - Scope: Domain/IP/ASN queries, structured objects, links/notices, response schemas and errors.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 6 test functions (dozens of queries) pass. OpenRDAP 0.10.2 and ICANN rdap 1.0.0 query every object class, search, help, 404 and 403 against the server; ICANN rdap-srv 1.0.0 serves every class, search, help, 404 and a 307 referral to the client; NetGet pair, RFC 9082 normalization/refusal and RFC 9083 envelope tests. Plain HTTP, no bootstrap, storage or authentication; Experimental. Source `844fb81f`, CI `07d19cd3`.

- [x] **18. EPP** — C/L; proposed feature `epp`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc5730.html).
  - Scope: Registry/client sessions and selected domain/host/contact mappings with check/create/renew/transfer operations.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 4 EPP test functions pass. RFC 5734 TLS framing (self-signed certificate published by default), RFC 5730 greeting/hello, login/logout session rules with optional registrar credentials (never sent to the handler; three failures close with 2501), poll with no queue, and result-coded refusals in Rust; domain (RFC 5731), host (5732) and contact (5733) check/info/create/renew/transfer/update/delete parsed by a bounded namespace-aware XML reader (no DOCTYPE) and answered by the handler, whose answers Rust renders as chkData/infData/creData/renData/trnData. Unchanged pyepp 0.2.0 (InternetNZ) is refused before login and with a wrong password, then checks, creates a contact, host and domain, reads a domain, gets 2303 for a missing one, renews, has a transfer accepted (1001) and refused (2202), and logs out. NetGet's client runs a provisioning flow against a registry over unchanged epp-lib v0.2.0 (the Swedish Internet Foundation; TLS, framing and namespace-routed dispatch) whose registry logic is test-authored: check, contact/host/domain create, info, renew with the reported expiry, transfer request, duplicate create (2302), logout; a wrong password and an untrusted certificate fail. Raw frames cover 2100, 2307, 2000, 2001 (including DOCTYPE), 2005, 2002, poll, a refused handler code (2400), an oversized frame (2500) and 2501. epp-go was not used: its cgo libxml2 binding does not build against libxml2 2.15. No extensions or poll messages; Experimental. Source `57fb4335`, CI `ebe29613`.

- [x] **19. JMAP** — B/L; proposed feature `jmap`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc8620.html).
  - Scope: JMAP Core plus Mail, session discovery, batched methods, object operations and change-state tokens.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 4 JMAP test functions pass. Rust owns the session resource, Basic/Bearer authentication, RFC 8620 request validation (notJSON, notRequest, unknownCapability, limit), capability and account checks, Core/echo, result references (JSON Pointer with `*`) and creation ids, and the get/set size limits; the handler is the store and answers every other Mailbox, Email, Thread, SearchSnippet, Identity, EmailSubmission and VacationResponse call, including its state tokens. Unchanged jmapc 0.3.0 (Python) discovers the session over HTTPS with the server's published self-signed certificate, echoes, queries mailboxes into a get by result reference, queries and gets emails, creates an email read back by creation id in the same request, has an update refused for an unknown id, reads changes and gets cannotCalculateChanges for an old state, and is refused with a wrong password. NetGet's client against an unchanged Stalwart 0.16.24 server gets mailboxes, creates an email read back by creation id, queries it into a get by reference, reads changes since the pre-create state, sets a keyword and gets unknownMethod for a bogus call; Stalwart, asked directly, holds the email with both keywords. Raw tests cover every request-level problem and the method errors Rust decides, createdIds both ways, 501 blob/push endpoints and a handler-less serverFail; NetGet pair over HTTPS with a Bearer token and an injected request. Deviation: Stalwart 0.16 is provisioned through its registry API in recovery mode, whose listener binds `[::]` on a random port with a one-time admin password for those seconds; the server it then runs binds 127.0.0.1 only with DNS pointed at loopback. No blob upload/download, EventSource or WebSocket push. Experimental. Source `0fb6b748`, CI `578e20dd`.

- [x] **20. ManageSieve** — B/M; proposed feature `managesieve`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc5804.html).
  - Scope: List/upload/activate/delete filter scripts, authentication, literals and errors; script execution is not implicit.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 5 ManageSieve test functions pass. Unchanged sievelib 1.5.0 (Python) logs in to NetGet's server and uploads, checks, activates, lists, reads, renames, deletes and asks for space, getting the handler's refusals (a script error, NONEXISTENT, ACTIVE, ALREADYEXISTS, QUOTA/MAXSIZE) and a refused login; sievelib normalizes scripts it reads to LF lines, so exact bytes are checked on the server's side. NetGet's client against unchanged Dovecot 2.4.5 with Pigeonhole 2.4.5 (C), built from pinned tarballs and run unprivileged: uploads, Pigeonhole's real compiler error for a bad script, CHECKSCRIPT, activation, listing, retrieval, renaming (read back from Dovecot's own script file and active link), ACTIVE and NONEXISTENT refusals, HAVESPACE, and a refused login. The earlier deferral over Dovecot 2.3 versus 2.4 configuration is resolved by building one pinned 2.4.5 everywhere; macOS needs `default_vsz_limit = 1024G` and a runtime directory short enough for sun_path. Wire tests cover the grammar, client against server, and raw refusals. NetGet never parses or runs Sieve; no STARTTLS; Experimental. Source `02e0a6d3`, CI `aba322bb`.

- [x] **21. CalDAV** — B/L; proposed feature `caldav`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc4791.html).
  - Scope: Calendar discovery, resources, REPORT queries, event CRUD and documented iCalendar/recurrence coverage.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 11 DAV test functions pass twice in a row (shared engine with item 22). Unchanged python caldav 3.3.1 is refused a bad password, discovers the principal and home, creates a calendar with MKCALENDAR, saves events, gets only the in-range event from a time-range search, updates and deletes by UID and refuses a duplicate UID; unchanged vdirsyncer 0.21.0 syncs a calendar both ways including a delete; NetGet's client discovers, creates, writes with If-None-Match and If-Match, lists, queries, reads and deletes against unchanged Radicale 3.8.1; wire tests cover PROPFIND, calendar-query (time-range and text), multiget, preconditions, no-uid-conflict and fail-closed logins. Recurrence sets are not expanded (a recurring object matches any range after its first start); no sync-collection, scheduling or free-busy; Experimental. Source `198024a7`, CI `61f8fd30`.

- [x] **22. CardDAV** — B/M-L; proposed feature `carddav`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc6352.html).
  - Scope: Address-book discovery, vCard resource CRUD, REPORT queries and identifiers.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: shares the DAV engine and test run with item 21. Unchanged vdirsyncer 0.21.0 discovers and downloads cards, uploads an edit and a new vCard 4.0 card and propagates a delete; NetGet's client creates an address book with extended MKCOL, writes, lists, queries, reads and deletes against unchanged Radicale 3.8.1; wire tests cover addressbook-query match types, negation, anyof/allof, is-not-defined, limit, multiget and MKCOL resourcetype checks. No sync-collection or vCard version conversion; Experimental. Source `198024a7`, CI `61f8fd30`.

- [x] **23. StatsD and DogStatsD** — A/S-M; proposed feature `statsd`. [Specification/reference](https://docs.datadoghq.com/extend/dogstatsd/datagram_shell/).
  - Scope: Collector/emitter, typed metrics, sample rates/tags, DogStatsD events/service checks and bounded datagram parsing.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.

  - Validation: 13 server and 5 client tests passed with Python `statsd==4.0.1` / `datadog==0.52.0` and Node `statsd@0.9.0`. Code `643eef1f`, integration merge `79b98590`; shared metadata and combined integration checks passed (see batch evidence below). No external DogStatsD Agent receiver, fuzz or packet-capture coverage is claimed.

- [x] **24. Graphite Carbon plaintext** — B/S; proposed feature `graphite`. [Specification/reference](https://graphite.readthedocs.io/en/stable/feeding-carbon.html).
  - Scope: Timestamped metric collection/emission with bounded lines and numeric validation.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 13 server and 5 client tests passed with Graphyte 1.7.1 and official Carbon 1.1.10/Twisted 25.5.0 (Python 3.11), including the NetGet pair. Code `56ec664b`, merge `ea66427a`. Experimental; TCP plaintext with bounded batches, no Pickle, UDP, TLS or storage/query service.

- [x] **25. Fluent Forward** — B/M; proposed feature `fluent_forward`. [Specification/reference](https://docs.fluentd.org/input/forward).
  - Scope: MessagePack event/batch modes, acknowledgments, bounded compression and explicit secure-transport scope.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.

  - Validation: 17 server and 7 client tests passed with fluent-logger 0.11.1/msgpack 1.1.2 and official Fluentd 1.19.4. Code `8342e85a`, integration `1d1b7a15`, published master `313ad42e`. Four bounded carriers, EventTime and correlated ACKs; no secure-forward/TLS, durable storage or retry claim. Experimental.

- [x] **26. GELF** — B/M; proposed feature `gelf`. [Specification/reference](https://go2docs.graylog.org/current/getting_in_log_data/gelf_format.html).
  - Scope: Structured logs over TCP/UDP, framing, bounded UDP reassembly and compression.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.

  - Validation: 17 server and 5 client tests passed with pygelf 0.4.3 and official Graylog Go reader sources pinned at `25db8704bc`; TCP/UDP, compressed/chunked framing, direct pairing, bounds and mixed handler failure are covered. Code `daa80399`, handler-failure fix `d58a4c0c`, published master `313ad42e`. Experimental; shared logs/memory, no collector persistence or acknowledgement invented.

- [x] **27. Loki push API** — B/M; proposed feature `loki`. [Specification/reference](https://grafana.com/docs/loki/latest/reference/loki-http-api/).
  - Scope: Labeled log ingestion/emission, authentication/tenancy, batch validation, compression and failure responses.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.

  - Validation: 30 checks (9 client, 21 server) passed at 100 test threads with official Loki 3.7.8 service readback, maintained Alloy 1.20.1 protobuf/Snappy emission and Python logging-loki 0.3.1 JSON emission. All three carriers preserve timestamps, labels, text and structured metadata; tenancy/authentication, error responses, decompression bounds and cancellation are exercised. Code `b576578c`, HTTP-token correction `bbce4898`, shared integration `9008eb88`. Experimental cleartext push API; no query, durable store, retention/order engine or automatic retries.

- [x] **28. InfluxDB write API** — B/S-M; proposed feature `influxdb`. [Specification/reference](https://docs.influxdata.com/influxdb/v2/api/write/).
  - Scope: Pinned write API, line protocol, types/escaping/timestamp precision, authentication and partial errors.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.

  - Validation: code `cf9237ba`, signed integration `3d8f39d8`; all 18 server and 10 client checks pass at 100 threads against official influxdb-client 1.50.0, the unmodified official line-protocol/v2 2.2.1 decoder, and InfluxDB 2.9.1 daemon readback. Five field types, four precisions and identity/gzip carriers are covered. HTTP v2 writes only; no database/query engine or HTTPS transport claim. Experimental. The Linux independent-pair job also passed.

- [x] **29. IPFIX** — B/M-L; proposed feature `ipfix`. [Specification/reference](https://www.rfc-editor.org/info/rfc7011/).
  - Scope: Collector/exporter, templates, typed data records, domain/sequence tracking and template lifecycle.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.

  - Validation: see Batch 7 below — 28 checks (20 collector, eight exporter) against unmodified Python ipfix 0.9.7 and the official GoFlow2 2.2.7. Source `69eb9b8c`. Experimental; no complete RFC, reliable-delivery, TLS, flow-store, fuzz or pcap claim.

- [x] **30. sFlow v5** — B/M; proposed feature `sflow`. [Specification/reference](https://sflow.org/developers/specifications.php).
  - Scope: Collector/agent, flow/counter samples, sampling metadata and extensible bounded records.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.

  - Validation: **27 checks** (17 collector, ten exporter) passed at 100 threads with pinned BSD Cistern/sflow and actual GoFlow2 2.2.7. All four v5 sample carriers, literal wire fixtures, selected typed flow/interface/Ethernet/VLAN records, sequence/session/queue bounds and cancellation are covered. Source `9be47d52`, peer output-order correction `d3686cce`. Experimental; no SNMP polling, full record catalog, auth, durable flow store, fuzz or pcap claim.

- [x] **31. AMQP 1.0** — B/L; proposed feature `amqp1`. [Specification/reference](https://docs.oasis-open.org/amqp/core/v1.0/os/amqp-core-overview-v1.0-os.html).
  - Scope: Separate from 0-9-1: connection/session/link lifecycle, credit, send/receive, settlement and outcomes.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 5 AMQP 1.0 test functions pass. Unchanged rhea 3.0.5 (JavaScript) and go-amqp 1.7.0 (Go) authenticate with SASL PLAIN, publish and consume through the container, get accepted and rejected outcomes (conditions and descriptions intact), receive the confirmation the handler routes to another address, and are refused a forbidden address and a wrong password; rhea also receives the message the handler produces for its credited news receiver and its own data message relayed on chat. NetGet's client against an unchanged rhea broker sends (accepted, rejected, refused link) and receives with credit. Codec tests cover compact encodings, round trips and hostile input; the pair covers relay and produced messages; no handler answer fails closed. rhea exposed two points now handled: answering a client's detach of an already-refused link must not detach twice, and rhea's broker accepts an attach without echoing the terminus (a null terminus is a refusal only if its detach follows). Addresses are topics; no transactions, link recovery, filters or storage; Experimental. Source `37c9673b` (shared task guard `5ab69c55`), CI `2083abe1`.

- [x] **32. Zenoh** — B/M-L; proposed feature `zenoh`. [Specification/reference](https://zenoh.io/docs/overview/what-is-zenoh/).
  - Scope: Listening/connecting peer roles, publication, subscriptions and query/queryable handlers using existing runtime.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 4 Zenoh test functions pass. NetGet embeds the zenoh 1.10.1 runtime (TCP only), so the independent peer is zenoh-pico 1.10.1, a separate C implementation built from its pinned release. Pico clients against NetGet's router: a publication the handler echoes reaches a pico subscriber, a query is answered and another refused with an error, and a get the handler issues is answered by a pico queryable; the links appear as loopback connections. NetGet's client, as a peer, against pico peers listening on their own ports: a pico subscriber receives NetGet's put, a pico queryable answers NetGet's get, and NetGet's subscriber receives a pico publisher's values. A peer-mode session opens before its link is up, so the client waits up to 10 s for it. Wire tests cover validation, client against router, a handler with an invalid answer failing the query closed with a category only, and a refused startup key. zenoh-pico examples block-buffer stdout on a pipe, so they run to completion. No TLS, QUIC, UDP or shared memory; Experimental. Source `3081497c`, CI `14a1e6a5`.

- [x] **33. WAMP** — C/M-L; proposed feature `wamp`. [Specification/reference](https://wamp-proto.org/).
  - Scope: Router/client sessions, realms, routed RPC and pub/sub with correlation and errors.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 6 WAMP test functions pass. Unchanged autobahn-python 24.4.2 and nexus 3.3.0 (Go) join realm1 on the router, register and call through it (autobahn also sees its own callee's runtime error routed back), publish with acknowledgement and receive their own events, subscribe by prefix (autobahn), call the router's handler-answered procedures (a result and an application error), are refused a duplicate registration (autobahn) and realm "blocked", and leave with GOODBYE. NetGet's client against the unchanged nexus router calls nexus's callee (result and error), receives its ticks, publishes to its subscriber and registers a procedure that nexus's caller invokes and the handler answers, all asserted from nexus's own output. Raw WebSocket tests cover subprotocol refusal, HELLO rules and timeout, wildcard/exact subscriptions with exclusion and black/white listing, routed RPC with disclose_me, routed errors, unknown subscription/registration, a callee leaving mid-call, an injected publication and violations after WELCOME; no handler answer is ABORT not_authorized / ERROR unavailable; the NetGet pair covers all four client roles. JSON over WebSocket only; anonymous auth; no progressive results, cancellation, shared registrations or meta API; Experimental. Source `c26eb71c`, CI `c252f69b`.

- [x] **34. Apache Thrift** — B/L; proposed feature `thrift`. [Specification/reference](https://thrift.apache.org/docs/).
  - Scope: Explicit IDL/schema-driven RPC, selected transports/encodings and structured calls/results/errors.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 7 Thrift test functions pass. Unchanged thriftpy2 0.7.1 (IDL-driven, C codecs) calls NetGet's server over framed binary and buffered compact; Apache Thrift 0.25.0's own protocol classes, with no generated code and results read generically by field id, call it over buffered binary and framed compact. Between them: return values, structs, a list of structs from a set of enums, a struct argument, a declared exception in its throws field, an application error, oneway calls, and an unknown method refused with UNKNOWN_METHOD without reaching the handler. NetGet's client calls an unchanged thriftpy2 server over both pairings (results, declared exception, UNKNOWN_METHOD, a struct argument and oneway call the server prints) and refuses an argument missing a required field before the wire. Codec tests cover every value type in both protocols, every truncation reported incomplete, 10 000-level nesting bombs, IDL refusals, an oversized frame, a byte-at-a-time unframed call and pipelined calls. Unframed messages are decoded again only on half-again growth or a 20 ms pause, so a trickling peer cannot force a decode per read. The transport is detected from the first byte, so a non-strict binary client must be framed; no multiplexed, JSON, HTTP or THeader; Experimental. Source `f510ca3e`, CI `428fc7fb`.

- [x] **35. OPC UA** — B/L; proposed feature `opcua`. [Specification/reference](https://github.com/FreeOpcUa/async-opcua).
  - Scope: Device address space and client browse/read/write/method/subscription operations; declare security policies.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: OPC UA: async-opcua 0.19.0 with documented connection/service ownership and chunk-length patches; unchanged asyncua 1.1.8 validates browse, read, write, method, and data-change subscriptions in both directions. Six focused checks cover protocol statuses, malformed/oversized frames, 256 live connections, injected disconnect, owner stop, and remote transport failure. Only anonymous SecurityPolicy None / MessageSecurityMode None; fixed Device/Double Value/Double method metadata, handler-sourced values, initial and approved-write notifications. No secure policies, periodic sampling, history, or events. Experimental. Source `571edcfc`, ownership/lifecycle corrections `068364f0`, integrated master merge `c4ccc5cb`. Standalone all-target feature build and blocking all-target clippy pass; reproducible peer setup and CI job are in `tests/helpers/ICS_PEERS.md`.

- [x] **36. BACnet/IP** — B/M-L; proposed feature `bacnet`. [Specification/reference](https://github.com/bacnet-stack/bacnet-stack).
  - Scope: Device discovery and property reads/writes, correct BACnet framing/errors; document segmentation/COV scope.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: BACnet/IP: unchanged bacpypes3 0.0.102 validates WhoIs/IAm discovery, typed ReadProperty/WriteProperty, and protocol errors in both directions. Three checks include malformed framing, segmented-request Abort, unsupported-service Reject, and UDP stop/rebind. Local IPv4 NPDU and primitive values only; no segmentation, BBMD/routing, COV, or ReadPropertyMultiple. Handler values/approvals do not persist. Experimental. Source `571edcfc`, ownership/lifecycle corrections `068364f0`, integrated master merge `c4ccc5cb`. Standalone all-target feature build and blocking all-target clippy pass; reproducible peer setup and CI job are in `tests/helpers/ICS_PEERS.md`.

- [x] **37. MQTT-SN** — B/M; proposed feature `mqtt_sn`. [Specification/reference](https://mqtt.org/mqtt-specification/).
  - Scope: Gateway/sensor roles, discovery, topic registration/IDs, publish/subscribe, datagram and sleeping-client behavior.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 4 MQTT-SN test functions pass. Unchanged mqtt-sn-tools (C) publish and subscribe through NetGet's gateway: wildcard and short-topic subscribers receive QoS 1, 0 and -1 publishes (the last on predefined id 7 with no connection, delivered under that id) and one sent through forwarder encapsulation; an admin/ publish the handler refuses never reaches its subscriber (mqtt-sn-pub itself ignores the PUBACK return code), and the refused client gets CONNACK 0x03. NetGet's client through the unchanged Eclipse Paho MQTT-SN Gateway (C++) in front of Mosquitto: QoS 1, 2 and 0 publishes reach mosquitto_sub, a subscription receives what mosquitto_pub sends, and a message published while the client sleeps is held by the Paho gateway and delivered on wake. NetGet's client against its own gateway covers QoS 2 both ways, a handler-published greeting with a lowered grant, a lost client's will after 1.5 x keep-alive, held messages on wake, a peer-handle injection and raw-socket refusals; every packet type round-trips. The Paho gateway buffers stdout on a pipe, so its readiness is a CONNECT it answers. The gateway is its own broker with no retained-message store; Experimental. Source `9a0595f0`, CI `b5730e6c`.

- [x] **38. LwM2M** — B/L; proposed feature `lwm2m`. [Specification/reference](https://www.openmobilealliance.org/release/LightweightM2M/V1_2-20201110-A/HTML-Version/OMA-TS-LightweightM2M_Core-V1_2-20201110-A.html).
  - Scope: Management server/device client, registration, bootstrap, object resources, observation and declared security.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 5 LwM2M test functions pass. The unchanged Eclipse Leshan 2.0.0-M15 client demo (Java/Californium) registers with NetGet's server (Device, Location and Temperature objects declared) and is read in text and SenML JSON, written and read back, executed, discovered, refused 4.04 for an object it lacks, and observed, with a notification from its sensor; it deregisters on SIGTERM. NetGet's device against the unchanged Leshan server demo, driven through Leshan's REST API: it appears in Leshan's client list with its objects, answers reads, a write that reads back, an execute and a 4.04, and a notification it sends for Leshan's observation appears in Leshan's event stream; on disconnect Leshan drops it. One defect found by the pair: plain-text values were typed by parsing, so a UTC offset "+02" came back as the number 2; text is now a number only when it reads back exactly. The demo's TLS endpoint reuses the TCP port option, so it is bound to ::1. Wire tests cover codecs, device against server and raw registration refusals. No DTLS, OSCORE, bootstrap, TLV/CBOR or block-wise transfer; Experimental. Source `57ee76c4`, CI `1df0d563`.

- [x] **39. OCPP** — B/M-L; proposed feature `ocpp`. [Specification/reference](https://openchargealliance.org/protocols/open-charge-point-protocol/).
  - Scope: Charging-management server and simulated charge point; pin version with boot/heartbeat/status/transaction workflows.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 8 checks pass. python ocpp 2.1.0 (schema-validating) as charge point against the CSMS over 1.6 and 2.0.1 (boot, heartbeat, status, authorize, transactions, meter values, NotSupported CALLERROR, accepted remote start) and as central system against the charge point (both workflows, Reset after boot); NetGet pair, subprotocol and frame refusals, handler-less InternalError. No charging database, security profiles or schema engine; Experimental. Source `fec07b02`, CI `54cd5707`.

- [x] **40. DNP3** — C/L; proposed feature `dnp3`. [Specification/reference](https://github.com/stepfunc/dnp3).
  - Scope: Outstation/master, typed measurements, events, polling and declared controls, deterministic timing.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: DNP3: dependency decision is the self-contained Rust selected codec, with unchanged Apache-2.0 OpenDNP3 3.1.2 as an external master/outstation peer. Four checks cover class polls, typed binary/float/counter measurements, confirmed timestamped events, binary direct-operate, CRC errors, bounds, and live stop/rebind. Fixed link addresses 1/10; unconfirmed link data, bounded transport assembly, deterministic handler timestamps and 10-second client deadlines. No commercial dependency, unsolicited reporting, SELECT/OPERATE, analog controls, serial, or Secure Authentication. Experimental. Source `571edcfc`, ownership/lifecycle corrections `068364f0`, integrated master merge `c4ccc5cb`. Standalone all-target feature build and blocking all-target clippy pass; reproducible peer setup and CI job are in `tests/helpers/ICS_PEERS.md`.

- [x] **41. IEC 60870-5-104** — C/L; proposed feature `iec104`. [Specification/reference](https://github.com/mz-automation/lib60870/blob/master/user_guide.adoc).
  - Scope: Controlled/controlling stations, interrogation, telemetry, commands, sequence windows and timers.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: IEC 104: unchanged lib60870 2.3.4 validates controlled/controlling stations, GI telemetry and direct single commands. Six checks include invalid sequences, send-window exhaustion, t1 acknowledgment timeout, command bounds, and live stop/rebind. Selected ASDUs 1/13/45/100/102; k=12, immediate acknowledgments within w=8/t2, t1=15s and t3=20s. Client accepts spontaneous binary/float telemetry. Select commands, timestamps, files, clock sync and redundancy are outside this scope. Experimental. Source `571edcfc`, ownership/lifecycle corrections `068364f0`, integrated master merge `c4ccc5cb`. Standalone all-target feature build and blocking all-target clippy pass; reproducible peer setup and CI job are in `tests/helpers/ICS_PEERS.md`.

- [x] **42. EtherNet/IP CIP** — C/L; proposed feature `ethernet_ip`. [Specification/reference](https://github.com/EIPStackGroup/OpENer).
  - Scope: Adapter/scanner discovery and explicit object messaging; cyclic I/O is a separately declared scope.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: EtherNet/IP CIP: unchanged cpppo 5.2.5 validates explicit GetAttributeSingle/SetAttributeSingle in both directions. Four checks cover typed attributes, refused/unknown operations, TCP/unicast UDP ListIdentity, invalid sessions, bounds and TCP/UDP owner stop/rebind. Both sockets are acquired before tasks start. Logical class/instance/attribute paths only; schema declares write types and handler values do not persist. No routing, symbolic tags, ForwardOpen, or cyclic I/O. Experimental. Source `571edcfc`, ownership/lifecycle corrections `068364f0`, integrated master merge `c4ccc5cb`. Standalone all-target feature build and blocking all-target clippy pass; reproducible peer setup and CI job are in `tests/helpers/ICS_PEERS.md`.

- [x] **43. S7comm** — C/L; proposed feature `s7comm`. [Specification/reference](https://github.com/S7NetPlus/s7netplus).
  - Scope: PLC simulator/client, TPKT/COTP, selected legacy data-area reads/writes and protocol errors.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: S7comm: unchanged python-snap7 3.2.1 validates PLC/client selected legacy reads and writes over TPKT/COTP. Four checks cover DB/input/output/marker bytes, write approval, protocol address errors, malformed framing, bounds and live stop/rebind. S7ANY byte items only, 480-byte negotiated PDU, 16 items and 200 bytes/item; no S7plus, authentication, bit/multi-byte items, PLC commands or file operations. Experimental. Source `571edcfc`, ownership/lifecycle corrections `068364f0`, integrated master merge `c4ccc5cb`. Standalone all-target feature build and blocking all-target clippy pass; reproducible peer setup and CI job are in `tests/helpers/ICS_PEERS.md`.

- [x] **44. FastCGI** — B/M; proposed feature `fastcgi`. [Specification/reference](https://fastcgi-archives.github.io/FastCGI_Specification.html).
  - Scope: Application responder/client, parameters, input/output streams, request IDs, abort/end and bounded framing.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 5 test functions pass. Unchanged nginx forwards GET with query and header, a 100 KB POST (several STDIN records), a 200 000-byte answer (several STDOUT records), a binary answer and a STDERR line it logs, over one kept-alive upstream connection, and gets a 500 from a handler-less responder; unchanged flup 1.0.3 answers the client's GET, POST, large, stderr, 404, redirect, GET_VALUES (empty: flup's Python 3 lookup compares bytes with str keys) and a slow request the client aborts; raw records cover GET_VALUES, UNKNOWN_TYPE, UNKNOWN_ROLE, CANT_MPX_CONN, ABORT_REQUEST, KEEP_CONN, 431/413 bounds and versions. Responder role only, one request per connection, no Unix sockets; Experimental. Source `9b64a0ed`, CI `b0c9daaf`.

- [x] **45. ICAP** — B/M-L; proposed feature `icap`. [Specification/reference](https://www.rfc-editor.org/rfc/rfc3507.html).
  - Scope: Adaptation server/client, OPTIONS/REQMOD/RESPMOD, encapsulation offsets, preview, chunks and 204 behavior.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 6 checks pass. c-icap 0.6.5's c-icap-client against the server (OPTIONS, clean/blocked RESPMOD, redacted REQMOD, 512-byte preview continued to 3000 bytes) — it caught a request head wrongly echoed in RESPMOD responses that the NetGet pair had accepted; c-icap's echo service against the client (OPTIONS, RESPMOD, REQMOD, continued preview); framing and refusal tests. No scanning engine, 206 or TLS; Experimental. Source `d0c3d9d1`, CI `4db89756`.

- [x] **46. NBD** — C/L; proposed feature `nbd`. [Specification/reference](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md).
  - Scope: Read-only scripted block target and userspace client, negotiation, bounds, read/errors and structured replies.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 5 NBD test functions pass. Unchanged libnbd 1.24.3 (C) against NetGet's server: nbdinfo lists both exports with descriptions, describes disk0 (1 MiB, read-only, base:allocation, structured replies, preferred block size, description) and maps its allocation run by run exactly as the handler described it; nbdcopy copies disk0 byte for byte and fails with an I/O error on the export whose error region holds data (with the region in a hole, nbdcopy correctly skipped it via block status); a policy refusal and an unknown export are reported as such. NetGet's client against unchanged nbdkit 1.48.1 (C) with its data plugin and error filter: the export list, size and block sizes, the plugin's bytes, a zero region, allocation from block status, flush, and EIO once the filter is armed. The client against the server covers structured replies, block status, an error offset and EINVAL past the end; a raw client covers simple replies, EPERM for writes and trims, ERR_UNKNOWN, ERR_UNSUP and an oversized option. Read-only, no TLS or extended headers; Experimental. Source `67464673`, CI `7be38c85`.

- [x] **47. RTMP** — C/L; proposed feature `rtmp`. [Specification/reference](https://rtmp.veriskope.com/pdf/rtmp_specification_1.0.pdf).
  - Scope: Playback/publication endpoints, handshake, chunks, AMF command handling and supplied media with timestamps.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 4 RTMP test functions pass. Unchanged FFmpeg publishes an H.264/AAC clip that ffprobe reads back (h264 320x240, aac) and FFmpeg decodes, and unchanged MediaMTX 1.21.1 (its own Go RTMP stack) pulls the stream and reports H264 and MPEG-4 Audio tracks; FFmpeg is refused a stream key, an app and a play the policy rejects. NetGet's client plays from MediaMTX (Play.Start, avc/aac, counts, timestamps) and publishes the clip, which MediaMTX's API reports with both tracks. Raw-wire tests cover the handshake echo, connect accept/reject, ping, AMF3 and an oversized message closing the connection, and no handler answer; the NetGet pair covers cached metadata, sequence headers, keyframe join and an injected onTextData. MediaMTX exposed two compatibility points that are now handled: it sends the whole path as the app with an empty stream name, and treats a connection as one reader or publisher (and keeps streaming after deleteStream, which taught the client to wait on one overall deadline). Live relay only, AMF0 only, no RTMPS/RTMPT or digest handshake; Experimental. Source `89e60cda`, CI `fa1ff8cf`.

- [x] **48. SRT** — C/L; proposed feature `srt`. [Specification/reference](https://github.com/Haivision/srt).
  - Scope: Listening/connecting endpoints exchanging supplied media/data through a real retransmission/timing implementation.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 4 SRT test functions pass. Retransmission and timing come from srt-tokio 0.4.4 (pure Rust ARQ/TSBPD/AES). Unchanged libsrt 1.5 (srt-live-transmit) publishes a paced H.264/AAC MPEG-TS stream through the listener that a second libsrt caller reads back and ffprobe decodes, and is refused a forbidden resource; NetGet's caller reads from and publishes to libsrt listeners (reported PMT stream types; ffprobe decodes what libsrt wrote). Wire tests cover the stream-ID parser, handshake refusals (bad ID, forbidden, bidirectional, second publisher, no answer), a byte-exact relay with an injected text, and the idle close with statistics. Findings: srt-tokio puts its payload size in the handshake MSS field, which made libsrt cap messages at 1272 bytes (payload size raised to 1456 on both roles), and MediaMTX's gosrt refuses srt-tokio's SRT 1.3 handshake in both directions, so MediaMTX is not an SRT peer. Live mode only; no rendezvous, bidirectional mode, FEC or bonding; Experimental. Source `24e4800c`, CI `50a4efef`.

- [x] **49. WebTransport HTTP/3** — B/L; proposed feature `webtransport`. [Specification/reference](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/).
  - Scope: Pin draft/library compatibility; server/client sessions, streams, datagrams, cancellation and browser interop.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 4 WebTransport test functions pass, plus 4 in `tests/vendored_wtransport_patch_test.rs`. Pinned to the draft-02 wire Chrome and aioquic speak, on wtransport 0.7.2 vendored with an owned driver (closed and aborted on drop), a bounded reader set, checked SETTINGS and extended-CONNECT opt-in, and bounded QPACK field sections (64 fields, 16 KiB, no dynamic table, no duplicates). Unchanged aioquic 1.3.0 as client is admitted with an extra response header, exchanges bidirectional and unidirectional streams and datagrams, answers a stream the server opens (raised back as `webtransport_stream_reply`), sends hex data, has a 1 MiB + 1 stream reset unseen by the handler and an unanswered stream finished empty, and is closed by the handler with code 7; it is refused with 403, 429 and 404, a plain HTTP/3 GET never reaches the handler, and a server with no handler refuses with 429. Headless Chrome's own WebTransport API reaches the self-signed server through `serverCertificateHashes` with the hash the server publishes. NetGet's client against an aioquic server pins its certificate, sends extra headers, answers a server-opened stream, injects a datagram and closes; a refused path, a wrong pin and conflicting trust fail. NetGet pair with injection on both sides. aioquic does not mark bidirectional WebTransport streams it opens itself, so the test peer reads their answers at the QUIC layer; the library is unchanged. A refused session reaches the client only as "rejected" (wtransport does not surface the status). One session per connection; no CLOSE_WEBTRANSPORT_SESSION/DRAIN or flow-control capsules. Experimental. Source `ede90d34`, CI `201609ad`.

- [x] **50. HL7 v2 MLLP** — C/M; proposed feature `hl7`. [Specification/reference](https://www.hl7.eu/refactored/transport01mllp.html).
  - Scope: Integration endpoint/client, MLLP framing, selected message profiles, control IDs and validated acknowledgments.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 7 checks pass. python-hl7 0.4.5's MLLP client (ADT^A01, ORU^R01, QRY^A19 v2.3) against the endpoint and its MLLP server against the sender (AA, AE with ERR, AR; receiver-side parse asserted); NetGet pair, MLLP framing refusals, `\F\` escaping and segment-forgery refusal, handler-less AE, mismatched MSA-2. No clinical store or profile engine; Experimental. Source `a5aa48ff`, CI `5b86eb17`.

- [x] **51. DICOM DIMSE** — C/L; proposed feature `dicom`. [Specification/reference](https://dicom.nema.org/medical/dicom/current/output/html/part08.html).
  - Scope: Association/transfer syntax negotiation, C-ECHO and an explicitly selected useful service set, structured actions.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 8 DICOM test functions pass. Unchanged pynetdicom 3.0.4 (on pydicom 3.0.2) as the SCU is refused for a wrong called AE title, a rejected calling AE and an undecided association, negotiates Explicit VR Little Endian, echoes, stores three instances (one refused A700 with its comment) and gets wildcard, date-range, patient-root and empty C-FIND results matched and projected by Rust; as the SCP it decodes what NetGet's client stores (pixel bytes included), answers its C-FIND and refuses a wrong called AE title. Raw PDU tests cover an oversized PDU, a non-RQ first PDU, a SOP UID mismatch (A900, handler not asked), an unknown command (0211) and the idle abort; codec tests use literal Implicit/Explicit LE bytes, hostile lengths, an undelimited sequence and a depth bomb. Services: C-ECHO, C-STORE, C-FIND (Patient and Study Root); no C-MOVE, C-GET, N-services, compressed transfer syntaxes or TLS; Experimental. Source `917f1e24`, CI `7e6e4aa4`.

- [x] **52. FIX** — C/L; proposed feature `fix`. [Specification/reference](https://fixtrading.org/packages/fix-session-layer-technical-proposal/).
  - Scope: Acceptor/initiator session engine, dictionaries, heartbeat/resend/recovery and scripted application messages.
  - [x] Server or listening/collector role implemented and registered.
  - [x] Client or connecting/exporter role implemented and registered.
  - [x] Independent interoperability, negative/lifecycle tests and feature build pass.
  - [x] Documentation, honest metadata and integrated commit recorded.
  - Validation: 5 FIX test functions pass. Unchanged QuickFIX/Go 0.9.12, which validates every application message against FIX44.xml before its application sees it, logs on to the acceptor, gets an ExecutionReport and a BusinessMessageReject, exchanges heartbeats at HeartBtInt 1 without a session Reject, logs out, and is refused a wrong SenderCompID; as acceptor it validates and answers NetGet's NewOrderSingle and OrderCancelRequest and takes its Logout. Raw-wire tests cover the Logon rules and timeout, TestRequest, a garbled CheckSum ignored, ResendRequest answered with a gap fill and PossDup resends, gap detection with the held message resent, MsgSeqNum too low, the heartbeat timeout, BusinessMessageReject reason 4 with no model, a Logon with no decision and an injected News through the peer handle; the NetGet pair. Dictionary names generated from FIX44.xml (953 fields, 92 messages); application messages are not validated against it. No FIXT.1.1/FIX 5.0, persistence or encryption; Experimental. Source `1c034b27`, CI `56bc0b7e`.

## Existing protocol completion checklist

- [x] **53. HTTP/3 server**.
  - Scope: Real HTTP/3 headers/data/control/QPACK using h3/quinn and existing HTTP/3 client interoperability.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.

  - Validation: 8 server, 6 client and 2 standalone cancellation/early-hints tests passed with aioquic 1.3.0 and direct NetGet pairing at 100 threads in the final combined build. Code `168b8e82`, TE correction `c4ddd3df`, peer-port fix `73292cbc`, published master `313ad42e`. Authenticated TLS, real h3/QPACK/control, bounded UTF-8 headers/bodies/trailers and owned stream cancellation; no push, DATAGRAM/WebTransport, migration or 0-RTT. Experimental. Vendored h3-quinn 0.0.10 contains the tested pending-read cancellation fix.

- [x] **54. Raw QUIC client**.
  - Scope: Stream-oriented counterpart to existing raw QUIC server; explicit ALPN and stream lifecycle.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.
  - Validation: 6 client and 10 server tests passed with aioquic 1.3.0 in both independent roles and direct NetGet binary pairing. Code `5a872651`, allocation/pairing follow-up `7afc32e0`, final merge `b7a2e7c6`. Raw ALPN is now `netget-quic`; `h3` is reserved for HTTP/3. Verified TLS/custom trust, 1 MiB decoded/4 MiB encoded bounds, owned concurrent streams, cancellation and socket release. Experimental; no 0-RTT/datagrams/unidirectional application streams.

- [x] **55. SFTP client**.
  - Scope: Extend SSH with file/directory operations matching existing server SFTP, plus real external-server evidence.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.

  - Validation: read-only SFTP v3 stat, directory listing and UTF-8 file windows are integrated as `4a4884b0` (accurate startup modes `2e905b45`). In the merged `tcp,gearman,ssh` build, all 16 SSH client and 14 existing SSH server tests passed at 100 threads with independent OpenSSH 10.3p1 and direct NetGet pairing. All 129 shared checks across 31 targets, correctness/suspicious/unused-must-use lint and whole formatting pass. SFTP requires an explicit SHA256 host pin; bounded framing/channel queues and owned socket shutdown are tested. Experimental; no writes, binary file action, known_hosts, forwarding, second independent SFTP implementation, fuzz or new pcap claim. Logs: `.protocol-expansion-20261001/logs/batch5-ssh-initial.log` and `batch5-{shared,clippy,format}-initial.log`.


- [x] **56. OTLP client and gRPC receiver**.
  - Scope: Export traces/metrics/logs, both HTTP and gRPC as advertised; gRPC server alongside existing HTTP receiver.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.

  - Validation: 40 checks (9 client, 31 receiver) passed at 100 test threads. Official core Collector 0.162.0 independently receives typed traces, gauge metrics and text logs over HTTP protobuf and gRPC; otel-cli 0.4.5 and telemetrygen 0.161.0 exercise the receiver. Verified TLS exports/custom CA, none/gzip, partial success, retry/status details, message/body limits, deadline cancellation and same-connection recovery are covered. Existing HTTP checks remain. Code `00a32c6c`, compression/deadline-header correction `481fb76b`; shared tonic patch `c2a589a5` separately passes three 4 MiB boundary regressions and 28 gRPC/etcd neighbor checks. Experimental: documented signal subset, same-port cleartext receiver, no receiver TLS or automatic retries.

- [x] **57. Prometheus client**.
  - Scope: Scrape, negotiate and parse metrics into structured events; remote write tracked separately.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.

  - Validation: code `26854817`; all 20 client and 18 existing server checks pass at 100 threads with Prometheus/promtool 3.15.0 and prometheus-client 0.22.1, plus NetGet pairing. Text 0.0.4/OpenMetrics 1.0, negotiation, native metric families, limits, model/manual/script handlers and cancellation are covered. No remote write, PromQL, protobuf/native histograms or OpenMetrics 2.0 claim. Experimental. The Linux independent-pair job also passed.

- [x] **58. Docker client**.
  - Scope: Structured API actions paired with existing programmable Docker server.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.

  - Validation: 34 checks (16 client, 18 preserved server) passed at 100 test threads using real Docker Engine 29.7.2 and CLI 29.8.0. Native Unix socket and owned TCP relay cover eight read operations, API negotiation, filters, nullable/list/inspect shapes, bounded payloads, command injection and cancellation. Tests only read the existing daemon; they do not pull images or create resources. Code `ae95298a`, shared integration `9008eb88`. Experimental selected read-only Engine API with a 1.47 ceiling; existing mutation refusal remains, and TLS/named pipes are outside this scope.

- [x] **59. Vault client**.
  - Scope: Structured authentication/secret operations paired with existing programmable Vault server.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.

  - Validation: **34 checks** (24 client, ten existing server) passed at 100 threads with isolated native Vault 2.0.0 daemon/CLI and a NetGet pair. Public system reads, userpass authentication/local credential clear, KV v2 read/write CAS/list/metadata and typed credential-safe events are covered. Source `a419d0ff`, action/redaction preflight and iterative disposal `e5be0070`, shared private access-log followup `101e50d0`. The real server deadline test ran for 123.01 seconds. Experimental; existing programmable server auth refusal is preserved and unsupported API/TLS/browser surfaces are documented.

- [x] **60. Nostr client**.
  - Scope: Publish signed events, subscribe, handle relay notices/results and close subscriptions.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.
  - Selected native scope: NIP-01 signed publishing, bounded REQ/CLOSE subscriptions and optional NIP-11 information. Rust validates event IDs and BIP340 signatures; handler results are typed. WS and verified native WSS are supported; unknown publish outcome stays unknown, subscriptions remain volatile, and AUTH/COUNT/browser execution/positive WSS interoperability are excluded from this evidence.
  - Evidence: coordinator **20 client + 33 preserved relay checks** pass at 100 test threads using independent nak 0.20.7 and rust-nostr SDK 0.45.1, the NetGet pair and real OpenSSL certificate rejection. Existing relay packet-capture checks also pass. Depth/node/retained-byte preflight precedes copying, queues/tasks are bounded, and stop cancels parked handlers. Source `dd9b01a2`; feature `nostr`; reproduction and exclusions in `tests/client/nostr/AGENTS.md`.

- [x] **61. Bolt client**.
  - Scope: Negotiated Neo4j-compatible sessions, queries/results/errors against existing server and independent server.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.
  - Validation: **29 new client + 69 existing server checks** pass at 100 threads with official isolated Neo4j Community 5.26.31, Java21 and bundled cypher-shell 5.26.31 / Driver5.28.15. All eight CLI cases also pass with cypher-shell 2026.09.0 / Driver6.2.1. Selected direct Bolt5.x negotiation/authentication, parameterized RUN/PULL/DISCARD, explicit transactions, RESET, typed primitive/graph/temporal/spatial results, unknown-outcome errors, bounded tasks/queues and cancellation are implemented. Native client TLS verifies WebPKI/name; untrusted-certificate rejection is tested, with no positive trusted-local TLS claim. Routing pools, Bolt6/manifest negotiation, typed complex inputs, replay, local graph/query stores and pcap/fuzz/conformance are excluded; client remains Experimental. Server arity/outbound pre-clone bounds `4ec0de1e`, native CLI compatibility `995ff86f`, client `916f63f9`, refreshed `1f0e484b`, mandatory peer CI `bdec771e`; reproduction in `tests/client/bolt/AGENTS.md`.

- [x] **62. OCI Registry client**.
  - Scope: Manifest/blob operations, digest validation and authentication flows.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.
  - Validation: 27 client and 21 server checks (48) pass; crane 0.22.1 serves and pulls as the independent peer. Bounded read-only probe/catalog/tags/manifest/blob GET and HEAD over HTTP or verified HTTPS; exact raw-byte SHA-256 for manifests and blobs (HEAD stays unverified metadata); explicit constrained Bearer trust; no redirects or local blob store; Experimental. Source `7244763a`/`3542ae99`, merge `f999546d`, CI `eb5552fb`, gate fix `0175b558`.

- [x] **63. Beanstalkd client**.
  - Scope: Put/reserve/release/bury/delete jobs and command/reply framing.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.
  - Validation: 9 client and 30 existing server tests passed with beanstalkd 1.13 and greenstalk 2.1.1, including the NetGet pair. Code `5730ffeb`, scalar-only YAML hardening `222b0d74`, merges `492fc905`/`8ff3cda6`. Text jobs up to 65,535 bytes; bounded replies and responsive cancellation. Nested/recursive/expanding YAML rejected before traversal.

- [x] **64. NSQ client**.
  - Scope: Publish/subscribe, negotiated readiness, acknowledgments, requeue and heartbeat.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.

  - Validation: 20 client and 35 preserved server tests passed with nsqd, to_nsq and nsq_tail 1.3.0 and the NetGet pair. Code `9758dc00`, close-order fix `5002305d`, heartbeat test correction `7a981923`, published master `313ad42e`. PUB/MPUB/DPUB, subscription/RDY, heartbeat, FIN/REQ/TOUCH and graceful CLS correlation; no lookupd discovery, TLS/auth, compression, reconnect or binary outbound body claim. Experimental.

- [x] **65. Gearman client**.
  - Scope: Job submission and selected worker exchanges with correlation and errors.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.

  - Validation: code `2a095a08`, compatible-peer corrections `f41cad44` and `7b39c75e`; all 19 client and 28 existing server checks pass at 100 threads with official gearmand/gearman/gearadmin 2.1.0. Submitter plus selected worker exchanges, correlation, exceptional outcomes, bounds, handlers and cancellation are covered. Existing server remains the documented model-as-worker role; no generic queue broker/storage claim. Experimental. Linux peer compilation is verified; the required existing packet-capture oracle exposed a missing tshark package, now added to CI and awaiting a rerun.

- [x] **66. Gemini client**.
  - Scope: TLS requests, certificate policy, status/meta/body handling and bounds.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.
  - Validation: 8 client and 24 existing server tests passed together with Agate 3.3.24, ignition-gemini 1.0.0 on supported Python 3.12, and the existing tshark TLS oracle. Code `d9b6f492`, merge `e3a682bb`; fixes server file-backed certificate provider startup. Experimental text/UTF-8 client with verified TLS/custom trust, structured gemtext, explicit input/redirects and bounded cancellation. No hidden TOFU, automatic cross-endpoint redirects, binary bodies or client certificate authentication.

- [x] **67. DICT client**.
  - Scope: Dictionary discovery, matching/definition operations, multiline replies and errors.
  - [x] Missing functionality implemented and registered; existing side preserved.
  - [x] Both directions validated with external peers and the NetGet pair.
  - [x] Negative/lifecycle tests, feature build, documentation and integrated commit recorded.
  - Validation: 8 client and 25 existing server tests passed with independent dictd, dictfmt and dict 1.13.3, including the NetGet pair. Code `434fc816`, merge `9146ee6d`. Experimental client; discovery/definitions/matches, bounded multiline decoding and cancellation. No AUTH, SASL, MIME negotiation or pipelining in the new client.

## Separated extension checklist

- [x] **68. Generic gRPC streaming and reflection**.
  - Scope: Add real streaming lifecycle and reflection; support new subscription-oriented services without false capability claims.
  - [x] Implementation and all required server/client integration complete.
  - [x] Independent validation, feature build, documentation and integrated commit recorded.

  - Validation: **38 checks** (24 server, 14 client) passed at 100 threads with mandatory generated grpcio 1.75.1 peers, grpcurl 1.9.4 and NetGet pairing; seven shared converter and three tonic framing checks also pass. All stream forms, half-close, reflection v1/v1alpha and discovery, gzip/message/schema bounds, verified client TLS, owned tasks, cancellation and stalled flow control are covered. Source `92504dc9`, integration `d4e7c192`. Experimental; new streams exclude reachable bytes/binary metadata, and receiver TLS, retries, full descriptor catalogs, fuzz and pcap are not claimed.

- [x] **69. gRPC-Web binding**.
  - Scope: Implement a separately advertised client/server binding with framing, trailers and chosen streaming support.
  - [x] Implementation and all required server/client integration complete.
  - [x] Independent validation, feature build, documentation and integrated commit recorded.
  - Selected native scope: binary protobuf cleartext HTTP/1.1 unary and server streaming with bounded frames, gzip, final status envelopes, metadata and exact-origin CORS. Shared gRPC descriptors/codecs retain typed semantics. Text/JSON message modes, client/bidi streaming, reflection, TLS/browser execution and pcap/fuzz claims are excluded; state is Experimental.
  - Evidence: coordinator **11 server + nine client checks**, **38 native gRPC neighbors** and **18 wire/converter/tonic checks** pass with independent Connect-ES 2.2.0 / protobuf-es 2.16.0 Node/Fetch transports. Admission, activity and timer guards survive the last status frame through explicit body EOF, error or drop; no TCP-flush ownership is claimed. Sources `4f9bf6c7`, `f5b859a8`, metadata correction `cb46779c`; feature `grpc-web`; reproduction in `tests/server/grpc_web/AGENTS.md` and `tests/client/grpc_web/AGENTS.md`.

- [x] **70. Prometheus remote write**.
  - Scope: Sender/receiver for a pinned version, protobuf/compression, validation and retry/error semantics.
  - [x] Implementation and all required server/client integration complete.
  - [x] Independent validation, feature build, documentation and integrated commit recorded.
  - Selected scope: published remote-write 1.0 float samples over HTTP/1.1 protobuf and Snappy block compression, signed millisecond timestamps and finite/special/stale values. Sender retries transport/5xx failures with bounded backoff while connected; 429 retry is opt-in. Receiver decisions are typed and use shared state only. No remote-write 2.0, metadata, histograms, exemplars, TLS, durable sender queue or full conformance claim; state is Experimental.
  - Evidence: coordinator **15 receiver + nine sender checks** pass at 100 threads with official Prometheus 3.15.0 sender and TSDB receiver/readback plus the pinned official Python prometheus-client 0.22.1 scrape fixture (the daemon owns remote-write encoding). Independent peers, NetGet pair, bounds, retries, rejection and parked-handler cancellation pass. The 10-second response-write bound begins after the handler completes. Source `7f6d77fd`, CI/capture `df5205c4`; feature `prometheus-remote-write`; reproduction in corresponding server/client test documents.

- [x] **71. NetFlow v9**.
  - Scope: Collector/exporter extension alongside IPFIX, distinct headers/templates and lifecycle.
  - [x] Implementation and all required server/client integration complete.
  - [x] Independent validation, feature build, documentation and integrated commit recorded.
  - Selected scope: native RFC3954 UDP v9 templates, options and typed data for 35 fixed-width fields and five scope kinds. Count tracks all records and sequence tracks export packets; source IP + SourceID owns the bounded transactional template cache. TTL/idle expiry and template refresh run in owned tasks. No IPFIX conflation, UDP acknowledgement, persistent flow store, enterprise/variable fields or full standard/pcap/fuzz claim; state is Experimental.
  - Evidence: coordinator **23 collector + seven exporter checks** pass at 100 threads with unmodified softflowd 1.1.1 in its upstream legacy build profile and official GoFlow2 2.2.7, including literal wire fixtures and the NetGet pair. Cache/count/sequence/padding/malformed input, typed scope handling, expiry/refresh and cancellation pass. Local send never claims remote collection. Source `6c83cd96`; feature `netflow-v9`; pinned bootstrap and reproduction in `tests/server/netflow_v9/AGENTS.md` and `tests/client/netflow_v9/AGENTS.md`.

- [x] **72. GraphQL subscriptions**.
  - Scope: Explicit subscription transport such as graphql-transport-ws; client/server lifecycle, typed execution and cancellation.
  - [x] Implementation and all required server/client integration complete.
  - [x] Independent validation, feature build, documentation and integrated commit recorded.
  - Validation: 4 subscription test functions pass alongside the 6 GraphQL ones (10 total). Unchanged gql 4.4.0's websockets transport (graphql-transport-ws) fetches the schema over the socket and runs a query, a completed countdown, a refused subscription and a `send_to_peer`-fed subscription it cancels; unchanged strawberry-graphql 0.330.2 serves the client a countdown with variables, an endless subscription the client cancels, and a refusal; lifecycle close codes 4400/4401/4408/4409/4429, peer-pushed events and the NetGet pair. gql must be configured with graphql-transport-ws only: it reads the agreed subprotocol case-sensitively and hyper writes lower-case header names. No SSE transport or legacy subscriptions-transport-ws; Experimental. Source `483c608a`.

## Integrated validation evidence

- **Batch 4 — 25 Fluent Forward, 26 GELF, 53 HTTP/3 server/client, 64 NSQ client:** published master merge `313ad42e` preserves the separate codebase audit `314c819a`. Final evidence totals **213 protocol test executions**: GELF 22, NSQ 55, HTTP/3 16 including cancellation/early-hints, Forward 24, NUT 20, DoQ 18, raw QUIC 17 and Beanstalkd 41. Initial combined runs passed; after the TE and peer-port corrections, all 16 HTTP/3 and 17 raw-QUIC checks passed again at 100 test threads. No failed or ignored cases in those final runs.
- Commands: `python3 /Users/matus/dev/netget/.protocol-expansion-20261001/run_cargo.py test --locked --offline --no-default-features --features tcp,nut,doq,gelf,beanstalkd,nsq,http3,quic,fluent-forward --test server --test client -- PROTOCOL:: --test-threads=4` for each named protocol. HTTP/3 final run additionally selects `--test http3_cancellation_test` with filter `http3` and `--test-threads=100`; raw QUIC reruns use `quic::` at 100 threads. Peer environments are specified in each protocol's test documentation and persistent `validate_batch4.py`.
- **Batch 5 — 55 SFTP, 65 Gearman, 28 InfluxDB writes, 57 Prometheus client:** all **143 protocol checks** pass at 100 test threads, zero failed/ignored. Gearman 47 and SSH/SFTP 30 were run with `tcp,gearman,ssh`; InfluxDB 28 and Prometheus 38 were run with `tcp,gearman,ssh,influxdb,prometheus`. Commands use the serialized guard: `test --locked --offline --no-default-features --features FEATURES --test server --test client -- PROTOCOL:: --test-threads=100`. Both shared feature combinations pass **129 checks across 31 targets**, correctness/suspicious/unused-must-use clippy and whole-package formatting. Persistent logs are `logs/batch5-*-initial.log` and `logs/batch5-*-collectors.log` under the owned programme source root. [Linux SFTP, InfluxDB and Prometheus jobs passed](https://github.com/netget-net/netget/actions/runs/37082508077). Gearman compiled its pinned peer, then its existing packet oracle failed for missing tshark; the CI dependency fix is included. No green full-CI claim.

- Batch 4 shared checks: **130 checks across 31 targets** pass after two targeted source-check corrections. The clean published baseline reproduced the unclassified HTTP URL validator; its deliberate rejection is recorded without rewriting requested URLs. The obsolete three-sleep HTTP/3 baseline was removed. Combined correctness/suspicious/unused-must-use lint, workflow YAML/shell syntax, test discovery and guarded whole-package formatting pass. All Cargo commands use the serialized disk guard. Logs: `/Users/matus/dev/netget/.protocol-expansion-20261001/logs/batch4-*.log`.
- The final HTTP/3 rerun exposed a fixture port reservation race before peer startup. `73292cbc` makes aioquic bind port zero itself and report its actual live socket; both affected suites pass at high concurrency. h3-quinn's pending-read cancellation panic is independently reproduced and corrected in the vendored adapter. The blocking pair workflow now includes HTTP/3, Forward, GELF and NSQ. [All six independent-pair jobs passed on Linux](https://github.com/netget-net/netget/actions/runs/37079410969). General CI on the checklist publication is still running; no full-CI green claim.


- Remote validation of `cf3f6a74`: [protocol pair run](https://github.com/netget-net/netget/actions/runs/37015942511) passed NUT/DoQ/StatsD and Graphite, then failed Beanstalkd 1.12 interoperability. [General CI](https://github.com/netget-net/netget/actions/runs/37015942450) found decision-tag, private-test discovery, peer-workflow evidence, silent failure declarations and Graphite validator declaration gaps. All four single-feature shards, browser build and blocking lint passed. Corrections are merged or in local verification; no claim of a green full CI run.

- Recovery on 2 October: temporary sources, logs and artifacts had been removed; committed implementations were restored from Git. Historical test counts below were recorded before cleanup. Original temporary log paths are no longer available. Previously uncommitted HTTP/3, GELF and NSQ work was reconstructed and signed; their final integration evidence is tracked below. Free space at recovery: approximately 148 GiB.

- **Batch 3 — 54 raw QUIC completion, 66 Gemini client:** all 48 protocol tests (16 QUIC, 32 Gemini) and 71 shared checks passed at merge `b7a2e7c6` with `tcp,nut,doq,statsd,graphite,beanstalkd,dict,quic,gemini`. Same test command shape and shared targets as Batch 2; logs in `/private/tmp/netget-protocol-expansion-20261001/validation-third/`. No failed or ignored cases. Raw QUIC review is closed; the independent peers and direct NetGet pairing agree. CI's `stream-pairs` job now includes Gemini/Agate/ignition and tshark.

- **Batch 2 — 24 Graphite, 63 Beanstalkd client, 67 DICT client; raw QUIC review in progress:** all 157 protocol tests passed with `tcp,nut,doq,statsd,graphite,beanstalkd,dict,quic` together at merge `08584d20`. This includes the first three protocols after the shared task-registration fix and 14 raw QUIC tests; its direct NetGet pairing review remains open. No failed or ignored tests in the final protocol runs.
- Batch 2 commands use the Batch 1 protocol command with that expanded feature set and each of `graphite`, `beanstalkd`, `dict`, `quic`, `nut`, `statsd`, `doq`. All 71 shared checks passed, adding `task_registration_cancellation_test`, `server_task_registry_test` and `client_stop_releases_socket_test` to Batch 1's targets. An obsolete QUIC server-only pairing assertion was updated to require the implemented client, then the shared checks passed.
- Lifecycle fix `7916e859`: a started child is owned before the registration future is first polled, and cancelled if registration is dropped. Both regression tests failed before the fix; successful registration/owner removal also remain covered.
- Batch 2 logs: `/private/tmp/netget-protocol-expansion-20261001/validation-second/`. CI's separate `stream-pairs` job installs Graphite, queue, dictionary and aioquic peers. The first remote run reproduced Beanstalkd 1.12 legacy statistics incompatibility; a focused correction is being validated. The eight-scope batch was merged to master and pushed as `cf3f6a74`.

- **Batch 1 — 01 DoQ, 06 NUT, 23 StatsD/DogStatsD:** all 53 protocol tests and 62 shared checks passed with `tcp,nut,doq,statsd` enabled together at merge `07339b83`; no ignored tests in this combined run. All three remain Experimental, with their selected scope and missing maturity evidence documented in their source/test `CLAUDE.md` files.
- Protocol command, once for each `PROTOCOL` in `nut`, `statsd`, `doq`: `cargo test --locked --offline --no-default-features --features tcp,nut,doq,statsd --test server --test client -- PROTOCOL:: --test-threads=4`. The programme runs Cargo through its serialized guard and provides the documented local peer paths.
- Shared checks: `event_action_declarations_test`, `advertised_actions_test`, `well_known_port_declaration_test`, `startup_param_defaults_test`, `startup_param_drift_test`, `protocol_startup_examples_test`, `dual_protocol_test`, `dashboard_wireshark_test`, `client_event_wiring_test`, `event_emit_sites_test` with the same feature set.
- Reproduction: `.github/workflows/protocol-pairs.yml` installs independent peers and runs these suites; each protocol's test documentation describes local setup. CI YAML and peer bootstrap were validated locally; the first remote NUT/DoQ/StatsD interoperability job passed on Linux. The eight-scope batch is published on master as `cf3f6a74`. Local detailed logs are in `/private/tmp/netget-protocol-expansion-20261001/validation/`.

- Documentation migration compatibility: both path and test-count checks discover `AGENTS.md` and legacy `CLAUDE.md`. Existing legacy citations resolve only when the migrated file actually exists; missing paths and stale foreign-path exemptions still fail. All four focused tests pass, including two new migration regressions. Workflow YAML and all 90 shell steps parse successfully.

- **Batch 6 — 27 Loki, 56 OTLP completion, 58 Docker client:** the merged `tcp,docker,loki,otlp,grpc,quic,gearman,http` build passes 104 new-scope checks (30 Loki, 40 OTLP, 34 Docker), plus 47 Gearman, 17 QUIC, five HTTP transport and three tonic boundary checks: **176 total**, zero failed/ignored in the final protocol runs. Command: `python3 /Users/matus/dev/netget/.protocol-expansion-20261001/run_cargo.py test --locked --offline --no-default-features --features tcp,docker,loki,otlp,grpc,quic,gearman,http --test server --test client -- PROTOCOL:: --test-threads=100`; the HTTP fixture uses `http::transport`, and the tonic boundary target is `vendored_tonic_patch_test`. Local peer environment is documented in each test directory and the owned batch scripts.
- All **132 shared checks across 31 targets** are green after 13 focused rerun checks corrected three initial audit failures: missing OTLP canonical catalogue membership, Loki's literal tenant default and two intentional control-rejection validators. The initial failure log is retained. `clippy --lib --bin netget` with correctness/suspicious/unused-must-use denied and whole-package formatting pass. Coordinator fixes `9008eb88`, CI gates `980e24c3`.
- Concrete CI fixture corrections: `29f76b09` streams the 8 MiB-plus-one HTTP response from an owned, bounded test peer instead of exceeding the shared static-action budget; `4735e4c0` owns concurrent QUIC streams and deliberately tests six-second model replies within the existing server deadline; `276d24e8` adds Gearman's GNU argument delimiter. Runtime limits remain intact. Previous Linux run `37084245867` passed eight pair jobs but failed the old Gearman/QUIC fixtures; general run `37084245909` passed its other blocking jobs but failed the old HTTP fixture. The corrected protocol-pair run `37089027868` passed all thirteen jobs. General run `37089027861` passed its other jobs but exposed the missing DoQ size declaration corrected in batch 7; full CI is not claimed green.
- Three new blocking jobs require independent Docker, Loki/Alloy and OTLP Collector/exporter peers. Workflow YAML and **101 shell steps** parse; the Linux Collector installer syntax and official release SHA256 match are verified (actual Linux bootstrap awaits CI). The OTLP Wireshark display filter parses; this is syntax evidence, not packet-capture maturity evidence. Logs: `.protocol-expansion-20261001/logs/batch6-*` and `tonic-*`. Free space after final validation is approximately 31 GiB; owned package cleanup previously reclaimed 10.6 GiB while retaining dependency caches, sources, peers and unrelated work.

- **Batch 7 — 29 IPFIX and shared credential diagnostics:** the merged `tcp,ipfix,grpc,etcd` build passes **28 IPFIX checks** (20 collector, eight exporter), **16 gRPC and 12 etcd neighbor checks**, and **104 credential/model/logging/scripting checks across 15 targets** at 100 test threads; zero failed/ignored. Native IPFIX UDP templates/options/data cover the documented typed 35-element IANA subset, bounded transactional caches, sequences/expiry, owned queue/task cancellation and local-send honesty. Unmodified Python ipfix 0.9.7 and the actual official GoFlow2 2.2.7 service validate both roles. It remains Experimental, with no complete RFC, reliable-delivery, TLS, flow-store, fuzz or pcap claim. Source `69eb9b8c`, readable loops `427a40d4`, terminal decisions `b90022ee`.
- All **134 shared checks across 32 targets** pass after **14 focused rerun checks** corrected the initial IPFIX decision-log/declaration gaps and rechecked the updated documentation. Initial three failures in two targets remain recorded. Required lib/bin clippy gates pass with `tcp,ipfix,grpc,etcd,doq`, including compilation of the corrected DoQ frame-size metadata; whole-package formatting passes. Shared privacy `20c60670` was merged while preserving request-owned breaker permits, bounded owned resident stderr and hyphen-sensitive key redaction. Actual action/wire values and explicit display actions remain unchanged; incidental credential-bearing model/script diagnostics are suppressed per invocation.
- Blocking CI `562bad0e` adds the IPFIX pair, its single-feature check, credential regressions and the inbound-size source ratchet. Both workflow files and **105 shell steps** parse. Official GoFlow2 release metadata confirms the pinned Linux/macOS asset hashes; local required peers pass, while the new Linux job awaits publication/run. IPFIX uses UDP/cflow capture guidance; tshark accepts decode-as/display syntax, which is not packet-capture maturity evidence. Reproduction uses the shared guard with the stated feature set and `--test server --test client -- ipfix:: --test-threads=100`, with peer bootstrap/environment documented under `tests/server/ipfix` and `tests/client/ipfix`. Logs: `.protocol-expansion-20261001/logs/batch7-*` and `agent-ipfix-decisions-*`.
- Disk maintenance reclaimed Cargo-reported **4.4 GiB of owned package outputs and 6.4 GiB of remaining compiled target outputs**, under the shared lock after package-only cleanup did not restore the 30 GiB start floor. Cargo download caches/registries, source, peers, logs, unrelated targets and processes were retained. Larger observed volume changes were not attributed to this cleanup. The final guarded format run started with approximately **33 GiB free**; all subsequent builds keep the same 30/25 GiB floor/stop policy.

- **Batch 8 — 30 sFlow, 59 Vault client and 68 generic gRPC streaming/reflection:** final independent protocol coverage is **99 checks**: sFlow 27, Vault 34 and gRPC 38; **105 privacy checks across 15 targets**, **12 etcd neighbor checks** and **ten converter/tonic checks** also pass. The initial shared run passed 140 of 141 checks across 33 targets; Vault correction `e5be0070` fixes the sole recursion-audit failure. All **141 final shared checks** pass, with **24 focused checks across five targets** rerun after that correction. Zero final failures or ignores. Required lib/bin clippy gates and whole-package formatting pass with `tcp,grpc,etcd,vault,sflow`; 93 advisory clippy warnings remain. Vault exact depth 32/+1, node 65536/+1, retained-content 8 MiB/+1 and 10000-level owned/injected values are verified before copying and during safe disposal.
- Shared followup `101e50d0` records only validated offered action names for credential-bearing client action diagnostics. Peer-control correction `5c1fb583` gives GELF/Graphite/Forward/NUT honest exchange-only reasons, reads sibling action metadata, recognizes both Hyper imports and shrinks the stale gRPC exemption after real stream controls adopted a handle. Capture/golden/silence integration `e384bf5a` includes sFlow and Vault. CI `cd924b23` adds three mandatory Linux peer jobs; both workflows and **116 shell steps** parse. The pinned Vault Linux release digest and 175150654-byte archive size were verified from official release metadata. The new Linux executions await publication.
- Reproduce through the shared guard with the stated feature set, `--test server --test client -- <grpc|vault|sflow>:: --test-threads=100`. Peer installation/environment and exact selected scopes live in the corresponding server/client test documents. Logs are retained under `.protocol-expansion-20261001/logs/batch8-*`, `item68-grpc-*` and `agent-*`. Initial source failure, the agent fixture-construction stack abort and one manager validation compile started before a module conflict was resolved are retained; that premature attempt ran no tests. Subsequent clean merged runs pass.
- Package-only maintenance under the shared lock removed a Cargo-reported **4.5 GiB** of programme-owned compiled outputs, leaving approximately **34 GiB free at that point**. Dependencies/download caches, source, peer fixtures, logs, unrelated targets and processes were retained. The final guarded format check started with **30.8 GiB free**; the same 30/25 GiB start/stop policy remains in force. Other observed volume changes were not attributed to this cleanup.

- **Batch 9 — 60 Nostr client, 69 gRPC-Web, 70 remote write and 71 native NetFlow v9:** coordinator evidence totals **183 protocol/neighbor checks**: remote write24, Nostr53, gRPC-Web20, native gRPC38 and wire/value/tonic18. All final results have zero failures or ignores. The initial shared run passed142 of145 checks across34 targets and exposed three gRPC-Web integration omissions; `cb46779c` corrects the named default timeout, truthful HTTP-carrier/no-port declaration and the documented intentional unread-response wait. The complete corrected run passes **145 shared checks across34 targets**. The HTTP-only example target is inactive in this feature bundle; no executed example test is claimed for that target.
- Final **all-target** clippy correctness/suspicious/unused-must-use gates and whole-package formatting pass with `tcp,prometheus-remote-write,vault,grpc,grpc-web,nostr,netflow-v9`; advisory warnings remain. Module reachability finds **2565 reachable source/test files, zero allowlisted**, all formatted. Both workflow files, **133 shell steps** and two native peer bootstrap ASTs parse. Required independent peer downloads are versioned, bounded and hash-verified; Linux executions await the next publication run. Capture carrier mappings and aliases are checked for HTTP/cflow; this mapping is not new protocol packet-capture maturity evidence.
- Reproduce using the shared guard and this feature bundle with `--test server --test client -- <grpc_web|grpc|nostr|netflow_v9>:: --test-threads=100`, the three gRPC wire/value/tonic targets and the34 shared targets recorded in owned logs. Remote write24 was validated first with `tcp,prometheus-remote-write,vault,grpc`; unchanged source retains that evidence. Peer environments are recorded in each protocol test document. Logs: `.protocol-expansion-20261001/logs/batch9-*`, `item69-*` and `agent-*`; initial source failures and invalid post-EOS stress attempts remain recorded separately from successful runs. The corrected report index was rebuilt from retained logs after a follow-up script overwrote its index; underlying logs were retained.
- Owned package-only maintenance under the shared lock reclaimed a Cargo-reported **2.0 GiB**, then **1.9 GiB** in separate measured cleanups. Download/dependency caches, peers, sources, logs, unrelated artifacts and processes were retained. Free space after final gates is approximately **40 GiB**. All builds retain the same30 GiB start floor and25 GiB stop reserve; observed unrelated volume changes are not attributed to cleanup.

- **Batch 10 — 07 TACACS+, 13 Connect RPC and 61 Bolt client:** final root evidence totals **206 protocol/neighbor checks**: Connect22, gRPC-Web20, native gRPC38, TACACS28 and Bolt98, all at 100 test threads. A separate **26 framing/converter/tonic checks** pass. All final results have zero failed or ignored cases. Independent peer versions, selected scopes and separate signed source changes are recorded on each item; all three new scopes remain Experimental.
- Final shared/privacy/startup controls additionally enable HTTP: **149 shared checks across35 active targets**, **148 privacy checks across20 active targets** and **45 startup/management checks across8 active targets** pass. These lists overlap; counts describe executions, not distinct tests. This activates the real HTTP-gated management/followup controls rather than counting cfg-disabled targets. Shared fixes `201c2a82`, `46d9dc11` and `495bb4e1` preflight constructed JSON before copies/drop and keep credential-bearing model/script diagnostics private while preserving typed values and the numeric retryable overload category.
- Initial integration failures are retained: omitted TACACS canonical names, Connect's incorrect compiled-out feature slug, a backpressure test that did not explicitly constrain peer buffering, invisible TACACS runtime event selection and Bolt's CI filter-list shape. Corrections add the actual Cargo-feature contract, move the same reply mapping beside its runtime caller and require nonzero unignored peer test counts in the three new jobs. Both HTTP bindings verify a successful multi-megabyte wire prefix and a constrained peer receive window before leaving output unread; the one-second RPC and actual 30/120-second connection limits remain intact. Full Connect and Web suites, including all long timer cases, pass after correction.
- Final all-target correctness/suspicious/unused-must-use clippy and whole-package formatting pass with `tcp,http,connect_rpc,grpc-web,tacacs,bolt`; advisory warnings remain. Module discovery finds **2603 reachable source/test files, zero allowlisted**, all formatted. Workflow validation parses24 mandatory jobs and91 shell run steps (192 total action/setup/run steps), plus the Neo4j bash/embedded-Python and TACACS installer syntax. New Linux peer jobs await publication; the earlier published21/21 and13/13 CI results apply to5192c107.
- Reproduction: `python3 /Users/matus/dev/netget/.protocol-expansion-20261001/run_cargo.py test --locked --offline --no-default-features --features tcp,connect_rpc,grpc-web,tacacs,bolt --test server --test client --no-fail-fast -- PROTOCOL:: --test-threads=100`, once per `connect_rpc`, `grpc_web`, `grpc`, `tacacs`, `bolt`, with owned native peer environments from `validate_batch10.py` and each test document. Shared/privacy/startup/lint runs use the additional `http` feature. Exact commands, versions and final log selection are retained in `logs/batch10-final-verified-results.json`; initial and diagnostic logs remain separate. Free space after final gates is approximately35GiB, with the unchanged30/25GiB build guard and one compiled target. No unrelated artifacts or processes were removed.

- **Batch 10 refresh against current master:** preserved published `88657066` in signed merge `ed66d10f`, including prompt/browser/final-action behavior, shared privacy fixtures and FTP/Bitcoin registry regressions. Complete independent role gates still pass **206 checks**, plus **26 framing/converter checks** and **19 bridge/prompt checks**. The newly required declaration audit exposed **147 repeated findings** in new action/event lists; signed correction `55f48f44` supplies explanatory Connect/TACACS/Bolt descriptions, canonical boolean hints and safe operation-specific logs. Its mandatory CI jobs now run the upstream declaration, startup-example and executable-example gates. The audit and baseline remain unchanged.
- The complete corrected refresh passes **188 shared checks across38 targets**, **148 privacy checks across20 targets** and **45 startup/management checks across8 targets**, with zero failures. One existing shared-audit diagnostic is intentionally ignored because it measures stale baseline entries only with `all-protocols`; protocol, framing, privacy, startup and bridge/prompt tests have zero ignores. These overlapping lists count executions. All-target correctness/suspicious/unused-must-use clippy and whole-package formatting pass. Module discovery finds **2604 reachable files, zero allowlisted**, all formatted; the24 mandatory jobs,91 shell run steps and192 total steps parse. Exact final commands/logs are retained in `logs/batch10-master-refresh-final-verified-results.json`; initial audit failure evidence remains separate. The pre-Programme3 prefix retains upstream's one-line STOMP citation repair to `AGENTS.md`, rather than discarding it. Approximately33GiB remains free; the30/25GiB guard and owned shared target remain in force.

## Implementation and independent peer plan

1. NUT: start with discovery/variables and supported authenticated operations. Test server with [upsc](https://networkupstools.org/docs/man/upsc.html), client with [upsd](https://networkupstools.org/docs/man/upsd.html) using synthetic UPS data.
2. DoQ: reuse DNS codec and quinn; test against [kdig](https://www.knot-dns.cz/docs/latest/html/man_kdig.html) and [AdGuard dnsproxy](https://github.com/AdguardTeam/dnsproxy).
3. StatsD/DogStatsD: typed parsing/emission and bounded batches; avoid an LLM invocation for every metric.
4. Socket.IO: evaluate [socketioxide](https://github.com/totodore/socketioxide) and [rust_socketio](https://github.com/1c3t3a/rust-socketio), test both sides against official JavaScript implementations.
5. GraphQL: evaluate [async-graphql dynamic schemas](https://github.com/async-graphql/async-graphql); let the library enforce execution while handlers supply data, with batching at the operation boundary.
6. NETCONF: SSH/XML layers and declared capabilities; [Netopeer2](https://github.com/CESNET/netopeer2) provides independent peers.
7. gNMI: use [official protobuf definitions](https://github.com/openconfig/gnmi/blob/master/proto/gnmi/gnmi.proto) and [gNMIc](https://github.com/openconfig/gnmic); streaming cannot reuse the unary-only generic server unchanged.
8. Redfish: DMTF schemas plus Gofish for server validation and [DMTF mockup server](https://github.com/DMTF/Redfish-Mockup-Server) for read-oriented client validation.
9. ACME: evaluate [instant-acme](https://github.com/djc/instant-acme) for the client and [Pebble](https://github.com/letsencrypt/pebble) as an external server.
10. AMQP 1.0: evaluate [fe2o3-amqp](https://github.com/minghuaw/fe2o3-amqp), which has acceptor support as well as client roles.
11. OPC UA: evaluate async-opcua but validate with an independent stack. BACnet and IEC104 have independent reference tools linked above. LwM2M has [Eclipse Leshan](https://github.com/eclipse-leshan/leshan).

Suggested scheduling order: bounded NUT/DoQ/StatsD work first; application Socket.IO/GraphQL and HTTP/3/SFTP/OTLP completion next; infrastructure NETCONF/gNMI/Redfish; then remaining messaging, identity, industrial and specialist families. All checklist entries remain in the authorized scope, regardless of research priority.

- **ICS completion (October 2026):** all six remaining scopes are registered in both roles. Local evidence: 27 focused protocol checks (six independent stacks), 147 shared checks across 36 targets, six standalone all-target builds and blocking all-target clippy; one pre-existing all-protocol-only audit is intentionally ignored in the narrower shared run. Browser/site and native release builds are separate publication gates; no full remote CI green claim.

## Peer-to-peer and news expansion (October 2026)

User-authorized extension of both DC++ hub and file-transfer scopes, NNTP and related peer protocols. New protocol features: `adc`, `dc_peer`, `adc_peer`, `soulseek`, `soulseek_peer`, `gnutella`; the existing `dc` and `nntp` features retain their names. The catalog now contains 240 features. All new roles remain Experimental and declare selected simulator scopes. `tests/peers/README.md` records pinned independent peers; each new source/test directory documents its scope.

- NMDC key authentication now preserves binary octets, escapes all reserved key values and rejects invalid challenges. Hub client framing is bounded.
- ADC/ADCS adds anonymous hub negotiation, handler-controlled identity/chat/search/results/rendezvous. Peer connectors can use a CID and hub token; listeners can advertise a handler-specified CID.
- NMDC and ADC peer roles add handler-supplied compressed XML file lists and binary downloads with ranges, refusal codes and optional whole-payload Tiger-tree verification. No autonomous download scheduler or filesystem content store is claimed.
- NNTP adds POST, IHAVE, sequential streaming feeds, verified implicit TLS and handler-approved AUTHINFO USER/PASS. No STARTTLS, SASL, compression or autonomous feed scheduler is claimed.
- Soulseek central and P-peer browsing roles add selected login/rooms/chat/status/addresses/search announcements and shared-directory/user-info operations. No Soulseek F-file-transfer channel, distributed tree, obfuscation or public central-service replacement is claimed.
- Gnutella adds a bounded 0.6 leaf-peer simulator with handshake, ping/pong, query/query-hit and push descriptors. No ultrapeer routing, public crawling, HTTP download service or push dialing is claimed.
- Existing BitTorrent tracker (`torrent-tracker`), DHT (`torrent-dht`) and peer (`torrent-peer`) role pairs remain in the catalog. Their existing Experimental metadata and limitations remain applicable; this expansion does not claim new third-party compatibility evidence for them.

- [x] All six new listening roles are implemented and registered.
- [x] All six new connecting roles are implemented and registered.
- [x] Independent exchanges, malformed/negative input and owner lifecycle checks pass. Local combined evidence: 80 server/client tests with no skips; final client event wiring: 26 passing; seven standalone all-target feature checks and blocking all-target clippy pass. Shared action/startup/event/task/site audits pass; the pre-existing all-features-only description report remains intentionally ignored in the narrow build. Existing BitTorrent review: 40 passing tests, one pre-existing ignored fixture. Static-bzip2 transfer checks also pass.
- [x] Source/test documentation and honest Experimental metadata are committed in `17a20aae`, integrated into master by signed merge `47e01748` (NMDC key fix `c7978e42` included).

Released [v0.3.3](https://github.com/netget-net/netget/releases/tag/v0.3.3). Focused Linux peer run [37700988948](https://github.com/netget-net/netget/actions/runs/37700988948) and the independent-peer gate in tagged release run [37702169346](https://github.com/netget-net/netget/actions/runs/37702169346) passed. The tagged release run completed successfully: all six native builds, archive/checksum validation, GitHub Release and NPM publication passed. The site is deployed at [netget.net](https://netget.net) with 240 distinct protocol links, asset prefix `v/1dc0239fb011` and completed CloudFront invalidation `I6XF3WJFNZ46I97PN72Z3WO0AT`. Desktop/mobile light/dark checks and browser smoke/NNTP checks pass; live JS, WASM and CSS bytes match the tested local assets. Native release builds bundle bzip2 statically. The peer workflow offers a focused `p2p-news` dispatch without launching unrelated protocol families.

Additional integration coverage: NMDC transfer listener/connector `nickname` can match hub rendezvous identities and rejects delimiter injection. The rebuilt 0.3.3 browser bundle passes general smoke tests and `web/test/nntp.mjs` posting/feed coverage in both roles.

Follow-up verification `392faa31` (signed master merge `48003fd1`) checks actual ncdc file downloads/uploads, whole-file TTH verification and partial ranges in both NMDC and ADC directions; all four independent checks pass locally. Broader CI found a missing CLI provider feature-list declaration, corrected in `7ddd316a` (signed master merge `f85475e6`); both manifest-derived provider audits pass and are now required by focused peer CI. The tagged distribution feature sets already enable that provider block, and shared TLS transports also initialize it before building configs. No full remote CI green claim is made.

Final publication evidence: all seven public `@smotana/netget` packages are at `0.3.3`, have provenance metadata and pin the six optional platform dependencies to that version. A clean main-package-only NPM installation selects the native `darwin-arm64` package and reports `netget 0.3.3`; its documentation dump contains both roles for all six new features plus DC and NNTP. The fresh focused Linux run [37703669196](https://github.com/netget-net/netget/actions/runs/37703669196), including actual file contents/ranges/TTH and the provider audit, passed. All 13 blocking jobs in broader CI run [37703663382](https://github.com/netget-net/netget/actions/runs/37703663382) passed; its separate registry-wide advisory audit was still running at this verification, so no complete broad-workflow conclusion is claimed.
