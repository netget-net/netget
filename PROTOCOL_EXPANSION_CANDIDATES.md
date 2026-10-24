# NetGet — protocol expansion candidates (October 2026)

A survey of protocols **not yet in the tree** that fit NetGet's model (Rust owns
framing/crypto/IDs/bounds; the LLM/script/static/manual handler decides what to say),
plus the handful of existing protocols that have only one of the two roles.

The hard filter throughout is NetGet's own maturity rule: **an independent third-party
peer must exist** (a binary or a crate that is not the one NetGet frames with), or the
protocol is permanently Experimental. Every entry below names its candidate Rust library
and its independent peer, because that pair is what decides whether the item can ever
leave Experimental. Library/peer notes were spot-checked against crates.io/docs.rs in
October 2026; re-verify maintenance status before adopting.

Status of the catalogue as of this survey: **194 server registrations, 87 client
registrations**; Programme 3's 72 items are all complete. This document is the *next*
pool, not a commitment.

## Implementation status (12 October 2026)

**Everything in Tier A and Tier B, every missing role with a usable peer, and every listed
extension has landed on `master`**, each as a server+client pair tested against the
independent peer named below (the pair jobs in `.github/workflows/protocol-pairs.yml` run
them and fail rather than skip when the peer is absent). Verified against `master` by
checking `src/server/<p>/` and `src/client/<p>/` and the Cargo feature for each item, not
against a memory of having done it.

| Batch | Landed in | Items |
|---|---|---|
| Tier A (all 12) and the first Tier B pairs | #164 (`3cf5db8e`) | ClickHouse, ZeroMQ, 9P (`ninep`), LMTP, LPD, inetd services (`inetd`), RCON + A2S + Minecraft SLP, SMPP, Cap'n Proto RPC, MessagePack-RPC, Zipkin, NATS JetStream; KNX/IP, D-Bus, X11 client, BFD, VXLAN + Geneve, WS-Discovery, Consul, Milter, Anthropic Messages API, PFCP, rsync (downloads), RadSec, Matrix |
| Remaining Tier B | #181–#187 (`66eb3c27`, `04999aca`) | libp2p, SunRPC/portmap, Guacamole, ActivityPub + WebFinger, Stratum V1, Pulsar, TR-069 (CWMP) |
| Missing roles | #188, #189–#195 (`04999aca`, `56c64b04`), #209 (`de365f09`) | Zabbix client, RTP / RTSP / HLS clients, RDP client |
| Extensions | #189–#195, #196–#201 (`b7657a5f`), #202–#211 (`de365f09`) | Redis RESP3, SNMP traps/informs, SNMPv3 USM, HTTP SSE, MQTT 5.0, QUIC DATAGRAM, WebSocket permessage-deflate, CoAP Observe + Block-wise, DNS TCP/EDNS0/AXFR/IXFR/DNSSEC, InfluxQL/Flux queries, Kafka flexible versions, gRPC client-streaming/bidi evidence (grpcurl), rsync uploads |

The mercurial and svn clients listed under "missing roles" below already existed when
this survey was written (they landed 4 October 2026); the survey was wrong about them.

### Not implemented

What is left from this document, with the reason each is still open:

- **Partial slices of shipped items:**
  - ~~**GRE**~~: landed 14 October 2026 as the `vxlan` feature's `gretap` encapsulation
    (Ethernet over GRE in UDP, RFC 8086, port 4754), tested against the Linux kernel's
    gretap-over-fou driver. **GRE directly on IP protocol 47 landed 24 October 2026** as its
    own `gre` protocol (server and client, Unix, `RawSockets`, so vxlan stays unprivileged),
    sharing vxlan's GRE codec (`src/utils/gre.rs`): gretap (0x6558) and L3 gre (0x0800)
    payloads, key/checksum/sequence copied per RFC 2784/2890, Cisco keepalives reflected,
    a peer allowlist, key filter, size and rate bounds. Tested against the Linux kernel's
    `ip_gre` (gre and gretap links in a namespace: ping, ARP, UDP both ways) and scapy as a
    second implementation, with tshark 4.2.2 reading both directions. Not built: IPv6,
    PPTP's enhanced GRE, WCCP/ERSPAN, inner fragmentation; macOS has never run it as root.
  - ~~**ONVIF**~~: landed 14 October 2026 as the `onvif` pair — device service
    (GetSystemDateAndTime, GetDeviceInformation, GetCapabilities, GetServices, GetScopes,
    GetNetworkInterfaces) and media ver10 (GetProfiles, GetVideoSources, GetStreamUri,
    GetSnapshotUri) with WS-Security UsernameToken digest, against onvif-zeep-async and
    use-go/onvif (server) and RPOS (client). **PTZ, Events, Media2, Imaging and the Device
    Set\* operations landed 23 October 2026** in both roles: PTZ moves and presets (the model
    decides each move; status and presets answered from device state), pull-point Events
    (bounded subscriptions and queues, long-polled PullMessages, model-raised `tns1:`
    notifications), Media2 from the same description as Media ver10, Imaging settings and
    focus moves, and SetSystemDateAndTime/Scopes/Hostname/SystemReboot as model decisions.
    Server peers: onvif-zeep-async and use-go/onvif for PTZ, Events, Imaging and Set\*;
    onvif2-zeep and IOTechSystems/onvif for Media2. Client peers: RPOS (PTZ, Imaging) and
    onvif_simple_server (Media2, Events). Still not built: Recording, Replay and Search,
    Basic Notification (device-initiated callbacks), PTZ home-position setting and tours,
    Imaging exposure/white-balance/WDR/backlight, Media2 configuration changes.
  - ~~**Stratum V2**~~: landed 14 October 2026 as the `stratum-v2` pair (Mining Protocol,
    standard and extended channels, Noise NX with the SV2 certificate), hand-rolled from
    sv2-spec so that SRI's `mining_device` and `pool_sv2` (over Bitcoin Core regtest) are
    independent peers. **The Template Distribution and Job Declaration protocols landed 23
    October 2026**, as `role` startup parameters on the same protocol: a Template Provider
    (the model writes each template; Rust builds the merkle path, witness commitment and
    BIP 34 height and verifies SubmitSolution against the target) tested by SRI's pool and
    mining_device with Bitcoin Core's `submitblock` accepting the assembled block; a Job
    Declarator Server (the model allocates tokens and accepts or refuses declared jobs;
    bounded token table and mempool) tested by SRI's jd_client; a Job Declarator Client
    against SRI's JDS, which validates with Bitcoin Core's `checkBlock`; and a Template
    Distribution client against sv2-tp 1.1.2, Bitcoin Core's tip becoming NetGet's block.
    **Work selection landed 23 October 2026**: a `pool_and_job_declarator` role takes
    SetCustomMiningJob against its own JDS's tokens, checked byte for byte against the
    declaration (and against a node's tip and nbits when `bitcoin_rpc_url` is set), and every
    server role relays the blocks it verifies with `submitblock`. SRI's jd_client, with sv2-tp
    and SRI's mining_device, drives a block end to end through NetGet's pool and JDS, and
    Bitcoin Core's chain holds it. Still not built: sigop checks (no UTXO set), chain checks
    without a configured node, a NetGet JDC that opens a mining channel for its own jobs.
  - ~~**IPFS above libp2p**~~: landed 14 October 2026 on the `libp2p` feature behind an
    `ipfs` startup parameter — Bitswap 1.0–1.2, CIDv0/v1 with `raw` and `dag-pb`, single-block
    UnixFS files, and the Kademlia DHT (FIND_NODE answered in Rust, GET_PROVIDERS and
    ADD_PROVIDER by the model) — with Kubo 0.43.1 fetching from NetGet and serving to it.
    **Multi-block files, directories, remembered wants, whole-DAG fetch and IPNS landed 23
    October 2026**: the model describes files and trees (`described_disk` vocabulary) and
    Rust chunks them as Kubo does, with every root CID equal to `ipfs add --only-hash` (85
    roots across seven profiles) and to Helia's importer 17.1.1 (38 roots three ways); the
    client fetches whole DAGs from Kubo with every block's hash checked; per-peer wantlists
    are remembered and answered when content arrives; IPNS records (Ed25519 signatureV2,
    sequence, validity) and provider records are kept in Rust. Helia 7.1.16 is the second
    independent implementation. Still not built: HAMT-sharded directories, rabin/buzhash
    chunkers and the trickle layout, multi-peer sessions, a full Kademlia node of the
    host's own, signed peer records.
  - ~~**NGAP/N2**~~: landed 15 October 2026 as the `ngap` pair (AMF and gNB over real
    SCTP, PPID 60, with a labelled lab-TCP transport for hosts without SCTP): NG Setup,
    Initial UE Message, Downlink/Uplink NAS Transport, and pre-security 5GMM, hand-written
    APER checked by tshark's `ngap` dissector, against UERANSIM's nr-gnb/nr-ue and Open5GS's
    AMF. **NAS security and PDU sessions landed 23 October 2026** in both roles: 5G-AKA
    (Milenage, RES*/XRES*, the TS 33.501 key hierarchy, SQN resynchronisation), SUCI null
    scheme and ECIES Profiles A and B, Security Mode with NIA2/NEA2/NEA0, NAS COUNT and
    replay checks, Registration Accept with the model's allowed NSSAI, PDU Session
    Establishment with the model deciding admission, DNN, S-NSSAI and the UE's address, and
    a GTP-U endpoint answering ICMP echo for the addresses the model chose. Subscriber keys
    are redacted startup parameters the model never sees. A real UERANSIM UE registers, gets
    a PDU session and pings through the tunnel; NetGet's gNB/UE registers with a full
    Open5GS 2.8 core (NRF, AUSF, UDM, UDR, PCF, SMF, UPF, AMF, MongoDB) and gets a PDU
    session, with Open5GS's K_gNB matching NetGet's. The gNB client is Beta. Still not
    built: NIA1/NEA1 and NIA3/NEA3, EAP-AKA', handover, paging, Service Request under
    security, PDU session release and modification, IPv6 sessions, multiple QoS flows,
    routed user plane (N6), and a gNB user plane.
  - ~~**Redis cluster and pub/sub depth**~~: landed 15 October 2026 on the `redis` server
    and client — pub/sub (channels, patterns, shard channels, RESP2 subscribed mode and RESP3
    pushes, model-initiated publish, bounded fan-out with a slow-subscriber limit) and cluster
    mode (CRC16 hash slots, `CLUSTER SLOTS/SHARDS/NODES`, MOVED/ASK/CROSSSLOT on the server; a
    slot-routing client following MOVED and ASK), against redis-cli, redis-rs and a real
    three-node cluster. No cluster bus, replicas, keyspace notifications or `CLIENT TRACKING`.
- **Peer-limited missing clients**: none left.
  ~~yarn~~ landed 15 October 2026 at Beta (the ResourceManager REST API: cluster info and
  metrics, the scheduler's queue tree, applications with filters, attempts, state and queue,
  nodes; `kill_application` only with `allow_kill`), against a real Apache Hadoop 3.5.0
  ResourceManager and NodeManager running distributed-shell applications; the same pass drove
  the YARN server with Datadog's YARN check and served the scheduler endpoint it needs.
  Submission is deliberately not built: its body is a shell command run on a cluster node.
  ~~spark~~ landed 15 October 2026 at Beta (the monitoring REST API: applications, jobs,
  stages with attempts and task summaries, executors, environment, SQL executions), against
  a real Apache Spark 4.2.0's live driver UI and History Server; the same pass drove the Spark
  server with Datadog's Spark check and fixed the two defects it exposed. The REST submission
  API is deliberately not built: it runs arbitrary code on a cluster.
  ~~snowflake~~ landed 15 October 2026 (connector REST protocol: password login, queries
  with JSON and Arrow rowsets decoded by column type, token renewal, result polling,
  logout; the target is mandatory and never derived) against fakesnow and
  snowflake-emulator; the same pass drove the Snowflake server with the official
  snowflake-connector-python for the first time and fixed the three defects it exposed.
  ~~db2~~ landed 15 October 2026 (EXCSAT/ACCSEC/SECCHK/ACCRDB, EXCSQLIMM, PRPSQLSTT +
  OPNQRY/CNTQRY with typed rows, commit/rollback) against Apache Derby's DRDA server; the
  same pass drove the Db2 server with Derby's JDBC driver and IBM's `ibm_db` for the first
  time and fixed the seven defects they exposed. IBM Db2 Community as a second peer is not
  done (linux/amd64-only image, privileged container).
  ~~gtp~~ landed 15 October 2026 (S5/S11 GTPv2 and Gn GTPv1, control and user plane),
  against wmnsk/go-gtp and osmo-ggsn with the kernel tun, under tshark's `gtpv2`/`gtp`
  dissectors.
- **Tier C**: every row has landed except **PCoIP**, which has no published wire
  specification and no open implementation to test against (see its row). Each landed row
  says what of its protocol is not built.
- **Storage additions**: iSCSI, NVMe over TCP, FUSE and HDFS have all landed (see that
  section).
- **Maturity**: almost everything above landed at `Experimental` or `Beta`. The client
  promotions that came with it are Kafka, DNS and RDP (Beta). None of these items has
  been taken through the six Stable conditions in `AGENTS.md`.

### Follow-up queue (approved 23 October 2026)

Taken one at a time, each covering what its protocol's own "not built" or "not tested" list
says. Strike an item when it lands.

1. ~~Stratum V2: SetCustomMiningJob in NetGet's pool, so SRI's jd_client drives PushSolution end to end.~~ Landed 23 October 2026.
2. ~~IPFS: multi-block DAGs and Bitswap sessions.~~ Landed 23 October 2026.
3. ~~GRE directly on IP protocol 47.~~ Landed 24 October 2026.
4. ~~Zigbee: TI Z-Stack MT dialect; EZSP 13 and older.~~ Landed 24 October 2026.
5. ~~HDFS: append, truncate, concat; tests for the fixed deadlines.~~ Landed 24 October 2026.
6. ~~The flaky telnet batching test and the startup-sweep hang.~~ Landed 24 October 2026: the telnet test's premise was wrong (it took the connect event's model call for the slow call) and is now deterministic, with a new test that a line still in the kernel buffer joins the batch; the sweep names a stuck protocol, aborts hung starts and has an overall deadline; two real defects found on the way, the stdio server holding the process open on an open stdin pipe and ActivityPub's unoptimised RSA keygen timing out under load, are fixed. What hung the 24 October run is not established.
6a. The same `call_count() == 0` premise and a fixed 200 ms gap in `tests/server/rcon/batching_test.rs` and `tests/server/pty/batching_test.rs`; the TCP server spawning a handler task per read, which could reorder back-to-back reads.
7. NGAP: PDU session release and modification, Service Request, paging, IPv6 sessions, NIA1/NEA1 and NIA3/NEA3.
8. ONVIF: Recording, Replay, Search; Basic Notification.
9. NVMe/TCP: DH-HMAC-CHAP, TLS, reservations, Compare/Verify/Copy.
10. iSCSI: error recovery levels 1 and 2, multiple connections per session, the remaining task management functions.
11. FUSE: hard links, extended attributes, fallocate. macOS needs macFUSE or FUSE-T installed, which waits on the maintainer.

PCoIP stays unbuilt: no published wire specification and no open implementation to test against.

Priority: **A** strongest general fit · **B** useful follow-on · **C** workload-specific.
Effort **S/M/L** covers both roles plus interoperability tests.

---

## Tier A — strong fit, real peer, reasonable effort (recommend first)

| # | Protocol | Transport | Rust lib | Independent peer | Pri/Eff | Note |
|---|---|---|---|---|---|---|
| 1 | **ClickHouse native TCP** | TCP 9000 | `opensrv-clickhouse` | `clickhouse-client` CLI | A/M | Mirrors `opensrv-mysql`, already a dep. The official `clickhouse` crate is HTTP/RowBinary, so NetGet's native server is distinct. Strongest DB gap. |
| 2 | **ZeroMQ / ZMTP 3.1** | TCP | `zeromq` (zmq.rs, supports `bind`) | libzmq via `pyzmq`, `zmq` CLI | A/M | REQ/REP, PUB/SUB, DEALER/ROUTER. Big messaging gap next to NATS/AMQP/MQTT. |
| 3 | **9P (9P2000.L)** | TCP / Unix | `rs9p` (tokio, async) | Linux `v9fs` mount, QEMU, `py9p` | A/M | Clean async VFS server; peer is the kernel. Rounds out the file family (SMB/NFS/FTP/WebDAV). |
| 4 | **LMTP (RFC 2033)** | TCP 24 | reuse SMTP stack | Postfix/Dovecot LMTP | A/S | Near-free given the SMTP server. Finishes the mail-delivery set. |
| 5 | **LPD (RFC 1179)** | TCP 515 | hand-rolled (trivial) | CUPS `lpd`, `lpr` | A/S | Print family companion to IPP. |
| 6 | **Classic inetd services** | TCP+UDP 7/9/13/17/19/37 | hand-rolled | `nc`, systemd/inetd socket units | A/S | Echo, Discard, Daytime, QOTD, Chargen, Time. One feature, trivial, excellent demo/test fixtures and a UDP-echo oracle. |
| 7 | **RCON + A2S + Minecraft SLP** | TCP (RCON) / UDP (A2S/SLP) | `rcon`, `a2s` (client side); hand-rolled server | `mcrcon`/`rcon-cli`, `gamedig`/`mcstatus` | A/S | Game-server family. Easy, self-contained, strong demo value. |
| 8 | **SMPP v5** | TCP 2775 | `rusmpp` (client+server, low-level) | SMPPSim, `jsmpp` | A/M | SMS/telecom; mature typed library. |
| 9 | **Cap'n Proto RPC** | TCP | `capnp-rpc` | C++ `capnp`, `pycapnp` | B/M | RPC family next to gRPC/Thrift/Connect. |
| 10 | **MessagePack-RPC** | TCP | `rmp-rpc` | **Neovim `nvim --embed`**, node/python msgpack-rpc | B/M | Free high-quality peer: Neovim speaks it natively. |
| 11 | **Zipkin span ingest** | HTTP+JSON | hand-rolled | Zipkin server, OTel exporter | B/S | Observability companion to OTLP/Prometheus/Loki. |
| 12 | **NATS JetStream** | TCP (extend `nats`) | extend existing | `nats-server` (already a build dep) | B/M | Extension of the shipped NATS core; peer is already installed. |

## Tier B — good fit, peer available, more effort or platform-bound

| Protocol | Transport | Rust lib | Independent peer | Pri/Eff | Note |
|---|---|---|---|---|---|
| **KNX/IP** | UDP 3671 | `knust` (tunnel+routing+secure) | `knxd`, Calimero | B/M | Building automation; UDP, testable without hardware. |
| **D-Bus** | Unix (Linux) | `zbus` (pure Rust) | `dbus-daemon` + `busctl`/`gdbus` | B/M | Serve a bus name on the session/system bus. Linux-only, like the BLE/CAN items. |
| **X11 client** | TCP/Unix 6000 | `x11rb` (client bindings) | `Xvfb`/`Xorg` | B/M | Client only — a server is a large build. Xvfb is a trivial CI peer. |
| **BFD (RFC 5880)** | UDP 3784 | hand-rolled | FRR `bfdd`, BIRD | B/M | Routing family (BGP/OSPF/ISIS/RIP neighbours). |
| **VXLAN / Geneve / GRE** | UDP 4789 / IP | hand-rolled | Linux `ip link` (kernel native) | B/M | Overlay/L2, extends the Tier-1 impersonation work; kernel is the peer. |
| **WS-Discovery + ONVIF** | UDP mcast + HTTP/SOAP | `quick-xml` | `python-ws-discovery`, real IP cameras | B/M | Discovery family (SSDP/mDNS/LLMNR). |
| **Consul** | HTTP + DNS | `consul`/community | `consul agent` | B/M | KV + catalog + health; DNS half reuses the DNS server. Client maturity limited by the generic-HTTP rule. |
| **Matrix client-server API** | HTTP+JSON | `ruma` (types) | Conduit/conduwuit (Rust), Synapse, `matrix-nio` | B/L | High value, large surface; real Rust and Python peers exist. |
| **Milter** | TCP | hand-rolled | Postfix/Sendmail driving the filter, `pymilter` | B/M | Mail-filter server; MTA is the peer. |
| **Apache Guacamole protocol** | TCP/WebSocket | hand-rolled text protocol | `guacd` | B/M | Remote-access family; guacd is a clean peer. |
| **Stratum V1 / V2** | TCP | `stratum` (V1), SRI `*_sv2` (V2) | `cpuminer`, SRI | B/M | Mining/blockchain next to Bitcoin/Nostr. |
| **Anthropic Messages API** | HTTP | hand-rolled (like `openai`) | official Anthropic SDKs | B/S | AI companion to `openai`/`ollama`/`mcp`; trivial given the OpenAI server. |
| **PFCP (5G core)** | UDP 8805 | hand-rolled | Open5GS, free5GC | C/L | Telecom; UDP so testable. NGAP/N2 needs SCTP (Linux CI only). |
| **ActivityPub + WebFinger** | HTTP+JSON-LD + HTTP sigs | `activitystreams` | Mastodon, `mastodon.py` | B/L | Fediverse; HTTP-signatures are the real protocol work. |
| **IPFS / libp2p** | TCP/QUIC + noise/yamux | `rust-libp2p` (excellent) | Kubo (go-ipfs) | B/L | Large but first-class Rust stack and a strong peer. |
| **rsync protocol** | TCP 873 | hand-rolled | `rsync` | B/L | Delta-transfer algorithm is the heavy part. |
| **SunRPC / portmap** | TCP/UDP 111 | `onc-rpc`-ish | `rpcbind`/`rpcinfo` | B/M | Infra under NFS; could expose standalone. |
| **Apache Pulsar** | TCP (protobuf-framed) | `pulsar` (apache) | Pulsar standalone | C/L | Messaging. |
| **TR-069 / CWMP** | HTTP+SOAP | `quick-xml` | GenieACS | C/M | CPE management. |
| **RadSec** | TLS 2083 | extend `radius` | FreeRADIUS | B/S | RADIUS over TLS; extends shipped RADIUS. |

## Tier C — defer (recorded so they are not re-litigated)

| Protocol | Why deferred |
|---|---|
| ~~**Kerberos KDC**~~ | **Landed 15 October 2026** as the `kerberos` pair: AS and TGS over UDP and TCP with PA-ENC-TIMESTAMP, aes256/aes128-cts-hmac-sha1-96, the model deciding admission, errors, lifetimes and flags under Rust-enforced ceilings, failing closed with KRB_ERR_GENERIC. Against MIT krb5 and Heimdal (kinit, klist, kvno, kgetcred; krb5kdc and kdc) under tshark's `kerberos` dissector. Not built: RFC 8009, FAST, PKINIT, PAC, cross-realm, renewal, S4U, kpasswd. |
| ~~**SPICE**~~ / **PCoIP** | **SPICE landed 15 October 2026** as the `spice` pair: link handshake with an RSA-OAEP ticket checked in Rust, main, display and inputs channels, the model drawing the screen with VNC's command vocabulary and answering key and mouse input; against spice-gtk (`spicy`, `spicy-screenshot`) and spice-html5 (server) and QEMU's spice-server (client), under tshark's `spice` dissector. Not built: TLS, SASL, cursor, audio, agent, USB, image decompression, video streams. **PCoIP is not buildable honestly**: Teradici/HP Anyware's proprietary protocol has no published wire specification and no open-source implementation, and every usable peer is a licensed proprietary binary. |
| ~~**Ethereum devp2p / RLPx**~~ | **Landed 16 October 2026** as the `devp2p` pair: RLPx (EIP-8 ECIES handshake, MAC-checked AES-CTR frames, snappy), the base protocol and eth/68–69 (Status with EIP-2124 fork id, headers, bodies, pooled transactions), with Rust encoding and hashing every header the model supplies; against go-ethereum (geth, which verifies a required block fetched from NetGet, and its `devp2p` tool) and reth, on loopback with discovery off. Not built: discv4/v5 discovery, `snap`, body-to-header trie verification, a fuzz target. |
| ~~**SS7 / SCCP / MAP / CAMEL**~~ / **H.323** | **SS7 landed 16 October 2026** on the `m3ua` feature: SCCP UDT/XUDT, ITU TCAP dialogues, MAP (SRI-SM, SRI, ATI, USSD, MO/MT-forwardSM, updateLocation) and CAP v2–4 (initialDP and its answers) above the M3UA SGP, plus an M3UA ASP client, hand-rolled bounded BER, against Restcomm jSS7 and osmo-stp over real SCTP under tshark's `m3ua`/`sccp`/`tcap`/`gsm_map`/`camel` dissectors. Not built: sendAuthenticationInfo (the model would invent key material), insertSubscriberData, SCCP segmentation and GTT, ANSI TCAP. **H.323 landed 16 October 2026** as the `h323` pair: an H.225.0 RAS gatekeeper (GRQ, RRQ, ARQ, LRQ decided by the model), a call-signalling endpoint with fastStart G.711 and tunnelled H.245, and a client that registers, asks admission and places calls; ALIGNED PER interpreted from tables generated from the ITU ASN.1 modules, with an `h323_per` fuzz target; against GNU Gatekeeper, H323Plus `simph323` and Asterisk's ooh323 under tshark's `h225`/`h245`/`q931` dissectors. Not built: H.235 security, gatekeeper-routed calls, a separate H.245 channel, codecs other than G.711, media sending, H.450. |
| ~~**OpenFlow**~~ | **Landed 16 October 2026** as the `openflow` pair: a hand-written OpenFlow 1.3 codec (HELLO bitmap negotiation, FEATURES, multipart, OXM matches, instructions, actions, PACKET_IN/OUT, FLOW_MOD) with the controller's model deciding policy and failing closed (no flood, no flow), and a switch client with a bounded flow table; against Open vSwitch (controller role) and os-ken and ovs-testcontroller (switch role) under tshark's `openflow_v4` dissector, plus an `openflow_message` fuzz target. Not built: OpenFlow 1.0–1.2, TLS, group/meter/table/port modification, a data plane in the switch. |
| ~~**Profinet / EtherCAT**~~ | **PROFINET IO landed 16 October 2026** as the `profinet` pair (device and controller): DCP Identify/Get/Set, PNIO-CM over DCE/RPC on UDP 34964 (Connect, Control, Release, Read/Write, I&M0–3) and RT_CLASS_1 cyclic IO with IOPS/IOCS, over raw Ethernet (`pnet` datalink, CAP_NET_RAW) or a labelled UDP lab transport, failing closed with IOPS BAD and refused connects; against profinet-py and pnio_dcp (device role) and rt-labs p-net (controller role) on a veth, under tshark's `pn_dcp`/`pn_io`/`pn_rt` dissectors, plus a `profinet_frame` fuzz target. Not built: alarms, RT_CLASS_2/3, MRP, multicast CRs, GSDML import, more than one AR on the controller. **EtherCAT landed 16 October 2026** as the `ethercat` pair: an emulated slave (ESC registers, SII, working counters, SyncManagers, FMMUs, the AL state machine, CoE SDO) whose model decides state changes, objects and inputs and refuses SAFE-OP until inputs are set, and a master that scans, configures, walks slaves to OP and runs cyclic LRW; over raw Ethernet (PROFINET's packet socket) or the standard EtherCAT-in-UDP encapsulation; against SOEM and ethercrab (slave role) and KickCAT's emulated CiA 402 drive (master role) under tshark's `ecat` dissectors, plus an `ethercat_frame` fuzz target. Not built: distributed clocks, FoE/EoE/SoE/AoE, PDO remapping, redundancy, ENI files. |
| ~~**M-Bus**~~ | **Landed 16 October 2026** as the `mbus` pair over M-Bus/IP (TCP): a gateway with model-described meters (E5, short/control/long frames, primary and secondary addressing with wildcard search and collisions, FCB, DIF/VIF records encoded exactly from structured values, failing closed with an application-error status and no records) and a master that scans, searches and reads; against libmbus and pyMeterBus (gateway role) and pyMbusSlave and Addiva's mbus-device replaying real-meter captures (master role), plus an `mbus_frame` fuzz target. tshark has no wired M-Bus dissector, so there is no pcap oracle. Not built: wireless M-Bus, serial ports, encryption, CI 0x73 fixed data, alarms. |
| ~~**AFP, NIS/YP, rsh/rlogin/rexec**~~ | Obsolete; low value, insecure legacy — built anyway on request. **AFP landed 17 October 2026** as the `afp` pair: AFP 3.x over DSI (TCP 548), No User Authent and Cleartxt Passwrd checked in Rust, volumes, listings, file contents and writes decided by the model and failing closed with kFPMiscErr; against netatalk 4.6.1's `afparg` and Nmap's AFP scripts (server role) and netatalk's `afpd` (client role) under tshark's `dsi`/`afp` dissectors, plus an `afp_dsi` fuzz target. Not built: DHX/DHX2/Kerberos UAMs, rename/copy/locks, the desktop database, resource-fork contents. **NIS/YP landed 17 October 2026** as the `nis` pair on NetGet's own ONC RPC code: ypserv (program 100004 v2, TCP and UDP, every procedure but XFR, optional portmapper registration) with the model deciding domains and map contents that Rust renders into canonical passwd/group/hosts/netgroup lines and refuses to let a field forge another, failing closed with YP_YPERR; and a client that binds and reads maps; against yp-tools and ypbind-mt (server role) and ypserv through rpcbind (client role) under tshark, plus a `nis_yp` fuzz target. NIS has no authentication or confidentiality, and the docs say so. Not built: yppasswdd, XFR/yppush, the ypbind protocol. **rsh, rlogin and rexec landed 17 October 2026** as one `rsh` module registering three servers and three clients: the NUL-field handshakes, the status byte, the stderr back-connection (only to the client's own address), rlogin's window-size control and reserved-port reporting in Rust; rexec passwords checked in Rust, rsh trust and rlogin sessions decided by the model, failing closed with `\1` and never trusting on failure; against inetutils and rsh-redone (clients and daemons) under tshark's `rsh`/`rlogin`/`exec` dissectors, plus an `rsh_handshake` fuzz target. Cleartext passwords and address trust are stated in the metadata. Not built: a second rexec client family, stdin on rsh/rexec, a pty for rlogin. |
| ~~**Zigbee**~~ / ~~**LoRaWAN**~~ radio | **LoRaWAN landed 17 October 2026** as the `lorawan` pair over the Semtech UDP packet forwarder (v1/v2, UDP 1700): a network server and a gateway client with LoRaWAN 1.0.x MAC in Rust (AES-CMAC MICs, Join Accept encryption, session keys, 32-bit frame counters, EU868 RX1/RX2), the model deciding joins and application payloads and failing closed by sending nothing; against LWN Simulator (server role) and ChirpStack v4 with its Gateway Bridge (client role), with tshark's `lorawan` dissector verifying every MIC from LoRaTap captures, plus a fuzz target. Not built: LoRaWAN 1.1, classes B/C, ADR, regions other than EU868, Basic Station. **Zigbee landed 21 October 2026** as the `zigbee` server: NetGet as a Silicon Labs EZSP network co-processor over TCP (6638, the port network-attached coordinators serve), ASH framing (CRC-CCITT, byte stuffing, randomisation, RST/RSTACK, ACK/NAK, frame numbers) and EZSP 14–17 in both the legacy and extended headers, implementing every command bellows and zigbee-herdsman send at startup, forming, joining and messaging. The model chooses whether a network is already formed, describes the devices that join (endpoints, clusters, attributes), decides each permit-join and each cluster command, and injects reports and button presses; descriptor queries, attribute reads and interviews are answered from the description with no model call, and a model failure becomes a ZCL Default Response FAILURE. Evidence: bellows 0.46.2 (CLI and a zigpy application) and zigbee-herdsman 11.1.1 (the Zigbee2MQTT stack), each forming or resuming the network and interviewing, switching and reading the model's device; fuzz target for the ASH deframer and EZSP decoder. This tests the host-to-co-processor link, not Zigbee over the air. **The TI Z-Stack 3.x.0 (MT/ZNP) dialect and EZSP 8–13 landed 24 October 2026**: a `dialect: znp` startup parameter selects Z-Stack, sharing the device descriptions, join decisions and ZCL answers with EZSP (`network.rs`); zigpy-znp 0.14.2 and zigbee-herdsman's `zstack` adapter each form or resume a network, interview the model's device, switch it and receive its report; bellows completes sessions at EZSP 8 through 13 and herdsman's `ember` at 13 (its floor). Not built: a client role (no independent co-processor simulator exists), EZSP 4–7 and 18+, Z-Stack 1.2 and 3.0.x, XNCP, Green Power, touchlink; tshark has no ASH, EZSP or MT dissector. |

---

## Storage additions (requested 16 October 2026)

Asked for after a survey of what NetGet already serves for storage — NBD and USB mass storage
(block), SMB, NFS, WebDAV, 9P and AFP (file shares), FTP/TFTP/SFTP/rsync, and S3. Queued after
Tier C, in this order:

| Protocol | Transport | Shape | Independent peers |
|---|---|---|---|
| ~~**iSCSI**~~ | TCP 3260 | **Landed 20 October 2026** as the `iscsi` pair (RFC 7143). Target: discovery (SendTargets), CHAP MD5 and mutual CHAP checked in Rust, CRC32C header and data digests, R2T and immediate/unsolicited data, CmdSN ordering, ABORT TASK; the model decides which targets discovery reveals, whether a login is admitted and what the LUNs contain, then every SCSI command is answered from that description with no further model call. SCSI is shared with USB mass storage (`src/server/scsi_common.rs`) and the disk model with NBD (`src/server/described_disk.rs`). Initiator: discovery, login with CHAP/mutual CHAP and digests, REPORT LUNS, INQUIRY, READ CAPACITY, READ/WRITE, logout, driven by the model one command at a time. Fuzz target `iscsi_pdu`. Not built: error recovery levels above 0, multiple connections per session, iSER, task management beyond ABORT TASK. | Target: libiscsi (`iscsi-ls`, `iscsi-inq`, `iscsi-readcapacity16`, `iscsi-md5sum` and a subset of `iscsi-test-cu`) and the Linux kernel initiator (open-iscsi, reading the disk through its by-path link); initiator: gotgt and tgtd (CHAP and mutual CHAP, CRC32C); tshark reads the sessions |
| ~~**NVMe over TCP**~~ | TCP 4420 | **Landed 20 October 2026** as the `NVMe-TCP` pair (`src/server/nvme_tcp`, `src/client/nvme_tcp`; NVMe/TCP transport 1.0). Target: ICReq/ICResp, CRC32C header and data digests, Fabrics Connect for admin and I/O queues, Property Get/Set, Identify (CNS 00h/01h/02h/03h/06h), Get Log Page (discovery 70h, error, SMART, changed namespaces), Set/Get Features, Keep Alive, held Asynchronous Event Requests, Read/Write/Flush/Write Zeroes, R2T and H2C/C2H data, and the well-known discovery subsystem; the model decides which subsystems exist and appear in discovery, which hosts may connect, and the namespaces and their contents (`src/server/described_disk.rs`, shared with NBD and iSCSI), asked once at the admin Connect. Writes to a namespace the model marks writable live in memory for that controller. Host: discovery, connect, Identify, Read/Write/Flush, shutdown, driven by the model one command at a time. Fuzz target for the PDU decoder. Not built: DH-HMAC-CHAP, TLS, reservations, ANA, namespace management, Compare/Verify/Copy, protection information, more than one R2T outstanding per command. | Target: the Linux kernel host (`nvme-cli` discover/connect, the namespace block device read back, `id-ctrl`/`id-ns`/`smart-log`) and SPDK (`spdk_nvme_identify`, `spdk_dd`, `spdk_nvme_perf`); host: the kernel `nvmet-tcp` target through configfs and SPDK `nvmf_tgt`; tshark's `nvme-tcp` and `nvme` dissectors read both directions |
| ~~**FUSE local filesystem**~~ | Local mount (not a network protocol) | **Landed 21 October 2026** as the `fuse` server (`src/server/fuse`, Linux only, `fuser` 0.18 with no libfuse; the kernel is the client, so there is no client role). A `mount_point` replaces the port. The model describes the tree lazily, one call per directory cached for the mount, with file contents in `described_disk`'s vocabulary (`src/server/described_tree.rs`); Rust serves lookup, getattr, readdir and reads. Each mutation (create, write, truncate, setattr, mkdir, unlink, rmdir, rename, symlink) is one model allow/deny with the errno it chooses, kept in a capped in-memory overlay for the life of the mount; `read_only` mounts without asking. Every model-dependent request has a deadline and fails closed with an errno. Stopping unmounts, and a watchdog unmounts after a killed process where fuse3 before 3.17 would leave the mount. Fuzz target for the tree description. Not built: hard links, extended attributes, fallocate, RENAME_EXCHANGE/WHITEOUT, macOS. | The Linux kernel FUSE driver through coreutils, findutils and Python as separate processes, and pjdfstest (198 of 238 files pass in full, held as a floor), unprivileged and as root on Ubuntu 24.04 |
| ~~**HDFS**~~ | TCP (NameNode RPC 8020, DataNode transfer 9866) | **Landed 21 October 2026** as the `hdfs` pair (`src/server/hdfs`, `src/client/hdfs`, Unix; Hadoop 3.5.0's own `.proto` files vendored under `proto/hadoop`). Server: one NameNode and one DataNode on two listeners; Hadoop IPC (`hrpc` v9, SASL SIMPLE, call ids, Java exception classes) with about 40 ClientNamenodeProtocol methods, and DataTransferProtocol v28 READ_BLOCK, WRITE_BLOCK (CRC32C chunk checksums verified) and BLOCK_CHECKSUM. The model describes the namespace lazily through the FUSE tree (`src/server/described_tree.rs`) with contents in `described_disk`'s vocabulary, decides which users may connect, and allows or denies each mutation with the exception it names; a written block is staged and the model decides at `complete`, accepted bytes kept in a capped in-memory overlay. Client: list, stat, read, mkdir, write through the pipeline, delete, rename, setPermission, driven by the model with RPC exceptions reaching it structured. Fuzz target for the RPC and transfer decoders. **Append, truncate and concat landed 24 October 2026** in both roles (append continues the last partial block's checksum chunks through PIPELINE_SETUP_APPEND; a mid-block truncate goes through recovery as `hdfs dfs -truncate -w` expects; concat keeps Hadoop 3.5's checks), each a model decision, against `hdfs dfs` and colinmarc/hdfs (append, truncate); the five connection deadlines are startup parameters with a test each. Not built: Kerberos/tokens, symlinks (no Hadoop CLI creates one), variable-length blocks, snapshots, ACLs, xattrs, quotas, encryption, erasure coding, pipeline recovery, more than one DataNode. | Server: Apache Hadoop 3.5.0's `hdfs dfs` CLI and colinmarc/hdfs v2.4.0 (Go, its own RPC and transfer code); client: a real single-node Hadoop 3.5.0 NameNode and DataNode, read back with `hdfs dfs` and checked against the NameNode audit log; tshark's `hdfs`/`hdfsdata` dissectors predate protobuf and check only the `hrpc` and op headers |

## Existing protocols missing one role (true gaps)

Registry coverage is otherwise complete — every apparent "client-only"/"server-only"
gate is a naming pair (`dynamo`/`dynamodb`, `openid`/`openidconnect`, `saml-idp`+`saml-sp`/`saml`,
`kubernetes-server`/`kubernetes`, `proxy`/`http_proxy`, USB/BLE device profiles whose peer
is a phone or a switch). The genuinely missing **client** roles, with their peers:

| Add client for | Peer | Note |
|---|---|---|
| ~~**mercurial**~~ | `hg` binary | Already existed (see status above). |
| ~~**svn**~~ | `svn` / `svnserve` | Already existed (see status above). |
| ~~**rtsp / rtp / hls**~~ | `ffmpeg`/`ffprobe` (installed), VLC | Landed (see "Missing roles" above). |
| ~~**rdp**~~ | `xfreerdp` | Landed (see "Missing roles" above). |
| ~~**zabbix**~~ | `zabbix_server`/`zabbix_sender` | Landed (see "Missing roles" above). |
| ~~gtp, db2, snowflake, spark, yarn~~ | peer-limited | Landed 15 October 2026 (see "Peer-limited missing clients" above). |

## Extensions to shipped protocols (the "separated extension" tradition)

- **gRPC client-streaming / bidi** (server streaming + reflection landed as items 68).
- **SNMPv3 + traps/informs** (have v1/v2c polling).
- **CoAP observe + blockwise** (RFC 7641 / 7959).
- **DNS AXFR/IXFR zone transfer + DNSSEC/EDNS0** (declared subset today).
- **InfluxQL / Flux query** (write path landed as item 28).
- **MQTT v5 property set**, **Kafka newer API versions**, **Redis RESP3/cluster/pubsub depth**.
- **QUIC datagrams**, **WebSocket permessage-deflate**, **HTTP SSE as a first-class server**.

## Validation lever already available

`tshark` 4.x dissects most raw/binary additions and gives an independent *encode-direction*
oracle for anything without a third-party client — worth wiring as a hard-fail peer (like
`nats-server`) for ZeroMQ, 9P, SMPP, KNX, BFD, VXLAN and the inetd/UDP services.
