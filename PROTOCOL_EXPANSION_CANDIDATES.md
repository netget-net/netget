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
    gretap-over-fou driver. GRE directly on IP protocol 47 is still not built: it needs a
    raw socket, and privilege is declared per protocol.
  - ~~**ONVIF**~~: landed 14 October 2026 as the `onvif` pair — device service
    (GetSystemDateAndTime, GetDeviceInformation, GetCapabilities, GetServices, GetScopes,
    GetNetworkInterfaces) and media ver10 (GetProfiles, GetVideoSources, GetStreamUri,
    GetSnapshotUri) with WS-Security UsernameToken digest, against onvif-zeep-async and
    use-go/onvif (server) and RPOS (client). Media2, PTZ, Imaging, Events, Recording and
    the Set* operations are not built.
  - ~~**Stratum V2**~~: landed 14 October 2026 as the `stratum-v2` pair (Mining Protocol,
    standard and extended channels, Noise NX with the SV2 certificate), hand-rolled from
    sv2-spec so that SRI's `mining_device` and `pool_sv2` (over Bitcoin Core regtest) are
    independent peers. The Job Declaration and Template Distribution protocols are not built.
  - ~~**IPFS above libp2p**~~: landed 14 October 2026 on the `libp2p` feature behind an
    `ipfs` startup parameter — Bitswap 1.0–1.2, CIDv0/v1 with `raw` and `dag-pb`, single-block
    UnixFS files, and the Kademlia DHT (FIND_NODE answered in Rust, GET_PROVIDERS and
    ADD_PROVIDER by the model) — with Kubo 0.43.1 fetching from NetGet and serving to it.
    Serving multi-block DAGs, Bitswap sessions, IPNS/DHT records and a second independent
    IPFS implementation are not done.
  - ~~**NGAP/N2**~~: landed 15 October 2026 as the `ngap` pair (AMF and gNB over real
    SCTP, PPID 60, with a labelled lab-TCP transport for hosts without SCTP): NG Setup,
    Initial UE Message, Downlink/Uplink NAS Transport, and pre-security 5GMM, hand-written
    APER checked by tshark's `ngap` dissector, against UERANSIM's nr-gnb/nr-ue and Open5GS's
    AMF. NAS security (5G-AKA, Security Mode), PDU sessions, handover and paging are not
    built, so a real UE cannot complete registration.
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
- **Tier C**: all deferred, unchanged, for the reasons in the table below. This includes
  the LoRaWAN Semtech UDP packet-forwarder slice, which could be promoted if IoT is
  wanted.
- **Maturity**: almost everything above landed at `Experimental` or `Beta`. The client
  promotions that came with it are Kafka, DNS and RDP (Beta). None of these items has
  been taken through the six Stable conditions in `AGENTS.md`.

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
| **OpenFlow** | Only dated crates (`rust_ofp` 2017); codec-heavy. Peer (Open vSwitch) exists if revisited. |
| **Profinet / EtherCAT** | Need real-time Ethernet / hardware; no viable Rust peer. |
| **M-Bus** | Weak Rust crates; mostly hardware gateways. |
| **AFP, NIS/YP, rsh/rlogin/rexec** | Obsolete; low value, insecure legacy. |
| **Zigbee / LoRaWAN radio** | Need radios. Exception: the **LoRaWAN Semtech UDP packet-forwarder** is UDP and testable against ChirpStack — promote that specific slice if IoT is wanted. |

---

## Existing protocols missing one role (true gaps)

Registry coverage is otherwise complete — every apparent "client-only"/"server-only"
gate is a naming pair (`dynamo`/`dynamodb`, `openid`/`openidconnect`, `saml-idp`+`saml-sp`/`saml`,
`kubernetes-server`/`kubernetes`, `proxy`/`http_proxy`, USB/BLE device profiles whose peer
is a phone or a switch). The genuinely missing **client** roles, with their peers:

| Add client for | Peer | Note |
|---|---|---|
| ~~**mercurial**~~ | `hg` binary | Already existed (see status above). |
| ~~**svn**~~ | `svn` / `svnserve` | Already existed (see status above). |
| **rtsp / rtp / hls** | `ffmpeg`/`ffprobe` (installed), VLC | Media clients; ffmpeg is already a test peer. |
| **rdp** | `xfreerdp` | Remote-desktop client (server exists). |
| **zabbix** | `zabbix_server`/`zabbix_sender` | Agent/sender client. |
| gtp, db2, snowflake, spark, yarn | peer-limited | Lower priority: no clean local independent server for most. |

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
