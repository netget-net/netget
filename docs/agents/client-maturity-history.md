# Client maturity: the client bar, and every pass that applied it

> Moved out of the root `AGENTS.md` on 21 November 2026, which now holds only the rules and
> a pointer here. The text is as it was written, so "this file" and "this section" mean
> the root file as it then was; dated claims are dated for a reason — re-derive before
> trusting one.

The four conditions are a checklist in the root `AGENTS.md` ("Maturity bars"). The passes
below are in the order they were written, which is not chronological: 16 September 2026
(nothing promoted), 26 September (five, then nine), 1 November (thirty-nine), then the
15 October and 26 September counts in between. **Generate the current list:**

```bash
python3 scripts/beta_evidence_table.py --side client --all   # table + the four-way split
python3 scripts/beta_evidence_table.py --side client --check # exit 1 on a defective Beta
```

Re-derived 21 November 2026: 39 Beta, 201 Experimental clients.

## The bar

**The client bar is the mirror of the Beta bar above, and it is genuinely different.** Written
down 16 September 2026, because 97 of 98 clients sit at Experimental and nothing in this file
said what the ninety-eighth had that the others did not.

A server proves itself against a third-party **client**. A client proves itself against a
third-party **server** — never NetGet's own server of the same protocol. That is the
circular-evidence case this section names for `ssh`/russh, wearing the other hat: pointing
NetGet's redis client at NetGet's redis server proves the two agree, which is what they were
both written to do.

A client is **Beta** when all four hold:

1. **The peer is a real third-party server** — a binary (`nats-server`, `redis-server`,
   `postgres`, `mysqld`, `mosquitto`, `nginx`, `sshd`, `unbound`) or a third-party crate in
   server role, and **not the crate NetGet's client is built on**. That last clause is what
   disqualifies `tls`: its test is driven by a `tokio_rustls::TlsAcceptor` while NetGet's TLS
   client *is* a `tokio_rustls::TlsConnector`, so the exchange proves that rustls interoperates
   with rustls. Contrast `quic`/quinn and `webrtc`/webrtc-rs, accepted on the server side:
   there NetGet authors real protocol logic above the crate and the crate is transport. Where
   the crate **is** the protocol, using it at both ends measures nothing.
2. **The test fails rather than skips when the peer is absent**, naming the binary and how to
   install it. `npm`'s reasoning, which `nats`' test states in as many words. A
   skip-when-missing gate is a silent pass, so a rating resting on one rests on nothing
   wherever the suite actually runs — and `#[ignore]` fails this the same way, because
   unreachable evidence is not evidence however good the reason for parking it.
3. **A real session, not a connect.** The client completes the protocol's own exchange —
   authenticate, ask, parse the answer — rather than proving that a socket opened.
4. **The client acts on the model's answer, asserted on the wire.**
   `tests/client_event_wiring_test.rs` exists because six clients asked the model what to do
   and discarded the reply, and that defect is silent: the client connects, reports success and
   does nothing. Asserting that the LLM was *called* does not cover it. Asserting the effect of
   an action the model produced does.

## 16 September 2026: nothing promoted

**Applied 16 September 2026: nothing was promoted, and `nats` remains the only Beta client.**
That is the finding rather than a failure to find one. Five *servers* had been sitting at
Experimental with the evidence already in the tree, and the same was expected here; it is not
the case. The clients fall into four groups and only one is near the bar:

- **Circular** — the overwhelming majority, ~60 protocols. `redis`, `postgresql`, `mysql`,
  `mongodb`, `imap`, `ftp`, `irc`, `http`, `whois` and the rest drive NetGet's own server of the
  same protocol. Several more (`jsonrpc`, `openapi`, `bitcoin`, `elasticsearch`, `rss`) drive
  NetGet's *HTTP* server, which is same-project **and** generic HTTP — two disqualifications.
- **Real peer, unreachable evidence** — `mqtt` (Mosquitto in Docker), `smtp` (Python `smtpd`),
  `ssh` (an external `sshd`), `smb`, `xmpp`, `ldap`, `s3`, `dynamodb`, `sqs`, `tor`. Each names
  a genuine third-party server and **every one of those tests is `#[ignore]`d**, so none of it
  runs. These are the cheapest promotions available, and the work is un-ignoring them — which
  means standing the peer up wherever the suite runs.
- **Real peer, wrong peer** — `tls` (rustls at both ends, above) and `oauth2` (an `axum`
  router, which is generic HTTP and is in `beta_evidence_table.py`'s own `INFRASTRUCTURE` set).
- **Public internet** — `dot`, `git`, `npm`, `pypi`, `maven`, `ntp` reach real third-party
  servers and are `#[ignore]`d for the right reason: this file requires localhost only. A local
  mirror would turn these into evidence; the public endpoint never will.

**What is installed on this machine**, so the remaining cost is a number rather than a guess:
`nats-server` (already in use), `redis-server` (valkey), `mosquitto`, `etcd`, `postgres`,
`mysqld`, `nginx`, `sshd`, `httpd`, `unbound`, `smbd`, `tor`, `openvpn`, `slapd` (under
openldap's `libexec`) and libmemcached's tools. Missing, for the list above: `vsftpd`,
`memcached`, `mongod`, and a MinIO or LocalStack for the AWS clients.

## 26 September 2026: `mqtt`, `redis`, `etcd`, `http`

**Applied again 26 September 2026: `mqtt`, `redis`, `etcd` and `http` are Beta — five Beta
clients, 93 Experimental.** The difference from the first pass is that the peers were stood up
rather than found: `tests/helpers/real_server.rs` (`RealServer`) spawns a third-party server on
a loopback port in a temp dir of its own, waits for its own "listening" log line, kills its
process group on drop and **fails naming the brew formula and the Ubuntu package** when the
binary is absent. Each client then has `tests/client/<p>/real_server_test.rs`: Mosquitto with
`mosquitto_sub`/`mosquitto_pub`, a real `redis-server` read back with `redis-cli`, the official
Go `etcd` read back with `etcdctl`, and nginx asserted through its own access log. Every one
asserts condition 4 from the server's side of the wire, and every one was checked by mutation
— emptying the loop over the model's actions fails it. CI now installs those servers
(`registry-audit`, plus `redis-server` and `nginx` in the blocking `test` job, because `redis`
and `http` are in `CI_FEATURES` and their real-server tests run there), and
`tests/real_client_evidence_is_run_test.rs` scans `tests/client/` as well as `tests/server/`,
so a client suite that drives a real server and runs in no CI job fails the build. Before that
extension the one Beta client's own evidence, `nats`, ran in no CI job at all.

Two findings from it are worth carrying to the next client:

- **A real server finds framing bugs a same-project one agrees with.** The redis client read
  replies **line by line**, so `GET k` → `$5\r\nhello\r\n` reached the model as two events,
  `"$5"` and `"hello"`, and it split commands on whitespace, so `SET k "a b"` stored `"a`.
  NetGet's own Redis server never exposed either: the tests against it asserted only that the
  model was called. `src/client/redis/resp.rs` now reads one whole RESP2/RESP3 reply per event
  (depth, declared size and element count bounded — without the depth bound a 40 KB reply
  aborts the process on a stack overflow) and splits the way `redis-cli` does.
- **Match each mocked reply on its parsed content, and put the most specific rule first.** A
  rule matched on `reply_type` and `value` is what turns "the reply was split" into a failure
  rather than an extra LLM call; and nginx's echo quoting the previous response back made a
  looser rule answer both responses until the follow-up depth cap stopped the loop.

## 1 November 2026: thirty-nine

**Thirty-nine as of 1 November 2026 (39 Beta, 201 Experimental — re-derive with
`--side client`).** `--side client --all` listed 43 clients in "real peer, evidence runs";
reading each test for condition 4, running it against the installed peer and emptying the loop
over the model's actions promoted 21: `afp` (netatalk), `beanstalkd`, `capnp_rpc` (pycapnp and
go-capnp), `db2` (Apache Derby, a DRDA server that is not IBM Db2), `dbus` (dbus-daemon),
`dict` (dictd), `docker` (the Docker Engine), `gearman` (gearmand), `kerberos` (MIT and
Heimdal KDCs), `nostr` (nak and nostr_sdk), `nsq` (nsqd), `oci_registry` (crane's registry),
`openflow` (os-ken), `prometheus`, `radsec` (FreeRADIUS), `rsync`, `rtp` (ffmpeg), `snmp`
(Net-SNMP snmpd), `srt` (libsrt), `vault` and `x11` (Xvfb). Each `AGENTS.md` names the
server-side assertion. Script and static handlers count as the model here, as they already did
for `dns`, `rdp` and `ngap`: `call_llm_for_client` routes them, so they reach the same loop.

What that pass found, worth expecting of the next client:

- **Chains with no bound at all**, the September finding again. `beanstalkd`, `dict` and `srt`
  forwarded every action the model returned with no depth, so a model that answered each
  response with another request looped for as long as the server answered. All three now stop
  at `MAX_FOLLOWUPS` 4, and the test counts the requests on the server's side (beanstalkd's
  `cmd-list-tubes`, dictd's command log, the bytes libsrt wrote). `mqtt_sn` and `radsec`'s
  shape was checked too: `radsec` runs on the RADIUS client's bounded loop; `mqtt_sn` is still
  unbounded and unpromoted.
- **Mocked-model tests that asserted the client's report rather than the server's state.**
  `nsq`'s "server-side" reader was NetGet's own subscriber; `vault`, `nostr`, `docker` and
  `prometheus` checked the event the client raised. Each now reads the effect from the
  third-party side (`nsq_tail`, the `vault` CLI, `nak req`, the `docker` CLI, Prometheus's own
  handler counter). For a read-only client the effect of its action is the server's answer,
  cross-checked with the server's own tool.
- **The installed peer was not the pinned one, and the tests showed it.** nak 0.21 reads events
  from a piped stdin instead of its arguments, so the nostr tests' empty pipe made `nak event`
  and `nak req` do nothing; macOS's bundled snmpd 5.6 has no SHA-256 and no `rwuser`.

Not promoted: the peer is missing here for `bfd`, `ethercat`, `gtp`, `guacamole`, `h323`, `hls`
(GStreamer), `inetd`, `iscsi`, `nis`, `nvme_tcp`, `profinet`, `spice`, `sunrpc` (rpcbind on
:111), `wsdiscovery` and `zabbix` (`zabbix_proxy`); `bolt`, `lorawan`, `mqtt_sn` and `rtsp` need
peers built or downloaded (Neo4j, ChirpStack, the Paho gateway, MediaMTX) and were not run —
`bolt`'s, `mqtt_sn`'s and `rtsp`'s real-server tests drive injected actions only, so they need a
condition-4 test as well; `grpc` (`mkfifo` is not a peer — it is self-served),
`webrtc` (webrtc-rs at both ends) and `ssh` (demoted on 2 October for its SFTP evidence) are
not candidates at all.

## October, and the second half of 26 September: `postgresql`, `mysql`, `ldap`, `ssh`

**Seventeen as of 15 October 2026 (17 Beta — re-derive with `--side client`).**
Since the thirteen below: `kafka`, `dns` and `rdp` arrived Beta with the protocol-expansion
pairs, `spark` against a real Apache Spark's live driver UI and History Server, and `yarn`
against a real Hadoop ResourceManager and NodeManager. `ssh` went
the other way on 2 October 2026: its SFTP operations shipped without a second independent SFTP
server, pcap oracle or fuzz target, and its `metadata()` says so.

**Thirteen as of 26 September 2026 (13 Beta, 89 Experimental).**
`memcached`, `coap`, `modbus` and `radius` are new clients that arrived Beta against memcached,
libcoap's `coap-server`, a pymodbus device and FreeRADIUS. The paragraphs below are how the
count got to nine first.

**The same day's second half made it nine: `postgresql`, `mysql`, `ldap` and `ssh` are Beta —
nine Beta clients, 89 Experimental.** The peers are the PostgreSQL server (`initdb` +
`postgres`, read back with `psql`), Oracle's `mysqld` (`--initialize-insecure`, read back with
the `mysql` CLI), OpenLDAP's `slapd` (a temp-dir `slapd.conf`, seeded with `ldapadd`, read back
with `ldapsearch`) and OpenSSH's `sshd` run **unprivileged** (a temp-dir `sshd_config`,
`ssh-keygen` keys, public-key auth as the current user — an unprivileged sshd can log in no one
else and check no password). `RealServer` grew `setup_command` for the data directory a server
needs before it will start, and `graceful_stop`, because a SIGKILLed postmaster leaks a System
V shared memory segment and macOS allows 32. CI installs all four in `registry-audit` only
(none is in `CI_FEATURES`), and unloads Ubuntu's AppArmor profiles for `mysqld` and `slapd`,
which confine them to their packaged paths.

Every one of the four had defects NetGet's own servers had never shown, which is the point of
the exercise and worth expecting of the next client:

- **A result that did not say what it was.** MySQL reported the *row count* as
  `affected_rows`, so an `INSERT` read as affecting nothing; LDAP's one response event for add,
  modify and delete named neither the operation nor the DN; SSH's output event did not name
  its command. A mock matched on the server's own answer (`affected_rows` 1, `last_insert_id`
  1, `operation` add) is what caught each.
- **A real server's normal sequence breaking a loop written against our own.** The SSH client
  stopped reading at the channel's EOF; OpenSSH sends `exit-status` *after* EOF, so every exit
  status was lost.
- **A refusal that raised nothing.** A search slapd answered with `noSuchObject` ended the LDAP
  chain silently, and an attribute written as a plain string (`{"cn": "Ada"}`) was dropped
  from an add. Both reached the model only once the server said no.
- **Chains that were one step deep, or unbounded.** PostgreSQL executed the model's answer to
  a result and dropped that query's rows, so create → insert → select → act was impossible;
  LDAP and SSH followed the chain with no bound at all. All three now follow it and stop at
  `MAX_FOLLOWUP_DEPTH` 4, as MySQL already did, and each bound has a test that fails without
  it — the LDAP one counts the searches in slapd's own log.

## Generating the groups: `--side client`

**Do not read the four groups above as the list — generate them:**

```bash
python3 scripts/beta_evidence_table.py --side client --all   # table + the four-way split
python3 scripts/beta_evidence_table.py --side client --check # exit 1 on a defective Beta
```

`--side client` landed 16 September 2026 and applies the bar above rather than the server one:
it detects **self-served** (a test that builds a `ServerForm`, calls `start_netget_server` or
sends an `open_server` action — the peer is NetGet's own server) and treats `#[ignore]`d
evidence as disqualifying rather than as a review flag, attributing peers **per file** so a
peer named only in tests that never run is reported as unreachable. Its first run agreed with
the hand audit and sharpened it: 62 self-served rather than "~60", **zero** protocols in the
"real peer, evidence runs" group, and `mqtt` alone in "real peer, unreachable". What no scan
can check is condition 4 — that the client acts on the model's answer — and the script says so
instead of implying it passed. It reads a server spawned through `RealServer::builder("<bin>")`
as a binary peer, since the helper, not the test file, is what spawns it. Re-derived
26 September 2026 after the promotions above: Beta 9, Experimental 89 — 55 self-served, 9
wrong peer, 25 with no peer, and none left in either "real peer" group.

**It also follows a peer whose program is computed rather than spelled**, which it did not
until 31 October 2026, and the miss was large: `hdfs` (`RealServer::builder(&hdfs, …)` with
`hdfs = home.join("bin/hdfs")` under `NETGET_HADOOP_HOME`), `pfcp` (`Command::new(peer)` with
`peer` read from `NETGET_PFCP_GO_PEER`) and `devp2p` (geth and reth started inside
`tests/helpers/ethereum.rs`) were reported as having no peer while each hard-fails without
one. `program_names` follows the spawn argument back through `let` bindings to a literal in a
naming position (a `.join` path, a lookup helper's argument, an environment variable or its
fallback) and never invents a name; an environment variable naming a runtime or a directory
(`*_PYTHON`, `*_HOME`) is not a peer. For a client, a `RealServer::builder` inside a
`tests/helpers/` module the test uses counts too — a helper's `Command::new` does not, since
`pcap_oracle` runs tshark. `smb` is not this case: its only real-peer tests are `#[ignore]`d
and expect an externally run Samba, so "no peer" is right. The change made 32 clients' peers
visible. Re-derived 6 November 2026, after the 21 client promotions above: Beta 39,
Experimental 201 — 54 with a real peer whose evidence runs, 1 unreachable, 21 wrong peer,
53 self-served, 72 with no peer.
