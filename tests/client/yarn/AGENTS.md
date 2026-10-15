# YARN client tests

Two files, both under `--features tcp,yarn`:

| file | what | peer |
|---|---|---|
| `real_server_test.rs` | the client with the model mocked, against Hadoop's own YARN | Hadoop 3.5.0: a ResourceManager and a NodeManager running distributed-shell applications |
| `request_test.rs` | action → URL/body, id and filter validation, the endpoint rule, the queue walk, and every response bound | none, or a scripted HTTP server for the bounds |

## Peers

`install_peers.sh <root>` downloads the official `hadoop-3.5.0.tar.gz` (from
downloads.apache.org, falling back to archive.apache.org), checks its pinned SHA-512, unpacks it
and prints `export NETGET_HADOOP_HOME=…`. It needs a JDK 17 (`JAVA_HOME`, or `java` on `PATH`;
on this Mac the default `java_home` is a JDK 26, so export
`JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home`). **Without
`NETGET_HADOOP_HOME` every real-server test fails** and names the script; it never skips.

`Cluster::start` writes a minimal configuration into the ResourceManager's temporary directory
— `fs.defaultFS=file:///` (no HDFS), every address on 127.0.0.1 and a probed port, two
capacity-scheduler queues `default` (60) and `netget` (40), a 4096 MB / 4 vcore node — and runs
`yarn resourcemanager` (ready on `Transitioned to active state`) and, for the cluster test,
`yarn nodemanager` with the same `HADOOP_CONF_DIR` (ready on `Registered with ResourceManager`).
Two settings matter more than they look:

- **`yarn.node-attribute.fs-store.root-dir`** defaults to `/tmp/hadoop-yarn-${user}/node-attribute`
  regardless of `hadoop.tmp.dir`. Two ResourceManagers started at once (`--test-threads=4`)
  trample each other's mirror file and one dies after its web app is up — so the readiness line
  is the active transition, not `Web app cluster started`. Both it and the node-label store now
  live in the temporary directory.
- **The NodeManager's disk health checker is off.** A developer disk above 90% full marks every
  local dir bad, the node goes UNHEALTHY, and no container is ever scheduled.

Applications are YARN's own **distributed-shell** example (`hadoop-yarn-applications-
distributedshell-3.5.0.jar`, one container, AM 256 MB, container 128 MB): `netget-ok` (`echo`,
queue `default`), `netget-fail` (`false`, queue `netget`: FINISHED / FAILED with YARN's
diagnostics) and `netget-sleep` (`sleep 600`, queue `netget`, RUNNING until the model kills it).

## What is asserted

`WireTap` is a recording TCP relay between NetGet and the ResourceManager: it parses each HTTP
request that crosses it (method, target, and the body by `Content-Length`), because the RM keeps
no request log NetGet can read. Each chain asserts the **exact set** of requests (and their
count) the model's actions name. The relay closes NetGet's side when the RM closes, so a dead
RM is an immediate error rather than a 30-second timeout on a pooled connection.

| test | LLM calls | asserts |
|---|---|---|
| `yarn_client_reads_and_kills_on_a_real_cluster` | 14 | the connected RM (3.5.0, ACTIVE, cluster id = the application ids' timestamp); metrics (3 submitted, 2 completed, 1 running, 1 node, 4096 MB, 4 vcores); the scheduler's queues and capacities = capacity-scheduler.xml, netget holding the running app; the node = `yarn node -list -all` (id, state, HTTP address) running 2 containers / 384 MB; every application's name, type, user, queue, state and final status = `yarn application -list -appStates ALL` taken before NetGet read anything; the failed application the model picked out of the FINISHED list = `yarn application -status` (queue, start/finish time, MB-seconds, diagnostics); its attempt = `yarn applicationattempt -list` (attempt id, state, AM container); its queue; the sleeper's state; the kill (202 KILLING or 200 KILLED) and then `yarn application -status` reporting KILLED / KILLED; YARN's own `404 NotFoundException app with id: … not found`; 13 requests on the wire and the PUT's body `{"state":"KILLED"}` |
| `kill_is_refused_without_allow_kill` | 2 | `decision=refused_kill_not_allowed`, a `yarn_error` naming `allow_kill` with no HTTP status, and only the connect probe on the wire |
| `followup_chain_stops_at_the_bound` | 8 | `decision=followup_depth`, and exactly 1 + `MAX_FOLLOWUP_DEPTH` info requests on the wire |
| `llm_failure_reads_nothing` | 1 | `decision=fail_closed_llm_error`, and only the connect probe on the wire (with `allow_kill` on) |
| `the_tap_splits_requests_and_bodies` | 0 | the relay's own request parser |

Mutation-checked (each applied alone, the named test failing on its own assertion, then
reverted): splitting a path segment on `/`, allowing `/` and `.` in an app id, removing the size
bound, removing the depth bound, following redirects, defaulting a missing target
(`request_test.rs`); removing the kill gate (`request_test.rs` and `kill_is_refused…`); removing
the follow-up bound; sending a request when the model call fails; dropping the model's actions
(the cluster chain).

## Running

```bash
sh tests/client/yarn/install_peers.sh /tmp/hadoop-peers
export NETGET_HADOOP_HOME=/tmp/hadoop-peers/hadoop-3.5.0
export JAVA_HOME=<a JDK 17>
./cargo-isolated.sh test --no-default-features --features tcp,yarn --test client -- client::yarn:: --test-threads=4
```

About 22 s on an M-series Mac with four threads; the cluster test runs four JVMs (RM, NM, the
distributed-shell client per application, and the CLI). The `protocol-pairs.yml` job `yarn`
runs the suite in CI with Temurin 17.
