# Docker Engine API

NetGet answers the read-only core of the Docker Engine API well enough for the real
`docker -H tcp://127.0.0.1:<port>` CLI: `version`, `info`, `ps [-a]`, `images`, `inspect`,
`network ls`, `volume ls`. The model decides which containers, images, networks and volumes
exist; NetGet owns negotiation, routing and the shape of every document.

**State**: Beta. **Privilege**: `None` (2375 is unprivileged). **Feature**: `docker`
(needs only `urlencoding` for query decoding). **Group**: AI & API. **Keywords**: `docker`,
`dockerd`, `docker engine`, `docker api`, `moby`.

## Library choice

hyper HTTP/1.1, the same shape as `kubernetes`. No `bollard` or Docker types crate: the CLI
decodes JSON into its own Go structs, so what matters is the field names and the fields it
dereferences, and `api.rs` writes those directly. That keeps the feature dependency-free.

## What the CLI sends (captured from Docker CLI 29.8.0)

Every command is `HEAD /_ping`, then one or more `GET /v<negotiated>/…`. The CLI reads the
`API-Version` header from `/_ping` and downgrades to it ("1.47 (downgraded from 1.56)").
`docker inspect <unknown>` tries `/containers/<x>/json`, then `/images/<x>/json`,
`/networks/<x>`, `/volumes/<x>`, `/plugins/<x>/json`, and reads `/info` to decide whether to try
the swarm types — so an unknown name costs two model calls (the container and `/info`).

## What NetGet decides vs what the model decides

| Served deterministically, no model call | Decided by the model (`docker_api_request`) |
|---|---|
| `HEAD`/`GET /_ping` with `API-Version`, `Server: Docker/<engine> (linux)`, `Ostype`, `Docker-Experimental` | `/version` → `send_docker_version` |
| `/vX.Y/` above `api_version` → 400 "client version X is too new…"; below 1.24 → 400 "too old" (Docker's own wording) | `/info` → `send_docker_info` |
| every `POST`/`PUT`/`DELETE` → 501 `{"message": "…read-only…"}` | `/containers/json` → `send_docker_containers` |
| any other `GET` → 404 `{"message": "page not found"}` (this is what `docker inspect`'s fallbacks hit) | `/containers/{id}/json` → `send_docker_container` |
| the filler fields in every document | `/images/json`, `/networks`, `/volumes` → `send_docker_images` / `_networks` / `_volumes` |
| | any of them → `send_docker_error {status, message}` |

The event is `docker_api_request {method, path, api_version, query, resource, id?,
answer_with}`; `path` is without the version prefix, `query` is decoded (`all`, `filters` as its
JSON string), `resource` is one of `version`, `info`, `containers`, `container`, `images`,
`networks`, `volumes`, and `id` is set for `container`. `answer_with` (`Route::answer_with`)
names the action for this one request — for a list, the array it carries (and for
`/containers/json` whether stopped containers belong in it), for an inspect the 404 and its
`No such container: <id>` message. Naming the array matters as much as naming the action: a
hint that said only "send_docker_containers with the running containers" was answered with
`{"type": "send_docker_containers"}` and nothing else in 13 of 15 list requests.

**Each route is raised with only the actions that can answer it.** `actions::event_for_resource`
raises `docker_api_request` — the same id, so handlers match as before — offering the route's one
answering action and `send_docker_error`, under a description naming the request ("This request
is `docker ps` …", "This request inspects one container, named by `id` …"). The declared event
in `get_event_types()` keeps all eight actions and the route table, which is what
`get_protocol_docs` and handler validation read. Offered all eight, llama3.1:8b answered an
inspect of a missing container with `send_docker_version`, and later with
`{"type": "send_docker_volumes", "volumes": [{"name": "none"}]}` in every run, reasoning that it
was answering "the resource=volumes request"; the connection loop ignores any action but the
route's own, so those seven were only ever wrong answers. Offered two, it answers the 404
(`inspect-missing` 0/5 → 5/5, 29 September 2026). One wording cost a round of its own: a
description saying the request "lists containers" was answered with an invented
`{"type": "list_containers", "all": "1"}` tool call beside a correct `send_docker_containers`,
which the LLM layer rejects as an unknown action, 4 runs in 5; the descriptions name the CLI
command instead.

**The server picks the action that answers the route.** A response carrying several actions —
which is what a static handler is, since it answers every `docker_api_request` identically — is
scanned for the one whose name matches the route; the rest are ignored. So a fixed host is one
static rule with one action per route (`example_static_actions()` in `actions.rs`), and a model
that answers `/containers/json` with `send_docker_version` gets `decision=fail_closed_no_action`,
not a wrong document.

## Rendering (`api.rs`)

Accepts snake_case (`private_port`) and Docker's own PascalCase (`PrivatePort`) for every field.
Fills: a 64-hex ID derived deterministically from the name when none is given (so `ps` and
`inspect` agree), `/`-prefixed names, `ImageID`, `Status` from `State` (`Up`, `Exited (N)`…),
`HostConfig`, `NetworkSettings`, `Mounts`, `SharedSize: -1`, `Containers: -1`, the `Components`
list of `/version`, and the ~40 fields of `/info` (`Swarm.LocalNodeState: inactive`, plugins,
runtimes). `created` is unix seconds or RFC 3339.

Three things a model writes that Docker would not, rendered the way Docker would rather than
refused (each was the whole of a 0/15 eval case, `api_test.rs` pins each):

- **A name as the ID** (`"id": "eval-web"`). Letters and digits are used as given; a value
  shaped like a container name is the seed a missing ID is derived from, so it renders as the
  same 64-hex ID omitting it would, and `ps` and `inspect` agree. The client only ever receives
  letters and digits.
- **`"state": "stopped"`** is `exited` — what `docker stop` leaves.
- **An exited container's `status` without its code** ("Exited 10 minutes ago", "Stopped") is
  written `Exited (<exit_code>) 10 minutes ago` / `Exited (<exit_code>)`, the daemon's form. A
  running container's wording is the model's own.
- **A blank `created` or `id`** (`""`, which the model writes for every example field the
  instruction did not mention) is the field left out: the creation time is now and the ID is
  derived from the name. Refusing it failed `docker ps -a` on two eval seeds in five.

**A repeated ID in one `ps` list is replaced** by the ID derived from that container's name; the
first container keeps it. Two containers never share an ID, and llama3.1:8b copied the action
example's 64-hex ID onto every container of a `ps -a` (9 times across the eval's two `ps`
cases), which left two rows `docker inspect` could not tell apart. `api_test.rs` pins it
(checked by removing the replacement).

Two prompt changes were measured against the eval's docker cases and **not** shipped, because
both runs came out worse than the baseline of ps 5/5, ps -a 5/5, inspect-missing 3/5 (5 runs each,
seed 42):

- Dropping `id` from the container example and telling the model to leave it out, together
  with rewording the inspect `answer_with` to lead with the lookup and give the 404 as a literal
  action (the shape that worked for coap, modbus and zabbix): ps 3/5 (the model also dropped
  `ports`), ps -a 4/5, inspect-missing 0/5.
- The example change alone, with the inspect hint as it is: ps 4/5, ps -a 5/5, inspect-missing
  still 0/5 — `send_docker_version` or `send_docker_volumes` for an inspect every run. So the
  inspect regression followed the example change, not the reworded hint; a change to one
  action's example moved the answer to a different route.

The example keeps its ID, and a repeated ID is repaired on the server side instead (above).
`inspect-missing` was unchanged by the ID repair and noisy at that prompt (3/5, then 1/5, then
0/5 on 29 September), every miss `{"type": "send_docker_volumes", "volumes": [{"name":
"none"}]}`; offering each route only its own actions (above) is what fixed it.

Refuses, with a reason: a container with no name or image, a name Docker would refuse
(`[a-zA-Z0-9][a-zA-Z0-9_.-]*`), a state outside `created|running|paused|restarting|removing|
exited|dead` (after the `stopped` alias), a port outside 1..=65535, a port type other than
tcp/udp/sctp, an ID that is neither letters and digits nor name-shaped (spaces, slashes,
punctuation), an unparseable timestamp, a tag with whitespace, an `api_version` that is not
`N.M`, a negative count. Refusals happen in `execute_action`, so they reach the log and access log
(`list_access_logs`) as a failed action; the network path does not re-prompt the model with them.

## Failure behaviour

| Condition | Wire | Log |
|---|---|---|
| model answered the route's action | 200 + document | `decision=model_answer action=…` |
| model answered `send_docker_error` | its status + `{"message": …}` (one line) | `decision=model_reject` |
| action refused by the executor | 500 `{"message": "netget: the handler returned no usable answer for this request"}` | `decision=fail_closed_invalid_answer (<reason>)` |
| no action answering this route | same 500 | `decision=fail_closed_no_action` |
| backend saturated | 503 + `Retry-After: 5`, `netget: backend at capacity, retry later` | `decision=fail_closed_llm_error category=Overloaded` |
| backend failed | 500, `netget: request could not be processed` | `decision=fail_closed_llm_error category=Unavailable` |
| mutating endpoint | 501 | `decision=fail_closed_not_implemented` |
| body over the cap | 413 | `decision=fail_closed_body_rejected` |

Never an empty list on failure: `[]` from `/containers/json` means "no containers", and an
outage must not say that. The CLI prints the message as `Error response from daemon: …`.

## Bounds

| Bound | Value | Why |
|---|---|---|
| `MAX_REQUEST_BODY_BYTES` | 1 MiB | reads carry no body and writes are refused; read before routing so it holds everywhere |
| `FIRST_BYTE_READ_TIMEOUT` | 30 s | `peek` before hyper |
| `IDLE_BETWEEN_REQUESTS_TIMEOUT` | 120 s | the CLI connects per command; SDK pools go quiet between calls |
| `MAX_CONNECTIONS` | 256 | refusal is a 503 with a Docker-shaped JSON body |

No peer handle: hyper owns the socket (`HyperOwnsSocket` in
`tests/peer_handle_coverage_ratchet_test.rs`).

## Startup parameters

`api_version` (default `1.47`, must be ≥ 1.24) and `engine_version` (default `27.5.1`), both
read in `spawn()` and validated there.

## Not implemented

Everything that changes state (create/start/stop/exec/pull/build/rm), `/images/{id}/json`,
logs, events, stats, attach, the swarm and plugin endpoints, TLS on 2376, and authentication —
the unauthenticated TCP API on 2375 has none, and neither does this.

## Maturity

Beta. The bar is "works against real clients", and the evidence is
`tests/server/docker/real_client_test.rs`: the real `docker` CLI — a Go client that decodes
every document into the Engine's own types and renders it — prints exactly the handler's values
for `version`, `ps -a`, `images`, `inspect`, `network ls`, `volume ls` and `info`, and
`require_tool("docker")` **hard-fails** when the binary is absent. If that gate is ever softened
to a skip, demote this in the same commit. Promoted after the suite passed three consecutive
runs at `--test-threads=100`.

Not Stable: one client (no SDK such as `bollard` or docker-py drives it yet), no fuzz target, no
pcap-oracle test (Wireshark has no Docker dissector), and the API is a read-only subset.
