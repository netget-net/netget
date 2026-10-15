# Redis Client E2E Tests

Seven files, declared in `tests/client/redis/mod.rs`. Nothing is `#[ignore]`d.

| File | Peer | Tests | LLM calls |
|---|---|---|---|
| `real_server_test.rs` | **real `redis-server`** + `redis-cli` | 2 | 9 |
| `pubsub_real_server_test.rs` | **real `redis-server`** + `redis-cli` | 2 | 18 |
| `cluster_real_server_test.rs` | **real 3-node Redis Cluster** + `redis-cli` | 1 | 5 |
| `cluster_redirect_bound_test.rs` | two NetGet servers that disagree about a slot | 1 | 2 |
| `resp_reader_test.rs` | none — bytes fed to `resp::read_reply` / `split_command` | 7 | 0 |
| `e2e_test.rs` | NetGet's own Redis server | 2 | 6 |
| `command_channel_test.rs` | NetGet's own Redis server | 1 | 0 |

## Running

`--test` names a **target**, not a module path — `--test client::redis::e2e_test` makes cargo
list its targets and exit having run nothing, and it exits 0, so it reads as a pass:

```bash
./cargo-isolated.sh test --no-default-features --features redis \
    --test client -- client::redis --test-threads=100
```

## `real_server_test.rs` — the evidence the rating rests on

The peer is the real C server (`redis-server`; Valkey on Homebrew, Redis on Ubuntu), spawned per
test by `tests/helpers/real_server.rs` on a probed loopback port with `--save "" --appendonly no`,
ready when it logs `Ready to accept connections`. State is read back with `redis-cli`. **It fails,
never skips,** when either binary is missing, naming `brew install valkey` /
`apt-get install redis-server redis-tools`.

### `redis_client_writes_reads_and_acts_on_a_reply_against_redis_server` (5 calls)

`redis_connected` → `SET netget:greeting "hello from the model"` (a quoted value with a space);
the `+OK` event (matched on `reply_type` `simple_string`) → `GET netget:greeting`; the bulk
reply event (matched on `reply_type` `bulk_string` **and** `value` containing the whole string)
→ `RPUSH netget:log "the model saw: <value>"`; the `:1` event (matched on `integer` and
`(integer) 1`) → nothing. Then `redis-cli GET` must print `hello from the model` and
`redis-cli LRANGE` must print `the model saw: hello from the model`.

### `redis_client_reads_an_array_reply_prepared_by_redis_cli` (4 calls)

`redis-cli HSET` writes a hash whose values contain a space and a real newline. The model sends
`HGETALL`; the reply reaches it as **one** `array` event, and it stores a summary computed from
the parsed array; `redis-cli GET` must print `4 elements; field2 has 9 chars`. A line-framed
reader would have split the newline-bearing value and got the count wrong.

### Why this is condition 4 of the client bar

The assertions are on the server's state, written by commands the model chose — one of them
built from a reply the model was shown. Verified by mutation: dropping the actions in the read
loop's `for action in actions` makes both tests fail while the mock still records its calls.
And the per-reply matchers are the regression test for the framing: under the old line reader
the bulk reply arrived as `"$20"` then `"hello from the model"`, neither of which matches.

No sleeps: the last mock rule in each test is the reply to the model's last command, so once
`wait_for_mocks` returns, the server has applied everything the model sent.

## `pubsub_real_server_test.rs` — pub/sub against a real server (8 + 10 calls)

Run once on RESP2 and once with `resp3: true`. A `redis-cli SUBSCRIBE netget:out` is started
first. On `redis_connected` the model subscribes to `netget:in` and the pattern
`netget:alerts.*`; the test waits until the real server's `PUBSUB NUMSUB` / `NUMPAT` show both,
then `redis-cli PUBLISH`es. Each message reaches the model as `redis_message_received`, matched
on `kind`, `channel`, `pattern` and `protocol` (the `pmessage` rule comes first, because
`"pmessage"` contains `"message"`), and the model answers with `redis_publish` to `netget:out`,
which the `redis-cli` subscriber must print — on RESP2 that publish goes over the side
connection, on RESP3 over the subscribed connection, whose `:1` replies are two more events. A
`bye` message makes the model `redis_unsubscribe` with no fields, and the real server's
`NUMSUB`/`NUMPAT` must drop to 0. Verified by mutation: discarding the model's actions, or not
recognising `pmessage`, fails it.

## `cluster_real_server_test.rs` — a real Redis Cluster (5 calls)

Three `redis-server --cluster-enabled yes` nodes (bus port via `--cluster-port`, so all three
run unprivileged on probed ports), joined with `redis-cli --cluster create … --cluster-yes`,
waited on until every node reports `cluster_state:ok` and three known nodes. The client
connects in cluster mode and loads the slot map. Then:

1. **Reshard**: the slot of `netget:moved` is moved to another node with Redis's own
   `CLUSTER SETSLOT … IMPORTING / MIGRATING / NODE` sequence (the slot is empty, so no
   `MIGRATE`), and the test waits until all three nodes agree. `SET netget:moved hello` is
   injected; the stale map sends it to the old owner, which answers `MOVED`; the reply event
   must carry `redirects` with `MOVED` and `node` = the new owner. The model writes that node
   into `netget:moved-via`, and `redis-cli` on the new owner (no `-c`) reads `hello`.
2. **Migration**: the slot of `netget:asked` is left `MIGRATING`/`IMPORTING`. The injected
   `SET netget:asked world` gets `ASK` from the owner; the client sends `ASKING` + `SET` to the
   importing node. `redis-cli` there must answer `ASKING` / `GET` with `OK` / `world`, and the
   model's `netget:asked-via` names the importing node.

Mutating the client to not follow `MOVED`, or to skip `ASKING`, fails it.

## `cluster_redirect_bound_test.rs` — the redirection bound (2 calls)

Two NetGet servers each say a slot belongs to the other, so they bounce a command forever. The
client must stop after `MAX_REDIRECTS` (5) and show the model the last `MOVED` with
`redirects_exhausted: true` and five entries in `redirects`; setting the bound to 6 fails the
test. The same test checks that a seed which is not a cluster node fails the connect. These
are NetGet's own servers, so this is a bound test, not interoperability evidence.

## `resp_reader_test.rs` — framing and bounds (0 calls)

A bulk string is one reply, CRLF inside it included; every RESP2 type and a pipeline of seven
replies; RESP3 map/set/push/boolean/double/big number/verbatim, and an attribute that is dropped
without counting as an element; `redis-cli`-compatible command splitting. And the bounds, each
verified by removing it:

- **depth** (`MAX_REPLY_DEPTH` 32): 10 000 × `*1\r\n` is refused. Without the bound the whole
  test binary aborts with `fatal runtime error: stack overflow` — the value is built iteratively
  but dropped recursively.
- **declared string length**: `$4294967295` and `$16777216` are refused before any allocation.
- **declared aggregate length**: `*1048577` is refused.

## `e2e_test.rs` and `command_channel_test.rs` — same-project

The peer is NetGet's own Redis server, so these show the two halves agree — circular evidence,
kept for what it does cover: `test_redis_client_connect_and_command_with_mocks` (3 calls) and
`test_redis_client_llm_controlled_commands_with_mocks` (3 calls) drive the client through a
server whose own mock is asserted too, and `command_channel_test` (0 calls) puts a command on the
wire through `AppState::send_to_client`, the dashboard's `[ send ]` path.

## What the mocks must get right

Answer `redis_response_received` with `execute_redis_command`, `wait_for_more`, `disconnect` or
nothing. A name the executor does not know is logged and nothing goes on the wire, which is easy
to mistake for success. Match on `reply_type` / `value`, not on raw RESP: the event carries the
parsed reply, never the bytes.

## Not covered

- **AUTH / SELECT.** The client declares no startup parameters, so a password or database index
  can only be sent as an explicit `execute_redis_command`.
- **RESP3 outside pub/sub** against a real server: `resp3: true` is driven only by the pub/sub
  test.
- **Cluster pub/sub** — refused in cluster mode.
- **Connect timeout.** A server that accepts and never speaks leaves the client waiting.
