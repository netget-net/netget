# NVMe/TCP host tests

No LLM anywhere: python script handlers play the host's model (and, against NetGet's own
target, the target's), and the LLM endpoint is unreachable, so an event no handler answers
fails closed. LLM calls: zero.

## `e2e_test.rs` — against NetGet's own target (regression, not evidence)

| Test | What it pins |
|---|---|
| `the_host_runs_the_models_session_against_netgets_target` | discover → connect to the first entry → identify namespace → read → write → read back → SMART → flush → disconnect, each step the model's action; the discovery log's entries, the controller's identity and namespaces; exactly one discovery and one connect reached the target's model, with the host NQN, host ID and KATO the client configured |
| `statuses_hex_and_digests_reach_the_model` | CRC32C digests negotiated; hex reads; UNRECOVERED READ ERROR, NAMESPACE IS WRITE PROTECTED, LBA OUT OF RANGE by name; Identify Controller and the namespace list; an 8 KiB write (in the capsule) and its read back; Write Zeroes; an inactive namespace; the firmware slot log; a malformed action refused before the wire |
| `a_refused_connect_injected_actions_and_the_chain_bound` | CONNECT INVALID PARAMETERS (SUBNQN) reported, then a connect that works; a chain of Flushes stops at `MAX_FOLLOWUP_DEPTH`; an operator's injected read runs |
| `keep_alive_holds_an_idle_association_and_a_vanished_target_is_reported` | with KATO 1 s the association outlives 4.5 s of idleness (the target ends an association after KATO + 2 s without a command); stopping the target raises `nvme_tcp_disconnected` |
| `a_model_that_cannot_answer_sends_nothing` | no handler, unreachable model: nothing is connected |

## `real_server_test.rs` — the Linux kernel target

Linux, as root, in the `nvme-tcp` pair job: `nvmet` and `nvmet-tcp` configured through configfs
(`/sys/kernel/config/nvmet`) for each test — a subsystem with `attr_allow_any_host` 0, the
test's own host NQN in `allowed_hosts`, a namespace backed by a 4 MiB file the test wrote, and a
TCP port on 127.0.0.1 — and torn down in reverse when the test ends.

| Test | What it pins |
|---|---|
| `the_kernel_target_serves_the_models_session_from_its_backing_file` | nvmet's discovery log lists the subsystem; the whole session above against nvmet; the read is the file's bytes, and the model's write lands in the file |
| `the_kernel_target_with_digests_and_a_large_write` | CRC32C digests with nvmet; an 8 KiB write and read back; a read past the end refused by name, with no data; Identify Controller's SUBNQN; 7 s idle past a 5 s KATO with the association held by Keep Alive; the write in the backing file |
| `the_kernel_target_refuses_a_host_it_does_not_allow` | CONNECT INVALID HOST for a host not in `allowed_hosts` |

On failure each prints the configfs tree it made and the tail of `dmesg`.

nvmet taught two things the tests now encode: its discovery log lists itself first (as the
current discovery subsystem), so the session policy picks the first NVM subsystem; and its file
backend answers a read past the end with CAPACITY EXCEEDED rather than LBA OUT OF RANGE, and
takes the backing file system's block size (4096 on the VM), which the tests read rather than
assume.

## `spdk_target_test.rs` — SPDK's nvmf_tgt

Linux, in the `nvme-tcp` pair job, SPDK v26.09 built by `scripts/test-peers/build-spdk.sh`
(`NETGET_SPDK_DIR`): `nvmf_tgt --no-huge` configured through `scripts/rpc.py` (a TCP transport,
an AIO bdev over a 4 MiB file the test wrote, a subsystem with serial and model, listeners for it
and for the discovery service), then the whole session above — the discovery log, the
controller's serial and model, the file's bytes read and the model's write landing in the file.
On failure it prints nvmf_tgt's log.

Every test fails, never skips, when root, the modules, configfs or SPDK is missing.
