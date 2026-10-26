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

## `auth_commands_test.rs` — DH-HMAC-CHAP and the new actions against NetGet's own target (regression)

| Test | What it pins |
|---|---|
| `the_host_authenticates_both_ways_and_runs_the_new_commands` | sha512/ffdhe3072 both ways, named in the connect result (which holds no secret); compare (match and COMPARE FAILURE), verify (good and UNRECOVERED READ ERROR), copy (read back as hex), COMMAND SIZE LIMIT EXCEEDED; register, acquire, report (type, registrants, key, held), a conflicting acquire, clear; three decisions reached the target's model; a malformed reservation action refused before the wire |
| `a_wrong_secret_or_a_controller_that_cannot_prove_itself_is_refused` | the target refuses a wrong host secret; the host refuses a controller secret it does not hold (the target logs AUTH_Failure2); no secret against ATR; an open subsystem connects without authenticating; a malformed secret or a controller secret alone refuse to start |

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
| `the_host_authenticates_to_the_kernel_target` | nvmet configured through the host's `dhchap_key`, `dhchap_ctrl_key`, `dhchap_hash`, `dhchap_dhgroup` with secrets from `nvme gen-dhchap-key`: sha256/null one way, sha512/ffdhe4096 and sha384/ffdhe8192 both ways, the connect result naming what nvmet chose; then the whole session, the write landing in the file |
| `the_kernel_target_refuses_a_wrong_secret_and_the_host_refuses_a_wrong_controller` | a wrong host secret: refused, nvmet logs `host response mismatch`; a controller secret nvmet does not hold: the host refuses it and nvmet logs the fatal error AUTH_Failure2 causes; no secret against ATR |
| `the_host_reserves_on_the_kernel_target_which_has_no_compare_verify_or_copy` | a `resv_enable` namespace: register, acquire with the wrong key (RESERVATION CONFLICT) and the right one, nvmet's report (type, one registrant, key, held), replace, release, clear, an empty report; nvmet implements neither Compare, Verify nor Copy and the host reports INVALID COMMAND OPCODE for each |

On failure each prints the configfs tree it made and the tail of `dmesg`.

nvmet taught two things the tests now encode: its discovery log lists itself first (as the
current discovery subsystem), so the session policy picks the first NVM subsystem; and its file
backend answers a read past the end with CAPACITY EXCEEDED rather than LBA OUT OF RANGE, and
takes the backing file system's block size (4096 on the VM), which the tests read rather than
assume.

## `spdk_target_test.rs` — SPDK's nvmf_tgt

Linux, in the `nvme-tcp` pair job, SPDK v26.09 built by `scripts/test-peers/build-spdk.sh`
(`NETGET_SPDK_DIR`): `nvmf_tgt --no-huge` configured through SPDK's own rpc.py (a TCP transport,
an AIO bdev over a 4 MiB file the test wrote, a subsystem with serial and model, listeners for it
and for the discovery service), then the whole session above — the discovery log, the
controller's serial and model, the file's bytes read and the model's write landing in the file.
On failure it prints nvmf_tgt's log. Every nvmf_tgt runs with `--disable-cpumask-locks`, so the
three tests can each start one on core 0 at once.

| Test | What it pins |
|---|---|
| `spdk_nvmf_tgt_serves_the_models_session_from_its_backing_file` | the session above |
| `spdk_nvmf_tgt_and_the_host_authenticate_each_other` | `keyring_file_add_key` and `nvmf_subsystem_add_host --dhchap-key --dhchap-ctrlr-key` with secrets from `nvme gen-dhchap-key`: nvmf_tgt picks sha512/ffdhe8192 and both sides prove themselves, then the session, the write in the file; a wrong host secret refused by nvmf_tgt, a controller secret nvmf_tgt does not hold refused by the host |
| `spdk_nvmf_tgt_compares_verifies_copies_and_reserves` | Compare match and COMPARE FAILURE; nvmf_tgt's own Copy limits read from Identify Namespace (one range, 263 blocks), two copies landing in the file and one range past MSRC refused by nvmf_tgt; Verify, which nvmf_tgt answers INVALID COMMAND OPCODE; register, acquire Exclusive Access - Registrants Only, nvmf_tgt's report, release with the wrong type (INVALID FIELD, as NetGet's target also answers), clear |

Every test fails, never skips, when root, the modules, configfs or SPDK is missing.
