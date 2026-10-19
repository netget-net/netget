# SSH client and SFTP v3

`mod.rs` owns one authenticated russh 0.45 SSH connection. `actions.rs` exposes command
execution and read-only SFTP operations through the existing `ssh` client registration.
`sftp.rs` implements bounded SFTP v3 framing and typed replies; it does not use the
russh-sftp client session, whose packet reader allocates directly from a peer's length prefix
and starts detached session tasks.

## Authentication and ownership

`username` is required. Password authentication uses `password`; public-key authentication
loads the operator's OpenSSH key from `private_key_path`, optionally using
`private_key_passphrase`. When `auth_method` is absent, a key path selects public-key auth,
otherwise password auth is used. Keys and passwords are never included in events.

`host_key_sha256` accepts an independently trusted OpenSSH `SHA256:` fingerprint. A mismatch
fails during SSH key exchange. **Every SFTP operation requires this startup pin.** Legacy
command-only connections may omit it and accept any host key; that mode retains the prior
behavior and remains vulnerable to an active network attacker. There is no automatic
known_hosts lookup, TOFU, SSH agent, keyboard-interactive or certificate authentication.

The command channel is registered before `ssh_connected` is dispatched. One registered
owner polls both injected actions and owned `FuturesUnordered` sets of operations and event
handlers. A manual or model handler can park while other actions, including disconnect,
remain responsive. At most 16 operations and handlers exist in total; each operation reserves
its eventual handler slot. A handler may return at most 16 actions. Follow-up operations stop
after four levels, while disconnect remains usable at the bound.

russh starts an internal transport driver. A duplicate socket held by the registered owner
is shut down on drop, so removing the client closes that driver and its active channels.
Its channel queues are unbounded upstream and window credit is replenished before an
application read. The SSH handler therefore counts each owned channel's bytes and messages,
including ignored extended data and control messages, and ends the connection at its bound.
These callbacks run immediately after upstream enqueues the current message, so at most one
additional SSH packet (upstream's 256 KiB packet cap, checked before allocation) can exceed
the counter. Unsolicited server channels are refused. The counter map has at most 16 entries;
peer CLOSE releases an entry. These transport violations close the whole SSH connection.
Normal disconnect gives the driver up to one second to flush its SSH disconnect message.
Every operation closes its channel on success, framing failure or timeout; a blocked close
has a 250 ms grace period before the whole socket is shut down.

**Batching.** Operations run side by side and each result is asked about in its own handler,
so with batching off concurrent results mean concurrent model calls. With batching on (the
declared default) an `ssh_output_received` that finishes while any handler is asking the model
is held, and when a handler finishes everything held is answered in one call through
`call_llm_for_client_batch`, the newest the trigger, at the deepest follow-up depth among them.
SFTP results and operation failures are never held. A held output keeps its operation's slot in
the 16-operation bound until it is answered. `tests/client/ssh/batching_test.rs` drives both
against the unprivileged `sshd` the real-server test starts: three commands finishing at
different times, the first answered slowly, batching off as the control.

## Actions and events

| Action | Semantic result |
|---|---|
| `execute_command(command)` | `ssh_output_received`: stdout, optional stderr and exit status |
| `sftp_stat(path, follow_symlinks=false)` | `ssh_sftp_result`: supplied size, owners, permissions, type and timestamps; LSTAT by default, STAT when requested |
| `sftp_list_directory(path)` | `ssh_sftp_result`: entries containing names and typed attributes |
| `sftp_read_file(path, offset=0, length=65536)` | `ssh_sftp_result`: UTF-8 window, bytes_read and EOF flag |
| `disconnect` | Cancels operations and handlers and closes SSH |
| `wait_for_more` | No operation |

`ssh_connected` includes remote_addr, username and host_key_verified. An operation failure
becomes `ssh_operation_failed` with action_type, path or command and a local error. The shared
client dispatcher handles static/script/manual/model rules and AppState instruction/memory;
memory updates are saved before follow-up actions run. Unknown or invalid actions are rejected.

The three startup examples use the same trusted host-key pin and read-only directory listing:
an LLM instruction, an executable Python event handler, and static rules. Each disconnects
after a result or operation failure. Replace the example key path and independently trusted
fingerprint before connecting.

Command output preserves the prior lossy UTF-8 handling. EOF does not discard a later SSH
exit-status; the loop waits for status plus EOF, channel CLOSE or the end of the channel.
Injected operations report honest `Executed` details. They do not claim encrypted wire byte
counts (`Sent`), which russh does not expose.

## SFTP exchange and bounds

Each SFTP operation opens a fresh `sftp` subsystem channel and negotiates version 3. It sends
one request at a time and requires the exact response ID. OPEN is read-only. Handles stay
inside the operation and are closed after successful reads/listings; failures close the
channel. No local domain files, path store, binary action, upload/write or extension request
is implemented. The model sees attributes, entries and text, never packets or opaque handles.

The four-byte packet prefix is checked **before** allocating its buffer. Strings and counts
are checked against remaining bytes and their caps before copying or reserving collections.
Unknown packet types, attribute flags, status codes, trailing bytes and invalid UTF-8 names
fail the operation. VERSION and attribute extensions are bounded and ignored.

| Bound | Value |
|---|---|
| Resolution/TCP/SSH/authentication deadline | 10 s default; startup range 1..60 s |
| Whole command/SFTP operation deadline | 30 s default; startup range 1..300 s |
| SSH inactivity timeout | 300 s default; startup range 1..3600 s |
| Combined command stdout and stderr | 1 MiB |
| All SSH channel data/control payloads | 3 MiB per channel |
| SSH channel messages / channels awaiting peer CLOSE | 4096 / 16 |
| Command and SFTP path | 4096 bytes; SFTP paths must be nonempty and contain no NUL |
| SFTP packet payload | 64 KiB |
| Read request/data chunk | 32768 bytes |
| UTF-8 read window | 1 MiB maximum; offset+length must not overflow |
| Directory entries across all batches | 1024 |
| Empty directory batches before EOF | 16 |
| All received SFTP packet payloads per operation | 2 MiB |
| Handle / VERSION or attribute extension counts | 256 bytes / 64 extensions |

A read stops at the requested window or an explicit EOF. `eof=false` means the window filled
without observing EOF, even if it happened to reach the file's end. Arbitrary byte offsets
can cut a UTF-8 code point; such a window fails instead of exposing binary encoding to the
model. An empty directory batch is accepted and followed by another READDIR, with the cap
above preventing an unbounded no-progress loop.

## Evidence and maturity

Overall **Experimental** for the expanded surface. Prior command evidence remains in
`tests/client/ssh/real_server_test.rs`: independent OpenSSH commands selected by model
responses, stdout/stderr/exit status, rejected public key and bounded follow-up chaining.
`tests/client/ssh/sftp_test.rs` adds OpenSSH internal-sftp stat/list/chunked reads and response
follow-ups, host-key negatives, errors, bounds, active removal and direct NetGet pairing.
Tests fail when external peers are missing. See `tests/client/ssh/AGENTS.md` for exact probes.

Not claimed: a second independent SFTP server, pcap oracle, fuzz target, password auth against
a real external server, PTY, stdin streaming, SCP, forwarding, interactive shell or tunnels.

Wire reference: [SFTP v3 draft](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02).
