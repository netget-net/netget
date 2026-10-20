# Protocol Documentation

## CRITICAL: When to Use Server vs Client Mode

**Server Mode (open_server)** - Use when the user wants to HOST/SERVE content:
- Keywords: "serve", "host", "listen", "start a server", "create a server", "run a server", "open server", "provide", "respond to"
- You LISTEN on a port and RESPOND to incoming requests
- User wants to PROVIDE a service that others connect to
- Examples: "host a website", "start HTTP server", "create DNS server", "run FTP server"

**Client Mode (open_client)** - Use when the user wants to CONNECT to an existing remote server:
- Keywords: "connect to", "fetch from", "query", "access", "call", "request from", "get from", "send to", "send a"
- You CONNECT to a remote server and SEND requests to it
- User wants to ACCESS a service that someone else is running
- Examples: "connect to Redis at localhost:6379", "fetch from API", "query database"

**⚠️ IMPORTANT**: If the user says "serve", "host", or "provide" content, use `open_server` even if they mistakenly say "client".
The ACTION (serving content) matters more than the word choice.

---

# SSH (Server Mode)

**Mode:** Server - listens for incoming connections
**Stack:** ETH>IP>TCP>SSH
**Group:** Core
**Maturity:** Beta
**Privilege required:** Privileged port 22 (requires root or capabilities)
**Port:** omit `port` to listen on the well-known port 22 (tcp). If this process cannot bind it (below 1024 without privilege, or already in use) the server starts on an OS-assigned port and the result says so. An explicit port, `0` included, is used as given.
**When the model cannot answer:** answers — the peer gets the protocol's own error reply carrying a category (overloaded or unavailable), never an invented success and never the error text
**History:** the model is shown up to 40 earlier exchanges on the same connection with each event, within a 4 KB budget (pass `history` to change it; 0 turns it off)
**Batching:** on by default — events arriving while the model is answering are delivered together in one follow-up call (pass `batching: false` to answer each separately)

## Description

Secure shell server for remote access

## Example Prompt

Pretent to be a shell via SSH on port 2222

## Keywords

ssh

## Notes

FAILS CLOSED: an LLM error, a handler that returns no ssh_auth_decision, and a malformed decision all deny, logged as decision=fail_closed_* and never as decision=model_reject. Shell and SFTP only: no port forwarding, no X11, no keyboard-interactive. SFTP is read-only (write/remove/mkdir/rmdir/rename are not implemented) and serves no real filesystem — every listing, stat and byte comes from the model. Host key is regenerated on every start, so clients warn about a changed key. Shell output has \n rewritten to \r\n on EVERY path, including the one-shot exec channel where no PTY exists and a real sshd would not translate - so `ssh host cmd` returns CRLF and `$(ssh host cmd)` keeps a trailing CR.

### Starting this Protocol

**LLM Mode** (LLM handles all responses intelligently):
```json
{
  "type": "open_server",
  "protocol": "ssh",
  "instruction": "SSH server providing secure shell access"
}
```

**Script Mode** (code-based deterministic responses):
```json
{
  "type": "open_server",
  "protocol": "ssh",
  "event_handlers": [
    {
      "event_pattern": "ssh_shell_command",
      "handler": {
        "type": "script",
        "language": "python",
        "code": "import json, sys\ndata = json.load(sys.stdin)\nevent = data[\"event\"]\nif data[\"event_type_id\"] == \"ssh_shell_command\":\n    actions = [{\"type\": \"ssh_shell_response\", \"response\": \"command not found\\n\"}]\nelse:\n    actions = []\nprint(json.dumps({\"actions\": actions}))"
      }
    }
  ]
}
```

**Static Mode** (fixed, unchanging responses):
```json
{
  "type": "open_server",
  "protocol": "ssh",
  "event_handlers": [
    {
      "event_pattern": "ssh_auth",
      "handler": {
        "type": "static",
        "actions": [
          {
            "type": "ssh_auth_decision",
            "allowed": true
          }
        ]
      }
    }
  ]
}
```

## Events (`ssh_auth`, `ssh_banner`, `ssh_shell_command`, `sftp_operation`) — valid `event_pattern` values for event handlers

### `ssh_auth`

A client is trying to authenticate. You must answer with ssh_auth_decision: anything else, including an error, is treated as a denial. The client may retry with a different method or username, so expect this event more than once per connection.

Event data fields (a script reads these as `data['event'][…]`):

- `username` (string, **required**) — Username the client is attempting to log in as
- `auth_type` (string, **required**) — Authentication method, exactly "password" or "publickey". Match on this value in a script or static handler
- `password` (string, optional) — The password the client sent, in the clear. Present only when auth_type is "password"; absent for "publickey". The key itself is verified by the SSH transport and is not exposed here, so for publickey you are deciding on the username alone

Respond with: `ssh_auth_decision`

Example handler response:

```json
{
  "actions": [
    {
      "type": "ssh_auth_decision",
      "allowed": true
    }
  ]
}
```

### `ssh_banner`

A shell session just opened, after successful authentication and before the user has typed anything. Answer with ssh_send_banner to greet them, or return nothing for a silent login.

Event data: (no documented fields)

Respond with: `ssh_send_banner`

Example handler response:

```json
{
  "actions": [
    {
      "type": "ssh_send_banner",
      "banner": "Welcome to NetGet SSH Server!\n"
    }
  ]
}
```

### `ssh_shell_command`

The user pressed Enter (or a control key) in an SSH shell, or ran a one-shot command with `ssh host <command>`. Answer with ssh_shell_response. The server echoes typed characters and writes a "$ " prompt after your output on its own, so do not include a prompt unless you want a second one.

Event data fields (a script reads these as `data['event'][…]`):

- `command` (string, **required**) — The line the user typed, including the trailing newline, or the whole command line for `ssh host <command>`. Control characters such as Ctrl-C (0x03) appear here literally; the flags below are the reliable way to detect them
- `first_input` (boolean, **required**) — True on the first Enter of this shell session. Useful for printing a message-of-the-day or the initial prompt
- `empty_input` (boolean, **required**) — True when the user pressed Enter on an empty line. Return an empty response - the server prints the prompt itself
- `control` (array, **required**) — Names of the control keys present in this input, as strings: "ctrl_c" (interrupt), "ctrl_d" (end of file - usually means log out), "ctrl_z" (suspend). Empty for ordinary commands

Respond with: `ssh_shell_response`, `close_this_connection`

Example handler response:

```json
{
  "actions": [
    {
      "type": "ssh_shell_response",
      "response": "/home/user\n"
    }
  ]
}
```

### `sftp_operation`

An SFTP client asked for a filesystem operation. You are the filesystem: nothing is read from or written to disk, so invent a consistent virtual tree and keep it in memory across operations. Answer with exactly one reply action, chosen by 'operation': opendir/open -> sftp_handle, readdir -> sftp_directory_listing, read -> sftp_file_content, lstat/fstat -> sftp_file_attributes. Any operation may instead be refused with sftp_error.

Event data fields (a script reads these as `data['event'][…]`):

- `operation` (string, **required**) — Which request this is: "opendir", "readdir", "open", "read" or "lstat". A client's fstat is resolved to the handle's path and arrives as "lstat"; close and realpath are answered by the server and never reach you
- `path` (string, **required**) — Absolute path being operated on. For handle-based operations (readdir, read, fstat) this is the path the handle was opened with, resolved for you
- `handle` (string, optional) — The open handle this request refers to. Present for readdir, read and fstat; absent for opendir, open and lstat
- `offset` (number, optional) — Byte offset the client wants to read from ('read' only). Informational - return the whole file in sftp_file_content and the server slices it
- `length` (number, optional) — Number of bytes the client wants ('read' only). Informational, as for 'offset'

Respond with: `sftp_handle`, `sftp_directory_listing`, `sftp_file_content`, `sftp_file_attributes`, `sftp_error`

Example handler response:

```json
{
  "actions": [
    {
      "type": "sftp_directory_listing",
      "entries": [
        {
          "name": "readme.txt",
          "is_dir": false,
          "size": 24
        }
      ]
    }
  ]
}
```

## Response Actions

The action objects that answer an event — what you, a script (inside `{"actions":[…]}`) or a static handler (`handler.actions`) return.

### `send_ssh_data`

Write text to the client's terminal on the current shell channel. This is a lower-level alias for ssh_shell_response and behaves identically, including the \n -> \r\n conversion; prefer ssh_shell_response when answering a command. This is NOT a way to send raw SSH protocol bytes - the transport is encrypted by the server and you never see or write wire-level SSH packets.

Parameters:

- `data` (string, **required**) — Text for the terminal. Bare \n is converted to \r\n before sending, so you may write either

```json
{
  "type": "send_ssh_data",
  "data": "connection reset by peer\n"
}
```

### `wait_for_more`

Send nothing and wait for the client's next input line. The shell reads one line at a time, so this simply means 'no output for this command'. Note the server still writes its own "$ " prompt afterwards.

Parameters: none.

```json
{
  "type": "wait_for_more"
}
```

### `close_this_connection`

End the shell session on the channel that raised this event: sends exit status 0, then EOF, then closes the channel. Use it for 'exit', 'logout' or Ctrl-D. Emit any farewell text with ssh_shell_response in the same response, before this action.

Parameters: none.

```json
{
  "type": "close_this_connection"
}
```

### `sftp_handle`

Answer an SFTP 'open' or 'opendir' request by granting a handle for the path. The handle is an opaque string you choose; the client passes it back on every later read/readdir/close for that file or directory, and the server remembers which path it stood for. Reply with sftp_error instead if the path should not exist.

Parameters:

- `handle` (string, optional) — Opaque identifier for this open file or directory. Must be unique among currently-open handles on this session. If omitted, the requested path is used as the handle

```json
{
  "type": "sftp_handle",
  "handle": "dir-1"
}
```

### `sftp_directory_listing`

Answer an SFTP 'readdir' request with the full contents of the directory. Send every entry in one response - the server reports end-of-directory on the next readdir for the same handle, so a second call will not be made. An empty 'entries' array is a valid empty directory.

Parameters:

- `entries` (array, **required**) — Array of objects, one per directory entry. 'name' (string, the bare file name with no path) is required; an entry without it is dropped. 'is_dir' (boolean, default false) and 'size' (number of bytes, default 0) are optional but should be set - clients display them, and 'size' should match what sftp_file_attributes reports for the same file. Permissions are derived from 'is_dir' (0755 for directories, 0644 for files)

```json
{
  "type": "sftp_directory_listing",
  "entries": [
    {
      "name": "readme.txt",
      "is_dir": false,
      "size": 24
    },
    {
      "name": "logs",
      "is_dir": true,
      "size": 4096
    }
  ]
}
```

### `sftp_file_content`

Answer an SFTP 'read' request with the contents of the file. IMPORTANT: return the WHOLE file every time, not the slice the request asked for - the server applies the request's offset and length for you. Keep the content consistent with the 'size' you reported from sftp_file_attributes for the same path, otherwise the client's download will be truncated or will not terminate.

Parameters:

- `content` (string, **required**) — The complete file contents as text. Binary files cannot be served: the string's UTF-8 bytes are what the client receives

```json
{
  "type": "sftp_file_content",
  "content": "Hello from NetGet SFTP!\n"
}
```

### `sftp_file_attributes`

Answer an SFTP 'lstat' or 'fstat' request with the metadata of a path. Clients call this before downloading to learn the file size, so 'size' must match the length of what sftp_file_content will return for the same path. Reply with sftp_error instead if the path should not exist.

Parameters:

- `size` (number, **required**) — File size in bytes. Must equal the byte length of the 'content' you would return for this path
- `is_dir` (boolean, **required**) — True if this path is a directory. Sets the directory bit in the reported mode, which is what makes `ls` and `cd` treat it as one
- `permissions` (number, optional) — Optional Unix mode as a decimal number (e.g. 420 for 0644, 493 for 0755). Defaults to 0644, with the directory bit added when is_dir is true

```json
{
  "type": "sftp_file_attributes",
  "size": 24,
  "is_dir": false
}
```

### `sftp_error`

Fail the SFTP request with an error status. Use this for paths that should not exist, permission denials, and operations you do not want to support. Returning no action at all also fails the request, but with a less specific status - prefer this so the client shows the right message.

Parameters:

- `code` (string, optional) — One of: "no_such_file" (the default, for a path that does not exist), "permission_denied", "failure" (generic), "op_unsupported", or "eof". Any other value is treated as "failure"

```json
{
  "type": "sftp_error",
  "code": "no_such_file"
}
```


---

# ssh (Client Mode)

**Mode:** Client - connects to remote servers
**Stack:** ETH>IP>TCP>SSH
**Group:** Network Infrastructure
**Maturity:** Experimental
**Privilege required:** None
**History:** the model is shown up to 40 earlier exchanges on the same connection with each event, within a 4 KB budget (pass `history` to change it; 0 turns it off)
**Batching:** on by default — events arriving while the model is answering are delivered together in one follow-up call (pass `batching: false` to answer each separately)

## Description

SSH commands and pinned SFTP v3 stat, directory listing and UTF-8 file reads

## Startup Parameters

Passed as `startup_params`; a key not listed here is an error.

- `username` (string, **required**) — SSH account used to authenticate this connection Example: `"user"`
- `password` (string, optional) — Password for password authentication Example: `"password"`
- `private_key_path` (string, optional) — Operator's OpenSSH private-key file; read only at connect Example: `"/home/user/.ssh/id_ed25519"`
- `private_key_passphrase` (string, optional) — Passphrase for the private key Example: `"passphrase"`
- `auth_method` (string, optional) — password or publickey; defaults to publickey when private_key_path is set Example: `"publickey"`
- `host_key_sha256` (string, optional) — Trusted OpenSSH SHA256: host-key fingerprint. Required for SFTP; when supplied a mismatch fails the SSH handshake Example: `"SHA256:<trusted fingerprint>"`
- `handshake_timeout_secs` (number, optional, default: `10`) — Resolution, TCP, SSH handshake and authentication deadline, 1..60 seconds Example: `10`
- `operation_timeout_secs` (number, optional, default: `30`) — Whole command or SFTP exchange deadline, 1..300 seconds Example: `30`
- `idle_timeout_secs` (number, optional, default: `300`) — SSH inactivity deadline, 1..3600 seconds Example: `300`

## Example Prompt

Connect with a trusted SHA256 host-key pin and list /reports over SFTP

## Keywords

ssh, secure shell, sftp, connect to ssh

## Notes

SFTP requires an explicit SHA256 host-key pin. Command-only legacy sessions without a pin accept the peer key and are vulnerable to active attackers. SFTP packets 64 KiB, paths 4 KiB, read windows 1 MiB, directories 1024 entries and 16 empty batches, whole response budget 2 MiB; 16 total active operations/handlers. SSH stdout/stderr 1 MiB combined; channel payload 3 MiB and 4096 messages, at most 16 channels until peer CLOSE. A transport bound closes SSH; callback checks may include one extra upstream packet capped at 256 KiB. No SFTP writes, binary file action, protocol extensions, known_hosts, SSH agent, keyboard-interactive, certificate auth, PTY or forwarding. Experimental: no second independent SFTP server, pcap oracle or fuzz target

## Events (`ssh_connected`, `ssh_output_received`, `ssh_sftp_result`, `ssh_operation_failed`) — valid `event_pattern` values for event handlers

### `ssh_connected`

SSH session authenticated

Event data fields (a script reads these as `data['event'][…]`):

- `remote_addr` (string, **required**) — Remote SSH server
- `username` (string, **required**) — Authenticated username
- `host_key_verified` (boolean, **required**) — Whether the configured SHA256 host-key pin matched

Respond with: `execute_command`, `sftp_stat`, `sftp_list_directory`, `sftp_read_file`, `disconnect`, `wait_for_more`

Example handler response:

```json
{
  "actions": [
    {
      "type": "wait_for_more"
    }
  ]
}
```

### `ssh_output_received`

SSH command completed

Event data fields (a script reads these as `data['event'][…]`):

- `command` (string, **required**) — Executed command
- `output` (string, **required**) — Captured standard output from the completed command
- `stderr` (string, optional) — Command stderr when present
- `exit_code` (number, optional) — Exit status when supplied by the peer

Respond with: `execute_command`, `sftp_stat`, `sftp_list_directory`, `sftp_read_file`, `disconnect`, `wait_for_more`

Example handler response:

```json
{
  "actions": [
    {
      "type": "wait_for_more"
    }
  ]
}
```

### `ssh_sftp_result`

SFTP v3 operation completed

Event data fields (a script reads these as `data['event'][…]`):

- `operation` (string, **required**) — stat, list_directory or read_file
- `path` (string, **required**) — Remote file or directory path selected for SFTP
- `attributes` (object, optional) — File size, permissions, type, owners and timestamps when supplied
- `entries` (array, optional) — Directory entries with name and typed attributes
- `offset` (number, optional) — Read window start
- `bytes_read` (number, optional) — Bytes in the UTF-8 window
- `eof` (boolean, optional) — Whether the server reported EOF before the window filled
- `text` (string, optional) — UTF-8 file window

Respond with: `execute_command`, `sftp_stat`, `sftp_list_directory`, `sftp_read_file`, `disconnect`, `wait_for_more`

Example handler response:

```json
{
  "actions": [
    {
      "type": "wait_for_more"
    }
  ]
}
```

### `ssh_operation_failed`

SSH command or SFTP operation failed

Event data fields (a script reads these as `data['event'][…]`):

- `action_type` (string, **required**) — Name of the rejected SSH or SFTP action
- `path` (string, optional) — Remote path for SFTP
- `command` (string, optional) — Command for exec
- `error` (string, **required**) — Transport, status, framing or local validation error

Respond with: `execute_command`, `sftp_stat`, `sftp_list_directory`, `sftp_read_file`, `disconnect`, `wait_for_more`

Example handler response:

```json
{
  "actions": [
    {
      "type": "wait_for_more"
    }
  ]
}
```

## Response Actions

The action objects that answer an event — what you, a script (inside `{"actions":[…]}`) or a static handler (`handler.actions`) return.

### `execute_command`

Execute a shell command; bounded stdout/stderr and exit status become ssh_output_received

Parameters:

- `command` (string, **required**) — Shell command, 1..4096 bytes

```json
{
  "type": "execute_command",
  "command": "pwd"
}
```

### `sftp_stat`

Inspect remote file or directory attributes using pinned SFTP v3

Parameters:

- `path` (string, **required**) — Remote path, 1..4096 bytes without NUL
- `follow_symlinks` (boolean, optional) — Use STAT instead of LSTAT; default false

```json
{
  "type": "sftp_stat",
  "path": "/reports"
}
```

### `sftp_list_directory`

List a remote directory, at most 1024 entries, with typed attributes

Parameters:

- `path` (string, **required**) — Remote directory, 1..4096 bytes without NUL

```json
{
  "type": "sftp_list_directory",
  "path": "/reports"
}
```

### `sftp_read_file`

Read a bounded UTF-8 window from a remote file; no local file is created

Parameters:

- `path` (string, **required**) — Remote path, 1..4096 bytes without NUL
- `offset` (number, optional) — Unsigned starting byte offset, default 0
- `length` (number, optional) — Maximum bytes, 1..1048576, default 65536

```json
{
  "type": "sftp_read_file",
  "path": "/reports/today.txt",
  "offset": 0,
  "length": 65536
}
```

### `disconnect`

Disconnect SSH and cancel every command, SFTP operation and response handler

Parameters: none.

```json
{
  "type": "disconnect"
}
```

### `wait_for_more`

Take no action and wait for another result

Parameters: none.

```json
{
  "type": "wait_for_more"
}
```


---

## Enabled Actions

**⚠️ BEFORE CHOOSING**: Re-read the user's request. What do they want to DO?
- If they want to SERVE/HOST/PROVIDE content → use `open_server`
- If they want to CONNECT TO/FETCH FROM a remote server → use `open_client`
- The ACTION matters, not the words. "serve recipes" = server, even if user says "client"

### open_server (For SERVING content)

Use when: User wants to HOST content, SERVE data, LISTEN for connections, or PROVIDE a service. `open_server` is now enabled for the protocols above. Leave `port` out to listen on the protocol's well-known port (its **Port** line above); give one only when the user names it.

**Example for ssh server:**
```json
{
  "type": "open_server",
  "protocol": "ssh",
  "instruction": "Handle incoming requests"
}
```

### open_client (For CONNECTING to remote servers)

Use when: User wants to CONNECT TO an existing server, FETCH data, QUERY a database, or ACCESS a remote service. `open_client` is now enabled for the protocols above. `remote_addr` is the `host:port` the user names; the examples use the protocol's well-known port on this machine.

**Example for ssh client:**
```json
{
  "type": "open_client",
  "protocol": "ssh",
  "remote_addr": "127.0.0.1:22",
  "instruction": "Connect and interact"
}
```

