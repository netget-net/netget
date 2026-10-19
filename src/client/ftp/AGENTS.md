# FTP Client Implementation

## Overview

FTP client implementation that allows the LLM to connect to remote FTP servers, send commands, and interpret responses. The client handles the FTP control channel protocol.

## Architecture

### Control Channel Client

This implementation handles FTP control channel communication:
- Line-based request/response protocol
- Response code parsing (3-digit codes)
- Multiline response support (with `-` continuation)

### Connection Flow

1. LLM initiates connection via `open_client` action
2. Client connects to FTP server (typically port 21)
3. Server sends 220 greeting
4. LLM receives `ftp_response` event with greeting
5. LLM sends commands via `send_ftp_command` action
6. Server responses trigger `ftp_response` events
7. Session continues until QUIT or disconnect

## Library Choices

- **tokio**: Async TCP handling with `BufReader` for line-based reading
- **No external FTP library**: Manual protocol for full LLM control

## LLM Integration

### Events

| Event | Description | Parameters |
|-------|-------------|------------|
| `ftp_connected` | Connected to server | `remote_addr` |
| `ftp_response` | Response from server | `response`, `response_code` |

### Actions

| Action | Description | Parameters |
|--------|-------------|------------|
| `send_ftp_command` | Send FTP command | `command` |
| `wait_for_more` | Wait for more data | - |
| `disconnect` | Close connection | - |

### Common FTP Commands

- `USER <username>` - Set username
- `PASS <password>` - Set password
- `SYST` - Get system type
- `PWD` - Print working directory
- `CWD <path>` - Change directory
- `LIST` - List directory contents
- `RETR <file>` - Retrieve file
- `STOR <file>` - Store file
- `QUIT` - End session

## Dashboard injection (command channel)

The client registers `command_support::register_command_channel` **before** the `ftp_connected`
LLM call (a manual handler can park that call; `[ send_ftp_command ]` works throughout). Because
the read loop uses `BufReader::read_line`, which is not cancellation-safe, the channel is drained
by a separate task (playbook shape 2) that shares the `Arc<Mutex<WriteHalf>>`, registered with
`register_client_task` so stop/remove aborts it. `send_ftp_command` returns `SendData`, so the
generic `handle_stream_client_command` arm executes it; `disconnect` half-closes the write side
and the read loop's EOF path runs. The handle is removed on every loop exit. No `Custom`-result
gap. Proven with zero LLM calls in `tests/client/ftp/command_channel_test.rs`.

## Batching (what arrives while the model is answering)

The control channel is read on a registered task, one bounded-queue item per line (32). An
FTP server sends lines the client did not just ask for — the rest of a multi-line reply, a 226
after a 150, the replies to several commands sent in one answer — and those now wait in the
queue with their boundaries kept. With batching off each line is its own model call; with it
on everything waiting is one call through `call_llm_for_client_batch`, one `ftp_response`
event per line. Declared `BatchingMode::On`. This replaced an Idle/Processing/Accumulating
machine that could never leave Idle and cleared a queue nothing filled. A `disconnect` the
model returns now ends the session (it used to break only the loop over that answer's
actions), and the memory is copied out before the call instead of being borrowed under a
lock the success arm locks again. Test: `tests/client/ftp/batching_test.rs`.

## Limitations

1. **Control Channel Only**: No passive/active mode data channel
2. **No TLS**: FTPS not supported
3. **No Binary Transfers**: Text-only interaction
4. **Synchronous Commands**: One command at a time

## Example Usage

```
User: Connect to ftp.example.com and log in as anonymous to list files

LLM Response on ftp_connected:
- wait_for_more (wait for 220 greeting)

LLM Response on ftp_response (220 greeting):
- send_ftp_command("USER anonymous")

LLM Response on ftp_response (331):
- send_ftp_command("PASS guest@example.com")

LLM Response on ftp_response (230 logged in):
- send_ftp_command("LIST")

LLM Response on ftp_response (150 opening data connection):
- wait_for_more

LLM Response on ftp_response (226 transfer complete):
- send_ftp_command("QUIT")
- disconnect
```

## Testing

Test with FTP servers:
- Local netget FTP server
- vsftpd or proftpd
- Public anonymous FTP servers

## Bounded response reading (October 2026 review)

Response lines now use `client::response_reader::read_response_line`, sharing the
existing bounded line decoder. The 64 KiB cap includes the line terminator; a partial
line at EOF is an error. Oversized or incomplete replies are not forwarded as successful
responses.
Pure decoder tests are in `tests/client_review_regression_test.rs::text_responses`.

## Response completion deadlines (October 2026 follow-up)

Shared text readers allow an idle established connection to wait for its first response byte,
then enforce a 30-second absolute line-completion deadline. Dot-terminated bodies have a
30-second whole-response deadline in addition to their byte cap. NNTP greetings are bounded
from the first wait; HTTP CONNECT has a single deadline spanning status and headers. A framing
timeout is terminal because resuming an interrupted parse would misalign the stream.
