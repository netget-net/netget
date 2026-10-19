# NNTP Client Implementation

## Overview

The NNTP (Network News Transfer Protocol) client implementation provides LLM-controlled access to Usenet newsgroups.
NNTP is a text-based protocol defined in RFC 3977 (and earlier RFCs 977, 2980) used for reading and posting articles to
distributed discussion systems.

## Library Choices

**No external dependencies** - NNTP is implemented using:

- `tokio::net::TcpStream` for network I/O
- `tokio::io::BufReader` for line-based reading
- Manual protocol implementation (text-based commands)

This approach was chosen because:

1. **Simplicity**: NNTP is a simple text protocol similar to SMTP/IMAP
2. **No mature Rust crate**: No suitable high-level NNTP client library exists
3. **LLM control**: Direct protocol control allows the LLM to construct any command
4. **Lightweight**: No additional dependencies beyond tokio

## Architecture

### Connection Model

```
┌─────────────┐         TCP          ┌─────────────┐
│             │◄────────────────────►│             │
│  NetGet     │   Text Protocol      │   NNTP      │
│  NNTP Client│   (Commands/Replies) │   Server    │
│             │                      │   (Usenet)  │
└─────────────┘                      └─────────────┘
```

### Protocol Flow

1. **Connection**: TCP connection to server (default port 119)
2. **Welcome**: Server sends `200` (read/post) or `201` (read-only) greeting
3. **Commands**: Client sends text commands terminated by CRLF
4. **Responses**: Server sends status code + text, multi-line for some commands
5. **Multi-line Data**: Terminated by `.` on a line by itself

### State Machine

```
ConnectionState:
  Idle ──────► Processing ──────► Accumulating
    ▲               │                    │
    │               │                    │
    └───────────────┴────────────────────┘
```

- **Idle**: No LLM call in progress, ready to process new data
- **Processing**: LLM call in progress, queue new data
- **Accumulating**: LLM still processing, continue queuing

### Multi-line Response Handling

NNTP commands that return multi-line responses include:

- **LIST** (215): List of newsgroups
- **ARTICLE** (220): Full article (headers + body)
- **HEAD** (221): Article headers only
- **BODY** (222): Article body only
- **XOVER** (224): Article overview information

The client detects multi-line responses by status code and reads until it encounters a `.` terminator.

## LLM Integration

### Event Types

1. **nntp_connected**
    - Fired when connection established
    - Includes: `remote_addr`, `welcome_message`
    - LLM decides: Initial command (LIST, GROUP, etc.)

2. **nntp_response_received**
    - Fired for each server response
    - Includes: `status_code`, `response`, `command` (that triggered it)
    - LLM decides: Next command or action

### Actions

#### Async Actions (User-triggered)

- `nntp_group`: Select a newsgroup (GROUP command)
- `nntp_article`: Retrieve full article (ARTICLE command)
- `nntp_head`: Retrieve article headers (HEAD command)
- `nntp_body`: Retrieve article body (BODY command)
- `nntp_list`: List newsgroups (LIST command)
- `nntp_xover`: Get article overviews (XOVER command)
- `nntp_post`: Post a new article (POST command)
- `nntp_stat`: Get article status (STAT command)
- `nntp_quit`: Disconnect (QUIT command)

#### Sync Actions (Response-triggered)

- `nntp_group`: Select newsgroup in response to data
- `wait_for_more`: Wait for more data before responding

### Action Execution

Most actions are converted to `ClientActionResult::Custom` with command strings:

```json
{
  "name": "nntp_command",
  "data": {
    "command": "GROUP comp.lang.rust"
  }
}
```

The `nntp_post` action follows the proper NNTP POST protocol flow:

1. Send `POST` command
2. Article data (headers + body) is stored in pending state
3. Server responds with `340 Send article to be posted`
4. Article data is automatically sent (headers + body + terminator)
5. Server responds with `240 Article received ok` or error code

### Dashboard injection (`[ nntp_group ]`, `[ nntp_list ]`, … `[ nntp_quit ]`)

`p2p_support::connect` registers the client command handle and tracks the transport and event worker under the owning client. Its cancellation-safe Framer retains partial input across command selection. `Session::exchange` encodes each command and awaits its matching reply, including POST/340/article/final status; simple commands retain byte-count acknowledgements. Injected actions are recorded, and QUIT awaits 205 before closing. Owner removal aborts the transport and event tasks. See `tests/client/nntp/command_channel_test.rs` and `extensions_test.rs`.

## Response Codes

Common NNTP status codes:

- **200**: Server ready, posting allowed
- **201**: Server ready, posting not allowed
- **211**: Group selected (GROUP response)
- **215**: List of newsgroups follows (LIST response)
- **220**: Article retrieved (ARTICLE response)
- **221**: Headers retrieved (HEAD response)
- **222**: Body retrieved (BODY response)
- **224**: Overview information follows (XOVER response)
- **340**: Send article to be posted (POST intermediate)
- **411**: No such newsgroup
- **420**: Current article number is invalid
- **423**: No article with that number
- **430**: No article with that message-id
- **500**: Command not recognized
- **502**: Command not permitted

## Example Prompts

### List Available Newsgroups

```
Connect to NNTP at news.example.com:119 and list all newsgroups
```

LLM flow:

1. Receives `nntp_connected` event
2. Executes `nntp_list` action
3. Receives `nntp_response_received` with newsgroup list
4. Can parse and display results

### Read Articles from Group

```
Connect to NNTP at news.example.com:119, select comp.lang.rust, and retrieve the last 10 articles
```

LLM flow:

1. Receives `nntp_connected` event
2. Executes `nntp_group` with group_name="comp.lang.rust"
3. Receives `211` response with article range
4. Executes `nntp_xover` with range to get article list
5. Executes `nntp_article` for each article of interest

### Post Article

```
Connect to NNTP at news.example.com:119 and post a test article to test.misc
```

LLM flow:

1. Receives `nntp_connected` event
2. Executes `nntp_post` action with headers and body
3. POST command is sent, article data is stored pending 340 response
4. When 340 response is received, article is automatically transmitted
5. LLM receives final success (240) or error response

## Limitations

1. **Authentication**: AUTHINFO USER/PASS requires verified implicit TLS; SASL and STARTTLS are outside scope.
2. **Sequential Transactions**: Commands and MODE STREAM/CHECK/TAKETHIS feeds are processed one at a time.
3. **No Binary Decoding**: No yEnc or uuencode attachment codec is supplied.
4. **Response Parsing**: Status codes and bounded multiline responses are structured; specialized article/range fields remain response text.
5. **No Compression**: COMPRESS is outside scope.
6. **TLS**: `use_tls=true` validates certificates using public roots or an optional PEM `ca_path`; `server_name` selects the expected hostname.

## Future Improvements

STARTTLS, SASL, attachment codecs, pipelining, specialized header/overview parsing and automatic transient-error retries remain separate work.

## Testing

See `tests/client/nntp/AGENTS.md` for testing strategy.

## References

- RFC 3977: Network News Transfer Protocol (NNTP)
- RFC 2980: Common NNTP Extensions
- RFC 977: Original NNTP specification (obsoleted by RFC 3977)

## Bounded response reading (October 2026 review)

Response lines now use `client::response_reader::read_response_line`, sharing the
existing bounded line decoder. The 64 KiB cap includes the line terminator; a partial
line at EOF is an error. Oversized or incomplete replies are not forwarded as successful
responses.
Dot-terminated responses additionally have an 8 MiB aggregate cap, require an exact
`.` terminator and undo dot stuffing. A peer closing before that terminator is a
framing failure, avoiding POP3's former EOF loop and NNTP's partial-success result.
Pure decoder tests are in `tests/client_review_regression_test.rs::text_responses`.

## Response completion deadlines (October 2026 follow-up)

Shared text readers allow an idle established connection to wait for its first response byte,
then enforce a 30-second absolute line-completion deadline. Dot-terminated bodies have a
30-second whole-response deadline in addition to their byte cap. NNTP greetings are bounded
from the first wait; HTTP CONNECT has a single deadline spanning status and headers. A framing
timeout is terminal because resuming an interrupted parse would misalign the stream.

## October 2026 extensions

The client now uses sequential bounded command/reply transactions and reads multiline CAPABILITIES (101). POST awaits 340 before sending a validated, dot-stuffed article; IHAVE awaits 335; MODE STREAM/CHECK/TAKETHIS support sequential feeds with matching message IDs. AUTHINFO USER/PASS requires verified implicit TLS (`use_tls`, optional PEM `ca_path`, expected `server_name`). QUIT still reaches the wire, and existing simple-command byte-count acknowledgements are preserved. No STARTTLS, SASL, compression or pipelined feed scheduler is claimed.

Independent TLS/authentication/posting coverage uses nntpserver 0.0.3. Untrusted certificates must fail. See `tests/client/nntp/extensions_test.rs` and `tests/peers/README.md`.

Browser regression: after `./web/build.sh`, run `node web/test/nntp.mjs`. It drives both roles through capabilities, dot-stuffed POST, sequential TAKETHIS and QUIT over the browser’s virtual loopback; this is runtime coverage, not independent-peer interoperability evidence. Browser CI runs it beside the general bundle smoke test.

## Batching

Declared `BatchingMode::On`. Replies to the later commands of one answer queue while the model
answers an earlier one; the shared `server::p2p_support::connect` runner (also behind the adc,
adc_peer, dc_peer, gnutella, soulseek and soulseek_peer clients) drains everything waiting into
one `call_llm_for_client_batch` call. With batching off it answers one reply per call.
`tests/client_batching_test.rs::p2p_runner_answers_replies_that_arrived_during_a_call_together`
covers both, with off as the control. The runner logs each reply's arrival with
`record_access_log_only`, so the reply appears once in the session's history — written by the
model call with what answered it — rather than twice.
