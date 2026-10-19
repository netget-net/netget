# IMAP Client Implementation

## Overview

IMAP (Internet Message Access Protocol) client for email retrieval and management. Supports connecting to IMAP servers,
authenticating, selecting mailboxes, searching messages, and performing common email operations.

## Library Choice

**Primary:** `async-imap` v0.10+ with `tokio-native-tls`

**Rationale:**

- Mature async IMAP implementation
- Native Rust with Tokio async runtime
- Supports TLS/SSL (required for port 993)
- Good IMAP4rev1 compliance
- Simple API for common operations

**Dependencies:**

```toml
async-imap = "0.10"
tokio-native-tls = "0.3"
native-tls = "0.2"
```

## Architecture

### Connection Flow

1. **Connect:** Establish TCP connection to IMAP server
2. **TLS: NOT IMPLEMENTED.** This client speaks IMAP over a plain `TcpStream`; there is no
   TLS path at all. `use_tls: true` is **refused** at connect with a reason rather than
   silently downgraded — see below.
3. **Authenticate:** Login with username/password
4. **LLM Integration:** Call LLM with `imap_connected` event
5. **Action Loop:** Execute LLM-generated actions (select, search, fetch, etc.)

### State Machine

IMAP has three main states:

- **Not Authenticated:** After connection, before login
- **Authenticated:** After successful login, can select mailboxes
- **Selected:** After selecting a mailbox, can search/fetch messages

This implementation handles state transitions automatically:

- Connection → Authentication (handled in `connect_with_llm_actions`)
- Authentication → Selection (via `select_mailbox` action)
- Selection → Operations (search, fetch, mark, delete)

### LLM Integration

**Events Triggered:**

1. `imap_connected` - After successful authentication
2. `imap_mailbox_selected` - Mailbox name plus its `exists`/`recent` counts
3. `imap_search_results` - The criteria and the matching sequence numbers
4. `imap_message_fetched` - `subject`, `from` and `body` per message

The last three were declared here and in `get_event_types()` for a long time while nothing
raised them: each verb ran, logged, and told the model nothing, so the model got exactly one
turn on connect and then went deaf. `select_mailbox` could never be followed by `search_messages`,
and `fetch_message` read the body and dropped it on the floor. `get_event_types()` now returns
clones of the same statics the client emits, so a declaration cannot drift from what is raised.

**How the chaining is structured.** `apply_action` runs one verb and *returns* the event it
produced -- it never calls the LLM. `report_event` makes the call and feeds the answer back
through `execute_imap_action_at_depth`. That split is not stylistic: the recursion is real
(action -> event -> action), so the future is self-referential and has to go through a
`Pin<Box<dyn Future>>` or it fails to type-check with E0391. `MAX_FOLLOWUP_DEPTH` (8) bounds it,
because a model that answers `fetch_message` with `fetch_message` would otherwise loop on the
LLM forever. Bodies are capped with `truncate_for_llm` so one large message cannot dominate the
prompt.

On the injected path the follow-up event is reported from its own **registered** task rather
than inline, for the same reason the connect call is: a dashboard-created client defaults to a
`*` -> manual rule, and awaiting a parked call inside `command_loop` would wedge it far past the
dashboard's 30s send timeout on an action that in fact succeeded.

**Action Types:**

**Async Actions (User-Initiated):**

- `select_mailbox` - Select a mailbox (INBOX, Sent, etc.)
- `search_messages` - Search for messages (UNSEEN, FROM, SUBJECT, etc.)
- `fetch_message` - Fetch message by ID
- `mark_as_read` - Mark message as seen
- `mark_as_unread` - Remove seen flag
- `delete_message` - Mark for deletion and expunge
- `list_mailboxes` - List available mailboxes
- `disconnect` - Close IMAP connection

**Sync Actions (Response-Triggered):**

- `fetch_message` - Fetch messages from search results
- `wait_for_more` - Wait without taking action

### Dual Logging

All operations use dual logging:

- **Tracing macros:** `debug!`, `info!`, `trace!`, `error!` → `netget.log`
- **Status channel:** `status_tx.send()` → TUI display

**Log Levels:**

- `ERROR` - Authentication failures, connection errors
- `WARN` - (Not currently used)
- `INFO` - Connection, authentication, mailbox selection, message operations
- `DEBUG` - Action decisions, mailbox lists
- `TRACE` - Low-level protocol operations, search criteria

## Startup Parameters

IMAP client requires authentication credentials:

```json
{
  "username": "user@example.com",
  "password": "secret123",
  "use_tls": true
}
```

**Parameters:**

- `username` (required) - IMAP username
- `password` (required) - IMAP password
- `use_tls` (optional) - **Only `false` is accepted.** `true` is refused: this client has no
  TLS support, and connecting anyway would put the password on the wire in cleartext while
  reporting an encrypted session. This parameter was declared and read by nothing for a long
  time, and these docs claimed it worked; `tests/client/imap/use_tls_refusal_test.rs` pins the
  refusal so the claim cannot come back without the mechanism.

## Example Prompts

### Basic Connection

```
Connect to IMAP server at imap.gmail.com:993 with username test@gmail.com and password mypass, then fetch unread messages from INBOX
```

### Search and Read

```
Connect to imap.example.com:993, select INBOX, search for messages from alice@example.com, and mark them as read
```

### Mailbox Management

```
Connect to IMAP at mail.company.com:993, list all mailboxes, then select Sent and fetch the last 5 messages
```

## Limitations

### 1. Simplified RESP Parsing

The current implementation uses basic envelope parsing from `async-imap`. Complex MIME parsing is not fully implemented.

**Impact:** Message bodies are returned as raw strings, not parsed into structured parts.

**Workaround:** LLM can parse message text, but may struggle with complex multipart messages.

### 2. TLS Certificate Validation

Currently uses `danger_accept_invalid_certs(true)` for testing.

**Impact:** Vulnerable to MITM attacks.

**Production Fix:** Remove `danger_accept_invalid_certs` or make it configurable.

### 3. No IDLE Support

The implementation does not support IMAP IDLE (push notifications).

**Impact:** Cannot receive real-time notifications of new messages.

**Workaround:** Poll with periodic `search_messages` actions.

### 4. No OAuth2 Support

Only supports username/password authentication.

**Impact:** Cannot connect to Gmail/Outlook with app passwords disabled.

**Future:** Add OAuth2 flow support.

### 5. Synchronous Action Execution

Actions are executed sequentially, not concurrently.

**Impact:** Fetching multiple messages takes time.

**Future:** Implement concurrent fetch with Tokio spawn.

### 6. Error Recovery

Limited error handling for network failures or protocol errors.

**Impact:** Client may disconnect on errors without retry.

**Future:** Add reconnection logic and retry mechanisms.

## Testing Considerations

### E2E Testing

- Requires IMAP server (Docker with `greenmail/standalone` or similar)
- Test server should support plaintext auth for testing
- Use port 1143 (non-TLS) or 1993 (TLS) to avoid conflicts

### Security

- Never commit real credentials to tests
- Use environment variables or test servers with known credentials
- Clear test mailboxes before/after tests

### LLM Call Budget

Target < 10 LLM calls for E2E suite:

1. Connect and authenticate (1 call)
2. Select mailbox (1 call)
3. Search messages (1 call)
4. Fetch message (1 call)
5. Mark as read (1 call)
6. Delete message (1 call)

**Total:** ~6 LLM calls

## Known Issues

### 1. Session Type Complexity

`async-imap::Session` has complex type parameters due to dynamic trait objects.

**Workaround:** Use `Box<dyn AsyncRead + Unpin + Send>` for generics.

### 2. Lifetime Issues with Actions

Actions must be queued and executed in a loop to avoid holding locks across `.await` points.

**Solution:** Action queue pattern used in `spawn_action_executor`.

### 3. Envelope Parsing

Some IMAP servers may return envelopes in different formats.

**Workaround:** Gracefully handle missing envelope fields with `unwrap_or_default()`.

## Future Enhancements

1. **OAuth2 Authentication** - Support Google/Microsoft OAuth flows
2. **IDLE Support** - Real-time push notifications
3. **Concurrent Fetching** - Parallel message retrieval
4. **MIME Parsing** - Structured email part extraction
5. **Attachment Handling** - Download and manage attachments
6. **Folder Operations** - Create, delete, rename mailboxes
7. **Message Composition** - Draft creation (use SMTP for sending)
8. **Search Query Builder** - Helper for complex search criteria

## References

- [IMAP RFC 3501](https://tools.ietf.org/html/rfc3501)
- [async-imap Documentation](https://docs.rs/async-imap/)
- [IMAP Search Criteria](https://www.atmail.com/blog/imap-commands/)

### Dashboard injection (`[ send ]`)

`connect_with_llm_actions` registers a command channel and spawns `command_loop` **before**
the task that makes the `imap_client_connected` LLM call, which a manual `*` rule can park.

`command_loop` is a task of its own rather than a `select!` arm because there is nothing to
select against: `async_imap` owns the socket and this client has no read loop. It is also what
keeps the session usable after the connected-event handler returns — previously the session
was reachable only from inside that one task.

Injected actions go through `apply_action`, the same function the LLM path uses, so the
IMAP command encoding exists exactly once.

**Outcome semantics.** `async_imap` writes and reads the tagged command itself, so this loop can
honestly claim no byte count: a verb that ran reports
`Executed { detail: "<verb> completed (async_imap frames the tagged command, …)" }`. A verb the
server refused is an `Err`. An injected `disconnect` replies `Disconnected`, marks the client
disconnected and then does a **bounded** best-effort `LOGOUT` (5s) — unbounded, a server that
never answers would strand the task holding the client's command handle. Every exit removes the
handle.

Test: `tests/client/imap/command_channel_test.rs` (zero LLM calls). Note what its server config
documents: the IMAP server's greeting is **not** deterministic — without an `imap_connection`
handler it writes `* BYE` and hangs up — and the `imap_auth` rule must interpolate
`{{event.tag}}`, because `async_imap` picks its own tags and the server checks the tag rather
than substring-matching.

## Batching

Declared `BatchingMode::Unsupported`: nothing can arrive while the model is answering.
`async_imap` owns the socket, there is no IDLE, and every event is the result of the client's
own verb, reported (and answered) before the next verb runs.
