# DynamoDB Client Implementation

## Overview

The DynamoDB client implementation provides LLM-controlled access to AWS DynamoDB or local DynamoDB instances (DynamoDB
Local, LocalStack). The LLM can execute DynamoDB operations and interpret responses.

## Implementation Details

### Library Choice

- **aws-sdk-dynamodb** - Official AWS SDK for Rust
- Supports all standard DynamoDB operations
- AWS Signature v4 authentication
- HTTP-based (uses TLS for AWS, optional for local)

### Architecture

```
┌──────────────────────────────────────────┐
│  DynamoDbClient::connect_with_llm_actions│
│  - Initialize AWS SDK config             │
│  - Store credentials/region/endpoint     │
│  - Mark as Connected                     │
└──────────────────────────────────────────┘
         │
         ├─► Operation Methods (PutItem, GetItem, etc.)
         │   - Build AWS SDK request
         │   - Execute via aws-sdk-dynamodb
         │   - Call LLM with response
         │   - Update memory
         │
         └─► Connected-event task (registered)
             - Asks the model once on connect
             - Runs whatever it answers through run_operation_once
```

(There is no background monitor task. One existed and was removed; this diagram outlived it.)

### Connection Model

Unlike TCP (persistent connection), DynamoDB client is **request/response** based:

- "Connection" = initialization of AWS SDK client with credentials
- Each operation is independent
- LLM triggers operations via actions
- Responses trigger LLM calls for interpretation

### LLM Control

**Async Actions** (user-triggered):

- `put_item` - Put an item into a table
    - Parameters: table_name, item (with DynamoDB types)
- `get_item` - Get an item by primary key
    - Parameters: table_name, key (with DynamoDB types)
- `query` - Query items using key conditions
    - Parameters: table_name, key_condition_expression, expression_attribute_values
- `scan` - Scan all items in a table
    - Parameters: table_name, filter_expression (optional), expression_attribute_values (optional)
- `update_item` - Update an item
    - Parameters: table_name, key, update_expression, expression_attribute_values
- `delete_item` - Delete an item
    - Parameters: table_name, key
- `disconnect` - Stop DynamoDB client

**Sync Actions** (in response to DynamoDB responses):

- `put_item` - Put another item based on response data
- `query` - Query based on response data

**Events:**

- `dynamodb_connected` - Fired when client initialized
- `dynamodb_response_received` - Fired when response received
    - Data includes: operation, success (boolean), data (optional), error (optional)

### Structured Actions (CRITICAL)

DynamoDB client uses **structured data with DynamoDB types**, NOT raw bytes:

```json
// PutItem action
{
  "type": "put_item",
  "table_name": "Users",
  "item": {
    "id": {"S": "user123"},
    "name": {"S": "Alice"},
    "age": {"N": "30"},
    "active": {"BOOL": true}
  }
}

// GetItem action
{
  "type": "get_item",
  "table_name": "Users",
  "key": {
    "id": {"S": "user123"}
  }
}

// Query action
{
  "type": "query",
  "table_name": "Users",
  "key_condition_expression": "id = :id",
  "expression_attribute_values": {
    ":id": {"S": "user123"}
  }
}

// Response event
{
  "event_type": "dynamodb_response_received",
  "data": {
    "operation": "get_item",
    "success": true,
    "data": {
      "table_name": "Users",
      "item": {
        "id": {"S": "user123"},
        "name": {"S": "Alice"},
        "age": {"N": "30"}
      }
    }
  }
}
```

### DynamoDB Type System

DynamoDB uses typed attributes:

- **S** - String
- **N** - Number (stored as string)
- **B** - Binary (base64-encoded)
- **BOOL** - Boolean
- **NULL** - Null value
- **SS** - String Set
- **NS** - Number Set
- **BS** - Binary Set
- **M** - Map (nested object)
- **L** - List (array)

The LLM constructs typed attribute maps, and NetGet converts them to AWS SDK types.

### Startup Parameters

- `region` (optional) - AWS region (default: "us-east-1")
    - Example: "us-west-2", "eu-west-1"
- `endpoint_url` (optional) - Custom endpoint for local testing
    - Example: "http://localhost:8000" (DynamoDB Local)
    - Example: "http://localhost:4566" (LocalStack)
- `access_key_id` (optional) - AWS access key ID
    - Defaults to environment variable AWS_ACCESS_KEY_ID
- `secret_access_key` (optional) - AWS secret access key
    - Defaults to environment variable AWS_SECRET_ACCESS_KEY

### Dual Logging

Operations log to `netget.log` through `tracing`, and **only failures** reach the status
stream, as one `Log` line that both sinks read:

```rust
Log::to(status_tx).error(format!(
    "DynamoDB client {} operation {} failed: {}",
    client_id, name, e
)); // → netget.log and the TUI
```

There is no per-operation success message on the status stream — a completed operation sends
`__UPDATE_UI__` and nothing else. This section used to show an
`info!("... PutItem to table ...")` / `status_tx.send("[CLIENT] DynamoDB PutItem succeeded")`
pair; neither line exists anywhere in the code.

### Error Handling

- **Connection**: `connect()` cannot currently fail. It marks the client `Connected` before
  anything has been verified, so a typo'd endpoint or an unreachable host still shows a
  healthy client and the first symptom is an operation failing later. This is the client-side
  form of "a server that lies about being up"; closing it wants one cheap probe during connect
- **Operation Failed**: logged, sent to the status stream, and returned to the injector as
  `ClientSendOutcome::Rejected` — *not* `Executed`, which is how it used to render, making a
  refusal indistinguishable from a completed write in the dashboard
- **Unconvertible attribute**: refused before the request is built, naming the attribute. It
  used to be dropped from the item silently and the write reported as successful
- **Authentication Failed**: AWS SDK handles authentication errors
- **LLM Error**: logged, and the command loop keeps accepting actions

## Features

### Supported Operations

- ✅ PutItem
- ✅ GetItem
- ✅ Query
- ✅ Scan
- ✅ UpdateItem
- ✅ DeleteItem
- ⏸ BatchGetItem (future)
- ⏸ BatchWriteItem (future)
- ⏸ TransactWriteItems (future)

### Authentication

- ✅ AWS credentials from environment variables — **only against AWS itself** (no
  `endpoint_url`, empty `remote_addr`). With a custom endpoint and no `access_key_id` /
  `secret_access_key` the connect is refused (`client::aws_support`): the SDK would otherwise
  sign requests to a model-settable host with the operator's ambient identity, and on EC2 or
  under an assumed role the session token rides along in `x-amz-security-token`. Any value
  works for a local emulator. `tests/client/dynamodb/ambient_credentials_test.rs`.
- ✅ `region` is validated before the SDK sees it (`client::aws_support::validate_region`):
  1–32 characters of `a-z`, `0-9` and `-`, not starting or ending with `-`. Without an
  endpoint the SDK builds the host as `dynamodb.` + region + `.amazonaws.com`, so a
  model-set `"region": "attacker.example/x"` would send requests signed with the ambient
  identity to `attacker.example`. Same test file.
- ✅ Explicit credentials via startup parameters
- ✅ Custom endpoint for local testing
- ✅ AWS Signature v4 (handled by SDK)

## Limitations

- **No Streaming** - Responses buffered in memory
- **No Pagination** - Large scans/queries return first page only
- **No Complex Types** - only `S`, `N`, `B`, `BOOL` and `NULL` convert. Maps (M), lists (L)
  and sets (SS/NS/BS) are **refused with an error naming the attribute**, not dropped: an
  unsupported attribute used to vanish from the item while the write reported success, and a
  `B` value whose base64 did not decode was written as an empty blob
- **No Batch Operations** - BatchGetItem/BatchWriteItem not implemented
- **No Transactions** - TransactWriteItems not implemented
- **No Streams** - DynamoDB Streams not supported

## Usage Examples

### Connect to DynamoDB Local

**User**: "Connect to DynamoDB Local at localhost:8000"

**Startup Parameters**:

```json
{
  "region": "us-east-1",
  "endpoint_url": "http://localhost:8000",
  "access_key_id": "fakeAccessKeyId",
  "secret_access_key": "fakeSecretAccessKey"
}
```

### PutItem

**User**: "Put a user with id=user123, name=Alice, age=30"

**LLM Action**:

```json
{
  "type": "put_item",
  "table_name": "Users",
  "item": {
    "id": {"S": "user123"},
    "name": {"S": "Alice"},
    "age": {"N": "30"}
  }
}
```

### GetItem

**User**: "Get the user with id=user123"

**LLM Action**:

```json
{
  "type": "get_item",
  "table_name": "Users",
  "key": {
    "id": {"S": "user123"}
  }
}
```

### Query

**User**: "Query all users with id=user123"

**LLM Action**:

```json
{
  "type": "query",
  "table_name": "Users",
  "key_condition_expression": "id = :id",
  "expression_attribute_values": {
    ":id": {"S": "user123"}
  }
}
```

### Scan with Filter

**User**: "Scan all users older than 21"

**LLM Action**:

```json
{
  "type": "scan",
  "table_name": "Users",
  "filter_expression": "age > :min_age",
  "expression_attribute_values": {
    ":min_age": {"N": "21"}
  }
}
```

### UpdateItem

**User**: "Update user123's age to 31"

**LLM Action**:

```json
{
  "type": "update_item",
  "table_name": "Users",
  "key": {
    "id": {"S": "user123"}
  },
  "update_expression": "SET age = :age",
  "expression_attribute_values": {
    ":age": {"N": "31"}
  }
}
```

### DeleteItem

**User**: "Delete user with id=user123"

**LLM Action**:

```json
{
  "type": "delete_item",
  "table_name": "Users",
  "key": {
    "id": {"S": "user123"}
  }
}
```

## Testing Strategy

See `tests/client/dynamodb/AGENTS.md` for E2E testing approach.

Recommended test setup:

- **DynamoDB Local** - Standalone Java application
    - Download: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html
    - Run: `java -Djava.library.path=./DynamoDBLocal_lib -jar DynamoDBLocal.jar -sharedDb`
    - Endpoint: http://localhost:8000
- **LocalStack** - AWS service emulator
    - Docker: `docker run -p 4566:4566 localstack/localstack`
    - Endpoint: http://localhost:4566

## Future Enhancements

- **Pagination** - Handle large result sets with pagination tokens
- **Batch Operations** - BatchGetItem, BatchWriteItem
- **Transactions** - TransactWriteItems, TransactGetItems
- **Complex Types** - Maps (M) and Lists (L) attribute types
- **TTL Support** - Time to Live attribute handling
- **Global Secondary Indexes** - Query GSIs
- **Conditional Operations** - ConditionExpression support
- **DynamoDB Streams** - Real-time change data capture

## Command channel (dashboard `[ send ]`)

`AppState::send_to_client` can inject an action into a running DynamoDB client.
`connect_with_llm_actions` registers the channel (`command_support::register_command_channel`)
and spawns a registered `command_loop` task in place of the old 5s "has this client been removed
yet" poll — dropping the client drops the handle and `recv()` returns `None` immediately.

**This closed a larger hole than the channel itself.** The client had no dispatcher at all:
`execute_action` advertised six verbs, `put_item` and `get_item` existed as standalone
functions nothing called, and `query`, `scan`, `update_item` and `delete_item` had no
implementation. `DynamoDbClient::execute_operation` is now the single dispatch point and all six
verbs are implemented against the SDK, so an advertised verb can no longer be silently swallowed.

Outcome semantics — the AWS SDK owns the socket and reports no wire byte count, so **`Sent` is
never returned**:

| Situation | `ClientSendOutcome` |
|---|---|
| `execute_action` refused it | `Rejected { error }` |
| Operation ran and the service answered | `Executed { detail: "put_item completed: {…}" }` |
| Operation ran and the service or the SDK failed | `Executed { detail: "put_item failed: …" }` |
| `disconnect` | `Disconnected` (loop ends, handle removed) |

The DynamoDB call itself is **awaited** in the loop, so the detail is a real result. The
`dynamodb_response_received` event is raised from its own registered task, so an event handler
that parks for a human answer cannot wedge the command loop.

**The `dynamodb_connected` event *is* raised**, from a registered task rather than inline so a
manual routing rule cannot block client creation, and whatever the model answers runs through
`run_operation_once`. (This paragraph used to say the opposite — that no connected event
exists and the LLM cannot drive this client at all.) What is still true is the shape of the
chain: `run_operation_once` raises no event, so a follow-up the model issues in reply to
`dynamodb_response_received` is the last step. That is the "non-notifying path" the root
`AGENTS.md` names, and the prescribed fix is a depth bound rather than silence.

**Where requests go.** `remote_addr` is the endpoint unless `endpoint_url` overrides it. It
used to be ignored outright, so a client aimed at `localhost:8000` with no explicit
`endpoint_url` had the SDK resolve `https://dynamodb.<region>.amazonaws.com` and sign with
whatever ambient credentials the machine had — real reads and writes against real AWS from a
client that looked local. All four startup parameters are declared optional and are now read
as optional; they were read with `get_string`, which errors on a missing key, so passing any
strict subset of them (`endpoint_url` alone, the documented local-testing case) failed the
connect with "Required string parameter 'region' is missing".

Tests: `tests/client/dynamodb/command_channel_test.rs` (no LLM, no AWS — the endpoint is a
loopback listener). Three tests, all running by default: the injected `put_item` path, that
`remote_addr` alone reaches the stub, and that an unsupported attribute type is refused rather
than dropped. The four tests in `e2e_test.rs` are all `#[ignore]`d **and drive
`aws_sdk_dynamodb` directly** — they never touch this client, so even un-ignored they would
prove things about the AWS SDK.

`tests/client/mod.rs` gates `pub mod dynamodb` on `any(feature = "dynamo", feature =
"dynamodb")`, so the directory compiles under either. (It used to say `dynamo` only, which was
wrong.) The genuine quirk is one level down: `tests/client/dynamodb/mod.rs` gates
`mod e2e_test` on `dynamo`, the **server** feature, so `--features dynamodb` alone compiles the
client tests without it.
