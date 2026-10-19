# VNC Client Implementation

## Overview

The VNC client implementation provides LLM-controlled connections to VNC (Remote Framebuffer) servers. The LLM can
control mouse movement, keyboard input, request screen updates, and interact with remote desktops.

## Implementation Details

### Library Choice

- **Custom RFB protocol implementation** - No external VNC library
- Direct TCP connection with manual RFB (Remote Framebuffer) protocol handling
- Simplified implementation supporting essential VNC operations

### Architecture

```
┌────────────────────────────────────────┐
│  VncClient::connect_with_llm_actions   │
│  - Connect to VNC server               │
│  - Perform RFB handshake               │
│  - Authenticate (None or VNC auth)     │
│  - Receive ServerInit (dimensions)     │
│  - Spawn read loop for server msgs     │
└────────────────────────────────────────┘
         │
         ├─► Handshake Flow
         │   1. ProtocolVersion exchange
         │   2. Security negotiation
         │   3. VNC authentication (if needed)
         │   4. ClientInit (shared flag)
         │   5. ServerInit (fb dimensions, name)
         │   6. SetEncodings (Raw only)
         │
         ├─► Read Loop
         │   - FramebufferUpdate (type 0)
         │   - SetColourMapEntries (type 1, skipped)
         │   - Bell (type 2)
         │   - ServerCutText (type 3, clipboard)
         │   - Call LLM with events
         │   - Execute actions from LLM
         │
         └─► Write Messages
             - FramebufferUpdateRequest (type 3)
             - KeyEvent (type 4)
             - PointerEvent (type 5)
             - ClientCutText (type 6)
```

### RFB Protocol Implementation

**Protocol Version:**

- Supports RFB 003.008 (modern VNC)
- Sends: `RFB 003.008\n`

**Security Types Supported:**

- **Type 1: None** - No authentication
- **Type 2: VNC Authentication** - DES challenge-response

**Client-to-Server Messages:**

- **SetEncodings (2):** Declares support for Raw encoding
- **FramebufferUpdateRequest (3):** Request screen updates
    - Parameters: incremental, x, y, width, height
- **KeyEvent (4):** Send keyboard input
    - Parameters: key (X11 keysym), down (press/release)
- **PointerEvent (5):** Send mouse input
    - Parameters: x, y, button_mask
- **ClientCutText (6):** Send clipboard text
    - Parameters: text

**Server-to-Client Messages:**

- **FramebufferUpdate (0):** Screen update notification
    - Contains number of updated rectangles
    - Actual pixel data is not parsed (simplified)
- **Bell (2):** Server bell notification
- **ServerCutText (3):** Server clipboard update

### Reader task and batching (on by default)

A reader task (`spawn_client_task`) frames whole server messages into a bounded queue
(`MAX_BATCH_EVENTS` messages; past it the reader stops and TCP holds the server back); the
answering loop asks the model. Framebuffer updates and clipboard text are pushed by the server,
so they pile up while the model answers. With batching on the loop takes everything waiting and
answers it in one `call_llm_for_client_batch` call, one event per message; with it off, one
message per call. The model used to be called inline in the read loop, behind an
`Idle`/`Processing` state whose "skip while processing" arm could never run.
`tests/client/vnc/batching_test.rs` drives an RFB server written in the test, off and on.
A model `disconnect` half-closes the socket, and the session ends at the server's EOF.

**Lifecycle:**

1. **Connect & Handshake** - Establish RFB connection
2. **Connected Event** - LLM receives connection info (dimensions, server name)
3. **Message Loop** - Process FramebufferUpdate, ServerCutText events
4. **Disconnect** - Connection closed

### LLM Control

**Async Actions** (user-triggered):

- `request_framebuffer_update` - Request screen update from server
    - `incremental`: Only send changes (default: true)
    - `x, y, width, height`: Region to update (default: full screen)
- `send_pointer_event` - Send mouse movement or click
    - `x, y`: Pointer coordinates
    - `button_mask`: 0=no buttons, 1=left, 2=middle, 4=right
- `send_key_event` - Send keyboard input
    - `key`: X11 keysym value (e.g., 65 for 'A')
    - `down`: true for press, false for release
- `send_client_cut_text` - Send clipboard text to server
    - `text`: Text to send
- `disconnect` - Close connection

**Sync Actions** (in response to server events):

- `request_framebuffer_update` - Request update after receiving previous update
- `send_pointer_event` - Click in response to screen changes
- `wait_for_more` - Wait for more updates before acting

**Events:**

- `vnc_connected` - Fired when connection established
    - Data: remote_addr, width, height, server_name
- `vnc_framebuffer_update` - Fired when screen update received
    - Data: rectangles (count), update_summary
- `vnc_server_cut_text` - Fired when server sends clipboard text
    - Data: text

**Startup Parameters:**

- `password` (optional) - VNC password for authentication

### Data Encoding

Unlike TCP client, VNC uses **structured data** for actions:

- **Pointer events**: `{"x": 100, "y": 200, "button_mask": 1}`
- **Key events**: `{"key": 65, "down": true}`
- **Framebuffer requests**: `{"incremental": true}`

No hex encoding needed - LLM works with high-level concepts (coordinates, keys).

### Dual Logging

```rust
info!("VNC client {} connected: {}x{}", client_id, width, height);  // → netget.log
status_tx.send("[CLIENT] VNC client connected");                    // → TUI
```

### Authentication

**VNC Authentication (Type 2):**

- **Challenge-Response:** Server sends 16-byte challenge
- **DES Encryption:** Client encrypts challenge with password
- **Current Implementation:** DES-ECB over both challenge blocks with the first eight password bytes, zero-padded and bit-reversed for VNC key order.
- **Recommendation:** Use security type 1 (None) for testing

Authentication has a 30-second handshake deadline; clipboard and framebuffer body reads have bounded frame deadlines.

## Dashboard injection (`[ send_key_event ]`, `[ send_pointer_event ]`, `[ disconnect ]`)

`connect_with_llm_actions` splits the stream, then registers a command channel
(`client::command_support::register_command_channel`) and spawns a draining `command_loop`
task **before** the `vnc_connected` LLM call — which a manual `*` rule can park — so the operator
can reach the client while it waits. Because the read loop uses `read_exact` (not
cancellation-safe), commands are drained by that separate task, not a `select!` arm; both share
the `Arc<Mutex<WriteHalf>>`.

Every VNC client verb yields `ClientActionResult::Custom`, so the generic
`handle_stream_client_command` cannot write them. `command_loop` routes each through
`apply_injected_action`, which reuses `send_vnc_message_with_writer` — the exact encoder the LLM
path uses — encoding into a buffer for an accurate byte count, then records an `injected_action`
access-log entry and replies with `ClientSendOutcome`. An injected `disconnect` half-closes; the
read loop sees EOF, marks the client `Disconnected`, and drops the command handle
(`remove_client_handle` is called on every read-loop exit, so the rail stops offering `[ send ]`
on a dead client). Test: `tests/client/vnc/command_channel_test.rs` (zero LLM calls).

## Limitations

- **Transport security** - legacy VNC password authentication does not encrypt the session
    - Works with security type 1 (None)
    - May fail with strict VNC auth servers
- **Raw Encoding Only** - Does not support RRE, Hextile, ZRLE, etc.
- **No Pixel Data Parsing** - FramebufferUpdate events don't include actual pixels
    - LLM receives only "N rectangles updated"
    - Sufficient for automation (click, type) but not for visual analysis
- **No Image Analysis** - LLM cannot "see" the screen
    - Future: Could add screenshot capability or OCR
- **No Resize Support** - Framebuffer dimensions fixed at connection
- **No Desktop Sharing** - Uses shared-flag=1 (allows multiple clients)

## Use Cases

### 1. Automated GUI Testing

**Scenario:** Test a desktop application by clicking buttons and typing text.

**LLM Actions:**

```json
[
  {"type": "send_pointer_event", "x": 100, "y": 50, "button_mask": 1},
  {"type": "send_pointer_event", "x": 100, "y": 50, "button_mask": 0},
  {"type": "send_key_event", "key": 65, "down": true},
  {"type": "send_key_event", "key": 65, "down": false}
]
```

### 2. Remote Desktop Control

**Scenario:** LLM navigates a remote desktop to perform tasks.

**Workflow:**

1. Connect → receive screen dimensions
2. Request framebuffer updates
3. LLM "imagines" UI layout based on instructions
4. Send pointer/key events to navigate

### 3. Screen Recording Trigger

**Scenario:** Monitor for screen changes and trigger actions.

**LLM receives:** `vnc_framebuffer_update` events
**LLM decides:** Whether to request more updates or wait

### 4. Clipboard Sync

**Scenario:** Sync clipboard between client and server.

**Events:**

- `vnc_server_cut_text` - Server copied text
- LLM can respond with `send_client_cut_text`

## X11 Keysym Reference

Common X11 keysyms for `send_key_event`:

| Key           | Keysym         | Description |
|---------------|----------------|-------------|
| `a`           | 97             | Lowercase a |
| `A`           | 65             | Uppercase A |
| `0-9`         | 48-57          | Digits      |
| `Enter`       | 65293 (0xFF0D) | Enter key   |
| `Backspace`   | 65288 (0xFF08) | Backspace   |
| `Tab`         | 65289 (0xFF09) | Tab         |
| `Escape`      | 65307 (0xFF1B) | Escape      |
| `Space`       | 32             | Space       |
| `Left Arrow`  | 65361 (0xFF51) | Left arrow  |
| `Up Arrow`    | 65362 (0xFF52) | Up arrow    |
| `Right Arrow` | 65363 (0xFF53) | Right arrow |
| `Down Arrow`  | 65364 (0xFF54) | Down arrow  |

Full list: https://cgit.freedesktop.org/xorg/proto/x11proto/plain/keysymdef.h

## Testing Strategy

See `tests/client/vnc/AGENTS.md` for E2E testing approach.

## Future Enhancements

- **Additional Encodings** - RRE, Hextile, ZRLE for efficiency
- **Pixel Data Parsing** - Extract actual framebuffer content
- **Screenshot Capability** - Convert framebuffer to image
- **OCR Integration** - Allow LLM to "see" screen text
- **Video Recording** - Record VNC session
- **TLS Support** - VeNCrypt for encrypted connections
- **Resize Events** - Handle dynamic resolution changes
- **Extended Desktop Size** - Support for multi-monitor setups

## Inbound framing bounds (October 2026 review)

Server names, authentication failure reasons and clipboard text use `read_server_text`:
1 MiB maximum, checked before allocation. Raw rectangles are streamed into a discard
sink with bounded scratch storage rather than allocating width × height × 4 bytes;
rectangles over 256 MiB are refused (an 8K display still fits). The client sends
SetPixelFormat to negotiate the 32-bit true-color format its raw reader consumes.
An unsupported encoding, truncated frame or other message parsing error terminates the
reader and removes its command handle, instead of interpreting leftover payload as a
new message. CPU-only decoder tests live in `tests/client_review_regression_test.rs::vnc`.
The existing placeholder VNC authentication remains a separate limitation.

## Follow-up verification (October 2026)

VNC authentication now computes the response instead of echoing the challenge. A supplied
password selects type 2 when offered. The pure regression uses an independently generated
OpenSSL DES fixture, plus truncation/padding checks. Action coordinates and pointer masks are
checked before Custom data is constructed, so the transport cannot receive already-wrapped
values. `tests/client_followup_test.rs` covers those boundaries without a display or model.
