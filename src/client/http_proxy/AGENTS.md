# HTTP Proxy Client Implementation

## Overview

The HTTP proxy client implements HTTP CONNECT tunneling, allowing NetGet to route connections through HTTP proxy
servers. This enables LLM-controlled proxy operations for accessing remote servers through intermediate proxies.

## Protocol Stack

```
ETH > IP > TCP > HTTP
```

## Library Choices

### Core Libraries

- **tokio::net::TcpStream**: TCP connection to proxy server
- **tokio::io::BufReader**: Buffered reading for HTTP response parsing
- **hex**: Hex encoding/decoding for raw data transmission

### Rationale

- **No external HTTP proxy library**: We implement the HTTP CONNECT protocol directly using TCP, giving us full control
  over the proxy handshake
- **Tokio async runtime**: Standard async I/O for concurrent client connections
- **Manual protocol implementation**: HTTP CONNECT is simple enough to implement directly without heavy dependencies

## Architecture

### Connection Model

1. **TCP Connection**: Connect to proxy server via TCP
2. **CONNECT Handshake**: Send HTTP CONNECT request to establish tunnel
3. **Response Parsing**: Parse proxy response (200 Connection established)
4. **Tunnel Mode**: After successful CONNECT, stream becomes transparent tunnel
5. **Data Forwarding**: All data sent/received through tunnel

### Batching (what arrives while the model is answering)

The tunnel, once the CONNECT reply has been read, is read on a registered task of its own (`client/inbound_queue.rs`, shared with
the other proxied byte-stream clients), feeding a bounded queue of reads (32). The answering
loop takes one read per model call with batching off, and with batching on joins everything
already waiting into one payload, as the `tcp` client does. Declared `BatchingMode::On`.
This replaced an Idle/Processing/Accumulating machine that could never leave Idle — the loop
read, called the model and wrote in sequence — and "cleared" a queue nothing filled: nothing
was lost, but what arrived during a call merged in the kernel buffer, so batching off and on
could not be told apart. A `disconnect` the model returns now ends the session (it used to
break only the loop over that answer's actions). Test: `tests/client/http_proxy/batching_test.rs`.

### HTTP CONNECT Protocol

```
Client -> Proxy: CONNECT target.com:443 HTTP/1.1
                 Host: target.com:443
                 [Proxy-Authorization: Basic base64creds] (optional)

Proxy -> Client: HTTP/1.1 200 Connection established
                 [headers...]

[Now tunnel is established, data flows transparently]
```

## LLM Integration

### Actions

#### Async Actions (User-Triggered)

1. **establish_tunnel**
    - Parameters: `target_host`, `target_port`
    - Sends CONNECT request to proxy
    - Waits for 200 response
    - Triggers `http_proxy_tunnel_established` event on success

2. **send_http_request**
    - Parameters: `method`, `path`, `headers`, `body`
    - Constructs HTTP request string
    - Sends through established tunnel
    - Example: GET / HTTP/1.1

3. **send_data**
    - Parameters: `data_hex`
    - Sends raw data through tunnel
    - For protocols other than HTTP

4. **disconnect**
    - Closes connection to proxy

#### Sync Actions (Response to Network Events)

1. **send_http_request**: Send request based on received response
2. **send_data**: Send raw data in response
3. **wait_for_more**: Queue data without responding

### Events

1. **http_proxy_connected**
    - Triggered when TCP connection to proxy is established
    - LLM can decide whether to establish tunnel immediately or wait

2. **http_proxy_tunnel_established**
    - Triggered when CONNECT succeeds (200 response)
    - Parameters: `target_host`, `target_port`, `status_code`
    - LLM can now send requests through tunnel

3. **http_proxy_response_received**
    - Triggered when data arrives through tunnel
    - Parameters: `data_hex`, `data_length`
    - LLM decides how to respond

## Implementation Details

### Tunnel Establishment Flow

1. Client connects to proxy server (TCP)
2. LLM receives `http_proxy_connected` event
3. LLM action: `establish_tunnel` with target host/port
4. Client sends CONNECT request
5. Client parses response headers until empty line
6. If status 200, tunnel established
7. LLM receives `http_proxy_tunnel_established` event
8. Now client can send/receive data through tunnel

### Response Parsing

We use `BufReader` to read the CONNECT response line-by-line:

- First line: `HTTP/1.1 200 Connection established`
- Following lines: Headers
- Empty line: End of headers, tunnel ready

After tunnel establishment, we switch to raw byte reading.

### Proxy Authentication

The `proxy_auth` startup parameter takes `username:password` and is resolved once at connect
into a `Proxy-Authorization: Basic <base64(username:password)>` header:

```
Proxy-Authorization: Basic base64(username:password)
```

`connect_request()` is the single encoder, so the header rides on **every** CONNECT — the
LLM's, the default-target one, and a dashboard-injected `establish_tunnel` alike. It belongs
on the CONNECT specifically: that is the only request the proxy ever parses, everything after
it is opaque tunnel bytes. Only Basic is supported; there is no 407-challenge/Digest handling.

### Default target

`default_target` (`host:port`) is the tunnel to open when nothing else selects one. It is
used in three places, all of them the same rule — a target nobody named falls back to it:
an `establish_tunnel` action missing `target_host`/`target_port`, an injected
`establish_tunnel` missing the same, and the connect path itself, which opens the tunnel
after the connected-event LLM call if no action set a target.

## Dashboard command channel

The client registers `command_support::register_command_channel` **before** the
`http_proxy_connected` LLM call (a manual handler can park that call), so
`AppState::send_to_client` / the dashboard's `[ send_http_request ]`, `[ send_data ]`,
`[ establish_tunnel ]` and `[ disconnect ]` rows work for the connection's whole life. The read
loop mixes `read_line` (CONNECT headers, not cancellation-safe) and `read`, so the channel is
drained by a separate task registered via `register_client_task`, writing through the shared
`Arc<Mutex<WriteHalf>>`. `send_http_request` / `send_data` / `disconnect` go through the generic
`handle_stream_client_command`; `establish_tunnel` returns `ClientActionResult::Custom`, so a
small bespoke arm in `mod.rs` (`handle_injected_command`) encodes it with the same
`connect_request()` the tunnel task uses. An injected CONNECT's reply is not parsed as a status
line — it reaches the model as ordinary tunnel bytes (`http_proxy_response_received`) because the
loop has already left the header-reading phase. The handle is removed on every loop exit.

## Limitations

1. **HTTP CONNECT only**: Only supports CONNECT method, not GET/POST proxying
2. **Basic proxy auth only**: `proxy_auth` produces a `Proxy-Authorization: Basic ...`
   header; there is no Digest support and no handling of a 407 challenge
3. **No HTTPS MITM**: Cannot inspect/modify HTTPS traffic (tunnel is opaque)
4. **No proxy chaining**: Cannot chain multiple proxies
5. **No SOCKS**: Only HTTP proxy, not SOCKS4/SOCKS5

## Future Enhancements

1. **Proxy Response Parsing**
    - Parse Proxy-Agent header
    - Handle 407 Proxy Authentication Required
    - Handle other error codes (502 Bad Gateway, etc.)

2. **Connection Pooling**
    - Reuse proxy connections for multiple tunnels
    - HTTP/1.1 persistent connections

3. **Proxy PAC Files**
    - Parse PAC (Proxy Auto-Configuration) files
    - LLM decides which proxy to use based on destination

4. **Transparent Proxying**
    - Allow other client protocols to use proxy transparently
    - Proxy-as-middleware pattern

## Testing Strategy

See `tests/client/http_proxy/AGENTS.md` for testing details.

## Example Prompts

```
"Connect via HTTP proxy at localhost:8080 to reach example.com:80"
"Establish tunnel through proxy 192.168.1.100:3128 to api.github.com:443"
"Use proxy at proxy.corp.com:8080 to fetch http://internal-server/status"
```

## References

- RFC 7231 Section 4.3.6: CONNECT method
- RFC 2817: HTTP Upgrade to TLS
- Squid proxy documentation: http://www.squid-cache.org/

## Bounded response reading (October 2026 review)

Response lines now use `client::response_reader::read_response_line`, sharing the
existing bounded line decoder. The 64 KiB cap includes the line terminator; a partial
line at EOF is an error. Oversized or incomplete replies are not forwarded as successful
responses.
CONNECT response headers have the same 64 KiB aggregate cap. A 200 status followed
by premature EOF or a header read failure no longer establishes a tunnel.
Pure decoder tests are in `tests/client_review_regression_test.rs::text_responses`.

## Response completion deadlines (October 2026 follow-up)

Shared text readers allow an idle established connection to wait for its first response byte,
then enforce a 30-second absolute line-completion deadline. Dot-terminated bodies have a
30-second whole-response deadline in addition to their byte cap. NNTP greetings are bounded
from the first wait; HTTP CONNECT has a single deadline spanning status and headers. A framing
timeout is terminal because resuming an interrupted parse would misalign the stream.
