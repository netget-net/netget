# NetGet Client Protocol Feasibility Analysis

This document analyzes all existing NetGet server protocols for client implementation feasibility. Each protocol is evaluated for:
- **Client libraries** (real Rust crates)
- **Implementation complexity** (Easy/Medium/Hard/Very Hard/Unfeasible)
- **LLM control points** (where the LLM can make decisions)
- **Implementation strategy**

**Legend:**
- ✅ **Easy** (1-2 days) - Simple request-response, existing libs
- 🟡 **Medium** (3-5 days) - Stateful, moderate complexity
- 🟠 **Hard** (1-2 weeks) - Complex state machines, custom protocols
- 🔴 **Very Hard** (2-4 weeks) - Low-level control, extensive state
- ❌ **Unfeasible** - Doesn't make sense as client or too complex

---

## Core Network Protocols

### TCP ✅ (Already Implemented)
**Complexity:** Easy
**Client Library:** `tokio::net::TcpStream`
**Status:** ✅ Implemented in `src/client/tcp/`

**LLM Control:**
- Send arbitrary hex data
- Disconnect decision
- Wait for more data

**Implementation:** Direct socket I/O with state machine.

---

### UDP 🟡
**Complexity:** Medium
**Client Library:** `tokio::net::UdpSocket`

**LLM Control:**
- Send datagram to address
- Change target address
- Process received responses

**Implementation Strategy:**
```rust
// Similar to TCP but connectionless
// LLM chooses: send_udp(target, data), change_target(addr)
UdpSocket::bind("0.0.0.0:0").await?
socket.send_to(&data, remote_addr).await?
```

**Challenges:**
- No connection state (send to any address)
- May receive from multiple sources
- Need timeout handling for responses

**Note on Connectionless Protocols:**
Even though UDP has no "connection", the client still maintains active state:
- **Listening state**: Client remains active to receive responses
- **LLM trigger system**: Events fire when data arrives
- **Scheduled tasks**: LLM can schedule periodic sends (e.g., heartbeats)
- **Client lifecycle**: Open client → active listening → close client

This pattern applies to all connectionless protocols (UDP, IGMP, multicast, etc.). We track the **active listening state**, not connections.

---

### DataLink 🟠
**Complexity:** Hard (Requires Root)
**Client Library:** `pcap` crate

**Prerequisites:**
- **Root/CAP_NET_RAW** - Required for raw packet capture/injection
- **libpcap** system library
- Network interface in promiscuous mode

**LLM Control:**
- Inject raw Ethernet frames (hex)
- Specify interface
- Set Ethernet type (0x0800 for IPv4, 0x0806 for ARP, etc.)
- Construct custom L2 protocols

**Implementation Strategy:**
```rust
use pcap::{Capture, Device};

// Open interface for sending (requires root)
let device = Device::lookup()?.unwrap();
let mut cap = Capture::from_device(device)?.open()?;

// LLM constructs raw Ethernet frame
let frame = hex::decode(llm_frame_hex)?;
cap.sendpacket(&frame)?;
```

**Use Cases:**
- Custom L2 protocols
- Network simulation/testing
- ARP spoofing detection testing
- Ethernet frame analysis

**Challenges:**
- Requires elevated privileges
- Platform-specific (libpcap behavior differs)
- Must handle Ethernet framing manually

**Server Implementation Reference:** `src/server/datalink/mod.rs` shows packet injection with `cap.sendpacket()`

---

### ARP 🟠
**Complexity:** Hard (Requires Root)
**Client Library:** `pcap` + `pnet` for ARP packet construction

**Prerequisites:**
- Same as DataLink (root access, libpcap)

**LLM Control:**
- Send ARP requests (who-has queries)
- Send ARP replies (gratuitous ARP)
- Spoof source MAC/IP (testing only)
- ARP cache poisoning detection testing

**Implementation Strategy:**
```rust
use pcap::Capture;
use pnet::packet::arp::{ArpPacket, MutableArpPacket, ArpOperations};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};

// LLM decides: send ARP request
let mut arp_buffer = vec![0u8; 28]; // ARP packet size
let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
arp_packet.set_protocol_type(EtherTypes::Ipv4);
arp_packet.set_operation(ArpOperations::Request);
// ... set MAC/IP fields

// Wrap in Ethernet frame
let mut eth_buffer = vec![0u8; 14 + 28];
let mut eth_packet = MutableEthernetPacket::new(&mut eth_buffer).unwrap();
eth_packet.set_ethertype(EtherTypes::Arp);
// ... construct frame

cap.sendpacket(&eth_buffer)?;
```

**Use Cases:**
- Network reconnaissance
- ARP table manipulation (testing)
- Gratuitous ARP announcements
- Duplicate IP detection

**Server Implementation Reference:** `src/server/arp/mod.rs` shows ARP packet construction and injection

**Important:** ARP spoofing can be used maliciously. Only use for authorized testing/research.

---

## HTTP Family

### HTTP ✅ (Already Implemented)
**Complexity:** Easy
**Client Library:** `reqwest`
**Status:** ✅ Implemented in `src/client/http/`

**LLM Control:**
- Choose HTTP method (GET/POST/PUT/DELETE)
- Set headers
- Set request body
- Follow redirects decision

---

### HTTPS 🟡
**Complexity:** Medium
**Client Library:** `reqwest` (built-in TLS support)

**LLM Control:**
- Same as HTTP
- Certificate validation decision
- SNI hostname

**Implementation Strategy:**
```rust
// reqwest handles TLS automatically
let client = reqwest::Client::builder()
    .danger_accept_invalid_certs(llm_decides) // LLM controls
    .build()?;
```

**Note:** Just a configuration variant of HTTP client.

---

### HTTP/2 🟡
**Complexity:** Medium
**Client Library:** `reqwest` (automatic), `hyper` with `h2`

**LLM Control:**
- Same as HTTP/1.1
- Server push acceptance

**Implementation Strategy:**
- Use reqwest with HTTP/2 enabled (automatic negotiation)
- LLM makes same decisions as HTTP/1.1

**Note:** Mostly transparent upgrade from HTTP/1.1.

---

### HTTP/3 (QUIC) 🟠
**Complexity:** Hard
**Client Library:** `quinn` (QUIC), `h3` (HTTP/3)

**LLM Control:**
- Request multiplexing decisions
- Stream priorities
- 0-RTT data decision

**Implementation Strategy:**
```rust
// quinn for QUIC transport
let endpoint = quinn::Endpoint::client(bind_addr)?;
let connection = endpoint.connect(server_addr, "example.com")?.await?;

// h3 for HTTP/3 layer
let mut h3_conn = h3::client::new(connection).await?;
```

**Challenges:**
- QUIC connection management
- UDP-based (different from TCP)
- Complex state (streams, flow control)

---

### WebDAV 🟡
**Complexity:** Medium
**Client Library:** `reqwest` + custom WebDAV methods

**LLM Control:**
- Choose WebDAV method (PROPFIND, MKCOL, COPY, MOVE)
- XML body construction
- Recursive operations

**Implementation Strategy:**
```rust
// Extend HTTP client with WebDAV methods
client.request(Method::from_bytes(b"PROPFIND")?, url)
    .header("Depth", depth)
    .body(xml_body)
    .send().await?
```

---

## DNS Family

### DNS 🟡
**Complexity:** Medium
**Client Library:** `trust-dns-client` (now `hickory-dns`)

**LLM Control:**
- Query type (A, AAAA, MX, TXT, etc.)
- Recursive vs iterative
- DNSSEC validation

**Implementation Strategy:**
```rust
use hickory_client::client::{Client, SyncClient};
use hickory_client::udp::UdpClientConnection;

let conn = UdpClientConnection::new(dns_server)?;
let client = SyncClient::new(conn);

// LLM decides query type
let response = client.query(name, DNSClass::IN, RecordType::A)?;
```

**Events:**
- `dns_response_received` - LLM decides follow-up queries

---

### DoT (DNS over TLS) 🟡
**Complexity:** Medium
**Client Library:** `hickory-dns` with TLS

**LLM Control:**
- Same as DNS
- TLS verification decisions

**Implementation:** hickory-dns with TLS transport.

---

### DoH (DNS over HTTPS) 🟡
**Complexity:** Medium
**Client Library:** `doh-client`, `https-dns`, or `hickory-dns` with DoH support

**LLM Control:**
- Same as DNS query control
- DoH server selection (Google, Cloudflare, custom)
- Wire format vs JSON format

**Implementation Strategy:**
```rust
use doh_client::DoHClient;

let client = DoHClient::new("https://dns.google/dns-query".to_string());

// LLM decides query
let response = client.query_dns(name, record_type).await?;
```

**Alternative:**
```rust
// Using hickory-dns with DoH
use hickory_client::client::AsyncClient;
use hickory_https::HttpsClientStreamBuilder;

let stream = HttpsClientStreamBuilder::new()
    .build::<AsyncClient>(dns_https_url);
```

**Available DoH Providers:**
- Google: `https://dns.google/dns-query`
- Cloudflare: `https://cloudflare-dns.com/dns-query`
- Quad9: `https://dns.quad9.net/dns-query`

**Implementation:** HTTPS POST/GET with DNS wire format or JSON API.

---

### mDNS 🟠
**Complexity:** Hard
**Client Library:** `mdns` crate

**LLM Control:**
- Service discovery (_http._tcp.local)
- Query/announce decision
- Multicast group management

**Challenges:**
- Multicast requires special socket options
- Local network only
- Race conditions in discovery

---

## Email & Messaging

### SMTP 🟡
**Complexity:** Medium
**Client Library:** `lettre`

**LLM Control:**
- Compose email (from, to, subject, body)
- STARTTLS decision
- Authentication (PLAIN, LOGIN)
- Attachments

**Implementation Strategy:**
```rust
use lettre::{Message, SmtpTransport, Transport};

let email = Message::builder()
    .from(from.parse()?)
    .to(to.parse()?)
    .subject(subject)
    .body(body)?;

let mailer = SmtpTransport::relay(smtp_server)?
    .credentials(creds)
    .build();

mailer.send(&email)?;
```

**Events:**
- `smtp_connected` - LLM builds email
- `smtp_sent` - Confirmation

---

### IMAP 🟠
**Complexity:** Hard
**Client Library:** `async-imap`

**LLM Control:**
- Login/authenticate
- Select mailbox
- Search criteria (FROM, SUBJECT, DATE)
- Fetch messages
- Mark as read/unread
- Delete/move messages

**Implementation Strategy:**
```rust
use async_imap::Client;

let client = Client::connect((server, 993)).await?;
let mut session = client.login(user, pass).await?;

// LLM decides: select_mailbox, search, fetch, etc.
session.select("INBOX").await?;
let messages = session.search("UNSEEN").await?;
```

**Challenges:**
- Complex state machine (Not Authenticated → Authenticated → Selected)
- Many commands with interdependencies
- Email parsing complexity

---

### IRC 🟡
**Complexity:** Medium
**Client Library:** `irc` crate

**LLM Control:**
- Join/part channels
- Send messages (PRIVMSG)
- Change nick
- CTCP responses

**Implementation Strategy:**
```rust
use irc::client::prelude::*;

let client = Client::new(config).await?;
client.identify()?;

// LLM decides: JOIN #channel, PRIVMSG, etc.
client.send_privmsg(target, message)?;
```

**Events:**
- `irc_message_received` - LLM responds to chat

---

### XMPP 🟠
**Complexity:** Hard
**Client Library:** `xmpp-rs` or `tokio-xmpp`

**LLM Control:**
- SASL authentication
- Roster management
- Send stanzas (message, presence, iq)
- MUC (multi-user chat) operations

**Challenges:**
- XML stream parsing
- Complex authentication flows
- Stateful protocol with many extensions

---

### MQTT 🟡
**Complexity:** Medium
**Client Library:** `rumqttc` (async)

**LLM Control:**
- Connect with client ID
- Subscribe to topics (wildcards)
- Publish messages (QoS 0/1/2)
- Unsubscribe

**Implementation Strategy:**
```rust
use rumqttc::{MqttOptions, AsyncClient, QoS};

let mut mqttoptions = MqttOptions::new(client_id, host, port);
let (client, mut eventloop) = AsyncClient::new(mqttoptions, 10);

// LLM decides: subscribe, publish
client.subscribe("topic/#", QoS::AtMostOnce).await?;
client.publish("topic", QoS::AtLeastOnce, false, payload).await?;
```

**Events:**
- `mqtt_message_received` - LLM processes and responds

---

## Database Protocols

### Redis ✅ (Already Implemented)
**Complexity:** Easy
**Client Library:** `redis` crate
**Status:** ✅ Implemented in `src/client/redis/`

**LLM Control:**
- Execute any Redis command
- Parse RESP responses

---

### MySQL 🟡
**Complexity:** Medium
**Client Library:** `mysql_async` or `sqlx`

**LLM Control:**
- Execute queries (SELECT, INSERT, UPDATE, DELETE)
- Transaction control (BEGIN, COMMIT, ROLLBACK)
- Prepared statements

**Implementation Strategy:**
```rust
use mysql_async::prelude::*;

let pool = Pool::new(connection_url);
let mut conn = pool.get_conn().await?;

// LLM generates SQL
let result = conn.query_iter("SELECT * FROM users").await?;
```

**Events:**
- `mysql_connected` - LLM executes queries
- `mysql_result_received` - LLM analyzes results

---

### PostgreSQL 🟡
**Complexity:** Medium
**Client Library:** `tokio-postgres` or `sqlx`

**LLM Control:**
- Same as MySQL
- Extended query protocol
- LISTEN/NOTIFY

**Implementation:** Similar to MySQL, PostgreSQL-specific wire protocol.

---

### Cassandra 🟠
**Complexity:** Hard
**Client Library:** `cdrs-tokio` or `scylla` (Rust driver)

**LLM Control:**
- CQL queries
- Prepared statements
- Paging control
- Consistency levels

**Challenges:**
- Binary protocol (CQL native)
- Cluster topology awareness
- Complex result sets

---

### DynamoDB 🟡
**Complexity:** Medium
**Client Library:** `aws-sdk-dynamodb`

**LLM Control:**
- PutItem, GetItem, Query, Scan
- UpdateItem expressions
- Conditional writes
- BatchGetItem

**Implementation Strategy:**
```rust
use aws_sdk_dynamodb::Client;

let client = Client::new(&config);

// LLM constructs queries
let result = client.get_item()
    .table_name("MyTable")
    .key("id", AttributeValue::S(id))
    .send().await?;
```

**Note:** HTTP-based (uses AWS signature v4).

---

### Elasticsearch 🟡
**Complexity:** Medium
**Client Library:** `elasticsearch` official crate

**LLM Control:**
- Index documents
- Search queries (JSON DSL)
- Aggregations
- Bulk operations

**Implementation:** REST API over HTTP (extends HTTP client).

---

## Network Infrastructure

### SSH 🟠
**Complexity:** Hard
**Client Library:** `russh`

**LLM Control:**
- Authenticate (password, pubkey)
- Execute commands
- SCP/SFTP file transfers
- Port forwarding

**Implementation Strategy:**
```rust
use russh::*;

let session = Session::connect(config, addr, None).await?;
let auth = session.authenticate_password(user, pass).await?;

let mut channel = auth.channel_open_session().await?;
channel.exec(true, command).await?;

// Read command output
let mut output = Vec::new();
channel.read_to_end(&mut output).await?;
```

**Challenges:**
- Complex authentication flows
- Channel multiplexing
- Interactive shells vs commands

---

### Telnet 🟡
**Complexity:** Medium
**Client Library:** Raw TCP + telnet option negotiation

**LLM Control:**
- Send commands
- Respond to option negotiations (WILL/WONT/DO/DONT)
- Handle escape sequences

**Implementation:** Custom protocol on top of TCP.

---

### LDAP 🟠
**Complexity:** Hard
**Client Library:** `ldap3`

**LLM Control:**
- Bind (authenticate)
- Search (filter, base DN, scope)
- Add/modify/delete entries
- Paging control

**Implementation Strategy:**
```rust
use ldap3::{LdapConn, Scope, SearchEntry};

let mut ldap = LdapConn::new(ldap_url)?;
ldap.simple_bind(dn, password)?;

// LLM constructs searches
let (rs, _res) = ldap.search(
    base_dn,
    Scope::Subtree,
    filter,
    vec!["cn", "mail"]
)?;
```

**Challenges:**
- ASN.1/BER encoding
- Complex directory navigation
- Schema understanding

---

### SNMP 🟡
**Complexity:** Medium
**Client Library:** `snmp` or custom

**LLM Control:**
- GET/GETNEXT/GETBULK/SET
- OID selection
- Community strings
- Walk MIB trees

**Implementation:** UDP-based request-response with ASN.1 encoding.

---

### NTP 🟡
**Complexity:** Medium
**Client Library:** `ntp` crate

**LLM Control:**
- Query time servers
- Select server from pool
- Interpret stratum/offset

**Implementation Strategy:**
```rust
use ntp::request;

let response = request(ntp_server)?;
let local_time = response.transmit_time;
```

**Note:** Simple request-response, mostly for time sync.

---

## VPN & Tunneling

### WireGuard 🔴
**Complexity:** Very Hard
**Client Library:** `boringtun` or kernel module

**LLM Control:**
- Peer configuration
- Allowed IPs
- Keepalive intervals

**Challenges:**
- Cryptographic key management
- Kernel module interaction
- TUN/TAP device management
- Requires root/CAP_NET_ADMIN

**Implementation:** Likely needs kernel WireGuard + userspace config.

---

### OpenVPN ❌
**Complexity:** Unfeasible
**Reason:** No pure Rust library. Extremely complex protocol with TLS control channel + data channel. Certificate/key management. Requires external `openvpn` binary or kernel module integration.

**Why Unfeasible:**
- No Rust implementation of OpenVPN protocol
- Would need to wrap C library or `openvpn` binary
- Certificate/PKI infrastructure complexity
- Requires TUN/TAP devices (kernel interaction)
- Authentication complexity (username/password, certificates, 2FA)

**Alternative:** Command wrapper approach - LLM generates `.ovpn` config files and executes `openvpn --config llm-generated.ovpn`

---

### IPSec ❌
**Complexity:** Unfeasible
**Reason:** Kernel-level protocol. Requires `ip xfrm` commands or strongSwan. Not practical for userspace LLM control.

---

### Tor (SOCKS/Directory) 🟠
**Complexity:** Hard
**Client Library:** `arti` (Tor in Rust)

**LLM Control:**
- Circuit creation
- Exit node selection
- Hidden service connections
- Bridge configuration

**Implementation Strategy:**
```rust
use arti_client::{TorClient, TorClientConfig};

let config = TorClientConfig::default();
let tor_client = TorClient::create_bootstrapped(config).await?;

// LLM decides: connect via Tor
let stream = tor_client.connect((addr, port)).await?;
```

**Challenges:**
- Bootstrapping (consensus fetch)
- Circuit building
- Hidden service descriptor parsing

---

## Proxy Protocols

### SOCKS5 🟡
**Complexity:** Medium
**Client Library:** `tokio-socks`

**LLM Control:**
- Target address selection
- Authentication
- UDP ASSOCIATE vs TCP CONNECT

**Implementation Strategy:**
```rust
use tokio_socks::tcp::Socks5Stream;

let stream = Socks5Stream::connect(
    proxy_addr,
    target_addr
).await?;

// Now use stream as normal TCP
stream.write_all(request).await?;
```

**Events:**
- `socks_connected` - LLM sends application data

---

### HTTP Proxy 🟡
**Complexity:** Medium
**Client Library:** `reqwest` with proxy support

**LLM Control:**
- Proxy selection
- CONNECT tunneling
- Proxy authentication

**Implementation:** Configure reqwest with proxy settings.

---

### STUN 🟡
**Complexity:** Medium
**Client Library:** `stun` crate

**LLM Control:**
- Server selection
- Attribute parsing (XOR-MAPPED-ADDRESS)
- Binding refresh

**Implementation Strategy:**
```rust
use stun::client::*;

let client = Client::new(stun_server, None)?;
let response = client.binding_request()?;

// Extract public IP/port
let mapped_addr = response.get_xor_mapped_addr()?;
```

**Note:** Simple NAT traversal discovery.

---

### TURN 🟠
**Complexity:** Hard
**Client Library:** `webrtc-rs` (includes TURN client)

**LLM Control:**
- Allocate request
- Create permissions
- Channel binding
- Refresh intervals

**Challenges:**
- Complex state (allocations, permissions, channels)
- Authentication (long-term credentials)
- Relay data handling

---

## RPC & API Protocols

### gRPC 🟡
**Complexity:** Medium
**Client Library:** `tonic`

**LLM Control:**
- Call RPC methods
- Set metadata/headers
- Streaming (unary, client-stream, server-stream, bidirectional)

**Implementation Strategy:**
```rust
use tonic::Request;

// LLM generates protobuf message
let request = Request::new(MyRequest { field: value });

let response = client.my_method(request).await?;
```

**Note:** Requires .proto files or dynamic message construction.

---

### JSON-RPC 🟡
**Complexity:** Medium
**Client Library:** `jsonrpc` or custom HTTP client

**LLM Control:**
- Method names
- Parameters (JSON)
- Batch requests

**Implementation:** HTTP POST with JSON body (extends HTTP client).

---

### XML-RPC 🟡
**Complexity:** Medium
**Client Library:** `xmlrpc` crate

**LLM Control:**
- Method calls
- XML parameter construction

**Implementation:** HTTP POST with XML body.

---

### MCP (Model Context Protocol) 🟡
**Complexity:** Medium
**Client Library:** Custom (JSON-RPC over stdio/HTTP)

**LLM Control:**
- Tool calls
- Resource queries
- Prompt expansion

**Implementation:** JSON-RPC client with MCP-specific methods.

---

### OpenAI API 🟡
**Complexity:** Medium
**Client Library:** `async-openai`

**LLM Control:**
- Model selection
- Chat completions
- Embeddings
- Function calling

**Implementation Strategy:**
```rust
use async_openai::{Client, types::*};

let client = Client::new();

let request = CreateChatCompletionRequestArgs::default()
    .model("gpt-4")
    .messages(vec![...])
    .build()?;

let response = client.chat().create(request).await?;
```

**Note:** Just an HTTP API client.

---

### OpenAPI Client ✅
**Complexity:** Medium (Already Implemented)
**Client Library:** `openapi-rs` (parser), `reqwest` (HTTP client)
**Status:** ✅ Implemented in `src/client/openapi/`

**LLM Control:**
- Operation selection by ID (no path memorization)
- Path parameter provision
- Query parameter provision
- Request body construction
- Header customization

**Implementation Strategy:**
```rust
use openapi_rs::model::parse::OpenAPI;
use reqwest::Client;

// 1. Parse OpenAPI spec (YAML or JSON)
let spec: OpenAPI = serde_yaml::from_str(&spec_yaml)?;

// 2. Extract base URL from spec
let base_url = spec.servers.first().map(|s| &s.url)?;

// 3. LLM chooses operation by ID
let (path_template, method, operation) = find_operation(&spec, "listUsers")?;

// 4. Substitute path parameters
// "/users/{id}" + {"id": "123"} → "/users/123"
let path = substitute_path_params(path_template, &path_params)?;

// 5. Build and execute HTTP request
let url = format!("{}{}", base_url, path);
let response = http_client.request(method, &url)
    .query(&query_params)
    .headers(headers)
    .json(&body)
    .send().await?;
```

**Features:**
- ✅ Inline spec (YAML/JSON string)
- ✅ Spec file loading (`spec_file` parameter)
- ✅ Base URL override
- ✅ Operation lookup by `operation_id`
- ✅ Path parameter substitution (`/users/{id}` → `/users/123`)
- ✅ Query parameter merging
- ✅ Header merging (spec defaults + overrides)
- ✅ JSON request bodies
- ✅ HTTPS with HTTP/2 support

**Benefits vs HTTP Client:**
1. **Spec-Driven**: LLM doesn't memorize paths/methods
2. **Type Safety**: Parameters defined by spec
3. **Self-Documenting**: Operation list sent to LLM automatically
4. **Path Parameters**: Automatic substitution
5. **Consistency**: All requests follow spec structure
6. **Discovery**: LLM sees available operations on connect

**Use Cases:**
- API testing against OpenAPI specs
- API exploration (GitHub API, Swagger Petstore)
- Automated workflows (create N resources)
- Spec compliance testing
- Integration testing with OpenAPI-first APIs

**Events:**
- `openapi_client_connected` - Spec loaded, operations listed
- `openapi_operation_response` - Response received with operation context

**Actions:**
- `execute_operation` - Execute operation by ID with parameters
- `list_operations` - View all operations (auto-sent on connect)
- `get_operation_details` - Inspect specific operation
- `disconnect` - Stop client

**Testing:**
- Mock-based E2E tests in `tests/client/openapi/e2e_test.rs`
- Test coverage: spec parsing, operation execution, path substitution
- LLM call budget: 4 calls per test (< 5 target)

**Implementation:** ~1000 lines across:
- `src/client/openapi/mod.rs` - Main implementation
- `src/client/openapi/actions.rs` - Client trait
- `src/client/openapi/CLAUDE.md` - Documentation
- `tests/client/openapi/e2e_test.rs` - E2E tests
- `tests/client/openapi/CLAUDE.md` - Test documentation

**Limitations:**
- No response schema validation (future)
- No request body validation (future)
- No authentication flow handling (future)
- Single base URL (cannot switch between servers)
- No WebSocket/SSE operations

**Note:** This is the spec-driven complement to the raw HTTP client. Use OpenAPI client when you have a spec, HTTP client for arbitrary HTTP requests.

---

## Routing Protocols

### BGP 🟠
**Complexity:** Hard (Query Mode)
**Client Library:** Custom TCP + BGP wire format

**Use Case:** Query BGP peer for routing information (not full participation)

**LLM Control:**
- Connect to BGP peer (port 179)
- Send BGP OPEN (establish session)
- Query route information (REQUEST routes)
- Parse UPDATE messages (learned routes)
- Send KEEPALIVE messages

**Implementation Strategy:**
```rust
// BGP query client - connects to peer to gather routing info
use std::net::TcpStream;

// LLM decides: query this BGP peer
let mut stream = TcpStream::connect((peer_ip, 179))?;

// Send OPEN message
let open_msg = BgpOpenMessage {
    version: 4,
    my_as: llm_as_number, // Can be fake for monitoring
    hold_time: 180,
    bgp_id: my_ip,
    // ...
};
stream.write_all(&open_msg.encode())?;

// Receive UPDATE messages with routes
let update = BgpUpdateMessage::decode(&stream)?;
// LLM analyzes: prefix, AS path, next hop, communities
```

**Use Cases:**
- Query peer for advertised routes
- Monitor BGP updates
- Analyze AS paths
- BGP route debugging

**Challenges:**
- BGP wire protocol parsing
- Session management (OPEN, KEEPALIVE, NOTIFICATION)
- Route parsing (NLRI, path attributes)
- Requires valid AS number (can be private AS for testing)

**Note:** This is **passive monitoring/querying**, not active route announcement.

---

### OSPF 🟠
**Complexity:** Hard (Query Mode)
**Client Library:** Raw IP socket + OSPF packet parsing

**Use Case:** Query OSPF router for link-state database

**Prerequisites:**
- Root access (raw IP sockets)
- Multicast support (224.0.0.5, 224.0.0.6)

**LLM Control:**
- Send Hello packets (neighbor discovery)
- Request Link State Database (LSDB)
- Parse LSAs (Link State Advertisements)
- Query router information

**Implementation Strategy:**
```rust
use socket2::{Socket, Domain, Type, Protocol};

// OSPF uses IP protocol 89
let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(89)))?;

// LLM decides: query router for LSDB
let hello_packet = OspfHelloPacket { /* ... */ };
socket.send_to(&hello_packet.encode(), ospf_router_addr)?;

// Receive Database Description packets
let lsdb = parse_ospf_lsdb(&response)?;
// LLM analyzes: network topology, link costs
```

**Use Cases:**
- Topology discovery
- Link cost monitoring
- OSPF debugging
- Network visualization

**Challenges:**
- Raw IP socket handling
- OSPF state machine (simplified for querying)
- Multicast group membership
- LSA parsing complexity

---

### ISIS 🟠
**Complexity:** Hard (Query Mode)
**Client Library:** Raw packet capture (pcap) + IS-IS parsing

**Use Case:** Capture and parse IS-IS PDUs for topology information

**Prerequisites:**
- Root access (pcap)
- Layer 2 access (Ethernet)

**LLM Control:**
- Capture IS-IS Hello PDUs
- Parse LSPs (Link State PDUs)
- Analyze topology database
- Query neighbor information

**Implementation:**
Similar to OSPF but at Layer 2 (uses LLC/SNAP, not IP). Requires pcap for raw frame capture.

**Use Cases:**
- Topology monitoring
- IS-IS debugging
- Network analysis

---

### RIP 🟡
**Complexity:** Medium (Query Mode)
**Client Library:** UDP socket + RIP packet parsing

**Use Case:** Query RIP router for routing table

**LLM Control:**
- Send RIP Request (query routing table)
- Parse RIP Response
- Analyze routes (destination, metric, next hop)

**Implementation Strategy:**
```rust
use tokio::net::UdpSocket;

// RIP uses UDP port 520
let socket = UdpSocket::bind("0.0.0.0:520").await?;

// LLM decides: query router
let request = RipRequestMessage::new();
socket.send_to(&request.encode(), (router_ip, 520)).await?;

// Receive routing table
let (data, _) = socket.recv_from(&mut buf).await?;
let routes = RipResponseMessage::decode(&data)?;
// LLM analyzes: network, metric, next hop
```

**Use Cases:**
- Simple routing table queries
- RIP network debugging
- Route metric analysis

**Challenges:**
- RIPv1 vs RIPv2 parsing
- Authentication handling
- Limited route information (compared to BGP/OSPF)

**Note:** Easiest of the routing protocols - UDP-based, simple format.

---

## Specialized Protocols

### Bitcoin 🟡
**Complexity:** Medium
**Client Library:** `bitcoin-rpc` for RPC, `bitcoin` crate for P2P

**Two Client Modes:**

#### 1. Bitcoin RPC Client (Easier) 🟡
**Connects to:** Bitcoin Core node via JSON-RPC

**LLM Control:**
- **Blockchain Queries:**
  - Get block by height/hash (`getblock`, `getblockhash`)
  - Get transaction details (`getrawtransaction`, `gettransaction`)
  - Get blockchain info (`getblockchaininfo`)
  - Get mempool info (`getmempoolinfo`, `getrawmempool`)
  - Get mining info (`getmininginfo`, `getnetworkhashps`)

- **Wallet Operations:**
  - Get wallet balance (`getbalance`, `getwalletinfo`)
  - List transactions (`listtransactions`)
  - Get addresses (`getnewaddress`, `getaddressinfo`)
  - Send transaction (`sendtoaddress`, `sendrawtransaction`)
  - Create raw transaction (`createrawtransaction`)
  - Sign transaction (`signrawtransactionwithwallet`)

- **Network Queries:**
  - Get peer info (`getpeerinfo`)
  - Get network info (`getnetworkinfo`)
  - Get node addresses (`getnodeaddresses`)

**Implementation Strategy:**
```rust
use bitcoincore_rpc::{Auth, Client, RpcApi};

// Connect to Bitcoin Core RPC
let rpc = Client::new(
    "http://localhost:8332",
    Auth::UserPass("user".to_string(), "pass".to_string())
)?;

// LLM decides: get transaction details
let txid = Txid::from_str(tx_hash)?;
let tx = rpc.get_raw_transaction(&txid, None)?;

// LLM decides: get block info
let block_hash = rpc.get_block_hash(block_height)?;
let block = rpc.get_block(&block_hash)?;

// LLM decides: send transaction
let address = Address::from_str(destination)?;
let txid = rpc.send_to_address(
    &address,
    Amount::from_btc(0.001)?,
    None, None, None, None, None, None
)?;

// LLM decides: query mempool
let mempool = rpc.get_raw_mempool()?;
```

**Use Cases:**
- Query blockchain data
- Monitor transactions
- Wallet management
- Transaction submission
- Mining statistics
- Network monitoring

#### 2. Bitcoin P2P Client (Harder) 🟠
**Connects to:** Bitcoin P2P network nodes

**LLM Control:**
- Connect to peers (version handshake)
- Request blocks (getdata)
- Request transactions
- Relay transactions (inv, tx)
- Query mempool
- Peer discovery (addr messages)

**Implementation Strategy:**
```rust
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::Magic;

// Connect to Bitcoin node
let mut stream = TcpStream::connect((peer_ip, 8333)).await?;

// Send version handshake
let version = NetworkMessage::Version(VersionMessage {
    version: 70015,
    services: ServiceFlags::NETWORK,
    // ...
});
let msg = RawNetworkMessage { magic: Magic::BITCOIN, payload: version };
msg.consensus_encode(&mut stream)?;

// LLM decides: request block
let getdata = NetworkMessage::GetData(vec![
    Inventory::Block(block_hash)
]);
// ...
```

**Challenges (P2P mode):**
- P2P protocol complexity
- Peer discovery
- Block/transaction validation
- Large data downloads
- DOS protection

**Recommended:** Use RPC mode for most use cases (simpler, more reliable)

---

### Kafka ✅ implemented
**Complexity:** Hard
**Client Library:** `kafka-protocol` (pure Rust), used in the client direction and shared with
the Kafka broker through `src/server/kafka/mod.rs`'s re-export. **Not `rdkafka`** — that was
removed for aborting in malloc, and the optional feature it left behind gated the client out of
every `--features kafka` build. See `src/client/kafka/CLAUDE.md`.

**LLM Control:**
- Produce records (`produce_message`, with explicit `utf8`/`hex` field encodings)
- Fetch records from an explicit offset (`fetch_records`)
- Cluster metadata (`list_topics`)
- Offset commits (`commit_offset`)
- **Not** consumer groups: `FindCoordinator`/`JoinGroup`/`SyncGroup`/`Heartbeat` are implemented
  by neither the client nor the broker, so partitions are assigned manually

**Implementation Strategy:**
```rust
use rdkafka::producer::{FutureProducer, FutureRecord};

let producer: FutureProducer = ClientConfig::new()
    .set("bootstrap.servers", brokers)
    .create()?;

// LLM decides: produce to topic
producer.send(
    FutureRecord::to(topic)
        .payload(payload)
        .key(key),
    Duration::from_secs(0)
).await?;
```

**Challenges:**
- Complex protocol (multiple API versions)
- Cluster metadata management
- Consumer group coordination

---

### etcd 🟡
**Complexity:** Medium
**Client Library:** `etcd-client`

**LLM Control:**
- Put/Get/Delete keys
- Watch for changes
- Leases
- Transactions

**Implementation Strategy:**
```rust
use etcd_client::Client;

let mut client = Client::connect(["localhost:2379"], None).await?;

// LLM decides: put, get, watch
client.put("key", "value", None).await?;
let resp = client.get("key", None).await?;
```

**Note:** gRPC-based, relatively straightforward.

---

### Git 🟠
**Complexity:** Hard
**Client Library:** `git2` (libgit2 wrapper)

**LLM Control:**
- Clone repositories
- Fetch/pull/push
- Checkout branches
- Commit creation

**Implementation Strategy:**
```rust
use git2::Repository;

// LLM decides: clone, fetch, etc.
let repo = Repository::clone(url, path)?;
repo.find_remote("origin")?.fetch(&["main"], None, None)?;
```

**Challenges:**
- Smart HTTP/Git protocol complexity
- Authentication (SSH keys, tokens)
- Merge conflict resolution

---

### SVN ❌
**Complexity:** Unfeasible
**Client Library:** `subversion` v0.0.8 (immature, FFI bindings)

**Why Unfeasible:**
- Rust bindings exist (`subversion` v0.0.8) but extremely immature
- Requires Subversion C library (libsvn)
- Complex C API surface (dozens of libraries: libsvn_client, libsvn_ra, libsvn_wc, etc.)
- Working copy management complexity
- Authentication complexity (HTTP, SSH, SVN protocol)
- Limited documentation for Rust bindings
- Better to use `svn` command-line tool via wrapper

**Alternative:** Command wrapper approach - LLM generates `svn` commands:
```rust
// Example: LLM generates svn commands
std::process::Command::new("svn")
    .args(&["checkout", repo_url, dest_path])
    .output()?;
```

---

### Mercurial ❌
**Complexity:** Unfeasible
**Client Library:** `hglib` v0.1.1 or `tokio-hglib` v0.4.0 (command server clients)

**Why Unfeasible:**
- Rust bindings exist (`hglib`, `tokio-hglib`) but use Mercurial command server protocol
- Requires `hg` binary installed on system
- Command server is a Python subprocess wrapper
- Limited to operations exposed by command server
- Not a native protocol implementation
- Wire protocol extremely complex (would need full reimplementation)
- Better to use `hg` command-line tool directly

**Alternative:** Command wrapper approach - LLM generates `hg` commands:
```rust
// Example: LLM generates hg commands
std::process::Command::new("hg")
    .args(&["clone", repo_url, dest_path])
    .output()?;
```

**Note:** `tokio-hglib` provides async command server client if Mercurial integration is required.

---

### VNC 🟡
**Complexity:** Medium
**Client Library:** Custom RFB protocol implementation

**LLM Control:**
- Authentication
- Framebuffer update requests
- Mouse/keyboard events
- Clipboard sync

**Implementation Strategy:**
```rust
// Custom RFB protocol
// LLM decides: click(x, y), type("text"), request_update()

struct VncClient {
    stream: TcpStream,
}

impl VncClient {
    async fn click(&mut self, x: u16, y: u16) {
        // Send PointerEvent message
        let msg = [5, 1, x >> 8, x & 0xff, y >> 8, y & 0xff];
        self.stream.write_all(&msg).await?;
    }
}
```

**Challenges:**
- Framebuffer parsing (large images)
- Encoding formats (Raw, RRE, Hextile, ZRLE)
- Screen coordinate reasoning for LLM

---

### NPM Registry 🟡
**Complexity:** Medium
**Client Library:** HTTP client

**LLM Control:**
- Package search
- Version selection
- Tarball download
- Publish packages

**Implementation:** HTTP API client (extends HTTP).

---

### PyPI 🟡
**Complexity:** Medium
**Client Library:** HTTP client

**LLM Control:**
- Search packages
- Download wheels/sdists
- Upload packages

**Implementation:** Simple HTTP API (extends HTTP).

---

### Maven 🟡
**Complexity:** Medium
**Client Library:** HTTP client

**LLM Control:**
- Artifact search (groupId:artifactId:version)
- POM parsing
- Dependency resolution

**Implementation:** HTTP with XML parsing (extends HTTP).

---

## File & Print Protocols

### SMB/CIFS 🟠
**Complexity:** Hard
**Client Library:** `pavao` or `smbc` (both libsmbclient wrappers)

**LLM Control:**
- Connect to SMB share
- List directory contents
- Read/write files
- Create/delete files and directories
- Get file attributes

**Implementation Strategy (Option 1: pavao):**
```rust
use pavao::{SmbClient, SmbCredentials, SmbMode};

// LLM decides: connect to share
let creds = SmbCredentials::new("username", "password", None, None);
let client = SmbClient::new(creds, SmbMode::Auto)?;

// LLM decides: list directory
let entries = client.list_dir("smb://server/share/path")?;

// LLM decides: read file
let data = client.read("smb://server/share/file.txt")?;

// LLM decides: write file
client.write("smb://server/share/newfile.txt", data)?;
```

**Implementation Strategy (Option 2: smbc):**
```rust
use smbc::{Smb, SmbOptions};

// LLM decides: connect
let options = SmbOptions::default()
    .username("user")
    .password("pass");
let smb = Smb::new(options)?;

// std::fs-like interface
let entries = smb.read_dir("smb://server/share/")?;
let file = smb.open("smb://server/share/file.txt")?;
```

**Use Cases:**
- Windows file share access
- SMB network browsing
- File transfer to/from Windows servers
- CIFS protocol testing

**Challenges:**
- Requires libsmbclient system library
- SMB protocol complexity (SMB1/2/3 versions)
- NTLM authentication complexity
- Windows domain integration
- Kerberos authentication (optional)

**Recommendation:** Use `pavao` for SMB 2/3 support, or `smbc` for std::fs-like interface. Both require libsmbclient system library.

---

### NFS 🟠
**Complexity:** Hard
**Client Library:** `nfs3_client` (pure Rust) or `libnfs` (C bindings)

**LLM Control:**
- Mount NFS export
- Read/write files
- Create/delete files and directories
- Get file attributes
- List directory contents

**Implementation Strategy (Option 1: Pure Rust):**
```rust
use nfs3_client::{Client, MountClient};

// LLM decides: mount NFS export
let mount_client = MountClient::new(nfs_server)?;
let mount_result = mount_client.mount(export_path).await?;

// Get NFS client
let nfs_client = Client::new(nfs_server, mount_result.fhandle)?;

// LLM decides: read file
let file_handle = nfs_client.lookup(dir_fh, filename).await?;
let data = nfs_client.read(file_handle, offset, count).await?;

// LLM decides: write file
nfs_client.write(file_handle, offset, data).await?;
```

**Implementation Strategy (Option 2: C Bindings):**
```rust
use libnfs::{Nfs, NfsContext};

// LLM decides: mount and access
let nfs = Nfs::new()?;
nfs.mount(nfs_server, export_path)?;

// Read/write operations
let data = nfs.read(filepath)?;
nfs.write(filepath, data)?;
```

**Use Cases:**
- Remote file access
- NFS export browsing
- File transfer over NFS
- Network storage testing

**Challenges:**
- NFS v3 protocol complexity (RPC, XDR encoding)
- Mount protocol interaction
- File handle management
- Authentication (AUTH_SYS, Kerberos)
- Performance (many round trips for operations)

**Recommendation:** Use `nfs3_client` for pure Rust implementation, or `libnfs` for more mature C library bindings.

---

### IPP (Internet Printing Protocol) 🟡
**Complexity:** Medium
**Client Library:** HTTP + IPP encoding

**LLM Control:**
- Print job submission
- Job status queries
- Printer capabilities (Get-Printer-Attributes)

**Implementation:** HTTP POST with IPP-encoded body (extends HTTP).

---

## Real-time & Streaming

### SIP (VoIP) 🟠
**Complexity:** Hard
**Client Library:** Custom or `libpjproject` wrapper

**LLM Control:**
- INVITE/BYE call control
- REGISTER for presence
- SDP negotiation
- DTMF tones

**Challenges:**
- SDP (Session Description Protocol) parsing
- RTP media streams (separate from SIP control)
- NAT traversal (STUN/TURN integration)
- Codec selection

**Note:** SIP is only control plane; actual audio/video is RTP.

---

### WebRTC 🔴
**Complexity:** Very Hard
**Client Library:** `webrtc-rs`

**Challenges:**
- Complex signaling (offer/answer SDP exchange)
- ICE candidate gathering (STUN/TURN)
- DTLS-SRTP for media encryption
- Media stack integration (audio/video codecs)

**Reason:** Too complex for LLM-controlled client. LLM would struggle with real-time media decisions.

---

## BitTorrent Family

### BitTorrent Tracker 🟡
**Complexity:** Medium
**Client Library:** HTTP client + bencode

**LLM Control:**
- Announce (started, stopped, completed)
- Parse peer list
- Scrape statistics

**Implementation:** HTTP GET with bencoded response (extends HTTP).

---

### BitTorrent DHT 🟠
**Complexity:** Hard
**Client Library:** Custom (Kademlia DHT)

**LLM Control:**
- find_node queries
- get_peers queries
- announce_peer

**Challenges:**
- UDP-based Kademlia protocol
- Routing table management
- Node ID space understanding

---

### BitTorrent Peer Wire 🟠
**Complexity:** Hard
**Client Library:** Custom

**LLM Control:**
- Handshake
- Bitfield exchange
- Request pieces
- Choke/unchoke strategy

**Challenges:**
- Piece selection algorithms (rarest-first)
- Upload/download rate management
- End-game mode

---

## Authentication & Identity

### OAuth2 🟡
**Complexity:** Medium
**Client Library:** `oauth2` crate

**LLM Control:**
- Flow selection (authorization code, device code, password, client credentials)
- Scope selection
- Token refresh
- Authorization decision

**OAuth2 Flows (Multiple Strategies):**

#### 1. Resource Owner Password Credentials (Direct Username/Password)
**Use Case:** User provides username and password directly to NetGet
```rust
use oauth2::*;

let client = BasicClient::new(
    ClientId::new(client_id),
    Some(ClientSecret::new(client_secret)),
    AuthUrl::new(auth_url)?,
    Some(TokenUrl::new(token_url)?)
);

// LLM prompts user for username/password, then exchanges for tokens
let token_result = client
    .exchange_password(
        &ResourceOwnerUsername::new(username),
        &ResourceOwnerPassword::new(password)
    )
    .add_scope(Scope::new("read".to_string()))
    .request_async(async_http_client)
    .await?;

// Access token and refresh token obtained
let access_token = token_result.access_token();
let refresh_token = token_result.refresh_token();
```

**Pros:** Simple, no browser redirect
**Cons:** Less secure (user trusts NetGet with credentials), not supported by all providers

#### 2. Device Code Flow (For CLI/Terminal Apps)
**Use Case:** User authenticates via browser on another device
```rust
// LLM initiates device code flow
let device_auth_response = client
    .exchange_device_code()?
    .add_scope(Scope::new("read".to_string()))
    .request_async(async_http_client)
    .await?;

// Display to user
println!("Visit: {}", device_auth_response.verification_uri());
println!("Enter code: {}", device_auth_response.user_code());

// LLM polls for completion
let token_result = client
    .exchange_device_access_token(&device_auth_response)
    .request_async(async_http_client, tokio::time::sleep, None)
    .await?;
```

**Pros:** Secure, user authenticates in browser
**Cons:** Requires polling, user must switch to browser

#### 3. Authorization Code Flow (Traditional Web Flow)
**Use Case:** Open browser for user to authenticate
```rust
// LLM generates authorization URL
let (auth_url, csrf_state) = client
    .authorize_url(CsrfToken::new_random)
    .add_scope(Scope::new("read".to_string()))
    .url();

// Open browser (or display URL for user to visit)
println!("Visit: {}", auth_url);

// After user completes auth, receive callback with code
let token_result = client
    .exchange_code(AuthorizationCode::new(code))
    .request_async(async_http_client)
    .await?;
```

**Pros:** Most secure, standard flow
**Cons:** Requires web server to receive callback or manual code paste

#### 4. Client Credentials Flow (Machine-to-Machine)
**Use Case:** Service account authentication (no user)
```rust
// LLM uses client credentials only
let token_result = client
    .exchange_client_credentials()
    .add_scope(Scope::new("api.read".to_string()))
    .request_async(async_http_client)
    .await?;
```

**Pros:** Simplest for service accounts
**Cons:** No user context

**Recommendation for NetGet:**
- **Primary:** Resource Owner Password Credentials (direct username/password)
- **Alternative:** Device Code Flow (more secure, good UX for CLI)
- **Advanced:** Authorization Code with localhost callback server

**Implementation Strategy:**
```rust
// LLM prompts user: "Enter OAuth2 flow: password, device_code, client_credentials"
match llm_flow_choice {
    "password" => {
        // Prompt for username and password
        let tokens = exchange_password(username, password).await?;
    }
    "device_code" => {
        // Display device code and URL
        let tokens = poll_device_code().await?;
    }
    "client_credentials" => {
        // Use client ID/secret only
        let tokens = exchange_client_credentials().await?;
    }
}
```

---

### OpenID Connect 🟡
**Complexity:** Medium
**Client Library:** `openidconnect` crate

**LLM Control:**
- Discovery (.well-known/openid-configuration)
- Authentication request
- Token validation
- UserInfo endpoint

**Implementation:** OAuth2 extension with ID tokens (JWT).

---

### SAML 🟠
**Complexity:** Hard
**Client Library:** Custom XML (no mature Rust SAML lib)

**LLM Control:**
- SP-initiated SSO
- AuthnRequest generation
- Response parsing/validation

**Challenges:**
- XML signatures (xmlsec)
- Certificate management
- SAML bindings (HTTP-POST, HTTP-Redirect)

---

## Cloud & Container Orchestration

### S3 (AWS) 🟡
**Complexity:** Medium
**Client Library:** `aws-sdk-s3`

**LLM Control:**
- PutObject/GetObject
- ListBuckets
- Multipart uploads
- Presigned URLs

**Implementation Strategy:**
```rust
use aws_sdk_s3::Client;

let client = Client::new(&config);

// LLM decides: upload, download, list
client.put_object()
    .bucket(bucket)
    .key(key)
    .body(data.into())
    .send().await?;
```

**Note:** HTTP-based with AWS Signature v4 auth.

---

### SQS (AWS) 🟡
**Complexity:** Medium
**Client Library:** `aws-sdk-sqs`

**LLM Control:**
- SendMessage
- ReceiveMessage
- DeleteMessage
- Queue attributes

**Implementation:** HTTP-based AWS API (extends HTTP).

---

### Kubernetes API 🟡
**Complexity:** Medium
**Client Library:** `kube` v2.0.1 (kube-rs) - mature, actively maintained

**LLM Control:**
- Resource CRUD (Pods, Deployments, Services, ConfigMaps, etc.)
- Namespace selection
- Label selectors and field selectors
- Watch resources for changes
- Logs streaming
- Port forwarding
- Execute commands in pods

**Implementation Strategy:**
```rust
use kube::{Client, Api, ResourceExt};
use k8s_openapi::api::core::v1::Pod;

// Create k8s client
let client = Client::try_default().await?;

// LLM decides: list pods in namespace
let pods: Api<Pod> = Api::namespaced(client.clone(), "default");
let pod_list = pods.list(&Default::default()).await?;

for pod in pod_list {
    println!("Pod: {}", pod.name_any());
}

// LLM decides: create deployment
use k8s_openapi::api::apps::v1::Deployment;
let deployments: Api<Deployment> = Api::namespaced(client.clone(), "default");
let deployment = serde_json::from_value(llm_deployment_json)?;
deployments.create(&Default::default(), &deployment).await?;

// LLM decides: get pod logs
let logs = pods.logs("my-pod", &Default::default()).await?;

// LLM decides: watch for changes
use futures::TryStreamExt;
let mut stream = pods.watch(&Default::default(), "0").await?.boxed();
while let Some(event) = stream.try_next().await? {
    // LLM processes event
}
```

**Use Cases:**
- Cluster management and monitoring
- Pod/Deployment operations (create, delete, scale)
- Log collection and analysis
- Resource inspection (describe, get)
- Namespace management
- ConfigMap/Secret operations
- Service discovery

**Kubernetes Resources Accessible:**
- **Workloads:** Pods, Deployments, StatefulSets, DaemonSets, Jobs, CronJobs
- **Services:** Services, Endpoints, Ingress
- **Config:** ConfigMaps, Secrets
- **Storage:** PersistentVolumes, PersistentVolumeClaims
- **RBAC:** Roles, RoleBindings, ServiceAccounts
- **Cluster:** Nodes, Namespaces, Events

**Authentication:**
- Kubeconfig file (`~/.kube/config`)
- In-cluster service account
- Bearer token
- Client certificates

**LLM Action Examples:**
```json
{
  "type": "k8s_list_pods",
  "namespace": "default",
  "label_selector": "app=nginx"
}

{
  "type": "k8s_get_logs",
  "pod_name": "nginx-abc123",
  "namespace": "default",
  "tail_lines": 100
}

{
  "type": "k8s_scale_deployment",
  "deployment_name": "nginx",
  "namespace": "default",
  "replicas": 3
}
```

**Challenges:**
- Requires kubeconfig or in-cluster credentials
- Large API surface (many resource types)
- Version skew between client and server
- Complex RBAC permissions
- LLM must understand k8s concepts (Deployments vs Pods, etc.)

**Recommendation:** Use `kube` crate with k8s-openapi types. LLM generates resource manifests as JSON, NetGet applies via API.

---

## Misc Protocols

### Whois 🟡
**Complexity:** Medium
**Client Library:** Raw TCP + text protocol

**LLM Control:**
- Domain/IP query
- Parse text response
- Follow referrals

**Implementation Strategy:**
```rust
// Simple TCP text protocol
let mut stream = TcpStream::connect("whois.iana.org:43").await?;
stream.write_all(b"example.com\r\n").await?;

let mut response = String::new();
stream.read_to_string(&mut response).await?;
```

**Note:** Very simple, mostly parsing challenge.

---

### Syslog 🟡
**Complexity:** Medium
**Client Library:** `syslog` crate

**LLM Control:**
- Log message generation
- Facility/severity selection
- Target server

**Implementation:** UDP or TCP with syslog message format.

---

### NNTP (Usenet) 🟡
**Complexity:** Medium
**Client Library:** Custom TCP client

**LLM Control:**
- GROUP selection
- ARTICLE/HEAD/BODY retrieval
- POST articles
- XOVER for message lists

**Implementation:** Text protocol over TCP (similar to SMTP/IMAP).

---

### DHCP 🟡
**Complexity:** Medium
**Client Library:** `dhcproto` (parser/encoder), `mozim` (client library), or `toe-beans` (client + server)

**Use Case:** DHCP testing, network diagnostics, IP address discovery (NOT for managing OS network stack)

**LLM Control:**
- Send DHCP DISCOVER (broadcast or unicast)
- Send DHCP REQUEST for specific IP
- Request IP for specific MAC address (spoofing for testing)
- Parse DHCP OFFER/ACK responses
- Extract offered IP, subnet mask, gateway, DNS servers
- DHCP INFORM requests (query options without lease)

**Implementation Strategy:**
```rust
use dhcproto::{v4, Encodable, Decodable};
use tokio::net::UdpSocket;

// Bind to DHCP client port
let socket = UdpSocket::bind("0.0.0.0:68").await?;
socket.set_broadcast(true)?;

// LLM decides: send DHCP DISCOVER for specific MAC
let mut discover = v4::Message::new(
    /* your IP */ Ipv4Addr::UNSPECIFIED,
    /* server IP */ Ipv4Addr::UNSPECIFIED,
    /* gateway */ Ipv4Addr::UNSPECIFIED,
    /* client MAC */ llm_specified_mac,
);
discover.set_flags(v4::Flags::BROADCAST);
discover.opcode = v4::Opcode::BootRequest;
discover.opts_mut().insert(v4::DhcpOption::MessageType(v4::MessageType::Discover));

// Send to broadcast or specific DHCP server
let encoded = discover.to_vec()?;
socket.send_to(&encoded, "255.255.255.255:67").await?;

// LLM processes: receive DHCP OFFER
let mut buf = vec![0u8; 1500];
let (len, peer) = socket.recv_from(&mut buf).await?;
let offer = v4::Message::decode(&mut &buf[..len])?;

// Extract offered IP address
if let Some(v4::DhcpOption::MessageType(v4::MessageType::Offer)) = offer.opts().get(v4::OptionCode::MessageType) {
    let offered_ip = offer.yiaddr(); // Your IP address
    let server_ip = offer.opts().get(v4::OptionCode::ServerIdentifier);
    // LLM analyzes offer and decides whether to accept
}
```

**Use Cases:**
- **DHCP Server Testing:** Verify server responds correctly
- **Network Discovery:** Find DHCP servers on network
- **IP Conflict Detection:** Request specific IP to test if already allocated
- **MAC-based IP Querying:** Request IP for specific MAC (useful for testing)
- **DHCP Option Analysis:** Inspect DNS, gateway, NTP servers offered
- **Rogue DHCP Detection:** Monitor for unauthorized DHCP servers

**LLM Action Examples:**
```json
{
  "type": "dhcp_discover",
  "mac_address": "00:11:22:33:44:55",
  "broadcast": true
}

{
  "type": "dhcp_request",
  "requested_ip": "192.168.1.100",
  "dhcp_server": "192.168.1.1",
  "mac_address": "00:11:22:33:44:55"
}

{
  "type": "dhcp_inform",
  "current_ip": "192.168.1.50",
  "query_options": ["dns_servers", "gateway", "ntp_servers"]
}
```

**Challenges:**
- Requires binding to port 68 (may need elevated privileges)
- Broadcast socket configuration
- DHCP option parsing (many option types)
- Timing (DHCP has specific timeout requirements)
- Does NOT configure OS network stack (that's intentional)

**Important:** This is for DHCP **testing and monitoring**, NOT for managing the OS network interface. The OS DHCP client continues to manage actual network configuration.

**Recommendation:** Use `dhcproto` for protocol encoding/decoding, implement custom client logic for testing scenarios.

---

### BOOTP 🟡
**Complexity:** Medium
**Client Library:** `dhcproto` (supports BOOTP as DHCP subset)

**Use Case:** Legacy network testing, embedded systems, diskless workstation simulation

**LLM Control:**
- Send BOOTP request
- Specify client MAC address
- Parse BOOTP reply (IP, server, boot filename)
- Extract boot server address

**Implementation Strategy:**
```rust
use dhcproto::v4;

// BOOTP is essentially DHCP without options
let mut bootp_request = v4::Message::new(
    Ipv4Addr::UNSPECIFIED,
    Ipv4Addr::UNSPECIFIED,
    Ipv4Addr::UNSPECIFIED,
    client_mac,
);
bootp_request.opcode = v4::Opcode::BootRequest;
// No DHCP options = BOOTP

// Send to BOOTP server
socket.send_to(&bootp_request.to_vec()?, "255.255.255.255:67").await?;

// Parse BOOTP reply
let reply = v4::Message::decode(&mut response_buf)?;
let assigned_ip = reply.yiaddr();
let boot_server = reply.siaddr();
let boot_filename = reply.fname(); // Boot file name (e.g., "pxelinux.0")
```

**Use Cases:**
- PXE boot testing
- Diskless workstation simulation
- Legacy network compatibility testing
- TFTP server discovery

**Note:** BOOTP is simpler than DHCP (no options), primarily for boot file location.

---

### IGMP 🟠
**Complexity:** Hard (Requires Root)
**Client Library:** `pcap` + `pnet` for IGMP packet construction, or raw IP sockets

**Prerequisites:**
- **Root/CAP_NET_RAW** - Required for raw packet injection
- Alternatively, use socket options (IP_ADD_MEMBERSHIP) for standard multicast join

**LLM Control:**
- Send IGMP Membership Report (join multicast group)
- Send IGMP Leave Group message
- Send IGMPv2/IGMPv3 reports
- Specify multicast group address
- Query IGMP state

**Implementation Strategy (Option 1: Raw Packet Injection):**
```rust
use pcap::{Capture, Device};
use pnet::packet::igmp::{IgmpPacket, MutableIgmpPacket, IgmpType};
use pnet::packet::ip::IpNextHeaderProtocols;

// Open interface for sending (requires root)
let device = Device::lookup()?.unwrap();
let mut cap = Capture::from_device(device)?.open()?;

// LLM decides: join multicast group 239.1.2.3
let multicast_addr = Ipv4Addr::new(239, 1, 2, 3);

// Construct IGMP Membership Report
let mut igmp_buffer = vec![0u8; 8]; // IGMP packet size
let mut igmp_packet = MutableIgmpPacket::new(&mut igmp_buffer).unwrap();

igmp_packet.set_igmp_type(IgmpType::MembershipReportV2);
igmp_packet.set_group_addr(multicast_addr);
igmp_packet.set_checksum(/* calculate checksum */);

// Wrap in IP packet
let mut ip_packet = construct_ip_packet(
    src_ip,
    multicast_addr, // Dest is the multicast group
    IpNextHeaderProtocols::Igmp,
    &igmp_buffer
);

// Send via pcap
cap.sendpacket(&ip_packet)?;
```

**Implementation Strategy (Option 2: Socket Options - Easier):**
```rust
use socket2::{Socket, Domain, Type, Protocol};
use std::net::Ipv4Addr;

// Create UDP socket
let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

// LLM decides: join multicast group
let multicast_addr = Ipv4Addr::new(239, 1, 2, 3);
let interface_addr = Ipv4Addr::new(0, 0, 0, 0); // Any interface

// Join multicast group (kernel sends IGMP report automatically)
socket.join_multicast_v4(&multicast_addr, &interface_addr)?;

// LLM can now receive multicast traffic
// When done, leave group (kernel sends IGMP leave)
socket.leave_multicast_v4(&multicast_addr, &interface_addr)?;
```

**Use Cases:**
- **Multicast Group Testing:** Verify multicast router functionality
- **IGMP Snooping Testing:** Test switch IGMP snooping behavior
- **Multicast Discovery:** Find active multicast groups
- **IGMP Query Response:** Respond to router IGMP queries
- **Group Membership Simulation:** Simulate multiple hosts joining groups

**IGMP Message Types:**
- **IGMPv1 Membership Report** (0x12)
- **IGMPv2 Membership Report** (0x16)
- **IGMPv2 Leave Group** (0x17)
- **IGMPv3 Membership Report** (0x22)
- **IGMP Membership Query** (0x11) - Usually sent by routers

**LLM Action Examples:**
```json
{
  "type": "igmp_join_group",
  "multicast_group": "239.1.2.3",
  "interface": "eth0",
  "igmp_version": "v2"
}

{
  "type": "igmp_leave_group",
  "multicast_group": "239.1.2.3",
  "interface": "eth0"
}

{
  "type": "igmp_send_report",
  "groups": ["239.1.2.3", "239.1.2.4"],
  "igmp_version": "v3"
}
```

**Challenges:**
- Raw packet injection requires root privileges
- IGMP checksum calculation (includes IP pseudo-header)
- TTL must be 1 for IGMP packets (link-local)
- Router Alert IP option required for IGMPv2/v3
- Coordination with kernel multicast stack

**Recommendation:**
- **For Testing:** Use raw packet injection (Option 1) to manually craft IGMP messages
- **For Receiving Multicast:** Use socket options (Option 2) for standard multicast reception
- **Hybrid:** Socket options for join/leave, pcap capture for monitoring IGMP traffic

**Important:** IGMP is typically handled by the kernel, but raw injection allows testing IGMP behavior without kernel involvement.

---

## Proxy Routing Architecture

### Overview

NetGet supports routing client traffic through proxy protocols (HTTP Proxy, SOCKS5, STUN, TURN). This enables:
- HTTP client → HTTP Proxy → destination
- Any TCP client → SOCKS5 → destination
- WebRTC client → TURN relay → peer

### Design Approach

**Proxy-as-Middleware Pattern:**

Clients accept an optional `proxy_config` parameter that specifies routing through a proxy client. The proxy client establishes the tunnel, then the target client sends data through it.

### Implementation Strategy

#### Option 1: Configuration-Based (Recommended)

```rust
// Client startup accepts proxy configuration
pub struct ProxyConfig {
    pub proxy_type: ProxyType,  // Socks5, HttpProxy, etc.
    pub proxy_addr: String,
    pub auth: Option<ProxyAuth>,
}

pub enum ProxyType {
    Socks5,
    HttpProxy,
    HttpsProxy,
}

// HTTP client with proxy support
HttpClient::connect_with_llm_actions(
    remote_addr,
    llm_client,
    app_state,
    status_tx,
    client_id,
    Some(ProxyConfig {
        proxy_type: ProxyType::Socks5,
        proxy_addr: "127.0.0.1:1080".to_string(),
        auth: None,
    })
).await?;
```

**Implementation in HTTP client:**
```rust
impl HttpClient {
    pub async fn connect_with_llm_actions(
        /* ... */
        proxy_config: Option<ProxyConfig>,
    ) -> Result<SocketAddr> {
        let client = if let Some(proxy) = proxy_config {
            match proxy.proxy_type {
                ProxyType::Socks5 => {
                    // Use tokio-socks to establish SOCKS tunnel
                    let proxy = Proxy::all(&proxy.proxy_addr)?;
                    reqwest::Client::builder()
                        .proxy(proxy)
                        .build()?
                }
                ProxyType::HttpProxy => {
                    let proxy = Proxy::http(&proxy.proxy_addr)?;
                    reqwest::Client::builder()
                        .proxy(proxy)
                        .build()?
                }
            }
        } else {
            reqwest::Client::new()
        };

        // Rest of implementation...
    }
}
```

#### Option 2: Chained Clients (Advanced)

For protocols that don't natively support proxies, chain through SOCKS:

```rust
// 1. LLM opens SOCKS5 client
let socks_client_id = open_client("socks5", "127.0.0.1:1080", "Establish tunnel to example.com:80").await?;

// 2. SOCKS5 client negotiates and returns a TcpStream-like handle
let tunneled_stream = app_state.get_proxy_stream(socks_client_id)?;

// 3. Custom protocol uses the tunneled stream
let custom_client = CustomTcpClient::connect_via_stream(tunneled_stream, llm_client, ...).await?;
```

**Challenges:**
- Need abstraction for "stream provider" (direct TCP vs proxied TCP)
- Proxy client must expose the tunneled connection
- Connection lifecycle management (close proxy when client closes)

#### Option 3: LLM-Directed Composition

LLM explicitly chains clients:

```rust
// User: "Connect to example.com via SOCKS proxy at 127.0.0.1:1080"

// LLM interprets as two-step process:
// Step 1: Open SOCKS5 client
let socks_id = execute_action(json!({
    "type": "open_client",
    "protocol": "socks5",
    "remote_addr": "127.0.0.1:1080",
    "instruction": "Establish tunnel to example.com:80"
}));

// Step 2: Use SOCKS client ID in HTTP request
let http_id = execute_action(json!({
    "type": "open_client",
    "protocol": "http",
    "remote_addr": "example.com:80",
    "proxy_client_id": socks_id,  // Route through this client
    "instruction": "GET / via SOCKS proxy"
}));
```

### Proxy Protocol Details

#### SOCKS5 Proxy Client

**Purpose:** TCP proxy for any protocol

```rust
pub struct Socks5ClientProtocol;

impl Client for Socks5ClientProtocol {
    async fn connect(&self, ctx: ConnectContext) -> Result<SocketAddr> {
        // 1. Connect to SOCKS5 proxy
        let stream = TcpStream::connect(&ctx.remote_addr).await?;

        // 2. SOCKS5 handshake
        // Auth negotiation (none, username/password)

        // 3. CONNECT request (LLM specifies target)
        let target = parse_target_from_instruction(&ctx.instruction)?;
        send_socks5_connect(&stream, target).await?;

        // 4. Now stream is tunneled - store for other clients to use
        ctx.app_state.set_proxy_stream(ctx.client_id, stream).await;

        Ok(stream.local_addr()?)
    }
}
```

**Actions:**
- `socks_connect(target)` - Establish tunnel to target
- `socks_disconnect()` - Close tunnel

#### HTTP Proxy Client

**Purpose:** HTTP/HTTPS proxy (CONNECT method)

```rust
pub struct HttpProxyClientProtocol;

impl Client for HttpProxyClientProtocol {
    async fn connect(&self, ctx: ConnectContext) -> Result<SocketAddr> {
        // For HTTPS, send CONNECT request
        let target = parse_target_from_instruction(&ctx.instruction)?;

        let request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            target, target
        );

        // Send CONNECT, read "200 Connection established"
        // Now tunnel is ready for TLS/data

        Ok(stream.local_addr()?)
    }
}
```

#### TURN Relay Client

**Purpose:** UDP relay for WebRTC/NAT traversal

```rust
pub struct TurnClientProtocol;

impl Client for TurnClientProtocol {
    async fn connect(&self, ctx: ConnectContext) -> Result<SocketAddr> {
        // 1. Connect to TURN server
        // 2. Allocate relay (STUN Allocate request)
        // 3. Create permissions for peer
        // 4. ChannelBind for efficient relay

        // Return relay address for peer connection
        Ok(relay_addr)
    }
}
```

**Actions:**
- `turn_allocate()` - Request relay address
- `turn_create_permission(peer_addr)` - Allow peer
- `turn_send_data(data)` - Send via relay
- `turn_refresh()` - Keep allocation alive

### Usage Examples

#### Example 1: HTTP via HTTP Proxy

```bash
# User command
open_client http example.com:80 --proxy http://proxy.example.com:8080 "GET /"
```

```rust
// Translated to action
{
  "type": "open_client",
  "protocol": "http",
  "remote_addr": "example.com:80",
  "proxy_config": {
    "type": "http_proxy",
    "address": "proxy.example.com:8080"
  },
  "instruction": "GET /"
}
```

#### Example 2: SSH via SOCKS5

```bash
# User command
open_client ssh remote-server:22 --proxy socks5://localhost:1080 "Connect and execute ls"
```

```rust
// SSH client receives proxy config, establishes via SOCKS
let stream = if let Some(proxy) = proxy_config {
    Socks5Stream::connect(
        proxy.address,
        (remote_host, 22)
    ).await?
} else {
    TcpStream::connect((remote_host, 22)).await?
};
```

#### Example 3: Chained Proxies

```bash
# User wants: HTTP → SOCKS5 → HTTP Proxy → Destination
open_client http example.com:80 --proxy socks5://localhost:1080 --proxy-chain http://proxy:8080 "GET /"
```

**Implementation:** Recursively wrap connections:
1. Connect to SOCKS5 (localhost:1080)
2. SOCKS5 connects to HTTP Proxy (proxy:8080)
3. HTTP Proxy connects to destination (example.com:80)

### State Management

Proxy clients are tracked as regular clients:
```rust
pub struct ClientInstance {
    pub id: ClientId,
    pub protocol_name: String,  // "socks5", "http_proxy", etc.
    pub remote_addr: String,    // Proxy address
    pub status: ClientStatus,
    pub proxy_target: Option<String>,  // Ultimate destination
    // ...
}
```

**Lifecycle:**
1. User opens proxy client → ClientId assigned
2. Proxy establishes tunnel → Status: Connected
3. Target client references proxy → Uses tunneled connection
4. User closes target client → Target closed, proxy remains
5. User closes proxy client → Tunnel torn down

### LLM Integration

LLM sees proxy actions in both client types:

**HTTP Client Actions (with proxy support):**
```json
{
  "name": "send_http_request",
  "parameters": {
    "method": "GET",
    "path": "/",
    "headers": {},
    "use_proxy": "client-123"  // Optional: route via proxy client
  }
}
```

**SOCKS5 Client Actions:**
```json
{
  "name": "socks_establish_tunnel",
  "parameters": {
    "target_host": "example.com",
    "target_port": 80
  }
}
```

### Implementation Priority

1. **Phase 1:** SOCKS5 client (most versatile, works with any TCP protocol)
2. **Phase 2:** HTTP Proxy client (common for HTTP/HTTPS)
3. **Phase 3:** Configuration-based proxy support in HTTP/SSH/etc clients
4. **Phase 4:** TURN client (specialized for WebRTC)

---

## Summary Statistics

### By Complexity

| Complexity | Count | Protocols |
|------------|-------|-----------|
| ✅ Easy | 4 | TCP, HTTP, Redis, Whois |
| 🟡 Medium | 40 | UDP, HTTPS, HTTP/2, WebDAV, DNS, DoT, DoH, SMTP, IRC, MQTT, MySQL, PostgreSQL, DynamoDB, Elasticsearch, Telnet, SNMP, NTP, SOCKS5, HTTP Proxy, STUN, gRPC, JSON-RPC, XML-RPC, MCP, OpenAI, etcd, VNC, NPM, PyPI, Maven, IPP, BitTorrent Tracker, OAuth2, OpenID, S3, SQS, Syslog, NNTP, Bitcoin (RPC), RIP (Query), **Kubernetes**, **DHCP**, **BOOTP** |
| 🟠 Hard | 23 | HTTP/3, mDNS, IMAP, XMPP, Cassandra, SSH, LDAP, Tor, TURN, Kafka, Git, SIP, BitTorrent DHT, BitTorrent Peer, SAML, DataLink (requires root), ARP (requires root), BGP (Query), OSPF (Query), ISIS (Query), **NFS**, **SMB**, **IGMP** (requires root) |
| 🔴 Very Hard | 1 | WireGuard |
| ❌ Unfeasible | 5 | OpenVPN, IPSec, **SVN**, **Mercurial**, WebRTC |

### Implementation Priority Recommendations

**Phase 1 (Quick Wins):**
1. UDP - Simple extension of TCP pattern
2. DNS - Common need, excellent library (hickory-dns)
3. SMTP - Email sending with `lettre`
4. MySQL/PostgreSQL - Database clients (`mysql_async`, `tokio-postgres`)
5. MQTT - IoT/messaging with `rumqttc`
6. SOCKS5 - Universal TCP proxy client

**Phase 2 (High Value):**
1. SSH - Remote command execution (`russh`)
2. gRPC - Modern microservices (`tonic`)
3. Elasticsearch - Search/analytics (HTTP-based)
4. Kafka - Streaming data (`rdkafka`)
5. S3 - Object storage (`aws-sdk-s3`)
6. Bitcoin RPC - Blockchain queries (`bitcoin-rpc`)

**Phase 3 (Specialized):**
1. IMAP - Email retrieval (`async-imap`)
2. LDAP - Directory services (`ldap3`)
3. Git - Version control (`git2`)
4. VNC - Remote desktop (custom RFB)
5. RIP - Routing table queries (UDP-based)

**Phase 4 (Advanced/Research):**
1. BGP Query - Route monitoring (custom protocol)
2. OSPF Query - Topology discovery (raw sockets, requires root)
3. DataLink/ARP - Raw frame injection (pcap, requires root)
4. Tor - Onion routing (`arti`)
5. BitTorrent P2P - Distributed file sharing

**Avoid (Too Complex/Low Value):**
- OpenVPN (no Rust library, extremely complex)
- VPN protocols requiring kernel (WireGuard, IPSec)
- Version control with immature bindings (SVN, Mercurial - use command wrappers)
- WebRTC (real-time media too complex for LLM)

---

## Mock/Fake Client Strategy

For protocols marked as "Unfeasible" but needed for testing:

### Option 1: Command Wrapper Clients
Use existing CLI tools, LLM generates commands:
- **OpenVPN**: `openvpn --config llm-generated.conf`
- **WireGuard**: `wg-quick up llm-generated-wg0.conf`
- **SMB**: `smbclient //server/share -c "ls"`
- **DHCP**: `dhclient -sf /path/to/llm-script`

### Option 2: Fake Protocol Clients
Simulate protocol without real implementation:
- **BGP**: HTTP client sends fake BGP announcements to monitoring API
- **OSPF**: Log "routing updates" without real packets
- **WebRTC**: Use WebRTC signaling only (no media)

### Option 3: Stateful Mocks
TCP client sending protocol-shaped data:
- Connect to server
- Send plausible-looking protocol messages
- Parse responses (best-effort)
- Good for testing server implementations

---

## Implementation Template

For new client protocols, follow this structure:

```rust
// src/client/{protocol}/mod.rs
pub mod actions;
pub use actions::{ProtocolClientProtocol};

use tokio::net::TcpStream;
use crate::llm::action_helper::call_llm_for_client;

pub struct ProtocolClient;

impl ProtocolClient {
    pub async fn connect_with_llm_actions(
        remote_addr: String,
        llm_client: OllamaClient,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
        client_id: ClientId,
    ) -> Result<SocketAddr> {
        // 1. Connect to server
        let stream = TcpStream::connect(&remote_addr).await?;
        let local_addr = stream.local_addr()?;

        // 2. Spawn LLM integration loop
        tokio::spawn(async move {
            // State machine: Idle -> Processing -> Accumulating
            loop {
                // Read from server
                // Call LLM with event
                // Execute actions
            }
        });

        Ok(local_addr)
    }
}

// src/client/{protocol}/actions.rs
use crate::llm::actions::client_trait::{Client, ClientActionResult};

pub static PROTOCOL_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("protocol_connected", "Connected to protocol server")
});

pub struct ProtocolClientProtocol;

impl Client for ProtocolClientProtocol {
    fn connect(&self, ctx: ConnectContext) -> Pin<Box<dyn Future<Output = Result<SocketAddr>> + Send>> {
        Box::pin(async move {
            ProtocolClient::connect_with_llm_actions(
                ctx.remote_addr, ctx.llm_client, ctx.app_state,
                ctx.status_tx, ctx.client_id
            ).await
        })
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "send_data".to_string(),
                description: "Send data to server".to_string(),
                parameters: vec![...],
                example: json!({...}),
            }
        ]
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        match action["type"].as_str() {
            Some("send_data") => {
                let data = ...; // Parse from action
                Ok(ClientActionResult::SendData(data))
            }
            _ => Err(anyhow!("Unknown action"))
        }
    }
}
```

---

## Conclusion

**73 server protocols analyzed:**
- ✅ **4 Easy** - Already proven pattern (TCP, HTTP, Redis implemented)
- 🟡 **40 Medium** - Straightforward with good libraries (including Kubernetes, DHCP, BOOTP)
- 🟠 **23 Hard** - Complex but feasible with effort (including NFS, SMB, IGMP)
- 🔴 **1 Very Hard** - Possible but marginal value (WireGuard only)
- ❌ **5 Unfeasible** - Wrong abstraction or requires kernel (OpenVPN, IPSec, SVN, Mercurial, WebRTC)

**Key Updates:**
- **Kubernetes:** Now feasible with `kube` v2.0.1 (mature, actively maintained)
- **DHCP/BOOTP:** Feasible for testing and monitoring (not OS network stack management)
- **IGMP:** Feasible via raw packet injection or socket options (multicast testing)
- **NFS:** Feasible with `nfs3_client` (pure Rust) or `libnfs` (C bindings)
- **SMB:** Feasible with `pavao` or `smbc` (libsmbclient wrappers)
- **SVN/Mercurial:** Marked unfeasible (use command wrappers instead)

**Recommended next implementations:** UDP, DNS, SMTP, MySQL, MQTT, Kubernetes (all Medium complexity, high utility).

**Mock client strategy:** Command wrappers for unfeasible protocols (SVN, Mercurial) enable server testing without full client implementation.
