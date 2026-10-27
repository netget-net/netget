# Protocol Metadata V2 - Example Implementations

This file contains example `metadata_v2()` implementations for various protocols to serve as a reference when migrating.

## Core Transport Protocols

### HTTP (Beta - Real Server Library)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Beta)
        .implementation("hyper v1.0 web server library")
        .llm_control("Response content (status, headers, body)")
        .e2e_testing("reqwest HTTP client - 14 LLM calls")
        .build()
}
```

### TCP (Beta - Protocol Parser)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Beta)
        .implementation("Manual TCP socket handling with tokio")
        .llm_control("Full byte stream control - all sent/received data")
        .e2e_testing("tokio::net::TcpStream")
        .notes("Basis for FTP, SMTP, custom protocols")
        .build()
}
```

### UDP (Beta - Protocol Parser)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Beta)
        .implementation("Manual UDP socket handling with tokio")
        .llm_control("Full datagram control - all sent/received data")
        .e2e_testing("std::net::UdpSocket")
        .notes("Stateless, used by DNS/DHCP/NTP")
        .build()
}
```

## Application Protocols - Beta

### SSH (Beta with Scripting)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Beta)
        .implementation("russh v0.40 with SFTP support")
        .llm_control("Authentication decisions + shell responses + SFTP operations")
        .e2e_testing("ssh2 crate (libssh2 bindings)")
        .notes("Supports scripting for auth (0 LLM calls after setup)")
        .build()
}
```

### DNS (Beta - Real Server Library)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Beta)
        .implementation("hickory-proto for parsing and construction")
        .llm_control("Response records (A, AAAA, MX, TXT, CNAME, NXDOMAIN)")
        .e2e_testing("hickory-client AsyncClient - 5 LLM calls")
        .notes("Excellent scripting candidate")
        .build()
}
```

### DHCP (Beta)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Beta)
        .implementation("dhcproto v0.11 for parsing")
        .llm_control("DISCOVER→OFFER, REQUEST→ACK flow + lease options")
        .e2e_testing("Manual DHCP packet construction - 3 LLM calls")
        .notes("Lenient validation for testing")
        .build()
}
```

### NTP (Beta)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Beta)
        .implementation("Manual 48-byte NTP packet construction")
        .llm_control("Time responses (stratum, timestamps)")
        .e2e_testing("Manual NTP packet construction")
        .notes("Sub-ms with scripting, simple protocol")
        .build()
}
```

### SNMP (Beta)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Beta)
        .implementation("rasn-snmp v0.18 for parsing + manual BER encoding")
        .llm_control("OID responses (sysDescr, ifTable, custom MIBs)")
        .e2e_testing("net-snmp tools (snmpget)")
        .notes("SNMPv1/v2c only, manual BER encoding")
        .build()
}
```

### DoT (DNS-over-TLS) (Beta)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Beta)
        .implementation("hickory-proto + tokio-rustls")
        .llm_control("Same as DNS (delegates to DNS protocol)")
        .e2e_testing("hickory-client with TLS")
        .notes("Self-signed certs, TLS overhead")
        .build()
}
```

### DoH (DNS-over-HTTPS) (Beta)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Beta)
        .implementation("hickory-proto + hyper + tokio-rustls")
        .llm_control("Same as DNS (delegates to DNS protocol)")
        .e2e_testing("reqwest with DoH support")
        .notes("GET/POST methods, HTTP/2")
        .build()
}
```

### DataLink (Beta - Capture Only)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState, PrivilegeRequirement};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Beta)
        .privilege_requirement(PrivilegeRequirement::RawSockets)
        .implementation("libpcap (pcap crate) for Layer 2 packet capture")
        .llm_control("Observation only - no packet injection")
        .e2e_testing("libpcap for packet validation")
        .notes("Requires root/CAP_NET_RAW for promiscuous mode")
        .build()
}
```

## VPN/Network Protocols

### WireGuard (Stable - Production Ready)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState, PrivilegeRequirement};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Stable)
        .privilege_requirement(PrivilegeRequirement::Root)
        .implementation("defguard_wireguard_rs v0.7 - creates real TUN interfaces")
        .llm_control("Peer authorization + allowed IPs configuration")
        .e2e_testing("wg CLI or WireGuard client libraries")
        .notes("ONLY functional VPN - production-ready")
        .build()
}
```

### Tor Relay (Stable - Production Ready)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Stable)
        .implementation("Custom Tor OR protocol with ntor handshake - 2,182 LOC")
        .llm_control("Circuit creation logging + unknown relay command responses")
        .e2e_testing("Official Tor client (tor binary)")
        .notes("Full exit relay, cryptographically correct, production-ready")
        .build()
}
```

### Tor Directory (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("HTTP-based directory protocol")
        .llm_control("Directory responses (consensus, descriptors)")
        .e2e_testing("HTTP client (reqwest)")
        .notes("Serves Tor network directory info")
        .build()
}
```

### OpenVPN (Incomplete - Honeypot)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Incomplete)
        .implementation("Manual opcode parsing (no TLS/encryption)")
        .llm_control("Detection/logging only - no tunnel establishment")
        .e2e_testing("N/A (honeypot only)")
        .notes("Detects OpenVPN handshakes but cannot establish tunnels")
        .build()
}
```

### IPSec (Incomplete - Honeypot)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Incomplete)
        .implementation("Honeypot only (no encryption)")
        .llm_control("Detection only")
        .e2e_testing("N/A (honeypot only)")
        .notes("Too complex for full implementation")
        .build()
}
```

### HTTP Proxy (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("Manual HTTP proxy with MITM support")
        .llm_control("Request/response filtering + modification")
        .e2e_testing("reqwest with proxy")
        .notes("MITM with cert generation, pass-through mode")
        .build()
}
```

### SOCKS5 (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("Manual SOCKS5 RFC 1928 implementation")
        .llm_control("Authentication + connection filtering + optional MITM")
        .e2e_testing("Manual SOCKS5 client")
        .notes("Username/password auth, CONNECT only")
        .build()
}
```

## AI & API Protocols

### OpenAI API (Beta - Passthrough)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Beta)
        .implementation("hyper with OpenAI-compatible HTTP endpoints")
        .llm_control("No LLM control - direct Ollama delegation")
        .e2e_testing("openai Python SDK and async-openai Rust client")
        .notes("Zero-config passthrough to Ollama")
        .build()
}
```

### MCP (Model Context Protocol) (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("Custom MCP implementation")
        .llm_control("Tool calls + context")
        .e2e_testing("MCP client")
        .notes("Anthropic's MCP standard")
        .build()
}
```

### JSON-RPC (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("Manual JSON-RPC 2.0")
        .llm_control("Method responses")
        .e2e_testing("JSON-RPC client libs")
        .notes("RPC over JSON")
        .build()
}
```

### XML-RPC (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("Manual XML-RPC parsing")
        .llm_control("Method responses")
        .e2e_testing("XML-RPC client libs")
        .notes("Legacy RPC format")
        .build()
}
```

### gRPC (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("tonic framework")
        .llm_control("RPC method responses")
        .e2e_testing("tonic client")
        .notes("HTTP/2 + Protocol Buffers")
        .build()
}
```

## Database Protocols (All Experimental)

### MySQL (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("opensrv-mysql v0.8 protocol library")
        .llm_control("Query responses (result sets, OK packets, errors)")
        .e2e_testing("mysql_async client crate")
        .notes("No authentication, errors sent as OK (library limitation)")
        .build()
}
```

### PostgreSQL (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("pgwire v0.26")
        .llm_control("Query responses (result sets, tags, errors)")
        .e2e_testing("tokio-postgres")
        .notes("Extended query protocol timeout issue")
        .build()
}
```

### Redis (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("redis-protocol v5.2 parsing + manual RESP2 encoding")
        .llm_control("RESP2 responses (strings, integers, arrays, errors)")
        .e2e_testing("redis-rs")
        .notes("RESP2 only, no persistence/pub-sub")
        .build()
}
```

### Cassandra (Incomplete)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Incomplete)
        .implementation("Simulated CQL responses")
        .llm_control("Simulated table operations")
        .e2e_testing("Not yet implemented")
        .notes("Requires binary protocol")
        .build()
}
```

### Elasticsearch (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("HTTP REST API simulation")
        .llm_control("Search/index responses")
        .e2e_testing("elasticsearch-rs")
        .notes("HTTP-based search")
        .build()
}
```

## Application Protocols (Experimental/Alpha)

### SMTP (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("Manual line-based parsing with tokio")
        .llm_control("All SMTP commands + responses")
        .e2e_testing("lettre SMTP client")
        .notes("No auth/TLS, basic MTA functionality")
        .build()
}
```

### IMAP (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("Manual IMAP4rev1 parsing")
        .llm_control("Authentication + mailbox ops + FETCH")
        .e2e_testing("async-imap client")
        .notes("Session state machine, no persistence")
        .build()
}
```

### IRC (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("Manual line-based IRC parsing")
        .llm_control("All IRC messages (NICK, JOIN, PRIVMSG)")
        .e2e_testing("Manual IRC client")
        .notes("No channel state tracking")
        .build()
}
```

### Telnet (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("Simplified line-based (no IAC negotiation)")
        .llm_control("Terminal responses")
        .e2e_testing("telnet CLI / raw TCP")
        .notes("Telnet-lite, no option negotiation")
        .build()
}
```

### mDNS (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("hickory-proto for multicast DNS")
        .llm_control("Service announcements + responses")
        .e2e_testing("mdns-sd or avahi")
        .notes("Multicast service discovery")
        .build()
}
```

### LDAP (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("ldap3_server or manual")
        .llm_control("Directory queries + authentication")
        .e2e_testing("ldap3 client")
        .notes("Lightweight directory")
        .build()
}
```

### MQTT (Experimental)

```rust
fn metadata_v2(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
    use crate::protocol::metadata::{ProtocolMetadataV2, ProtocolState};

    ProtocolMetadataV2::builder()
        .state(ProtocolState::Experimental)
        .implementation("rumqttd or manual")
        .llm_control("Pub/sub message routing")
        .e2e_testing("rumqttc")
        .notes("IoT messaging")
        .build()
}
```

## Summary

This collection provides templates for all major protocol categories. When creating `metadata_v2()` for a new protocol:

1. Choose the appropriate `ProtocolState` (default to `Experimental` for new protocols)
2. Describe the implementation honestly and specifically
3. Explain what the LLM controls in clear terms
4. Describe the E2E testing approach
5. Add notes for any important limitations or features
6. Set `privilege_requirement` if needed (root, raw sockets, etc.)
