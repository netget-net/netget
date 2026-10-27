//! Every server either declares the port it is registered for, or says why it has none.
//!
//! `ProtocolMetadataV2::well_known_port` is what a server starts on when the caller names no
//! port (the picker, the create form, MCP `start_server`, `open_server`, `--server`), resolved
//! through `netget::protocol::default_port`. Before it existed every socket server started on an
//! OS-assigned port unless the caller knew the number, and the only place a well-known port was
//! written down at all was `PrivilegeRequirement::PrivilegedPort(n)` — for the 30-odd protocols
//! below 1024, as a privilege advisory, and read by nothing that picks a port.
//!
//! Four checks, all by reading source so they hold at every feature set (the blocking CI job
//! compiles 6 of ~160 servers, so a registry walk would see almost nothing):
//!
//! 1. every server declares `.well_known_port(n)` / `.well_known_udp_port(n)` /
//!    `.well_known_sctp_port(n)` — or the struct-literal `well_known_port: Some(n)` — or is in
//!    [`NO_WELL_KNOWN_PORT`] with the reason;
//! 2. every `PrivilegedPort(n)` agrees with the declared well-known port, so the privilege
//!    advisory and the default port cannot name two different numbers;
//! 3. the declared transport agrees with the protocol's own `stack_name()` where that names
//!    TCP, UDP or SCTP — a UDP port probed with a TCP bind says nothing about whether it is free;
//! 4. every entry in the list names a protocol that exists and gives a real reason.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp \
//!       --test well_known_port_declaration_test

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Servers with no port of their own, each with the reason.
///
/// These are finished answers, not a work queue: a protocol here starts on an OS-assigned port
/// when the caller names none, which is the right default for it. What must not happen is a
/// protocol landing here because nobody looked up its number — a new server that has a
/// registered port declares it.
const NO_WELL_KNOWN_PORT: &[(&str, &str)] = &[
    // ---- Generic transports: the operator's protocol, so the operator's port ----
    (
        "tcp",
        "raw TCP carries whatever the operator says it does; there is no protocol to register",
    ),
    (
        "udp",
        "raw UDP carries whatever the operator says it does; there is no protocol to register",
    ),
    (
        "msgpack_rpc",
        "MessagePack-RPC registers no port: each application picks its own (Neovim listens wherever --listen says)",
    ),
    (
        "capnp_rpc",
        "Cap'n Proto RPC registers no port: each application's schema and deployment choose one",
    ),
    (
        "dbus",
        "D-Bus registers no port: buses listen on Unix sockets, and a TCP address names whatever port its bus config chose",
    ),
    (
        "zeromq",
        "ZeroMQ registers no port: every endpoint is chosen by its application (the guide's examples use 5555)",
    ),
    (
        "tls",
        "generic TLS termination; 443 belongs to HTTPS, which this server does not speak",
    ),
    (
        "reverse_shell",
        "a listener for shells that call back; any port the operator hands the target is right",
    ),
    (
        "spice",
        "SPICE registers no port with IANA and neither spice-server nor QEMU has a default: every \
         -spice port=… is the operator's, and libvirt hands them out from VNC's 5900 range",
    ),
    (
        "nis",
        "ypserv has no assigned port: it binds an ephemeral one and registers it with the \
         portmapper as ONC RPC program 100004, and clients (ypbind, ypcat -h, rpcinfo) ask port \
         111 where it is",
    ),
    // ---- Below the transport layer: no port exists ----
    ("arp", "link layer (EtherType 0x0806); ports do not exist here"),
    ("cdp", "link layer (802.3 LLC/SNAP); ports do not exist here"),
    ("datalink", "raw Ethernet frames; ports do not exist here"),
    ("eapol", "link layer (EtherType 0x888E); ports do not exist here"),
    ("icmp", "IP protocol 1; ICMP has no ports"),
    ("igmp", "IP protocol 2; IGMP has no ports"),
    ("isis", "link layer (OSI CLNS over 802.3); ports do not exist here"),
    ("lldp", "link layer (EtherType 0x88CC); ports do not exist here"),
    ("ndp", "ICMPv6 message types; NDP has no ports"),
    ("ospf", "IP protocol 89; OSPF has no ports"),
    ("gre", "IP protocol 47; GRE has no ports"),
    ("rawip", "raw IP with an operator-chosen protocol number; no ports"),
    ("stp", "link layer (802.1D BPDUs over LLC); ports do not exist here"),
    ("vrrp", "IP protocol 112; VRRP has no ports"),
    ("tuntap", "a virtual network interface; it carries whole packets, not one port"),
    (
        "can",
        "CAN bus frames addressed by arbitration id; no IP, no ports",
    ),
    // ---- Local IPC and devices ----
    ("named_pipe", "a filesystem FIFO path, not a socket port"),
    ("pty", "a pseudo-terminal device path, not a socket port"),
    ("socket_file", "a Unix domain socket path, not a port"),
    ("ssh_agent", "a Unix domain socket path (SSH_AUTH_SOCK), not a port"),
    ("stdio", "the process's own stdin and stdout; nothing to bind"),
    (
        "fuse",
        "a local filesystem mount at a mount_point: the kernel's FUSE driver over /dev/fuse on \
         Linux, FUSE-T's own loopback NFS server (which picks its port) on macOS; NetGet binds \
         no socket and has no port",
    ),
    ("nfc", "a PC/SC reader device; no network port"),
    ("bluetooth_ble", "a Bluetooth LE radio; GATT has no IP port"),
    ("bluetooth_ble_battery", "a Bluetooth LE GATT profile; no IP port"),
    (
        "bluetooth_ble_beacon",
        "Bluetooth LE advertising payload only; no IP port",
    ),
    ("bluetooth_ble_cycling", "a Bluetooth LE GATT profile; no IP port"),
    ("bluetooth_ble_data_stream", "a Bluetooth LE GATT profile; no IP port"),
    ("bluetooth_ble_environmental", "a Bluetooth LE GATT profile; no IP port"),
    ("bluetooth_ble_file_transfer", "a Bluetooth LE GATT profile; no IP port"),
    ("bluetooth_ble_gamepad", "a Bluetooth LE GATT profile; no IP port"),
    ("bluetooth_ble_heart_rate", "a Bluetooth LE GATT profile; no IP port"),
    ("bluetooth_ble_keyboard", "a Bluetooth LE GATT profile; no IP port"),
    ("bluetooth_ble_mouse", "a Bluetooth LE GATT profile; no IP port"),
    ("bluetooth_ble_presenter", "a Bluetooth LE GATT profile; no IP port"),
    ("bluetooth_ble_proximity", "a Bluetooth LE GATT profile; no IP port"),
    ("bluetooth_ble_remote", "a Bluetooth LE GATT profile; no IP port"),
    ("bluetooth_ble_running", "a Bluetooth LE GATT profile; no IP port"),
    ("bluetooth_ble_thermometer", "a Bluetooth LE GATT profile; no IP port"),
    ("bluetooth_ble_weight_scale", "a Bluetooth LE GATT profile; no IP port"),
    (
        "usb_fido2",
        "a virtual USB device exported over USB/IP; 3240 is a usbipd convention IANA assigns to \
         something else",
    ),
    (
        "usb_keyboard",
        "a virtual USB device exported over USB/IP; 3240 is a usbipd convention IANA assigns to \
         something else",
    ),
    (
        "usb_mouse",
        "a virtual USB device exported over USB/IP; 3240 is a usbipd convention IANA assigns to \
         something else",
    ),
    (
        "usb_msc",
        "a virtual USB device exported over USB/IP; 3240 is a usbipd convention IANA assigns to \
         something else",
    ),
    (
        "usb_serial",
        "a virtual USB device exported over USB/IP; 3240 is a usbipd convention IANA assigns to \
         something else",
    ),
    (
        "usb_smartcard",
        "a virtual USB device exported over USB/IP; 3240 is a usbipd convention IANA assigns to \
         something else",
    ),
    // ---- Application protocols carried on plain HTTP, with no port of their own ----
    //
    // Their port is HTTP's. Declaring 80 for each would put every one of these mocks on the
    // same port by default, and the services they imitate (AWS, OpenAI, Snowflake, the
    // package registries) are reached over HTTPS 443, which these plain-HTTP servers do not
    // speak — so neither number is honestly theirs. Where the reference implementation does
    // document a port of its own (Elasticsearch 9200, `hg serve` 8000, DynamoDB Local 8000,
    // the OCI distribution registry 5000), the protocol declares it instead of being here.
    ("git", "Git smart HTTP rides on HTTP; git:// (9418) is a different protocol this server does not speak"),
    ("grpc", "gRPC rides on HTTP/2 and has no registered port of its own"),
    ("grpc_web", "binary gRPC-Web rides on the configured HTTP origin and has no registered port of its own"),
    ("connect_rpc", "ConnectRPC rides on the configured HTTP origin and has no registered port of its own"),
    ("rdap", "RDAP is an HTTP(S) service under a base URL (RFC 7480) and has no port of its own"),
    ("ocpp", "OCPP-J runs on the WebSocket URL a CSMS publishes to its charge points; no port is assigned"),
    ("a2a", "an A2A agent is an HTTP(S) service its agent card points at; no port is assigned"),
    ("graphql", "GraphQL is served over HTTP(S) at an application-chosen path and port; none is assigned"),
    ("caldav", "CalDAV is WebDAV over HTTP(S) on the web server's port, found through /.well-known/caldav or DNS SRV (RFC 6764); no port is assigned"),
    ("carddav", "CardDAV is WebDAV over HTTP(S) on the web server's port, found through /.well-known/carddav or DNS SRV (RFC 6764); no port is assigned"),
    ("srt", "SRT has no assigned port; each deployment picks one (srt-live-transmit and OBS examples use 9000, MediaMTX 8890)"),
    ("wamp", "WAMP runs over WebSocket on the web server's port; no port is assigned (Crossbar.io's 8080 is a convention)"),
    ("sse", "server-sent events are an HTTP response type (text/event-stream) served at whatever origin publishes them; WHATWG assigns no port"),
    ("activitypub", "ActivityPub is served over HTTP(S) at the instance's own origin (its ids are URLs); W3C assigns no port, and real instances sit behind 443"),
    ("restconf", "RESTCONF is carried on HTTP(S) at whatever port the web server uses; RFC 8040 assigns none (443 for HTTPS by convention)"),
    ("jmap", "JMAP is served on an HTTPS server's port and found through /.well-known/jmap; RFC 8620 assigns no port of its own"),
    ("webtransport", "WebTransport sessions are extended CONNECT requests on an HTTP/3 server's port; the draft assigns none (443/UDP by convention)"),
    ("bmp", "BMP has no assigned port (RFC 7854 leaves it to configuration); collectors use 5000 or 11019 by convention"),
    ("mbus", "M-Bus/IP is wired M-Bus (EN 13757-2) carried transparently through a serial device server; neither EN 13757 nor IANA assigns a port and libmbus names none, so each gateway uses its serial server's own default (10001, 4001, 9999)"),
    ("thrift", "Thrift has no assigned port: every service picks its own, and Apache's tutorial uses 9090 (IANA's websm) by convention only"),
    ("fix", "FIX has no assigned port: each venue publishes its own, and the QuickFIX examples use 9876 and 9878 by convention only"),
    ("acme", "ACME is JSON over HTTPS at a directory URL the CA publishes (RFC 8555 §7.1.1); no port is assigned, and test CAs such as Pebble use arbitrary ones"),
    ("socketio", "Socket.IO is served over HTTP(S) at a path (/socket.io/) on an application-chosen port; none is assigned"),
    ("scim", "SCIM is a REST API served over HTTPS at an application-chosen path and port; none is assigned"),
    ("onvif", "ONVIF services are carried on the device's HTTP port (80 by convention, shared with its web UI); the ONVIF Core Specification assigns none, and devices advertise theirs in WS-Discovery XAddrs"),
    ("redfish", "Redfish is served over HTTPS on the BMC's web port (443 by convention, often shared with its web UI); no port is assigned to Redfish itself"),
    ("fastcgi", "FastCGI has no assigned port; an application listens wherever its web server is told to pass requests (php-fpm's 9000 is a convention, not an assignment)"),
    ("hls", "HLS is playlists and segments served over plain HTTP; no port of its own"),
    ("jsonrpc", "JSON-RPC over HTTP has no registered port; each service picks its own"),
    ("maven", "a Maven repository is a layout over plain HTTP; no port of its own"),
    ("mcp", "MCP over streamable HTTP has no registered port"),
    ("npm", "the npm registry protocol rides on HTTP(S); no port of its own"),
    ("oauth2", "OAuth 2.0 endpoints live on the authorization server's HTTPS origin; no port of their own"),
    ("openai", "the OpenAI API is served over HTTPS 443, which this plain-HTTP mock does not speak"),
    ("openapi", "an OpenAPI document describes some HTTP service; the service picks the port"),
    ("openid", "OpenID Connect endpoints live on the provider's HTTPS origin; no port of their own"),
    ("pypi", "the PyPI simple API rides on HTTP(S); no port of its own"),
    ("rss", "an RSS feed is a document served over plain HTTP; no port of its own"),
    ("s3", "the S3 API is served over HTTPS 443, which this plain-HTTP mock does not speak"),
    ("saml_idp", "SAML bindings ride on the IdP's HTTPS origin; no port of their own"),
    ("saml_sp", "SAML bindings ride on the SP's HTTPS origin; no port of their own"),
    ("snowflake", "the Snowflake API is served over HTTPS 443, which this plain-HTTP mock does not speak"),
    ("sqs", "the SQS API is served over HTTPS 443, which this plain-HTTP mock does not speak"),
    ("webdav", "WebDAV is an HTTP extension (RFC 4918) and uses HTTP's port"),
    ("websocket", "RFC 6455 upgrades an HTTP connection and uses HTTP's port; there is no WebSocket port"),
    (
        "nostr",
        "relays are ws(s):// URLs on HTTP's ports; no specification assigns one, and the relays \
         disagree (strfry.conf port = 7777, nostr-rs-relay config.toml port = 8080)",
    ),
    ("webrtc_signaling", "the signalling channel is an ad-hoc JSON relay over WebSocket; no port of its own"),
    ("xmlrpc", "XML-RPC is a POST body over plain HTTP; no port of its own"),
    (
        "webrtc",
        "WebRTC media and data ride ICE-negotiated ephemeral UDP ports; there is no fixed one",
    ),
    (
        "anthropic",
        "the Anthropic API is served over HTTPS 443, which this plain-HTTP server does not speak; \
         compatible servers pick their own (llama.cpp 8080, LiteLLM 4000)",
    ),
    (
        "milter",
        "no registry or specification assigns a milter port; each filter's socket is local MTA \
         configuration and the filters disagree (OpenDKIM 8891, OpenDMARC 8893, rspamd 11332)",
    ),
];

fn server_action_files() -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(Path::new("src/server")) else {
        return out;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        // Nested families (`usb/*`) keep their `actions.rs` one level deeper, and there the
        // children are the protocols and the parent is not.
        let mut nested = Vec::new();
        if let Ok(children) = std::fs::read_dir(&dir) {
            for child in children.flatten() {
                let sub = child.path();
                if sub.is_dir() && sub.join("actions.rs").is_file() {
                    nested.push((
                        format!("{}_{}", name, child.file_name().to_string_lossy()),
                        sub.join("actions.rs"),
                    ));
                }
            }
        }
        if !nested.is_empty() {
            out.extend(nested);
            continue;
        }
        let actions = dir.join("actions.rs");
        // `http_common/actions.rs` is a response helper with no `metadata()`: nothing to declare.
        if actions.is_file()
            && strip_comments(&std::fs::read_to_string(&actions).unwrap_or_default())
                .contains("fn metadata(")
        {
            out.push((name, actions));
        }
    }
    out.sort();
    out
}

/// Strip `//` comments, leaving `//` inside a string literal alone.
///
/// Several protocols explain in a comment why they do **not** declare `PrivilegedPort(n)` —
/// `nats` names 4222, `ssdp` names svn's 3690 — and a scan that read those would report a
/// disagreement the code does not have.
fn strip_comments(src: &str) -> String {
    src.lines()
        .map(|line| {
            let bytes = line.as_bytes();
            let mut in_string = false;
            let mut i = 0usize;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' if in_string => i += 1,
                    b'"' => in_string = !in_string,
                    b'/' if !in_string && bytes.get(i + 1) == Some(&b'/') => {
                        return line[..i].to_string()
                    }
                    _ => {}
                }
                i += 1;
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Tcp,
    Udp,
    Sctp,
}

/// The well-known port a protocol's source declares, in either form metadata can be written.
///
/// The builder form is `.well_known_port(n)` and its UDP/SCTP siblings; the struct-literal form
/// (`src/client/ospf/actions.rs` builds its metadata that way) is `well_known_port: Some(n)`
/// beside `well_known_transport: PortTransport::X`. A scan that knew only the builder would
/// read a literal declaration as "declares nothing" — which fails safe here, but is still a
/// false report.
fn declared_port(src: &str) -> Option<(u16, Transport)> {
    let src = strip_comments(src);
    let builder =
        regex::Regex::new(r"\.well_known_(udp_|sctp_)?port\(\s*(\d+)\s*\)").expect("regex");
    if let Some(c) = builder.captures(&src) {
        let transport = match c.get(1).map(|m| m.as_str()) {
            Some("udp_") => Transport::Udp,
            Some("sctp_") => Transport::Sctp,
            _ => Transport::Tcp,
        };
        return Some((c[2].parse().expect("port fits u16"), transport));
    }
    let literal = regex::Regex::new(r"well_known_port:\s*Some\(\s*(\d+)\s*\)").expect("regex");
    if let Some(c) = literal.captures(&src) {
        let transport_re =
            regex::Regex::new(r"well_known_transport:\s*(?:[\w:]*::)?PortTransport::(\w+)")
                .expect("regex");
        let transport = match transport_re
            .captures(&src)
            .map(|t| t[1].to_string())
            .as_deref()
        {
            Some("Udp") => Transport::Udp,
            Some("Sctp") => Transport::Sctp,
            _ => Transport::Tcp,
        };
        return Some((c[1].parse().expect("port fits u16"), transport));
    }
    None
}

fn privileged_port(src: &str) -> Option<u16> {
    let re = regex::Regex::new(r"PrivilegedPort\(\s*(\d+)\s*\)").expect("regex");
    re.captures(&strip_comments(src))
        .map(|c| c[1].parse().expect("port fits u16"))
}

/// The transport the protocol's own `stack_name()` names, when it is a literal that names one.
fn stack_transport(src: &str) -> Option<Transport> {
    let re = regex::Regex::new(r#"fn stack_name\(&self\)[^{]*\{\s*"([^"]*)""#).expect("regex");
    let stack = re.captures(src)?[1].to_string();
    let layers: Vec<&str> = stack.split('>').map(str::trim).collect();
    if layers.contains(&"UDP") {
        Some(Transport::Udp)
    } else if layers.contains(&"TCP") {
        Some(Transport::Tcp)
    } else if layers.contains(&"SCTP") {
        Some(Transport::Sctp)
    } else {
        None
    }
}

#[test]
fn every_server_declares_a_well_known_port_or_says_why_it_has_none() {
    let exempt: BTreeSet<&str> = NO_WELL_KNOWN_PORT.iter().map(|(p, _)| *p).collect();
    let mut undeclared = Vec::new();
    let mut both = Vec::new();
    let mut zero = Vec::new();

    for (protocol, path) in server_action_files() {
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        match (declared_port(&src), exempt.contains(protocol.as_str())) {
            (None, false) => undeclared.push(protocol),
            (Some(_), true) => both.push(protocol),
            (Some((0, _)), false) => zero.push(protocol),
            _ => {}
        }
    }

    assert!(
        undeclared.is_empty(),
        "these servers declare no well-known port and are not in NO_WELL_KNOWN_PORT:\n  {}\n\n\
         Declare the port IANA (or the protocol's own specification) registers for it, in \
         metadata():\n    .well_known_port(6379)        // TCP\n    \
         .well_known_udp_port(53)      // UDP\n\n\
         If it genuinely has none — link layer, a device, a pipe, an application protocol \
         carried on plain HTTP — add it to NO_WELL_KNOWN_PORT with the reason.",
        undeclared.join("\n  ")
    );
    assert!(
        both.is_empty(),
        "these servers declare a well-known port but are still listed as having none — \
         remove them from NO_WELL_KNOWN_PORT:\n  {}",
        both.join("\n  ")
    );
    assert!(
        zero.is_empty(),
        "these servers declare well-known port 0, which is 'no port' spelled as a number; \
         list them in NO_WELL_KNOWN_PORT instead:\n  {}",
        zero.join("\n  ")
    );
}

#[test]
fn every_privileged_port_agrees_with_the_well_known_port() {
    let mut disagree = Vec::new();
    for (protocol, path) in server_action_files() {
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        let Some(privileged) = privileged_port(&src) else {
            continue;
        };
        match declared_port(&src) {
            Some((port, _)) if port == privileged => {}
            Some((port, _)) => disagree.push(format!(
                "{protocol}: PrivilegedPort({privileged}) but well-known port {port}"
            )),
            None => disagree.push(format!(
                "{protocol}: PrivilegedPort({privileged}) but no well-known port declared"
            )),
        }
        if privileged >= 1024 {
            disagree.push(format!(
                "{protocol}: PrivilegedPort({privileged}) is not below 1024, so it can never fire \
                 — declare PrivilegeRequirement::None"
            ));
        }
    }
    assert!(
        disagree.is_empty(),
        "the privilege advisory and the default port must name the same number:\n  {}",
        disagree.join("\n  ")
    );
}

#[test]
fn every_well_known_port_transport_agrees_with_the_stack() {
    let mut disagree = Vec::new();
    for (protocol, path) in server_action_files() {
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        let (Some((port, declared)), Some(stack)) = (declared_port(&src), stack_transport(&src))
        else {
            continue;
        };
        if declared != stack {
            disagree.push(format!(
                "{protocol}: declares {declared:?} port {port} but stack_name() says {stack:?}"
            ));
        }
    }
    assert!(
        disagree.is_empty(),
        "a well-known port's transport decides which socket probes whether it is free; it must \
         match the protocol's own stack:\n  {}",
        disagree.join("\n  ")
    );
}

#[test]
fn every_no_port_entry_names_a_real_protocol_and_gives_a_reason() {
    let known: BTreeMap<String, PathBuf> = server_action_files().into_iter().collect();
    let mut stale = Vec::new();
    let mut unreasoned = Vec::new();
    let mut duplicated = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for (protocol, reason) in NO_WELL_KNOWN_PORT {
        if !known.contains_key(*protocol) {
            stale.push(*protocol);
        }
        if reason.len() < 20 {
            unreasoned.push(*protocol);
        }
        if !seen.insert(*protocol) {
            duplicated.insert(*protocol);
        }
    }
    assert!(
        stale.is_empty(),
        "NO_WELL_KNOWN_PORT entries naming no protocol under src/server/: {stale:?}"
    );
    assert!(
        unreasoned.is_empty(),
        "NO_WELL_KNOWN_PORT entries whose reason says nothing: {unreasoned:?}"
    );
    assert!(
        duplicated.is_empty(),
        "NO_WELL_KNOWN_PORT entries listed twice: {duplicated:?}"
    );
}

/// The walker must see the protocols it exists to check, in both layouts. A walk that silently
/// found nothing would pass every assertion above.
#[test]
fn the_walker_sees_flat_and_nested_protocols() {
    let names: BTreeSet<String> = server_action_files().into_iter().map(|(p, _)| p).collect();
    for expected in ["redis", "dns", "http", "usb_mouse", "tcp"] {
        assert!(
            names.contains(expected),
            "the walker did not find {expected}; it found {} protocols",
            names.len()
        );
    }
    assert!(
        names.len() > 100,
        "only {} server protocols found",
        names.len()
    );
}
