//! Dual-protocol detection (`src/protocol/dual.rs`): the deterministic join
//! between the server and client canonical name tables.

use netget::protocol::dual::{
    alias_table_problems, all_dual_protocols, client_protocol_for_server,
    compiled_client_protocol_for_server,
};

/// The alias table must stay consistent with both registries: every alias side
/// must name a real protocol, and no alias may duplicate what normalization
/// already achieves.
#[test]
fn alias_table_is_consistent() {
    let problems = alias_table_problems();
    assert!(
        problems.is_empty(),
        "alias table problems:\n{}",
        problems.join("\n")
    );
}

/// Golden set: protocols that unambiguously exist on both sides must map.
#[test]
fn golden_duals_map() {
    for server in [
        "TCP",
        "UDP",
        "Telnet",
        "HTTP",
        "HTTP3",
        "DNS",
        "Redis",
        "IRC",
        "FTP",
        "SMTP",
        "IMAP",
        "POP3",
        "MQTT",
        "SSH",
        "WebSocket",
        "PostgreSQL",
        "MySQL",
        "LDAP",
        "NNTP",
        "SNMP",
        "Syslog",
        "TLS",
        "VNC",
        "XMPP",
        "WHOIS",
        "NTP",
        "DHCP",
        "BOOTP",
        "STUN",
        "DoQ",
        "NUT",
        "StatsD",
        "Graphite",
        "GELF",
        "FluentForward",
        "NSQ",
        "Gearman",
        "Prometheus",
        "PrometheusRemoteWrite",
        "InfluxDB",
        "Docker",
        "Loki",
        "OTLP",
        "IPFIX",
        "sFlow",
        "NetFlowV9",
        "gRPC-Web",
        "ConnectRPC",
        "gNMI",
        "TACACS",
        "Diameter",
        "NETCONF",
        "RPKI-RTR",
        "RDAP",
        "HL7",
        "ICAP",
        "OCPP",
        "A2A",
        "GraphQL",
        "FastCGI",
        "Redfish",
        "SCIM",
        "Socket.IO",
        "CalDAV",
        "CardDAV",
        "DICOM",
        "ACME",
        "FIX",
        "WAMP",
        "RTMP",
        "SRT",
        "AMQP1",
        "Thrift",
        "BMP",
        "MQTT-SN",
        "NBD",
        "ManageSieve",
        "Zenoh",
        "LwM2M",
        "RESTCONF",
        "WebTransport",
        "JMAP",
        "EPP",
        "LMTP",
        "LPD",
        "Echo",
        "Discard",
        "Daytime",
        "QOTD",
        "Chargen",
        "Time",
        "RCON",
        "A2S",
        "Minecraft",
        "9P",
        "ZeroMQ",
        "SMPP",
        "ClickHouse",
        "MessagePack-RPC",
        "Zipkin",
        "Cap'n Proto RPC",
        "KNX/IP",
        "LoRaWAN",
        "Consul",
        "Milter",
        "Anthropic",
        "RadSec",
        "D-Bus",
        "BFD",
        "VXLAN",
        "rsync",
        "PFCP",
        "NGAP",
        "M3UA",
        "Matrix",
        "libp2p",
        "SunRPC",
        "NIS",
        "Guacamole",
        "ActivityPub",
        "Stratum",
        "Stratum V2",
        "Apache Pulsar",
        "TR-069 (CWMP)",
        "SSE",
        "WS-Discovery",
        "ONVIF",
        "Kerberos",
        "SPICE",
        "devp2p",
        "H323",
        "OpenFlow",
        "PROFINET",
        "EtherCAT",
        "M-Bus",
        "AFP",
        "Nostr",
        "Vault",
        "Bolt",
        "OCI-Registry",
        "Beanstalkd",
        "DICT",
        "Gemini",
        "QUIC",
    ] {
        assert!(
            client_protocol_for_server(server).is_some(),
            "expected a client counterpart for server protocol {server:?}"
        );
    }
}

/// Divergent-name pairs resolve through the alias table.
#[test]
fn aliased_duals_map() {
    assert_eq!(client_protocol_for_server("DoH"), Some("DNS-over-HTTPS"));
    assert_eq!(client_protocol_for_server("Proxy"), Some("HTTP Proxy"));
    assert_eq!(client_protocol_for_server("Tor Relay"), Some("Tor"));
    assert_eq!(client_protocol_for_server("SamlIdp"), Some("SAML"));
    assert_eq!(client_protocol_for_server("SamlSp"), Some("SAML"));
    assert_eq!(client_protocol_for_server("OpenID"), Some("OpenIDConnect"));
    assert_eq!(
        client_protocol_for_server("Torrent-Tracker"),
        Some("BitTorrent Tracker")
    );
    assert_eq!(
        client_protocol_for_server("Torrent-DHT"),
        Some("BitTorrent DHT")
    );
    assert_eq!(
        client_protocol_for_server("Torrent-Peer"),
        Some("BitTorrent Peer Wire")
    );
}

/// Case/punctuation-only differences resolve through normalization, without
/// needing alias entries.
#[test]
fn normalized_duals_map() {
    assert_eq!(client_protocol_for_server("IGMP"), Some("igmp"));
    assert_eq!(client_protocol_for_server("ISIS"), Some("IS-IS"));
    assert_eq!(client_protocol_for_server("KAFKA"), Some("Kafka"));
    assert_eq!(client_protocol_for_server("WireGuard"), Some("wireguard"));
    assert_eq!(client_protocol_for_server("OSPF"), Some("ospf"));
    assert_eq!(
        client_protocol_for_server("SOCKET_FILE"),
        Some("SocketFile")
    );
    assert_eq!(client_protocol_for_server("SSH Agent"), Some("SSH Agent"));
    assert_eq!(
        client_protocol_for_server("BLUETOOTH_BLE"),
        Some("Bluetooth (BLE)")
    );
    // Server protocols that gained a client of the same name.
    assert_eq!(client_protocol_for_server("RADIUS"), Some("RADIUS"));
    assert_eq!(client_protocol_for_server("Modbus"), Some("Modbus"));
    assert_eq!(client_protocol_for_server("CoAP"), Some("CoAP"));
    assert_eq!(client_protocol_for_server("Memcached"), Some("Memcached"));
    assert_eq!(client_protocol_for_server("RTP"), Some("RTP"));
    assert_eq!(client_protocol_for_server("RTSP"), Some("RTSP"));
    assert_eq!(client_protocol_for_server("HLS"), Some("HLS"));
    assert_eq!(client_protocol_for_server("RDP"), Some("RDP"));
    assert_eq!(client_protocol_for_server("GTP"), Some("GTP"));
    assert_eq!(client_protocol_for_server("Db2"), Some("Db2"));
    assert_eq!(client_protocol_for_server("Snowflake"), Some("Snowflake"));
    assert_eq!(client_protocol_for_server("Spark"), Some("Spark"));
    assert_eq!(client_protocol_for_server("YARN"), Some("YARN"));
}

/// Server-only protocols must return None — a false positive here would make
/// the UI offer a client that does not exist.
#[test]
fn server_only_protocols_have_no_dual() {
    for server in [
        "Bitcoin P2P", // The Bitcoin client is Core RPC over HTTP.
        "TFTP",
        "SVN",
        "Mercurial",
        "Reverse Shell",
        "OpenVPN",
        // Profile servers deliberately not paired with the generic base clients:
        "USB-Keyboard",
        "BLUETOOTH_BLE_KEYBOARD",
    ] {
        assert_eq!(
            client_protocol_for_server(server),
            None,
            "server protocol {server:?} unexpectedly mapped to a client"
        );
    }
}

/// Determinism: repeated evaluation yields identical results (guards against
/// any future reintroduction of unordered-map matching).
#[test]
fn mapping_is_deterministic() {
    assert_eq!(all_dual_protocols(), all_dual_protocols());
}

/// `compiled_` only reports clients present in this build's registry, and
/// whatever it reports must agree with the codebase-wide mapping.
#[test]
fn compiled_mapping_is_subset_of_codebase_mapping() {
    for (server, client) in all_dual_protocols() {
        if let Some(compiled) = compiled_client_protocol_for_server(server) {
            assert_eq!(
                compiled, client,
                "compiled mapping disagrees for {server:?}"
            );
        }
    }
    // TCP is in every default/test build; the demo pair must be live.
    assert_eq!(
        compiled_client_protocol_for_server("TCP").as_deref(),
        Some("TCP")
    );
}

/// "Not compiled into this build" guidance names what the build needs. When that is a Cargo
/// feature (the system-library features), the feature must exist; a plausible slug can
/// otherwise tell the user to rebuild with a flag the manifest rejects.
#[test]
fn compiled_out_dual_protocol_guidance_names_real_cargo_features() {
    use netget::protocol::{
        client_registry::{ClientProtocolLookupError, CLIENT_REGISTRY},
        server_registry::{registry as server_registry, ProtocolLookupError},
    };
    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string("Cargo.toml").unwrap()).unwrap();
    let features = manifest["features"].as_table().unwrap();
    let check = |who: &str, requires: &str| {
        if let Some(rest) = requires.strip_prefix("the `") {
            let feature = rest.split('`').next().unwrap();
            assert!(
                features.contains_key(feature),
                "{who} advises nonexistent Cargo feature {feature:?}"
            );
        }
    };
    for (server, client) in all_dual_protocols() {
        match server_registry().resolve(server) {
            Ok(_) => {}
            Err(ProtocolLookupError::NotCompiled { requires, .. }) => {
                check(&format!("server {server:?}"), requires)
            }
            Err(error) => panic!("known dual server {server:?} is unresolved: {error}"),
        }
        match CLIENT_REGISTRY.resolve(client) {
            Ok(_) => {}
            Err(ClientProtocolLookupError::NotCompiled { requires, .. }) => {
                check(&format!("client {client:?}"), requires)
            }
            Err(error) => panic!("known dual client {client:?} is unresolved: {error}"),
        }
    }
}

/// A running instance keeps the operator's registry keyword, not necessarily its canonical
/// name. Bitcoin's keyword is also the RPC client's name, so resolve the server first.
#[test]
fn bitcoin_server_keyword_never_offers_the_rpc_client() {
    assert_eq!(compiled_client_protocol_for_server("bitcoin"), None);
    assert_eq!(compiled_client_protocol_for_server("Bitcoin P2P"), None);
}
