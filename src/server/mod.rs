//! Server module
//!
//! Handles network servers, connection management, and protocol implementations

pub mod accept_bounded;
pub mod connection;
pub mod peer_support;
// server_trait requires async-trait, so only compile when features that provide it are enabled
#[cfg(any(
    feature = "tcp",
    feature = "ssh",
    feature = "mysql",
    feature = "postgresql",
    feature = "redis",
    feature = "cassandra",
    feature = "grpc",
    feature = "mcp",
    feature = "vnc"
))]
pub mod server_trait;
pub mod socket_helpers;

// Shared HTTP request/response infrastructure: request extraction, the request
// filter, and `build_safe_response` — the only non-panicking way to turn
// model-supplied status/headers/body into a hyper `Response`.
//
// Keep this list in sync with the protocols that serve HTTP themselves. It is
// not just `http`/`http2`: the auth family (`oauth2`, `openid`, `saml-idp`,
// `saml-sp`) speaks HTTP over hyper without enabling the `http` feature, so it
// could not reach `build_safe_response` and each carried its own local copy of
// it. Protocols that reach it by enabling `http` transitively (`openapi`,
// `mercurial`, `pypi`) need no entry here.
#[cfg(any(
    feature = "http",
    feature = "http2",
    feature = "oauth2",
    feature = "openid",
    feature = "saml-idp",
    feature = "saml-sp"
))]
pub mod http_common;

// TLS certificate management for DoT, DoH, HTTP, HTTP/2, QUIC, SMTP, POP3 and TLS protocols.
// Keep this list in sync with the protocols that actually call into it: POP3's TLS session
// path is fully implemented and its spawn already takes the config, but it was missing here,
// so POP3S could not be built at all.
#[cfg(any(
    feature = "dot",
    feature = "doq",
    feature = "doh",
    feature = "http",
    feature = "http2",
    feature = "quic",
    feature = "http3",
    feature = "smtp",
    feature = "pop3",
    feature = "tls",
    feature = "kubernetes-server",
    feature = "gemini",
    feature = "acme",
    feature = "jmap",
    feature = "epp"
))]
pub mod tls_cert_manager;

#[cfg(feature = "tcp")]
pub mod tcp;
#[cfg(feature = "tcp")]
pub use tcp::actions::TcpProtocol;
#[cfg(feature = "tcp")]
pub use tcp::TcpServer;

#[cfg(all(feature = "socket_file", unix))]
pub mod socket_file;
#[cfg(all(feature = "socket_file", unix))]
pub use socket_file::actions::SocketFileProtocol;
#[cfg(all(feature = "socket_file", unix))]
pub use socket_file::SocketFileServer;

#[cfg(all(feature = "named_pipe", unix))]
pub mod named_pipe;
#[cfg(all(feature = "named_pipe", unix))]
pub use named_pipe::actions::NamedPipeProtocol;
#[cfg(all(feature = "named_pipe", unix))]
pub use named_pipe::NamedPipeServer;

#[cfg(all(feature = "pty", unix))]
pub mod pty;
#[cfg(all(feature = "pty", unix))]
pub use pty::actions::PtyProtocol;
#[cfg(all(feature = "pty", unix))]
pub use pty::PtyServer;

#[cfg(all(feature = "stdio", unix))]
pub mod stdio;
#[cfg(all(feature = "stdio", unix))]
pub use stdio::actions::StdioProtocol;
#[cfg(all(feature = "stdio", unix))]
pub use stdio::StdioServer;

#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "http")]
pub use http::actions::HttpProtocol;
#[cfg(feature = "http")]
pub use http::HttpServer;

#[cfg(feature = "http2")]
pub mod http2;
#[cfg(feature = "http2")]
pub use http2::actions::Http2Protocol;
#[cfg(feature = "http2")]
pub use http2::H2Server;

#[cfg(feature = "pypi")]
pub mod pypi;
#[cfg(feature = "pypi")]
pub use pypi::actions::PypiProtocol;
#[cfg(feature = "pypi")]
pub use pypi::PypiServer;

#[cfg(feature = "maven")]
pub mod maven;
#[cfg(feature = "maven")]
pub use maven::actions::MavenProtocol;
#[cfg(feature = "maven")]
pub use maven::MavenServer;

#[cfg(feature = "datalink")]
pub mod datalink;
#[cfg(feature = "datalink")]
pub use datalink::actions::DataLinkProtocol;
#[cfg(feature = "datalink")]
pub use datalink::DataLinkServer;

#[cfg(feature = "arp")]
pub mod arp;
#[cfg(feature = "arp")]
pub use arp::actions::ArpProtocol;
#[cfg(feature = "arp")]
pub use arp::ArpServer;

#[cfg(feature = "icmp")]
pub mod icmp;
#[cfg(feature = "icmp")]
pub use icmp::actions::IcmpProtocol;
#[cfg(feature = "icmp")]
pub use icmp::IcmpServer;

#[cfg(feature = "dc")]
pub mod dc;
#[cfg(feature = "dc")]
pub use dc::actions::DcProtocol;
#[cfg(feature = "dc")]
pub use dc::DcServer;

#[cfg(feature = "udp")]
pub mod udp;
#[cfg(feature = "udp")]
pub use udp::actions::UdpProtocol;
#[cfg(feature = "udp")]
pub use udp::{SharedUdpSocket, UdpPeerMap, UdpServer};

#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "dns")]
pub use dns::actions::DnsProtocol;
#[cfg(feature = "dns")]
pub use dns::DnsServer;

#[cfg(feature = "dot")]
pub mod dot;
#[cfg(feature = "dot")]
pub use dot::actions::DotProtocol;
#[cfg(feature = "dot")]
pub use dot::DotServer;

#[cfg(feature = "doh")]
pub mod doh;
#[cfg(feature = "doh")]
pub use doh::actions::DohProtocol;
#[cfg(feature = "doh")]
pub use doh::DohServer;

#[cfg(feature = "dhcp")]
pub mod dhcp;
#[cfg(feature = "dhcp")]
pub use dhcp::actions::DhcpProtocol;
#[cfg(feature = "dhcp")]
pub use dhcp::DhcpServer;

#[cfg(feature = "bootp")]
pub mod bootp;
#[cfg(feature = "bootp")]
pub use bootp::actions::BootpProtocol;
#[cfg(feature = "bootp")]
pub use bootp::BootpServer;

#[cfg(feature = "ntp")]
pub mod ntp;
#[cfg(feature = "ntp")]
pub use ntp::actions::NtpProtocol;
#[cfg(feature = "ntp")]
pub use ntp::NtpServer;

#[cfg(feature = "tftp")]
pub mod tftp;
#[cfg(feature = "tftp")]
pub use tftp::actions::TftpProtocol;
#[cfg(feature = "tftp")]
pub use tftp::TftpServer;

#[cfg(feature = "whois")]
pub mod whois;
#[cfg(feature = "whois")]
pub use whois::actions::WhoisProtocol;
#[cfg(feature = "whois")]
pub use whois::WhoisServer;
#[cfg(feature = "ndp")]
pub mod ndp;
#[cfg(feature = "ndp")]
pub use ndp::actions::NdpProtocol;
#[cfg(feature = "ndp")]
pub use ndp::NdpServer;
#[cfg(feature = "dhcpv6")]
pub mod dhcpv6;
#[cfg(feature = "dhcpv6")]
pub use dhcpv6::actions::Dhcpv6Protocol;
#[cfg(feature = "dhcpv6")]
pub use dhcpv6::Dhcpv6Server;
#[cfg(feature = "tuntap")]
pub mod tuntap;
#[cfg(feature = "tuntap")]
pub use tuntap::actions::TunTapProtocol;
#[cfg(feature = "tuntap")]
pub use tuntap::TunTapServer;
#[cfg(feature = "rawip")]
pub mod rawip;
#[cfg(feature = "rawip")]
pub use rawip::actions::RawIpProtocol;
#[cfg(feature = "rawip")]
pub use rawip::RawIpServer;
#[cfg(feature = "gtp")]
pub mod gtp;
#[cfg(feature = "gtp")]
pub use gtp::actions::GtpProtocol;
#[cfg(feature = "gtp")]
pub use gtp::GtpServer;
#[cfg(feature = "m3ua")]
pub mod m3ua;
#[cfg(feature = "m3ua")]
pub use m3ua::actions::M3uaProtocol;
#[cfg(feature = "m3ua")]
pub use m3ua::M3uaServer;
#[cfg(feature = "can")]
pub mod can;
#[cfg(feature = "ngap")]
pub mod ngap;
#[cfg(feature = "can")]
pub use can::actions::CanProtocol;
#[cfg(feature = "can")]
pub use can::CanServer;
#[cfg(feature = "lldp")]
pub mod lldp;
#[cfg(feature = "lldp")]
pub use lldp::actions::LldpProtocol;
#[cfg(feature = "lldp")]
pub use lldp::LldpServer;
#[cfg(feature = "cdp")]
pub mod cdp;
#[cfg(feature = "cdp")]
pub use cdp::actions::CdpProtocol;
#[cfg(feature = "cdp")]
pub use cdp::CdpServer;
#[cfg(feature = "stp")]
pub mod stp;
#[cfg(feature = "stp")]
pub use stp::actions::StpProtocol;
#[cfg(feature = "stp")]
pub use stp::StpServer;
#[cfg(feature = "vrrp")]
pub mod vrrp;
#[cfg(feature = "vrrp")]
pub use vrrp::actions::VrrpProtocol;
#[cfg(feature = "vrrp")]
pub use vrrp::VrrpServer;
#[cfg(feature = "hsrp")]
pub mod hsrp;
#[cfg(feature = "hsrp")]
pub use hsrp::actions::HsrpProtocol;
#[cfg(feature = "hsrp")]
pub use hsrp::HsrpServer;
#[cfg(feature = "eapol")]
pub mod eapol;
#[cfg(feature = "eapol")]
pub use eapol::actions::EapolProtocol;
#[cfg(feature = "eapol")]
pub use eapol::EapolServer;
#[cfg(feature = "wol")]
pub mod wol;
#[cfg(feature = "wol")]
pub use wol::actions::WolProtocol;
#[cfg(feature = "wol")]
pub use wol::WolServer;
#[cfg(feature = "nats")]
pub mod nats;
#[cfg(feature = "nats")]
pub use nats::actions::NatsProtocol;
#[cfg(feature = "nats")]
pub use nats::NatsServer;
#[cfg(feature = "stomp")]
pub mod stomp;
#[cfg(feature = "stomp")]
pub use stomp::actions::StompProtocol;
#[cfg(feature = "stomp")]
pub use stomp::StompServer;
#[cfg(feature = "ident")]
pub mod ident;
#[cfg(feature = "ident")]
pub use ident::actions::IdentProtocol;
#[cfg(feature = "ident")]
pub use ident::IdentServer;
#[cfg(feature = "gemini")]
pub mod gemini;
#[cfg(feature = "gemini")]
pub use gemini::actions::GeminiProtocol;
#[cfg(feature = "gemini")]
pub use gemini::GeminiServer;
#[cfg(feature = "dict")]
pub mod dict;
#[cfg(feature = "dict")]
pub use dict::actions::DictProtocol;
#[cfg(feature = "dict")]
pub use dict::DictServer;
#[cfg(feature = "beanstalkd")]
pub mod beanstalkd;
#[cfg(feature = "beanstalkd")]
pub use beanstalkd::actions::BeanstalkdProtocol;
#[cfg(feature = "beanstalkd")]
pub use beanstalkd::BeanstalkdServer;
#[cfg(feature = "zabbix")]
pub mod zabbix;
#[cfg(feature = "zabbix")]
pub use zabbix::actions::ZabbixProtocol;
#[cfg(feature = "zabbix")]
pub use zabbix::ZabbixServer;
#[cfg(feature = "gearman")]
pub mod gearman;
#[cfg(feature = "gearman")]
pub use gearman::actions::GearmanProtocol;
#[cfg(feature = "gearman")]
pub use gearman::GearmanServer;
#[cfg(feature = "nsq")]
pub mod nsq;
#[cfg(feature = "nsq")]
pub use nsq::actions::NsqProtocol;
#[cfg(feature = "nsq")]
pub use nsq::NsqServer;
#[cfg(feature = "gopher")]
pub mod gopher;
#[cfg(feature = "gopher")]
pub use gopher::actions::GopherProtocol;
#[cfg(feature = "gopher")]
pub use gopher::GopherServer;
#[cfg(feature = "finger")]
pub mod finger;
#[cfg(feature = "finger")]
pub use finger::actions::FingerProtocol;
#[cfg(feature = "finger")]
pub use finger::FingerServer;
#[cfg(feature = "ssdp")]
pub mod ssdp;
#[cfg(feature = "ssdp")]
pub use ssdp::actions::SsdpProtocol;
#[cfg(feature = "ssdp")]
pub use ssdp::SsdpServer;
#[cfg(feature = "llmnr")]
pub mod llmnr;
#[cfg(feature = "llmnr")]
pub use llmnr::actions::LlmnrProtocol;
#[cfg(feature = "llmnr")]
pub use llmnr::LlmnrServer;
#[cfg(feature = "netbios-ns")]
pub mod netbios_ns;
#[cfg(feature = "netbios-ns")]
pub use netbios_ns::actions::NetbiosNsProtocol;
#[cfg(feature = "netbios-ns")]
pub use netbios_ns::NetbiosNsServer;

#[cfg(feature = "snmp")]
pub mod snmp;
#[cfg(feature = "snmp")]
pub use snmp::actions::SnmpProtocol;
#[cfg(feature = "snmp")]
pub use snmp::SnmpServer;

#[cfg(feature = "igmp")]
pub mod igmp;
#[cfg(feature = "igmp")]
pub use igmp::actions::IgmpProtocol;
#[cfg(feature = "igmp")]
pub use igmp::IgmpServer;

#[cfg(feature = "syslog")]
pub mod syslog;
#[cfg(feature = "syslog")]
pub use syslog::actions::SyslogProtocol;
#[cfg(feature = "syslog")]
pub use syslog::SyslogServer;

#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "ssh")]
pub use ssh::actions::SshProtocol;
#[cfg(feature = "ssh")]
pub use ssh::sftp_handler::LlmSftpHandler;
#[cfg(feature = "ssh")]
pub use ssh::SshServer;

#[cfg(all(feature = "ssh-agent", unix))]
pub mod ssh_agent;
#[cfg(all(feature = "ssh-agent", unix))]
pub use ssh_agent::actions::SshAgentProtocol;
#[cfg(all(feature = "ssh-agent", unix))]
pub use ssh_agent::SshAgentServer;

#[cfg(feature = "svn")]
pub mod svn;
#[cfg(feature = "svn")]
pub use svn::actions::SvnProtocol;
#[cfg(feature = "svn")]
pub use svn::SvnServer;

#[cfg(feature = "irc")]
pub mod irc;
#[cfg(feature = "irc")]
pub use irc::actions::IrcProtocol;
#[cfg(feature = "irc")]
pub use irc::IrcServer;

#[cfg(feature = "xmpp")]
pub mod xmpp;
#[cfg(feature = "xmpp")]
pub use xmpp::actions::XmppProtocol;
#[cfg(feature = "xmpp")]
pub use xmpp::XmppServer;

#[cfg(feature = "telnet")]
pub mod telnet;
#[cfg(feature = "telnet")]
pub use telnet::actions::TelnetProtocol;
#[cfg(feature = "telnet")]
pub use telnet::TelnetServer;

#[cfg(feature = "smtp")]
pub mod smtp;
#[cfg(feature = "smtp")]
pub use smtp::actions::SmtpProtocol;
#[cfg(feature = "smtp")]
pub use smtp::SmtpServer;

#[cfg(feature = "ftp")]
pub mod ftp;
#[cfg(feature = "ftp")]
pub use ftp::actions::FtpProtocol;
#[cfg(feature = "ftp")]
pub use ftp::FtpServer;

#[cfg(feature = "mdns")]
pub mod mdns;
#[cfg(feature = "mdns")]
pub use mdns::actions::MdnsProtocol;
#[cfg(feature = "mdns")]
pub use mdns::MdnsServer;

#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "mysql")]
pub use mysql::actions::MysqlProtocol;
#[cfg(feature = "mysql")]
pub use mysql::MysqlServer;

#[cfg(feature = "snowflake")]
pub mod snowflake;
#[cfg(feature = "snowflake")]
pub use snowflake::actions::SnowflakeProtocol;
#[cfg(feature = "snowflake")]
pub use snowflake::SnowflakeServer;

#[cfg(feature = "db2")]
pub mod db2;
#[cfg(feature = "db2")]
pub use db2::actions::Db2Protocol;
#[cfg(feature = "db2")]
pub use db2::Db2Server;

#[cfg(feature = "mongodb-server")]
pub mod mongodb;
#[cfg(feature = "mongodb-server")]
pub use mongodb::actions::MongodbProtocol;
#[cfg(feature = "mongodb-server")]
pub use mongodb::MongodbServer;

#[cfg(feature = "mssql")]
pub mod mssql;
#[cfg(feature = "mssql")]
pub use mssql::actions::MssqlProtocol;
#[cfg(feature = "mssql")]
pub use mssql::MssqlServer;

#[cfg(feature = "ipp")]
pub mod ipp;
#[cfg(feature = "ipp")]
pub use ipp::actions::IppProtocol;
#[cfg(feature = "ipp")]
pub use ipp::IppServer;

#[cfg(feature = "postgresql")]
pub mod postgresql;
#[cfg(feature = "postgresql")]
pub use postgresql::actions::PostgresqlProtocol;
#[cfg(feature = "postgresql")]
pub use postgresql::PostgresqlServer;

#[cfg(feature = "memcached")]
pub mod memcached;
#[cfg(feature = "memcached")]
pub use memcached::actions::MemcachedProtocol;
#[cfg(feature = "memcached")]
pub use memcached::MemcachedServer;

#[cfg(feature = "radius")]
pub mod radius;
#[cfg(feature = "radius")]
pub use radius::actions::RadiusProtocol;
#[cfg(feature = "radius")]
pub use radius::RadiusServer;

#[cfg(feature = "redis")]
pub mod redis;
#[cfg(feature = "redis")]
pub use redis::actions::RedisProtocol;
#[cfg(feature = "redis")]
pub use redis::RedisServer;

#[cfg(feature = "rss")]
pub mod rss;
#[cfg(feature = "rss")]
pub use rss::actions::RssProtocol;
#[cfg(feature = "rss")]
pub use rss::RssServer;

#[cfg(feature = "cassandra")]
pub mod cassandra;
#[cfg(feature = "cassandra")]
pub use cassandra::actions::CassandraProtocol;
#[cfg(feature = "cassandra")]
pub use cassandra::CassandraServer;

#[cfg(feature = "proxy")]
pub mod proxy;
#[cfg(feature = "proxy")]
pub use proxy::actions::ProxyProtocol;
#[cfg(feature = "proxy")]
pub use proxy::filter::{
    CertificateMode, FilterMode, FullRequestInfo, FullResponseInfo, HttpsConnectionAction,
    HttpsConnectionInfo, ProxyFilterConfig, RequestAction, RequestFilter, ResponseAction,
    ResponseFilter,
};
#[cfg(feature = "proxy")]
pub use proxy::ProxyServer;

#[cfg(feature = "socks5")]
pub mod socks5;
#[cfg(feature = "socks5")]
pub use socks5::actions::Socks5Protocol;
#[cfg(feature = "socks5")]
pub use socks5::filter::{FilterMode as Socks5FilterMode, Socks5FilterConfig};
#[cfg(feature = "socks5")]
pub use socks5::Socks5Server;

#[cfg(feature = "webdav")]
pub mod webdav;
#[cfg(feature = "webdav")]
pub use webdav::actions::WebDavProtocol;
#[cfg(feature = "webdav")]
pub use webdav::WebDavServer;

#[cfg(feature = "nfs")]
pub mod nfs;
#[cfg(feature = "nfs")]
pub use nfs::actions::NfsProtocol;
#[cfg(feature = "nfs")]
pub use nfs::NfsServer;

#[cfg(feature = "nfc")]
pub mod nfc;
#[cfg(feature = "nfc")]
pub use nfc::actions::NfcServerProtocol;
#[cfg(feature = "nfc")]
pub use nfc::NfcServer;

#[cfg(feature = "smb")]
pub mod smb;
#[cfg(feature = "smb")]
pub use smb::actions::SmbProtocol;
#[cfg(feature = "smb")]
pub use smb::SmbServer;

#[cfg(feature = "stun")]
pub mod stun;
#[cfg(feature = "stun")]
pub use stun::actions::StunProtocol;
#[cfg(feature = "stun")]
pub use stun::StunServer;

#[cfg(feature = "turn")]
pub mod turn;
#[cfg(feature = "turn")]
pub use turn::actions::TurnProtocol;
#[cfg(feature = "turn")]
pub use turn::TurnServer;

#[cfg(feature = "webrtc")]
pub mod webrtc;
#[cfg(feature = "webrtc")]
pub use webrtc::actions::WebRtcProtocol;
#[cfg(feature = "webrtc")]
pub use webrtc::{WebRtcServer, WebRtcServerData};

#[cfg(feature = "websocket")]
pub mod websocket;
#[cfg(feature = "websocket")]
pub use websocket::actions::WebSocketProtocol;
#[cfg(feature = "websocket")]
pub use websocket::WebSocketServer;

#[cfg(feature = "webrtc")]
pub mod webrtc_signaling;
#[cfg(feature = "webrtc")]
pub use webrtc_signaling::actions::WebRtcSignalingProtocol;
#[cfg(feature = "webrtc")]
pub use webrtc_signaling::{WebRtcSignalingServer, WebRtcSignalingServerData};

#[cfg(feature = "sip")]
pub mod sip;
#[cfg(feature = "sip")]
pub use sip::actions::SipProtocol;
#[cfg(feature = "sip")]
pub use sip::SipServer;

// H.323 gatekeeper (H.225.0 RAS) and call-signalling endpoint (H.225.0 / Q.931)
#[cfg(feature = "h323")]
pub mod h323;

#[cfg(feature = "rtp")]
pub mod rtp;
#[cfg(feature = "rtp")]
pub use rtp::actions::RtpProtocol;
#[cfg(feature = "rtp")]
pub use rtp::RtpServer;

#[cfg(feature = "rtsp")]
pub mod rtsp;
#[cfg(feature = "rtsp")]
pub use rtsp::actions::RtspProtocol;
#[cfg(feature = "rtsp")]
pub use rtsp::RtspServer;

#[cfg(feature = "hls")]
pub mod hls;
#[cfg(feature = "hls")]
pub use hls::actions::HlsProtocol;
#[cfg(feature = "hls")]
pub use hls::HlsServer;

#[cfg(feature = "ldap")]
pub mod ldap;
#[cfg(feature = "ldap")]
pub use ldap::actions::LdapProtocol;
#[cfg(feature = "ldap")]
pub use ldap::LdapServer;

#[cfg(feature = "imap")]
pub mod imap;
#[cfg(feature = "imap")]
pub use imap::actions::ImapProtocol;
#[cfg(feature = "imap")]
pub use imap::ImapServer;

#[cfg(feature = "pop3")]
pub mod pop3;
#[cfg(feature = "pop3")]
pub use pop3::actions::Pop3Protocol;
#[cfg(feature = "pop3")]
pub use pop3::Pop3Server;

#[cfg(feature = "nntp")]
pub mod nntp;
#[cfg(feature = "nntp")]
pub use nntp::actions::NntpProtocol;
#[cfg(feature = "nntp")]
pub use nntp::NntpServer;

#[cfg(feature = "managesieve")]
pub mod managesieve;
#[cfg(feature = "mqtt")]
pub mod mqtt;
#[cfg(feature = "mqtt_sn")]
pub mod mqtt_sn;
#[cfg(feature = "nbd")]
pub mod nbd;
#[cfg(feature = "mqtt")]
pub use mqtt::actions::MqttProtocol;
#[cfg(feature = "mqtt")]
pub use mqtt::MqttServer;

#[cfg(feature = "modbus")]
pub mod modbus;
#[cfg(feature = "modbus")]
pub use modbus::actions::ModbusProtocol;
#[cfg(feature = "modbus")]
pub use modbus::ModbusServer;

#[cfg(feature = "coap")]
pub mod coap;
#[cfg(feature = "coap")]
pub use coap::actions::CoapProtocol;
#[cfg(feature = "coap")]
pub use coap::CoapServer;

#[cfg(feature = "amqp")]
pub mod amqp;
#[cfg(feature = "amqp")]
pub use amqp::actions::AmqpProtocol;
#[cfg(feature = "amqp")]
pub use amqp::AmqpServer;

#[cfg(feature = "elasticsearch")]
pub mod elasticsearch;
#[cfg(feature = "elasticsearch")]
pub use elasticsearch::actions::ElasticsearchProtocol;
#[cfg(feature = "elasticsearch")]
pub use elasticsearch::ElasticsearchServer;

#[cfg(feature = "couchdb")]
pub mod couchdb;
#[cfg(feature = "couchdb")]
pub use couchdb::actions::CouchDbProtocol;
#[cfg(feature = "couchdb")]
pub use couchdb::CouchDbServer;

#[cfg(feature = "yarn")]
pub mod yarn;
#[cfg(feature = "yarn")]
pub use yarn::actions::YarnProtocol;
#[cfg(feature = "yarn")]
pub use yarn::YarnServer;

#[cfg(feature = "spark")]
pub mod spark;
#[cfg(feature = "spark")]
pub use spark::actions::SparkProtocol;
#[cfg(feature = "spark")]
pub use spark::SparkServer;

#[cfg(feature = "dynamo")]
pub mod dynamo;
#[cfg(feature = "dynamo")]
pub use dynamo::actions::DynamoProtocol;
#[cfg(feature = "dynamo")]
pub use dynamo::DynamoServer;

#[cfg(feature = "s3")]
pub mod s3;
#[cfg(feature = "s3")]
pub use s3::actions::S3Protocol;
#[cfg(feature = "s3")]
pub use s3::S3Server;

#[cfg(feature = "sqs")]
pub mod sqs;
#[cfg(feature = "sqs")]
pub use sqs::actions::SqsProtocol;
#[cfg(feature = "sqs")]
pub use sqs::SqsServer;

#[cfg(feature = "npm")]
pub mod npm;
#[cfg(feature = "npm")]
pub use npm::actions::NpmProtocol;
#[cfg(feature = "npm")]
pub use npm::NpmServer;

#[cfg(feature = "oci-registry")]
pub mod oci_registry;
#[cfg(feature = "oci-registry")]
pub use oci_registry::actions::OciRegistryProtocol;
#[cfg(feature = "oci-registry")]
pub use oci_registry::OciRegistryServer;

// Kubernetes API server. Gated on `kubernetes-server`, NOT on the `kubernetes` client
// feature: the server is JSON-only and pulls in neither kube nor k8s-openapi.
#[cfg(feature = "kubernetes-server")]
pub mod kubernetes;
#[cfg(feature = "kubernetes-server")]
pub use kubernetes::actions::KubernetesProtocol;
#[cfg(feature = "kubernetes-server")]
pub use kubernetes::KubernetesServer;

#[cfg(feature = "prometheus")]
pub mod prometheus;
#[cfg(feature = "prometheus")]
pub use prometheus::actions::PrometheusProtocol;
#[cfg(feature = "prometheus")]
pub use prometheus::PrometheusServer;
#[cfg(feature = "otlp")]
pub mod otlp;
#[cfg(feature = "otlp")]
pub use otlp::actions::OtlpProtocol;
#[cfg(feature = "otlp")]
pub use otlp::OtlpServer;

#[cfg(feature = "docker")]
pub mod docker;
#[cfg(feature = "docker")]
pub use docker::actions::DockerProtocol;
#[cfg(feature = "docker")]
pub use docker::DockerServer;

#[cfg(feature = "vault")]
pub mod vault;
#[cfg(feature = "vault")]
pub use vault::actions::VaultProtocol;
#[cfg(feature = "vault")]
pub use vault::VaultServer;

#[cfg(feature = "bolt")]
pub mod bolt;
#[cfg(feature = "bolt")]
pub use bolt::actions::BoltProtocol;
#[cfg(feature = "bolt")]
pub use bolt::BoltServer;

#[cfg(feature = "openai")]
pub mod openai;
#[cfg(feature = "openai")]
pub use openai::actions::OpenAiProtocol;
#[cfg(feature = "openai")]
pub use openai::OpenAiServer;

#[cfg(feature = "ollama")]
pub mod ollama;
#[cfg(feature = "ollama")]
pub use ollama::actions::OllamaProtocol;
#[cfg(feature = "ollama")]
pub use ollama::OllamaServer;

#[cfg(feature = "oauth2")]
pub mod oauth2;
#[cfg(feature = "oauth2")]
pub use oauth2::actions::OAuth2Protocol;
#[cfg(feature = "oauth2")]
pub use oauth2::OAuth2Server;

#[cfg(feature = "jsonrpc")]
pub mod jsonrpc;
#[cfg(feature = "jsonrpc")]
pub use jsonrpc::actions::JsonRpcProtocol;
#[cfg(feature = "jsonrpc")]
pub use jsonrpc::JsonRpcServer;

#[cfg(feature = "wireguard")]
pub mod wireguard;
#[cfg(feature = "wireguard")]
pub use wireguard::actions::WireguardProtocol;
#[cfg(feature = "wireguard")]
pub use wireguard::WireguardServer;

#[cfg(feature = "openvpn")]
pub mod openvpn;
#[cfg(feature = "openvpn")]
pub use openvpn::actions::OpenvpnProtocol;
#[cfg(feature = "openvpn")]
pub use openvpn::OpenvpnServer;

#[cfg(feature = "ipsec")]
pub mod ipsec;
#[cfg(feature = "ipsec")]
pub use ipsec::actions::IpsecProtocol;
#[cfg(feature = "ipsec")]
pub use ipsec::IpsecServer;

#[cfg(feature = "bgp")]
pub mod bgp;
#[cfg(feature = "bgp")]
pub use bgp::actions::BgpProtocol;
#[cfg(feature = "bgp")]
pub use bgp::BgpServer;

#[cfg(feature = "ospf")]
pub mod ospf;
#[cfg(feature = "ospf")]
pub use ospf::actions::OspfProtocol;
#[cfg(feature = "ospf")]
pub use ospf::OspfServer;

#[cfg(feature = "isis")]
pub mod isis;
#[cfg(feature = "isis")]
pub use isis::actions::IsisProtocol;
#[cfg(feature = "isis")]
pub use isis::IsisServer;

#[cfg(feature = "rip")]
pub mod rip;
#[cfg(feature = "rip")]
pub use rip::actions::RipProtocol;
#[cfg(feature = "rip")]
pub use rip::RipServer;

#[cfg(feature = "bitcoin")]
pub mod bitcoin;
#[cfg(feature = "devp2p")]
pub mod devp2p;
#[cfg(feature = "bitcoin")]
pub use bitcoin::actions::BitcoinProtocol;
#[cfg(feature = "bitcoin")]
pub use bitcoin::BitcoinServer;
#[cfg(feature = "nostr")]
pub mod nostr;
#[cfg(feature = "nostr")]
pub use nostr::actions::NostrProtocol;
#[cfg(feature = "nostr")]
pub use nostr::NostrServer;

#[cfg(feature = "mcp")]
pub mod mcp;
#[cfg(feature = "mcp")]
pub use mcp::actions::McpProtocol;
#[cfg(feature = "mcp")]
pub use mcp::McpServer;

#[cfg(feature = "connect_rpc")]
pub mod connect_rpc;
#[cfg(feature = "gnmi")]
pub mod gnmi;
#[cfg(feature = "grpc")]
pub mod grpc;
#[cfg(feature = "grpc-web")]
pub mod grpc_web;
#[cfg(feature = "grpc")]
pub use grpc::actions::GrpcProtocol;
#[cfg(feature = "grpc")]
pub use grpc::GrpcServer;

#[cfg(feature = "etcd")]
pub mod etcd;
#[cfg(feature = "etcd")]
pub use etcd::actions::EtcdProtocol;
#[cfg(feature = "etcd")]
pub use etcd::EtcdServer;

#[cfg(feature = "xmlrpc")]
pub mod xmlrpc;
#[cfg(feature = "xmlrpc")]
pub use xmlrpc::actions::XmlRpcProtocol;
#[cfg(feature = "xmlrpc")]
pub use xmlrpc::XmlRpcServer;

#[cfg(feature = "zookeeper")]
pub mod zookeeper;
#[cfg(feature = "zookeeper")]
pub use zookeeper::actions::ZookeeperProtocol;
#[cfg(feature = "zookeeper")]
pub use zookeeper::ZookeeperServer;

#[cfg(feature = "tor")]
pub mod tor_relay;
#[cfg(feature = "tor")]
pub use tor_relay::actions::TorRelayProtocol;
#[cfg(feature = "tor")]
pub use tor_relay::TorRelayServer;

#[cfg(feature = "vnc")]
pub mod vnc;
#[cfg(feature = "vnc")]
pub use vnc::actions::VncProtocol;
#[cfg(feature = "vnc")]
pub use vnc::VncServer;

#[cfg(feature = "reverse-shell")]
pub mod reverse_shell;
#[cfg(feature = "reverse-shell")]
pub use reverse_shell::actions::ReverseShellProtocol;
#[cfg(feature = "reverse-shell")]
pub use reverse_shell::ReverseShellServer;

#[cfg(feature = "rdp")]
pub mod rdp;
#[cfg(feature = "spice")]
pub mod spice;
#[cfg(feature = "rdp")]
pub use rdp::actions::RdpProtocol;
#[cfg(feature = "rdp")]
pub use rdp::RdpServer;

#[cfg(feature = "openapi")]
pub mod openapi;
#[cfg(feature = "openapi")]
pub use openapi::actions::OpenApiProtocol;
#[cfg(feature = "openapi")]
pub use openapi::OpenApiServer;

#[cfg(feature = "openid")]
pub mod openid;
#[cfg(feature = "openid")]
pub use openid::actions::OpenIdProtocol;
#[cfg(feature = "openid")]
pub use openid::OpenIdServer;

#[cfg(feature = "git")]
pub mod git;
#[cfg(feature = "git")]
pub use git::actions::GitProtocol;
#[cfg(feature = "git")]
pub use git::GitServer;

#[cfg(feature = "mercurial")]
pub mod mercurial;
#[cfg(feature = "mercurial")]
pub use mercurial::actions::MercurialProtocol;
#[cfg(feature = "mercurial")]
pub use mercurial::MercurialServer;

#[cfg(feature = "kafka")]
pub mod kafka;
#[cfg(feature = "kafka")]
pub use kafka::actions::KafkaProtocol;
#[cfg(feature = "kafka")]
pub use kafka::KafkaServer;

// Raw QUIC stream server (RFC 9000/9001). Deliberately not HTTP/3 - the HTTP/3
// *client* lives at src/client/http3/ behind the separate `http3` feature.
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "quic")]
pub use quic::actions::QuicProtocol;
#[cfg(feature = "quic")]
pub use quic::QuicServer;

#[cfg(feature = "torrent-tracker")]
pub mod torrent_tracker;
#[cfg(feature = "torrent-tracker")]
pub use torrent_tracker::actions::TorrentTrackerProtocol;
#[cfg(feature = "torrent-tracker")]
pub use torrent_tracker::TorrentTrackerServer;

#[cfg(feature = "torrent-dht")]
pub mod torrent_dht;
#[cfg(feature = "torrent-dht")]
pub use torrent_dht::actions::TorrentDhtProtocol;
#[cfg(feature = "torrent-dht")]
pub use torrent_dht::TorrentDhtServer;

#[cfg(feature = "torrent-peer")]
pub mod torrent_peer;
#[cfg(feature = "torrent-peer")]
pub use torrent_peer::actions::TorrentPeerProtocol;
#[cfg(feature = "torrent-peer")]
pub use torrent_peer::TorrentPeerServer;

#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "tls")]
pub use tls::actions::TlsProtocol;
#[cfg(feature = "tls")]
pub use tls::TlsServer;

#[cfg(feature = "saml-idp")]
pub mod saml_idp;
#[cfg(feature = "saml-idp")]
pub use saml_idp::actions::SamlIdpProtocol;
#[cfg(feature = "saml-idp")]
pub use saml_idp::SamlIdpServer;

#[cfg(feature = "saml-sp")]
pub mod saml_sp;
#[cfg(feature = "saml-sp")]
pub use saml_sp::actions::SamlSpProtocol;
#[cfg(feature = "saml-sp")]
pub use saml_sp::SamlSpServer;

#[cfg(feature = "usb-common")]
pub mod usb;

#[cfg(feature = "usb-keyboard")]
pub use usb::keyboard::UsbKeyboardServer;
#[cfg(feature = "usb-keyboard")]
pub use usb::UsbKeyboardProtocol;

#[cfg(feature = "usb-mouse")]
pub use usb::mouse::UsbMouseServer;
#[cfg(feature = "usb-mouse")]
pub use usb::UsbMouseProtocol;

#[cfg(feature = "usb-serial")]
pub use usb::serial::UsbSerialServer;
#[cfg(feature = "usb-serial")]
pub use usb::UsbSerialProtocol;

#[cfg(feature = "usb-msc")]
pub use usb::msc::UsbMscServer;
#[cfg(feature = "usb-msc")]
pub use usb::UsbMscProtocol;

#[cfg(feature = "usb-fido2")]
pub use usb::fido2::UsbFido2Server;
#[cfg(feature = "usb-fido2")]
pub use usb::UsbFido2Protocol;

#[cfg(feature = "usb-smartcard")]
pub use usb::smartcard::UsbSmartCardServer;
#[cfg(feature = "usb-smartcard")]
pub use usb::UsbSmartCardProtocol;

#[cfg(feature = "bluetooth-ble")]
pub mod bluetooth_ble;
#[cfg(feature = "bluetooth-ble")]
pub use bluetooth_ble::actions::BluetoothBleProtocol;
#[cfg(feature = "bluetooth-ble")]
pub use bluetooth_ble::BluetoothBle;

#[cfg(feature = "bluetooth-ble-keyboard")]
pub mod bluetooth_ble_keyboard;
#[cfg(feature = "bluetooth-ble-keyboard")]
pub use bluetooth_ble_keyboard::actions::BluetoothBleKeyboardProtocol;
#[cfg(feature = "bluetooth-ble-keyboard")]
pub use bluetooth_ble_keyboard::BluetoothBleKeyboard;

#[cfg(feature = "bluetooth-ble-mouse")]
pub mod bluetooth_ble_mouse;
#[cfg(feature = "bluetooth-ble-mouse")]
pub use bluetooth_ble_mouse::actions::BluetoothBleMouseProtocol;
#[cfg(feature = "bluetooth-ble-mouse")]
pub use bluetooth_ble_mouse::BluetoothBleMouse;

#[cfg(feature = "bluetooth-ble-beacon")]
pub mod bluetooth_ble_beacon;
#[cfg(feature = "bluetooth-ble-beacon")]
pub use bluetooth_ble_beacon::actions::BluetoothBleBeaconProtocol;
#[cfg(feature = "bluetooth-ble-beacon")]
pub use bluetooth_ble_beacon::BluetoothBleBeacon;

#[cfg(feature = "bluetooth-ble-remote")]
pub mod bluetooth_ble_remote;
#[cfg(feature = "bluetooth-ble-remote")]
pub use bluetooth_ble_remote::actions::BluetoothBleRemoteProtocol;
#[cfg(feature = "bluetooth-ble-remote")]
pub use bluetooth_ble_remote::BluetoothBleRemote;

#[cfg(feature = "bluetooth-ble-battery")]
pub mod bluetooth_ble_battery;
#[cfg(feature = "bluetooth-ble-battery")]
pub use bluetooth_ble_battery::actions::BluetoothBleBatteryProtocol;
#[cfg(feature = "bluetooth-ble-battery")]
pub use bluetooth_ble_battery::BluetoothBleBattery;

#[cfg(feature = "bluetooth-ble-heart-rate")]
pub mod bluetooth_ble_heart_rate;
#[cfg(feature = "bluetooth-ble-heart-rate")]
pub use bluetooth_ble_heart_rate::actions::BluetoothBleHeartRateProtocol;
#[cfg(feature = "bluetooth-ble-heart-rate")]
pub use bluetooth_ble_heart_rate::BluetoothBleHeartRate;

#[cfg(feature = "bluetooth-ble-thermometer")]
pub mod bluetooth_ble_thermometer;
#[cfg(feature = "bluetooth-ble-thermometer")]
pub use bluetooth_ble_thermometer::actions::BluetoothBleThermometerProtocol;
#[cfg(feature = "bluetooth-ble-thermometer")]
pub use bluetooth_ble_thermometer::BluetoothBleThermometer;

#[cfg(feature = "bluetooth-ble-environmental")]
pub mod bluetooth_ble_environmental;
#[cfg(feature = "bluetooth-ble-environmental")]
pub use bluetooth_ble_environmental::actions::BluetoothBleEnvironmentalProtocol;
#[cfg(feature = "bluetooth-ble-environmental")]
pub use bluetooth_ble_environmental::BluetoothBleEnvironmental;

#[cfg(feature = "bluetooth-ble-proximity")]
pub mod bluetooth_ble_proximity;
#[cfg(feature = "bluetooth-ble-proximity")]
pub use bluetooth_ble_proximity::actions::BluetoothBleProximityProtocol;
#[cfg(feature = "bluetooth-ble-proximity")]
pub use bluetooth_ble_proximity::BluetoothBleProximity;

#[cfg(feature = "bluetooth-ble-gamepad")]
pub mod bluetooth_ble_gamepad;
#[cfg(feature = "bluetooth-ble-gamepad")]
pub use bluetooth_ble_gamepad::actions::BluetoothBleGamepadProtocol;
#[cfg(feature = "bluetooth-ble-gamepad")]
pub use bluetooth_ble_gamepad::BluetoothBleGamepad;

#[cfg(feature = "bluetooth-ble-presenter")]
pub mod bluetooth_ble_presenter;
#[cfg(feature = "bluetooth-ble-presenter")]
pub use bluetooth_ble_presenter::actions::BluetoothBlePresenterProtocol;
#[cfg(feature = "bluetooth-ble-presenter")]
pub use bluetooth_ble_presenter::BluetoothBlePresenter;

#[cfg(feature = "bluetooth-ble-file-transfer")]
pub mod bluetooth_ble_file_transfer;
#[cfg(feature = "bluetooth-ble-file-transfer")]
pub use bluetooth_ble_file_transfer::actions::BluetoothBleFileTransferProtocol;
#[cfg(feature = "bluetooth-ble-file-transfer")]
pub use bluetooth_ble_file_transfer::BluetoothBleFileTransfer;

#[cfg(feature = "bluetooth-ble-data-stream")]
pub mod bluetooth_ble_data_stream;
#[cfg(feature = "bluetooth-ble-data-stream")]
pub use bluetooth_ble_data_stream::actions::BluetoothBleDataStreamProtocol;
#[cfg(feature = "bluetooth-ble-data-stream")]
pub use bluetooth_ble_data_stream::BluetoothBleDataStream;

#[cfg(feature = "bluetooth-ble-cycling")]
pub mod bluetooth_ble_cycling;
#[cfg(feature = "bluetooth-ble-cycling")]
pub use bluetooth_ble_cycling::actions::BluetoothBleCyclingProtocol;
#[cfg(feature = "bluetooth-ble-cycling")]
pub use bluetooth_ble_cycling::BluetoothBleCycling;

#[cfg(feature = "bluetooth-ble-running")]
pub mod bluetooth_ble_running;
#[cfg(feature = "bluetooth-ble-running")]
pub use bluetooth_ble_running::actions::BluetoothBleRunningProtocol;
#[cfg(feature = "bluetooth-ble-running")]
pub use bluetooth_ble_running::BluetoothBleRunning;

#[cfg(feature = "bluetooth-ble-weight-scale")]
pub mod bluetooth_ble_weight_scale;
#[cfg(feature = "bluetooth-ble-weight-scale")]
pub use bluetooth_ble_weight_scale::actions::BluetoothBleWeightScaleProtocol;
#[cfg(feature = "bluetooth-ble-weight-scale")]
pub use bluetooth_ble_weight_scale::BluetoothBleWeightScale;

pub use connection::{Connection, ConnectionId};

#[cfg(feature = "doq")]
pub mod doq;
#[cfg(feature = "nut")]
pub mod nut;
#[cfg(feature = "statsd")]
pub mod statsd;

#[cfg(feature = "graphite")]
pub mod graphite;

#[cfg(feature = "gelf")]
pub mod gelf;

#[cfg(feature = "http3")]
pub mod http3;
#[cfg(feature = "http3")]
pub use http3::actions::Http3Protocol;
#[cfg(feature = "fluent-forward")]
pub mod fluent_forward;

#[cfg(feature = "influxdb")]
pub mod influxdb;

#[cfg(feature = "ipfix")]
pub mod ipfix;

#[cfg(feature = "sflow")]
pub mod sflow;

#[cfg(feature = "loki")]
pub mod loki;

#[cfg(feature = "prometheus-remote-write")]
pub mod prometheus_remote_write;

#[cfg(feature = "netflow-v9")]
pub mod netflow_v9;

#[cfg(feature = "a2a")]
pub mod a2a;
#[cfg(feature = "acme")]
pub mod acme;
#[cfg(feature = "amqp1")]
pub mod amqp1;
#[cfg(feature = "bmp")]
pub mod bmp;
#[cfg(feature = "caldav")]
pub mod caldav;
#[cfg(feature = "carddav")]
pub mod carddav;
#[cfg(any(feature = "caldav", feature = "carddav"))]
pub mod dav_common;
#[cfg(feature = "dicom")]
pub mod dicom;
#[cfg(feature = "fastcgi")]
pub mod fastcgi;
#[cfg(feature = "fix")]
pub mod fix;
#[cfg(feature = "graphql")]
pub mod graphql;
#[cfg(feature = "hl7")]
pub mod hl7;
#[cfg(feature = "icap")]
pub mod icap;
#[cfg(feature = "netconf")]
pub mod netconf;
#[cfg(feature = "ocpp")]
pub mod ocpp;
#[cfg(feature = "rdap")]
pub mod rdap;
#[cfg(feature = "redfish")]
pub mod redfish;
#[cfg(feature = "rpki_rtr")]
pub mod rpki_rtr;
#[cfg(feature = "rtmp")]
pub mod rtmp;
#[cfg(feature = "scim")]
pub mod scim;
#[cfg(feature = "socketio")]
pub mod socketio;
#[cfg(feature = "srt")]
pub mod srt;
#[cfg(feature = "tacacs")]
pub mod tacacs;
#[cfg(feature = "thrift")]
pub mod thrift;
#[cfg(feature = "wamp")]
pub mod wamp;

#[cfg(feature = "a2s")]
pub mod a2s;
#[cfg(feature = "activitypub")]
pub mod activitypub;
#[cfg(feature = "anthropic")]
pub mod anthropic;
#[cfg(feature = "bfd")]
pub mod bfd;
#[cfg(feature = "capnp-rpc")]
pub mod capnp_rpc;
#[cfg(feature = "clickhouse")]
pub mod clickhouse;
#[cfg(feature = "consul")]
pub mod consul;
#[cfg(feature = "dbus")]
pub mod dbus;
#[cfg(feature = "diameter")]
pub mod diameter;
#[cfg(feature = "epp")]
pub mod epp;
#[cfg(feature = "guacamole")]
pub mod guacamole;
#[cfg(feature = "inetd")]
pub mod inetd;
#[cfg(feature = "jmap")]
pub mod jmap;
#[cfg(feature = "kerberos")]
pub mod kerberos;
#[cfg(feature = "knx")]
pub mod knx;
#[cfg(feature = "libp2p")]
pub mod libp2p;
#[cfg(feature = "lmtp")]
pub mod lmtp;
#[cfg(feature = "lpd")]
pub mod lpd;
#[cfg(feature = "lwm2m")]
pub mod lwm2m;
#[cfg(feature = "matrix")]
pub mod matrix;
#[cfg(feature = "milter")]
pub mod milter;
#[cfg(feature = "minecraft")]
pub mod minecraft;
#[cfg(feature = "msgpack-rpc")]
pub mod msgpack_rpc;
#[cfg(feature = "ninep")]
pub mod ninep;
#[cfg(feature = "onvif")]
pub mod onvif;
#[cfg(feature = "openflow")]
pub mod openflow;
#[cfg(feature = "pfcp")]
pub mod pfcp;
#[cfg(feature = "pulsar")]
pub mod pulsar;
#[cfg(feature = "radsec")]
pub mod radsec;
#[cfg(feature = "rcon")]
pub mod rcon;
#[cfg(feature = "restconf")]
pub mod restconf;
#[cfg(feature = "rsync")]
pub mod rsync;
#[cfg(feature = "smpp")]
pub mod smpp;
#[cfg(feature = "sse")]
pub mod sse;
#[cfg(feature = "stratum")]
pub mod stratum;
#[cfg(feature = "stratum-v2")]
pub mod stratum_v2;
#[cfg(feature = "sunrpc")]
pub mod sunrpc;
#[cfg(feature = "tr069")]
pub mod tr069;
#[cfg(feature = "vxlan")]
pub mod vxlan;
#[cfg(feature = "webtransport")]
pub mod webtransport;
#[cfg(feature = "wsdiscovery")]
pub mod wsdiscovery;
#[cfg(feature = "zenoh")]
pub mod zenoh;
#[cfg(feature = "zeromq")]
pub mod zeromq;
#[cfg(feature = "zipkin")]
pub mod zipkin;

#[cfg(feature = "s7comm")]
pub mod s7comm;

#[cfg(any(
    feature = "s7comm",
    feature = "ethernet_ip",
    feature = "dnp3",
    feature = "iec104",
    feature = "bacnet",
    feature = "opcua"
))]
pub mod ics_support;

#[cfg(feature = "ethernet_ip")]
pub mod ethernet_ip;

#[cfg(feature = "dnp3")]
pub mod dnp3;

#[cfg(feature = "iec104")]
pub mod iec104;

#[cfg(feature = "bacnet")]
pub mod bacnet;

#[cfg(feature = "opcua")]
pub mod opcua;

#[cfg(any(
    feature = "dc_peer",
    feature = "adc",
    feature = "adc_peer",
    feature = "soulseek",
    feature = "gnutella",
    feature = "nntp"
))]
pub mod p2p_support;

#[cfg(feature = "dc_peer")]
pub mod dc_peer;

#[cfg(feature = "adc")]
pub mod adc;

#[cfg(feature = "adc_peer")]
pub mod adc_peer;

#[cfg(feature = "soulseek")]
pub mod soulseek;

#[cfg(feature = "soulseek_peer")]
pub mod soulseek_peer;

#[cfg(feature = "gnutella")]
pub mod gnutella;
