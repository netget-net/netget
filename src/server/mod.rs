//! Server module
//!
//! Handles network servers, connection management, and protocol implementations

pub mod accept_bounded;
pub mod command_batch;
pub mod connection;
pub mod peer_support;
// server_trait requires async-trait, so only compile when features that provide it are enabled
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
pub mod http_common;

// TLS certificate management for DoT, DoH, HTTP, HTTP/2, QUIC, SMTP, POP3 and TLS protocols.
// Keep this list in sync with the protocols that actually call into it: POP3's TLS session
// path is fully implemented and its spawn already takes the config, but it was missing here,
// so POP3S could not be built at all.
pub mod tls_cert_manager;

// A disk the model describes (size, extents, failing regions), served by the block servers
// (NBD, iSCSI) from the description, and the SCSI command set the USB mass-storage device and
// the iSCSI target and initiator share.
#[cfg(not(target_arch = "wasm32"))]
pub mod described_disk;
#[cfg(not(target_arch = "wasm32"))]
pub mod scsi_common;

pub mod tcp;
pub use tcp::actions::TcpProtocol;
pub use tcp::TcpServer;

#[cfg(unix)]
pub mod socket_file;
#[cfg(unix)]
pub use socket_file::actions::SocketFileProtocol;
#[cfg(unix)]
pub use socket_file::SocketFileServer;

#[cfg(unix)]
pub mod named_pipe;
#[cfg(unix)]
pub use named_pipe::actions::NamedPipeProtocol;
#[cfg(unix)]
pub use named_pipe::NamedPipeServer;

#[cfg(unix)]
pub mod pty;
#[cfg(unix)]
pub use pty::actions::PtyProtocol;
#[cfg(unix)]
pub use pty::PtyServer;

#[cfg(unix)]
pub mod stdio;
#[cfg(unix)]
pub use stdio::actions::StdioProtocol;
#[cfg(unix)]
pub use stdio::StdioServer;

pub mod http;
pub use http::actions::HttpProtocol;
pub use http::HttpServer;

pub mod http2;
pub use http2::actions::Http2Protocol;
pub use http2::H2Server;

pub mod pypi;
pub use pypi::actions::PypiProtocol;
pub use pypi::PypiServer;

pub mod maven;
pub use maven::actions::MavenProtocol;
pub use maven::MavenServer;

#[cfg(all(unix, feature = "libpcap"))]
pub mod datalink;
#[cfg(all(unix, feature = "libpcap"))]
pub use datalink::actions::DataLinkProtocol;
#[cfg(all(unix, feature = "libpcap"))]
pub use datalink::DataLinkServer;

#[cfg(all(unix, feature = "libpcap"))]
pub mod arp;
#[cfg(all(unix, feature = "libpcap"))]
pub use arp::actions::ArpProtocol;
#[cfg(all(unix, feature = "libpcap"))]
pub use arp::ArpServer;

#[cfg(unix)]
pub mod icmp;
#[cfg(unix)]
pub use icmp::actions::IcmpProtocol;
#[cfg(unix)]
pub use icmp::IcmpServer;

pub mod dc;
pub use dc::actions::DcProtocol;
pub use dc::DcServer;

pub mod udp;
pub use udp::actions::UdpProtocol;
pub use udp::{SharedUdpSocket, UdpPeerMap, UdpServer};

#[cfg(not(target_arch = "wasm32"))]
pub mod dns;
#[cfg(not(target_arch = "wasm32"))]
pub use dns::actions::DnsProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use dns::DnsServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod dot;
#[cfg(not(target_arch = "wasm32"))]
pub use dot::actions::DotProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use dot::DotServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod doh;
#[cfg(not(target_arch = "wasm32"))]
pub use doh::actions::DohProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use doh::DohServer;

pub mod dhcp;
pub use dhcp::actions::DhcpProtocol;
pub use dhcp::DhcpServer;

pub mod bootp;
pub use bootp::actions::BootpProtocol;
pub use bootp::BootpServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod ntp;
#[cfg(not(target_arch = "wasm32"))]
pub use ntp::actions::NtpProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use ntp::NtpServer;

pub mod tftp;
pub use tftp::actions::TftpProtocol;
pub use tftp::TftpServer;

pub mod whois;
pub use whois::actions::WhoisProtocol;
pub use whois::WhoisServer;
#[cfg(unix)]
pub mod ndp;
#[cfg(unix)]
pub use ndp::actions::NdpProtocol;
#[cfg(unix)]
pub use ndp::NdpServer;
pub mod dhcpv6;
pub use dhcpv6::actions::Dhcpv6Protocol;
pub use dhcpv6::Dhcpv6Server;
#[cfg(unix)]
pub mod tuntap;
#[cfg(unix)]
pub use tuntap::actions::TunTapProtocol;
#[cfg(unix)]
pub use tuntap::TunTapServer;
#[cfg(unix)]
pub mod rawip;
#[cfg(unix)]
pub use rawip::actions::RawIpProtocol;
#[cfg(unix)]
pub use rawip::RawIpServer;
pub mod gtp;
pub use gtp::actions::GtpProtocol;
pub use gtp::GtpServer;
#[cfg(unix)]
pub mod m3ua;
#[cfg(unix)]
pub use m3ua::actions::M3uaProtocol;
#[cfg(unix)]
pub use m3ua::M3uaServer;
#[cfg(unix)]
pub mod can;
#[cfg(unix)]
pub mod ngap;
#[cfg(unix)]
pub use can::actions::CanProtocol;
#[cfg(unix)]
pub use can::CanServer;
#[cfg(all(unix, feature = "libpcap"))]
pub mod lldp;
#[cfg(all(unix, feature = "libpcap"))]
pub use lldp::actions::LldpProtocol;
#[cfg(all(unix, feature = "libpcap"))]
pub use lldp::LldpServer;
#[cfg(all(unix, feature = "libpcap"))]
pub mod cdp;
#[cfg(all(unix, feature = "libpcap"))]
pub use cdp::actions::CdpProtocol;
#[cfg(all(unix, feature = "libpcap"))]
pub use cdp::CdpServer;
#[cfg(all(unix, feature = "libpcap"))]
pub mod stp;
#[cfg(all(unix, feature = "libpcap"))]
pub use stp::actions::StpProtocol;
#[cfg(all(unix, feature = "libpcap"))]
pub use stp::StpServer;
#[cfg(unix)]
pub mod vrrp;
#[cfg(unix)]
pub use vrrp::actions::VrrpProtocol;
#[cfg(unix)]
pub use vrrp::VrrpServer;
pub mod hsrp;
pub use hsrp::actions::HsrpProtocol;
pub use hsrp::HsrpServer;
#[cfg(all(unix, feature = "libpcap"))]
pub mod eapol;
#[cfg(all(unix, feature = "libpcap"))]
pub use eapol::actions::EapolProtocol;
#[cfg(all(unix, feature = "libpcap"))]
pub use eapol::EapolServer;
pub mod wol;
pub use wol::actions::WolProtocol;
pub use wol::WolServer;
pub mod nats;
pub use nats::actions::NatsProtocol;
pub use nats::NatsServer;
pub mod stomp;
pub use stomp::actions::StompProtocol;
pub use stomp::StompServer;
pub mod ident;
pub use ident::actions::IdentProtocol;
pub use ident::IdentServer;
#[cfg(not(target_arch = "wasm32"))]
pub mod gemini;
#[cfg(not(target_arch = "wasm32"))]
pub use gemini::actions::GeminiProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use gemini::GeminiServer;
#[cfg(not(target_arch = "wasm32"))]
pub mod dict;
#[cfg(not(target_arch = "wasm32"))]
pub use dict::actions::DictProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use dict::DictServer;
#[cfg(not(target_arch = "wasm32"))]
pub mod beanstalkd;
#[cfg(not(target_arch = "wasm32"))]
pub use beanstalkd::actions::BeanstalkdProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use beanstalkd::BeanstalkdServer;
#[cfg(not(target_arch = "wasm32"))]
pub mod zabbix;
#[cfg(not(target_arch = "wasm32"))]
pub use zabbix::actions::ZabbixProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use zabbix::ZabbixServer;
#[cfg(not(target_arch = "wasm32"))]
pub mod gearman;
#[cfg(not(target_arch = "wasm32"))]
pub use gearman::actions::GearmanProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use gearman::GearmanServer;
#[cfg(not(target_arch = "wasm32"))]
pub mod nsq;
#[cfg(not(target_arch = "wasm32"))]
pub use nsq::actions::NsqProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use nsq::NsqServer;
pub mod gopher;
pub use gopher::actions::GopherProtocol;
pub use gopher::GopherServer;
pub mod finger;
pub use finger::actions::FingerProtocol;
pub use finger::FingerServer;
pub mod ssdp;
pub use ssdp::actions::SsdpProtocol;
pub use ssdp::SsdpServer;
#[cfg(not(target_arch = "wasm32"))]
pub mod llmnr;
#[cfg(not(target_arch = "wasm32"))]
pub use llmnr::actions::LlmnrProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use llmnr::LlmnrServer;
pub mod netbios_ns;
pub use netbios_ns::actions::NetbiosNsProtocol;
pub use netbios_ns::NetbiosNsServer;

pub mod snmp;
pub use snmp::actions::SnmpProtocol;
pub use snmp::SnmpServer;

#[cfg(unix)]
pub mod igmp;
#[cfg(unix)]
pub use igmp::actions::IgmpProtocol;
#[cfg(unix)]
pub use igmp::IgmpServer;

pub mod syslog;
pub use syslog::actions::SyslogProtocol;
pub use syslog::SyslogServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod ssh;
#[cfg(not(target_arch = "wasm32"))]
pub use ssh::actions::SshProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use ssh::sftp_handler::LlmSftpHandler;
#[cfg(not(target_arch = "wasm32"))]
pub use ssh::SshServer;

#[cfg(unix)]
pub mod ssh_agent;
#[cfg(unix)]
pub use ssh_agent::actions::SshAgentProtocol;
#[cfg(unix)]
pub use ssh_agent::SshAgentServer;

pub mod svn;
pub use svn::actions::SvnProtocol;
pub use svn::SvnServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod irc;
#[cfg(not(target_arch = "wasm32"))]
pub use irc::actions::IrcProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use irc::IrcServer;

#[cfg(unix)]
pub mod xmpp;
#[cfg(unix)]
pub use xmpp::actions::XmppProtocol;
#[cfg(unix)]
pub use xmpp::XmppServer;

pub mod telnet;
pub use telnet::actions::TelnetProtocol;
pub use telnet::TelnetServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod smtp;
#[cfg(not(target_arch = "wasm32"))]
pub use smtp::actions::SmtpProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use smtp::SmtpServer;

pub mod ftp;
pub use ftp::actions::FtpProtocol;
pub use ftp::FtpServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod mdns;
#[cfg(not(target_arch = "wasm32"))]
pub use mdns::actions::MdnsProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use mdns::MdnsServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod mysql;
#[cfg(not(target_arch = "wasm32"))]
pub use mysql::actions::MysqlProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use mysql::MysqlServer;

pub mod snowflake;
pub use snowflake::actions::SnowflakeProtocol;
pub use snowflake::SnowflakeServer;

pub mod db2;
pub use db2::actions::Db2Protocol;
pub use db2::Db2Server;

pub mod mongodb;
pub use mongodb::actions::MongodbProtocol;
pub use mongodb::MongodbServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod mssql;
#[cfg(not(target_arch = "wasm32"))]
pub use mssql::actions::MssqlProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use mssql::MssqlServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod ipp;
#[cfg(not(target_arch = "wasm32"))]
pub use ipp::actions::IppProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use ipp::IppServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod postgresql;
#[cfg(not(target_arch = "wasm32"))]
pub use postgresql::actions::PostgresqlProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use postgresql::PostgresqlServer;

pub mod memcached;
pub use memcached::actions::MemcachedProtocol;
pub use memcached::MemcachedServer;

pub mod radius;
pub use radius::actions::RadiusProtocol;
pub use radius::RadiusServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod redis;
#[cfg(not(target_arch = "wasm32"))]
pub use redis::actions::RedisProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use redis::RedisServer;

pub mod rss;
pub use rss::actions::RssProtocol;
pub use rss::RssServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod cassandra;
#[cfg(not(target_arch = "wasm32"))]
pub use cassandra::actions::CassandraProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use cassandra::CassandraServer;

#[cfg(unix)]
pub mod proxy;
#[cfg(unix)]
pub use proxy::actions::ProxyProtocol;
#[cfg(unix)]
pub use proxy::filter::{
    CertificateMode, FilterMode, FullRequestInfo, FullResponseInfo, HttpsConnectionAction,
    HttpsConnectionInfo, ProxyFilterConfig, RequestAction, RequestFilter, ResponseAction,
    ResponseFilter,
};
#[cfg(unix)]
pub use proxy::ProxyServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod socks5;
#[cfg(not(target_arch = "wasm32"))]
pub use socks5::actions::Socks5Protocol;
#[cfg(not(target_arch = "wasm32"))]
pub use socks5::filter::{FilterMode as Socks5FilterMode, Socks5FilterConfig};
#[cfg(not(target_arch = "wasm32"))]
pub use socks5::Socks5Server;

#[cfg(not(target_arch = "wasm32"))]
pub mod webdav;
#[cfg(not(target_arch = "wasm32"))]
pub use webdav::actions::WebDavProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use webdav::WebDavServer;

#[cfg(unix)]
pub mod nfs;
#[cfg(unix)]
pub use nfs::actions::NfsProtocol;
#[cfg(unix)]
pub use nfs::NfsServer;

#[cfg(unix)]
pub mod nfc;
#[cfg(unix)]
pub use nfc::actions::NfcServerProtocol;
#[cfg(unix)]
pub use nfc::NfcServer;

pub mod smb;
pub use smb::actions::SmbProtocol;
pub use smb::SmbServer;

#[cfg(unix)]
pub mod stun;
#[cfg(unix)]
pub use stun::actions::StunProtocol;
#[cfg(unix)]
pub use stun::StunServer;

#[cfg(unix)]
pub mod turn;
#[cfg(unix)]
pub use turn::actions::TurnProtocol;
#[cfg(unix)]
pub use turn::TurnServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod webrtc;
#[cfg(not(target_arch = "wasm32"))]
pub use webrtc::actions::WebRtcProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use webrtc::{WebRtcServer, WebRtcServerData};

#[cfg(not(target_arch = "wasm32"))]
pub mod websocket;
#[cfg(not(target_arch = "wasm32"))]
pub use websocket::actions::WebSocketProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use websocket::WebSocketServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod webrtc_signaling;
#[cfg(not(target_arch = "wasm32"))]
pub use webrtc_signaling::actions::WebRtcSignalingProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use webrtc_signaling::{WebRtcSignalingServer, WebRtcSignalingServerData};

pub mod sip;
pub use sip::actions::SipProtocol;
pub use sip::SipServer;

// H.323 gatekeeper (H.225.0 RAS) and call-signalling endpoint (H.225.0 / Q.931)
#[cfg(not(target_arch = "wasm32"))]
pub mod h323;

pub mod rtp;
pub use rtp::actions::RtpProtocol;
pub use rtp::RtpServer;

pub mod rtsp;
pub use rtsp::actions::RtspProtocol;
pub use rtsp::RtspServer;

pub mod hls;
pub use hls::actions::HlsProtocol;
pub use hls::HlsServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod ldap;
#[cfg(not(target_arch = "wasm32"))]
pub use ldap::actions::LdapProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use ldap::LdapServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod imap;
#[cfg(not(target_arch = "wasm32"))]
pub use imap::actions::ImapProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use imap::ImapServer;

pub mod pop3;
pub use pop3::actions::Pop3Protocol;
pub use pop3::Pop3Server;

pub mod nntp;
pub use nntp::actions::NntpProtocol;
pub use nntp::NntpServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod managesieve;
#[cfg(not(target_arch = "wasm32"))]
pub mod mqtt;
#[cfg(not(target_arch = "wasm32"))]
pub mod mqtt_sn;
#[cfg(not(target_arch = "wasm32"))]
pub mod nbd;
#[cfg(not(target_arch = "wasm32"))]
pub use mqtt::actions::MqttProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use mqtt::MqttServer;

pub mod modbus;
pub use modbus::actions::ModbusProtocol;
pub use modbus::ModbusServer;

pub mod coap;
pub use coap::actions::CoapProtocol;
pub use coap::CoapServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod amqp;
#[cfg(not(target_arch = "wasm32"))]
pub use amqp::actions::AmqpProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use amqp::AmqpServer;

pub mod elasticsearch;
pub use elasticsearch::actions::ElasticsearchProtocol;
pub use elasticsearch::ElasticsearchServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod couchdb;
#[cfg(not(target_arch = "wasm32"))]
pub use couchdb::actions::CouchDbProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use couchdb::CouchDbServer;

pub mod yarn;
pub use yarn::actions::YarnProtocol;
pub use yarn::YarnServer;

pub mod spark;
pub use spark::actions::SparkProtocol;
pub use spark::SparkServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod dynamo;
#[cfg(not(target_arch = "wasm32"))]
pub use dynamo::actions::DynamoProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use dynamo::DynamoServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod s3;
#[cfg(not(target_arch = "wasm32"))]
pub use s3::actions::S3Protocol;
#[cfg(not(target_arch = "wasm32"))]
pub use s3::S3Server;

#[cfg(not(target_arch = "wasm32"))]
pub mod sqs;
#[cfg(not(target_arch = "wasm32"))]
pub use sqs::actions::SqsProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use sqs::SqsServer;

pub mod npm;
pub use npm::actions::NpmProtocol;
pub use npm::NpmServer;

pub mod oci_registry;
pub use oci_registry::actions::OciRegistryProtocol;
pub use oci_registry::OciRegistryServer;

// Kubernetes API server. Gated on `kubernetes-server`, NOT on the `kubernetes` client
// feature: the server is JSON-only and pulls in neither kube nor k8s-openapi.
pub mod kubernetes;
pub use kubernetes::actions::KubernetesProtocol;
pub use kubernetes::KubernetesServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod prometheus;
#[cfg(not(target_arch = "wasm32"))]
pub use prometheus::actions::PrometheusProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use prometheus::PrometheusServer;
#[cfg(not(target_arch = "wasm32"))]
pub mod otlp;
#[cfg(not(target_arch = "wasm32"))]
pub use otlp::actions::OtlpProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use otlp::OtlpServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod docker;
#[cfg(not(target_arch = "wasm32"))]
pub use docker::actions::DockerProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use docker::DockerServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod vault;
#[cfg(not(target_arch = "wasm32"))]
pub use vault::actions::VaultProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use vault::VaultServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod bolt;
#[cfg(not(target_arch = "wasm32"))]
pub use bolt::actions::BoltProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use bolt::BoltServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod openai;
#[cfg(not(target_arch = "wasm32"))]
pub use openai::actions::OpenAiProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use openai::OpenAiServer;

pub mod ollama;
pub use ollama::actions::OllamaProtocol;
pub use ollama::OllamaServer;

pub mod oauth2;
pub use oauth2::actions::OAuth2Protocol;
pub use oauth2::OAuth2Server;

pub mod jsonrpc;
pub use jsonrpc::actions::JsonRpcProtocol;
pub use jsonrpc::JsonRpcServer;

#[cfg(unix)]
pub mod wireguard;
#[cfg(unix)]
pub use wireguard::actions::WireguardProtocol;
#[cfg(unix)]
pub use wireguard::WireguardServer;

#[cfg(unix)]
pub mod openvpn;
#[cfg(unix)]
pub use openvpn::actions::OpenvpnProtocol;
#[cfg(unix)]
pub use openvpn::OpenvpnServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod ipsec;
#[cfg(not(target_arch = "wasm32"))]
pub use ipsec::actions::IpsecProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use ipsec::IpsecServer;

pub mod bgp;
pub use bgp::actions::BgpProtocol;
pub use bgp::BgpServer;

#[cfg(unix)]
pub mod ospf;
#[cfg(unix)]
pub use ospf::actions::OspfProtocol;
#[cfg(unix)]
pub use ospf::OspfServer;

#[cfg(all(unix, feature = "libpcap"))]
pub mod isis;
#[cfg(all(unix, feature = "libpcap"))]
pub use isis::actions::IsisProtocol;
#[cfg(all(unix, feature = "libpcap"))]
pub use isis::IsisServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod rip;
#[cfg(not(target_arch = "wasm32"))]
pub use rip::actions::RipProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use rip::RipServer;

pub mod bitcoin;
#[cfg(not(target_arch = "wasm32"))]
pub mod devp2p;
pub use bitcoin::actions::BitcoinProtocol;
pub use bitcoin::BitcoinServer;
#[cfg(not(target_arch = "wasm32"))]
pub mod nostr;
#[cfg(not(target_arch = "wasm32"))]
pub use nostr::actions::NostrProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use nostr::NostrServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod mcp;
#[cfg(not(target_arch = "wasm32"))]
pub use mcp::actions::McpProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use mcp::McpServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod connect_rpc;
#[cfg(not(target_arch = "wasm32"))]
pub mod gnmi;
#[cfg(not(target_arch = "wasm32"))]
pub mod grpc;
#[cfg(not(target_arch = "wasm32"))]
pub mod grpc_web;
#[cfg(not(target_arch = "wasm32"))]
pub use grpc::actions::GrpcProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use grpc::GrpcServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod etcd;
#[cfg(not(target_arch = "wasm32"))]
pub use etcd::actions::EtcdProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use etcd::EtcdServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod xmlrpc;
#[cfg(not(target_arch = "wasm32"))]
pub use xmlrpc::actions::XmlRpcProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use xmlrpc::XmlRpcServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod zookeeper;
#[cfg(not(target_arch = "wasm32"))]
pub use zookeeper::actions::ZookeeperProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use zookeeper::ZookeeperServer;

#[cfg(unix)]
pub mod tor_relay;
#[cfg(unix)]
pub use tor_relay::actions::TorRelayProtocol;
#[cfg(unix)]
pub use tor_relay::TorRelayServer;

pub mod vnc;
pub use vnc::actions::VncProtocol;
pub use vnc::VncServer;

pub mod reverse_shell;
pub use reverse_shell::actions::ReverseShellProtocol;
pub use reverse_shell::ReverseShellServer;

pub mod rdp;
#[cfg(not(target_arch = "wasm32"))]
pub mod spice;
pub use rdp::actions::RdpProtocol;
pub use rdp::RdpServer;

pub mod openapi;
pub use openapi::actions::OpenApiProtocol;
pub use openapi::OpenApiServer;

pub mod openid;
pub use openid::actions::OpenIdProtocol;
pub use openid::OpenIdServer;

#[cfg(not(target_arch = "wasm32"))]
pub mod git;
#[cfg(not(target_arch = "wasm32"))]
pub use git::actions::GitProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use git::GitServer;

pub mod mercurial;
pub use mercurial::actions::MercurialProtocol;
pub use mercurial::MercurialServer;

pub mod kafka;
pub use kafka::actions::KafkaProtocol;
pub use kafka::KafkaServer;

// Raw QUIC stream server (RFC 9000/9001). Deliberately not HTTP/3 - the HTTP/3
// *client* lives at src/client/http3/ behind the separate `http3` feature.
#[cfg(not(target_arch = "wasm32"))]
pub mod quic;
#[cfg(not(target_arch = "wasm32"))]
pub use quic::actions::QuicProtocol;
#[cfg(not(target_arch = "wasm32"))]
pub use quic::QuicServer;

pub mod torrent_tracker;
pub use torrent_tracker::actions::TorrentTrackerProtocol;
pub use torrent_tracker::TorrentTrackerServer;

pub mod torrent_dht;
pub use torrent_dht::actions::TorrentDhtProtocol;
pub use torrent_dht::TorrentDhtServer;

pub mod torrent_peer;
pub use torrent_peer::actions::TorrentPeerProtocol;
pub use torrent_peer::TorrentPeerServer;

pub mod tls;
pub use tls::actions::TlsProtocol;
pub use tls::TlsServer;

pub mod saml_idp;
pub use saml_idp::actions::SamlIdpProtocol;
pub use saml_idp::SamlIdpServer;

pub mod saml_sp;
pub use saml_sp::actions::SamlSpProtocol;
pub use saml_sp::SamlSpServer;

#[cfg(all(unix, feature = "libusb"))]
pub mod usb;

#[cfg(all(unix, feature = "libusb"))]
pub use usb::keyboard::UsbKeyboardServer;
#[cfg(all(unix, feature = "libusb"))]
pub use usb::UsbKeyboardProtocol;

#[cfg(all(unix, feature = "libusb"))]
pub use usb::mouse::UsbMouseServer;
#[cfg(all(unix, feature = "libusb"))]
pub use usb::UsbMouseProtocol;

#[cfg(all(unix, feature = "libusb"))]
pub use usb::serial::UsbSerialServer;
#[cfg(all(unix, feature = "libusb"))]
pub use usb::UsbSerialProtocol;

#[cfg(all(unix, feature = "libusb"))]
pub use usb::msc::UsbMscServer;
#[cfg(all(unix, feature = "libusb"))]
pub use usb::UsbMscProtocol;

#[cfg(all(unix, feature = "libusb"))]
pub use usb::fido2::UsbFido2Server;
#[cfg(all(unix, feature = "libusb"))]
pub use usb::UsbFido2Protocol;

#[cfg(all(unix, feature = "libusb"))]
pub use usb::smartcard::UsbSmartCardServer;
#[cfg(all(unix, feature = "libusb"))]
pub use usb::UsbSmartCardProtocol;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble::actions::BluetoothBleProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble::BluetoothBle;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_keyboard;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_keyboard::actions::BluetoothBleKeyboardProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_keyboard::BluetoothBleKeyboard;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_mouse;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_mouse::actions::BluetoothBleMouseProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_mouse::BluetoothBleMouse;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_beacon;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_beacon::actions::BluetoothBleBeaconProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_beacon::BluetoothBleBeacon;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_remote;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_remote::actions::BluetoothBleRemoteProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_remote::BluetoothBleRemote;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_battery;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_battery::actions::BluetoothBleBatteryProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_battery::BluetoothBleBattery;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_heart_rate;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_heart_rate::actions::BluetoothBleHeartRateProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_heart_rate::BluetoothBleHeartRate;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_thermometer;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_thermometer::actions::BluetoothBleThermometerProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_thermometer::BluetoothBleThermometer;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_environmental;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_environmental::actions::BluetoothBleEnvironmentalProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_environmental::BluetoothBleEnvironmental;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_proximity;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_proximity::actions::BluetoothBleProximityProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_proximity::BluetoothBleProximity;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_gamepad;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_gamepad::actions::BluetoothBleGamepadProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_gamepad::BluetoothBleGamepad;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_presenter;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_presenter::actions::BluetoothBlePresenterProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_presenter::BluetoothBlePresenter;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_file_transfer;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_file_transfer::actions::BluetoothBleFileTransferProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_file_transfer::BluetoothBleFileTransfer;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_data_stream;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_data_stream::actions::BluetoothBleDataStreamProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_data_stream::BluetoothBleDataStream;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_cycling;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_cycling::actions::BluetoothBleCyclingProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_cycling::BluetoothBleCycling;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_running;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_running::actions::BluetoothBleRunningProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_running::BluetoothBleRunning;

#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_weight_scale;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_weight_scale::actions::BluetoothBleWeightScaleProtocol;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth_ble_weight_scale::BluetoothBleWeightScale;

pub use connection::{Connection, ConnectionId};

#[cfg(not(target_arch = "wasm32"))]
pub mod doq;
#[cfg(not(target_arch = "wasm32"))]
pub mod nut;
#[cfg(not(target_arch = "wasm32"))]
pub mod statsd;

#[cfg(not(target_arch = "wasm32"))]
pub mod graphite;

#[cfg(not(target_arch = "wasm32"))]
pub mod gelf;

#[cfg(not(target_arch = "wasm32"))]
pub mod http3;
#[cfg(not(target_arch = "wasm32"))]
pub use http3::actions::Http3Protocol;
#[cfg(not(target_arch = "wasm32"))]
pub mod fluent_forward;

#[cfg(not(target_arch = "wasm32"))]
pub mod influxdb;

#[cfg(not(target_arch = "wasm32"))]
pub mod ipfix;

#[cfg(not(target_arch = "wasm32"))]
pub mod sflow;

#[cfg(not(target_arch = "wasm32"))]
pub mod loki;

#[cfg(not(target_arch = "wasm32"))]
pub mod prometheus_remote_write;

#[cfg(not(target_arch = "wasm32"))]
pub mod netflow_v9;

#[cfg(not(target_arch = "wasm32"))]
pub mod a2a;
#[cfg(not(target_arch = "wasm32"))]
pub mod acme;
#[cfg(not(target_arch = "wasm32"))]
pub mod afp;
#[cfg(not(target_arch = "wasm32"))]
pub mod amqp1;
#[cfg(not(target_arch = "wasm32"))]
pub mod bmp;
#[cfg(not(target_arch = "wasm32"))]
pub mod caldav;
#[cfg(not(target_arch = "wasm32"))]
pub mod carddav;
#[cfg(not(target_arch = "wasm32"))]
pub mod dav_common;
#[cfg(not(target_arch = "wasm32"))]
pub mod dicom;
#[cfg(not(target_arch = "wasm32"))]
pub mod fastcgi;
#[cfg(not(target_arch = "wasm32"))]
pub mod fix;
#[cfg(not(target_arch = "wasm32"))]
pub mod graphql;
#[cfg(not(target_arch = "wasm32"))]
pub mod hl7;
#[cfg(not(target_arch = "wasm32"))]
pub mod icap;
#[cfg(not(target_arch = "wasm32"))]
pub mod netconf;
#[cfg(not(target_arch = "wasm32"))]
pub mod ocpp;
#[cfg(not(target_arch = "wasm32"))]
pub mod rdap;
#[cfg(not(target_arch = "wasm32"))]
pub mod redfish;
#[cfg(not(target_arch = "wasm32"))]
pub mod rpki_rtr;
#[cfg(not(target_arch = "wasm32"))]
pub mod rtmp;
#[cfg(not(target_arch = "wasm32"))]
pub mod scim;
#[cfg(not(target_arch = "wasm32"))]
pub mod socketio;
#[cfg(not(target_arch = "wasm32"))]
pub mod srt;
#[cfg(not(target_arch = "wasm32"))]
pub mod tacacs;
#[cfg(not(target_arch = "wasm32"))]
pub mod thrift;
#[cfg(not(target_arch = "wasm32"))]
pub mod wamp;

#[cfg(not(target_arch = "wasm32"))]
pub mod a2s;
#[cfg(not(target_arch = "wasm32"))]
pub mod activitypub;
#[cfg(not(target_arch = "wasm32"))]
pub mod anthropic;
#[cfg(not(target_arch = "wasm32"))]
pub mod bfd;
#[cfg(not(target_arch = "wasm32"))]
pub mod capnp_rpc;
#[cfg(not(target_arch = "wasm32"))]
pub mod clickhouse;
#[cfg(not(target_arch = "wasm32"))]
pub mod consul;
#[cfg(not(target_arch = "wasm32"))]
pub mod dbus;
#[cfg(not(target_arch = "wasm32"))]
pub mod diameter;
#[cfg(not(target_arch = "wasm32"))]
pub mod epp;
#[cfg(not(target_arch = "wasm32"))]
pub mod ethercat;
#[cfg(not(target_arch = "wasm32"))]
pub mod guacamole;
#[cfg(not(target_arch = "wasm32"))]
pub mod inetd;
#[cfg(not(target_arch = "wasm32"))]
pub mod jmap;
#[cfg(not(target_arch = "wasm32"))]
pub mod kerberos;
#[cfg(not(target_arch = "wasm32"))]
pub mod knx;
#[cfg(not(target_arch = "wasm32"))]
pub mod libp2p;
#[cfg(not(target_arch = "wasm32"))]
pub mod lmtp;
#[cfg(not(target_arch = "wasm32"))]
pub mod lorawan;
#[cfg(not(target_arch = "wasm32"))]
pub mod lpd;
#[cfg(not(target_arch = "wasm32"))]
pub mod lwm2m;
#[cfg(not(target_arch = "wasm32"))]
pub mod matrix;
#[cfg(not(target_arch = "wasm32"))]
pub mod mbus;
#[cfg(not(target_arch = "wasm32"))]
pub mod milter;
#[cfg(not(target_arch = "wasm32"))]
pub mod minecraft;
#[cfg(not(target_arch = "wasm32"))]
pub mod msgpack_rpc;
#[cfg(not(target_arch = "wasm32"))]
pub mod ninep;
#[cfg(not(target_arch = "wasm32"))]
pub mod nis;
#[cfg(not(target_arch = "wasm32"))]
pub mod onvif;
#[cfg(not(target_arch = "wasm32"))]
pub mod openflow;
#[cfg(not(target_arch = "wasm32"))]
pub mod pfcp;
#[cfg(not(target_arch = "wasm32"))]
pub mod profinet;
#[cfg(not(target_arch = "wasm32"))]
pub mod pulsar;
#[cfg(not(target_arch = "wasm32"))]
pub mod radsec;
#[cfg(not(target_arch = "wasm32"))]
pub mod rcon;
#[cfg(not(target_arch = "wasm32"))]
pub mod restconf;
#[cfg(not(target_arch = "wasm32"))]
pub mod rsh;
#[cfg(not(target_arch = "wasm32"))]
pub mod rsync;
#[cfg(not(target_arch = "wasm32"))]
pub mod smpp;
#[cfg(not(target_arch = "wasm32"))]
pub mod sse;
#[cfg(not(target_arch = "wasm32"))]
pub mod stratum;
#[cfg(not(target_arch = "wasm32"))]
pub mod stratum_v2;
#[cfg(not(target_arch = "wasm32"))]
pub mod sunrpc;
#[cfg(not(target_arch = "wasm32"))]
pub mod tr069;
#[cfg(not(target_arch = "wasm32"))]
pub mod vxlan;
#[cfg(not(target_arch = "wasm32"))]
pub mod webtransport;
#[cfg(not(target_arch = "wasm32"))]
pub mod wsdiscovery;
#[cfg(not(target_arch = "wasm32"))]
pub mod zenoh;
#[cfg(not(target_arch = "wasm32"))]
pub mod zeromq;
#[cfg(not(target_arch = "wasm32"))]
pub mod zipkin;

#[cfg(not(target_arch = "wasm32"))]
pub mod s7comm;

#[cfg(not(target_arch = "wasm32"))]
pub mod ics_support;

#[cfg(not(target_arch = "wasm32"))]
pub mod ethernet_ip;

#[cfg(not(target_arch = "wasm32"))]
pub mod dnp3;

#[cfg(not(target_arch = "wasm32"))]
pub mod iec104;

#[cfg(not(target_arch = "wasm32"))]
pub mod bacnet;

#[cfg(not(target_arch = "wasm32"))]
pub mod opcua;

pub mod p2p_support;

#[cfg(not(target_arch = "wasm32"))]
pub mod dc_peer;

#[cfg(not(target_arch = "wasm32"))]
pub mod adc;

#[cfg(not(target_arch = "wasm32"))]
pub mod adc_peer;

#[cfg(not(target_arch = "wasm32"))]
pub mod soulseek;

#[cfg(not(target_arch = "wasm32"))]
pub mod soulseek_peer;

#[cfg(not(target_arch = "wasm32"))]
pub mod gnutella;
