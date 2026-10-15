//! Client protocol implementations
//!
//! This module contains all client protocol implementations.
//! Each protocol provides LLM-controlled client behavior for connecting
//! to remote servers and exchanging data.

// Shared plumbing: budget-checked LLM entry point used by every client protocol.
// See the module docs for why clients need a hard call ceiling.
/// Credential policy the AWS-SDK clients share.
pub mod aws_support;
pub mod command_support;
/// The HTTP round trip the HTTP-family clients share: reqwest natively, hyper's HTTP/1.1
/// client over the virtual loopback in the browser build.
pub mod http_fetch;
pub mod llm_budget;
/// The directory a media client may read local files from (`srt`, `rtmp`).
pub mod media_root;
pub mod response_reader;
pub mod wire_values;

// arp client
#[cfg(all(unix, feature = "libpcap"))]
pub mod arp;
#[cfg(all(unix, feature = "libpcap"))]
pub use arp::actions::ArpClientProtocol;

// bgp client
pub mod bgp;
pub use bgp::actions::BgpClientProtocol;

// bitcoin client
pub mod bitcoin;
pub use bitcoin::actions::BitcoinClientProtocol;
// Ethereum devp2p dialler
#[cfg(not(target_arch = "wasm32"))]
pub mod devp2p;

// bluetooth-ble client
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth;
#[cfg(all(unix, feature = "bluetooth"))]
pub use bluetooth::actions::BluetoothClientProtocol;

// bootp client
pub mod bootp;
pub use bootp::actions::BootpClientProtocol;

// cassandra client
#[cfg(not(target_arch = "wasm32"))]
pub mod cassandra;
#[cfg(not(target_arch = "wasm32"))]
pub use cassandra::actions::CassandraClientProtocol;

// datalink client
#[cfg(all(unix, feature = "libpcap"))]
pub mod datalink;
#[cfg(all(unix, feature = "libpcap"))]
pub use datalink::actions::DataLinkClientProtocol;

// dc client
pub mod dc;
pub use dc::actions::DcClientProtocol;

// dhcp client
pub mod dhcp;
pub use dhcp::actions::DhcpClientProtocol;

// dns client
#[cfg(not(target_arch = "wasm32"))]
pub mod dns;
#[cfg(not(target_arch = "wasm32"))]
pub use dns::actions::DnsClientProtocol;

// doh client
#[cfg(not(target_arch = "wasm32"))]
pub mod doh;
#[cfg(not(target_arch = "wasm32"))]
pub use doh::actions::DohClientProtocol;

// dot client
#[cfg(not(target_arch = "wasm32"))]
pub mod dot;
#[cfg(not(target_arch = "wasm32"))]
pub use dot::actions::DotClientProtocol;

// dynamodb client
#[cfg(unix)]
pub mod dynamodb;
#[cfg(unix)]
pub use dynamodb::actions::DynamoDbClientProtocol;

// elasticsearch client
pub mod elasticsearch;
pub use elasticsearch::actions::ElasticsearchClientProtocol;

// etcd client
#[cfg(not(target_arch = "wasm32"))]
pub mod etcd;
#[cfg(not(target_arch = "wasm32"))]
pub use etcd::actions::EtcdClientProtocol;

// zookeeper client
#[cfg(not(target_arch = "wasm32"))]
pub mod zookeeper;
#[cfg(not(target_arch = "wasm32"))]
pub use zookeeper::actions::ZookeeperClientProtocol;

// git client
#[cfg(not(target_arch = "wasm32"))]
pub mod git;
#[cfg(not(target_arch = "wasm32"))]
pub use git::actions::GitClientProtocol;

// grpc client
#[cfg(not(target_arch = "wasm32"))]
pub mod connect_rpc;
#[cfg(not(target_arch = "wasm32"))]
pub mod gnmi;
#[cfg(not(target_arch = "wasm32"))]
pub mod grpc;
#[cfg(not(target_arch = "wasm32"))]
pub mod grpc_web;
#[cfg(not(target_arch = "wasm32"))]
pub use grpc::actions::GrpcClientProtocol;

// The HTTP-family clients run in the browser build too: there they issue their requests
// through `http_fetch` (hyper's client over the virtual loopback) instead of reqwest; see
// web/README.md.
pub mod http;
pub use http::actions::HttpClientProtocol;

// http2 client
pub mod http2;
pub use http2::actions::Http2ClientProtocol;

// http3 client
#[cfg(not(target_arch = "wasm32"))]
pub mod http3;
#[cfg(not(target_arch = "wasm32"))]
pub use http3::actions::Http3ClientProtocol;

// http_proxy client
#[cfg(unix)]
pub mod http_proxy;
#[cfg(unix)]
pub use http_proxy::actions::HttpProxyClientProtocol;

// igmp client
#[cfg(unix)]
pub mod igmp;
#[cfg(unix)]
pub use igmp::actions::IgmpClientProtocol;

// imap client
#[cfg(not(target_arch = "wasm32"))]
pub mod imap;
#[cfg(not(target_arch = "wasm32"))]
pub use imap::actions::ImapClientProtocol;

// ipp client
#[cfg(not(target_arch = "wasm32"))]
pub mod ipp;
#[cfg(not(target_arch = "wasm32"))]
pub use ipp::actions::IppClientProtocol;

// irc client
#[cfg(not(target_arch = "wasm32"))]
pub mod irc;
#[cfg(not(target_arch = "wasm32"))]
pub use irc::actions::IrcClientProtocol;

// isis client
#[cfg(all(unix, feature = "libpcap"))]
pub mod isis;
#[cfg(all(unix, feature = "libpcap"))]
pub use isis::actions::IsisClientProtocol;

// jsonrpc client
pub mod jsonrpc;
pub use jsonrpc::actions::JsonRpcClientProtocol;

// kafka client (pure Rust, shares the broker's kafka-protocol codecs)
pub mod kafka;
pub use kafka::actions::KafkaClientProtocol;

// kubernetes client
#[cfg(not(target_arch = "wasm32"))]
pub mod kubernetes;
#[cfg(not(target_arch = "wasm32"))]
pub use kubernetes::actions::KubernetesClientProtocol;

// ldap client
#[cfg(not(target_arch = "wasm32"))]
pub mod ldap;
#[cfg(not(target_arch = "wasm32"))]
pub use ldap::actions::LdapClientProtocol;

// maven client
pub mod maven;
pub use maven::actions::MavenClientProtocol;

// mcp client
#[cfg(not(target_arch = "wasm32"))]
pub mod mcp;
#[cfg(not(target_arch = "wasm32"))]
pub use mcp::actions::McpClientProtocol;

// mdns client
#[cfg(not(target_arch = "wasm32"))]
pub mod mdns;
#[cfg(not(target_arch = "wasm32"))]
pub use mdns::actions::MdnsClientProtocol;

// mqtt client
#[cfg(not(target_arch = "wasm32"))]
pub mod managesieve;
#[cfg(not(target_arch = "wasm32"))]
pub mod mqtt;
#[cfg(not(target_arch = "wasm32"))]
pub mod mqtt_sn;
#[cfg(not(target_arch = "wasm32"))]
pub mod nbd;
#[cfg(not(target_arch = "wasm32"))]
pub use mqtt::actions::MqttClientProtocol;

// amqp client
#[cfg(not(target_arch = "wasm32"))]
pub mod amqp;
#[cfg(not(target_arch = "wasm32"))]
pub use amqp::actions::AmqpClientProtocol;

// mysql client
#[cfg(not(target_arch = "wasm32"))]
pub mod mysql;
#[cfg(not(target_arch = "wasm32"))]
pub use mysql::actions::MysqlClientProtocol;

// mongodb client
#[cfg(not(target_arch = "wasm32"))]
pub mod mongodb;
#[cfg(not(target_arch = "wasm32"))]
pub use mongodb::actions::MongodbClientProtocol;

// nfs client
#[cfg(unix)]
pub mod nfs;
#[cfg(unix)]
pub use nfs::actions::NfsClientProtocol;

// nfc client
#[cfg(all(unix, feature = "pcsc"))]
pub mod nfc;
#[cfg(all(unix, feature = "pcsc"))]
pub use nfc::NfcClientProtocol;

// nntp client
pub mod nntp;
pub use nntp::actions::NntpClientProtocol;

// npm client
pub mod npm;
pub use npm::actions::NpmClientProtocol;

// ntp client
#[cfg(not(target_arch = "wasm32"))]
pub mod ntp;
#[cfg(not(target_arch = "wasm32"))]
pub use ntp::actions::NtpClientProtocol;

// oauth2 client
pub mod oauth2;
pub use oauth2::actions::OAuth2ClientProtocol;

// openai client
#[cfg(not(target_arch = "wasm32"))]
pub mod openai;
#[cfg(not(target_arch = "wasm32"))]
pub use openai::actions::OpenAiClientProtocol;

// ollama client
pub mod ollama;
pub use ollama::actions::OllamaClientProtocol;

// openapi client
pub mod openapi;
pub use openapi::actions::OpenApiClientProtocol;

// openidconnect client
pub mod openidconnect;
pub use openidconnect::actions::OpenIdConnectClientProtocol;

// otlp client
#[cfg(not(target_arch = "wasm32"))]
pub mod otlp;
#[cfg(not(target_arch = "wasm32"))]
pub use otlp::actions::OtlpClientProtocol;

// ospf client
#[cfg(unix)]
pub mod ospf;
#[cfg(unix)]
pub use ospf::actions::OspfClientProtocol;

// postgresql client
#[cfg(not(target_arch = "wasm32"))]
pub mod postgresql;
#[cfg(not(target_arch = "wasm32"))]
pub use postgresql::actions::PostgresqlClientProtocol;

// pypi client
pub mod pypi;
pub use pypi::actions::PypiClientProtocol;

// mssql client
#[cfg(not(target_arch = "wasm32"))]
pub mod mssql;
#[cfg(not(target_arch = "wasm32"))]
pub use mssql::actions::MssqlClientProtocol;

// redis client
#[cfg(not(target_arch = "wasm32"))]
pub mod redis;
#[cfg(not(target_arch = "wasm32"))]
pub use redis::actions::RedisClientProtocol;

// icmp client
#[cfg(unix)]
pub mod icmp;
#[cfg(unix)]
pub use icmp::actions::IcmpClientProtocol;

// couchdb client
#[cfg(not(target_arch = "wasm32"))]
pub mod couchdb;
#[cfg(not(target_arch = "wasm32"))]
pub use couchdb::actions::CouchDbClientProtocol;

// tftp client
pub mod tftp;
pub use tftp::actions::TftpClientProtocol;

// rss client
pub mod rss;
pub use rss::actions::RssClientProtocol;

// rip client
#[cfg(not(target_arch = "wasm32"))]
pub mod rip;
#[cfg(not(target_arch = "wasm32"))]
pub use rip::actions::RipClientProtocol;

// s3 client
#[cfg(not(target_arch = "wasm32"))]
pub mod s3;
#[cfg(not(target_arch = "wasm32"))]
pub use s3::actions::S3ClientProtocol;

// saml client
pub mod saml;
pub use saml::actions::SamlClientProtocol;

// sip client
pub mod sip;
pub use sip::actions::SipClientProtocol;

// H.323 endpoint: registers with a gatekeeper and places calls
#[cfg(not(target_arch = "wasm32"))]
pub mod h323;

// smb client
#[cfg(all(unix, feature = "libsmbclient"))]
pub mod smb;
#[cfg(all(unix, feature = "libsmbclient"))]
pub use smb::SmbClientProtocol;

// smtp client
#[cfg(not(target_arch = "wasm32"))]
pub mod smtp;
#[cfg(not(target_arch = "wasm32"))]
pub use smtp::actions::SmtpClientProtocol;

// ftp client
pub mod ftp;
pub use ftp::actions::FtpClientProtocol;

// pop3 client
pub mod pop3;
pub use pop3::actions::Pop3ClientProtocol;

// snmp client
pub mod snmp;
pub use snmp::actions::SnmpClientProtocol;

// socks5 client
#[cfg(not(target_arch = "wasm32"))]
pub mod socks5;
#[cfg(not(target_arch = "wasm32"))]
pub use socks5::actions::Socks5ClientProtocol;

// socket_file client
#[cfg(unix)]
pub mod socket_file;
#[cfg(unix)]
pub use socket_file::SocketFileClientProtocol;

// sqs client
#[cfg(not(target_arch = "wasm32"))]
pub mod sqs;
#[cfg(not(target_arch = "wasm32"))]
pub use sqs::actions::SqsClientProtocol;

// ssh client
#[cfg(not(target_arch = "wasm32"))]
pub mod ssh;
#[cfg(not(target_arch = "wasm32"))]
pub use ssh::actions::SshClientProtocol;

// ssh-agent client
#[cfg(unix)]
pub mod ssh_agent;
#[cfg(unix)]
pub use ssh_agent::actions::SshAgentClientProtocol;

// stun client
#[cfg(unix)]
pub mod stun;
#[cfg(unix)]
pub use stun::actions::StunClientProtocol;

// syslog client
pub mod syslog;
pub use syslog::actions::SyslogClientProtocol;

// tcp client
pub mod tcp;
pub use tcp::actions::TcpClientProtocol;

// telnet client
pub mod telnet;
pub use telnet::actions::TelnetClientProtocol;

// tls client
pub mod tls;
pub use tls::actions::TlsClientProtocol;

// tor client
#[cfg(unix)]
pub mod tor;
#[cfg(unix)]
pub use tor::actions::TorClientProtocol;

// torrent_dht client
pub mod torrent_dht;
pub use torrent_dht::actions::TorrentDhtClientProtocol;

// torrent_peer client
pub mod torrent_peer;
pub use torrent_peer::actions::TorrentPeerClientProtocol;

// torrent_tracker client
pub mod torrent_tracker;
pub use torrent_tracker::actions::TorrentTrackerClientProtocol;

// turn client
#[cfg(unix)]
pub mod turn;
#[cfg(unix)]
pub use turn::actions::TurnClientProtocol;

// udp client
pub mod udp;
pub use udp::actions::UdpClientProtocol;

// usb client
#[cfg(not(target_arch = "wasm32"))]
pub mod usb;
#[cfg(not(target_arch = "wasm32"))]
pub use usb::actions::UsbClientProtocol;

// vnc client
pub mod vnc;
pub use vnc::actions::VncClientProtocol;

// webdav client
#[cfg(not(target_arch = "wasm32"))]
pub mod webdav;
#[cfg(not(target_arch = "wasm32"))]
pub use webdav::actions::WebdavClientProtocol;

// webrtc client
#[cfg(not(target_arch = "wasm32"))]
pub mod webrtc;
#[cfg(not(target_arch = "wasm32"))]
pub use webrtc::actions::WebRtcClientProtocol;

// websocket client
#[cfg(not(target_arch = "wasm32"))]
pub mod websocket;
#[cfg(not(target_arch = "wasm32"))]
pub use websocket::actions::WebSocketClientProtocol;

// whois client
pub mod whois;
pub use whois::actions::WhoisClientProtocol;
// stomp client
pub mod stomp;
pub use stomp::actions::StompClientProtocol;
// netbios_ns client
pub mod netbios_ns;
pub use netbios_ns::actions::NetbiosNsClientProtocol;
// nats client
pub mod nats;
pub use nats::actions::NatsClientProtocol;

// memcached client
pub mod memcached;
pub use memcached::actions::MemcachedClientProtocol;

// modbus client
pub mod modbus;
pub use modbus::actions::ModbusClientProtocol;

// coap client
pub mod coap;
pub use coap::actions::CoapClientProtocol;

// radius client
pub mod radius;
pub use radius::actions::RadiusClientProtocol;
// ssdp client
pub mod ssdp;
pub use ssdp::actions::SsdpClientProtocol;
// gopher client
pub mod gopher;
pub use gopher::actions::GopherClientProtocol;
// finger client
pub mod finger;
pub use finger::actions::FingerClientProtocol;
// ident client
pub mod ident;
pub use ident::actions::IdentClientProtocol;
// llmnr client
#[cfg(not(target_arch = "wasm32"))]
pub mod llmnr;
#[cfg(not(target_arch = "wasm32"))]
pub use llmnr::actions::LlmnrClientProtocol;

// wireguard client
#[cfg(unix)]
pub mod wireguard;
#[cfg(unix)]
pub use wireguard::actions::WireguardClientProtocol;

// xmlrpc client
#[cfg(not(target_arch = "wasm32"))]
pub mod xmlrpc;
#[cfg(not(target_arch = "wasm32"))]
pub use xmlrpc::actions::XmlRpcClientProtocol;

// xmpp client
#[cfg(unix)]
pub mod xmpp;
#[cfg(unix)]
pub use xmpp::actions::XmppClientProtocol;

#[cfg(not(target_arch = "wasm32"))]
pub mod doq;
#[cfg(not(target_arch = "wasm32"))]
pub mod nut;
#[cfg(not(target_arch = "wasm32"))]
pub mod statsd;

#[cfg(not(target_arch = "wasm32"))]
pub mod gemini;

#[cfg(not(target_arch = "wasm32"))]
pub mod dict;

#[cfg(not(target_arch = "wasm32"))]
pub mod beanstalkd;
#[cfg(not(target_arch = "wasm32"))]
pub mod graphite;

#[cfg(not(target_arch = "wasm32"))]
pub mod quic;

#[cfg(not(target_arch = "wasm32"))]
pub mod gelf;

#[cfg(not(target_arch = "wasm32"))]
pub mod fluent_forward;
#[cfg(not(target_arch = "wasm32"))]
pub mod nsq;

#[cfg(not(target_arch = "wasm32"))]
pub mod gearman;

#[cfg(not(target_arch = "wasm32"))]
pub mod docker;
#[cfg(not(target_arch = "wasm32"))]
pub mod prometheus;

#[cfg(not(target_arch = "wasm32"))]
pub mod influxdb;

#[cfg(not(target_arch = "wasm32"))]
pub mod ipfix;

#[cfg(not(target_arch = "wasm32"))]
pub mod sflow;

#[cfg(not(target_arch = "wasm32"))]
pub mod loki;

#[cfg(not(target_arch = "wasm32"))]
pub mod vault;

#[cfg(not(target_arch = "wasm32"))]
pub mod prometheus_remote_write;

#[cfg(not(target_arch = "wasm32"))]
pub mod nostr;

#[cfg(not(target_arch = "wasm32"))]
pub mod netflow_v9;

#[cfg(not(target_arch = "wasm32"))]
pub mod a2a;
#[cfg(not(target_arch = "wasm32"))]
pub mod acme;
#[cfg(not(target_arch = "wasm32"))]
pub mod amqp1;
#[cfg(not(target_arch = "wasm32"))]
pub mod bmp;
#[cfg(not(target_arch = "wasm32"))]
pub mod caldav;
#[cfg(not(target_arch = "wasm32"))]
pub mod carddav;
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
pub mod diameter;

#[cfg(not(target_arch = "wasm32"))]
pub mod bolt;

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
pub mod db2;
#[cfg(not(target_arch = "wasm32"))]
pub mod dbus;
#[cfg(not(target_arch = "wasm32"))]
pub mod epp;
pub mod gtp;
#[cfg(not(target_arch = "wasm32"))]
pub mod guacamole;
pub mod hls;
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
pub mod lpd;
#[cfg(not(target_arch = "wasm32"))]
pub mod lwm2m;
#[cfg(unix)]
pub mod m3ua;
#[cfg(not(target_arch = "wasm32"))]
pub mod matrix;
#[cfg(not(target_arch = "wasm32"))]
pub mod milter;
#[cfg(not(target_arch = "wasm32"))]
pub mod minecraft;
#[cfg(not(target_arch = "wasm32"))]
pub mod msgpack_rpc;
#[cfg(unix)]
pub mod ngap;
#[cfg(not(target_arch = "wasm32"))]
pub mod ninep;
pub mod oci_registry;
#[cfg(not(target_arch = "wasm32"))]
pub mod onvif;
#[cfg(not(target_arch = "wasm32"))]
pub mod pfcp;
#[cfg(not(target_arch = "wasm32"))]
pub mod pulsar;
#[cfg(not(target_arch = "wasm32"))]
pub mod radsec;
#[cfg(not(target_arch = "wasm32"))]
pub mod rcon;
#[cfg(unix)]
pub mod rdp;
#[cfg(not(target_arch = "wasm32"))]
pub mod restconf;
#[cfg(not(target_arch = "wasm32"))]
pub mod rsync;
pub mod rtp;
pub mod rtsp;
#[cfg(not(target_arch = "wasm32"))]
pub mod smpp;
pub mod snowflake;
pub mod spark;
#[cfg(not(target_arch = "wasm32"))]
pub mod spice;
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
pub mod x11;
pub mod yarn;
#[cfg(not(target_arch = "wasm32"))]
pub mod zabbix;
#[cfg(not(target_arch = "wasm32"))]
pub mod zenoh;
#[cfg(not(target_arch = "wasm32"))]
pub mod zeromq;
#[cfg(not(target_arch = "wasm32"))]
pub mod zipkin;

#[cfg(not(target_arch = "wasm32"))]
pub mod s7comm;

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
