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
#[cfg(feature = "arp")]
pub mod arp;
#[cfg(feature = "arp")]
pub use arp::actions::ArpClientProtocol;

// bgp client
#[cfg(feature = "bgp")]
pub mod bgp;
#[cfg(feature = "bgp")]
pub use bgp::actions::BgpClientProtocol;

// bitcoin client
#[cfg(feature = "bitcoin")]
pub mod bitcoin;
#[cfg(feature = "bitcoin")]
pub use bitcoin::actions::BitcoinClientProtocol;
// Ethereum devp2p dialler
#[cfg(feature = "devp2p")]
pub mod devp2p;

// bluetooth-ble client
#[cfg(feature = "bluetooth-ble-client")]
pub mod bluetooth;
#[cfg(feature = "bluetooth-ble-client")]
pub use bluetooth::actions::BluetoothClientProtocol;

// bootp client
#[cfg(feature = "bootp")]
pub mod bootp;
#[cfg(feature = "bootp")]
pub use bootp::actions::BootpClientProtocol;

// cassandra client
#[cfg(feature = "cassandra")]
pub mod cassandra;
#[cfg(feature = "cassandra")]
pub use cassandra::actions::CassandraClientProtocol;

// datalink client
#[cfg(feature = "datalink")]
pub mod datalink;
#[cfg(feature = "datalink")]
pub use datalink::actions::DataLinkClientProtocol;

// dc client
#[cfg(feature = "dc")]
pub mod dc;
#[cfg(feature = "dc")]
pub use dc::actions::DcClientProtocol;

// dhcp client
#[cfg(feature = "dhcp")]
pub mod dhcp;
#[cfg(feature = "dhcp")]
pub use dhcp::actions::DhcpClientProtocol;

// dns client
#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "dns")]
pub use dns::actions::DnsClientProtocol;

// doh client
#[cfg(feature = "doh")]
pub mod doh;
#[cfg(feature = "doh")]
pub use doh::actions::DohClientProtocol;

// dot client
#[cfg(feature = "dot")]
pub mod dot;
#[cfg(feature = "dot")]
pub use dot::actions::DotClientProtocol;

// dynamodb client
#[cfg(feature = "dynamodb")]
pub mod dynamodb;
#[cfg(feature = "dynamodb")]
pub use dynamodb::actions::DynamoDbClientProtocol;

// elasticsearch client
#[cfg(feature = "elasticsearch")]
pub mod elasticsearch;
#[cfg(feature = "elasticsearch")]
pub use elasticsearch::actions::ElasticsearchClientProtocol;

// etcd client
#[cfg(feature = "etcd")]
pub mod etcd;
#[cfg(feature = "etcd")]
pub use etcd::actions::EtcdClientProtocol;

// zookeeper client
#[cfg(feature = "zookeeper")]
pub mod zookeeper;
#[cfg(feature = "zookeeper")]
pub use zookeeper::actions::ZookeeperClientProtocol;

// git client
#[cfg(feature = "git")]
pub mod git;
#[cfg(feature = "git")]
pub use git::actions::GitClientProtocol;

// grpc client
#[cfg(feature = "connect_rpc")]
pub mod connect_rpc;
#[cfg(feature = "gnmi")]
pub mod gnmi;
#[cfg(feature = "grpc")]
pub mod grpc;
#[cfg(feature = "grpc-web")]
pub mod grpc_web;
#[cfg(feature = "grpc")]
pub use grpc::actions::GrpcClientProtocol;

// The HTTP-family clients run in the browser build too: there they issue their requests
// through `http_fetch` (hyper's client over the virtual loopback) instead of reqwest; see
// web/README.md.
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "http")]
pub use http::actions::HttpClientProtocol;

// http2 client
#[cfg(feature = "http2")]
pub mod http2;
#[cfg(feature = "http2")]
pub use http2::actions::Http2ClientProtocol;

// http3 client
#[cfg(feature = "http3")]
pub mod http3;
#[cfg(feature = "http3")]
pub use http3::actions::Http3ClientProtocol;

// http_proxy client
#[cfg(feature = "http_proxy")]
pub mod http_proxy;
#[cfg(feature = "http_proxy")]
pub use http_proxy::actions::HttpProxyClientProtocol;

// igmp client
#[cfg(feature = "igmp")]
pub mod igmp;
#[cfg(feature = "igmp")]
pub use igmp::actions::IgmpClientProtocol;

// imap client
#[cfg(feature = "imap")]
pub mod imap;
#[cfg(feature = "imap")]
pub use imap::actions::ImapClientProtocol;

// ipp client
#[cfg(feature = "ipp")]
pub mod ipp;
#[cfg(feature = "ipp")]
pub use ipp::actions::IppClientProtocol;

// irc client
#[cfg(feature = "irc")]
pub mod irc;
#[cfg(feature = "irc")]
pub use irc::actions::IrcClientProtocol;

// isis client
#[cfg(feature = "isis")]
pub mod isis;
#[cfg(feature = "isis")]
pub use isis::actions::IsisClientProtocol;

// jsonrpc client
#[cfg(feature = "jsonrpc")]
pub mod jsonrpc;
#[cfg(feature = "jsonrpc")]
pub use jsonrpc::actions::JsonRpcClientProtocol;

// kafka client (pure Rust, shares the broker's kafka-protocol codecs)
#[cfg(feature = "kafka")]
pub mod kafka;
#[cfg(feature = "kafka")]
pub use kafka::actions::KafkaClientProtocol;

// kubernetes client
#[cfg(feature = "kubernetes")]
pub mod kubernetes;
#[cfg(feature = "kubernetes")]
pub use kubernetes::actions::KubernetesClientProtocol;

// ldap client
#[cfg(feature = "ldap")]
pub mod ldap;
#[cfg(feature = "ldap")]
pub use ldap::actions::LdapClientProtocol;

// maven client
#[cfg(feature = "maven")]
pub mod maven;
#[cfg(feature = "maven")]
pub use maven::actions::MavenClientProtocol;

// mcp client
#[cfg(feature = "mcp")]
pub mod mcp;
#[cfg(feature = "mcp")]
pub use mcp::actions::McpClientProtocol;

// mdns client
#[cfg(feature = "mdns")]
pub mod mdns;
#[cfg(feature = "mdns")]
pub use mdns::actions::MdnsClientProtocol;

// mqtt client
#[cfg(feature = "managesieve")]
pub mod managesieve;
#[cfg(feature = "mqtt")]
pub mod mqtt;
#[cfg(feature = "mqtt_sn")]
pub mod mqtt_sn;
#[cfg(feature = "nbd")]
pub mod nbd;
#[cfg(feature = "mqtt")]
pub use mqtt::actions::MqttClientProtocol;

// amqp client
#[cfg(feature = "amqp")]
pub mod amqp;
#[cfg(feature = "amqp")]
pub use amqp::actions::AmqpClientProtocol;

// mysql client
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "mysql")]
pub use mysql::actions::MysqlClientProtocol;

// mongodb client
#[cfg(feature = "mongodb")]
pub mod mongodb;
#[cfg(feature = "mongodb")]
pub use mongodb::actions::MongodbClientProtocol;

// nfs client
#[cfg(feature = "nfs")]
pub mod nfs;
#[cfg(feature = "nfs")]
pub use nfs::actions::NfsClientProtocol;

// nfc client
#[cfg(feature = "nfc-client")]
pub mod nfc;
#[cfg(feature = "nfc-client")]
pub use nfc::NfcClientProtocol;

// nntp client
#[cfg(feature = "nntp")]
pub mod nntp;
#[cfg(feature = "nntp")]
pub use nntp::actions::NntpClientProtocol;

// npm client
#[cfg(feature = "npm")]
pub mod npm;
#[cfg(feature = "npm")]
pub use npm::actions::NpmClientProtocol;

// ntp client
#[cfg(feature = "ntp")]
pub mod ntp;
#[cfg(feature = "ntp")]
pub use ntp::actions::NtpClientProtocol;

// oauth2 client
#[cfg(feature = "oauth2")]
pub mod oauth2;
#[cfg(feature = "oauth2")]
pub use oauth2::actions::OAuth2ClientProtocol;

// openai client
#[cfg(feature = "openai")]
pub mod openai;
#[cfg(feature = "openai")]
pub use openai::actions::OpenAiClientProtocol;

// ollama client
#[cfg(feature = "ollama")]
pub mod ollama;
#[cfg(feature = "ollama")]
pub use ollama::actions::OllamaClientProtocol;

// openapi client
#[cfg(feature = "openapi")]
pub mod openapi;
#[cfg(feature = "openapi")]
pub use openapi::actions::OpenApiClientProtocol;

// openidconnect client
#[cfg(feature = "openidconnect")]
pub mod openidconnect;
#[cfg(feature = "openidconnect")]
pub use openidconnect::actions::OpenIdConnectClientProtocol;

// otlp client
#[cfg(feature = "otlp")]
pub mod otlp;
#[cfg(feature = "otlp")]
pub use otlp::actions::OtlpClientProtocol;

// ospf client
#[cfg(feature = "ospf")]
pub mod ospf;
#[cfg(feature = "ospf")]
pub use ospf::actions::OspfClientProtocol;

// postgresql client
#[cfg(feature = "postgresql")]
pub mod postgresql;
#[cfg(feature = "postgresql")]
pub use postgresql::actions::PostgresqlClientProtocol;

// pypi client
#[cfg(feature = "pypi")]
pub mod pypi;
#[cfg(feature = "pypi")]
pub use pypi::actions::PypiClientProtocol;

// mssql client
#[cfg(feature = "mssql")]
pub mod mssql;
#[cfg(feature = "mssql")]
pub use mssql::actions::MssqlClientProtocol;

// redis client
#[cfg(feature = "redis")]
pub mod redis;
#[cfg(feature = "redis")]
pub use redis::actions::RedisClientProtocol;

// icmp client
#[cfg(feature = "icmp")]
pub mod icmp;
#[cfg(feature = "icmp")]
pub use icmp::actions::IcmpClientProtocol;

// couchdb client
#[cfg(feature = "couchdb")]
pub mod couchdb;
#[cfg(feature = "couchdb")]
pub use couchdb::actions::CouchDbClientProtocol;

// tftp client
#[cfg(feature = "tftp")]
pub mod tftp;
#[cfg(feature = "tftp")]
pub use tftp::actions::TftpClientProtocol;

// rss client
#[cfg(feature = "rss")]
pub mod rss;
#[cfg(feature = "rss")]
pub use rss::actions::RssClientProtocol;

// rip client
#[cfg(feature = "rip")]
pub mod rip;
#[cfg(feature = "rip")]
pub use rip::actions::RipClientProtocol;

// s3 client
#[cfg(feature = "s3")]
pub mod s3;
#[cfg(feature = "s3")]
pub use s3::actions::S3ClientProtocol;

// saml client
#[cfg(feature = "saml")]
pub mod saml;
#[cfg(feature = "saml")]
pub use saml::actions::SamlClientProtocol;

// sip client
#[cfg(feature = "sip")]
pub mod sip;
#[cfg(feature = "sip")]
pub use sip::actions::SipClientProtocol;

// smb client
#[cfg(feature = "smb-client")]
pub mod smb;
#[cfg(feature = "smb-client")]
pub use smb::SmbClientProtocol;

// smtp client
#[cfg(feature = "smtp")]
pub mod smtp;
#[cfg(feature = "smtp")]
pub use smtp::actions::SmtpClientProtocol;

// ftp client
#[cfg(feature = "ftp")]
pub mod ftp;
#[cfg(feature = "ftp")]
pub use ftp::actions::FtpClientProtocol;

// pop3 client
#[cfg(feature = "pop3")]
pub mod pop3;
#[cfg(feature = "pop3")]
pub use pop3::actions::Pop3ClientProtocol;

// snmp client
#[cfg(feature = "snmp")]
pub mod snmp;
#[cfg(feature = "snmp")]
pub use snmp::actions::SnmpClientProtocol;

// socks5 client
#[cfg(feature = "socks5")]
pub mod socks5;
#[cfg(feature = "socks5")]
pub use socks5::actions::Socks5ClientProtocol;

// socket_file client
#[cfg(all(feature = "socket_file", unix))]
pub mod socket_file;
#[cfg(all(feature = "socket_file", unix))]
pub use socket_file::SocketFileClientProtocol;

// sqs client
#[cfg(feature = "sqs")]
pub mod sqs;
#[cfg(feature = "sqs")]
pub use sqs::actions::SqsClientProtocol;

// ssh client
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "ssh")]
pub use ssh::actions::SshClientProtocol;

// ssh-agent client
#[cfg(all(feature = "ssh-agent", unix))]
pub mod ssh_agent;
#[cfg(all(feature = "ssh-agent", unix))]
pub use ssh_agent::actions::SshAgentClientProtocol;

// stun client
#[cfg(feature = "stun")]
pub mod stun;
#[cfg(feature = "stun")]
pub use stun::actions::StunClientProtocol;

// syslog client
#[cfg(feature = "syslog")]
pub mod syslog;
#[cfg(feature = "syslog")]
pub use syslog::actions::SyslogClientProtocol;

// tcp client
#[cfg(feature = "tcp")]
pub mod tcp;
#[cfg(feature = "tcp")]
pub use tcp::actions::TcpClientProtocol;

// telnet client
#[cfg(feature = "telnet")]
pub mod telnet;
#[cfg(feature = "telnet")]
pub use telnet::actions::TelnetClientProtocol;

// tls client
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "tls")]
pub use tls::actions::TlsClientProtocol;

// tor client
#[cfg(feature = "tor")]
pub mod tor;
#[cfg(feature = "tor")]
pub use tor::actions::TorClientProtocol;

// torrent_dht client
#[cfg(feature = "torrent-dht")]
pub mod torrent_dht;
#[cfg(feature = "torrent-dht")]
pub use torrent_dht::actions::TorrentDhtClientProtocol;

// torrent_peer client
#[cfg(feature = "torrent-peer")]
pub mod torrent_peer;
#[cfg(feature = "torrent-peer")]
pub use torrent_peer::actions::TorrentPeerClientProtocol;

// torrent_tracker client
#[cfg(feature = "torrent-tracker")]
pub mod torrent_tracker;
#[cfg(feature = "torrent-tracker")]
pub use torrent_tracker::actions::TorrentTrackerClientProtocol;

// turn client
#[cfg(feature = "turn")]
pub mod turn;
#[cfg(feature = "turn")]
pub use turn::actions::TurnClientProtocol;

// udp client
#[cfg(feature = "udp")]
pub mod udp;
#[cfg(feature = "udp")]
pub use udp::actions::UdpClientProtocol;

// usb client
#[cfg(feature = "usb")]
pub mod usb;
#[cfg(feature = "usb")]
pub use usb::actions::UsbClientProtocol;

// vnc client
#[cfg(feature = "vnc")]
pub mod vnc;
#[cfg(feature = "vnc")]
pub use vnc::actions::VncClientProtocol;

// webdav client
#[cfg(feature = "webdav")]
pub mod webdav;
#[cfg(feature = "webdav")]
pub use webdav::actions::WebdavClientProtocol;

// webrtc client
#[cfg(feature = "webrtc")]
pub mod webrtc;
#[cfg(feature = "webrtc")]
pub use webrtc::actions::WebRtcClientProtocol;

// websocket client
#[cfg(feature = "websocket")]
pub mod websocket;
#[cfg(feature = "websocket")]
pub use websocket::actions::WebSocketClientProtocol;

// whois client
#[cfg(feature = "whois")]
pub mod whois;
#[cfg(feature = "whois")]
pub use whois::actions::WhoisClientProtocol;
// stomp client
#[cfg(feature = "stomp")]
pub mod stomp;
#[cfg(feature = "stomp")]
pub use stomp::actions::StompClientProtocol;
// netbios_ns client
#[cfg(feature = "netbios-ns")]
pub mod netbios_ns;
#[cfg(feature = "netbios-ns")]
pub use netbios_ns::actions::NetbiosNsClientProtocol;
// nats client
#[cfg(feature = "nats")]
pub mod nats;
#[cfg(feature = "nats")]
pub use nats::actions::NatsClientProtocol;

// memcached client
#[cfg(feature = "memcached")]
pub mod memcached;
#[cfg(feature = "memcached")]
pub use memcached::actions::MemcachedClientProtocol;

// modbus client
#[cfg(feature = "modbus")]
pub mod modbus;
#[cfg(feature = "modbus")]
pub use modbus::actions::ModbusClientProtocol;

// coap client
#[cfg(feature = "coap")]
pub mod coap;
#[cfg(feature = "coap")]
pub use coap::actions::CoapClientProtocol;

// radius client
#[cfg(feature = "radius")]
pub mod radius;
#[cfg(feature = "radius")]
pub use radius::actions::RadiusClientProtocol;
// ssdp client
#[cfg(feature = "ssdp")]
pub mod ssdp;
#[cfg(feature = "ssdp")]
pub use ssdp::actions::SsdpClientProtocol;
// gopher client
#[cfg(feature = "gopher")]
pub mod gopher;
#[cfg(feature = "gopher")]
pub use gopher::actions::GopherClientProtocol;
// finger client
#[cfg(feature = "finger")]
pub mod finger;
#[cfg(feature = "finger")]
pub use finger::actions::FingerClientProtocol;
// ident client
#[cfg(feature = "ident")]
pub mod ident;
#[cfg(feature = "ident")]
pub use ident::actions::IdentClientProtocol;
// llmnr client
#[cfg(feature = "llmnr")]
pub mod llmnr;
#[cfg(feature = "llmnr")]
pub use llmnr::actions::LlmnrClientProtocol;

// wireguard client
#[cfg(feature = "wireguard")]
pub mod wireguard;
#[cfg(feature = "wireguard")]
pub use wireguard::actions::WireguardClientProtocol;

// xmlrpc client
#[cfg(feature = "xmlrpc")]
pub mod xmlrpc;
#[cfg(feature = "xmlrpc")]
pub use xmlrpc::actions::XmlRpcClientProtocol;

// xmpp client
#[cfg(feature = "xmpp")]
pub mod xmpp;
#[cfg(feature = "xmpp")]
pub use xmpp::actions::XmppClientProtocol;

#[cfg(feature = "doq")]
pub mod doq;
#[cfg(feature = "nut")]
pub mod nut;
#[cfg(feature = "statsd")]
pub mod statsd;

#[cfg(feature = "gemini")]
pub mod gemini;

#[cfg(feature = "dict")]
pub mod dict;

#[cfg(feature = "beanstalkd")]
pub mod beanstalkd;
#[cfg(feature = "graphite")]
pub mod graphite;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "gelf")]
pub mod gelf;

#[cfg(feature = "fluent-forward")]
pub mod fluent_forward;
#[cfg(feature = "nsq")]
pub mod nsq;

#[cfg(feature = "gearman")]
pub mod gearman;

#[cfg(feature = "docker")]
pub mod docker;
#[cfg(feature = "prometheus")]
pub mod prometheus;

#[cfg(feature = "influxdb")]
pub mod influxdb;

#[cfg(feature = "ipfix")]
pub mod ipfix;

#[cfg(feature = "sflow")]
pub mod sflow;

#[cfg(feature = "loki")]
pub mod loki;

#[cfg(feature = "vault")]
pub mod vault;

#[cfg(feature = "prometheus-remote-write")]
pub mod prometheus_remote_write;

#[cfg(feature = "nostr")]
pub mod nostr;

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

#[cfg(feature = "diameter")]
pub mod diameter;

#[cfg(feature = "bolt")]
pub mod bolt;

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
#[cfg(feature = "db2")]
pub mod db2;
#[cfg(feature = "dbus")]
pub mod dbus;
#[cfg(feature = "epp")]
pub mod epp;
#[cfg(feature = "gtp")]
pub mod gtp;
#[cfg(feature = "guacamole")]
pub mod guacamole;
#[cfg(feature = "hls")]
pub mod hls;
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
#[cfg(feature = "m3ua")]
pub mod m3ua;
#[cfg(feature = "matrix")]
pub mod matrix;
#[cfg(feature = "milter")]
pub mod milter;
#[cfg(feature = "minecraft")]
pub mod minecraft;
#[cfg(feature = "msgpack-rpc")]
pub mod msgpack_rpc;
#[cfg(feature = "ngap")]
pub mod ngap;
#[cfg(feature = "ninep")]
pub mod ninep;
#[cfg(feature = "oci-registry")]
pub mod oci_registry;
#[cfg(feature = "onvif")]
pub mod onvif;
#[cfg(feature = "pfcp")]
pub mod pfcp;
#[cfg(feature = "pulsar")]
pub mod pulsar;
#[cfg(feature = "radsec")]
pub mod radsec;
#[cfg(feature = "rcon")]
pub mod rcon;
#[cfg(feature = "rdp-client")]
pub mod rdp;
#[cfg(feature = "restconf")]
pub mod restconf;
#[cfg(feature = "rsync")]
pub mod rsync;
#[cfg(feature = "rtp")]
pub mod rtp;
#[cfg(feature = "rtsp")]
pub mod rtsp;
#[cfg(feature = "smpp")]
pub mod smpp;
#[cfg(feature = "snowflake")]
pub mod snowflake;
#[cfg(feature = "spark")]
pub mod spark;
#[cfg(feature = "spice")]
pub mod spice;
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
#[cfg(feature = "x11")]
pub mod x11;
#[cfg(feature = "yarn")]
pub mod yarn;
#[cfg(feature = "zabbix")]
pub mod zabbix;
#[cfg(feature = "zenoh")]
pub mod zenoh;
#[cfg(feature = "zeromq")]
pub mod zeromq;
#[cfg(feature = "zipkin")]
pub mod zipkin;

#[cfg(feature = "s7comm")]
pub mod s7comm;

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
