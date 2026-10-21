//! Client protocol e2e tests

/// The shared shape of the per-client batching tests.
pub mod batching_support;

pub mod amqp;
#[cfg(all(unix, feature = "libpcap"))]
pub mod arp;
pub mod bgp;
pub mod bitcoin;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth;
pub mod bootp;
pub mod cassandra;
pub mod coap;
pub mod connect_rpc;
pub mod couchdb;
#[cfg(all(unix, feature = "libpcap"))]
pub mod datalink;
pub mod dc;
pub mod devp2p;
pub mod dhcp;
pub mod dns;
pub mod doh;
pub mod dot;
pub mod dynamodb;
pub mod elasticsearch;
pub mod etcd;
pub mod finger;
pub mod ftp;
pub mod git;
pub mod gnmi;
pub mod gopher;
pub mod grpc;
pub mod grpc_web;
pub mod h323;
pub mod http;
pub mod http2;
pub mod http3;
#[cfg(unix)]
pub mod http_proxy;
#[cfg(unix)]
pub mod icmp;
pub mod ident;
#[cfg(unix)]
pub mod igmp;
pub mod imap;
pub mod ipp;
pub mod irc;
pub mod iscsi;
#[cfg(all(unix, feature = "libpcap"))]
pub mod isis;
pub mod jsonrpc;
pub mod kafka;
pub mod kubernetes;
pub mod ldap;
pub mod llmnr;
pub mod maven;
pub mod mcp;
pub mod mdns;
pub mod memcached;
pub mod modbus;
pub mod mongodb;
pub mod mqtt;
pub mod mssql;
pub mod mysql;
pub mod nats;
pub mod netbios_ns;
#[cfg(all(unix, feature = "pcsc"))]
pub mod nfc;
#[cfg(unix)]
pub mod nfs;
pub mod nntp;
pub mod npm;
pub mod ntp;
pub mod oauth2;
pub mod ollama;
pub mod openai;
pub mod openapi;
pub mod openidconnect;
#[cfg(unix)]
pub mod ospf;
pub mod pop3;
pub mod postgresql;
pub mod pypi;
pub mod radius;
pub mod redis;
pub mod rip;
pub mod rss;
pub mod s3;
pub mod saml;
pub mod sip;
pub mod smb;
pub mod smtp;
pub mod snmp;
#[cfg(unix)]
pub mod socket_file;
pub mod socks5;
pub mod sqs;
pub mod ssdp;
pub mod ssh;
#[cfg(unix)]
pub mod ssh_agent;
pub mod stomp;
#[cfg(unix)]
pub mod stun;
pub mod syslog;
pub mod tcp;
pub mod telnet;
pub mod tftp;
pub mod tls;
#[cfg(unix)]
pub mod tor;
pub mod torrent_dht;
pub mod torrent_peer;
pub mod torrent_tracker;
#[cfg(unix)]
pub mod turn;
pub mod udp;
pub mod usb;
pub mod vnc;
pub mod webdav;
pub mod webrtc;
pub mod websocket;
pub mod whois;
#[cfg(unix)]
pub mod wireguard;
pub mod xmlrpc;
#[cfg(unix)]
pub mod xmpp;
pub mod zookeeper;

pub mod doq;
pub mod nut;
pub mod statsd;

pub mod gemini;

pub mod dict;

pub mod beanstalkd;
pub mod graphite;

pub mod quic;

pub mod gelf;

pub mod fluent_forward;
pub mod nsq;

pub mod gearman;

pub mod docker;
pub mod prometheus;

pub mod influxdb;

pub mod ipfix;

pub mod loki;

pub mod otlp;

pub mod sflow;

pub mod vault;

pub mod prometheus_remote_write;

pub mod nostr;

pub mod netflow_v9;

pub mod tacacs;

pub mod netconf;

pub mod rpki_rtr;

pub mod rdap;

pub mod hl7;

pub mod icap;

pub mod ocpp;

pub mod a2a;

pub mod graphql;

pub mod fastcgi;

pub mod redfish;

pub mod scim;

pub mod socketio;

pub mod caldav;

pub mod carddav;

pub mod dicom;

pub mod acme;

pub mod fix;

pub mod wamp;

pub mod rtmp;

pub mod srt;

pub mod amqp1;

pub mod thrift;

pub mod bmp;

pub mod mqtt_sn;

#[cfg(unix)]
pub mod hdfs;
pub mod nbd;
pub mod nvme_tcp;

pub mod managesieve;

pub mod zenoh;

pub mod lwm2m;

pub mod a2s;
pub mod activitypub;
pub mod afp;
pub mod anthropic;
pub mod bfd;
pub mod capnp_rpc;
pub mod clickhouse;
pub mod consul;
pub mod db2;
pub mod dbus;
pub mod epp;
pub mod ethercat;
pub mod gtp;
pub mod guacamole;
pub mod hls;
pub mod inetd;
pub mod jmap;
pub mod kerberos;
pub mod knx;
pub mod libp2p;
pub mod lmtp;
pub mod lorawan;
pub mod lpd;
#[cfg(unix)]
pub mod m3ua;
pub mod matrix;
pub mod mbus;
pub mod milter;
pub mod minecraft;
pub mod msgpack_rpc;
#[cfg(unix)]
pub mod ngap;
pub mod ninep;
pub mod nis;
pub mod onvif;
pub mod openflow;
pub mod pfcp;
pub mod profinet;
pub mod pulsar;
pub mod radsec;
pub mod rcon;
#[cfg(unix)]
pub mod rdp;
pub mod restconf;
pub mod rsh;
pub mod rsync;
pub mod rtp;
pub mod rtsp;
pub mod smpp;
pub mod snowflake;
pub mod spark;
pub mod spice;
pub mod sse;
pub mod stratum;
pub mod stratum_v2;
pub mod sunrpc;
pub mod tr069;
pub mod vxlan;
pub mod webtransport;
pub mod wsdiscovery;
pub mod x11;
pub mod yarn;
pub mod zabbix;
pub mod zeromq;
pub mod zipkin;

pub mod diameter;

pub mod bolt;

pub mod oci_registry;

pub mod s7comm;

pub mod ethernet_ip;

pub mod dnp3;

pub mod iec104;

pub mod bacnet;

pub mod opcua;

pub mod soulseek;

pub mod soulseek_peer;

pub mod adc;

pub mod adc_peer;

pub mod dc_peer;

pub mod gnutella;
