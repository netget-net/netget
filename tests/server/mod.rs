//! Server protocol e2e tests

pub mod amqp;
#[cfg(all(unix, feature = "libpcap"))]
pub mod arp;
pub mod beanstalkd;
pub mod bgp;
pub mod bitcoin;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_battery;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_beacon;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_cycling;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_data_stream;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_environmental;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_file_transfer;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_gamepad;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_heart_rate;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_keyboard;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_mouse;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_presenter;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_proximity;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_remote;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_running;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_thermometer;
#[cfg(all(unix, feature = "bluetooth"))]
pub mod bluetooth_ble_weight_scale;
pub mod bolt;
pub mod bootp;
#[cfg(unix)]
pub mod can;
pub mod cassandra;
#[cfg(all(unix, feature = "libpcap"))]
pub mod cdp;
pub mod coap;
pub mod connect_rpc;
pub mod couchdb;
#[cfg(all(unix, feature = "libpcap"))]
pub mod datalink;
pub mod db2;
pub mod dc;
pub mod devp2p;
pub mod dhcp;
pub mod dhcpv6;
pub mod dict;
pub mod dns;
pub mod docker;
pub mod doh;
pub mod dot;
pub mod dynamo;
#[cfg(all(unix, feature = "libpcap"))]
pub mod eapol;
pub mod elasticsearch;
pub mod etcd;
pub mod finger;
pub mod ftp;
pub mod gearman;
pub mod gemini;
pub mod git;
pub mod gnmi;
pub mod gopher;
pub mod grpc;
pub mod grpc_web;
pub mod gtp;
pub mod h323;
pub mod hls;
pub mod hsrp;
pub mod http;
pub mod http2;
#[cfg(unix)]
pub mod icmp;
pub mod ident;
#[cfg(unix)]
pub mod igmp;
pub mod imap;
pub mod ipp;
pub mod ipsec;
pub mod irc;
#[cfg(all(unix, feature = "libpcap"))]
pub mod isis;
pub mod jsonrpc;
pub mod kafka;
pub mod kubernetes;
pub mod ldap;
#[cfg(all(unix, feature = "libpcap"))]
pub mod lldp;
pub mod llmnr;
#[cfg(unix)]
pub mod m3ua;
pub mod maven;
pub mod mcp;
pub mod mdns;
pub mod memcached;
pub mod mercurial;
pub mod modbus;
pub mod mongodb;
pub mod mqtt;
pub mod mssql;
pub mod mysql;
#[cfg(unix)]
pub mod named_pipe;
pub mod nats;
#[cfg(unix)]
pub mod ndp;
pub mod netbios_ns;
#[cfg(unix)]
pub mod nfc;
#[cfg(unix)]
pub mod nfs;
#[cfg(unix)]
pub mod ngap;
pub mod nntp;
pub mod nostr;
pub mod npm;
pub mod nsq;
pub mod ntp;
pub mod oauth2;
pub mod oci_registry;
pub mod ollama;
pub mod openai;
pub mod openapi;
pub mod openid;
#[cfg(unix)]
pub mod openvpn;
#[cfg(unix)]
pub mod ospf;
pub mod otlp;
pub mod pop3;
pub mod postgresql;
pub mod prometheus;
#[cfg(unix)]
pub mod proxy;
#[cfg(unix)]
pub mod pty;
pub mod pypi;
pub mod quic;
pub mod radius;
#[cfg(unix)]
pub mod rawip;
pub mod rdp;
pub mod redis;
pub mod reverse_shell;
pub mod rip;
pub mod rss;
pub mod rtp;
pub mod rtsp;
pub mod s3;
pub mod saml_idp;
pub mod saml_sp;
pub mod sip;
pub mod smb;
pub mod smtp;
pub mod snmp;
pub mod snowflake;
#[cfg(unix)]
pub mod socket_file;
pub mod socks5;
pub mod spark;
pub mod spice;
pub mod sqs;
pub mod ssdp;
pub mod ssh;
#[cfg(unix)]
pub mod ssh_agent;
#[cfg(unix)]
pub mod stdio;
pub mod stomp;
#[cfg(all(unix, feature = "libpcap"))]
pub mod stp;
#[cfg(unix)]
pub mod stun;
pub mod svn;
pub mod syslog;
pub mod tcp;
pub mod telnet;
pub mod tftp;
pub mod tls;
#[cfg(unix)]
pub mod tor_integration;
#[cfg(unix)]
pub mod tor_relay;
pub mod torrent_dht;
pub mod torrent_integration;
pub mod torrent_peer;
pub mod torrent_tracker;
#[cfg(unix)]
pub mod tuntap;
#[cfg(unix)]
pub mod turn;
pub mod udp;
#[cfg(all(unix, feature = "libusb"))]
pub mod usb_fido2;
#[cfg(all(unix, feature = "libusb"))]
pub mod usb_keyboard;
#[cfg(all(unix, feature = "libusb"))]
pub mod usb_mouse;
#[cfg(all(unix, feature = "libusb"))]
pub mod usb_msc;
#[cfg(all(unix, feature = "libusb"))]
pub mod usb_serial;
#[cfg(all(unix, feature = "libusb"))]
pub mod usb_smartcard;
pub mod vault;
pub mod vnc;
#[cfg(unix)]
pub mod vrrp;
pub mod webdav;
pub mod webrtc;
pub mod webrtc_signaling;
pub mod websocket;
pub mod whois;
#[cfg(unix)]
pub mod wireguard;
pub mod wol;
pub mod xmlrpc;
#[cfg(unix)]
pub mod xmpp;
pub mod yarn;
pub mod zabbix;
pub mod zookeeper;

// Shared test helpers - re-export from top-level for backward compatibility
pub use super::helpers;

pub mod doq;
pub mod nut;
pub mod statsd;

pub mod graphite;

pub mod gelf;

pub mod fluent_forward;
pub mod http3;

pub mod influxdb;

pub mod ipfix;

pub mod sflow;

pub mod loki;

pub mod prometheus_remote_write;

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

pub mod nbd;

pub mod managesieve;

pub mod zenoh;

pub mod lwm2m;

pub mod a2s;
pub mod activitypub;
pub mod anthropic;
pub mod bfd;
pub mod capnp_rpc;
pub mod clickhouse;
pub mod consul;
pub mod dbus;
pub mod epp;
pub mod guacamole;
pub mod inetd;
pub mod jmap;
pub mod kerberos;
pub mod knx;
pub mod libp2p;
pub mod lmtp;
pub mod lpd;
pub mod matrix;
pub mod milter;
pub mod minecraft;
pub mod msgpack_rpc;
pub mod ninep;
pub mod onvif;
pub mod pfcp;
pub mod pulsar;
pub mod radsec;
pub mod rcon;
pub mod restconf;
pub mod rsync;
pub mod smpp;
pub mod sse;
pub mod stratum;
pub mod stratum_v2;
pub mod sunrpc;
pub mod tr069;
pub mod vxlan;
pub mod openflow;
pub mod webtransport;
pub mod wsdiscovery;
pub mod zeromq;
pub mod zipkin;

pub mod diameter;

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
