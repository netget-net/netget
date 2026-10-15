//! Server protocol e2e tests

#[cfg(feature = "amqp")]
pub mod amqp;
#[cfg(feature = "arp")]
pub mod arp;
#[cfg(feature = "beanstalkd")]
pub mod beanstalkd;
#[cfg(feature = "bgp")]
pub mod bgp;
#[cfg(feature = "bitcoin")]
pub mod bitcoin;
#[cfg(feature = "bluetooth-ble")]
pub mod bluetooth_ble;
#[cfg(feature = "bluetooth-ble-battery")]
pub mod bluetooth_ble_battery;
#[cfg(feature = "bluetooth-ble-beacon")]
pub mod bluetooth_ble_beacon;
#[cfg(feature = "bluetooth-ble-cycling")]
pub mod bluetooth_ble_cycling;
#[cfg(feature = "bluetooth-ble-data-stream")]
pub mod bluetooth_ble_data_stream;
#[cfg(feature = "bluetooth-ble-environmental")]
pub mod bluetooth_ble_environmental;
#[cfg(feature = "bluetooth-ble-file-transfer")]
pub mod bluetooth_ble_file_transfer;
#[cfg(feature = "bluetooth-ble-gamepad")]
pub mod bluetooth_ble_gamepad;
#[cfg(feature = "bluetooth-ble-heart-rate")]
pub mod bluetooth_ble_heart_rate;
#[cfg(feature = "bluetooth-ble-keyboard")]
pub mod bluetooth_ble_keyboard;
#[cfg(feature = "bluetooth-ble-mouse")]
pub mod bluetooth_ble_mouse;
#[cfg(feature = "bluetooth-ble-presenter")]
pub mod bluetooth_ble_presenter;
#[cfg(feature = "bluetooth-ble-proximity")]
pub mod bluetooth_ble_proximity;
#[cfg(feature = "bluetooth-ble-remote")]
pub mod bluetooth_ble_remote;
#[cfg(feature = "bluetooth-ble-running")]
pub mod bluetooth_ble_running;
#[cfg(feature = "bluetooth-ble-thermometer")]
pub mod bluetooth_ble_thermometer;
#[cfg(feature = "bluetooth-ble-weight-scale")]
pub mod bluetooth_ble_weight_scale;
#[cfg(feature = "bolt")]
pub mod bolt;
#[cfg(feature = "bootp")]
pub mod bootp;
#[cfg(feature = "can")]
pub mod can;
#[cfg(feature = "cassandra")]
pub mod cassandra;
#[cfg(feature = "cdp")]
pub mod cdp;
#[cfg(feature = "coap")]
pub mod coap;
#[cfg(feature = "connect_rpc")]
pub mod connect_rpc;
#[cfg(feature = "couchdb")]
pub mod couchdb;
#[cfg(feature = "datalink")]
pub mod datalink;
#[cfg(feature = "db2")]
pub mod db2;
#[cfg(feature = "dc")]
pub mod dc;
#[cfg(feature = "devp2p")]
pub mod devp2p;
#[cfg(feature = "dhcp")]
pub mod dhcp;
#[cfg(feature = "dhcpv6")]
pub mod dhcpv6;
#[cfg(feature = "dict")]
pub mod dict;
#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "docker")]
pub mod docker;
#[cfg(feature = "doh")]
pub mod doh;
#[cfg(feature = "dot")]
pub mod dot;
#[cfg(feature = "dynamo")]
pub mod dynamo;
#[cfg(feature = "eapol")]
pub mod eapol;
#[cfg(feature = "elasticsearch")]
pub mod elasticsearch;
#[cfg(feature = "etcd")]
pub mod etcd;
#[cfg(feature = "finger")]
pub mod finger;
#[cfg(feature = "ftp")]
pub mod ftp;
#[cfg(feature = "gearman")]
pub mod gearman;
#[cfg(feature = "gemini")]
pub mod gemini;
#[cfg(feature = "git")]
pub mod git;
#[cfg(feature = "gnmi")]
pub mod gnmi;
#[cfg(feature = "gopher")]
pub mod gopher;
#[cfg(feature = "grpc")]
pub mod grpc;
#[cfg(feature = "grpc-web")]
pub mod grpc_web;
#[cfg(feature = "gtp")]
pub mod gtp;
#[cfg(feature = "h323")]
pub mod h323;
#[cfg(feature = "hls")]
pub mod hls;
#[cfg(feature = "hsrp")]
pub mod hsrp;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "http2")]
pub mod http2;
#[cfg(feature = "icmp")]
pub mod icmp;
#[cfg(feature = "ident")]
pub mod ident;
#[cfg(feature = "igmp")]
pub mod igmp;
#[cfg(feature = "imap")]
pub mod imap;
#[cfg(feature = "ipp")]
pub mod ipp;
#[cfg(feature = "ipsec")]
pub mod ipsec;
#[cfg(feature = "irc")]
pub mod irc;
#[cfg(feature = "isis")]
pub mod isis;
#[cfg(feature = "jsonrpc")]
pub mod jsonrpc;
#[cfg(feature = "kafka")]
pub mod kafka;
#[cfg(feature = "kubernetes-server")]
pub mod kubernetes;
#[cfg(feature = "ldap")]
pub mod ldap;
#[cfg(feature = "lldp")]
pub mod lldp;
#[cfg(feature = "llmnr")]
pub mod llmnr;
#[cfg(feature = "m3ua")]
pub mod m3ua;
#[cfg(feature = "maven")]
pub mod maven;
#[cfg(feature = "mcp")]
pub mod mcp;
#[cfg(feature = "mdns")]
pub mod mdns;
#[cfg(feature = "memcached")]
pub mod memcached;
#[cfg(feature = "mercurial")]
pub mod mercurial;
#[cfg(feature = "modbus")]
pub mod modbus;
#[cfg(feature = "mongodb-server")]
pub mod mongodb;
#[cfg(feature = "mqtt")]
pub mod mqtt;
#[cfg(feature = "mssql")]
pub mod mssql;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(all(feature = "named_pipe", unix))]
pub mod named_pipe;
#[cfg(feature = "nats")]
pub mod nats;
#[cfg(feature = "ndp")]
pub mod ndp;
#[cfg(feature = "netbios-ns")]
pub mod netbios_ns;
#[cfg(feature = "nfc")]
pub mod nfc;
#[cfg(feature = "nfs")]
pub mod nfs;
#[cfg(feature = "ngap")]
pub mod ngap;
#[cfg(feature = "nntp")]
pub mod nntp;
#[cfg(feature = "nostr")]
pub mod nostr;
#[cfg(feature = "npm")]
pub mod npm;
#[cfg(feature = "nsq")]
pub mod nsq;
#[cfg(feature = "ntp")]
pub mod ntp;
#[cfg(feature = "oauth2")]
pub mod oauth2;
#[cfg(feature = "oci-registry")]
pub mod oci_registry;
#[cfg(feature = "ollama")]
pub mod ollama;
#[cfg(feature = "openai")]
pub mod openai;
#[cfg(feature = "openapi")]
pub mod openapi;
#[cfg(feature = "openid")]
pub mod openid;
#[cfg(feature = "openvpn")]
pub mod openvpn;
#[cfg(feature = "ospf")]
pub mod ospf;
#[cfg(feature = "otlp")]
pub mod otlp;
#[cfg(feature = "pop3")]
pub mod pop3;
#[cfg(feature = "postgresql")]
pub mod postgresql;
#[cfg(feature = "prometheus")]
pub mod prometheus;
#[cfg(feature = "proxy")]
pub mod proxy;
#[cfg(all(feature = "pty", unix))]
pub mod pty;
#[cfg(feature = "pypi")]
pub mod pypi;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "radius")]
pub mod radius;
#[cfg(feature = "rawip")]
pub mod rawip;
#[cfg(feature = "rdp")]
pub mod rdp;
#[cfg(feature = "redis")]
pub mod redis;
#[cfg(feature = "reverse-shell")]
pub mod reverse_shell;
#[cfg(feature = "rip")]
pub mod rip;
#[cfg(feature = "rss")]
pub mod rss;
#[cfg(feature = "rtp")]
pub mod rtp;
#[cfg(feature = "rtsp")]
pub mod rtsp;
#[cfg(feature = "s3")]
pub mod s3;
#[cfg(feature = "saml-idp")]
pub mod saml_idp;
#[cfg(feature = "saml-sp")]
pub mod saml_sp;
#[cfg(feature = "sip")]
pub mod sip;
#[cfg(feature = "smb")]
pub mod smb;
#[cfg(feature = "smtp")]
pub mod smtp;
#[cfg(feature = "snmp")]
pub mod snmp;
#[cfg(feature = "snowflake")]
pub mod snowflake;
#[cfg(all(feature = "socket_file", unix))]
pub mod socket_file;
#[cfg(feature = "socks5")]
pub mod socks5;
#[cfg(feature = "spark")]
pub mod spark;
#[cfg(feature = "spice")]
pub mod spice;
#[cfg(feature = "sqs")]
pub mod sqs;
#[cfg(feature = "ssdp")]
pub mod ssdp;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(all(feature = "ssh-agent", unix))]
pub mod ssh_agent;
#[cfg(all(feature = "stdio", unix))]
pub mod stdio;
#[cfg(feature = "stomp")]
pub mod stomp;
#[cfg(feature = "stp")]
pub mod stp;
#[cfg(feature = "stun")]
pub mod stun;
#[cfg(feature = "svn")]
pub mod svn;
#[cfg(feature = "syslog")]
pub mod syslog;
#[cfg(feature = "tcp")]
pub mod tcp;
#[cfg(feature = "telnet")]
pub mod telnet;
#[cfg(feature = "tftp")]
pub mod tftp;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "tor")]
pub mod tor_integration;
#[cfg(feature = "tor")]
pub mod tor_relay;
#[cfg(feature = "torrent-dht")]
pub mod torrent_dht;
#[cfg(all(
    feature = "torrent-tracker",
    feature = "torrent-dht",
    feature = "torrent-peer"
))]
pub mod torrent_integration;
#[cfg(feature = "torrent-peer")]
pub mod torrent_peer;
#[cfg(feature = "torrent-tracker")]
pub mod torrent_tracker;
#[cfg(feature = "tuntap")]
pub mod tuntap;
#[cfg(feature = "turn")]
pub mod turn;
#[cfg(feature = "udp")]
pub mod udp;
#[cfg(feature = "usb-fido2")]
pub mod usb_fido2;
#[cfg(feature = "usb-keyboard")]
pub mod usb_keyboard;
#[cfg(feature = "usb-mouse")]
pub mod usb_mouse;
#[cfg(feature = "usb-msc")]
pub mod usb_msc;
#[cfg(feature = "usb-serial")]
pub mod usb_serial;
#[cfg(feature = "usb-smartcard")]
pub mod usb_smartcard;
#[cfg(feature = "vault")]
pub mod vault;
#[cfg(feature = "vnc")]
pub mod vnc;
#[cfg(feature = "vrrp")]
pub mod vrrp;
#[cfg(feature = "webdav")]
pub mod webdav;
#[cfg(feature = "webrtc")]
pub mod webrtc;
#[cfg(feature = "webrtc")]
pub mod webrtc_signaling;
#[cfg(feature = "websocket")]
pub mod websocket;
#[cfg(feature = "whois")]
pub mod whois;
#[cfg(feature = "wireguard")]
pub mod wireguard;
#[cfg(feature = "wol")]
pub mod wol;
#[cfg(feature = "xmlrpc")]
pub mod xmlrpc;
#[cfg(feature = "xmpp")]
pub mod xmpp;
#[cfg(feature = "yarn")]
pub mod yarn;
#[cfg(feature = "zabbix")]
pub mod zabbix;
#[cfg(feature = "zookeeper")]
pub mod zookeeper;

// Shared test helpers - re-export from top-level for backward compatibility
pub use super::helpers;

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

#[cfg(feature = "fluent-forward")]
pub mod fluent_forward;
#[cfg(feature = "http3")]
pub mod http3;

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

#[cfg(feature = "tacacs")]
pub mod tacacs;

#[cfg(feature = "netconf")]
pub mod netconf;

#[cfg(feature = "rpki_rtr")]
pub mod rpki_rtr;

#[cfg(feature = "rdap")]
pub mod rdap;

#[cfg(feature = "hl7")]
pub mod hl7;

#[cfg(feature = "icap")]
pub mod icap;

#[cfg(feature = "ocpp")]
pub mod ocpp;

#[cfg(feature = "a2a")]
pub mod a2a;

#[cfg(feature = "graphql")]
pub mod graphql;

#[cfg(feature = "fastcgi")]
pub mod fastcgi;

#[cfg(feature = "redfish")]
pub mod redfish;

#[cfg(feature = "scim")]
pub mod scim;

#[cfg(feature = "socketio")]
pub mod socketio;

#[cfg(feature = "caldav")]
pub mod caldav;

#[cfg(feature = "carddav")]
pub mod carddav;

#[cfg(feature = "dicom")]
pub mod dicom;

#[cfg(feature = "acme")]
pub mod acme;

#[cfg(feature = "fix")]
pub mod fix;

#[cfg(feature = "wamp")]
pub mod wamp;

#[cfg(feature = "rtmp")]
pub mod rtmp;

#[cfg(feature = "srt")]
pub mod srt;

#[cfg(feature = "amqp1")]
pub mod amqp1;

#[cfg(feature = "thrift")]
pub mod thrift;

#[cfg(feature = "bmp")]
pub mod bmp;

#[cfg(feature = "mqtt_sn")]
pub mod mqtt_sn;

#[cfg(feature = "nbd")]
pub mod nbd;

#[cfg(feature = "managesieve")]
pub mod managesieve;

#[cfg(feature = "zenoh")]
pub mod zenoh;

#[cfg(feature = "lwm2m")]
pub mod lwm2m;

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
#[cfg(feature = "openflow")]
pub mod openflow;
#[cfg(feature = "webtransport")]
pub mod webtransport;
#[cfg(feature = "wsdiscovery")]
pub mod wsdiscovery;
#[cfg(feature = "zeromq")]
pub mod zeromq;
#[cfg(feature = "zipkin")]
pub mod zipkin;

#[cfg(feature = "diameter")]
pub mod diameter;

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

#[cfg(feature = "soulseek")]
pub mod soulseek;

#[cfg(feature = "soulseek_peer")]
pub mod soulseek_peer;

#[cfg(feature = "adc")]
pub mod adc;

#[cfg(feature = "adc_peer")]
pub mod adc_peer;

#[cfg(feature = "dc_peer")]
pub mod dc_peer;

#[cfg(feature = "gnutella")]
pub mod gnutella;
