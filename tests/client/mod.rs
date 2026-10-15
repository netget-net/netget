//! Client protocol e2e tests

#[cfg(feature = "amqp")]
pub mod amqp;
#[cfg(feature = "arp")]
pub mod arp;
#[cfg(feature = "bgp")]
pub mod bgp;
#[cfg(feature = "bitcoin")]
pub mod bitcoin;
#[cfg(feature = "bluetooth-ble-client")]
pub mod bluetooth;
#[cfg(feature = "bootp")]
pub mod bootp;
#[cfg(feature = "cassandra")]
pub mod cassandra;
#[cfg(feature = "coap")]
pub mod coap;
#[cfg(feature = "connect_rpc")]
pub mod connect_rpc;
#[cfg(feature = "couchdb")]
pub mod couchdb;
#[cfg(feature = "datalink")]
pub mod datalink;
#[cfg(feature = "dc")]
pub mod dc;
#[cfg(feature = "devp2p")]
pub mod devp2p;
#[cfg(feature = "dhcp")]
pub mod dhcp;
#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "doh")]
pub mod doh;
#[cfg(feature = "dot")]
pub mod dot;
#[cfg(any(feature = "dynamo", feature = "dynamodb"))]
pub mod dynamodb;
#[cfg(feature = "elasticsearch")]
pub mod elasticsearch;
#[cfg(feature = "etcd")]
pub mod etcd;
#[cfg(feature = "finger")]
pub mod finger;
#[cfg(feature = "ftp")]
pub mod ftp;
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
#[cfg(feature = "h323")]
pub mod h323;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "http2")]
pub mod http2;
#[cfg(feature = "http3")]
pub mod http3;
#[cfg(feature = "http_proxy")]
pub mod http_proxy;
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
#[cfg(feature = "irc")]
pub mod irc;
#[cfg(feature = "isis")]
pub mod isis;
#[cfg(feature = "jsonrpc")]
pub mod jsonrpc;
#[cfg(feature = "kafka")]
pub mod kafka;
#[cfg(feature = "kubernetes")]
pub mod kubernetes;
#[cfg(feature = "ldap")]
pub mod ldap;
#[cfg(feature = "llmnr")]
pub mod llmnr;
#[cfg(feature = "maven")]
pub mod maven;
#[cfg(feature = "mcp")]
pub mod mcp;
#[cfg(feature = "mdns")]
pub mod mdns;
#[cfg(feature = "memcached")]
pub mod memcached;
#[cfg(feature = "modbus")]
pub mod modbus;
#[cfg(feature = "mongodb")]
pub mod mongodb;
#[cfg(feature = "mqtt")]
pub mod mqtt;
#[cfg(feature = "mssql")]
pub mod mssql;
#[cfg(feature = "mysql")]
pub mod mysql;
#[cfg(feature = "nats")]
pub mod nats;
#[cfg(feature = "netbios-ns")]
pub mod netbios_ns;
#[cfg(feature = "nfc-client")]
pub mod nfc;
#[cfg(feature = "nfs")]
pub mod nfs;
#[cfg(feature = "nntp")]
pub mod nntp;
#[cfg(feature = "npm")]
pub mod npm;
#[cfg(feature = "ntp")]
pub mod ntp;
#[cfg(feature = "oauth2")]
pub mod oauth2;
#[cfg(feature = "ollama")]
pub mod ollama;
#[cfg(feature = "openai")]
pub mod openai;
#[cfg(feature = "openapi")]
pub mod openapi;
#[cfg(feature = "openidconnect")]
pub mod openidconnect;
#[cfg(feature = "ospf")]
pub mod ospf;
#[cfg(feature = "pop3")]
pub mod pop3;
#[cfg(feature = "postgresql")]
pub mod postgresql;
#[cfg(feature = "pypi")]
pub mod pypi;
#[cfg(feature = "radius")]
pub mod radius;
#[cfg(feature = "redis")]
pub mod redis;
#[cfg(feature = "rip")]
pub mod rip;
#[cfg(feature = "rss")]
pub mod rss;
#[cfg(feature = "s3")]
pub mod s3;
#[cfg(feature = "saml")]
pub mod saml;
#[cfg(feature = "sip")]
pub mod sip;
#[cfg(feature = "smb")]
pub mod smb;
#[cfg(feature = "smtp")]
pub mod smtp;
#[cfg(feature = "snmp")]
pub mod snmp;
#[cfg(feature = "socket_file")]
pub mod socket_file;
#[cfg(feature = "socks5")]
pub mod socks5;
#[cfg(feature = "sqs")]
pub mod sqs;
#[cfg(feature = "ssdp")]
pub mod ssdp;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(all(feature = "ssh-agent", unix))]
pub mod ssh_agent;
#[cfg(feature = "stomp")]
pub mod stomp;
#[cfg(feature = "stun")]
pub mod stun;
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
pub mod tor;
#[cfg(feature = "torrent-dht")]
pub mod torrent_dht;
#[cfg(feature = "torrent-peer")]
pub mod torrent_peer;
#[cfg(feature = "torrent-tracker")]
pub mod torrent_tracker;
#[cfg(feature = "turn")]
pub mod turn;
#[cfg(feature = "udp")]
pub mod udp;
#[cfg(feature = "usb")]
pub mod usb;
#[cfg(feature = "vnc")]
pub mod vnc;
#[cfg(feature = "webdav")]
pub mod webdav;
#[cfg(feature = "webrtc")]
pub mod webrtc;
#[cfg(feature = "websocket")]
pub mod websocket;
#[cfg(feature = "whois")]
pub mod whois;
#[cfg(feature = "wireguard")]
pub mod wireguard;
#[cfg(feature = "xmlrpc")]
pub mod xmlrpc;
#[cfg(feature = "xmpp")]
pub mod xmpp;
#[cfg(feature = "zookeeper")]
pub mod zookeeper;

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

#[cfg(feature = "loki")]
pub mod loki;

#[cfg(feature = "otlp")]
pub mod otlp;

#[cfg(feature = "sflow")]
pub mod sflow;

#[cfg(feature = "vault")]
pub mod vault;

#[cfg(feature = "prometheus-remote-write")]
pub mod prometheus_remote_write;

#[cfg(feature = "nostr")]
pub mod nostr;

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
#[cfg(feature = "zeromq")]
pub mod zeromq;
#[cfg(feature = "zipkin")]
pub mod zipkin;

#[cfg(feature = "diameter")]
pub mod diameter;

#[cfg(feature = "bolt")]
pub mod bolt;

#[cfg(feature = "oci-registry")]
pub mod oci_registry;

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
