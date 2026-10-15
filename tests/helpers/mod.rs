// Shared E2E test helpers for NetGet

pub mod child_guard;
pub mod client;
pub mod common;
#[cfg(feature = "devp2p")]
pub mod ethereum;
pub mod event_trigger;
pub mod example_test_framework;
#[cfg(feature = "grpc")]
pub mod grpc_peer;
#[cfg(feature = "h323")]
pub mod h323;
#[cfg(feature = "h323")]
pub mod h323_peers;
pub mod http_bounds;
pub mod inbound_limit;
pub mod llm_live;
pub mod llm_live_case;
pub mod mock;
pub mod mock_action_names;
pub mod mock_builder;
pub mod mock_config;
pub mod mock_matcher;
pub mod mock_ollama;
pub mod netget;
#[cfg(all(any(feature = "vxlan", feature = "sunrpc"), target_os = "linux"))]
pub mod netns;
pub mod ollama_test_builder;
pub mod pcap_oracle;
pub mod real_server;
#[cfg(any(feature = "kerberos", feature = "spice", feature = "openflow"))]
pub mod recording_relay;
pub mod server;
#[cfg(feature = "sflow")]
pub mod sflow;
pub mod startup_ports;
pub mod usbip_bounds;
pub mod usbip_client;

// Re-export commonly used types and functions for convenience
pub use self::netget::NetGetConfig;
pub use client::{start_netget_client, wait_for_client_startup};
pub use common::{
    retry, retry_with_backoff, wait_for_server_listening, with_aws_sdk_timeout,
    with_cassandra_timeout, with_client_timeout, with_timeout, E2EResult,
};
pub use event_trigger::EventTrigger;
pub use example_test_framework::{ProtocolExampleTest, TestReport};
pub use mock_config::{
    MockLlmConfig, MockResponse, MockRule, ResponseGenerator, SerializedMockRule,
};
pub use mock_matcher::{LlmContext, MockMatcher};
pub use ollama_test_builder::OllamaTestBuilder;
pub use server::{start_netget_server, wait_for_server_startup};

#[cfg(any(feature = "quic", feature = "http3"))]
pub mod quic_peer;

#[cfg(feature = "prometheus-remote-write")]
pub mod prometheus_remote_write;

#[cfg(feature = "connect_rpc")]
pub mod connect_rpc_peer;
#[cfg(feature = "gnmi")]
pub mod gnmi_peer;
#[cfg(feature = "grpc-web")]
pub mod grpcweb_peer;

#[cfg(feature = "netflow-v9")]
pub mod netflow_v9;

#[cfg(feature = "tacacs")]
pub mod tacacs;

#[cfg(feature = "diameter")]
pub mod diameter;

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

#[cfg(any(feature = "caldav", feature = "carddav"))]
pub mod dav;

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

#[cfg(feature = "epp")]
pub mod epp;
#[cfg(feature = "inetd")]
pub mod inetd;
#[cfg(feature = "jmap")]
pub mod jmap;
#[cfg(feature = "restconf")]
pub mod restconf;
#[cfg(feature = "webtransport")]
pub mod webtransport;

#[cfg(any(
    feature = "s7comm",
    feature = "ethernet_ip",
    feature = "dnp3",
    feature = "iec104",
    feature = "bacnet",
    feature = "opcua"
))]
pub mod ics;

#[cfg(any(
    feature = "adc",
    feature = "dc_peer",
    feature = "soulseek",
    feature = "gnutella",
    feature = "nntp"
))]
pub mod p2p;
#[cfg(feature = "radsec")]
pub mod radsec_pki;

#[cfg(feature = "libp2p")]
pub mod kubo;
