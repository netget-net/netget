// Shared E2E test helpers for NetGet

pub mod child_guard;
pub mod client;
pub mod common;
pub mod ethereum;
pub mod event_trigger;
pub mod example_test_framework;
pub mod grpc_peer;
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
#[cfg(all(unix, target_os = "linux"))]
pub mod netns;
pub mod ollama_test_builder;
pub mod pcap_oracle;
pub mod real_server;
pub mod recording_relay;
pub mod server;
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

pub mod quic_peer;

pub mod prometheus_remote_write;

pub mod connect_rpc_peer;
pub mod gnmi_peer;
pub mod grpcweb_peer;

pub mod netflow_v9;

pub mod tacacs;

pub mod diameter;

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

pub mod dav;

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

pub mod epp;
pub mod inetd;
pub mod jmap;
pub mod restconf;
pub mod webtransport;

pub mod ics;

pub mod p2p;
pub mod radsec_pki;

pub mod kubo;
