//! Client protocol registry
//!
//! This module provides a centralized registry that maps client protocol names
//! to their client implementations. It enables trait-based client lookup
//! and keyword-based parsing for client connections.

use crate::llm::actions::Client;
use std::collections::HashMap;
use std::sync::Arc;

/// Global client protocol registry mapping protocol names to client implementations
pub struct ClientRegistry {
    /// Maps protocol name (e.g., "TCP", "HTTP") to client implementation
    protocols: HashMap<String, Arc<dyn Client>>,
    /// Maps lowercase keywords to protocol name for fast parsing
    keyword_map: HashMap<String, String>,
}

impl ClientRegistry {
    /// Create a new client protocol registry
    fn new() -> Self {
        tracing::debug!("ClientRegistry::new() - Creating new client registry");
        let mut registry = Self {
            protocols: HashMap::new(),
            keyword_map: HashMap::new(),
        };

        // Register every client protocol this platform builds
        tracing::debug!("ClientRegistry::new() - Registering client protocols");
        registry.register_protocols();
        tracing::debug!("ClientRegistry::new() - Client protocols registered");

        tracing::debug!("ClientRegistry::new() - Building keyword map");
        registry.build_keyword_map();
        tracing::debug!("ClientRegistry::new() - Keyword map built");

        // Validate that no keywords overlap between protocols
        tracing::debug!("ClientRegistry::new() - Validating keyword uniqueness");
        registry.validate_keyword_uniqueness();
        tracing::debug!("ClientRegistry::new() - Keyword uniqueness validated");

        tracing::debug!("ClientRegistry::new() - Client registry created");
        registry
    }

    /// Register all available client protocols based on compiled features
    fn register_protocols(&mut self) {
        #[cfg(all(unix, feature = "libpcap"))]
        self.register(Arc::new(crate::client::arp::ArpClientProtocol::new()));

        self.register(Arc::new(crate::client::bgp::BgpClientProtocol::new()));

        self.register(Arc::new(
            crate::client::bitcoin::BitcoinClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::devp2p::actions::Devp2pClientProtocol::new(),
        ));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(
            crate::client::bluetooth::BluetoothClientProtocol::new(),
        ));

        self.register(Arc::new(crate::client::bootp::BootpClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::cassandra::CassandraClientProtocol::new(),
        ));

        #[cfg(all(unix, feature = "libpcap"))]
        self.register(Arc::new(
            crate::client::datalink::DataLinkClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::dc_peer::actions::DcPeerClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::adc::actions::AdcClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::adc_peer::actions::AdcPeerClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::soulseek::actions::SoulseekClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::soulseek_peer::actions::SoulseekPeerClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::gnutella::actions::GnutellaClientProtocol::new(),
        ));

        self.register(Arc::new(crate::client::dc::DcClientProtocol::new()));

        self.register(Arc::new(crate::client::dhcp::DhcpClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::dns::DnsClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::doh::DohClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::doq::actions::DoqClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::dot::DotClientProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(
            crate::client::dynamodb::DynamoDbClientProtocol::new(),
        ));

        self.register(Arc::new(
            crate::client::elasticsearch::ElasticsearchClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::etcd::EtcdClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::git::GitClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::zookeeper::ZookeeperClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::grpc::GrpcClientProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::gnmi::actions::GnmiClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::grpc_web::actions::GrpcWebClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::connect_rpc::actions::ConnectRpcClientProtocol::new(),
        ));

        {
            tracing::debug!("ClientRegistry: Registering HTTP client protocol");
            self.register(Arc::new(crate::client::http::HttpClientProtocol::new()));
            tracing::debug!("ClientRegistry: HTTP client protocol registered");
        }

        self.register(Arc::new(crate::client::http2::Http2ClientProtocol::new()));

        // Raw QUIC and RFC 9114 HTTP/3 have distinct client/server registrations.
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::quic::actions::QuicClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::http3::Http3ClientProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(
            crate::client::http_proxy::HttpProxyClientProtocol::new(),
        ));

        #[cfg(unix)]
        self.register(Arc::new(crate::client::igmp::IgmpClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::imap::ImapClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::ipp::IppClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::irc::IrcClientProtocol::new()));

        #[cfg(all(unix, feature = "libpcap"))]
        self.register(Arc::new(crate::client::isis::IsisClientProtocol::new()));

        self.register(Arc::new(
            crate::client::jsonrpc::JsonRpcClientProtocol::new(),
        ));

        self.register(Arc::new(crate::client::kafka::KafkaClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::kubernetes::KubernetesClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::ldap::LdapClientProtocol::new()));

        self.register(Arc::new(crate::client::maven::MavenClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::mcp::McpClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::mdns::MdnsClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::mqtt::MqttClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::amqp::AmqpClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::mysql::MysqlClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::mongodb::MongodbClientProtocol::new(),
        ));

        #[cfg(unix)]
        self.register(Arc::new(crate::client::nfs::NfsClientProtocol::new()));

        #[cfg(all(unix, feature = "pcsc"))]
        self.register(Arc::new(crate::client::nfc::NfcClientProtocol));

        self.register(Arc::new(crate::client::nntp::NntpClientProtocol::new()));

        self.register(Arc::new(crate::client::npm::NpmClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::ntp::NtpClientProtocol::new()));

        self.register(Arc::new(crate::client::oauth2::OAuth2ClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::openai::OpenAiClientProtocol::new()));

        self.register(Arc::new(crate::client::ollama::OllamaClientProtocol::new()));

        self.register(Arc::new(
            crate::client::openapi::OpenApiClientProtocol::new(),
        ));

        self.register(Arc::new(
            crate::client::openidconnect::OpenIdConnectClientProtocol::new(),
        ));

        #[cfg(unix)]
        self.register(Arc::new(crate::client::ospf::OspfClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::otlp::actions::OtlpClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::postgresql::PostgresqlClientProtocol::new(),
        ));

        self.register(Arc::new(crate::client::pypi::PypiClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::mssql::MssqlClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::redis::RedisClientProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::client::icmp::IcmpClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::couchdb::CouchDbClientProtocol::new(),
        ));

        self.register(Arc::new(crate::client::tftp::TftpClientProtocol::new()));

        self.register(Arc::new(crate::client::rss::RssClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::rip::RipClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::s3::S3ClientProtocol::new()));

        self.register(Arc::new(crate::client::saml::SamlClientProtocol::new()));

        self.register(Arc::new(crate::client::sip::SipClientProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::h323::actions::H323ClientProtocol::new(),
        ));

        #[cfg(all(unix, feature = "libsmbclient"))]
        self.register(Arc::new(crate::client::smb::SmbClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::smtp::SmtpClientProtocol::new()));

        self.register(Arc::new(crate::client::ftp::FtpClientProtocol::new()));

        self.register(Arc::new(crate::client::pop3::Pop3ClientProtocol::new()));

        self.register(Arc::new(crate::client::snmp::SnmpClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::socks5::Socks5ClientProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(
            crate::client::socket_file::SocketFileClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::sqs::SqsClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::ssh::SshClientProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(
            crate::client::ssh_agent::SshAgentClientProtocol::new(),
        ));

        #[cfg(unix)]
        self.register(Arc::new(crate::client::stun::StunClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::diameter::actions::DiameterClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::tacacs::actions::TacacsClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::netconf::actions::NetconfClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::rpki_rtr::actions::RpkiRtrClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::rdap::actions::RdapClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::hl7::actions::Hl7ClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::icap::actions::IcapClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::s7comm::actions::S7commClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::ethernet_ip::actions::EthernetIpClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::dnp3::actions::Dnp3ClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::iec104::actions::Iec104ClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::bacnet::actions::BacnetClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::opcua::actions::OpcuaClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::ocpp::actions::OcppClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::a2a::actions::A2aClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::graphql::actions::GraphqlClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::fastcgi::actions::FastcgiClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::redfish::actions::RedfishClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::scim::actions::ScimClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::socketio::actions::SocketIoClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::caldav::actions::CalDavClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::carddav::actions::CardDavClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::dicom::actions::DicomClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::acme::actions::AcmeClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::fix::actions::FixClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::wamp::actions::WampClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::rtmp::actions::RtmpClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::srt::actions::SrtClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::amqp1::actions::Amqp1ClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::thrift::actions::ThriftClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::bmp::actions::BmpClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::mqtt_sn::actions::MqttSnClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::nbd::actions::NbdClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::managesieve::actions::ManageSieveClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::zenoh::actions::ZenohClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::lwm2m::actions::Lwm2mClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::restconf::actions::RestconfClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::webtransport::actions::WebTransportClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::jmap::actions::JmapClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::epp::actions::EppClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::lmtp::actions::LmtpClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::lpd::actions::LpdClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::inetd::actions::EchoClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::inetd::actions::DiscardClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::inetd::actions::DaytimeClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::inetd::actions::QotdClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::inetd::actions::ChargenClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::inetd::actions::TimeClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::rcon::actions::RconClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::a2s::actions::A2sClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::minecraft::actions::MinecraftClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::ninep::actions::NinepClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::zeromq::actions::ZeromqClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::smpp::actions::SmppClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::clickhouse::actions::ClickhouseClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::msgpack_rpc::actions::MsgpackRpcClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::zipkin::actions::ZipkinClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::capnp_rpc::actions::CapnpRpcClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::knx::actions::KnxClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::consul::actions::ConsulClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::milter::actions::MilterClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::anthropic::actions::AnthropicClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::radsec::actions::RadsecClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::dbus::actions::DbusClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::bfd::actions::BfdClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::vxlan::actions::VxlanClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::openflow::actions::OpenFlowClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::profinet::actions::ProfinetClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::ethercat::actions::EthercatClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::mbus::actions::MbusClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::rsync::actions::RsyncClientProtocol::new(),
        ));
        #[cfg(unix)]
        self.register(Arc::new(
            crate::client::rdp::actions::RdpClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::spice::actions::SpiceClientProtocol::new(),
        ));
        #[cfg(unix)]
        self.register(Arc::new(
            crate::client::m3ua::actions::M3uaClientProtocol::new(),
        ));
        #[cfg(unix)]
        self.register(Arc::new(
            crate::client::ngap::actions::NgapClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::pfcp::actions::PfcpClientProtocol::new(),
        ));
        self.register(Arc::new(
            crate::client::gtp::actions::GtpClientProtocol::new(),
        ));
        self.register(Arc::new(
            crate::client::db2::actions::Db2ClientProtocol::new(),
        ));
        self.register(Arc::new(
            crate::client::snowflake::actions::SnowflakeClientProtocol::new(),
        ));
        self.register(Arc::new(
            crate::client::spark::actions::SparkClientProtocol::new(),
        ));
        self.register(Arc::new(
            crate::client::yarn::actions::YarnClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::matrix::actions::MatrixClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::libp2p::actions::Libp2pClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::sunrpc::actions::SunRpcClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::guacamole::actions::GuacamoleClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::activitypub::actions::ActivityPubClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::stratum::actions::StratumClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::stratum_v2::actions::StratumV2ClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::pulsar::actions::PulsarClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::tr069::actions::Tr069ClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::sse::actions::SseClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::zabbix::actions::ZabbixClientProtocol::new(),
        ));
        self.register(Arc::new(
            crate::client::rtp::actions::RtpClientProtocol::new(),
        ));
        self.register(Arc::new(
            crate::client::rtsp::actions::RtspClientProtocol::new(),
        ));
        self.register(Arc::new(
            crate::client::hls::actions::HlsClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::wsdiscovery::actions::WsDiscoveryClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::onvif::actions::OnvifClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::kerberos::actions::KerberosClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::x11::actions::X11ClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::netflow_v9::actions::NetflowV9ClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::ipfix::actions::IpfixClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::loki::actions::LokiClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::influxdb::actions::InfluxDbClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::prometheus_remote_write::actions::PrometheusRemoteWriteClientProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::sflow::actions::SflowClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::fluent_forward::actions::FluentForwardClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::gelf::actions::GelfClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::graphite::actions::GraphiteClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::statsd::actions::StatsdClientProtocol::new(),
        ));

        self.register(Arc::new(crate::client::syslog::SyslogClientProtocol::new()));

        self.register(Arc::new(crate::client::tcp::TcpClientProtocol::new()));

        self.register(Arc::new(crate::client::telnet::TelnetClientProtocol::new()));

        self.register(Arc::new(crate::client::tls::TlsClientProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::client::tor::TorClientProtocol::new()));

        self.register(Arc::new(
            crate::client::torrent_dht::TorrentDhtClientProtocol::new(),
        ));

        self.register(Arc::new(
            crate::client::torrent_peer::TorrentPeerClientProtocol::new(),
        ));

        self.register(Arc::new(
            crate::client::torrent_tracker::TorrentTrackerClientProtocol::new(),
        ));

        #[cfg(unix)]
        self.register(Arc::new(crate::client::turn::TurnClientProtocol::new()));

        self.register(Arc::new(crate::client::udp::UdpClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::usb::UsbClientProtocol::new()));

        self.register(Arc::new(crate::client::vnc::VncClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::webdav::WebdavClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::webrtc::WebRtcClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::websocket::WebSocketClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::gemini::GeminiClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::dict::DictClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::beanstalkd::BeanstalkdClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::vault::VaultClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::bolt::BoltClientProtocol::new()));

        self.register(Arc::new(
            crate::client::oci_registry::OciRegistryClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::nostr::NostrClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::prometheus::PrometheusClientProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::docker::DockerClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::gearman::GearmanClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::nsq::NsqClientProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::client::nut::actions::NutClientProtocol::new(),
        ));

        self.register(Arc::new(crate::client::whois::WhoisClientProtocol::new()));
        self.register(Arc::new(crate::client::stomp::StompClientProtocol::new()));
        self.register(Arc::new(
            crate::client::netbios_ns::NetbiosNsClientProtocol::new(),
        ));
        self.register(Arc::new(crate::client::nats::NatsClientProtocol::new()));
        self.register(Arc::new(
            crate::client::memcached::MemcachedClientProtocol::new(),
        ));
        self.register(Arc::new(crate::client::modbus::ModbusClientProtocol::new()));
        self.register(Arc::new(crate::client::coap::CoapClientProtocol::new()));
        self.register(Arc::new(crate::client::radius::RadiusClientProtocol::new()));
        self.register(Arc::new(crate::client::ssdp::SsdpClientProtocol::new()));
        self.register(Arc::new(crate::client::gopher::GopherClientProtocol::new()));
        self.register(Arc::new(crate::client::finger::FingerClientProtocol::new()));
        self.register(Arc::new(crate::client::ident::IdentClientProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::llmnr::LlmnrClientProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(
            crate::client::wireguard::WireguardClientProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::client::xmlrpc::XmlRpcClientProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::client::xmpp::XmppClientProtocol::new()));
    }

    /// Build keyword map for fast protocol parsing
    fn build_keyword_map(&mut self) {
        for (protocol_name, protocol) in &self.protocols {
            // Add all protocol keywords
            for keyword in protocol.keywords() {
                let lower = keyword.to_lowercase();
                // Store the hyphen/space-normalized form too. Input is normalized
                // before lookup, so a keyword declared as "ssh-agent" was previously
                // unreachable: "ssh_agent" never contains "ssh-agent".
                let normalized = lower.replace(['-', ' '], "_");
                self.keyword_map.insert(lower, protocol_name.clone());
                self.keyword_map.insert(normalized, protocol_name.clone());
            }

            // Also add the full stack name as a keyword
            // This allows parsing inputs like "eth>ip>tcp>http" or "ETH>IP>UDP>DNS"
            let stack_name = protocol.stack_name().to_lowercase();
            self.keyword_map.insert(stack_name, protocol_name.clone());
        }
    }

    /// Validate that no two protocols share the same keyword
    ///
    /// This ensures keyword uniqueness across all registered protocols.
    /// Panics if overlapping keywords are detected.
    fn validate_keyword_uniqueness(&self) {
        use std::collections::HashMap;

        // Build a map: keyword (lowercase) -> Vec<(protocol_name, keyword_source)>
        // keyword_source is either "keyword" or "stack_name"
        let mut keyword_to_protocols: HashMap<String, Vec<(String, String)>> = HashMap::new();

        for (protocol_name, protocol) in &self.protocols {
            // Collect all keywords from keywords()
            for keyword in protocol.keywords() {
                let key = keyword.to_lowercase();
                keyword_to_protocols
                    .entry(key)
                    .or_default()
                    .push((protocol_name.clone(), format!("keyword '{}'", keyword)));
            }

            // Also collect the stack name as a keyword
            let stack_name = protocol.stack_name();
            let key = stack_name.to_lowercase();
            keyword_to_protocols.entry(key).or_default().push((
                protocol_name.clone(),
                format!("stack_name '{}'", stack_name),
            ));
        }

        // Only count overlaps across DISTINCT protocols — a protocol whose keyword
        // equals its own stack_name contributes two entries for one keyword and is
        // not an overlap.
        let mut overlaps = Vec::new();
        for (keyword, protocols) in &keyword_to_protocols {
            let distinct: std::collections::HashSet<&String> =
                protocols.iter().map(|(name, _)| name).collect();
            if distinct.len() > 1 {
                overlaps.push((keyword.clone(), protocols.clone()));
            }
        }

        // Development-time advisory only — log at DEBUG (netget.log) rather than
        // spamming the TUI on every startup. `test_keyword_overlaps` is the gate.
        if !overlaps.is_empty() {
            use tracing::debug;
            debug!("Client keyword overlaps detected between protocols:");

            for (keyword, protocols) in &overlaps {
                debug!("  Keyword '{}' is used by:", keyword);
                for (protocol_name, source) in protocols {
                    debug!("    - {} ({})", protocol_name, source);
                }
            }

            debug!("Note: Each keyword should ideally be unique to a single protocol.");
            debug!(
                "      Run 'cargo test test_keyword_overlaps -- --ignored' to see all overlaps."
            );
        }
    }

    /// Register a client protocol implementation
    #[allow(dead_code)]
    fn register(&mut self, protocol: Arc<dyn Client>) {
        let protocol_name = protocol.protocol_name().to_string();
        self.protocols.insert(protocol_name, protocol);
    }

    /// Get client protocol implementation by protocol name
    pub fn get(&self, protocol_name: &str) -> Option<Arc<dyn Client>> {
        self.protocols.get(protocol_name).cloned()
    }

    /// Resolve user/LLM-supplied input (a protocol name or keyword) to a
    /// registered client protocol implementation.
    ///
    /// Mirrors `ServerRegistry::resolve()`: unlike calling `get()` /
    /// `parse_from_str()` directly, a failure here distinguishes "this
    /// protocol exists but wasn't compiled into this build" from "this is not
    /// a real NetGet client protocol at all", and offers a "did you mean"
    /// suggestion for likely typos — see [`ClientProtocolLookupError`].
    pub fn resolve(&self, input: &str) -> Result<Arc<dyn Client>, ClientProtocolLookupError> {
        // Exact canonical name first — handles a name already resolved by a
        // previous call.
        if let Some(p) = self.get(input) {
            return Ok(p);
        }

        // Fall back to keyword / stack-name parsing (case-insensitive,
        // hyphen/space tolerant) against currently-compiled protocols.
        if let Some(name) = self.parse_from_str(input) {
            if let Some(p) = self.get(&name) {
                return Ok(p);
            }
        }

        // Not found among compiled-in protocols. Check whether `input` names a
        // real NetGet client protocol that simply wasn't compiled into this
        // build.
        let input_norm = input.to_lowercase().replace(['-', ' '], "_");
        for (name, requires) in ALL_KNOWN_CLIENT_PROTOCOLS {
            let name_norm = name.to_lowercase().replace(['-', ' '], "_");
            if name_norm == input_norm {
                return Err(ClientProtocolLookupError::NotCompiled { name, requires });
            }
        }

        // Truly unknown. Offer a "did you mean" suggestion via edit distance
        // against every known client protocol name, compiled in or not.
        Err(ClientProtocolLookupError::Unknown {
            input: input.to_string(),
            suggestion: suggest_client_protocol_name(input, ALL_KNOWN_CLIENT_PROTOCOLS),
        })
    }

    /// Parse client protocol from user input string
    ///
    /// Attempts to match keywords from registered client protocols.
    /// Returns protocol name if match found, None otherwise.
    pub fn parse_from_str(&self, input: &str) -> Option<String> {
        let input_lower = input.to_lowercase();
        // Normalize hyphens and spaces to underscores for consistent matching
        // e.g., "bluetooth-ble" -> "bluetooth_ble", "WebRTC Signaling" -> "webrtc_signaling"
        let input_normalized = input_lower.replace(['-', ' '], "_");

        // First, try exact match with stack names (for LLM-generated responses)
        for (protocol_name, protocol) in &self.protocols {
            let stack_lower = protocol.stack_name().to_lowercase();
            let stack_normalized = stack_lower.replace(['-', ' '], "_");
            if input_lower == stack_lower
                || input_normalized == stack_lower
                || input_normalized == stack_normalized
            {
                return Some(protocol_name.clone());
            }
        }

        // An exact keyword match wins outright, before any substring test.
        if let Some(protocol_name) = self
            .keyword_map
            .get(&input_normalized)
            .or_else(|| self.keyword_map.get(&input_lower))
        {
            return Some(protocol_name.clone());
        }

        // Substring matching, longest keyword first.
        //
        // This used to return the first `contains()` hit while iterating a HashMap,
        // whose order is unspecified. "ssh_agent" contains both "ssh" and "agent", so
        // it resolved to SSH or to SSH Agent depending on hash order -- creating an
        // ssh_agent client could silently produce an SSH client instead, and the same
        // input could resolve differently between runs or between feature sets.
        // Preferring the longest matching keyword makes the more specific protocol
        // win, and the name tie-break makes the answer identical on every run.
        let mut best: Option<(usize, &String)> = None;
        for (keyword, protocol_name) in &self.keyword_map {
            if !(input_lower.contains(keyword) || input_normalized.contains(keyword)) {
                continue;
            }
            let better = match best {
                None => true,
                Some((best_len, best_name)) => {
                    keyword.len() > best_len
                        || (keyword.len() == best_len && protocol_name < best_name)
                }
            };
            if better {
                best = Some((keyword.len(), protocol_name));
            }
        }
        best.map(|(_, name)| name.clone())
    }

    /// List all registered client protocol names
    pub fn list_protocols(&self) -> Vec<String> {
        self.protocols.keys().cloned().collect()
    }

    /// Check if a protocol is registered
    pub fn has_protocol(&self, protocol_name: &str) -> bool {
        self.protocols.contains_key(protocol_name)
    }

    /// Get all registered client protocols
    pub fn get_all(&self) -> Vec<Arc<dyn Client>> {
        self.protocols.values().cloned().collect()
    }

    /// Get protocols that are excluded due to missing dependencies
    ///
    /// Returns a map of protocol name -> list of missing dependencies
    pub fn get_excluded_protocols(
        &self,
        caps: &crate::privilege::SystemCapabilities,
    ) -> std::collections::HashMap<String, Vec<super::dependencies::ProtocolDependency>> {
        let mut excluded = std::collections::HashMap::new();

        for (protocol_name, protocol) in &self.protocols {
            let dependencies = protocol.get_dependencies();
            let mut missing = Vec::new();

            for dep in dependencies {
                if !dep.is_available(caps) {
                    missing.push(dep);
                }
            }

            if !missing.is_empty() {
                excluded.insert(protocol_name.clone(), missing);
            }
        }

        excluded
    }

    /// Get protocols that are available (have all dependencies met)
    ///
    /// Returns a list of protocol names that can be used
    pub fn get_available_protocols(
        &self,
        caps: &crate::privilege::SystemCapabilities,
    ) -> Vec<String> {
        let excluded = self.get_excluded_protocols(caps);

        self.protocols
            .keys()
            .filter(|name| !excluded.contains_key(*name))
            .cloned()
            .collect()
    }

    /// Check if a specific protocol is available (has all dependencies met)
    pub fn is_protocol_available(
        &self,
        protocol_name: &str,
        caps: &crate::privilege::SystemCapabilities,
    ) -> bool {
        if let Some(protocol) = self.get(protocol_name) {
            let dependencies = protocol.get_dependencies();
            dependencies.iter().all(|dep| dep.is_available(caps))
        } else {
            false
        }
    }
}

/// All client protocol names known to the netget codebase, paired with what a build needs to
/// include each one ("a native build (not the browser)", "the `libpcap` feature, on Unix",
/// …) — independent of what *this* build includes. This lets [`ClientRegistry::resolve`] tell
/// "protocol exists but wasn't compiled in" apart from "no such protocol", and say why.
///
/// Kept manually in sync with the platform gates on the registrations in
/// `register_protocols()` above. This is the one acceptable central touchpoint
/// per CLAUDE.md's decentralization policy (it plays the same role as the
/// `register()` calls themselves) — when adding a new client protocol, add its
/// (canonical name, requirement) pair here too.
pub(crate) const ALL_KNOWN_CLIENT_PROTOCOLS: &[(&str, &str)] = &[
    ("BGP", "nothing (every build has it)"),
    ("BOOTP", "nothing (every build has it)"),
    ("Cassandra", "a native build (not the browser)"),
    ("DataLink", "the `libpcap` feature, on Unix"),
    ("NMDC Peer", "a native build (not the browser)"),
    ("ADC", "a native build (not the browser)"),
    ("ADC Peer", "a native build (not the browser)"),
    ("Soulseek", "a native build (not the browser)"),
    ("Soulseek Peer", "a native build (not the browser)"),
    ("Gnutella", "a native build (not the browser)"),
    ("DC", "nothing (every build has it)"),
    ("DHCP", "nothing (every build has it)"),
    ("DNS", "a native build (not the browser)"),
    ("DNS-over-HTTPS", "a native build (not the browser)"),
    ("DoT", "a native build (not the browser)"),
    ("DoQ", "a native build (not the browser)"),
    ("etcd", "a native build (not the browser)"),
    ("ZooKeeper", "a native build (not the browser)"),
    ("gRPC", "a native build (not the browser)"),
    ("gRPC-Web", "a native build (not the browser)"),
    ("gNMI", "a native build (not the browser)"),
    ("ConnectRPC", "a native build (not the browser)"),
    ("TACACS", "a native build (not the browser)"),
    ("NETCONF", "a native build (not the browser)"),
    ("RPKI-RTR", "a native build (not the browser)"),
    ("RDAP", "a native build (not the browser)"),
    ("HL7", "a native build (not the browser)"),
    ("ICAP", "a native build (not the browser)"),
    ("OCPP", "a native build (not the browser)"),
    ("A2A", "a native build (not the browser)"),
    ("GraphQL", "a native build (not the browser)"),
    ("FastCGI", "a native build (not the browser)"),
    ("Redfish", "a native build (not the browser)"),
    ("SCIM", "a native build (not the browser)"),
    ("Socket.IO", "a native build (not the browser)"),
    ("CalDAV", "a native build (not the browser)"),
    ("CardDAV", "a native build (not the browser)"),
    ("DICOM", "a native build (not the browser)"),
    ("ACME", "a native build (not the browser)"),
    ("FIX", "a native build (not the browser)"),
    ("WAMP", "a native build (not the browser)"),
    ("RTMP", "a native build (not the browser)"),
    ("SRT", "a native build (not the browser)"),
    ("AMQP1", "a native build (not the browser)"),
    ("Thrift", "a native build (not the browser)"),
    ("BMP", "a native build (not the browser)"),
    ("MQTT-SN", "a native build (not the browser)"),
    ("NBD", "a native build (not the browser)"),
    ("ManageSieve", "a native build (not the browser)"),
    ("Zenoh", "a native build (not the browser)"),
    ("LwM2M", "a native build (not the browser)"),
    ("RESTCONF", "a native build (not the browser)"),
    ("WebTransport", "a native build (not the browser)"),
    ("JMAP", "a native build (not the browser)"),
    ("EPP", "a native build (not the browser)"),
    ("LMTP", "a native build (not the browser)"),
    ("LPD", "a native build (not the browser)"),
    ("Echo", "a native build (not the browser)"),
    ("Discard", "a native build (not the browser)"),
    ("Daytime", "a native build (not the browser)"),
    ("QOTD", "a native build (not the browser)"),
    ("Chargen", "a native build (not the browser)"),
    ("Time", "a native build (not the browser)"),
    ("RCON", "a native build (not the browser)"),
    ("A2S", "a native build (not the browser)"),
    ("Minecraft", "a native build (not the browser)"),
    ("9P", "a native build (not the browser)"),
    ("ZeroMQ", "a native build (not the browser)"),
    ("SMPP", "a native build (not the browser)"),
    ("ClickHouse", "a native build (not the browser)"),
    ("MessagePack-RPC", "a native build (not the browser)"),
    ("Zipkin", "a native build (not the browser)"),
    ("Cap'n Proto RPC", "a native build (not the browser)"),
    ("KNX/IP", "a native build (not the browser)"),
    ("Consul", "a native build (not the browser)"),
    ("Milter", "a native build (not the browser)"),
    ("Anthropic", "a native build (not the browser)"),
    ("RadSec", "a native build (not the browser)"),
    ("D-Bus", "a native build (not the browser)"),
    ("BFD", "a native build (not the browser)"),
    ("VXLAN", "a native build (not the browser)"),
    ("OpenFlow", "a native build (not the browser)"),
    ("PROFINET", "a native build (not the browser)"),
    ("EtherCAT", "a native build (not the browser)"),
    ("M-Bus", "a native build (not the browser)"),
    ("rsync", "a native build (not the browser)"),
    ("RDP", "a Unix build (macOS or Linux)"),
    ("SPICE", "a native build (not the browser)"),
    ("PFCP", "a native build (not the browser)"),
    ("GTP", "nothing (every build has it)"),
    ("Db2", "nothing (every build has it)"),
    ("Snowflake", "nothing (every build has it)"),
    ("Spark", "nothing (every build has it)"),
    ("YARN", "nothing (every build has it)"),
    ("M3UA", "a Unix build (macOS or Linux)"),
    ("NGAP", "a Unix build (macOS or Linux)"),
    ("Matrix", "a native build (not the browser)"),
    ("libp2p", "a native build (not the browser)"),
    ("SunRPC", "a native build (not the browser)"),
    ("Guacamole", "a native build (not the browser)"),
    ("ActivityPub", "a native build (not the browser)"),
    ("Stratum", "a native build (not the browser)"),
    ("Stratum V2", "a native build (not the browser)"),
    ("Apache Pulsar", "a native build (not the browser)"),
    ("TR-069 (CWMP)", "a native build (not the browser)"),
    ("SSE", "a native build (not the browser)"),
    ("Zabbix", "a native build (not the browser)"),
    ("RTP", "nothing (every build has it)"),
    ("RTSP", "nothing (every build has it)"),
    ("HLS", "nothing (every build has it)"),
    ("WS-Discovery", "a native build (not the browser)"),
    ("ONVIF", "a native build (not the browser)"),
    ("Kerberos", "a native build (not the browser)"),
    ("X11", "a native build (not the browser)"),
    ("HTTP", "nothing (every build has it)"),
    ("HTTP2", "nothing (every build has it)"),
    ("HTTP3", "a native build (not the browser)"),
    ("QUIC", "a native build (not the browser)"),
    ("igmp", "a Unix build (macOS or Linux)"),
    ("IPP", "a native build (not the browser)"),
    ("IS-IS", "the `libpcap` feature, on Unix"),
    ("JSON-RPC", "nothing (every build has it)"),
    ("Kafka", "nothing (every build has it)"),
    ("mDNS", "a native build (not the browser)"),
    ("AMQP", "a native build (not the browser)"),
    ("MySQL", "a native build (not the browser)"),
    ("nfc", "the `pcsc` feature, on Unix"),
    ("NTP", "a native build (not the browser)"),
    ("OpenAI", "a native build (not the browser)"),
    ("OTLP", "a native build (not the browser)"),
    ("PostgreSQL", "a native build (not the browser)"),
    ("PyPI", "nothing (every build has it)"),
    ("MSSQL", "a native build (not the browser)"),
    ("Redis", "a native build (not the browser)"),
    ("ICMP", "a Unix build (macOS or Linux)"),
    ("RIP", "a native build (not the browser)"),
    ("SAML", "nothing (every build has it)"),
    ("SIP", "nothing (every build has it)"),
    ("H323", "a native build (not the browser)"),
    ("SMTP", "a native build (not the browser)"),
    ("FTP", "nothing (every build has it)"),
    ("POP3", "nothing (every build has it)"),
    ("SNMP", "nothing (every build has it)"),
    ("SOCKS5", "a native build (not the browser)"),
    ("SocketFile", "a Unix build (macOS or Linux)"),
    ("SSH", "a native build (not the browser)"),
    ("SSH Agent", "a Unix build (macOS or Linux)"),
    ("Syslog", "nothing (every build has it)"),
    ("FluentForward", "a native build (not the browser)"),
    ("NETFLOWV9", "a native build (not the browser)"),
    ("NETFLOW-V9", "a native build (not the browser)"),
    ("NETFLOW_V9", "a native build (not the browser)"),
    ("IPFIX", "a native build (not the browser)"),
    ("IPFIX-UDP", "a native build (not the browser)"),
    ("PrometheusRemoteWrite", "a native build (not the browser)"),
    ("RemoteWrite", "a native build (not the browser)"),
    ("sFlow", "a native build (not the browser)"),
    ("sFlow-v5", "a native build (not the browser)"),
    ("Loki", "a native build (not the browser)"),
    ("LokiPush", "a native build (not the browser)"),
    ("InfluxDB", "a native build (not the browser)"),
    ("InfluxDB2", "a native build (not the browser)"),
    ("GELF", "a native build (not the browser)"),
    ("Graylog", "a native build (not the browser)"),
    ("Graphite", "a native build (not the browser)"),
    ("StatsD", "a native build (not the browser)"),
    ("DogStatsD", "a native build (not the browser)"),
    ("TCP", "nothing (every build has it)"),
    ("Telnet", "nothing (every build has it)"),
    ("TLS", "nothing (every build has it)"),
    ("Tor", "a Unix build (macOS or Linux)"),
    ("BitTorrent DHT", "nothing (every build has it)"),
    ("BitTorrent Peer Wire", "nothing (every build has it)"),
    ("BitTorrent Tracker", "nothing (every build has it)"),
    ("TURN", "a Unix build (macOS or Linux)"),
    ("UDP", "nothing (every build has it)"),
    ("Gemini", "a native build (not the browser)"),
    ("DICT", "a native build (not the browser)"),
    ("Beanstalkd", "a native build (not the browser)"),
    ("Gearman", "a native build (not the browser)"),
    ("Prometheus", "a native build (not the browser)"),
    ("Docker", "a native build (not the browser)"),
    ("Vault", "a native build (not the browser)"),
    ("Nostr", "a native build (not the browser)"),
    ("Bolt", "a native build (not the browser)"),
    ("OCI-Registry", "nothing (every build has it)"),
    ("NSQ", "a native build (not the browser)"),
    ("NUT", "a native build (not the browser)"),
    ("WHOIS", "nothing (every build has it)"),
    ("STOMP", "nothing (every build has it)"),
    ("NetBIOS-NS", "nothing (every build has it)"),
    ("NATS", "nothing (every build has it)"),
    ("Memcached", "nothing (every build has it)"),
    ("Modbus", "nothing (every build has it)"),
    ("CoAP", "nothing (every build has it)"),
    ("RADIUS", "nothing (every build has it)"),
    ("DIAMETER", "a native build (not the browser)"),
    ("SSDP", "nothing (every build has it)"),
    ("Gopher", "nothing (every build has it)"),
    ("Finger", "nothing (every build has it)"),
    ("Ident", "nothing (every build has it)"),
    ("LLMNR", "a native build (not the browser)"),
    ("wireguard", "a Unix build (macOS or Linux)"),
    ("XML-RPC", "a native build (not the browser)"),
    ("XMPP", "a Unix build (macOS or Linux)"),
    ("ARP", "the `libpcap` feature, on Unix"),
    ("HTTP Proxy", "a Unix build (macOS or Linux)"),
    ("IMAP", "a native build (not the browser)"),
    ("IRC", "a native build (not the browser)"),
    ("MCP", "a native build (not the browser)"),
    ("MQTT", "a native build (not the browser)"),
    ("MongoDB", "a native build (not the browser)"),
    ("NNTP", "nothing (every build has it)"),
    ("NPM", "nothing (every build has it)"),
    ("Ollama", "nothing (every build has it)"),
    ("OpenAPI", "nothing (every build has it)"),
    ("ospf", "a Unix build (macOS or Linux)"),
    ("SMB", "the `libsmbclient` feature, on Unix"),
    ("SQS", "a native build (not the browser)"),
    ("STUN", "a Unix build (macOS or Linux)"),
    ("USB", "a native build (not the browser)"),
    ("VNC", "nothing (every build has it)"),
    ("WebRTC", "a native build (not the browser)"),
    ("WebSocket", "a native build (not the browser)"),
    ("Bitcoin", "nothing (every build has it)"),
    ("devp2p", "a native build (not the browser)"),
    ("Bluetooth (BLE)", "the `bluetooth` feature, on Unix"),
    ("DynamoDB", "a Unix build (macOS or Linux)"),
    ("Elasticsearch", "nothing (every build has it)"),
    ("Git", "a native build (not the browser)"),
    ("Kubernetes", "a native build (not the browser)"),
    ("LDAP", "a native build (not the browser)"),
    ("Maven", "nothing (every build has it)"),
    ("NFS", "a Unix build (macOS or Linux)"),
    ("OAuth2", "nothing (every build has it)"),
    ("OpenIDConnect", "nothing (every build has it)"),
    ("CouchDB", "a native build (not the browser)"),
    ("S3", "a native build (not the browser)"),
    ("WebDAV", "a native build (not the browser)"),
];

/// Why [`ClientRegistry::resolve`] could not find a protocol for the given
/// input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientProtocolLookupError {
    /// A real NetGet client protocol by this name exists, but this build does not
    /// include it (`requires` says what does).
    NotCompiled {
        name: &'static str,
        requires: &'static str,
    },
    /// No client protocol by this name/keyword is known to NetGet at all, in
    /// any build.
    Unknown {
        input: String,
        suggestion: Option<&'static str>,
    },
}

impl std::fmt::Display for ClientProtocolLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientProtocolLookupError::NotCompiled { name, requires } => write!(
                f,
                "Client protocol '{name}' exists but is not compiled into this build: it needs {requires}"
            ),
            ClientProtocolLookupError::Unknown {
                input,
                suggestion: Some(s),
            } => write!(f, "Unknown client protocol: '{input}'. Did you mean '{s}'?"),
            ClientProtocolLookupError::Unknown {
                input,
                suggestion: None,
            } => write!(f, "Unknown client protocol: '{input}'"),
        }
    }
}

impl std::error::Error for ClientProtocolLookupError {}

/// Suggest the closest known client protocol name to `input` via Levenshtein
/// edit distance, if it's plausibly a typo rather than something unrelated.
fn suggest_client_protocol_name(
    input: &str,
    known: &[(&'static str, &'static str)],
) -> Option<&'static str> {
    let input_norm = input.to_lowercase();
    let mut best: Option<(&'static str, usize)> = None;

    for (name, _feature) in known {
        let distance = levenshtein(&input_norm, &name.to_lowercase());
        best = match best {
            Some((_, best_dist)) if best_dist <= distance => best,
            _ => Some((name, distance)),
        };
    }

    best.and_then(|(name, distance)| {
        let threshold = (input_norm.chars().count() / 3).max(2);
        if distance <= threshold {
            Some(name)
        } else {
            None
        }
    })
}

/// Minimal Levenshtein edit distance between two strings. Implemented by hand
/// (no external dependency) since a "did you mean" suggestion doesn't justify
/// adding a crate.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut dp: Vec<usize> = (0..=b.len()).collect();

    for i in 1..=a.len() {
        let mut prev = dp[0];
        dp[0] = i;
        for j in 1..=b.len() {
            let tmp = dp[j];
            dp[j] = if a[i - 1] == b[j - 1] {
                prev
            } else {
                1 + prev.min(dp[j]).min(dp[j - 1])
            };
            prev = tmp;
        }
    }

    dp[b.len()]
}

/// Global client protocol registry instance
///
/// This registry is initialized once at startup with all available client protocols
/// based on compiled features. Use `CLIENT_REGISTRY.get(protocol_name)` to retrieve
/// a client protocol implementation.
pub static CLIENT_REGISTRY: std::sync::LazyLock<ClientRegistry> =
    std::sync::LazyLock::new(ClientRegistry::new);
