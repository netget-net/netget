//! Protocol registry
//!
//! This module provides a centralized registry that maps protocol names
//! to their protocol implementations. It enables trait-based protocol lookup
//! and keyword-based parsing.

use super::metadata::ProtocolMetadataV2;
use crate::llm::actions::Server;
use std::collections::HashMap;
use std::sync::Arc;

/// Global protocol registry mapping protocol names to protocol implementations
pub struct ServerRegistry {
    /// Maps protocol name (e.g., "TCP", "HTTP") to protocol implementation
    protocols: HashMap<String, Arc<dyn Server>>,
    /// Maps lowercase keywords to protocol name for fast parsing
    keyword_map: HashMap<String, String>,
}

impl ServerRegistry {
    /// Create a new protocol registry
    fn new() -> Self {
        let mut registry = Self {
            protocols: HashMap::new(),
            keyword_map: HashMap::new(),
        };

        // Register every protocol this platform builds
        registry.register_protocols();
        registry.build_keyword_map();

        // Validate that no keywords overlap between protocols
        registry.validate_keyword_uniqueness();

        registry
    }

    /// Register every protocol this build includes (platform and system-library gates)
    fn register_protocols(&mut self) {
        // Create a shared dummy AppState for protocols that need it during registration
        // This avoids creating multiple AppState instances which trigger expensive environment detection
        let dummy_state = Arc::new(crate::state::app_state::AppState::new());

        self.register(Arc::new(crate::server::TcpProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::SocketFileProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::NamedPipeProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::PtyProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::StdioProtocol::new()));

        self.register(Arc::new(crate::server::HttpProtocol::new()));

        self.register(Arc::new(crate::server::Http2Protocol::new()));

        self.register(Arc::new(crate::server::PypiProtocol::new()));

        self.register(Arc::new(crate::server::MavenProtocol::new()));

        self.register(Arc::new(crate::server::UdpProtocol::new()));

        #[cfg(all(unix, feature = "libpcap"))]
        self.register(Arc::new(crate::server::DataLinkProtocol::new()));

        #[cfg(all(unix, feature = "libpcap"))]
        self.register(Arc::new(crate::server::ArpProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::IcmpProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::dc_peer::actions::DcPeerProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::adc::actions::AdcProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::adc_peer::actions::AdcPeerProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::soulseek::actions::SoulseekProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::soulseek_peer::actions::SoulseekPeerProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::gnutella::actions::GnutellaProtocol::new(),
        ));

        self.register(Arc::new(crate::server::DcProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::DnsProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::doq::actions::DoqProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::DotProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::DohProtocol::new()));

        self.register(Arc::new(crate::server::DhcpProtocol::new()));

        self.register(Arc::new(crate::server::BootpProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::NtpProtocol::new()));

        self.register(Arc::new(crate::server::TftpProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::nut::actions::NutProtocol::new()));

        self.register(Arc::new(crate::server::WhoisProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::NdpProtocol::new()));

        self.register(Arc::new(crate::server::Dhcpv6Protocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::TunTapProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::RawIpProtocol::new()));

        self.register(Arc::new(crate::server::GtpProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::M3uaProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::ngap::actions::NgapProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::CanProtocol::new()));

        #[cfg(all(unix, feature = "libpcap"))]
        self.register(Arc::new(crate::server::LldpProtocol::new()));

        #[cfg(all(unix, feature = "libpcap"))]
        self.register(Arc::new(crate::server::CdpProtocol::new()));

        #[cfg(all(unix, feature = "libpcap"))]
        self.register(Arc::new(crate::server::StpProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::VrrpProtocol::new()));

        self.register(Arc::new(crate::server::HsrpProtocol::new()));

        #[cfg(all(unix, feature = "libpcap"))]
        self.register(Arc::new(crate::server::EapolProtocol::new()));

        self.register(Arc::new(crate::server::WolProtocol::new()));

        self.register(Arc::new(crate::server::NatsProtocol::new()));

        self.register(Arc::new(crate::server::StompProtocol::new()));

        self.register(Arc::new(crate::server::IdentProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::GeminiProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::DictProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::BeanstalkdProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::ZabbixProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::GearmanProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::NsqProtocol::new()));

        self.register(Arc::new(crate::server::GopherProtocol::new()));

        self.register(Arc::new(crate::server::FingerProtocol::new()));

        self.register(Arc::new(crate::server::SsdpProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::LlmnrProtocol::new()));

        self.register(Arc::new(crate::server::NetbiosNsProtocol::new()));

        self.register(Arc::new(crate::server::SnmpProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::IgmpProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::diameter::actions::DiameterProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::tacacs::actions::TacacsProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::netconf::actions::NetconfProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::rpki_rtr::actions::RpkiRtrProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::rdap::actions::RdapProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::hl7::actions::Hl7Protocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::icap::actions::IcapProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::s7comm::actions::S7commProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::ethernet_ip::actions::EthernetIpProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::dnp3::actions::Dnp3Protocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::iec104::actions::Iec104Protocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::bacnet::actions::BacnetProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::opcua::actions::OpcuaProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::ocpp::actions::OcppProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::a2a::actions::A2aProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::graphql::actions::GraphqlProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::fastcgi::actions::FastcgiProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::redfish::actions::RedfishProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::scim::actions::ScimProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::socketio::actions::SocketIoProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::caldav::actions::CalDavProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::carddav::actions::CardDavProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::dicom::actions::DicomProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::acme::actions::AcmeProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::fix::actions::FixProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::wamp::actions::WampProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::rtmp::actions::RtmpProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::srt::actions::SrtProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::amqp1::actions::Amqp1Protocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::thrift::actions::ThriftProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::bmp::actions::BmpProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::mqtt_sn::actions::MqttSnProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::nbd::actions::NbdProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::managesieve::actions::ManageSieveProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::zenoh::actions::ZenohProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::lwm2m::actions::Lwm2mProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::restconf::actions::RestconfProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::webtransport::actions::WebTransportProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::jmap::actions::JmapProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::epp::actions::EppProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::lmtp::actions::LmtpProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::lpd::actions::LpdProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::inetd::actions::EchoProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::inetd::actions::DiscardProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::inetd::actions::DaytimeProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::inetd::actions::QotdProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::inetd::actions::ChargenProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::inetd::actions::TimeProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::rcon::actions::RconProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::a2s::actions::A2sProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::minecraft::actions::MinecraftProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::ninep::actions::NinepProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::zeromq::actions::ZeromqProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::smpp::actions::SmppProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::clickhouse::actions::ClickhouseProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::msgpack_rpc::actions::MsgpackRpcProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::zipkin::actions::ZipkinProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::capnp_rpc::actions::CapnpRpcProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::knx::actions::KnxProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::consul::actions::ConsulProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::milter::actions::MilterProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::anthropic::actions::AnthropicProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::radsec::actions::RadsecProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::dbus::actions::DbusProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::bfd::actions::BfdProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::vxlan::actions::VxlanProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::openflow::actions::OpenFlowProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::profinet::actions::ProfinetProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::ethercat::actions::EthercatProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::mbus::actions::MbusProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::afp::actions::AfpProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::rsync::actions::RsyncProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::pfcp::actions::PfcpProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::matrix::actions::MatrixProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::libp2p::actions::Libp2pProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::sunrpc::actions::SunRpcProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::nis::actions::NisProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::rsh::actions::RshProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::rsh::actions::RexecProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::rsh::rlogin::actions::RloginProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::lorawan::actions::LorawanProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::guacamole::actions::GuacamoleProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::activitypub::actions::ActivityPubProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::stratum::actions::StratumProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::stratum_v2::actions::StratumV2Protocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::pulsar::actions::PulsarProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::tr069::actions::Tr069Protocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::sse::actions::SseProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::wsdiscovery::actions::WsDiscoveryProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::onvif::actions::OnvifProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::kerberos::actions::KerberosProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::netflow_v9::actions::NetflowV9Protocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::ipfix::actions::IpfixProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::prometheus_remote_write::actions::PrometheusRemoteWriteProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::sflow::actions::SflowProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::loki::actions::LokiProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::influxdb::actions::InfluxDbProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::fluent_forward::actions::FluentForwardProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::gelf::actions::GelfProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::graphite::actions::GraphiteProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::statsd::actions::StatsdProtocol::new(),
        ));

        self.register(Arc::new(crate::server::SyslogProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::SshProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::SshAgentProtocol::new()));

        self.register(Arc::new(crate::server::SvnProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::IrcProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::XmppProtocol::new()));

        self.register(Arc::new(crate::server::TelnetProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::SmtpProtocol::new()));

        self.register(Arc::new(crate::server::FtpProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::ImapProtocol::new()));

        self.register(Arc::new(crate::server::Pop3Protocol::new()));

        self.register(Arc::new(crate::server::NntpProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::MqttProtocol::new()));

        self.register(Arc::new(crate::server::ModbusProtocol::new()));

        self.register(Arc::new(crate::server::CoapProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::AmqpProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::MdnsProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::LdapProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        {
            use crate::server::connection::ConnectionId;
            use tokio::sync::mpsc;
            let (tx, _rx) = mpsc::unbounded_channel();
            self.register(Arc::new(crate::server::MysqlProtocol::new(
                ConnectionId::new(0), // Placeholder for protocol registry
                dummy_state.clone(),
                tx,
            )));
        }

        {
            use crate::server::connection::ConnectionId;
            use tokio::sync::mpsc;
            let (tx, _rx) = mpsc::unbounded_channel();
            self.register(Arc::new(crate::server::SnowflakeProtocol::new(
                ConnectionId::new(0), // Placeholder for protocol registry
                dummy_state.clone(),
                tx,
            )));
        }

        {
            use crate::server::connection::ConnectionId;
            use tokio::sync::mpsc;
            let (tx, _rx) = mpsc::unbounded_channel();
            self.register(Arc::new(crate::server::Db2Protocol::new(
                ConnectionId::new(0), // Placeholder for protocol registry
                dummy_state.clone(),
                tx,
            )));
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            use crate::server::connection::ConnectionId;
            use tokio::sync::mpsc;
            let (tx, _rx) = mpsc::unbounded_channel();
            self.register(Arc::new(crate::server::MssqlProtocol::new(
                ConnectionId::new(0), // Placeholder for protocol registry
                dummy_state.clone(),
                tx,
            )));
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            use crate::server::connection::ConnectionId;
            use tokio::sync::mpsc;
            let (tx, _rx) = mpsc::unbounded_channel();
            self.register(Arc::new(crate::server::PostgresqlProtocol::new(
                ConnectionId::new(0), // Placeholder for protocol registry
                dummy_state.clone(),
                tx,
            )));
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            use crate::server::connection::ConnectionId;
            use tokio::sync::mpsc;
            let (tx, _rx) = mpsc::unbounded_channel();
            self.register(Arc::new(crate::server::RedisProtocol::new(
                ConnectionId::new(0), // Placeholder for protocol registry
                dummy_state.clone(),
                tx,
            )));
        }

        self.register(Arc::new(crate::server::MemcachedProtocol::new()));

        self.register(Arc::new(crate::server::RadiusProtocol::new()));

        self.register(Arc::new(crate::server::RssProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        {
            use crate::server::connection::ConnectionId;
            use tokio::sync::mpsc;
            let (tx, _rx) = mpsc::unbounded_channel();
            self.register(Arc::new(crate::server::CassandraProtocol::new(
                ConnectionId::new(0), // Placeholder for protocol registry
                dummy_state.clone(),
                tx,
            )));
        }

        {
            use crate::server::connection::ConnectionId;
            use tokio::sync::mpsc;
            let (tx, _rx) = mpsc::unbounded_channel();
            self.register(Arc::new(crate::server::MongodbProtocol::new(
                ConnectionId::new(0), // Placeholder for protocol registry
                dummy_state.clone(),
                tx,
            )));
        }

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::DynamoProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::S3Protocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::SqsProtocol::new()));

        self.register(Arc::new(crate::server::ElasticsearchProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::CouchDbProtocol::new()));

        self.register(Arc::new(crate::server::YarnProtocol::new()));

        self.register(Arc::new(crate::server::SparkProtocol::new()));

        self.register(Arc::new(crate::server::NpmProtocol::new()));

        self.register(Arc::new(crate::server::OciRegistryProtocol::new()));

        self.register(Arc::new(crate::server::KubernetesProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::PrometheusProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::OtlpProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::DockerProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::VaultProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::BoltProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::IppProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::WebDavProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::NfsProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::NfcServerProtocol));

        self.register(Arc::new(crate::server::SmbProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::ProxyProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::Socks5Protocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::WireguardProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::OpenvpnProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::IpsecProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::StunProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::TurnProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::WebRtcProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::WebRtcSignalingProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::WebSocketProtocol::new()));

        self.register(Arc::new(crate::server::SipProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::h323::actions::H323GatekeeperProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::h323::actions::H323EndpointProtocol::new(),
        ));

        self.register(Arc::new(crate::server::RtpProtocol::new()));

        self.register(Arc::new(crate::server::RtspProtocol::new()));

        self.register(Arc::new(crate::server::HlsProtocol::new()));

        self.register(Arc::new(crate::server::BgpProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::OspfProtocol::new()));

        #[cfg(all(unix, feature = "libpcap"))]
        self.register(Arc::new(crate::server::IsisProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::RipProtocol::new()));

        self.register(Arc::new(crate::server::BitcoinProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::devp2p::actions::Devp2pProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::NostrProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::McpProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::OpenAiProtocol::new()));

        self.register(Arc::new(crate::server::OllamaProtocol::new()));

        self.register(Arc::new(crate::server::OAuth2Protocol::new()));

        self.register(Arc::new(crate::server::JsonRpcProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::XmlRpcProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::GrpcProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::grpc_web::actions::GrpcWebProtocol::new(),
        ));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::gnmi::actions::GnmiProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(
            crate::server::connect_rpc::actions::ConnectRpcProtocol::new(),
        ));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::EtcdProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::ZookeeperProtocol::new()));

        #[cfg(unix)]
        self.register(Arc::new(crate::server::TorRelayProtocol::new()));

        self.register(Arc::new(crate::server::VncProtocol::new()));

        self.register(Arc::new(crate::server::ReverseShellProtocol::new()));

        self.register(Arc::new(crate::server::RdpProtocol::new()));
        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::spice::actions::SpiceProtocol::new()));

        self.register(Arc::new(crate::server::OpenApiProtocol::new()));

        self.register(Arc::new(crate::server::OpenIdProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::GitProtocol::new()));

        self.register(Arc::new(crate::server::MercurialProtocol::new()));

        self.register(Arc::new(crate::server::KafkaProtocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::Http3Protocol::new()));

        #[cfg(not(target_arch = "wasm32"))]
        self.register(Arc::new(crate::server::QuicProtocol::new()));

        self.register(Arc::new(crate::server::TorrentTrackerProtocol::new()));

        self.register(Arc::new(crate::server::TorrentDhtProtocol::new()));

        self.register(Arc::new(crate::server::TorrentPeerProtocol::new()));

        self.register(Arc::new(crate::server::TlsProtocol::new()));

        self.register(Arc::new(crate::server::SamlIdpProtocol::new()));

        self.register(Arc::new(crate::server::SamlSpProtocol::new()));

        #[cfg(all(unix, feature = "libusb"))]
        self.register(Arc::new(crate::server::UsbKeyboardProtocol::new()));

        #[cfg(all(unix, feature = "libusb"))]
        self.register(Arc::new(crate::server::UsbMouseProtocol::new()));

        #[cfg(all(unix, feature = "libusb"))]
        self.register(Arc::new(crate::server::UsbSerialProtocol::new()));

        #[cfg(all(unix, feature = "libusb"))]
        self.register(Arc::new(crate::server::UsbMscProtocol::new()));

        #[cfg(all(unix, feature = "libusb"))]
        self.register(Arc::new(crate::server::UsbFido2Protocol::new()));

        #[cfg(all(unix, feature = "libusb"))]
        self.register(Arc::new(crate::server::UsbSmartCardProtocol::new()));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(crate::server::BluetoothBleProtocol::new()));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(crate::server::BluetoothBleKeyboardProtocol::new()));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(crate::server::BluetoothBleMouseProtocol::new()));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(crate::server::BluetoothBleBeaconProtocol::new()));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(crate::server::BluetoothBleRemoteProtocol::new()));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(crate::server::BluetoothBleBatteryProtocol::new()));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(crate::server::BluetoothBleHeartRateProtocol::new()));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(
            crate::server::BluetoothBleThermometerProtocol::new(),
        ));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(
            crate::server::BluetoothBleEnvironmentalProtocol::new(),
        ));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(crate::server::BluetoothBleProximityProtocol::new()));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(crate::server::BluetoothBleGamepadProtocol::new()));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(crate::server::BluetoothBlePresenterProtocol::new()));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(
            crate::server::BluetoothBleFileTransferProtocol::new(),
        ));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(
            crate::server::BluetoothBleDataStreamProtocol::new(),
        ));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(crate::server::BluetoothBleCyclingProtocol::new()));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(crate::server::BluetoothBleRunningProtocol::new()));

        #[cfg(all(unix, feature = "bluetooth"))]
        self.register(Arc::new(
            crate::server::BluetoothBleWeightScaleProtocol::new(),
        ));
    }

    /// Build keyword map for fast protocol parsing
    fn build_keyword_map(&mut self) {
        for (protocol_name, protocol) in &self.protocols {
            // Add all protocol keywords
            for keyword in protocol.keywords() {
                let lower = keyword.to_lowercase();
                // Store the hyphen/space-normalized form too; input is normalized
                // before lookup, so a keyword declared as "ssh-agent" was otherwise
                // unreachable from the input "ssh_agent".
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

    /// Get keyword overlaps between protocols
    ///
    /// Returns a vector of (keyword, protocols) tuples for keywords
    /// that are claimed by multiple protocols.
    pub fn get_keyword_overlaps(&self) -> Vec<(String, Vec<(String, String)>)> {
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

        // Find all keywords claimed by more than one DISTINCT protocol. A single
        // protocol whose keyword equals its own stack_name contributes two entries
        // for the same keyword — that is not an overlap and must not be reported.
        let mut overlaps = Vec::new();
        for (keyword, protocols) in &keyword_to_protocols {
            let distinct: std::collections::HashSet<&String> =
                protocols.iter().map(|(name, _)| name).collect();
            if distinct.len() > 1 {
                overlaps.push((keyword.clone(), protocols.clone()));
            }
        }

        overlaps
    }

    /// Validate that no two protocols share the same keyword
    ///
    /// This logs warnings for any overlapping keywords detected,
    /// but does not panic to allow the application to continue running.
    fn validate_keyword_uniqueness(&self) {
        let overlaps = self.get_keyword_overlaps();

        // Overlaps between distinct protocols are a development-time advisory, not a
        // runtime problem (many are intentional family keywords like "bluetooth"/"usb"
        // that then narrow by a more specific keyword). Log at DEBUG so it lands in
        // netget.log for whoever cares without spamming the TUI on every startup; the
        // `test_keyword_overlaps` test is the enforcement point.
        if !overlaps.is_empty() {
            use tracing::debug;
            debug!("Keyword overlaps detected between protocols:");

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

    /// Register a protocol implementation
    #[allow(dead_code)]
    fn register(&mut self, protocol: Arc<dyn Server>) {
        let protocol_name = protocol.protocol_name().to_string();
        self.protocols.insert(protocol_name, protocol);
    }

    /// Get protocol implementation by protocol name
    pub fn get(&self, protocol_name: &str) -> Option<Arc<dyn Server>> {
        self.protocols.get(protocol_name).cloned()
    }

    /// Resolve user/LLM-supplied input (a protocol name or keyword) to a
    /// registered protocol implementation.
    ///
    /// This is the recommended entry point for turning arbitrary protocol input
    /// (CLI args, `/load` scripts, MCP `start_server` calls, or an already
    /// canonical name such as a stored `ServerInfo::protocol_name`) into a
    /// protocol implementation. Unlike calling `get()` / `parse_from_str()`
    /// directly, a failure here distinguishes "this protocol exists but wasn't
    /// compiled into this build" from "this is not a real NetGet protocol at
    /// all", and offers a "did you mean" suggestion for likely typos — see
    /// [`ProtocolLookupError`].
    pub fn resolve(&self, input: &str) -> Result<Arc<dyn Server>, ProtocolLookupError> {
        // Exact canonical name first — handles a name already resolved by a
        // previous call (e.g. a stored `ServerInfo::protocol_name`).
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
        // real NetGet protocol that simply wasn't compiled into this build.
        let input_norm = input.to_lowercase().replace(['-', ' '], "_");
        for (name, requires) in ALL_KNOWN_PROTOCOLS {
            let name_norm = name.to_lowercase().replace(['-', ' '], "_");
            if name_norm == input_norm {
                return Err(ProtocolLookupError::NotCompiled { name, requires });
            }
        }

        // Truly unknown. Offer a "did you mean" suggestion via edit distance
        // against every known protocol name, compiled in or not.
        Err(ProtocolLookupError::Unknown {
            input: input.to_string(),
            suggestion: suggest_protocol_name(input, ALL_KNOWN_PROTOCOLS),
        })
    }

    /// Parse protocol from user input string
    ///
    /// Attempts to match keywords from registered protocols.
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

        // Second, try exact match with protocol names (for startup messages)
        for (protocol_name, protocol) in &self.protocols {
            let proto_lower = protocol.protocol_name().to_lowercase();
            let proto_normalized = proto_lower.replace(['-', ' '], "_");
            if input_lower == proto_lower
                || input_normalized == proto_lower
                || input_normalized == proto_normalized
            {
                return Some(protocol_name.clone());
            }
        }

        // Try keyword matching with priority ordering
        // More specific protocols checked first to avoid substring collisions

        // Priority 1: Check mDNS before DNS (avoid substring match)
        if let Some(stack) =
            self.match_protocol_by_any_keyword_with_boundaries(&input_lower, "mDNS")
        {
            return Some(stack);
        }

        // Priority 2: Check IMAP before SMTP (more specific for mail/email)
        if let Some(stack) =
            self.match_protocol_by_any_keyword_with_boundaries(&input_lower, "IMAP")
        {
            return Some(stack);
        }

        // Priority 2.5: Check SMTP before general loop (avoid hash order collisions)
        if let Some(stack) =
            self.match_protocol_by_any_keyword_with_boundaries(&input_lower, "SMTP")
        {
            return Some(stack);
        }

        // Priority 2.7: Check SNMP before SSH-Agent (avoid "agent" substring match)
        if let Some(stack) =
            self.match_protocol_by_any_keyword_with_boundaries(&input_lower, "SNMP")
        {
            return Some(stack);
        }

        // Priority 3: Check PostgreSQL before MySQL (avoid "sql" substring)
        if let Some(stack) =
            self.match_protocol_by_any_keyword_with_boundaries(&input_lower, "PostgreSQL")
        {
            return Some(stack);
        }

        // Priority 4: Check XML-RPC and JSON-RPC before HTTP (avoid "http" substring in stack names)
        if let Some(stack) =
            self.match_protocol_by_any_keyword_with_boundaries(&input_lower, "XmlRPC")
        {
            return Some(stack);
        }
        if let Some(stack) =
            self.match_protocol_by_any_keyword_with_boundaries(&input_lower, "JsonRPC")
        {
            return Some(stack);
        }

        // Priority 5: Check Proxy before HTTP (avoid "http" substring in "http proxy")
        if let Some(stack) =
            self.match_protocol_by_any_keyword_with_boundaries(&input_lower, "Proxy")
        {
            return Some(stack);
        }

        // Priority 6: Check Tor protocols before TCP fallback
        if let Some(stack) =
            self.match_protocol_by_any_keyword_with_boundaries(&input_lower, "TorDirectory")
        {
            return Some(stack);
        }
        if let Some(stack) =
            self.match_protocol_by_any_keyword_with_boundaries(&input_lower, "TorRelay")
        {
            return Some(stack);
        }

        // Priority 7: Check WebRTC Signaling before the generic WebSocket protocol.
        // "websocket signaling" is a strict superset of WebSocket's "websocket" keyword, and
        // the loop below iterates a HashMap, so without this the winner is whichever the hash
        // order happens to yield. Nothing is registered under this name unless the `webrtc`
        // feature is on, in which case the lookup simply misses.
        if let Some(stack) =
            self.match_protocol_by_any_keyword_with_boundaries(&input_lower, "WebRTC Signaling")
        {
            return Some(stack);
        }

        // Priority 8: AWS cloud services before the generic loop and the HTTP fallback.
        // S3, SQS and DynamoDB are all HTTP/REST underneath, so their distinctive names
        // ("s3 bucket", "sqs queue", "dynamodb", …) must win over the plain "http" keyword
        // and over each other deterministically — the general loop below iterates a
        // HashMap and would otherwise let hash order decide "act as an S3 bucket over
        // http" between S3 and HTTP. Each check is a no-op if the feature is not compiled.
        // MQTT before the AWS block. MQTT stands for "Message Queuing Telemetry Transport"
        // and advertises "message queue telemetry"; SQS advertises the plain two-word
        // "message queue" deliberately. SQS is checked below, so without this the shorter and
        // *less* specific keyword won and "message queue telemetry transport" started an SQS
        // server. Note the general loop further down already resolves this correctly - it
        // takes the longest matching keyword - so it is these priority blocks, not the
        // matching rule, that create the collision they exist to prevent.
        if let Some(stack) =
            self.match_protocol_by_any_keyword_with_boundaries(&input_lower, "MQTT")
        {
            return Some(stack);
        }

        for aws_service in ["S3", "SQS", "DynamoDB"] {
            if let Some(stack) =
                self.match_protocol_by_any_keyword_with_boundaries(&input_lower, aws_service)
            {
                return Some(stack);
            }
        }

        // For all other protocols, check ALL keywords from each protocol with word
        // boundaries -- longest matching keyword first.
        //
        // This used to return the first hit while iterating a HashMap, whose order is
        // unspecified, so a input matching two protocols' keywords resolved to
        // whichever the hash order yielded and could differ between runs or feature
        // sets. That is what the hand-maintained priority ladder above exists to work
        // around, one collision at a time. Preferring the longest keyword makes the
        // more specific protocol win on its own, and the name tie-break makes the
        // answer identical on every run.
        let mut best: Option<(usize, &String)> = None;
        for (protocol_name, protocol) in &self.protocols {
            for keyword in protocol.keywords() {
                let keyword = keyword.to_lowercase();
                if !self.matches_with_word_boundary(&input_lower, &keyword) {
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
        }
        if let Some((_, protocol_name)) = best {
            return Some(protocol_name.clone());
        }

        // Default to TCP if "tcp", "raw", "ftp", "custom" found
        if input_lower.contains("tcp")
            || input_lower.contains("raw")
            || input_lower.contains("ftp")
            || input_lower.contains("custom")
        {
            return Some("TCP".to_string());
        }

        None
    }

    /// Check if input matches keyword with word boundaries
    ///
    /// Matches if keyword appears as a complete word or phrase (not substring).
    /// Examples:
    ///   - "mail" matches "mail server" ✓
    ///   - "mail" does NOT match "email" ✗
    ///   - "ai" does NOT match "mail" ✗
    fn matches_with_word_boundary(&self, input: &str, keyword: &str) -> bool {
        // Handle multi-word keywords (e.g., "mail server", "ssh keys")
        if keyword.contains(' ') {
            return input.contains(keyword);
        }

        // For single-word keywords, check word boundaries
        let input_bytes = input.as_bytes();

        if let Some(pos) = input.find(keyword) {
            // Check character before keyword
            let before_ok = if pos == 0 {
                true
            } else {
                let c = input_bytes[pos - 1];
                !c.is_ascii_alphanumeric() && c != b'_' && c != b'-'
            };

            // Check character after keyword
            let end_pos = pos + keyword.len();
            let after_ok = if end_pos >= input.len() {
                true
            } else {
                let c = input_bytes[end_pos];
                !c.is_ascii_alphanumeric() && c != b'_' && c != b'-'
            };

            return before_ok && after_ok;
        }

        false
    }

    /// Match a specific protocol by checking if input contains ANY of its keywords (with word boundaries)
    ///
    /// This method checks ALL keywords defined by the protocol, not just a hardcoded subset.
    /// Returns the protocol name if any keyword matches.
    fn match_protocol_by_any_keyword_with_boundaries(
        &self,
        input_lower: &str,
        protocol_name: &str,
    ) -> Option<String> {
        if let Some(protocol) = self.protocols.get(protocol_name) {
            for keyword in protocol.keywords() {
                if self.matches_with_word_boundary(input_lower, &keyword.to_lowercase()) {
                    return Some(protocol_name.to_string());
                }
            }
        }
        None
    }

    /// Get list of available protocol names
    pub fn available_protocols(&self) -> Vec<&'static str> {
        let mut protocols: Vec<&'static str> =
            self.protocols.values().map(|p| p.protocol_name()).collect();
        // Sort alphabetically for deterministic output
        protocols.sort();
        protocols
    }

    /// Get stack name by protocol name (e.g., "HTTP" -> "ETH>IP>TCP>HTTP")
    pub fn stack_name_by_protocol(&self, protocol_name: &str) -> Option<&'static str> {
        self.get(protocol_name).map(|p| p.stack_name())
    }

    /// Get metadata for a protocol by name
    pub fn metadata(&self, protocol_name: &str) -> Option<ProtocolMetadataV2> {
        self.get(protocol_name).map(|p| p.metadata())
    }

    /// Why a server of this protocol can only answer its peers, when the protocol declares
    /// that — see [`ProtocolMetadataV2::request_only`]. `None` for anything else, including a
    /// protocol this build does not compile.
    pub fn request_only_reason(&self, protocol_name: &str) -> Option<&'static str> {
        self.resolve(protocol_name)
            .ok()
            .and_then(|p| p.metadata().request_only)
    }

    /// Get all registered protocols with their metadata
    pub fn all_protocols(&self) -> Vec<(String, Arc<dyn Server>)> {
        self.protocols
            .iter()
            .map(|(name, protocol)| (name.clone(), Arc::clone(protocol)))
            .collect()
    }

    /// Get protocols that are excluded due to missing dependencies
    ///
    /// Returns a map of protocol name -> list of missing dependencies
    pub fn get_excluded_protocols(
        &self,
        caps: &crate::privilege::SystemCapabilities,
    ) -> HashMap<String, Vec<super::dependencies::ProtocolDependency>> {
        let mut excluded = HashMap::new();

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

    /// Protocols whose *default* port needs privilege this process does not have.
    ///
    /// These are **not** excluded — they run on any unprivileged port, and that is
    /// the whole point of listing them separately. Returns protocol name -> default
    /// port, so a caller can say "DNS defaults to 53; use 5353" instead of dropping
    /// DNS from the catalogue, which is what used to happen.
    ///
    /// Empty when the process can bind privileged ports (root, or CAP_NET_BIND_SERVICE).
    pub fn privileged_default_ports(
        &self,
        caps: &crate::privilege::SystemCapabilities,
    ) -> Vec<(String, u16)> {
        if caps.can_bind_privileged_ports {
            return Vec::new();
        }
        let mut out: Vec<(String, u16)> = self
            .protocols
            .iter()
            .filter_map(
                |(name, protocol)| match protocol.metadata().privilege_requirement {
                    crate::protocol::metadata::PrivilegeRequirement::PrivilegedPort(port) => {
                        Some((name.clone(), port))
                    }
                    _ => None,
                },
            )
            .collect();
        out.sort();
        out
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

/// All protocol names known to the netget codebase, paired with what a build needs to
/// include each one ("a native build (not the browser)", "the `libpcap` feature, on Unix",
/// …) — independent of what *this* build includes. This lets [`ServerRegistry::resolve`] tell
/// "protocol exists but wasn't compiled in" apart from "no such protocol", and say why.
///
/// Kept manually in sync with the platform gates on the registrations in
/// `register_protocols()` above. This is the one acceptable central touchpoint
/// per CLAUDE.md's decentralization policy (it plays the same role as the
/// `register()` calls themselves) — when adding a new protocol, add its
/// (canonical name, requirement) pair here too.
pub(crate) const ALL_KNOWN_PROTOCOLS: &[(&str, &str)] = &[
    ("TCP", "nothing (every build has it)"),
    ("SOCKET_FILE", "a Unix build (macOS or Linux)"),
    // The other three local-descriptor protocols. Without these, a build that does not compile
    // them answers `Unknown protocol: 'pty'. Did you mean 'NTP'?` instead of saying the protocol
    // exists but is not compiled in - the table is what tells those two cases apart.
    ("PTY", "a Unix build (macOS or Linux)"),
    ("STDIO", "a Unix build (macOS or Linux)"),
    ("NAMED_PIPE", "a Unix build (macOS or Linux)"),
    ("HTTP", "nothing (every build has it)"),
    ("HTTP2", "nothing (every build has it)"),
    ("PyPI", "nothing (every build has it)"),
    ("Maven", "nothing (every build has it)"),
    ("UDP", "nothing (every build has it)"),
    ("DataLink", "the `libpcap` feature, on Unix"),
    ("ARP", "the `libpcap` feature, on Unix"),
    ("ICMP", "a Unix build (macOS or Linux)"),
    ("NMDC Peer", "a native build (not the browser)"),
    ("ADC", "a native build (not the browser)"),
    ("ADC Peer", "a native build (not the browser)"),
    ("Soulseek", "a native build (not the browser)"),
    ("Soulseek Peer", "a native build (not the browser)"),
    ("Gnutella", "a native build (not the browser)"),
    ("DC", "nothing (every build has it)"),
    ("DNS", "a native build (not the browser)"),
    ("DoT", "a native build (not the browser)"),
    ("DoQ", "a native build (not the browser)"),
    ("DoH", "a native build (not the browser)"),
    ("DHCP", "nothing (every build has it)"),
    ("BOOTP", "nothing (every build has it)"),
    ("NTP", "a native build (not the browser)"),
    ("TFTP", "nothing (every build has it)"),
    ("NUT", "a native build (not the browser)"),
    ("WHOIS", "nothing (every build has it)"),
    ("NDP", "a Unix build (macOS or Linux)"),
    ("DHCPv6", "nothing (every build has it)"),
    ("TUN/TAP", "a Unix build (macOS or Linux)"),
    ("Raw IP", "a Unix build (macOS or Linux)"),
    ("GTP", "nothing (every build has it)"),
    ("M3UA", "a Unix build (macOS or Linux)"),
    ("NGAP", "a Unix build (macOS or Linux)"),
    ("CAN", "a Unix build (macOS or Linux)"),
    ("LLDP", "the `libpcap` feature, on Unix"),
    ("CDP", "the `libpcap` feature, on Unix"),
    ("STP", "the `libpcap` feature, on Unix"),
    ("VRRP", "a Unix build (macOS or Linux)"),
    ("HSRP", "nothing (every build has it)"),
    ("EAPOL", "the `libpcap` feature, on Unix"),
    ("Wake-on-LAN", "nothing (every build has it)"),
    ("NATS", "nothing (every build has it)"),
    ("STOMP", "nothing (every build has it)"),
    ("Ident", "nothing (every build has it)"),
    ("Gopher", "nothing (every build has it)"),
    ("DICT", "a native build (not the browser)"),
    ("Beanstalkd", "a native build (not the browser)"),
    ("Zabbix", "a native build (not the browser)"),
    ("Gearman", "a native build (not the browser)"),
    ("NSQ", "a native build (not the browser)"),
    ("Gemini", "a native build (not the browser)"),
    ("Finger", "nothing (every build has it)"),
    ("SSDP", "nothing (every build has it)"),
    ("LLMNR", "a native build (not the browser)"),
    ("NetBIOS-NS", "nothing (every build has it)"),
    ("SNMP", "nothing (every build has it)"),
    ("IGMP", "a Unix build (macOS or Linux)"),
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
    ("SSH", "a native build (not the browser)"),
    ("SSH Agent", "a Unix build (macOS or Linux)"),
    ("SVN", "nothing (every build has it)"),
    ("IRC", "a native build (not the browser)"),
    ("XMPP", "a Unix build (macOS or Linux)"),
    ("Telnet", "nothing (every build has it)"),
    ("SMTP", "a native build (not the browser)"),
    ("FTP", "nothing (every build has it)"),
    ("IMAP", "a native build (not the browser)"),
    ("NNTP", "nothing (every build has it)"),
    ("MQTT", "a native build (not the browser)"),
    ("Modbus", "nothing (every build has it)"),
    ("CoAP", "nothing (every build has it)"),
    ("AMQP", "a native build (not the browser)"),
    ("mDNS", "a native build (not the browser)"),
    ("LDAP", "a native build (not the browser)"),
    ("MySQL", "a native build (not the browser)"),
    ("MSSQL", "a native build (not the browser)"),
    ("Snowflake", "nothing (every build has it)"),
    ("Db2", "nothing (every build has it)"),
    ("PostgreSQL", "a native build (not the browser)"),
    ("Memcached", "nothing (every build has it)"),
    ("RADIUS", "nothing (every build has it)"),
    ("DIAMETER", "a native build (not the browser)"),
    ("Redis", "a native build (not the browser)"),
    ("RSS", "nothing (every build has it)"),
    ("Cassandra", "a native build (not the browser)"),
    ("MongoDB", "nothing (every build has it)"),
    ("DynamoDB", "a native build (not the browser)"),
    ("SQS", "a native build (not the browser)"),
    ("Elasticsearch", "nothing (every build has it)"),
    ("CouchDB", "a native build (not the browser)"),
    ("YARN", "nothing (every build has it)"),
    ("Spark", "nothing (every build has it)"),
    ("NPM", "nothing (every build has it)"),
    ("OCI-Registry", "nothing (every build has it)"),
    ("Kubernetes", "nothing (every build has it)"),
    ("Prometheus", "a native build (not the browser)"),
    ("OTLP", "a native build (not the browser)"),
    ("Docker", "a native build (not the browser)"),
    ("Vault", "a native build (not the browser)"),
    ("Bolt", "a native build (not the browser)"),
    ("IPP", "a native build (not the browser)"),
    ("WebDAV", "a native build (not the browser)"),
    ("NFS", "a Unix build (macOS or Linux)"),
    ("nfc", "a Unix build (macOS or Linux)"),
    ("SMB", "nothing (every build has it)"),
    ("Proxy", "a Unix build (macOS or Linux)"),
    ("SOCKS5", "a native build (not the browser)"),
    ("WireGuard", "a Unix build (macOS or Linux)"),
    ("OpenVPN", "a Unix build (macOS or Linux)"),
    ("IPSec/IKEv2", "a native build (not the browser)"),
    ("TURN", "a Unix build (macOS or Linux)"),
    ("WebRTC Signaling", "a native build (not the browser)"),
    ("WebSocket", "a native build (not the browser)"),
    ("SIP", "nothing (every build has it)"),
    ("H323", "a native build (not the browser)"),
    ("H323-Gatekeeper", "a native build (not the browser)"),
    ("RTP", "nothing (every build has it)"),
    ("RTSP", "nothing (every build has it)"),
    ("HLS", "nothing (every build has it)"),
    ("ISIS", "the `libpcap` feature, on Unix"),
    ("RIP", "a native build (not the browser)"),
    ("Bitcoin P2P", "nothing (every build has it)"),
    ("devp2p", "a native build (not the browser)"),
    ("Nostr", "a native build (not the browser)"),
    ("MCP", "a native build (not the browser)"),
    ("OpenAI", "a native build (not the browser)"),
    ("Ollama", "nothing (every build has it)"),
    ("OAuth2", "nothing (every build has it)"),
    ("JSON-RPC", "nothing (every build has it)"),
    ("XML-RPC", "a native build (not the browser)"),
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
    ("AFP", "a native build (not the browser)"),
    ("rsync", "a native build (not the browser)"),
    ("PFCP", "a native build (not the browser)"),
    ("Matrix", "a native build (not the browser)"),
    ("libp2p", "a native build (not the browser)"),
    ("SunRPC", "a native build (not the browser)"),
    ("NIS", "a native build (not the browser)"),
    ("RSH", "a native build (not the browser)"),
    ("REXEC", "a native build (not the browser)"),
    ("RLOGIN", "a native build (not the browser)"),
    ("LoRaWAN", "a native build (not the browser)"),
    ("Guacamole", "a native build (not the browser)"),
    ("ActivityPub", "a native build (not the browser)"),
    ("Stratum", "a native build (not the browser)"),
    ("Stratum V2", "a native build (not the browser)"),
    ("Apache Pulsar", "a native build (not the browser)"),
    ("TR-069 (CWMP)", "a native build (not the browser)"),
    ("SSE", "a native build (not the browser)"),
    ("WS-Discovery", "a native build (not the browser)"),
    ("ONVIF", "a native build (not the browser)"),
    ("Kerberos", "a native build (not the browser)"),
    ("etcd", "a native build (not the browser)"),
    ("ZooKeeper", "a native build (not the browser)"),
    ("Tor Relay", "a Unix build (macOS or Linux)"),
    ("VNC", "nothing (every build has it)"),
    ("Reverse Shell", "nothing (every build has it)"),
    ("RDP", "nothing (every build has it)"),
    ("SPICE", "a native build (not the browser)"),
    ("OpenAPI", "nothing (every build has it)"),
    ("OpenID", "nothing (every build has it)"),
    ("KAFKA", "nothing (every build has it)"),
    // Separate raw QUIC and RFC 9114 HTTP/3 transports.
    ("HTTP3", "a native build (not the browser)"),
    ("QUIC", "a native build (not the browser)"),
    ("Torrent-Tracker", "nothing (every build has it)"),
    ("Torrent-DHT", "nothing (every build has it)"),
    ("Torrent-Peer", "nothing (every build has it)"),
    ("TLS", "nothing (every build has it)"),
    ("SamlIdp", "nothing (every build has it)"),
    ("SamlSp", "nothing (every build has it)"),
    ("USB-Keyboard", "the `libusb` feature, on Unix"),
    ("USB-Mouse", "the `libusb` feature, on Unix"),
    ("USB-Serial", "the `libusb` feature, on Unix"),
    ("USB-MassStorage", "the `libusb` feature, on Unix"),
    ("usb-fido2", "the `libusb` feature, on Unix"),
    ("usb-smartcard", "the `libusb` feature, on Unix"),
    ("BLUETOOTH_BLE", "the `bluetooth` feature, on Unix"),
    ("BLUETOOTH_BLE_KEYBOARD", "the `bluetooth` feature, on Unix"),
    ("BLUETOOTH_BLE_MOUSE", "the `bluetooth` feature, on Unix"),
    ("BLUETOOTH_BLE_BEACON", "the `bluetooth` feature, on Unix"),
    ("BLUETOOTH_BLE_REMOTE", "the `bluetooth` feature, on Unix"),
    ("BLUETOOTH_BLE_BATTERY", "the `bluetooth` feature, on Unix"),
    (
        "BLUETOOTH_BLE_HEART_RATE",
        "the `bluetooth` feature, on Unix",
    ),
    (
        "BLUETOOTH_BLE_THERMOMETER",
        "the `bluetooth` feature, on Unix",
    ),
    (
        "BLUETOOTH_BLE_ENVIRONMENTAL",
        "the `bluetooth` feature, on Unix",
    ),
    (
        "BLUETOOTH_BLE_PROXIMITY",
        "the `bluetooth` feature, on Unix",
    ),
    ("BLUETOOTH_BLE_GAMEPAD", "the `bluetooth` feature, on Unix"),
    (
        "BLUETOOTH_BLE_PRESENTER",
        "the `bluetooth` feature, on Unix",
    ),
    (
        "BLUETOOTH_BLE_FILE_TRANSFER",
        "the `bluetooth` feature, on Unix",
    ),
    (
        "BLUETOOTH_BLE_DATA_STREAM",
        "the `bluetooth` feature, on Unix",
    ),
    ("BLUETOOTH_BLE_CYCLING", "the `bluetooth` feature, on Unix"),
    ("BLUETOOTH_BLE_RUNNING", "the `bluetooth` feature, on Unix"),
    (
        "BLUETOOTH_BLE_WEIGHT_SCALE",
        "the `bluetooth` feature, on Unix",
    ),
    ("POP3", "nothing (every build has it)"),
    ("S3", "a native build (not the browser)"),
    ("STUN", "a Unix build (macOS or Linux)"),
    ("WebRTC", "a native build (not the browser)"),
    ("BGP", "nothing (every build has it)"),
    ("OSPF", "a Unix build (macOS or Linux)"),
    ("Git", "a native build (not the browser)"),
    ("Mercurial", "nothing (every build has it)"),
];

/// Why [`ServerRegistry::resolve`] could not find a protocol for the given input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolLookupError {
    /// A real NetGet protocol by this name exists, but this build does not include it
    /// (`requires` says what does).
    NotCompiled {
        name: &'static str,
        requires: &'static str,
    },
    /// No protocol by this name/keyword is known to NetGet at all, in any build.
    Unknown {
        input: String,
        suggestion: Option<&'static str>,
    },
}

impl std::fmt::Display for ProtocolLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolLookupError::NotCompiled { name, requires } => write!(
                f,
                "Protocol '{name}' exists but is not compiled into this build: it needs {requires}"
            ),
            ProtocolLookupError::Unknown {
                input,
                suggestion: Some(s),
            } => write!(f, "Unknown protocol: '{input}'. Did you mean '{s}'?"),
            ProtocolLookupError::Unknown {
                input,
                suggestion: None,
            } => write!(f, "Unknown protocol: '{input}'"),
        }
    }
}

impl std::error::Error for ProtocolLookupError {}

/// Suggest the closest known protocol name to `input` via Levenshtein edit
/// distance, if it's plausibly a typo rather than something unrelated.
fn suggest_protocol_name(
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

/// Global singleton registry instance
static REGISTRY: once_cell::sync::Lazy<ServerRegistry> =
    once_cell::sync::Lazy::new(ServerRegistry::new);

/// Get the global protocol registry
pub fn registry() -> &'static ServerRegistry {
    &REGISTRY
}
