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

        // Register all protocols based on feature flags
        registry.register_protocols();
        registry.build_keyword_map();

        // Validate that no keywords overlap between protocols
        registry.validate_keyword_uniqueness();

        registry
    }

    /// Register all available protocols based on compiled features
    fn register_protocols(&mut self) {
        // Create a shared dummy AppState for protocols that need it during registration
        // This avoids creating multiple AppState instances which trigger expensive environment detection
        #[cfg(any(
            feature = "mysql",
            feature = "mssql",
            feature = "snowflake",
            feature = "db2",
            feature = "postgresql",
            feature = "redis",
            feature = "cassandra",
            feature = "mongodb-server"
        ))]
        let dummy_state = Arc::new(crate::state::app_state::AppState::new());

        #[cfg(feature = "tcp")]
        self.register(Arc::new(crate::server::TcpProtocol::new()));

        #[cfg(all(feature = "socket_file", unix))]
        self.register(Arc::new(crate::server::SocketFileProtocol::new()));

        #[cfg(all(feature = "named_pipe", unix))]
        self.register(Arc::new(crate::server::NamedPipeProtocol::new()));

        #[cfg(all(feature = "pty", unix))]
        self.register(Arc::new(crate::server::PtyProtocol::new()));

        #[cfg(all(feature = "stdio", unix))]
        self.register(Arc::new(crate::server::StdioProtocol::new()));

        #[cfg(feature = "http")]
        self.register(Arc::new(crate::server::HttpProtocol::new()));

        #[cfg(feature = "http2")]
        self.register(Arc::new(crate::server::Http2Protocol::new()));

        #[cfg(feature = "pypi")]
        self.register(Arc::new(crate::server::PypiProtocol::new()));

        #[cfg(feature = "maven")]
        self.register(Arc::new(crate::server::MavenProtocol::new()));

        #[cfg(feature = "udp")]
        self.register(Arc::new(crate::server::UdpProtocol::new()));

        #[cfg(feature = "datalink")]
        self.register(Arc::new(crate::server::DataLinkProtocol::new()));

        #[cfg(feature = "arp")]
        self.register(Arc::new(crate::server::ArpProtocol::new()));

        #[cfg(feature = "icmp")]
        self.register(Arc::new(crate::server::IcmpProtocol::new()));

        #[cfg(feature = "dc_peer")]
        self.register(Arc::new(
            crate::server::dc_peer::actions::DcPeerProtocol::new(),
        ));

        #[cfg(feature = "adc")]
        self.register(Arc::new(crate::server::adc::actions::AdcProtocol::new()));

        #[cfg(feature = "adc_peer")]
        self.register(Arc::new(
            crate::server::adc_peer::actions::AdcPeerProtocol::new(),
        ));

        #[cfg(feature = "soulseek")]
        self.register(Arc::new(
            crate::server::soulseek::actions::SoulseekProtocol::new(),
        ));

        #[cfg(feature = "soulseek_peer")]
        self.register(Arc::new(
            crate::server::soulseek_peer::actions::SoulseekPeerProtocol::new(),
        ));

        #[cfg(feature = "gnutella")]
        self.register(Arc::new(
            crate::server::gnutella::actions::GnutellaProtocol::new(),
        ));

        #[cfg(feature = "dc")]
        self.register(Arc::new(crate::server::DcProtocol::new()));

        #[cfg(feature = "dns")]
        self.register(Arc::new(crate::server::DnsProtocol::new()));

        #[cfg(feature = "doq")]
        self.register(Arc::new(crate::server::doq::actions::DoqProtocol::new()));

        #[cfg(feature = "dot")]
        self.register(Arc::new(crate::server::DotProtocol::new()));

        #[cfg(feature = "doh")]
        self.register(Arc::new(crate::server::DohProtocol::new()));

        #[cfg(feature = "dhcp")]
        self.register(Arc::new(crate::server::DhcpProtocol::new()));

        #[cfg(feature = "bootp")]
        self.register(Arc::new(crate::server::BootpProtocol::new()));

        #[cfg(feature = "ntp")]
        self.register(Arc::new(crate::server::NtpProtocol::new()));

        #[cfg(feature = "tftp")]
        self.register(Arc::new(crate::server::TftpProtocol::new()));

        #[cfg(feature = "nut")]
        self.register(Arc::new(crate::server::nut::actions::NutProtocol::new()));

        #[cfg(feature = "whois")]
        self.register(Arc::new(crate::server::WhoisProtocol::new()));

        #[cfg(feature = "ndp")]
        self.register(Arc::new(crate::server::NdpProtocol::new()));

        #[cfg(feature = "dhcpv6")]
        self.register(Arc::new(crate::server::Dhcpv6Protocol::new()));

        #[cfg(feature = "tuntap")]
        self.register(Arc::new(crate::server::TunTapProtocol::new()));

        #[cfg(feature = "rawip")]
        self.register(Arc::new(crate::server::RawIpProtocol::new()));

        #[cfg(feature = "gtp")]
        self.register(Arc::new(crate::server::GtpProtocol::new()));

        #[cfg(feature = "m3ua")]
        self.register(Arc::new(crate::server::M3uaProtocol::new()));

        #[cfg(feature = "ngap")]
        self.register(Arc::new(crate::server::ngap::actions::NgapProtocol::new()));

        #[cfg(feature = "can")]
        self.register(Arc::new(crate::server::CanProtocol::new()));

        #[cfg(feature = "lldp")]
        self.register(Arc::new(crate::server::LldpProtocol::new()));

        #[cfg(feature = "cdp")]
        self.register(Arc::new(crate::server::CdpProtocol::new()));

        #[cfg(feature = "stp")]
        self.register(Arc::new(crate::server::StpProtocol::new()));

        #[cfg(feature = "vrrp")]
        self.register(Arc::new(crate::server::VrrpProtocol::new()));

        #[cfg(feature = "hsrp")]
        self.register(Arc::new(crate::server::HsrpProtocol::new()));

        #[cfg(feature = "eapol")]
        self.register(Arc::new(crate::server::EapolProtocol::new()));

        #[cfg(feature = "wol")]
        self.register(Arc::new(crate::server::WolProtocol::new()));

        #[cfg(feature = "nats")]
        self.register(Arc::new(crate::server::NatsProtocol::new()));

        #[cfg(feature = "stomp")]
        self.register(Arc::new(crate::server::StompProtocol::new()));

        #[cfg(feature = "ident")]
        self.register(Arc::new(crate::server::IdentProtocol::new()));

        #[cfg(feature = "gemini")]
        self.register(Arc::new(crate::server::GeminiProtocol::new()));

        #[cfg(feature = "dict")]
        self.register(Arc::new(crate::server::DictProtocol::new()));

        #[cfg(feature = "beanstalkd")]
        self.register(Arc::new(crate::server::BeanstalkdProtocol::new()));

        #[cfg(feature = "zabbix")]
        self.register(Arc::new(crate::server::ZabbixProtocol::new()));

        #[cfg(feature = "gearman")]
        self.register(Arc::new(crate::server::GearmanProtocol::new()));

        #[cfg(feature = "nsq")]
        self.register(Arc::new(crate::server::NsqProtocol::new()));

        #[cfg(feature = "gopher")]
        self.register(Arc::new(crate::server::GopherProtocol::new()));

        #[cfg(feature = "finger")]
        self.register(Arc::new(crate::server::FingerProtocol::new()));

        #[cfg(feature = "ssdp")]
        self.register(Arc::new(crate::server::SsdpProtocol::new()));

        #[cfg(feature = "llmnr")]
        self.register(Arc::new(crate::server::LlmnrProtocol::new()));

        #[cfg(feature = "netbios-ns")]
        self.register(Arc::new(crate::server::NetbiosNsProtocol::new()));

        #[cfg(feature = "snmp")]
        self.register(Arc::new(crate::server::SnmpProtocol::new()));

        #[cfg(feature = "igmp")]
        self.register(Arc::new(crate::server::IgmpProtocol::new()));

        #[cfg(feature = "diameter")]
        self.register(Arc::new(
            crate::server::diameter::actions::DiameterProtocol::new(),
        ));

        #[cfg(feature = "tacacs")]
        self.register(Arc::new(
            crate::server::tacacs::actions::TacacsProtocol::new(),
        ));

        #[cfg(feature = "netconf")]
        self.register(Arc::new(
            crate::server::netconf::actions::NetconfProtocol::new(),
        ));

        #[cfg(feature = "rpki_rtr")]
        self.register(Arc::new(
            crate::server::rpki_rtr::actions::RpkiRtrProtocol::new(),
        ));

        #[cfg(feature = "rdap")]
        self.register(Arc::new(crate::server::rdap::actions::RdapProtocol::new()));

        #[cfg(feature = "hl7")]
        self.register(Arc::new(crate::server::hl7::actions::Hl7Protocol::new()));

        #[cfg(feature = "icap")]
        self.register(Arc::new(crate::server::icap::actions::IcapProtocol::new()));

        #[cfg(feature = "s7comm")]
        self.register(Arc::new(
            crate::server::s7comm::actions::S7commProtocol::new(),
        ));

        #[cfg(feature = "ethernet_ip")]
        self.register(Arc::new(
            crate::server::ethernet_ip::actions::EthernetIpProtocol::new(),
        ));

        #[cfg(feature = "dnp3")]
        self.register(Arc::new(crate::server::dnp3::actions::Dnp3Protocol::new()));

        #[cfg(feature = "iec104")]
        self.register(Arc::new(
            crate::server::iec104::actions::Iec104Protocol::new(),
        ));

        #[cfg(feature = "bacnet")]
        self.register(Arc::new(
            crate::server::bacnet::actions::BacnetProtocol::new(),
        ));

        #[cfg(feature = "opcua")]
        self.register(Arc::new(crate::server::opcua::actions::OpcuaProtocol::new()));

        #[cfg(feature = "ocpp")]
        self.register(Arc::new(crate::server::ocpp::actions::OcppProtocol::new()));

        #[cfg(feature = "a2a")]
        self.register(Arc::new(crate::server::a2a::actions::A2aProtocol::new()));

        #[cfg(feature = "graphql")]
        self.register(Arc::new(
            crate::server::graphql::actions::GraphqlProtocol::new(),
        ));

        #[cfg(feature = "fastcgi")]
        self.register(Arc::new(
            crate::server::fastcgi::actions::FastcgiProtocol::new(),
        ));

        #[cfg(feature = "redfish")]
        self.register(Arc::new(
            crate::server::redfish::actions::RedfishProtocol::new(),
        ));

        #[cfg(feature = "scim")]
        self.register(Arc::new(crate::server::scim::actions::ScimProtocol::new()));

        #[cfg(feature = "socketio")]
        self.register(Arc::new(
            crate::server::socketio::actions::SocketIoProtocol::new(),
        ));

        #[cfg(feature = "caldav")]
        self.register(Arc::new(
            crate::server::caldav::actions::CalDavProtocol::new(),
        ));

        #[cfg(feature = "carddav")]
        self.register(Arc::new(
            crate::server::carddav::actions::CardDavProtocol::new(),
        ));

        #[cfg(feature = "dicom")]
        self.register(Arc::new(crate::server::dicom::actions::DicomProtocol::new()));

        #[cfg(feature = "acme")]
        self.register(Arc::new(crate::server::acme::actions::AcmeProtocol::new()));

        #[cfg(feature = "fix")]
        self.register(Arc::new(crate::server::fix::actions::FixProtocol::new()));

        #[cfg(feature = "wamp")]
        self.register(Arc::new(crate::server::wamp::actions::WampProtocol::new()));

        #[cfg(feature = "rtmp")]
        self.register(Arc::new(crate::server::rtmp::actions::RtmpProtocol::new()));

        #[cfg(feature = "srt")]
        self.register(Arc::new(crate::server::srt::actions::SrtProtocol::new()));

        #[cfg(feature = "amqp1")]
        self.register(Arc::new(crate::server::amqp1::actions::Amqp1Protocol::new()));

        #[cfg(feature = "thrift")]
        self.register(Arc::new(
            crate::server::thrift::actions::ThriftProtocol::new(),
        ));
        #[cfg(feature = "bmp")]
        self.register(Arc::new(crate::server::bmp::actions::BmpProtocol::new()));
        #[cfg(feature = "mqtt_sn")]
        self.register(Arc::new(
            crate::server::mqtt_sn::actions::MqttSnProtocol::new(),
        ));
        #[cfg(feature = "nbd")]
        self.register(Arc::new(crate::server::nbd::actions::NbdProtocol::new()));
        #[cfg(feature = "managesieve")]
        self.register(Arc::new(
            crate::server::managesieve::actions::ManageSieveProtocol::new(),
        ));
        #[cfg(feature = "zenoh")]
        self.register(Arc::new(crate::server::zenoh::actions::ZenohProtocol::new()));
        #[cfg(feature = "lwm2m")]
        self.register(Arc::new(crate::server::lwm2m::actions::Lwm2mProtocol::new()));
        #[cfg(feature = "restconf")]
        self.register(Arc::new(
            crate::server::restconf::actions::RestconfProtocol::new(),
        ));
        #[cfg(feature = "webtransport")]
        self.register(Arc::new(
            crate::server::webtransport::actions::WebTransportProtocol::new(),
        ));
        #[cfg(feature = "jmap")]
        self.register(Arc::new(crate::server::jmap::actions::JmapProtocol::new()));
        #[cfg(feature = "epp")]
        self.register(Arc::new(crate::server::epp::actions::EppProtocol::new()));
        #[cfg(feature = "lmtp")]
        self.register(Arc::new(crate::server::lmtp::actions::LmtpProtocol::new()));
        #[cfg(feature = "lpd")]
        self.register(Arc::new(crate::server::lpd::actions::LpdProtocol::new()));
        #[cfg(feature = "inetd")]
        self.register(Arc::new(crate::server::inetd::actions::EchoProtocol::new()));
        #[cfg(feature = "inetd")]
        self.register(Arc::new(
            crate::server::inetd::actions::DiscardProtocol::new(),
        ));
        #[cfg(feature = "inetd")]
        self.register(Arc::new(
            crate::server::inetd::actions::DaytimeProtocol::new(),
        ));
        #[cfg(feature = "inetd")]
        self.register(Arc::new(crate::server::inetd::actions::QotdProtocol::new()));
        #[cfg(feature = "inetd")]
        self.register(Arc::new(
            crate::server::inetd::actions::ChargenProtocol::new(),
        ));
        #[cfg(feature = "inetd")]
        self.register(Arc::new(crate::server::inetd::actions::TimeProtocol::new()));
        #[cfg(feature = "rcon")]
        self.register(Arc::new(crate::server::rcon::actions::RconProtocol::new()));
        #[cfg(feature = "a2s")]
        self.register(Arc::new(crate::server::a2s::actions::A2sProtocol::new()));
        #[cfg(feature = "minecraft")]
        self.register(Arc::new(
            crate::server::minecraft::actions::MinecraftProtocol::new(),
        ));
        #[cfg(feature = "ninep")]
        self.register(Arc::new(crate::server::ninep::actions::NinepProtocol::new()));
        #[cfg(feature = "zeromq")]
        self.register(Arc::new(
            crate::server::zeromq::actions::ZeromqProtocol::new(),
        ));
        #[cfg(feature = "smpp")]
        self.register(Arc::new(crate::server::smpp::actions::SmppProtocol::new()));
        #[cfg(feature = "clickhouse")]
        self.register(Arc::new(
            crate::server::clickhouse::actions::ClickhouseProtocol::new(),
        ));
        #[cfg(feature = "msgpack-rpc")]
        self.register(Arc::new(
            crate::server::msgpack_rpc::actions::MsgpackRpcProtocol::new(),
        ));
        #[cfg(feature = "zipkin")]
        self.register(Arc::new(
            crate::server::zipkin::actions::ZipkinProtocol::new(),
        ));
        #[cfg(feature = "capnp-rpc")]
        self.register(Arc::new(
            crate::server::capnp_rpc::actions::CapnpRpcProtocol::new(),
        ));
        #[cfg(feature = "knx")]
        self.register(Arc::new(crate::server::knx::actions::KnxProtocol::new()));
        #[cfg(feature = "consul")]
        self.register(Arc::new(
            crate::server::consul::actions::ConsulProtocol::new(),
        ));
        #[cfg(feature = "milter")]
        self.register(Arc::new(
            crate::server::milter::actions::MilterProtocol::new(),
        ));
        #[cfg(feature = "anthropic")]
        self.register(Arc::new(
            crate::server::anthropic::actions::AnthropicProtocol::new(),
        ));
        #[cfg(feature = "radsec")]
        self.register(Arc::new(
            crate::server::radsec::actions::RadsecProtocol::new(),
        ));
        #[cfg(feature = "dbus")]
        self.register(Arc::new(crate::server::dbus::actions::DbusProtocol::new()));
        #[cfg(feature = "bfd")]
        self.register(Arc::new(crate::server::bfd::actions::BfdProtocol::new()));
        #[cfg(feature = "vxlan")]
        self.register(Arc::new(crate::server::vxlan::actions::VxlanProtocol::new()));
        #[cfg(feature = "rsync")]
        self.register(Arc::new(crate::server::rsync::actions::RsyncProtocol::new()));
        #[cfg(feature = "pfcp")]
        self.register(Arc::new(crate::server::pfcp::actions::PfcpProtocol::new()));
        #[cfg(feature = "matrix")]
        self.register(Arc::new(
            crate::server::matrix::actions::MatrixProtocol::new(),
        ));
        #[cfg(feature = "libp2p")]
        self.register(Arc::new(
            crate::server::libp2p::actions::Libp2pProtocol::new(),
        ));
        #[cfg(feature = "sunrpc")]
        self.register(Arc::new(
            crate::server::sunrpc::actions::SunRpcProtocol::new(),
        ));
        #[cfg(feature = "guacamole")]
        self.register(Arc::new(
            crate::server::guacamole::actions::GuacamoleProtocol::new(),
        ));
        #[cfg(feature = "activitypub")]
        self.register(Arc::new(
            crate::server::activitypub::actions::ActivityPubProtocol::new(),
        ));
        #[cfg(feature = "stratum")]
        self.register(Arc::new(
            crate::server::stratum::actions::StratumProtocol::new(),
        ));
        #[cfg(feature = "stratum-v2")]
        self.register(Arc::new(
            crate::server::stratum_v2::actions::StratumV2Protocol::new(),
        ));
        #[cfg(feature = "pulsar")]
        self.register(Arc::new(
            crate::server::pulsar::actions::PulsarProtocol::new(),
        ));
        #[cfg(feature = "tr069")]
        self.register(Arc::new(crate::server::tr069::actions::Tr069Protocol::new()));
        #[cfg(feature = "sse")]
        self.register(Arc::new(crate::server::sse::actions::SseProtocol::new()));
        #[cfg(feature = "wsdiscovery")]
        self.register(Arc::new(
            crate::server::wsdiscovery::actions::WsDiscoveryProtocol::new(),
        ));
        #[cfg(feature = "onvif")]
        self.register(Arc::new(crate::server::onvif::actions::OnvifProtocol::new()));
        #[cfg(feature = "kerberos")]
        self.register(Arc::new(
            crate::server::kerberos::actions::KerberosProtocol::new(),
        ));

        #[cfg(feature = "netflow-v9")]
        self.register(Arc::new(
            crate::server::netflow_v9::actions::NetflowV9Protocol::new(),
        ));
        #[cfg(feature = "ipfix")]
        self.register(Arc::new(crate::server::ipfix::actions::IpfixProtocol::new()));
        #[cfg(feature = "prometheus-remote-write")]
        self.register(Arc::new(
            crate::server::prometheus_remote_write::actions::PrometheusRemoteWriteProtocol::new(),
        ));
        #[cfg(feature = "sflow")]
        self.register(Arc::new(crate::server::sflow::actions::SflowProtocol::new()));
        #[cfg(feature = "loki")]
        self.register(Arc::new(crate::server::loki::actions::LokiProtocol::new()));
        #[cfg(feature = "influxdb")]
        self.register(Arc::new(
            crate::server::influxdb::actions::InfluxDbProtocol::new(),
        ));

        #[cfg(feature = "fluent-forward")]
        self.register(Arc::new(
            crate::server::fluent_forward::actions::FluentForwardProtocol::new(),
        ));

        #[cfg(feature = "gelf")]
        self.register(Arc::new(crate::server::gelf::actions::GelfProtocol::new()));

        #[cfg(feature = "graphite")]
        self.register(Arc::new(
            crate::server::graphite::actions::GraphiteProtocol::new(),
        ));

        #[cfg(feature = "statsd")]
        self.register(Arc::new(
            crate::server::statsd::actions::StatsdProtocol::new(),
        ));

        #[cfg(feature = "syslog")]
        self.register(Arc::new(crate::server::SyslogProtocol::new()));

        #[cfg(feature = "ssh")]
        self.register(Arc::new(crate::server::SshProtocol::new()));

        #[cfg(all(feature = "ssh-agent", unix))]
        self.register(Arc::new(crate::server::SshAgentProtocol::new()));

        #[cfg(feature = "svn")]
        self.register(Arc::new(crate::server::SvnProtocol::new()));

        #[cfg(feature = "irc")]
        self.register(Arc::new(crate::server::IrcProtocol::new()));

        #[cfg(feature = "xmpp")]
        self.register(Arc::new(crate::server::XmppProtocol::new()));

        #[cfg(feature = "telnet")]
        self.register(Arc::new(crate::server::TelnetProtocol::new()));

        #[cfg(feature = "smtp")]
        self.register(Arc::new(crate::server::SmtpProtocol::new()));

        #[cfg(feature = "ftp")]
        self.register(Arc::new(crate::server::FtpProtocol::new()));

        #[cfg(feature = "imap")]
        self.register(Arc::new(crate::server::ImapProtocol::new()));

        #[cfg(feature = "pop3")]
        self.register(Arc::new(crate::server::Pop3Protocol::new()));

        #[cfg(feature = "nntp")]
        self.register(Arc::new(crate::server::NntpProtocol::new()));

        #[cfg(feature = "mqtt")]
        self.register(Arc::new(crate::server::MqttProtocol::new()));

        #[cfg(feature = "modbus")]
        self.register(Arc::new(crate::server::ModbusProtocol::new()));

        #[cfg(feature = "coap")]
        self.register(Arc::new(crate::server::CoapProtocol::new()));

        #[cfg(feature = "amqp")]
        self.register(Arc::new(crate::server::AmqpProtocol::new()));

        #[cfg(feature = "mdns")]
        self.register(Arc::new(crate::server::MdnsProtocol::new()));

        #[cfg(feature = "ldap")]
        self.register(Arc::new(crate::server::LdapProtocol::new()));

        #[cfg(feature = "mysql")]
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

        #[cfg(feature = "snowflake")]
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

        #[cfg(feature = "db2")]
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

        #[cfg(feature = "mssql")]
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

        #[cfg(feature = "postgresql")]
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

        #[cfg(feature = "redis")]
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

        #[cfg(feature = "memcached")]
        self.register(Arc::new(crate::server::MemcachedProtocol::new()));

        #[cfg(feature = "radius")]
        self.register(Arc::new(crate::server::RadiusProtocol::new()));

        #[cfg(feature = "rss")]
        self.register(Arc::new(crate::server::RssProtocol::new()));

        #[cfg(feature = "cassandra")]
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

        #[cfg(feature = "mongodb-server")]
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

        #[cfg(feature = "dynamo")]
        self.register(Arc::new(crate::server::DynamoProtocol::new()));

        #[cfg(feature = "s3")]
        self.register(Arc::new(crate::server::S3Protocol::new()));

        #[cfg(feature = "sqs")]
        self.register(Arc::new(crate::server::SqsProtocol::new()));

        #[cfg(feature = "elasticsearch")]
        self.register(Arc::new(crate::server::ElasticsearchProtocol::new()));

        #[cfg(feature = "couchdb")]
        self.register(Arc::new(crate::server::CouchDbProtocol::new()));

        #[cfg(feature = "yarn")]
        self.register(Arc::new(crate::server::YarnProtocol::new()));

        #[cfg(feature = "spark")]
        self.register(Arc::new(crate::server::SparkProtocol::new()));

        #[cfg(feature = "npm")]
        self.register(Arc::new(crate::server::NpmProtocol::new()));

        #[cfg(feature = "oci-registry")]
        self.register(Arc::new(crate::server::OciRegistryProtocol::new()));

        #[cfg(feature = "kubernetes-server")]
        self.register(Arc::new(crate::server::KubernetesProtocol::new()));

        #[cfg(feature = "prometheus")]
        self.register(Arc::new(crate::server::PrometheusProtocol::new()));

        #[cfg(feature = "otlp")]
        self.register(Arc::new(crate::server::OtlpProtocol::new()));

        #[cfg(feature = "docker")]
        self.register(Arc::new(crate::server::DockerProtocol::new()));

        #[cfg(feature = "vault")]
        self.register(Arc::new(crate::server::VaultProtocol::new()));

        #[cfg(feature = "bolt")]
        self.register(Arc::new(crate::server::BoltProtocol::new()));

        #[cfg(feature = "ipp")]
        self.register(Arc::new(crate::server::IppProtocol::new()));

        #[cfg(feature = "webdav")]
        self.register(Arc::new(crate::server::WebDavProtocol::new()));

        #[cfg(feature = "nfs")]
        self.register(Arc::new(crate::server::NfsProtocol::new()));

        #[cfg(feature = "nfc")]
        self.register(Arc::new(crate::server::NfcServerProtocol));

        #[cfg(feature = "smb")]
        self.register(Arc::new(crate::server::SmbProtocol::new()));

        #[cfg(feature = "proxy")]
        self.register(Arc::new(crate::server::ProxyProtocol::new()));

        #[cfg(feature = "socks5")]
        self.register(Arc::new(crate::server::Socks5Protocol::new()));

        #[cfg(feature = "wireguard")]
        self.register(Arc::new(crate::server::WireguardProtocol::new()));

        #[cfg(feature = "openvpn")]
        self.register(Arc::new(crate::server::OpenvpnProtocol::new()));

        #[cfg(feature = "ipsec")]
        self.register(Arc::new(crate::server::IpsecProtocol::new()));

        #[cfg(feature = "stun")]
        self.register(Arc::new(crate::server::StunProtocol::new()));

        #[cfg(feature = "turn")]
        self.register(Arc::new(crate::server::TurnProtocol::new()));

        #[cfg(feature = "webrtc")]
        self.register(Arc::new(crate::server::WebRtcProtocol::new()));

        #[cfg(feature = "webrtc")]
        self.register(Arc::new(crate::server::WebRtcSignalingProtocol::new()));

        #[cfg(feature = "websocket")]
        self.register(Arc::new(crate::server::WebSocketProtocol::new()));

        #[cfg(feature = "sip")]
        self.register(Arc::new(crate::server::SipProtocol::new()));
        #[cfg(feature = "h323")]
        self.register(Arc::new(
            crate::server::h323::actions::H323GatekeeperProtocol::new(),
        ));
        #[cfg(feature = "h323")]
        self.register(Arc::new(
            crate::server::h323::actions::H323EndpointProtocol::new(),
        ));

        #[cfg(feature = "rtp")]
        self.register(Arc::new(crate::server::RtpProtocol::new()));

        #[cfg(feature = "rtsp")]
        self.register(Arc::new(crate::server::RtspProtocol::new()));

        #[cfg(feature = "hls")]
        self.register(Arc::new(crate::server::HlsProtocol::new()));

        #[cfg(feature = "bgp")]
        self.register(Arc::new(crate::server::BgpProtocol::new()));

        #[cfg(feature = "ospf")]
        self.register(Arc::new(crate::server::OspfProtocol::new()));

        #[cfg(feature = "isis")]
        self.register(Arc::new(crate::server::IsisProtocol::new()));

        #[cfg(feature = "rip")]
        self.register(Arc::new(crate::server::RipProtocol::new()));

        #[cfg(feature = "bitcoin")]
        self.register(Arc::new(crate::server::BitcoinProtocol::new()));
        #[cfg(feature = "devp2p")]
        self.register(Arc::new(
            crate::server::devp2p::actions::Devp2pProtocol::new(),
        ));
        #[cfg(feature = "nostr")]
        self.register(Arc::new(crate::server::NostrProtocol::new()));

        #[cfg(feature = "mcp")]
        self.register(Arc::new(crate::server::McpProtocol::new()));

        #[cfg(feature = "openai")]
        self.register(Arc::new(crate::server::OpenAiProtocol::new()));

        #[cfg(feature = "ollama")]
        self.register(Arc::new(crate::server::OllamaProtocol::new()));

        #[cfg(feature = "oauth2")]
        self.register(Arc::new(crate::server::OAuth2Protocol::new()));

        #[cfg(feature = "jsonrpc")]
        self.register(Arc::new(crate::server::JsonRpcProtocol::new()));

        #[cfg(feature = "xmlrpc")]
        self.register(Arc::new(crate::server::XmlRpcProtocol::new()));

        #[cfg(feature = "grpc")]
        self.register(Arc::new(crate::server::GrpcProtocol::new()));
        #[cfg(feature = "grpc-web")]
        self.register(Arc::new(
            crate::server::grpc_web::actions::GrpcWebProtocol::new(),
        ));
        #[cfg(feature = "gnmi")]
        self.register(Arc::new(crate::server::gnmi::actions::GnmiProtocol::new()));
        #[cfg(feature = "connect_rpc")]
        self.register(Arc::new(
            crate::server::connect_rpc::actions::ConnectRpcProtocol::new(),
        ));

        #[cfg(feature = "etcd")]
        self.register(Arc::new(crate::server::EtcdProtocol::new()));

        #[cfg(feature = "zookeeper")]
        self.register(Arc::new(crate::server::ZookeeperProtocol::new()));

        #[cfg(feature = "tor")]
        self.register(Arc::new(crate::server::TorRelayProtocol::new()));

        #[cfg(feature = "vnc")]
        self.register(Arc::new(crate::server::VncProtocol::new()));

        #[cfg(feature = "reverse-shell")]
        self.register(Arc::new(crate::server::ReverseShellProtocol::new()));

        #[cfg(feature = "rdp")]
        self.register(Arc::new(crate::server::RdpProtocol::new()));
        #[cfg(feature = "spice")]
        self.register(Arc::new(crate::server::spice::actions::SpiceProtocol::new()));

        #[cfg(feature = "openapi")]
        self.register(Arc::new(crate::server::OpenApiProtocol::new()));

        #[cfg(feature = "openid")]
        self.register(Arc::new(crate::server::OpenIdProtocol::new()));

        #[cfg(feature = "git")]
        self.register(Arc::new(crate::server::GitProtocol::new()));

        #[cfg(feature = "mercurial")]
        self.register(Arc::new(crate::server::MercurialProtocol::new()));

        #[cfg(feature = "kafka")]
        self.register(Arc::new(crate::server::KafkaProtocol::new()));

        #[cfg(feature = "http3")]
        self.register(Arc::new(crate::server::Http3Protocol::new()));

        #[cfg(feature = "quic")]
        self.register(Arc::new(crate::server::QuicProtocol::new()));

        #[cfg(feature = "torrent-tracker")]
        self.register(Arc::new(crate::server::TorrentTrackerProtocol::new()));

        #[cfg(feature = "torrent-dht")]
        self.register(Arc::new(crate::server::TorrentDhtProtocol::new()));

        #[cfg(feature = "torrent-peer")]
        self.register(Arc::new(crate::server::TorrentPeerProtocol::new()));

        #[cfg(feature = "tls")]
        self.register(Arc::new(crate::server::TlsProtocol::new()));

        #[cfg(feature = "saml-idp")]
        self.register(Arc::new(crate::server::SamlIdpProtocol::new()));

        #[cfg(feature = "saml-sp")]
        self.register(Arc::new(crate::server::SamlSpProtocol::new()));

        #[cfg(feature = "usb-keyboard")]
        self.register(Arc::new(crate::server::UsbKeyboardProtocol::new()));

        #[cfg(feature = "usb-mouse")]
        self.register(Arc::new(crate::server::UsbMouseProtocol::new()));

        #[cfg(feature = "usb-serial")]
        self.register(Arc::new(crate::server::UsbSerialProtocol::new()));

        #[cfg(feature = "usb-msc")]
        self.register(Arc::new(crate::server::UsbMscProtocol::new()));

        #[cfg(feature = "usb-fido2")]
        self.register(Arc::new(crate::server::UsbFido2Protocol::new()));

        #[cfg(feature = "usb-smartcard")]
        self.register(Arc::new(crate::server::UsbSmartCardProtocol::new()));

        #[cfg(feature = "bluetooth-ble")]
        self.register(Arc::new(crate::server::BluetoothBleProtocol::new()));

        #[cfg(feature = "bluetooth-ble-keyboard")]
        self.register(Arc::new(crate::server::BluetoothBleKeyboardProtocol::new()));

        #[cfg(feature = "bluetooth-ble-mouse")]
        self.register(Arc::new(crate::server::BluetoothBleMouseProtocol::new()));

        #[cfg(feature = "bluetooth-ble-beacon")]
        self.register(Arc::new(crate::server::BluetoothBleBeaconProtocol::new()));

        #[cfg(feature = "bluetooth-ble-remote")]
        self.register(Arc::new(crate::server::BluetoothBleRemoteProtocol::new()));

        #[cfg(feature = "bluetooth-ble-battery")]
        self.register(Arc::new(crate::server::BluetoothBleBatteryProtocol::new()));

        #[cfg(feature = "bluetooth-ble-heart-rate")]
        self.register(Arc::new(crate::server::BluetoothBleHeartRateProtocol::new()));

        #[cfg(feature = "bluetooth-ble-thermometer")]
        self.register(Arc::new(
            crate::server::BluetoothBleThermometerProtocol::new(),
        ));

        #[cfg(feature = "bluetooth-ble-environmental")]
        self.register(Arc::new(
            crate::server::BluetoothBleEnvironmentalProtocol::new(),
        ));

        #[cfg(feature = "bluetooth-ble-proximity")]
        self.register(Arc::new(crate::server::BluetoothBleProximityProtocol::new()));

        #[cfg(feature = "bluetooth-ble-gamepad")]
        self.register(Arc::new(crate::server::BluetoothBleGamepadProtocol::new()));

        #[cfg(feature = "bluetooth-ble-presenter")]
        self.register(Arc::new(crate::server::BluetoothBlePresenterProtocol::new()));

        #[cfg(feature = "bluetooth-ble-file-transfer")]
        self.register(Arc::new(
            crate::server::BluetoothBleFileTransferProtocol::new(),
        ));

        #[cfg(feature = "bluetooth-ble-data-stream")]
        self.register(Arc::new(
            crate::server::BluetoothBleDataStreamProtocol::new(),
        ));

        #[cfg(feature = "bluetooth-ble-cycling")]
        self.register(Arc::new(crate::server::BluetoothBleCyclingProtocol::new()));

        #[cfg(feature = "bluetooth-ble-running")]
        self.register(Arc::new(crate::server::BluetoothBleRunningProtocol::new()));

        #[cfg(feature = "bluetooth-ble-weight-scale")]
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
        for (name, feature) in ALL_KNOWN_PROTOCOLS {
            let name_norm = name.to_lowercase().replace(['-', ' '], "_");
            if name_norm == input_norm {
                return Err(ProtocolLookupError::NotCompiled { name, feature });
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
        #[cfg(feature = "tcp")]
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

/// All protocol names known to the netget codebase, paired with the Cargo
/// feature flag that compiles each one in — independent of which features are
/// actually enabled in *this* build. This lets [`ServerRegistry::resolve`] tell
/// "protocol exists but wasn't compiled in" apart from "no such protocol".
///
/// Kept manually in sync with the `#[cfg(feature = "...")]` registrations in
/// `register_protocols()` above. This is the one acceptable central touchpoint
/// per CLAUDE.md's decentralization policy (it plays the same role as the
/// `register()` calls themselves) — when adding a new protocol, add its
/// (canonical name, feature) pair here too.
pub(crate) const ALL_KNOWN_PROTOCOLS: &[(&str, &str)] = &[
    ("TCP", "tcp"),
    ("SOCKET_FILE", "socket_file"),
    // The other three local-descriptor protocols. Without these, a build that does not compile
    // them answers `Unknown protocol: 'pty'. Did you mean 'NTP'?` instead of saying the protocol
    // exists but is not compiled in - the table is what tells those two cases apart.
    ("PTY", "pty"),
    ("STDIO", "stdio"),
    ("NAMED_PIPE", "named_pipe"),
    ("HTTP", "http"),
    ("HTTP2", "http2"),
    ("PyPI", "pypi"),
    ("Maven", "maven"),
    ("UDP", "udp"),
    ("DataLink", "datalink"),
    ("ARP", "arp"),
    ("ICMP", "icmp"),
    ("NMDC Peer", "dc_peer"),
    ("ADC", "adc"),
    ("ADC Peer", "adc_peer"),
    ("Soulseek", "soulseek"),
    ("Soulseek Peer", "soulseek_peer"),
    ("Gnutella", "gnutella"),
    ("DC", "dc"),
    ("DNS", "dns"),
    ("DoT", "dot"),
    ("DoQ", "doq"),
    ("DoH", "doh"),
    ("DHCP", "dhcp"),
    ("BOOTP", "bootp"),
    ("NTP", "ntp"),
    ("TFTP", "tftp"),
    ("NUT", "nut"),
    ("WHOIS", "whois"),
    ("NDP", "ndp"),
    ("DHCPv6", "dhcpv6"),
    ("TUN/TAP", "tuntap"),
    ("Raw IP", "rawip"),
    ("GTP", "gtp"),
    ("M3UA", "m3ua"),
    ("NGAP", "ngap"),
    ("CAN", "can"),
    ("LLDP", "lldp"),
    ("CDP", "cdp"),
    ("STP", "stp"),
    ("VRRP", "vrrp"),
    ("HSRP", "hsrp"),
    ("EAPOL", "eapol"),
    ("Wake-on-LAN", "wol"),
    ("NATS", "nats"),
    ("STOMP", "stomp"),
    ("Ident", "ident"),
    ("Gopher", "gopher"),
    ("DICT", "dict"),
    ("Beanstalkd", "beanstalkd"),
    ("Zabbix", "zabbix"),
    ("Gearman", "gearman"),
    ("NSQ", "nsq"),
    ("Gemini", "gemini"),
    ("Finger", "finger"),
    ("SSDP", "ssdp"),
    ("LLMNR", "llmnr"),
    ("NetBIOS-NS", "netbios-ns"),
    ("SNMP", "snmp"),
    ("IGMP", "igmp"),
    ("Syslog", "syslog"),
    ("FluentForward", "fluent-forward"),
    ("NETFLOWV9", "netflow-v9"),
    ("NETFLOW-V9", "netflow-v9"),
    ("NETFLOW_V9", "netflow-v9"),
    ("IPFIX", "ipfix"),
    ("IPFIX-UDP", "ipfix"),
    ("PrometheusRemoteWrite", "prometheus-remote-write"),
    ("RemoteWrite", "prometheus-remote-write"),
    ("sFlow", "sflow"),
    ("sFlow-v5", "sflow"),
    ("Loki", "loki"),
    ("LokiPush", "loki"),
    ("InfluxDB", "influxdb"),
    ("InfluxDB2", "influxdb"),
    ("GELF", "gelf"),
    ("Graylog", "gelf"),
    ("Graphite", "graphite"),
    ("StatsD", "statsd"),
    ("DogStatsD", "statsd"),
    ("SSH", "ssh"),
    ("SSH Agent", "ssh-agent"),
    ("SVN", "svn"),
    ("IRC", "irc"),
    ("XMPP", "xmpp"),
    ("Telnet", "telnet"),
    ("SMTP", "smtp"),
    ("FTP", "ftp"),
    ("IMAP", "imap"),
    ("NNTP", "nntp"),
    ("MQTT", "mqtt"),
    ("Modbus", "modbus"),
    ("CoAP", "coap"),
    ("AMQP", "amqp"),
    ("mDNS", "mdns"),
    ("LDAP", "ldap"),
    ("MySQL", "mysql"),
    ("MSSQL", "mssql"),
    ("Snowflake", "snowflake"),
    ("Db2", "db2"),
    ("PostgreSQL", "postgresql"),
    ("Memcached", "memcached"),
    ("RADIUS", "radius"),
    ("DIAMETER", "diameter"),
    ("Redis", "redis"),
    ("RSS", "rss"),
    ("Cassandra", "cassandra"),
    ("MongoDB", "mongodb-server"),
    ("DynamoDB", "dynamo"),
    ("SQS", "sqs"),
    ("Elasticsearch", "elasticsearch"),
    ("CouchDB", "couchdb"),
    ("YARN", "yarn"),
    ("Spark", "spark"),
    ("NPM", "npm"),
    ("OCI-Registry", "oci-registry"),
    ("Kubernetes", "kubernetes-server"),
    ("Prometheus", "prometheus"),
    ("OTLP", "otlp"),
    ("Docker", "docker"),
    ("Vault", "vault"),
    ("Bolt", "bolt"),
    ("IPP", "ipp"),
    ("WebDAV", "webdav"),
    ("NFS", "nfs"),
    ("nfc", "nfc"),
    ("SMB", "smb"),
    ("Proxy", "proxy"),
    ("SOCKS5", "socks5"),
    ("WireGuard", "wireguard"),
    ("OpenVPN", "openvpn"),
    ("IPSec/IKEv2", "ipsec"),
    ("TURN", "turn"),
    ("WebRTC Signaling", "webrtc"),
    ("WebSocket", "websocket"),
    ("SIP", "sip"),
    ("H323", "h323"),
    ("H323-Gatekeeper", "h323"),
    ("RTP", "rtp"),
    ("RTSP", "rtsp"),
    ("HLS", "hls"),
    ("ISIS", "isis"),
    ("RIP", "rip"),
    ("Bitcoin P2P", "bitcoin"),
    ("devp2p", "devp2p"),
    ("Nostr", "nostr"),
    ("MCP", "mcp"),
    ("OpenAI", "openai"),
    ("Ollama", "ollama"),
    ("OAuth2", "oauth2"),
    ("JSON-RPC", "jsonrpc"),
    ("XML-RPC", "xmlrpc"),
    ("gRPC", "grpc"),
    ("gRPC-Web", "grpc-web"),
    ("gNMI", "gnmi"),
    ("ConnectRPC", "connect_rpc"),
    ("TACACS", "tacacs"),
    ("NETCONF", "netconf"),
    ("RPKI-RTR", "rpki_rtr"),
    ("RDAP", "rdap"),
    ("HL7", "hl7"),
    ("ICAP", "icap"),
    ("OCPP", "ocpp"),
    ("A2A", "a2a"),
    ("GraphQL", "graphql"),
    ("FastCGI", "fastcgi"),
    ("Redfish", "redfish"),
    ("SCIM", "scim"),
    ("Socket.IO", "socketio"),
    ("CalDAV", "caldav"),
    ("CardDAV", "carddav"),
    ("DICOM", "dicom"),
    ("ACME", "acme"),
    ("FIX", "fix"),
    ("WAMP", "wamp"),
    ("RTMP", "rtmp"),
    ("SRT", "srt"),
    ("AMQP1", "amqp1"),
    ("Thrift", "thrift"),
    ("BMP", "bmp"),
    ("MQTT-SN", "mqtt_sn"),
    ("NBD", "nbd"),
    ("ManageSieve", "managesieve"),
    ("Zenoh", "zenoh"),
    ("LwM2M", "lwm2m"),
    ("RESTCONF", "restconf"),
    ("WebTransport", "webtransport"),
    ("JMAP", "jmap"),
    ("EPP", "epp"),
    ("LMTP", "lmtp"),
    ("LPD", "lpd"),
    ("Echo", "inetd"),
    ("Discard", "inetd"),
    ("Daytime", "inetd"),
    ("QOTD", "inetd"),
    ("Chargen", "inetd"),
    ("Time", "inetd"),
    ("RCON", "rcon"),
    ("A2S", "a2s"),
    ("Minecraft", "minecraft"),
    ("9P", "ninep"),
    ("ZeroMQ", "zeromq"),
    ("SMPP", "smpp"),
    ("ClickHouse", "clickhouse"),
    ("MessagePack-RPC", "msgpack-rpc"),
    ("Zipkin", "zipkin"),
    ("Cap'n Proto RPC", "capnp-rpc"),
    ("KNX/IP", "knx"),
    ("Consul", "consul"),
    ("Milter", "milter"),
    ("Anthropic", "anthropic"),
    ("RadSec", "radsec"),
    ("D-Bus", "dbus"),
    ("BFD", "bfd"),
    ("VXLAN", "vxlan"),
    ("rsync", "rsync"),
    ("PFCP", "pfcp"),
    ("Matrix", "matrix"),
    ("libp2p", "libp2p"),
    ("SunRPC", "sunrpc"),
    ("Guacamole", "guacamole"),
    ("ActivityPub", "activitypub"),
    ("Stratum", "stratum"),
    ("Stratum V2", "stratum-v2"),
    ("Apache Pulsar", "pulsar"),
    ("TR-069 (CWMP)", "tr069"),
    ("SSE", "sse"),
    ("WS-Discovery", "wsdiscovery"),
    ("ONVIF", "onvif"),
    ("Kerberos", "kerberos"),
    ("etcd", "etcd"),
    ("ZooKeeper", "zookeeper"),
    ("Tor Relay", "tor"),
    ("VNC", "vnc"),
    ("Reverse Shell", "reverse-shell"),
    ("RDP", "rdp"),
    ("SPICE", "spice"),
    ("OpenAPI", "openapi"),
    ("OpenID", "openid"),
    ("KAFKA", "kafka"),
    // Separate raw QUIC and RFC 9114 HTTP/3 transports.
    ("HTTP3", "http3"),
    ("QUIC", "quic"),
    ("Torrent-Tracker", "torrent-tracker"),
    ("Torrent-DHT", "torrent-dht"),
    ("Torrent-Peer", "torrent-peer"),
    ("TLS", "tls"),
    ("SamlIdp", "saml-idp"),
    ("SamlSp", "saml-sp"),
    ("USB-Keyboard", "usb-keyboard"),
    ("USB-Mouse", "usb-mouse"),
    ("USB-Serial", "usb-serial"),
    ("USB-MassStorage", "usb-msc"),
    ("usb-fido2", "usb-fido2"),
    ("usb-smartcard", "usb-smartcard"),
    ("BLUETOOTH_BLE", "bluetooth-ble"),
    ("BLUETOOTH_BLE_KEYBOARD", "bluetooth-ble-keyboard"),
    ("BLUETOOTH_BLE_MOUSE", "bluetooth-ble-mouse"),
    ("BLUETOOTH_BLE_BEACON", "bluetooth-ble-beacon"),
    ("BLUETOOTH_BLE_REMOTE", "bluetooth-ble-remote"),
    ("BLUETOOTH_BLE_BATTERY", "bluetooth-ble-battery"),
    ("BLUETOOTH_BLE_HEART_RATE", "bluetooth-ble-heart-rate"),
    ("BLUETOOTH_BLE_THERMOMETER", "bluetooth-ble-thermometer"),
    ("BLUETOOTH_BLE_ENVIRONMENTAL", "bluetooth-ble-environmental"),
    ("BLUETOOTH_BLE_PROXIMITY", "bluetooth-ble-proximity"),
    ("BLUETOOTH_BLE_GAMEPAD", "bluetooth-ble-gamepad"),
    ("BLUETOOTH_BLE_PRESENTER", "bluetooth-ble-presenter"),
    ("BLUETOOTH_BLE_FILE_TRANSFER", "bluetooth-ble-file-transfer"),
    ("BLUETOOTH_BLE_DATA_STREAM", "bluetooth-ble-data-stream"),
    ("BLUETOOTH_BLE_CYCLING", "bluetooth-ble-cycling"),
    ("BLUETOOTH_BLE_RUNNING", "bluetooth-ble-running"),
    ("BLUETOOTH_BLE_WEIGHT_SCALE", "bluetooth-ble-weight-scale"),
    ("POP3", "pop3"),
    ("S3", "s3"),
    ("STUN", "stun"),
    ("WebRTC", "webrtc"),
    ("BGP", "bgp"),
    ("OSPF", "ospf"),
    ("Git", "git"),
    ("Mercurial", "mercurial"),
];

/// Why [`ServerRegistry::resolve`] could not find a protocol for the given input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolLookupError {
    /// A real NetGet protocol by this name exists, but this build was compiled
    /// without the feature that enables it.
    NotCompiled {
        name: &'static str,
        feature: &'static str,
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
            ProtocolLookupError::NotCompiled { name, feature } => write!(
                f,
                "Protocol '{name}' exists but is not compiled into this build (rebuild with --features {feature})"
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
