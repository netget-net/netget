//! Shared owned QUIC transport and authenticated client configuration.
use crate::protocol::StartupParams;
use anyhow::{bail, ensure, Context, Result};
use std::{sync::Arc, time::Duration};
pub const MAX_STREAMS: usize = 32;
pub const MAX_CONNECTIONS: usize = 64;
pub const MAX_BYTES: usize = 1024 * 1024;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const RAW_ALPN: &[u8] = b"netget-quic";
/// RFC 9221 DATAGRAM frames buffered per connection before Quinn drops the oldest. A
/// datagram is unreliable by definition, so a peer that outruns the handler loses
/// datagrams rather than growing this; 64 KiB holds about fifty full-size ones.
pub const DATAGRAM_BUFFER_BYTES: usize = 64 * 1024;
/// Closing on Drop matters when the owning registered task is aborted during removal.
/// Quinn's driver otherwise retains the endpoint until all connection handles disappear.
pub struct EndpointGuard(pub quinn::Endpoint);
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"endpoint stopped");
    }
}
pub struct ConnectionGuard(pub quinn::Connection);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"connection stopped");
    }
}

pub fn parameter(
    name: &str,
    description: &str,
    example: serde_json::Value,
    default: Option<serde_json::Value>,
) -> crate::llm::actions::ParameterDefinition {
    crate::llm::actions::ParameterDefinition {
        name: name.into(),
        description: description.into(),
        type_hint: if example.is_number() {
            "number"
        } else {
            "string"
        }
        .into(),
        required: false,
        example,
        default,
    }
}

pub fn bounded_parameter(
    params: Option<&crate::protocol::StartupParams>,
    name: &str,
    default: u64,
    max: u64,
) -> Result<u64> {
    let value = params
        .map(|p| p.get_optional_u64(name))
        .transpose()?
        .flatten()
        .unwrap_or(default);
    if value == 0 || value > max {
        bail!("{name} must be between 1 and {max}");
    }
    Ok(value)
}

pub fn client_parameters() -> Vec<crate::llm::actions::ParameterDefinition> {
    vec![
        parameter(
            "server_name",
            "TLS authentication name; defaults to remote hostname",
            serde_json::json!("localhost"),
            None,
        ),
        parameter(
            "ca_cert_path",
            "Additional PEM CA or self-signed certificate to trust",
            serde_json::json!("ca.pem"),
            None,
        ),
        parameter(
            "handshake_timeout_secs",
            "Resolution and TLS handshake deadline, 1..60 seconds",
            serde_json::json!(10),
            Some(serde_json::json!(10)),
        ),
        parameter(
            "exchange_timeout_secs",
            "Whole stream exchange deadline, 1..300 seconds",
            serde_json::json!(30),
            Some(serde_json::json!(30)),
        ),
        parameter(
            "idle_timeout_secs",
            "Connection idle deadline, 1..3600 seconds",
            serde_json::json!(300),
            Some(serde_json::json!(300)),
        ),
    ]
}
pub fn transport(idle: Duration, bidi: u32, uni: u32) -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config
        .max_concurrent_bidi_streams(bidi.into())
        .max_concurrent_uni_streams(uni.into());
    config.max_idle_timeout(Some(idle.try_into().expect("bounded idle timeout")));
    config.stream_receive_window((MAX_BYTES as u32).into());
    config.receive_window((MAX_BYTES as u32 * MAX_STREAMS as u32).into());
    // Advertises max_datagram_frame_size (RFC 9221 §3), so a peer may send DATAGRAM frames;
    // both buffers are bounded.
    config.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER_BYTES));
    config.datagram_send_buffer_size(DATAGRAM_BUFFER_BYTES);
    Arc::new(config)
}
pub async fn connect(
    remote: &str,
    params: Option<&StartupParams>,
    alpn: &[u8],
    uni: u32,
) -> Result<(EndpointGuard, ConnectionGuard)> {
    let handshake =
        Duration::from_secs(bounded_parameter(params, "handshake_timeout_secs", 10, 60)?);
    let idle = Duration::from_secs(bounded_parameter(params, "idle_timeout_secs", 300, 3600)?);
    let auth = params
        .map(|p| p.get_optional_string("server_name"))
        .transpose()?
        .flatten();
    let ca = params
        .map(|p| p.get_optional_string("ca_cert_path"))
        .transpose()?
        .flatten();
    let name = remote
        .rsplit_once(':')
        .context("Remote address must be host:port or [IPv6]:port")?
        .0
        .trim_matches(['[', ']']);
    let name = auth.unwrap_or_else(|| name.to_owned());
    ensure!(
        !alpn.is_empty() && alpn.len() <= 255,
        "ALPN must contain 1..255 bytes"
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca {
        let pem = std::fs::read(path).context("Read QUIC trust certificate")?;
        let certs = rustls_pemfile::certs(&mut pem.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(!certs.is_empty(), "Trust file contains no certificates");
        for cert in certs {
            roots.add(cert)?;
        }
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![alpn.to_vec()];
    tls.enable_early_data = false;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    config.transport_config(transport(idle, 0, uni));
    tokio::time::timeout(handshake, async {
        let remote = tokio::net::lookup_host(remote)
            .await?
            .next()
            .context("No address resolved")?;
        let mut endpoint = quinn::Endpoint::client(
            if remote.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            }
            .parse()?,
        )?;
        endpoint.set_default_client_config(config);
        let endpoint = EndpointGuard(endpoint);
        let connection = endpoint
            .0
            .connect(remote, &name)?
            .await
            .context("QUIC TLS handshake (check ca_cert_path and server_name)")?;
        Ok((endpoint, ConnectionGuard(connection)))
    })
    .await
    .context("QUIC handshake deadline exceeded")?
}
