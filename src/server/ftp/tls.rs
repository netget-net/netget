//! FTPS, explicit mode (RFC 4217): `AUTH TLS` turns the control connection into TLS in place,
//! and after `PBSZ 0` and `PROT P` every data connection is TLS as well.
//!
//! The server is always the TLS server, on the data connections too, whichever end opened them
//! (RFC 4217 §7). rustls does the TLS; this module holds the stream type both connections use
//! and the server's certificate: `cert_path`/`key_path`, or a self-signed one generated at
//! startup for `localhost`, `127.0.0.1` and `::1`.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Context as _, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

/// A control or data connection, before or after TLS.
pub enum MaybeTls {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl MaybeTls {
    pub fn is_tls(&self) -> bool {
        matches!(self, MaybeTls::Tls(_))
    }
}

impl AsyncRead for MaybeTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTls {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// The control connection's write half, shared with the dashboard's peer task.
///
/// `AUTH TLS` has to take the half out, rejoin it with the read half and wrap the socket in
/// TLS, so the half sits in an `Option`: while it is out (only for the length of the
/// handshake, under the lock) a write fails rather than reaching the socket in the clear.
pub struct ControlWriter(pub Option<WriteHalf<MaybeTls>>);

fn taken() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        "the FTP control connection is being upgraded to TLS",
    )
}

impl AsyncWrite for ControlWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut().0.as_mut() {
            Some(w) => Pin::new(w).poll_write(cx, buf),
            None => Poll::Ready(Err(taken())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut().0.as_mut() {
            Some(w) => Pin::new(w).poll_flush(cx),
            None => Poll::Ready(Err(taken())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut().0.as_mut() {
            Some(w) => Pin::new(w).poll_shutdown(cx),
            None => Poll::Ready(Err(taken())),
        }
    }
}

/// The names the generated certificate is valid for: what a client on this machine dials.
const GENERATED_NAMES: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// The server's TLS configuration: the PEM files the operator named, or a self-signed
/// certificate for this machine's loopback names.
pub fn server_config(cert_path: Option<&str>, key_path: Option<&str>) -> Result<Arc<ServerConfig>> {
    match (cert_path, key_path) {
        (Some(cert), Some(key)) => {
            crate::server::tls_cert_manager::load_tls_config_from_files(cert, key)
        }
        (None, None) => generated(),
        _ => Err(anyhow!(
            "cert_path and key_path must be given together (or neither, for a generated \
             self-signed certificate)"
        )),
    }
}

fn generated() -> Result<Arc<ServerConfig>> {
    // `ServerConfig::builder()` needs a process-level provider, which an in-process caller
    // may not have installed.
    let _ = rustls::crypto::ring::default_provider().install_default();
    // rcgen reads a name that parses as an address as an IP SAN, the rest as DNS names.
    let certified = rcgen::generate_simple_self_signed(
        GENERATED_NAMES
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>(),
    )
    .context("generating the FTPS self-signed certificate")?;
    let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der())
        .map_err(|e| anyhow!("the generated FTPS key did not parse: {e}"))?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certified.cert.der().to_vec())],
            key,
        )
        .context("building the FTPS TLS configuration")?;
    Ok(Arc::new(config))
}
