//! NetGet binary entry point

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Install a rustls CryptoProvider before anything can build a TLS config.
    //
    // rustls 0.23 panics unless exactly one provider is active, and a build can easily
    // have two: `ring` arrives with most of these features, `aws-lc-rs` with the AWS
    // SDK, so e.g. `--features kubernetes,s3` had both and panicked inside
    // `kube::Client::try_default()`. Installing one here settles it.
    //
    // This list must name every feature that enables `dep:rustls` -- otherwise `rustls`
    // is not a direct dependency under that feature and this block will not compile,
    // or worse, is compiled out and leaves the provider uninstalled. It drifted to 5 of
    // 15 before anyone noticed. `tests/rustls_provider_gate_test.rs` derives the true
    // set from Cargo.toml and fails if this list falls behind again.
    #[cfg(any(
        feature = "adc",
        feature = "adc_peer",
        feature = "dc_peer",
        feature = "gnutella",
        feature = "nntp",
        feature = "soulseek",
        feature = "bolt",
        feature = "dc",
        feature = "doh",
        feature = "doq",
        feature = "dot",
        feature = "epp",
        feature = "gemini",
        feature = "gnmi",
        feature = "acme",
        feature = "grpc",
        feature = "http",
        feature = "http2",
        feature = "http3",
        feature = "http_proxy",
        feature = "jmap",
        feature = "kubernetes",
        feature = "kubernetes-server",
        feature = "nostr",
        feature = "oci-registry",
        feature = "openvpn",
        feature = "otlp",
        feature = "pop3",
        feature = "proxy",
        feature = "quic",
        feature = "rdp-client",
        feature = "smtp",
        feature = "tls",
        feature = "tor",
        feature = "webrtc",
        feature = "webtransport",
    ))]
    {
        use rustls::crypto::CryptoProvider;
        let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    }

    netget::cli::run().await
}
