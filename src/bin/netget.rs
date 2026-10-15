//! NetGet binary entry point

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Install a rustls CryptoProvider before anything can build a TLS config.
    //
    // rustls 0.23 panics unless exactly one provider is active, and a build has two:
    // `ring` arrives with most TLS users, `aws-lc-rs` with the AWS SDK, which once
    // panicked inside `kube::Client::try_default()`. Installing one here settles it.
    //
    // Unconditional on purpose. It used to sit behind a `cfg(any(feature = ...))` list of
    // the protocols that enable rustls; that list drifted to 5 of 15, and a build with a
    // missing one started with no provider. `tests/rustls_provider_gate_test.rs` keeps it
    // ungated.
    {
        use rustls::crypto::CryptoProvider;
        let _ = CryptoProvider::install_default(rustls::crypto::ring::default_provider());
    }

    netget::cli::run().await
}
