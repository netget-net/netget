//! `main` installs the rustls `CryptoProvider` unconditionally.
//!
//! rustls 0.23 panics unless exactly one `CryptoProvider` is active, and a NetGet build has
//! two: `ring` arrives with most TLS users, `aws-lc-rs` with the AWS SDK. `main` installs one
//! up front to settle it.
//!
//! That block used to be gated on a hand-written `cfg(any(feature = ...))` list of every
//! protocol feature that enabled rustls. It named 5 of the 15 before a test caught it, and a
//! build with a missing feature started with no provider and panicked the first time anything
//! built a TLS config. Protocols are not features any more and rustls is always a dependency,
//! so the block is ungated — and this test fails if a gate comes back.

#[test]
fn the_crypto_provider_is_installed_without_a_cfg_gate() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/netget.rs"),
    )
    .expect("read src/bin/netget.rs");
    let install = src
        .find("CryptoProvider::install_default")
        .expect("main no longer installs a rustls CryptoProvider");
    let block = src[..install].rfind('{').expect("install block");
    // The nearest code line above the block's `{`, past its comment.
    let above = src[..block]
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("//"))
        .unwrap_or("");
    assert!(
        !above.starts_with("#[cfg") && !above.ends_with(")]"),
        "the CryptoProvider install in src/bin/netget.rs is behind a cfg gate again ({above}); \
         a build the gate misses starts with no provider and panics on its first TLS config"
    );
}
