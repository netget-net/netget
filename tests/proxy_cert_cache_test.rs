//! Unit tests for `netget::server::proxy::cert_cache`.
//!
//! Migrated out of `src/server/proxy/cert_cache.rs` — CLAUDE.md requires all
//! tests to live under `tests/` and reach internals through the public
//! `netget::` API.
//!
//! The whole file is gated on `proxy` because the module (and its `rcgen` /
//! `rustls` dependencies) are only compiled with that feature.

#![cfg(unix)]

use netget::server::proxy::cert_cache::CertificateCache;
use rcgen::{Certificate, CertificateParams, DnType, KeyPair};

fn test_ca() -> (Certificate, KeyPair, CertificateParams) {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    (ca_cert, ca_key, ca_params)
}

#[tokio::test]
async fn test_cert_cache_generation() {
    let (ca_cert, ca_key, ca_params) = test_ca();
    let cache = CertificateCache::new(ca_cert, ca_key, ca_params);

    let (chain1, key1) = cache.get_or_generate("example.com").await.unwrap();

    // Second request must return the identical certificate *and* the key it
    // certifies, otherwise the TLS handshake fails on every reconnect.
    let (chain2, key2) = cache.get_or_generate("example.com").await.unwrap();
    assert_eq!(chain1, chain2, "Certificate should be cached");
    assert_eq!(
        key1.secret_der(),
        key2.secret_der(),
        "Cached key must accompany the cached certificate"
    );

    // Different domain should generate a new cert
    let (chain3, _key3) = cache.get_or_generate("different.com").await.unwrap();
    assert_ne!(
        chain1, chain3,
        "Different domain should have different cert"
    );

    let stats = cache.get_stats().await;
    assert_eq!(
        stats.total_certificates, 2,
        "Should have 2 certificates in cache"
    );
}

#[tokio::test]
async fn test_cert_and_key_match() {
    let (ca_cert, ca_key, ca_params) = test_ca();
    let cache = CertificateCache::new(ca_cert, ca_key, ca_params);

    // Build a rustls config from both a fresh and a cached lookup. rustls
    // verifies that the key matches the certificate, so this fails loudly if
    // the two ever drift apart.
    let _ = rustls::crypto::ring::default_provider().install_default();
    for _ in 0..2 {
        let (chain, key) = cache.get_or_generate("example.com").await.unwrap();
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("certificate and key must match");
    }
}

#[tokio::test]
async fn test_cert_cache_normalization() {
    let (ca_cert, ca_key, ca_params) = test_ca();
    let cache = CertificateCache::new(ca_cert, ca_key, ca_params);

    // These should all resolve to the same cached certificate
    let (chain1, _) = cache.get_or_generate("Example.COM").await.unwrap();
    let (chain2, _) = cache.get_or_generate("example.com").await.unwrap();
    let (chain3, _) = cache.get_or_generate("  example.com  ").await.unwrap();

    assert_eq!(chain1, chain2);
    assert_eq!(chain2, chain3);

    let stats = cache.get_stats().await;
    assert_eq!(
        stats.total_certificates, 1,
        "Should have only 1 certificate (normalized)"
    );
}
