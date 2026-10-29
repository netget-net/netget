//! The secure channel key derivations against an independent implementation.
//!
//! The vector is libnvme 3.1's (nvme-cli 3.1 built from source on the Ubuntu 24.04 runner):
//! `nvme check-tls-key --identity=1` printed the identity, `nvme keys insert-tls-psk` put the
//! TLS PSK in the kernel's `.nvme` keyring and `keyctl pipe` read it back. The kernel's own NVMe/TCP
//! host and target then completed a TLS connection with that key. Every value below is that
//! run's, so a derivation that drifts from libnvme's by one byte fails here rather than as a
//! handshake that silently never completes.
//!
//! Ubuntu 24.04's packaged nvme-cli 2.8 (libnvme 1.8 on OpenSSL 3.0) derives a different digest
//! from the same key — its HKDF info is the host NQN alone — and is deliberately not matched;
//! `src/server/nvme_tcp/tls_psk.rs` says why.

use netget::server::nvme_tcp::auth::Hash;
use netget::server::nvme_tcp::tls_psk::{
    digest, host_offer, target_psk, ConfiguredKey, Identity, Refusal, DISCOVERY_NQN,
};

const KEY: &str = "NVMeTLSkey-1:01:3rMPGkRFakyIYjFLJ7LZQNiFQ3Lyua16Zm97sG5VS8yDf7yj:";
const HOST: &str = "nqn.2014-08.org.nvmexpress:uuid:ba0803c0-32db-44e9-a205-fe1a672be7d5";
const SUB: &str = "nqn.2026-10.net.netget:tls-probe";
const DIGEST: &str = "Sq8zszVkdTlm5qRXrqxJehYTwQ8dQQRqnxaf+vyU0J0=";
const TLS_PSK: &str = "34c780d5bedb09d45919ca880553a6e271447e41b868d348c8d19654ef84d465";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn derivations_match_libnvme() {
    let key = ConfiguredKey::parse(KEY).expect("libnvme's key parses");
    assert_eq!(key.hash(), Hash::Sha256);
    let retained = key.retained(HOST);
    assert_eq!(digest(Hash::Sha256, &retained, HOST, SUB), DIGEST);

    let (identity, psk) = host_offer(&key, HOST, SUB, 1);
    assert_eq!(
        identity.text(),
        format!("NVMe1R01 {HOST} {SUB} {DIGEST}"),
        "the version 1 identity libnvme printed"
    );
    assert_eq!(hex(&psk), TLS_PSK, "the TLS PSK libnvme put in the keyring");

    // The target derives the same key from the identity alone.
    let (seen, target) = target_psk(&key, &identity.text()).expect("accepted");
    assert_eq!(seen, identity);
    assert_eq!(hex(&target), TLS_PSK);

    let (v0, _) = host_offer(&key, HOST, SUB, 0);
    assert_eq!(
        v0.text(),
        format!("NVMe0R01 {HOST} {SUB}"),
        "libnvme's version 0"
    );
}

#[test]
fn the_interchange_text_round_trips_and_is_checked() {
    let key = ConfiguredKey::parse(KEY).unwrap();
    let raw = [7u8; 48];
    let text = ConfiguredKey::text(&raw, Some(Hash::Sha384));
    assert!(
        text.starts_with("NVMeTLSkey-1:02:") && text.len() == 89,
        "{text}"
    );
    assert_eq!(ConfiguredKey::parse(&text).unwrap().hash(), Hash::Sha384);
    assert_eq!(key.hash(), Hash::Sha256);

    // One base64 character changed breaks the CRC.
    let mut bad = KEY.to_string();
    bad.replace_range(20..21, if &KEY[20..21] == "A" { "B" } else { "A" });
    assert!(ConfiguredKey::parse(&bad).unwrap_err().contains("CRC"));
    // A 48-byte key may not claim SHA-256.
    let lying = ConfiguredKey::text(&raw, Some(Hash::Sha256));
    assert!(ConfiguredKey::parse(&lying).is_err());
    for refused in [
        "",
        "NVMeTLSkey-1:03:AAAA:",
        "DHHC-1:01:AAAA:",
        "NVMeTLSkey-1:01",
    ] {
        assert!(
            ConfiguredKey::parse(refused).is_err(),
            "{refused:?} accepted"
        );
    }
}

#[test]
fn a_target_refuses_identities_it_cannot_serve() {
    let key = ConfiguredKey::parse(KEY).unwrap();
    let (good, _) = host_offer(&key, HOST, SUB, 1);

    // Any subsystem, the discovery NQN included, is the Connect's to accept or refuse; the
    // identity's digest is computed over whichever one it names.
    let (disco, _) = host_offer(&key, HOST, DISCOVERY_NQN, 1);
    let (named, _) = target_psk(&key, &disco.text()).expect("discovery identity");
    assert_eq!(named.subnqn, DISCOVERY_NQN);

    // Renaming the subsystem in a valid identity leaves a digest computed over the old name.
    let other = good.text().replace(SUB, "nqn.2026-10.net.netget:other");
    assert_eq!(target_psk(&key, &other), Err(Refusal::DigestMismatch));

    // A host holding another key computes another digest.
    let stranger =
        ConfiguredKey::parse(&ConfiguredKey::text(&[9u8; 32], Some(Hash::Sha256))).unwrap();
    let (theirs, _) = host_offer(&stranger, HOST, SUB, 1);
    assert_eq!(
        target_psk(&key, &theirs.text()),
        Err(Refusal::DigestMismatch)
    );

    let sha384 = good.text().replacen("NVMe1R01", "NVMe1R02", 1);
    assert_eq!(target_psk(&key, &sha384), Err(Refusal::WrongHash));

    for malformed in [
        "NVMe1G01 a b c".to_string(),
        "NVMe2R01 a b c".to_string(),
        format!("NVMe1R01 {HOST} {SUB}"),
        format!("NVMe0R01 {HOST} {SUB} {DIGEST}"),
        format!("NVMe1R01 {HOST} {SUB} {DIGEST} extra"),
        "x".repeat(10_000),
    ] {
        assert!(
            matches!(target_psk(&key, &malformed), Err(Refusal::Malformed(_))),
            "{malformed:.60} was not refused as malformed"
        );
    }
    assert_eq!(Identity::parse(&good.text()).unwrap(), good);
}
