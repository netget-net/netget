//! DNSSEC on NetGet's DNS server, checked by validators that share no code with hickory:
//!
//! - ISC BIND's **`delv`** validates answers against a trust anchor built from the zone's own
//!   DNSKEY (fetched with `dig`): a positive answer and a compact-denial negative one.
//! - NLnet Labs' **`drill`** (ldns) chases the same signatures with the key as its anchor.
//! - **`ldns-verify-zone`** (ldns) and BIND's **`dnssec-verify`** each check a whole signed
//!   zone received by AXFR: every RRSIG against the DNSKEY, and the NSEC chain closing over
//!   every name.
//!
//! Two validators per question, from two projects. No model: `zone_support.rs`'s handler
//! answers. None of the tools is optional — missing, the test fails.

use super::zone_support::{dig, run, DnsDevice};
use serde_json::json;

async fn signed() -> DnsDevice {
    DnsDevice::start(Some(json!({"dnssec_zone": "example.com."}))).await
}

/// The zone's DNSKEY as `dig` prints it: flags, protocol, algorithm, base64 key.
async fn dnskey(port: u16) -> (String, String, String, String) {
    let out = dig(port, &["+short", "example.com.", "DNSKEY"]).await;
    let mut f = out.split_whitespace();
    let flags = f.next().expect("a DNSKEY").to_string();
    let proto = f.next().unwrap().to_string();
    let alg = f.next().unwrap().to_string();
    let key: String = f.collect();
    (flags, proto, alg, key)
}

#[tokio::test]
async fn delv_and_drill_validate_answers_and_denials() {
    let device = signed().await;
    let (flags, proto, alg, key) = dnskey(device.port).await;
    assert_eq!(
        (flags.as_str(), proto.as_str(), alg.as_str()),
        ("257", "3", "13")
    );
    let dir = tempfile::tempdir().unwrap();

    // delv: a trust-anchors clause naming the key.
    let anchors = dir.path().join("anchors.conf");
    std::fs::write(
        &anchors,
        format!(
            "trust-anchors {{\n  example.com. static-key {flags} {proto} {alg} \"{key}\";\n}};\n"
        ),
    )
    .unwrap();
    let delv = |name: &'static str, rtype: &'static str| {
        let port = device.port.to_string();
        let anchors = anchors.to_str().unwrap().to_string();
        async move {
            run(
                "delv",
                &[
                    "@127.0.0.1".into(),
                    "-p".into(),
                    port,
                    "-a".into(),
                    anchors,
                    "+root=example.com".into(),
                    name.into(),
                    rtype.into(),
                ],
                "bind9-dnsutils (delv)",
            )
            .await
        }
    };
    let out = delv("www.example.com.", "A").await;
    assert!(out.contains("; fully validated"), "{out}");
    assert!(out.contains("192.0.2.81"), "{out}");
    let out = delv("nope.example.com.", "A").await;
    assert!(
        out.contains("fully validated"),
        "a validated negative answer: {out}"
    );
    let out = delv("www.example.com.", "AAAA").await;
    assert!(out.contains("fully validated"), "a validated NODATA: {out}");

    // drill: the DNSKEY as a key file, signatures chased from the answer.
    let keyfile = dir.path().join("example.com.key");
    std::fs::write(
        &keyfile,
        format!("example.com. 3600 IN DNSKEY {flags} {proto} {alg} {key}\n"),
    )
    .unwrap();
    let out = run(
        "drill",
        &[
            "-S".into(),
            "-k".into(),
            keyfile.to_str().unwrap().into(),
            "-p".into(),
            device.port.to_string(),
            "@127.0.0.1".into(),
            "www.example.com.".into(),
            "A".into(),
        ],
        "ldnsutils (drill)",
    )
    .await;
    assert!(out.contains("Chase successful"), "{out}");
    assert!(out.contains("keytag:") && out.contains("alg: 13"), "{out}");
}

#[tokio::test]
async fn ldns_and_bind_verify_a_signed_zone_transfer() {
    let device = signed().await;
    let out = dig(
        device.port,
        &["+nocmd", "+nostats", "+nocomments", "axfr", "example.com."],
    )
    .await;
    // A zone file holds its SOA once; AXFR repeats it at the end.
    let mut lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(lines.last().unwrap().contains("SOA"));
    lines.pop();
    let dir = tempfile::tempdir().unwrap();
    let zonefile = dir.path().join("example.com.zone");
    std::fs::write(&zonefile, lines.join("\n") + "\n").unwrap();
    let out = run(
        "ldns-verify-zone",
        &[zonefile.to_str().unwrap().into()],
        "ldnsutils (ldns-verify-zone)",
    )
    .await;
    assert!(out.contains("Zone is verified and complete"), "{out}");
    // `-z`: this server signs with one key (flags 257) acting as KSK and ZSK — RFC 6781's
    // single-type signing, a "CSK". Without -z, dnssec-verify insists on a separate key
    // without the SEP flag and reports "Missing ZSK" before checking a single signature.
    let out = run(
        "dnssec-verify",
        &[
            "-z".into(),
            "-o".into(),
            "example.com.".into(),
            zonefile.to_str().unwrap().into(),
        ],
        "bind9-utils (dnssec-verify)",
    )
    .await;
    assert!(
        out.contains("Zone fully signed") || out.contains("fully signed"),
        "dnssec-verify: {out}"
    );
    // The NSEC chain covers every owner name once: the apex, the six named owners below it
    // (ns1, www, mail, _sip._tcp, ptr, big) and the 600 fillers.
    let nsec = lines.iter().filter(|l| l.contains("\tNSEC\t")).count();
    assert_eq!(nsec, 1 + 6 + 600, "one NSEC per owner name");
}
