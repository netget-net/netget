//! DNS over TCP, EDNS0, truncation, multi-record answers and zone transfers (AXFR, IXFR),
//! driven by ISC BIND's **`dig`** and Knot DNS's **`kdig`** — two resolvers from different
//! projects, sharing no code with hickory or with each other.
//!
//! Each assertion is on what the resolver printed after decoding NetGet's bytes with its own
//! parser: the records of a 600-name zone in AXFR order (SOA first and last, more than one
//! message), the IXFR difference sequence and the single-SOA "you are current" answer, the TC
//! bit and the retry over TCP, the OPT record answering an EDNS query, and NS/SOA/SRV/PTR and
//! multi-record answers through `send_dns_records`. No model: `zone_support.rs`'s script
//! handler answers. Neither tool is optional — missing, the test fails.

use super::zone_support::{dig, kdig, rr_lines, DnsDevice, FILLER, SERIAL};

#[tokio::test]
async fn dig_and_kdig_transfer_the_zone_over_tcp() {
    let device = DnsDevice::start(None).await;
    for (tool, out) in [
        ("dig", dig(device.port, &["axfr", "example.com."]).await),
        ("kdig", kdig(device.port, &["axfr", "example.com."]).await),
    ] {
        let rrs = rr_lines(&out);
        let soas: Vec<usize> = rrs
            .iter()
            .enumerate()
            .filter(|(_, r)| r.get(3).map(String::as_str) == Some("SOA"))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            soas,
            vec![0, rrs.len() - 1],
            "{tool}: the SOA opens and closes the transfer"
        );
        assert!(
            rrs[0].iter().any(|f| f == &SERIAL.to_string()),
            "{tool}: the serial: {:?}",
            rrs[0]
        );
        // SOA x2, NS, MX, TXT, 3 A, SRV, PTR, the big and huge TXT records, filler.
        assert_eq!(rrs.len(), 2 + 10 + FILLER, "{tool}: every record once");
        assert!(
            rrs.iter()
                .any(|r| r[0] == "_sip._tcp.example.com." && r[3] == "SRV" && r[6] == "5060"),
            "{tool}: SRV decoded"
        );
        assert!(
            rrs.iter()
                .any(|r| r[0] == "host599.example.com." && r[4] == "10.0.2.87"),
            "{tool}: the last filler record"
        );
    }
    // dig reports how many messages the transfer took; 600 names do not fit one 16 KiB message.
    let out = dig(device.port, &["axfr", "example.com."]).await;
    let messages: usize = out
        .lines()
        // ";; XFR size: 611 records (messages 2, bytes 16253)"
        .find_map(|l| l.split("(messages ").nth(1))
        .and_then(|rest| rest.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .expect("dig's XFR size line");
    assert!(messages > 1, "the zone went out in {messages} message(s)");

    // A zone the instructions do not hold: REFUSED, and dig says the transfer failed.
    let out = dig(device.port, &["axfr", "other.test."]).await;
    assert!(out.contains("Transfer failed"), "{out}");
    let refused = device
        .events()
        .await
        .into_iter()
        .filter(|(t, e)| t == "dns_zone_transfer" && e["zone"] == "other.test.")
        .count();
    assert_eq!(refused, 1);
}

#[tokio::test]
async fn ixfr_sends_the_difference_and_tells_a_current_client_so() {
    let device = DnsDevice::start(None).await;
    let from = (SERIAL - 1).to_string();
    for (tool, out) in [
        (
            "dig",
            dig(device.port, &[&format!("ixfr={from}"), "example.com."]).await,
        ),
        (
            "kdig",
            kdig(device.port, &[&format!("IXFR={from}"), "example.com."]).await,
        ),
    ] {
        let rrs = rr_lines(&out);
        // new SOA, old SOA, deleted www .80, new SOA, added www .81, new SOA.
        let shape: Vec<(String, String)> = rrs
            .iter()
            .map(|r| (r[3].clone(), r.get(4).cloned().unwrap_or_default()))
            .collect();
        assert_eq!(shape.len(), 6, "{tool}: {shape:?}");
        assert_eq!(shape[0].0, "SOA");
        assert!(
            rrs[1].contains(&from),
            "{tool}: the old serial: {:?}",
            rrs[1]
        );
        assert_eq!(shape[2], ("A".into(), "192.0.2.80".into()), "{tool}");
        assert_eq!(shape[4], ("A".into(), "192.0.2.81".into()), "{tool}");
        assert_eq!(shape[5].0, "SOA");
    }
    // Already current: the SOA alone.
    let out = dig(device.port, &[&format!("ixfr={SERIAL}"), "example.com."]).await;
    let rrs = rr_lines(&out);
    assert_eq!(rrs.len(), 1, "{out}");
    assert_eq!(rrs[0][3], "SOA");
    let serials: Vec<u64> = device
        .events()
        .await
        .iter()
        .filter(|(t, _)| t == "dns_zone_transfer")
        .filter_map(|(_, e)| e["client_serial"].as_u64())
        .collect();
    assert!(
        serials.contains(&u64::from(SERIAL - 1)) && serials.contains(&u64::from(SERIAL)),
        "the event carried the serial each client holds: {serials:?}"
    );
}

#[tokio::test]
async fn an_answer_too_big_for_udp_is_truncated_and_retried_over_tcp() {
    let device = DnsDevice::start(None).await;
    // Without EDNS the limit is 512 bytes; eight 200-octet strings are over it. dig sees TC,
    // says so, and asks again over TCP, where the whole RRset arrives.
    let out = dig(device.port, &["+noedns", "big.example.com.", "TXT"]).await;
    assert!(out.contains("Truncated, retrying in TCP mode"), "{out}");
    let txt: Vec<_> = rr_lines(&out)
        .into_iter()
        .filter(|r| r.get(3).map(String::as_str) == Some("TXT"))
        .collect();
    assert_eq!(txt.len(), 1, "one record: {out}");
    for c in 'a'..='h' {
        assert!(
            out.contains(&format!("\"{}\"", c.to_string().repeat(200))),
            "all eight 200-octet strings arrived over TCP: {out}"
        );
    }
    let transports: Vec<String> = device
        .events()
        .await
        .iter()
        .filter(|(_, e)| e["domain"] == "big.example.com.")
        .map(|(_, e)| e["transport"].as_str().unwrap_or("").to_string())
        .collect();
    assert_eq!(transports, ["udp", "tcp"]);

    // kdig over UDP with no retry sees the TC bit itself.
    let out = kdig(
        device.port,
        &["+notcp", "+noedns", "+ignoretc", "big.example.com.", "TXT"],
    )
    .await;
    assert!(out.contains("tc"), "the TC flag: {out}");
}

#[tokio::test]
async fn edns_is_answered_and_every_record_type_decodes() {
    let device = DnsDevice::start(None).await;
    // dig offers EDNS by default; the answer carries OPT with this server's 1232-byte buffer.
    let out = dig(device.port, &["www.example.com.", "A"]).await;
    assert!(out.contains("EDNS: version: 0"), "{out}");
    assert!(out.contains("udp: 1232"), "{out}");
    assert!(out.contains("192.0.2.81"), "{out}");

    for (q, t, want) in [
        ("example.com.", "NS", "ns1.example.com."),
        ("example.com.", "SOA", "hostmaster.example.com."),
        ("_sip._tcp.example.com.", "SRV", "5060"),
        ("ptr.example.com.", "PTR", "www.example.com."),
    ] {
        for out in [
            dig(device.port, &["+tcp", q, t]).await,
            kdig(device.port, &["+tcp", q, t]).await,
        ] {
            assert!(
                rr_lines(&out)
                    .iter()
                    .any(|r| r.get(3).map(String::as_str) == Some(t)
                        && r.contains(&want.to_string())),
                "{q} {t} over TCP: {out}"
            );
        }
    }
    // A name that does not exist: NXDOMAIN with the zone's SOA in the authority section.
    let out = kdig(device.port, &["nope.example.com.", "A"]).await;
    assert!(out.contains("NXDOMAIN"), "{out}");
    assert!(
        out.contains("hostmaster.example.com."),
        "the SOA for negative caching: {out}"
    );
}
