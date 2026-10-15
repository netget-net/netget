use netget::protocol::server_registry::registry;

#[test]
fn test_parse_http_stack() {
    assert_eq!(
        registry().parse_from_str("http stack"),
        Some("HTTP".to_string())
    );
    assert_eq!(
        registry().parse_from_str("http server"),
        Some("HTTP".to_string())
    );
    assert_eq!(
        registry().parse_from_str("via http"),
        Some("HTTP".to_string())
    );
}

#[test]
fn test_parse_tcp_stack() {
    assert_eq!(registry().parse_from_str("tcp"), Some("TCP".to_string()));
    assert_eq!(
        registry().parse_from_str("raw tcp"),
        Some("TCP".to_string())
    );
}

/// "ftp" belongs to FTP, not TCP.
///
/// TCP used to declare it as a keyword, from before a real FTP protocol existed, so a request
/// for an FTP server silently got a raw TCP socket. This test is gated on the `ftp` feature
/// rather than `tcp` because with only `tcp` compiled there is nothing for "ftp" to resolve to.
#[test]
fn test_parse_ftp_stack() {
    assert_eq!(registry().parse_from_str("ftp"), Some("FTP".to_string()));
    assert_eq!(
        registry().parse_from_str("file transfer"),
        Some("FTP".to_string())
    );
}

#[test]
fn test_parse_udp_stack() {
    assert_eq!(registry().parse_from_str("udp"), Some("UDP".to_string()));
    assert_eq!(
        registry().parse_from_str("via udp"),
        Some("UDP".to_string())
    );
}

#[test]
fn test_parse_dns_stack() {
    assert_eq!(registry().parse_from_str("dns"), Some("DNS".to_string()));
    assert_eq!(
        registry().parse_from_str("via dns"),
        Some("DNS".to_string())
    );
    assert_eq!(
        registry().parse_from_str("dns server"),
        Some("DNS".to_string())
    );
}

#[test]
fn test_parse_dhcp_stack() {
    assert_eq!(registry().parse_from_str("dhcp"), Some("DHCP".to_string()));
    assert_eq!(
        registry().parse_from_str("dhcp server"),
        Some("DHCP".to_string())
    );
}

#[test]
fn test_parse_ntp_stack() {
    assert_eq!(registry().parse_from_str("ntp"), Some("NTP".to_string()));
    assert_eq!(
        registry().parse_from_str("time server"),
        Some("NTP".to_string())
    );
}

#[test]
fn test_parse_snmp_stack() {
    assert_eq!(registry().parse_from_str("snmp"), Some("SNMP".to_string()));
    assert_eq!(
        registry().parse_from_str("snmp agent"),
        Some("SNMP".to_string())
    );
}

#[test]
fn test_parse_ssh_stack() {
    assert_eq!(registry().parse_from_str("ssh"), Some("SSH".to_string()));
    assert_eq!(
        registry().parse_from_str("ssh server"),
        Some("SSH".to_string())
    );
    assert_eq!(
        registry().parse_from_str("via ssh"),
        Some("SSH".to_string())
    );
}

#[test]
fn test_parse_irc_stack() {
    assert_eq!(registry().parse_from_str("irc"), Some("IRC".to_string()));
    assert_eq!(
        registry().parse_from_str("chat server"),
        Some("IRC".to_string())
    );
    assert_eq!(
        registry().parse_from_str("irc chat"),
        Some("IRC".to_string())
    );
}

#[test]
fn test_parse_telnet_stack() {
    assert_eq!(
        registry().parse_from_str("telnet"),
        Some("Telnet".to_string())
    );
    assert_eq!(
        registry().parse_from_str("telnet server"),
        Some("Telnet".to_string())
    );
}

#[test]
fn test_parse_smtp_stack() {
    assert_eq!(registry().parse_from_str("smtp"), Some("SMTP".to_string()));
    assert_eq!(
        registry().parse_from_str("mail server"),
        Some("SMTP".to_string())
    );
    assert_eq!(
        registry().parse_from_str("email server"),
        Some("SMTP".to_string())
    );
}

#[test]
fn test_parse_mdns_stack() {
    assert_eq!(registry().parse_from_str("mdns"), Some("mDNS".to_string()));
    assert_eq!(
        registry().parse_from_str("bonjour"),
        Some("mDNS".to_string())
    );
    assert_eq!(
        registry().parse_from_str("dns-sd"),
        Some("mDNS".to_string())
    );
}

#[test]
#[cfg(unix)]
fn test_parse_proxy_stack() {
    assert_eq!(
        registry().parse_from_str("proxy"),
        Some("Proxy".to_string())
    );
    assert_eq!(
        registry().parse_from_str("http proxy"),
        Some("Proxy".to_string())
    );
    assert_eq!(registry().parse_from_str("mitm"), Some("Proxy".to_string()));
}

#[test]
fn test_parse_webdav_stack() {
    assert_eq!(
        registry().parse_from_str("webdav"),
        Some("WebDAV".to_string())
    );
    assert_eq!(
        registry().parse_from_str("dav server"),
        Some("WebDAV".to_string())
    );
    assert_eq!(
        registry().parse_from_str("via webdav"),
        Some("WebDAV".to_string())
    );
}

#[test]
#[cfg(unix)]
fn test_parse_nfs_stack() {
    assert_eq!(registry().parse_from_str("nfs"), Some("NFS".to_string()));
    assert_eq!(
        registry().parse_from_str("file server"),
        Some("NFS".to_string())
    );
    assert_eq!(
        registry().parse_from_str("nfs server"),
        Some("NFS".to_string())
    );
}

#[test]
fn test_parse_sip_all_keywords() {
    // Test that ALL keywords defined by SIP protocol are recognized
    // This verifies that parse_from_str checks all keywords, not just hardcoded ones
    assert_eq!(registry().parse_from_str("sip"), Some("SIP".to_string()));
    assert_eq!(registry().parse_from_str("voip"), Some("SIP".to_string()));
    assert_eq!(
        registry().parse_from_str("session initiation"),
        Some("SIP".to_string())
    );
    assert_eq!(
        registry().parse_from_str("SIP server"),
        Some("SIP".to_string())
    );
    assert_eq!(
        registry().parse_from_str("VoIP server"),
        Some("SIP".to_string())
    );
}

/// Cloud services (S3, SQS, DynamoDB) are all HTTP/REST underneath. The model kept
/// resolving "act as an S3 bucket" / "act as an SQS queue" to the generic `http` stack or
/// to the wrong AWS service. Two root causes are covered here:
///   1. "queue" was claimed by both AMQP and SQS, so it resolved by HashMap order.
///   2. "dynamodb" never matched the bare "dynamo" keyword (the "db" broke the word
///      boundary), so DynamoDB requests resolved to nothing.
#[test]
fn test_parse_s3_stack() {
    assert_eq!(registry().parse_from_str("s3"), Some("S3".to_string()));
    assert_eq!(
        registry().parse_from_str("act as an S3 bucket"),
        Some("S3".to_string())
    );
    assert_eq!(
        registry().parse_from_str("emulate AWS S3 object storage"),
        Some("S3".to_string())
    );
    assert_eq!(registry().parse_from_str("minio"), Some("S3".to_string()));
}

#[test]
fn test_parse_sqs_stack() {
    assert_eq!(registry().parse_from_str("sqs"), Some("SQS".to_string()));
    assert_eq!(
        registry().parse_from_str("act as an SQS queue"),
        Some("SQS".to_string())
    );
    assert_eq!(
        registry().parse_from_str("stand up an AWS message queue"),
        Some("SQS".to_string())
    );
}

#[test]
fn test_parse_dynamo_stack() {
    assert_eq!(
        registry().parse_from_str("dynamo"),
        Some("DynamoDB".to_string())
    );
    // The regression: "dynamodb" in free text used to match nothing.
    assert_eq!(
        registry().parse_from_str("emulate a DynamoDB table"),
        Some("DynamoDB".to_string())
    );
    assert_eq!(
        registry().parse_from_str("aws dynamodb"),
        Some("DynamoDB".to_string())
    );
}

/// The AWS services must beat the generic HTTP stack even when the instruction also
/// mentions HTTP, since they are all HTTP underneath.
#[test]
fn test_s3_beats_http() {
    assert_eq!(
        registry().parse_from_str("an S3 bucket served over http"),
        Some("S3".to_string())
    );
}

/// AMQP must still resolve from its own names now that it no longer claims "queue".
#[test]
fn test_parse_amqp_stack() {
    assert_eq!(registry().parse_from_str("amqp"), Some("AMQP".to_string()));
    assert_eq!(
        registry().parse_from_str("a RabbitMQ broker"),
        Some("AMQP".to_string())
    );
}

/// "queue" was claimed by both AMQP and SQS. After the fix neither claims the bare word,
/// so it must not appear in the overlap report.
#[test]
fn test_queue_keyword_no_longer_overlaps() {
    let overlaps = registry().get_keyword_overlaps();
    assert!(
        !overlaps.iter().any(|(kw, _)| kw == "queue"),
        "the bare keyword 'queue' should no longer be claimed by multiple protocols: {:?}",
        overlaps
            .iter()
            .find(|(kw, _)| kw == "queue")
            .map(|(_, p)| p)
    );
}

#[test]
fn test_no_keyword_overlaps() {
    // This test verifies that the registry initialization succeeds without panicking.
    // The validate_keyword_uniqueness() function is called during registry creation,
    // so if there are any keyword overlaps, it will panic here.

    // Simply accessing the registry triggers initialization and validation
    let reg = registry();

    // If we get here, validation passed - no keyword overlaps detected
    assert!(
        !reg.all_protocols().is_empty(),
        "Registry should have protocols registered"
    );
}

#[test]
fn test_stack_name_as_keyword() {
    // Test that full stack names are recognized as valid keywords
    // This verifies that build_keyword_map() correctly adds stack_name() as a keyword

    // Test various protocols with their full stack names (feature-gated)
    assert_eq!(
        registry().parse_from_str("ETH>IP>TCP>HTTP"),
        Some("HTTP".to_string()),
        "Full HTTP stack name should be recognized"
    );

    assert_eq!(
        registry().parse_from_str("eth>ip>udp>dns"), // Test case-insensitivity
        Some("DNS".to_string()),
        "DNS stack name should be recognized (case-insensitive)"
    );

    assert_eq!(
        registry().parse_from_str("ETH>IP>TCP>SSH"),
        Some("SSH".to_string()),
        "Full SSH stack name should be recognized"
    );

    assert_eq!(
        registry().parse_from_str("ETH>IP>TCP>SMTP"),
        Some("SMTP".to_string()),
        "Full SMTP stack name should be recognized"
    );

    // Test that we can parse stack names returned by the registry itself
    for (protocol_name, protocol) in registry().all_protocols() {
        let stack_name = protocol.stack_name();
        let parsed = registry().parse_from_str(stack_name);
        assert_eq!(
            parsed,
            Some(protocol_name.clone()),
            "Protocol {} stack name '{}' should parse back to itself",
            protocol_name,
            stack_name
        );
    }
}
