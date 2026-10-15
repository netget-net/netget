//! The N2 transport: SCTP by default, refused by name where the host has none, and a lab TCP
//! framing that says what it is everywhere it appears.
use netget::llm::actions::protocol_trait::Protocol;
use netget::server::ngap::actions::NgapProtocol;
use netget::server::ngap::codec;
use netget::server::ngap::transport::{self, Transport};

fn host_has_sctp() -> bool {
    socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::from(transport::IPPROTO_SCTP)),
    )
    .is_ok()
}

/// Both outcomes are asserted: where the kernel has SCTP the listener binds; where it has none
/// the refusal names SCTP, the specification and the escape hatch. Neither branch is a skip.
#[tokio::test]
async fn sctp_binds_where_it_exists_and_is_refused_by_name_where_it_does_not() {
    let result = transport::bind_listener("127.0.0.1:0".parse().unwrap(), Transport::Sctp).await;
    if host_has_sctp() {
        let listener = result.expect("this host has SCTP, so the AMF must bind it");
        assert_ne!(listener.local_addr().unwrap().port(), 0);
    } else {
        let err = result.expect_err("no SCTP stack: must refuse").to_string();
        assert!(err.contains("SCTP"), "{err}");
        assert!(err.contains("38.412"), "{err}");
        assert!(err.contains("transport=\"tcp\""), "{err}");
        assert!(err.contains("NON-STANDARD"), "{err}");
    }
}

/// Where SCTP exists, one association carries whole messages both ways — each `write` one SCTP
/// message, read back with its boundary intact — and a message over the bound is drained and
/// reported without losing the next one. Where it does not, connecting is refused by name.
#[tokio::test]
async fn an_sctp_association_carries_whole_messages_where_sctp_exists() {
    use netget::server::ngap::transport::{Conn, ReadOutcome};
    use std::time::Duration;
    if !host_has_sctp() {
        let err = transport::connect(
            "127.0.0.1:38412".parse().unwrap(),
            Transport::Sctp,
            Duration::from_secs(2),
        )
        .await
        .err()
        .expect("no SCTP: connect must refuse")
        .to_string();
        assert!(err.contains("SCTP") && err.contains("gNB"), "{err}");
        return;
    }
    let listener = transport::bind_listener("127.0.0.1:0".parse().unwrap(), Transport::Sctp)
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let conn = Conn::new(stream, Transport::Sctp);
        let mut reader = conn.reader();
        let mut writer = conn.writer();
        let mut got = Vec::new();
        for _ in 0..3 {
            match reader.next(Duration::from_secs(10)).await {
                ReadOutcome::Message(m) => got.push(Ok(m.len())),
                ReadOutcome::TooLarge(n) => got.push(Err(n)),
                other => panic!("unexpected {other:?}"),
            }
        }
        writer
            .send(&codec::ng_reset_acknowledge(None).unwrap())
            .await
            .unwrap();
        got
    });
    let client = transport::connect(addr, Transport::Sctp, Duration::from_secs(5))
        .await
        .unwrap();
    let mut w = client.writer();
    let mut r = client.reader();
    let reset = codec::ng_reset(&codec::Cause::misc(codec::MISC_OM_INTERVENTION), None).unwrap();
    w.send(&reset).await.unwrap();
    // Over the bound: sent on the raw socket, since NetGet's own writer refuses to send it.
    let big = vec![0u8; codec::MAX_PDU_LEN + 100];
    client.socket().send(&big).unwrap();
    w.send(&reset).await.unwrap();
    let got = server.await.unwrap();
    assert_eq!(got[0], Ok(reset.len()));
    assert!(
        matches!(got[1], Err(n) if n > codec::MAX_PDU_LEN),
        "{got:?}"
    );
    assert_eq!(
        got[2],
        Ok(reset.len()),
        "the boundary after the oversize message survived"
    );
    match r.next(Duration::from_secs(10)).await {
        ReadOutcome::Message(m) => assert_eq!(m, codec::ng_reset_acknowledge(None).unwrap()),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn the_lab_transport_binds_and_is_labelled() {
    let listener = transport::bind_listener("127.0.0.1:0".parse().unwrap(), Transport::Tcp)
        .await
        .unwrap();
    assert_ne!(listener.local_addr().unwrap().port(), 0);
    assert!(Transport::Tcp.label().contains("NON-STANDARD"));
    assert!(Transport::Sctp.label().contains("PPID 60"));
    assert!(Transport::parse("udp").is_err());
}

#[test]
fn the_declared_default_is_sctp_and_the_port_is_38412() {
    let p = NgapProtocol::new();
    let param = p
        .get_startup_parameters()
        .into_iter()
        .find(|p| p.name == "transport")
        .expect("transport is declared");
    assert_eq!(param.example, serde_json::json!("sctp"));
    assert!(param.description.contains("NON-STANDARD"));
    assert_eq!(Transport::from_params(None).unwrap(), Transport::Sctp);
    let m = p.metadata();
    assert_eq!(m.max_inbound_bytes, Some(codec::MAX_PDU_LEN));
    assert_eq!(codec::SCTP_PORT, 38412);
    assert_eq!(
        m.well_known_port,
        Some(codec::SCTP_PORT),
        "metadata and codec agree"
    );
    assert_eq!(codec::PPID, 60);
    assert!(p.stack_name().contains("SCTP"));
}

#[test]
fn ue_associated_pdus_are_routed_off_stream_zero() {
    let reset = codec::ng_reset(&codec::Cause::misc(codec::MISC_OM_INTERVENTION), None).unwrap();
    assert!(!codec::is_ue_associated(&reset));
    let dl = codec::downlink_nas_transport(1, 1, &[0x7e, 0x00, 0x5b, 0x01]).unwrap();
    assert!(codec::is_ue_associated(&dl));
    let release = codec::ue_context_release_command(1, None, &codec::Cause::nas(0)).unwrap();
    assert!(
        codec::is_ue_associated(&release),
        "UE-NGAP-IDs alone makes it UE-associated"
    );
}
