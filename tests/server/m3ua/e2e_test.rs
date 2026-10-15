//! End-to-end M3UA tests.
//!
//! # What these prove, and what they do not
//!
//! They drive a real NetGet process over a real socket with a mocked model, through the whole
//! path: framing, the ASP state machine, the admission decisions, and DATA in both directions.
//!
//! **They run over the non-standard TCP lab transport, which is not M3UA's transport.** RFC 4666
//! puts M3UA on SCTP; macOS has no SCTP stack, so on this machine there is no way to run the
//! real one. Every layer above the socket is identical either way — M3UA is length-delimited,
//! so the framing does not change — but nothing here is evidence that NetGet interoperates with
//! a real SIGTRAN peer, because no real SIGTRAN peer speaks TCP. That is why the protocol is
//! `Experimental` and why `metadata().notes` says so in as many words. `transport_test.rs`
//! covers the SCTP refusal itself.
//!
//! Messages are hand-built from RFC 4666 here rather than through `codec`, so the tests
//! exercise the decoder against something NetGet did not encode.

#[cfg(unix)]
mod m3ua_e2e_test {
    use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    const CLASS_MGMT: u8 = 0;
    const CLASS_TRANSFER: u8 = 1;
    const CLASS_ASPSM: u8 = 3;
    const CLASS_ASPTM: u8 = 4;

    const MGMT_ERR: u8 = 0;
    const TRANSFER_DATA: u8 = 1;
    const ASPSM_ASPUP: u8 = 1;
    const ASPSM_BEAT: u8 = 3;
    const ASPSM_ASPUP_ACK: u8 = 4;
    const ASPSM_BEAT_ACK: u8 = 6;
    const ASPTM_ASPAC: u8 = 1;
    const ASPTM_ASPIA: u8 = 2;
    const ASPTM_ASPAC_ACK: u8 = 3;
    const ASPTM_ASPIA_ACK: u8 = 4;

    const TAG_INFO_STRING: u16 = 0x0004;
    const TAG_ROUTING_CONTEXT: u16 = 0x0006;
    const TAG_HEARTBEAT_DATA: u16 = 0x0009;
    const TAG_TRAFFIC_MODE_TYPE: u16 = 0x000b;
    const TAG_ERROR_CODE: u16 = 0x000c;
    const TAG_ASP_IDENTIFIER: u16 = 0x0011;
    const TAG_PROTOCOL_DATA: u16 = 0x0210;

    const ERR_UNEXPECTED_MESSAGE: u32 = 0x06;
    const ERR_REFUSED_MANAGEMENT_BLOCKING: u32 = 0x0d;

    /// How long to wait for a message that depends on a model round-trip.
    const LLM_TIMEOUT: Duration = Duration::from_secs(60);
    /// How long to wait for one NetGet answers in Rust with no model involved.
    const WIRE_TIMEOUT: Duration = Duration::from_secs(15);

    /// Build an M3UA message from the RFC: common header, then TLV parameters padded to a
    /// 4-octet boundary with the padding excluded from each parameter's length field.
    fn m3ua_message(class: u8, msg_type: u8, parameters: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (tag, value) in parameters {
            let declared = (4 + value.len()) as u16;
            body.extend_from_slice(&tag.to_be_bytes());
            body.extend_from_slice(&declared.to_be_bytes());
            body.extend_from_slice(value);
            let padding = (4 - (declared as usize % 4)) % 4;
            body.resize(body.len() + padding, 0);
        }
        let total = (8 + body.len()) as u32;
        let mut out = vec![1u8, 0x00, class, msg_type];
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn u32_param(value: u32) -> Vec<u8> {
        value.to_be_bytes().to_vec()
    }

    /// A Protocol Data parameter value: OPC, DPC, SI, NI, MP, SLS, then the user part.
    fn protocol_data(
        opc: u32,
        dpc: u32,
        si: u8,
        ni: u8,
        mp: u8,
        sls: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&opc.to_be_bytes());
        value.extend_from_slice(&dpc.to_be_bytes());
        value.push(si);
        value.push(ni);
        value.push(mp);
        value.push(sls);
        value.extend_from_slice(payload);
        value
    }

    /// Read one framed M3UA message: `(class, type, whole message including the header)`.
    async fn read_m3ua(stream: &mut TcpStream) -> E2EResult<(u8, u8, Vec<u8>)> {
        let mut header = [0u8; 8];
        stream.read_exact(&mut header).await?;
        if header[0] != 1 {
            return Err(format!("M3UA version {} is not 1", header[0]).into());
        }
        let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if !(8..=65535).contains(&length) {
            return Err(format!("M3UA message length {length} out of range").into());
        }
        let mut full = vec![0u8; length];
        full[..8].copy_from_slice(&header);
        if length > 8 {
            stream.read_exact(&mut full[8..]).await?;
        }
        Ok((header[2], header[3], full))
    }

    /// Find a parameter's value in a whole message, honouring the padding rule.
    fn find_param(message: &[u8], tag: u16) -> Option<Vec<u8>> {
        let mut offset = 8usize;
        while offset + 4 <= message.len() {
            let found = u16::from_be_bytes([message[offset], message[offset + 1]]);
            let declared = u16::from_be_bytes([message[offset + 2], message[offset + 3]]) as usize;
            if declared < 4 || offset + declared > message.len() {
                return None;
            }
            if found == tag {
                return Some(message[offset + 4..offset + declared].to_vec());
            }
            offset = offset + declared + ((4 - (declared % 4)) % 4);
        }
        None
    }

    fn param_u32(message: &[u8], tag: u16) -> Option<u32> {
        let value = find_param(message, tag)?;
        let bytes: [u8; 4] = value.as_slice().try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }

    /// The startup action every test here uses. `transport: "tcp"` is the lab transport and is
    /// the only reason this suite can run on macOS at all.
    fn startup_actions(instruction: &str) -> serde_json::Value {
        serde_json::json!([{
            "type": "open_server",
            "port": 0,
            "base_stack": "M3UA",
            "instruction": instruction,
            "startup_params": { "transport": "tcp", "routing_context": 100 }
        }])
    }

    /// The protocol end to end: an ASP comes up, is activated, exchanges an MSU, and the
    /// keepalive and de-escalation messages NetGet answers in Rust cost no model call.
    ///
    /// Four LLM calls: startup, ASPUP, ASPAC, DATA. BEAT and ASPIA are answered without one,
    /// and `verify_mocks` is what proves it — a fifth call would have gone unmatched.
    #[tokio::test]
    async fn test_m3ua_asp_comes_up_activates_and_exchanges_data() -> E2EResult<()> {
        let prompt = "listen on port 0 via m3ua over the tcp lab transport. You are an SGP: \
                      admit any ASP, activate routing context 100, and answer SCCP traffic.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("m3ua")
                .respond_with_actions(startup_actions(
                    "You are an SGP. Admit ASPs, activate routing context 100, answer SCCP.",
                ))
                .expect_calls(1)
                .and()
                .on_event("m3ua_asp_up_received")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_m3ua_asp_up_ack",
                    "info_string": "ok"
                }]))
                .expect_calls(1)
                .and()
                .on_event("m3ua_asp_active_received")
                .respond_with_actions(serde_json::json!([{
                    "type": "send_m3ua_asp_active_ack",
                    "traffic_mode": "loadshare",
                    "routing_context": 100
                }]))
                .expect_calls(1)
                .and()
                // Answer the MSU by swapping the point codes and echoing the SLS, which is what
                // an SS7 reply does. Reading the fields off the event is also the assertion
                // that they arrived as structured fields rather than as an opaque blob.
                .on_event("m3ua_data_received")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_m3ua_data",
                        "opc": event["dpc"],
                        "dpc": event["opc"],
                        "si": event["si"],
                        "ni": event["ni"],
                        "sls": event["sls"],
                        "payload": "0a0b0c",
                        "encoding": "hex",
                        "routing_context": 100
                    }])
                })
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;
        // Wait for the condition, never a fixed sleep: `start_netget_server` returns when
        // startup is *parsed*, not when the socket is bound, and two seconds is enough alone
        // and not when a hundred tests run together.
        server.wait_for_log("M3UA SGP listening on", 15).await?;

        let mut asp = timeout(
            Duration::from_secs(5),
            TcpStream::connect(format!("127.0.0.1:{}", server.port)),
        )
        .await??;

        // 1. ASPUP -> ASPUP ACK. This is the admission decision.
        asp.write_all(&m3ua_message(
            CLASS_ASPSM,
            ASPSM_ASPUP,
            &[(TAG_ASP_IDENTIFIER, u32_param(7))],
        ))
        .await?;
        asp.flush().await?;

        let (class, msg_type, message) = timeout(LLM_TIMEOUT, read_m3ua(&mut asp)).await??;
        assert_eq!(
            (class, msg_type),
            (CLASS_ASPSM, ASPSM_ASPUP_ACK),
            "expected ASPUP ACK, got class {class} type {msg_type}"
        );
        assert_eq!(
            find_param(&message, TAG_INFO_STRING),
            Some(b"ok".to_vec()),
            "the handler's INFO String must survive the TLV padding intact"
        );

        // 2. BEAT -> BEAT ACK, in Rust, with the Heartbeat Data echoed verbatim. A keepalive is
        //    not a decision: routing it through the model — or worse, through a parked manual
        //    handler — would let the association die while somebody read a question.
        let token = vec![0xde, 0xad, 0xbe, 0xef, 0x01];
        asp.write_all(&m3ua_message(
            CLASS_ASPSM,
            ASPSM_BEAT,
            &[(TAG_HEARTBEAT_DATA, token.clone())],
        ))
        .await?;
        asp.flush().await?;

        let (class, msg_type, message) = timeout(WIRE_TIMEOUT, read_m3ua(&mut asp)).await??;
        assert_eq!(
            (class, msg_type),
            (CLASS_ASPSM, ASPSM_BEAT_ACK),
            "expected BEAT ACK, got class {class} type {msg_type}"
        );
        assert_eq!(
            find_param(&message, TAG_HEARTBEAT_DATA),
            Some(token),
            "BEAT ACK must echo the ASP's opaque token; a five-octet value pads to eight and \
             the padding must not come back as data"
        );

        // 3. ASPAC -> ASPAC ACK. The second admission decision.
        asp.write_all(&m3ua_message(
            CLASS_ASPTM,
            ASPTM_ASPAC,
            &[
                (TAG_TRAFFIC_MODE_TYPE, u32_param(2)),
                (TAG_ROUTING_CONTEXT, u32_param(100)),
            ],
        ))
        .await?;
        asp.flush().await?;

        let (class, msg_type, message) = timeout(LLM_TIMEOUT, read_m3ua(&mut asp)).await??;
        assert_eq!(
            (class, msg_type),
            (CLASS_ASPTM, ASPTM_ASPAC_ACK),
            "expected ASPAC ACK, got class {class} type {msg_type}"
        );
        assert_eq!(param_u32(&message, TAG_TRAFFIC_MODE_TYPE), Some(2));
        assert_eq!(param_u32(&message, TAG_ROUTING_CONTEXT), Some(100));

        // 4. DATA -> DATA. The routing label must reach the model as fields and come back the
        //    same way, which is what the swapped point codes and the echoed SLS assert.
        asp.write_all(&m3ua_message(
            CLASS_TRANSFER,
            TRANSFER_DATA,
            &[
                (TAG_ROUTING_CONTEXT, u32_param(100)),
                (
                    TAG_PROTOCOL_DATA,
                    protocol_data(1001, 2002, 3, 2, 0, 5, &[0x09, 0x81, 0x03]),
                ),
            ],
        ))
        .await?;
        asp.flush().await?;

        let (class, msg_type, message) = timeout(LLM_TIMEOUT, read_m3ua(&mut asp)).await??;
        assert_eq!(
            (class, msg_type),
            (CLASS_TRANSFER, TRANSFER_DATA),
            "expected DATA back, got class {class} type {msg_type}"
        );
        let value = find_param(&message, TAG_PROTOCOL_DATA)
            .ok_or("the reply carries no Protocol Data parameter")?;
        assert!(
            value.len() >= 12,
            "Protocol Data is {} octets, too short for a routing label",
            value.len()
        );
        assert_eq!(
            u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
            2002,
            "the reply's OPC must be the request's DPC"
        );
        assert_eq!(
            u32::from_be_bytes([value[4], value[5], value[6], value[7]]),
            1001,
            "the reply's DPC must be the request's OPC"
        );
        assert_eq!(value[8], 3, "SI (SCCP) must survive the round trip");
        assert_eq!(value[9], 2, "NI must survive the round trip");
        assert_eq!(
            value[11], 5,
            "SLS must be echoed to keep the transaction on one link"
        );
        assert_eq!(
            &value[12..],
            &[0x0a, 0x0b, 0x0c],
            "the hex payload must be decoded as hex, not put on the wire as the six ASCII \
             characters \"0a0b0c\""
        );

        // 5. ASPIA -> ASPIA ACK, in Rust. Taking an ASP *out* of service needs no permission,
        //    and the fifth model call this would otherwise cost is what `verify_mocks` refuses.
        asp.write_all(&m3ua_message(
            CLASS_ASPTM,
            ASPTM_ASPIA,
            &[(TAG_ROUTING_CONTEXT, u32_param(100))],
        ))
        .await?;
        asp.flush().await?;

        let (class, msg_type, _) = timeout(WIRE_TIMEOUT, read_m3ua(&mut asp)).await??;
        assert_eq!(
            (class, msg_type),
            (CLASS_ASPTM, ASPTM_ASPIA_ACK),
            "expected ASPIA ACK, got class {class} type {msg_type}"
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        Ok(())
    }

    /// Silence is not consent.
    ///
    /// The policy runs and answers `wait_for_more` — a real answer, and not an acknowledgement.
    /// An ASP admitted on that basis would be in the signalling network because nobody said no,
    /// which is the fail-open pattern the root `CLAUDE.md` calls the most dangerous in this
    /// codebase. NetGet must answer ERR and leave the ASP DOWN, and the ASPAC that follows must
    /// then be refused as an unexpected message *without* a second model call.
    ///
    /// Two LLM calls: startup and the ASPUP.
    #[tokio::test]
    async fn test_m3ua_silence_does_not_admit_an_asp() -> E2EResult<()> {
        let prompt = "listen on port 0 via m3ua over the tcp lab transport as an SGP that \
                      admits nobody.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("m3ua")
                .respond_with_actions(startup_actions(
                    "You are an SGP. Do not admit any ASP you were not told about.",
                ))
                .expect_calls(1)
                .and()
                .on_event("m3ua_asp_up_received")
                .respond_with_actions(serde_json::json!([{ "type": "wait_for_more" }]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;
        // Wait for the condition, never a fixed sleep: `start_netget_server` returns when
        // startup is *parsed*, not when the socket is bound, and two seconds is enough alone
        // and not when a hundred tests run together.
        server.wait_for_log("M3UA SGP listening on", 15).await?;

        let mut asp = timeout(
            Duration::from_secs(5),
            TcpStream::connect(format!("127.0.0.1:{}", server.port)),
        )
        .await??;

        asp.write_all(&m3ua_message(CLASS_ASPSM, ASPSM_ASPUP, &[]))
            .await?;
        asp.flush().await?;

        let (class, msg_type, message) = timeout(LLM_TIMEOUT, read_m3ua(&mut asp)).await??;
        assert_eq!(
            (class, msg_type),
            (CLASS_MGMT, MGMT_ERR),
            "a policy that said nothing must produce ERR, never ASPUP ACK: got class {class} \
             type {msg_type}"
        );
        assert_eq!(
            param_u32(&message, TAG_ERROR_CODE),
            Some(ERR_REFUSED_MANAGEMENT_BLOCKING),
            "the refusal must be Refused - Management Blocking (0x0d)"
        );
        // The wire carries a category; the log has to carry which of the three non-answers it
        // was, or an operator cannot tell a policy that refused from a backend that fell over.
        server
            .wait_for_pattern("decision=model_silent", WIRE_TIMEOUT)
            .await?;

        // The ASP is still DOWN, so ASPAC is out of sequence. That is a protocol fact, decided
        // in Rust — no model call, and no chance of a second opinion admitting it.
        asp.write_all(&m3ua_message(
            CLASS_ASPTM,
            ASPTM_ASPAC,
            &[(TAG_ROUTING_CONTEXT, u32_param(100))],
        ))
        .await?;
        asp.flush().await?;

        let (class, msg_type, message) = timeout(WIRE_TIMEOUT, read_m3ua(&mut asp)).await??;
        assert_eq!(
            (class, msg_type),
            (CLASS_MGMT, MGMT_ERR),
            "ASPAC while ASP-DOWN must be refused: got class {class} type {msg_type}"
        );
        assert_eq!(
            param_u32(&message, TAG_ERROR_CODE),
            Some(ERR_UNEXPECTED_MESSAGE),
            "out-of-sequence is Unexpected Message (0x06), not a policy refusal"
        );

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        Ok(())
    }

    /// An SGP with no policy at all admits nobody.
    ///
    /// This is where M3UA deliberately parts company with BGP. BGP treats "no instruction and no
    /// handler" as a static default and completes the handshake, on the reasoning that the
    /// operator opened the port. An M3UA ASPUP is an admission into a signalling network, and
    /// there is no configuration-free answer to "who may join" that is not a guess — so the
    /// answer is ERR, and the log says `decision=no_policy_configured` rather than leaving an
    /// operator to wonder.
    ///
    /// One LLM call: startup. `verify_mocks` proves the ASPUP cost none — there is nothing to
    /// ask.
    #[tokio::test]
    async fn test_m3ua_refuses_when_no_policy_is_configured() -> E2EResult<()> {
        let prompt = "listen on port 0 via m3ua over the tcp lab transport with no instruction.";

        let config = NetGetConfig::new(prompt).with_mock(|mock| {
            mock.on_instruction_containing("m3ua")
                .respond_with_actions(startup_actions(""))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;
        // Wait for the condition, never a fixed sleep: `start_netget_server` returns when
        // startup is *parsed*, not when the socket is bound, and two seconds is enough alone
        // and not when a hundred tests run together.
        server.wait_for_log("M3UA SGP listening on", 15).await?;

        let mut asp = timeout(
            Duration::from_secs(5),
            TcpStream::connect(format!("127.0.0.1:{}", server.port)),
        )
        .await??;

        asp.write_all(&m3ua_message(CLASS_ASPSM, ASPSM_ASPUP, &[]))
            .await?;
        asp.flush().await?;

        let (class, msg_type, message) = timeout(WIRE_TIMEOUT, read_m3ua(&mut asp)).await??;
        assert_eq!(
            (class, msg_type),
            (CLASS_MGMT, MGMT_ERR),
            "with no policy configured nothing has decided who may join, so the answer is a \
             refusal: got class {class} type {msg_type}"
        );
        assert_eq!(
            param_u32(&message, TAG_ERROR_CODE),
            Some(ERR_REFUSED_MANAGEMENT_BLOCKING)
        );
        // Tagged distinctly from a policy that refused and from a backend that failed: this
        // one means nobody has configured an answer at all, and the log says so.
        server
            .wait_for_pattern("decision=no_policy_configured", WIRE_TIMEOUT)
            .await?;

        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        Ok(())
    }
}
