//! M3UA codec tests (RFC 4666), asserted against literal octets.
//!
//! **Every expected vector here is written out by hand from RFC 4666, field by field, with the
//! decode in the comment.** Round-tripping NetGet's encoder through NetGet's decoder would pass
//! just as happily if both were wrong in the same way — the root `CLAUDE.md` names that as
//! circular evidence, and for M3UA it is not hypothetical: the padding rule below is the single
//! most commonly mis-implemented part of the format, and it is exactly the kind of mistake that
//! survives a round-trip test forever.
//!
//! The rule under test, RFC 4666 section 3.2:
//!
//! > The Parameter Length field contains the size of the parameter in bytes, including the
//! > Parameter Tag, Parameter Length, and Parameter Value fields. ... If the length of the
//! > parameter is not a multiple of 4 bytes, the sender pads the parameter at the end ... with
//! > all zero bytes. The length of the padding is NOT included in the parameter length field.
//!
//! So a two-octet value yields a **length field of 6** in a parameter that occupies **8 octets**.
//! Both numbers appear in the same assertion below on purpose.

#[cfg(unix)]
mod m3ua_codec_test {
    use netget::server::m3ua::codec;

    /// Render a byte slice as spaced hex, so a failure shows the message rather than a wall of
    /// decimal.
    fn hexdump(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn assert_bytes(actual: &[u8], expected: &[u8], what: &str) {
        assert_eq!(
            actual,
            expected,
            "{what}\n  actual:   {}\n  expected: {}",
            hexdump(actual),
            hexdump(expected)
        );
    }

    // -----------------------------------------------------------------------
    // Common header
    // -----------------------------------------------------------------------

    /// The smallest legal M3UA message: a common header and nothing else.
    #[test]
    fn aspup_ack_with_no_parameters_is_the_bare_common_header() {
        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0x01,                   // Version = 1
            0x00,                   // Reserved
            0x03,                   // Message Class = 3 (ASPSM)
            0x04,                   // Message Type = 4 (ASPUP ACK)
            0x00, 0x00, 0x00, 0x08, // Message Length = 8, the header itself
        ];
        assert_bytes(
            &codec::aspup_ack(None).unwrap(),
            &expected,
            "ASPUP ACK, no parameters",
        );
    }

    /// The padding rule, stated as octets.
    ///
    /// INFO String "ok" is two octets. The Parameter Length field reads **6** (4 header + 2
    /// value, padding excluded) while the parameter occupies **8** octets on the wire, and the
    /// Message Length counts all 8 of them plus the common header: 16.
    #[test]
    fn parameter_length_excludes_padding_but_message_length_includes_it() {
        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0x01,                   // Version
            0x00,                   // Reserved
            0x03,                   // ASPSM
            0x04,                   // ASPUP ACK
            0x00, 0x00, 0x00, 0x10, // Message Length = 16 = 8 header + 8 parameter octets
            0x00, 0x04,             // Parameter Tag = 0x0004 (INFO String)
            0x00, 0x06,             // Parameter Length = 6, NOT 8: padding is excluded
            0x6f, 0x6b,             // "ok"
            0x00, 0x00,             // padding to the 4-octet boundary, counted by neither the
                                    // parameter length nor RFC 4666's definition of it
        ];
        let encoded = codec::aspup_ack(Some("ok")).unwrap();
        assert_bytes(&encoded, &expected, "ASPUP ACK with INFO String \"ok\"");

        // The two numbers that must differ, named explicitly so a regression says which one
        // moved rather than dumping 16 octets.
        assert_eq!(
            u16::from_be_bytes([encoded[10], encoded[11]]),
            6,
            "Parameter Length must be 6 (4 + 2 value octets), excluding the 2 padding octets"
        );
        assert_eq!(
            u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]) as usize,
            encoded.len(),
            "Message Length must cover the whole message, padding included"
        );
    }

    /// Three octets of padding — the largest amount RFC 4666 permits.
    #[test]
    fn beat_ack_echoes_heartbeat_data_with_three_octets_of_padding() {
        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0x01,                               // Version
            0x00,                               // Reserved
            0x03,                               // ASPSM
            0x06,                               // BEAT ACK
            0x00, 0x00, 0x00, 0x14,             // Message Length = 20
            0x00, 0x09,                         // Tag = 0x0009 (Heartbeat Data)
            0x00, 0x09,                         // Length = 9 = 4 + 5 value octets
            0xde, 0xad, 0xbe, 0xef, 0x01,       // the ASP's opaque token, echoed verbatim
            0x00, 0x00, 0x00,                   // 3 padding octets, excluded from the 9
        ];
        let data = [0xde, 0xad, 0xbe, 0xef, 0x01];
        assert_bytes(
            &codec::beat_ack(Some(&data)).unwrap(),
            &expected,
            "BEAT ACK echoing 5 octets of Heartbeat Data",
        );
    }

    /// ERR (RFC 4666 section 3.8.1). The Error Code parameter is a 32-bit value, so it needs no
    /// padding at all — the assertion is that none is added.
    #[test]
    fn error_message_carries_a_32_bit_error_code_and_no_diagnostic_text() {
        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0x01,                   // Version
            0x00,                   // Reserved
            0x00,                   // MGMT
            0x00,                   // ERR
            0x00, 0x00, 0x00, 0x10, // Message Length = 16
            0x00, 0x0c,             // Tag = 0x000c (Error Code)
            0x00, 0x08,             // Length = 8; a 4-octet value needs no padding
            0x00, 0x00, 0x00, 0x0d, // 0x0d = Refused - Management Blocking
        ];
        let encoded = codec::error(codec::ERR_REFUSED_MANAGEMENT_BLOCKING, None).unwrap();
        assert_bytes(&encoded, &expected, "ERR / Refused - Management Blocking");

        // The rule from `crate::utils::wire_failure`: the peer gets a category, the log gets the
        // error. Diagnostic Information (0x0007) is the only field in M3UA where an internal
        // string could leak, and it is never populated.
        let decoded = codec::Message::parse(&encoded).expect("ERR must decode");
        assert!(
            decoded.param(codec::TAG_DIAGNOSTIC_INFO).is_none(),
            "ERR must not carry Diagnostic Information: it is where an internal error string \
             would reach a stranger's SS7 stack"
        );
    }

    /// NTFY packs Status Type and Status Information into one 32-bit parameter.
    #[test]
    fn notify_packs_status_type_and_information_into_one_32_bit_field() {
        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0x01,                   // Version
            0x00,                   // Reserved
            0x00,                   // MGMT
            0x01,                   // NTFY
            0x00, 0x00, 0x00, 0x10, // Message Length = 16
            0x00, 0x0d,             // Tag = 0x000d (Status)
            0x00, 0x08,             // Length = 8
            0x00, 0x01,             // Status Type = 1 (Application Server state change)
            0x00, 0x03,             // Status Information = 3 (AS-ACTIVE)
        ];
        assert_bytes(
            &codec::notify(
                codec::STATUS_TYPE_AS_STATE_CHANGE,
                codec::STATUS_AS_ACTIVE,
                None,
                None,
                None,
            )
            .unwrap(),
            &expected,
            "NTFY AS-ACTIVE",
        );
    }

    /// ASPAC ACK with two optional parameters, in the order RFC 4666 section 3.7.3 lists them.
    #[test]
    fn aspac_ack_orders_traffic_mode_before_routing_context() {
        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0x01,                   // Version
            0x00,                   // Reserved
            0x04,                   // ASPTM
            0x03,                   // ASPAC ACK
            0x00, 0x00, 0x00, 0x18, // Message Length = 24
            0x00, 0x0b,             // Tag = 0x000b (Traffic Mode Type)
            0x00, 0x08,             // Length = 8
            0x00, 0x00, 0x00, 0x02, // 2 = Loadshare
            0x00, 0x06,             // Tag = 0x0006 (Routing Context)
            0x00, 0x08,             // Length = 8
            0x00, 0x00, 0x00, 0x64, // 100
        ];
        assert_bytes(
            &codec::aspac_ack(Some(codec::TRAFFIC_MODE_LOADSHARE), Some(100), None).unwrap(),
            &expected,
            "ASPAC ACK, loadshare, routing context 100",
        );
    }

    // -----------------------------------------------------------------------
    // Protocol Data
    // -----------------------------------------------------------------------

    /// DATA (RFC 4666 section 3.3.1) with a three-octet user part.
    ///
    /// This is the padding rule at its most consequential: the Protocol Data value is 15 octets
    /// (12 of routing label plus 3 of payload), so the Parameter Length reads 19 while the
    /// parameter occupies 20 octets. An implementation that wrote 20 into the length field would
    /// hand the far end one octet of padding as if it were user part — which for an ISUP message
    /// is a corrupted call.
    #[test]
    fn data_encodes_the_routing_label_and_pads_the_user_part() {
        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0x01,                   // Version
            0x00,                   // Reserved
            0x01,                   // Transfer
            0x01,                   // DATA
            0x00, 0x00, 0x00, 0x24, // Message Length = 36 = 8 + 8 (RC) + 20 (Protocol Data)
            0x00, 0x06,             // Tag = 0x0006 (Routing Context)
            0x00, 0x08,             // Length = 8
            0x00, 0x00, 0x00, 0x64, // 100
            0x02, 0x10,             // Tag = 0x0210 (Protocol Data)
            0x00, 0x13,             // Length = 19 = 4 + 12 routing label + 3 payload
            0x00, 0x00, 0x03, 0xe9, // OPC = 1001
            0x00, 0x00, 0x07, 0xd2, // DPC = 2002
            0x03,                   // SI = 3 (SCCP)
            0x02,                   // NI = 2 (national)
            0x00,                   // MP = 0
            0x05,                   // SLS = 5
            0x09, 0x81, 0x03,       // user part
            0x00,                   // 1 padding octet, outside the length field
        ];

        let protocol_data = codec::ProtocolData {
            opc: 1001,
            dpc: 2002,
            si: 3,
            ni: 2,
            mp: 0,
            sls: 5,
            payload: vec![0x09, 0x81, 0x03],
        };
        assert_bytes(
            &codec::data(&protocol_data, None, Some(100), None).unwrap(),
            &expected,
            "DATA with routing context 100",
        );
    }

    /// The receive direction, on a message written from the RFC rather than by NetGet.
    #[test]
    fn parses_a_hand_written_data_message_into_structured_fields() {
        #[rustfmt::skip]
        let wire: Vec<u8> = vec![
            0x01, 0x00, 0x01, 0x01,             // version 1, reserved, Transfer, DATA
            0x00, 0x00, 0x00, 0x1c,             // Message Length = 28
            0x02, 0x10,                         // Protocol Data
            0x00, 0x14,                         // Length = 20 = 4 + 12 + 4 payload octets
            0x00, 0x00, 0x00, 0x01,             // OPC = 1
            0x00, 0x00, 0x00, 0x02,             // DPC = 2
            0x05,                               // SI = 5 (ISUP)
            0x03,                               // NI = 3 (reserved for national use)
            0x01,                               // MP = 1
            0xff,                               // SLS = 255
            0x01, 0x02, 0x03, 0x04,             // user part, already 4-octet aligned: no padding
        ];

        let message = codec::Message::parse(&wire).expect("hand-written DATA must decode");
        assert_eq!(message.class, codec::CLASS_TRANSFER);
        assert_eq!(message.msg_type, codec::TRANSFER_DATA);
        assert_eq!(message.name(), "DATA");

        let parameter = message
            .param(codec::TAG_PROTOCOL_DATA)
            .expect("Protocol Data must be present");
        let protocol_data =
            codec::ProtocolData::parse(&parameter.value).expect("Protocol Data must decode");
        assert_eq!(protocol_data.opc, 1);
        assert_eq!(protocol_data.dpc, 2);
        assert_eq!(protocol_data.si, 5);
        assert_eq!(codec::si_name(protocol_data.si), "ISUP");
        assert_eq!(protocol_data.ni, 3);
        assert_eq!(protocol_data.mp, 1);
        assert_eq!(protocol_data.sls, 255);
        assert_eq!(
            protocol_data.payload,
            vec![0x01, 0x02, 0x03, 0x04],
            "the user part must be exactly the octets sent — no padding folded in"
        );
    }

    /// Padding must never reach the user part. A 15-octet Protocol Data pads to 16 on the wire;
    /// the decoded payload has to be 3 octets, not 4.
    #[test]
    fn decoded_payload_never_includes_the_padding_octet() {
        #[rustfmt::skip]
        let wire: Vec<u8> = vec![
            0x01, 0x00, 0x01, 0x01,
            0x00, 0x00, 0x00, 0x1c,             // Message Length = 28 (padding included)
            0x02, 0x10,
            0x00, 0x13,                         // Length = 19: 4 + 12 + 3 payload octets
            0x00, 0x00, 0x00, 0x0a,             // OPC = 10
            0x00, 0x00, 0x00, 0x14,             // DPC = 20
            0x03, 0x02, 0x00, 0x07,             // SI SCCP, NI national, MP 0, SLS 7
            0xaa, 0xbb, 0xcc,                   // 3 octets of user part
            0x00,                               // padding
        ];
        let message = codec::Message::parse(&wire).expect("must decode");
        let value = &message.param(codec::TAG_PROTOCOL_DATA).unwrap().value;
        let protocol_data = codec::ProtocolData::parse(value).expect("must decode");
        assert_eq!(
            protocol_data.payload,
            vec![0xaa, 0xbb, 0xcc],
            "the trailing zero is padding, not a fourth octet of SS7 payload"
        );
    }

    /// An ASPUP written from the RFC, with both of its optional parameters.
    #[test]
    fn parses_a_hand_written_aspup_with_asp_identifier_and_info_string() {
        #[rustfmt::skip]
        let wire: Vec<u8> = vec![
            0x01, 0x00, 0x03, 0x01,             // version 1, reserved, ASPSM, ASPUP
            0x00, 0x00, 0x00, 0x18,             // Message Length = 24
            0x00, 0x11,                         // Tag = 0x0011 (ASP Identifier)
            0x00, 0x08,                         // Length = 8
            0x00, 0x00, 0x00, 0x07,             // ASP Identifier = 7
            0x00, 0x04,                         // Tag = 0x0004 (INFO String)
            0x00, 0x07,                         // Length = 7 = 4 + 3 value octets
            0x61, 0x73, 0x70,                   // "asp"
            0x00,                               // padding
        ];
        let message = codec::Message::parse(&wire).expect("hand-written ASPUP must decode");
        assert_eq!(message.name(), "ASPUP");
        assert_eq!(message.param_u32(codec::TAG_ASP_IDENTIFIER), Some(7));
        assert_eq!(
            message
                .param(codec::TAG_INFO_STRING)
                .map(|p| p.value.clone()),
            Some(b"asp".to_vec()),
            "the INFO String value is 3 octets; the padding octet belongs to neither"
        );
    }

    /// A sender may leave the final parameter's padding out of the Message Length. RFC 4666
    /// still has it write the padding octets, and the reader in `mod.rs` consumes them — but
    /// the parameter parser has to tolerate a body that simply ends after the value.
    #[test]
    fn tolerates_a_final_parameter_whose_padding_was_omitted() {
        #[rustfmt::skip]
        let wire: Vec<u8> = vec![
            0x01, 0x00, 0x03, 0x04,             // ASPSM / ASPUP ACK
            0x00, 0x00, 0x00, 0x0e,             // Message Length = 14 — padding NOT counted
            0x00, 0x04,                         // INFO String
            0x00, 0x06,                         // Length = 6
            0x6f, 0x6b,                         // "ok", and the body ends here
        ];
        let message = codec::Message::parse(&wire).expect("must decode");
        assert_eq!(
            message
                .param(codec::TAG_INFO_STRING)
                .map(|p| p.value.clone()),
            Some(b"ok".to_vec())
        );
        assert_eq!(
            codec::alignment_slack(14),
            2,
            "14 octets leaves 2 octets of slack the reader must drain before the next header"
        );
        assert_eq!(
            codec::alignment_slack(16),
            0,
            "a message whose length already includes its padding leaves no slack"
        );
    }

    // -----------------------------------------------------------------------
    // Rejections
    // -----------------------------------------------------------------------

    #[test]
    fn rejects_a_version_that_is_not_one() {
        let wire = [0x02, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x08];
        let error = codec::parse_header(&wire).expect_err("version 2 must be refused");
        assert_eq!(error.error_code, codec::ERR_INVALID_VERSION);
    }

    #[test]
    fn rejects_a_message_length_below_the_header() {
        let wire = [0x01, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x04];
        let error = codec::parse_header(&wire).expect_err("length 4 must be refused");
        assert_eq!(error.error_code, codec::ERR_PROTOCOL_ERROR);
    }

    /// Nothing is allocated before the ceiling is checked, so a peer cannot pick the buffer
    /// size by declaring a huge length.
    #[test]
    fn rejects_a_message_length_above_the_ceiling() {
        let wire = [0x01, 0x00, 0x03, 0x01, 0xff, 0xff, 0xff, 0xff];
        let error = codec::parse_header(&wire).expect_err("4 GiB must be refused");
        assert_eq!(error.error_code, codec::ERR_PROTOCOL_ERROR);
    }

    #[test]
    fn rejects_a_parameter_shorter_than_its_own_tlv_header() {
        // Parameter Length 2 is impossible: the tag and length alone are 4 octets.
        let body = [0x00, 0x04, 0x00, 0x02];
        let error = codec::parse_parameters(&body).expect_err("length 2 must be refused");
        assert_eq!(error.error_code, codec::ERR_PARAMETER_FIELD_ERROR);
    }

    #[test]
    fn rejects_a_parameter_that_runs_past_the_end_of_the_message() {
        let body = [0x00, 0x04, 0x00, 0x40, 0x6f, 0x6b];
        let error = codec::parse_parameters(&body).expect_err("overlong parameter must be refused");
        assert_eq!(error.error_code, codec::ERR_PARAMETER_FIELD_ERROR);
    }

    #[test]
    fn rejects_protocol_data_shorter_than_the_routing_label() {
        let value = [0u8; 11];
        let error = codec::ProtocolData::parse(&value)
            .expect_err("11 octets cannot hold a 12-octet routing label");
        assert_eq!(error.error_code, codec::ERR_PARAMETER_FIELD_ERROR);
    }

    // -----------------------------------------------------------------------
    // Helpers the session depends on
    // -----------------------------------------------------------------------

    /// The session reads the class and type back off the octets an action produced, so the ASP
    /// state machine follows what is actually on the wire.
    #[test]
    fn peek_class_type_reads_the_header_without_decoding() {
        assert_eq!(
            codec::peek_class_type(&codec::aspup_ack(None).unwrap()),
            Some((codec::CLASS_ASPSM, codec::ASPSM_ASPUP_ACK))
        );
        assert_eq!(
            codec::peek_class_type(&codec::error(codec::ERR_UNEXPECTED_MESSAGE, None).unwrap()),
            Some((codec::CLASS_MGMT, codec::MGMT_ERR))
        );
        assert_eq!(
            codec::peek_class_type(&codec::aspac_ack(None, None, None).unwrap()),
            Some((codec::CLASS_ASPTM, codec::ASPTM_ASPAC_ACK))
        );
        assert_eq!(codec::peek_class_type(&[0x01, 0x00]), None);
    }

    #[test]
    fn padding_rounds_up_to_four_and_never_adds_a_whole_word() {
        assert_eq!(codec::padding_for(0), 0);
        assert_eq!(codec::padding_for(1), 3);
        assert_eq!(codec::padding_for(2), 2);
        assert_eq!(codec::padding_for(3), 1);
        assert_eq!(codec::padding_for(4), 0);
        assert_eq!(codec::padding_for(19), 1);
    }

    /// A user part too large to frame must be **refused at the action**, not wrapped.
    ///
    /// `Parameter::write_into` writes `declared_len()` as a `u16`, and `MAX_MESSAGE_LEN`
    /// guards only the decode side — where a hostile peer chooses the number. On the encode
    /// side, where the model chooses it, there was no bound at all: a user part of 65520
    /// octets or more wrapped the Parameter Length field and produced a message no SS7 peer
    /// could parse, with nothing anywhere saying so.
    ///
    /// The limit counts decoded octets, so declaring `hex` must not buy twice the budget.
    #[test]
    fn a_user_part_too_large_to_frame_is_refused_rather_than_wrapped() {
        use netget::llm::actions::protocol_trait::Server;
        use netget::server::m3ua::actions::M3uaProtocol;

        let protocol = M3uaProtocol::new();
        let send = |payload: String, encoding: &str| {
            protocol.execute_action(serde_json::json!({
                "type": "send_m3ua_data",
                "opc": 1,
                "dpc": 2,
                "si": 3,
                "payload": payload,
                "encoding": encoding,
            }))
        };

        // Exactly at the limit is still legal. Without this the over-limit assertion below
        // would pass just as happily against a guard that refused everything.
        assert!(
            send("x".repeat(codec::MAX_USER_DATA_LEN), "utf8").is_ok(),
            "exactly MAX_USER_DATA_LEN octets fits the Parameter Length field and must be \
             accepted"
        );

        let err = send("x".repeat(codec::MAX_USER_DATA_LEN + 1), "utf8")
            .expect_err("one octet over the limit must be refused");
        let err = err.to_string();
        assert!(
            err.contains(&codec::MAX_USER_DATA_LEN.to_string()),
            "the refusal must name the real limit so the model can act on it, got: {err}"
        );

        // The bound is on decoded octets: two hex digits per octet.
        assert!(send("41".repeat(codec::MAX_USER_DATA_LEN), "hex").is_ok());
        assert!(
            send("41".repeat(codec::MAX_USER_DATA_LEN + 1), "hex").is_err(),
            "a hex-declared payload must not get twice the budget"
        );

        // The limit is derived from the format, not picked: common header + parameter header
        // + Protocol Data's fixed fields + the padding rule must exactly account for the
        // difference. The padding half is easy to forget and was: a body is always a whole
        // number of 4-octet words, so the largest one that fits is 65524 rather than 65527,
        // and a constant that subtracted only the headers sat three octets too high — enough
        // for a payload at exactly the documented limit to produce a 65536-octet message.
        let declared = codec::MAX_USER_DATA_LEN + 4 + 12;
        assert_eq!(
            declared % 4,
            0,
            "the largest Protocol Data parameter needs no padding, or the bound is not tight"
        );
        assert_eq!(codec::HEADER_LEN + declared, 65_532);
        assert!(codec::HEADER_LEN + declared <= codec::MAX_MESSAGE_LEN);
        assert!(
            codec::HEADER_LEN + declared + 4 > codec::MAX_MESSAGE_LEN,
            "one more word must not fit, or the bound is loose rather than exact"
        );

        // And the constant is the *parameter* bound, not the message bound: a DATA message
        // that also carries the three optional 8-octet parameters cannot spend all of it, and
        // `Message::encode` is what says so rather than wrapping a length field.
        let protocol_data = codec::ProtocolData {
            opc: 1,
            dpc: 2,
            si: 3,
            ni: 0,
            mp: 0,
            sls: 0,
            payload: vec![0u8; codec::MAX_USER_DATA_LEN],
        };
        assert!(codec::data(&protocol_data, None, None, None).is_ok());
        assert!(codec::data(&protocol_data, Some(1), Some(2), Some(3)).is_err());
    }
}
