//! USB FIDO2/U2F security key E2E tests.
//!
//! The question these answer is: *the model is the button on a security key — does approving
//! actually create a credential, and does denying actually refuse?*
//!
//! They drive a real USB/IP client over TCP (`tests/helpers/usbip_client.rs`) and a CTAPHID
//! client written against the wire format (`super::ctaphid_client`): OP_REQ_IMPORT, then
//! 64-byte HID frames carrying CTAP2 CBOR and CTAP1 APDUs. The CBOR is decoded independently by
//! `serde_cbor`, and the assertion signature is verified with `ring` against the public key the
//! *authenticator itself* produced during registration. A broken CTAP path cannot pass.
//!
//! **What this does not prove.** There is no `vhci-hcd`, no `/dev/hidraw*`, no libfido2 and no
//! browser — macOS has no USB/IP client at all, which is why the protocol is spoken directly.
//! These establish that the device side is correct: netget puts the right CTAP bytes on the
//! wire, and the model's decision is what determines whether it does. They do not establish
//! that Chrome completes a WebAuthn ceremony against it.
//!
//! ## What this file replaced
//!
//! Fourteen tests, of which twelve exercised `Ctap2CredentialStore`, `CtapHidHandler` and
//! `ApprovalManager` in isolation and two were `#[ignore]`d stubs containing only comments. Not
//! one of them connected to the server. They passed throughout the period when the protocol
//! had no LLM integration at all, every declared event was unreachable, and
//! `execute_action("approve_request")` panicked with *"Cannot block the current thread from
//! within a runtime"* — the action the events' own examples told the model to use. The unit
//! tests worth keeping are still here at the bottom; the point is that they were never the
//! thing that could have caught it.

#[cfg(all(unix, feature = "libusb"))]
mod tests {
    use std::time::Duration;

    use crate::helpers::*;
    use crate::server::usb_fido2::ctaphid_client::*;

    /// Log line the server emits after each LLM call on a FIDO2 connection. The event kind
    /// comes before the connection id so a test can wait on one specific event.
    const ATTACH_CALL_LOG: &str = "USB FIDO2 LLM call completed (attach)";

    /// A fixed 32-byte client data hash. Its value does not matter to the authenticator — it is
    /// signed opaquely — but it must be the same on both sides for verification to mean
    /// anything.
    const CLIENT_DATA_HASH: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00,
    ];

    /// Parsed authenticator data, per WebAuthn §6.1.
    struct AuthData {
        rp_id_hash: [u8; 32],
        flags: u8,
        counter: u32,
        aaguid: Vec<u8>,
        credential_id: Vec<u8>,
        /// Uncompressed X9.62 P-256 point rebuilt from the COSE_Key.
        public_key: Vec<u8>,
    }

    /// Decode authenticator data with attested credential data attached.
    ///
    /// Written out from the spec rather than reusing netget's encoder, so the test constrains
    /// the layout instead of agreeing with it.
    fn parse_auth_data(bytes: &[u8]) -> AuthData {
        assert!(
            bytes.len() > 37,
            "authenticator data is {} bytes; 37 is the minimum before attested credential data",
            bytes.len()
        );
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&bytes[0..32]);
        let flags = bytes[32];
        let counter = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);

        assert_eq!(
            flags & 0x40,
            0x40,
            "the AT flag must be set when attested credential data follows"
        );
        assert!(bytes.len() >= 55, "attested credential data is truncated");

        let aaguid = bytes[37..53].to_vec();
        let cred_len = u16::from_be_bytes([bytes[53], bytes[54]]) as usize;
        assert!(
            bytes.len() >= 55 + cred_len,
            "credential id claims {} bytes but only {} remain",
            cred_len,
            bytes.len() - 55
        );
        let credential_id = bytes[55..55 + cred_len].to_vec();

        let cose: serde_cbor::Value = serde_cbor::from_slice(&bytes[55 + cred_len..])
            .expect("the bytes after the credential id must be a COSE_Key");
        let public_key = cose_to_uncompressed_point(&cose);

        AuthData {
            rp_id_hash,
            flags,
            counter,
            aaguid,
            credential_id,
            public_key,
        }
    }

    /// Rebuild the 65-byte uncompressed point from a COSE_Key ES256 map.
    fn cose_to_uncompressed_point(cose: &serde_cbor::Value) -> Vec<u8> {
        use serde_cbor::Value as C;
        let C::Map(map) = cose else {
            panic!("COSE_Key must be a CBOR map, got {:?}", cose);
        };

        let get_int = |k: i128| match map.get(&C::Integer(k)) {
            Some(C::Integer(v)) => Some(*v),
            _ => None,
        };
        let get_bytes = |k: i128| match map.get(&C::Integer(k)) {
            Some(C::Bytes(v)) => Some(v.clone()),
            _ => None,
        };

        assert_eq!(get_int(1), Some(2), "COSE kty must be 2 (EC2)");
        assert_eq!(get_int(3), Some(-7), "COSE alg must be -7 (ES256)");
        assert_eq!(get_int(-1), Some(1), "COSE crv must be 1 (P-256)");

        let x = get_bytes(-2).expect("COSE_Key must carry x");
        let y = get_bytes(-3).expect("COSE_Key must carry y");
        assert_eq!(x.len(), 32, "P-256 x is 32 bytes");
        assert_eq!(y.len(), 32, "P-256 y is 32 bytes");

        let mut point = Vec::with_capacity(65);
        point.push(0x04); // uncompressed
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        point
    }

    fn cbor_map(
        payload: &[u8],
    ) -> std::collections::BTreeMap<serde_cbor::Value, serde_cbor::Value> {
        match serde_cbor::from_slice::<serde_cbor::Value>(payload)
            .expect("CTAP2 payload must be valid CBOR")
        {
            serde_cbor::Value::Map(m) => m,
            other => panic!("CTAP2 payload must be a CBOR map, got {:?}", other),
        }
    }

    fn sha256(data: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, data)
            .as_ref()
            .to_vec()
    }

    /// The headline case: the model approves, and a real credential comes out that can then
    /// sign an assertion verifiable against its own public key.
    ///
    /// Also covers CTAP1/U2F on the same device, including that **check-only** authentication
    /// does not ask for user presence — a browser probes with `P1 = 0x07` before it prompts,
    /// and gating that would make every login raise a spurious approval.
    ///
    /// LLM calls: 6 (startup, attach, CTAP2 register, CTAP2 assertion, U2F register, U2F
    /// authenticate).
    #[tokio::test]
    async fn test_fido2_model_approval_produces_a_working_credential() -> E2EResult<()> {
        let config = NetGetConfig::new(
            "Be a FIDO2 security key that approves requests for example.com.".to_string(),
        )
        .with_mock(|mock| {
            mock.on_event("fido2_device_attached")
                .respond_with_actions(serde_json::json!([
                    {"type": "show_message", "message": "Security key attached"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("fido2_register_request")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "approve_request",
                        // Must be dynamic: the id identifies which request is being answered,
                        // and approving the wrong one would leave the real one to time out.
                        "approval_id": e["approval_id"].as_u64().unwrap_or(0)
                    }])
                })
                .expect_calls(2)
                .and()
                .on_event("fido2_authenticate_request")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "approve_request",
                        "approval_id": e["approval_id"].as_u64().unwrap_or(0)
                    }])
                })
                .expect_calls(2)
                .and()
                .on_event("fido2_device_detached")
                .respond_with_actions(serde_json::json!([
                    {"type": "show_message", "message": "Security key detached"}
                ]))
                .expect_at_least(0)
                .and()
                .on_instruction_containing("FIDO2 security key")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "usb-fido2",
                    "instruction": "Approve requests for example.com",
                    "startup_params": {
                        "support_u2f": true,
                        "support_fido2": true,
                        "auto_approve": false,
                        "approval_timeout_secs": 15
                    }
                }]))
                .expect_calls(1)
                .and()
        });

        let mut server = start_netget_server(config).await?;
        assert!(server.is_running(), "USB FIDO2 server should be running");

        // 1. Enumerate, attach, and allocate a CTAPHID channel.
        let mut key = CtapHidClient::attach(server.port).await?;
        server.wait_for_log(ATTACH_CALL_LOG, 10).await?;

        let init = key.init().await?;
        assert!(
            init.supports_cbor(),
            "a device with support_fido2=true must advertise CAPABILITY_CBOR, got {:#04x}",
            init.capabilities
        );
        assert!(
            !init.refuses_msg(),
            "a device with support_u2f=true must not set CAPABILITY_NMSG, got {:#04x}",
            init.capabilities
        );

        // 2. PING round trips through fragmentation and reassembly.
        let payload: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            key.ping(&payload).await?,
            payload,
            "PING must return exactly what it was sent, across multiple frames"
        );

        // 3. GetInfo needs no approval and must answer immediately.
        let info = key.cbor(&ctap2_get_info(), Duration::from_secs(5)).await?;
        assert_eq!(info.status, CTAP2_OK, "GetInfo must succeed");
        assert_eq!(
            info.keepalives, 0,
            "GetInfo needs no user presence and must not send KEEPALIVE"
        );
        let info_map = cbor_map(&info.payload);
        let versions = info_map
            .get(&serde_cbor::Value::Integer(0x01))
            .expect("GetInfo must carry versions at key 0x01");
        let serde_cbor::Value::Array(versions) = versions else {
            panic!("versions must be an array");
        };
        let versions: Vec<String> = versions
            .iter()
            .filter_map(|v| match v {
                serde_cbor::Value::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect();
        assert!(
            versions.contains(&"FIDO_2_0".to_string()) && versions.contains(&"U2F_V2".to_string()),
            "a dual-protocol key must advertise both versions, got {:?}",
            versions
        );
        let aaguid = match info_map.get(&serde_cbor::Value::Integer(0x03)) {
            Some(serde_cbor::Value::Bytes(b)) => b.clone(),
            other => panic!(
                "GetInfo must carry a 16-byte aaguid at 0x03, got {:?}",
                other
            ),
        };
        assert_eq!(aaguid.len(), 16, "an AAGUID is 16 bytes");

        // 4. MakeCredential. This is the request the model approves.
        let made = key
            .cbor(
                &ctap2_make_credential("example.com", "user@example.com", &CLIENT_DATA_HASH),
                Duration::from_secs(20),
            )
            .await?;
        assert_eq!(
            made.status, CTAP2_OK,
            "MakeCredential must succeed once the model approves"
        );
        assert!(
            made.keepalives > 0,
            "the device must hold the host on KEEPALIVE while the model decides, not go silent"
        );

        let made_map = cbor_map(&made.payload);
        assert_eq!(
            made_map.get(&serde_cbor::Value::Integer(0x01)),
            Some(&serde_cbor::Value::Text("none".to_string())),
            "attestation format must be 'none'; claiming 'packed' with a zero signature is a \
             lie a relying party can check"
        );
        let auth_data_bytes = match made_map.get(&serde_cbor::Value::Integer(0x02)) {
            Some(serde_cbor::Value::Bytes(b)) => b.clone(),
            other => panic!(
                "MakeCredential key 0x02 must be authenticator data as a byte string, got {:?}",
                other
            ),
        };
        assert!(
            matches!(
                made_map.get(&serde_cbor::Value::Integer(0x03)),
                Some(serde_cbor::Value::Map(_))
            ),
            "MakeCredential key 0x03 must be the attestation statement map"
        );

        let attested = parse_auth_data(&auth_data_bytes);
        assert_eq!(
            attested.rp_id_hash.to_vec(),
            sha256(b"example.com"),
            "authenticator data must begin with SHA-256 of the RP id"
        );
        assert_eq!(
            attested.flags & 0x01,
            0x01,
            "the UP flag must be set: the model's approval *is* the user presence"
        );
        assert_eq!(attested.aaguid, aaguid, "the AAGUID must match GetInfo's");
        assert!(
            !attested.credential_id.is_empty(),
            "a credential must have an id"
        );
        assert_eq!(
            attested.public_key.len(),
            65,
            "the COSE_Key must yield a 65-byte uncompressed P-256 point"
        );

        // 5. GetAssertion, also approved — and the signature must verify against the public key
        //    that came out of step 4. This is the assertion that makes the whole exercise
        //    meaningful: it can only pass if the private key was really generated, really
        //    stored, and really used.
        let asserted = key
            .cbor(
                &ctap2_get_assertion("example.com", &CLIENT_DATA_HASH),
                Duration::from_secs(20),
            )
            .await?;
        assert_eq!(asserted.status, CTAP2_OK, "GetAssertion must succeed");

        let assert_map = cbor_map(&asserted.payload);
        let descriptor = match assert_map.get(&serde_cbor::Value::Integer(0x01)) {
            Some(serde_cbor::Value::Map(m)) => m.clone(),
            other => panic!(
                "GetAssertion key 0x01 must be a PublicKeyCredentialDescriptor map, got {:?}",
                other
            ),
        };
        assert_eq!(
            descriptor.get(&serde_cbor::Value::Text("type".into())),
            Some(&serde_cbor::Value::Text("public-key".into())),
            "the credential descriptor must declare type 'public-key'"
        );
        assert_eq!(
            descriptor.get(&serde_cbor::Value::Text("id".into())),
            Some(&serde_cbor::Value::Bytes(attested.credential_id.clone())),
            "the assertion must name the credential that registration created"
        );

        let assert_auth_data = match assert_map.get(&serde_cbor::Value::Integer(0x02)) {
            Some(serde_cbor::Value::Bytes(b)) => b.clone(),
            other => panic!(
                "GetAssertion key 0x02 must be authenticator data, got {:?}",
                other
            ),
        };
        let signature = match assert_map.get(&serde_cbor::Value::Integer(0x03)) {
            Some(serde_cbor::Value::Bytes(b)) => b.clone(),
            other => panic!(
                "GetAssertion key 0x03 must be the signature, got {:?}",
                other
            ),
        };

        assert_eq!(
            &assert_auth_data[0..32],
            sha256(b"example.com").as_slice(),
            "assertion authenticator data must also start with the RP id hash"
        );
        assert_eq!(
            assert_auth_data[32] & 0x01,
            0x01,
            "the assertion must report user presence"
        );
        let assert_counter = u32::from_be_bytes([
            assert_auth_data[33],
            assert_auth_data[34],
            assert_auth_data[35],
            assert_auth_data[36],
        ]);
        assert!(
            assert_counter > attested.counter,
            "the signature counter must advance: {} did not exceed {}",
            assert_counter,
            attested.counter
        );

        let mut signed = assert_auth_data.clone();
        signed.extend_from_slice(&CLIENT_DATA_HASH);
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            &attested.public_key,
        )
        .verify(&signed, &signature)
        .map_err(|_| {
            "the assertion signature did not verify against the credential's own public key"
        })?;

        // 6. CTAP1/U2F on the same device. REGISTER needs presence and is approved.
        let application = sha256(b"https://example.com");
        let application: [u8; 32] = application
            .as_slice()
            .try_into()
            .expect("sha256 is 32 bytes");
        let challenge = [0x5au8; 32];

        let u2f_reg = key
            .msg(
                &u2f_register(&challenge, &application),
                Duration::from_secs(20),
            )
            .await?;
        assert_eq!(
            u2f_reg.sw, SW_NO_ERROR,
            "U2F_REGISTER must succeed once approved (SW {:#06x})",
            u2f_reg.sw
        );
        let registration = parse_u2f_registration(&u2f_reg.data)?;
        assert_eq!(
            registration.public_key[0], 0x04,
            "the U2F public key must be an uncompressed point"
        );
        assert!(
            !registration.key_handle.is_empty(),
            "U2F registration must produce a key handle"
        );

        // 7. Check-only authentication must NOT ask for user presence. A browser probes with
        //    P1=0x07 before prompting; asking here would raise an approval per probe.
        let check = key
            .msg(
                &u2f_authenticate(&challenge, &application, &registration.key_handle, 0x07),
                Duration::from_secs(5),
            )
            .await?;
        assert_eq!(
            check.keepalives, 0,
            "check-only authentication must not request user presence"
        );

        // 8. Enforce-user-presence authentication is approved and signs.
        let u2f_auth = key
            .msg(
                &u2f_authenticate(&challenge, &application, &registration.key_handle, 0x03),
                Duration::from_secs(20),
            )
            .await?;
        assert_eq!(
            u2f_auth.sw, SW_NO_ERROR,
            "U2F_AUTHENTICATE must succeed once approved (SW {:#06x})",
            u2f_auth.sw
        );
        assert!(
            u2f_auth.keepalives > 0,
            "enforce-user-presence authentication must hold the host on KEEPALIVE"
        );
        assert_eq!(
            u2f_auth.data[0], 0x01,
            "the user presence byte must report presence"
        );
        let u2f_counter = u32::from_be_bytes([
            u2f_auth.data[1],
            u2f_auth.data[2],
            u2f_auth.data[3],
            u2f_auth.data[4],
        ]);
        assert!(u2f_counter >= 1, "the U2F counter must have advanced");

        // The U2F signature covers application || presence || counter || challenge.
        let mut u2f_signed = Vec::new();
        u2f_signed.extend_from_slice(&application);
        u2f_signed.push(0x01);
        u2f_signed.extend_from_slice(&u2f_counter.to_be_bytes());
        u2f_signed.extend_from_slice(&challenge);
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            &registration.public_key[..],
        )
        .verify(&u2f_signed, &u2f_auth.data[5..])
        .map_err(|_| "the U2F assertion signature did not verify against the registered key")?;

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    /// The refusal paths, which matter more than the happy path: a security key that cannot say
    /// no is not a security key.
    ///
    /// Two distinct shapes, and they must both refuse:
    ///
    /// * The model **denies** — an explicit decision.
    /// * The model **says nothing usable** — it answers with `show_message` and no decision.
    ///   The request must time out and DENY, not fall through to an approval. This is the
    ///   fail-open pattern the project has been bitten by repeatedly; here it would mean an LLM
    ///   outage silently issuing credentials.
    ///
    /// LLM calls: 4 (startup, attach, denied register, unanswered register).
    #[tokio::test]
    async fn test_fido2_denial_and_silence_both_refuse() -> E2EResult<()> {
        let config = NetGetConfig::new(
            "Be a FIDO2 security key that refuses to register anything.".to_string(),
        )
        .with_mock(|mock| {
            mock.on_event("fido2_device_attached")
                .respond_with_actions(serde_json::json!([
                    {"type": "show_message", "message": "Security key attached"}
                ]))
                .expect_calls(1)
                .and()
                // An explicit denial.
                .on_event("fido2_register_request")
                .and_event_data_contains("rp_id", "denied.example")
                .respond_with_actions_from_event(|e| {
                    serde_json::json!([{
                        "type": "deny_request",
                        "approval_id": e["approval_id"].as_u64().unwrap_or(0)
                    }])
                })
                .expect_calls(1)
                .and()
                // A model that answers but decides nothing. The request must expire into a
                // denial rather than being treated as consent.
                .on_event("fido2_register_request")
                .and_event_data_contains("rp_id", "silent.example")
                .respond_with_actions(serde_json::json!([
                    {"type": "show_message", "message": "thinking about it"}
                ]))
                .expect_calls(1)
                .and()
                .on_event("fido2_device_detached")
                .respond_with_actions(serde_json::json!([
                    {"type": "show_message", "message": "detached"}
                ]))
                .expect_at_least(0)
                .and()
                .on_instruction_containing("refuses to register")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "usb-fido2",
                    "instruction": "Refuse every registration",
                    "startup_params": {
                        "auto_approve": false,
                        // Short, so the silence case does not spend the default 30s window.
                        "approval_timeout_secs": 3
                    }
                }]))
                .expect_calls(1)
                .and()
        });

        let server = start_netget_server(config).await?;

        let mut key = CtapHidClient::attach(server.port).await?;
        server.wait_for_log(ATTACH_CALL_LOG, 10).await?;
        key.init().await?;

        // 1. Explicit denial.
        let denied = key
            .cbor(
                &ctap2_make_credential("denied.example", "user@denied.example", &CLIENT_DATA_HASH),
                Duration::from_secs(20),
            )
            .await?;
        assert_eq!(
            denied.status, CTAP2_ERR_OPERATION_DENIED,
            "a denied MakeCredential must return CTAP2_ERR_OPERATION_DENIED (0x27), got {:#04x}",
            denied.status
        );
        assert!(
            denied.payload.is_empty(),
            "a denied request must carry no credential data, got {} bytes",
            denied.payload.len()
        );

        // A denial must leave nothing behind. If a key pair had been generated before the
        // decision, this would find it.
        let after_denial = key
            .cbor(
                &ctap2_get_assertion("denied.example", &CLIENT_DATA_HASH),
                Duration::from_secs(20),
            )
            .await?;
        assert_eq!(
            after_denial.status, CTAP2_ERR_NO_CREDENTIALS,
            "a denied registration must store nothing, so GetAssertion must report \
             CTAP2_ERR_NO_CREDENTIALS (0x2e), got {:#04x}",
            after_denial.status
        );

        // 2. Silence. The model answers, but with no decision.
        let unanswered = key
            .cbor(
                &ctap2_make_credential("silent.example", "user@silent.example", &CLIENT_DATA_HASH),
                Duration::from_secs(20),
            )
            .await?;
        assert_eq!(
            unanswered.status, CTAP2_ERR_OPERATION_DENIED,
            "an unanswered request must expire into a DENIAL, not an approval; got {:#04x}",
            unanswered.status
        );

        let after_silence = key
            .cbor(
                &ctap2_get_assertion("silent.example", &CLIENT_DATA_HASH),
                Duration::from_secs(20),
            )
            .await?;
        assert_eq!(
            after_silence.status, CTAP2_ERR_NO_CREDENTIALS,
            "silence must not have created a credential"
        );

        // Wait for the exchange the mocks describe, rather than trusting a fixed
        // sleep to have covered it. Under load the last event routinely lands after
        // the sleep expires, and the test reports it as never having happened.
        server.wait_for_mocks(30).await;
        server.verify_mocks().await?;
        server.stop().await?;
        Ok(())
    }

    // ---- Unit-level tests of the pieces the E2E tests exercise ----
    //
    // Kept because they pin behaviour that is awkward to reach over the wire: PIN retry
    // counters, resident-key bookkeeping, and CTAPHID fragmentation at its exact limits.

    /// PIN set / verify / retry accounting.
    #[tokio::test]
    async fn test_pin_uv_support() {
        use ::netget::server::usb::fido2::ctap2::Ctap2CredentialStore;

        let mut store = Ctap2CredentialStore::new();

        assert!(!store.has_pin(), "PIN should not be set initially");
        assert!(
            !store.pin_verified(),
            "PIN should not be verified initially"
        );
        assert_eq!(store.pin_retries(), 8, "Should start with 8 retries");

        store.set_pin("test1234").expect("Should set PIN");
        assert!(store.has_pin(), "PIN should be set after setting");

        assert!(
            store.verify_pin("test1234").expect("no error"),
            "Correct PIN should verify"
        );
        assert!(store.pin_verified(), "PIN should be verified");
        assert_eq!(store.pin_retries(), 8, "Retries should reset on success");

        assert!(
            !store.verify_pin("wrong").expect("no error"),
            "Wrong PIN should not verify"
        );
        assert!(!store.pin_verified(), "PIN verification should be cleared");
        assert_eq!(store.pin_retries(), 7, "Retries should decrement");

        assert!(store.set_pin("123").is_err(), "PIN too short should fail");
        assert!(
            store.set_pin(&"a".repeat(64)).is_err(),
            "PIN too long should fail"
        );
    }

    /// Resident and non-resident credentials, across relying parties.
    #[tokio::test]
    async fn test_resident_keys() {
        use ::netget::server::usb::fido2::ctap2::Ctap2CredentialStore;

        let mut store = Ctap2CredentialStore::new();

        store
            .make_credential("example.com", b"user123", "test@example.com", false, false)
            .expect("non-resident credential");
        store
            .make_credential("example.com", b"user456", "user2@example.com", true, false)
            .expect("resident credential");
        store
            .make_credential("test.com", b"user789", "user3@test.com", true, false)
            .expect("credential for a second RP");

        assert_eq!(
            store.credential_count("example.com"),
            2,
            "both credentials for the RP must be counted, which is what the approval event \
             reports to the model"
        );
        assert!(store.find_credentials("example.com", None).is_some());
        assert!(store.find_credentials("test.com", None).is_some());

        assert_eq!(
            store.delete_credentials("example.com"),
            2,
            "delete_credential must remove every credential for the RP"
        );
        assert!(
            store.find_credentials("example.com", None).is_none(),
            "deletion must actually delete"
        );
        assert!(
            store.find_credentials("test.com", None).is_some(),
            "deletion must not touch other relying parties"
        );
    }

    /// UV requires a PIN, and requires it to have been verified.
    #[tokio::test]
    async fn test_pin_required_for_uv() {
        use ::netget::server::usb::fido2::ctap2::Ctap2CredentialStore;

        let mut store = Ctap2CredentialStore::new();

        assert!(
            store
                .make_credential("example.com", b"user123", "test@example.com", false, true)
                .is_err(),
            "UV without a PIN must fail"
        );

        store.set_pin("test1234").unwrap();
        assert!(
            store
                .make_credential("example.com", b"user123", "test@example.com", false, true)
                .is_err(),
            "UV with an unverified PIN must fail"
        );

        store.verify_pin("test1234").unwrap();
        assert!(
            store
                .make_credential("example.com", b"user123", "test@example.com", false, true)
                .is_ok(),
            "UV with a verified PIN must succeed"
        );
    }

    /// A message that fits in one frame stays in one frame.
    #[tokio::test]
    async fn test_ctaphid_small_message() {
        use ::netget::server::usb::fido2::ctaphid::{CtapHidCommand, CtapHidHandler};

        let handler = CtapHidHandler::new();
        let cid = 0x12345678u32;
        let data = b"Hello FIDO2!";

        let packets = handler.fragment_response(cid, CtapHidCommand::Ping, data);
        assert_eq!(packets.len(), 1, "Small message should fit in 1 packet");

        let packet = &packets[0];
        assert_eq!(packet.len(), 64, "Packet should be 64 bytes");
        assert_eq!(
            u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]),
            cid
        );
        assert_eq!(packet[4], (CtapHidCommand::Ping as u8) | 0x80);
        assert_eq!(
            u16::from_be_bytes([packet[5], packet[6]]),
            data.len() as u16
        );
        assert_eq!(&packet[7..7 + data.len()], data);
    }

    /// 150 bytes is 1 init frame plus 2 continuations, with the exact byte ranges pinned.
    #[tokio::test]
    async fn test_ctaphid_large_message_fragmentation() {
        use ::netget::server::usb::fido2::ctaphid::{CtapHidCommand, CtapHidHandler};

        let handler = CtapHidHandler::new();
        let cid = 0xabcdef01u32;
        let data = vec![0xAAu8; 150];

        let packets = handler.fragment_response(cid, CtapHidCommand::Cbor, &data);
        assert_eq!(packets.len(), 3, "150-byte message should need 3 packets");

        let init_packet = &packets[0];
        assert_eq!(init_packet[4], (CtapHidCommand::Cbor as u8) | 0x80);
        assert_eq!(u16::from_be_bytes([init_packet[5], init_packet[6]]), 150);
        assert_eq!(&init_packet[7..64], &data[0..57]);

        let cont1 = &packets[1];
        assert_eq!(
            u32::from_be_bytes([cont1[0], cont1[1], cont1[2], cont1[3]]),
            cid
        );
        assert_eq!(cont1[4], 0, "First continuation packet should have SEQ=0");
        assert_eq!(&cont1[5..64], &data[57..116]);

        let cont2 = &packets[2];
        assert_eq!(cont2[4], 1, "Second continuation packet should have SEQ=1");
        assert_eq!(&cont2[5..5 + 34], &data[116..150]);
    }

    /// Fragment then reassemble: the round trip must be lossless.
    #[tokio::test]
    async fn test_ctaphid_packet_assembly() {
        use ::netget::server::usb::fido2::ctaphid::{CtapHidCommand, CtapHidHandler};

        let mut handler = CtapHidHandler::new();
        let cid = 0x99887766u32;
        let original_data = vec![0x42u8; 100];

        let packets = handler.fragment_response(cid, CtapHidCommand::Ping, &original_data);
        assert!(packets.len() > 1, "Should have multiple packets");

        let mut assembled_message = None;
        for packet_bytes in packets {
            let result = handler
                .process_packet(&packet_bytes)
                .expect("Packet processing should not error");
            if let Some(msg) = result {
                assembled_message = Some(msg);
            }
        }

        let message = assembled_message.expect("Message should be assembled");
        assert_eq!(message.cid, cid);
        assert_eq!(message.cmd, CtapHidCommand::Ping);
        assert_eq!(message.into_data(), original_data);
    }

    /// An out-of-order continuation frame is an error, not silently accepted data.
    #[tokio::test]
    async fn test_ctaphid_invalid_sequence() {
        use ::netget::server::usb::fido2::ctaphid::{CtapHidCommand, CtapHidHandler};

        let mut handler = CtapHidHandler::new();
        let cid = 0x11223344u32;
        let data = vec![0x55u8; 150];
        let packets = handler.fragment_response(cid, CtapHidCommand::Cbor, &data);

        assert!(
            handler
                .process_packet(&packets[0])
                .expect("init packet parses")
                .is_none(),
            "Init packet should not complete message"
        );

        assert!(
            handler.process_packet(&packets[2]).is_err(),
            "Should error on invalid sequence"
        );
    }

    /// The spec's maximum message is exactly 1 init + 128 continuation frames.
    #[tokio::test]
    async fn test_ctaphid_max_message_size() {
        use ::netget::server::usb::fido2::ctaphid::{CtapHidCommand, CtapHidHandler};

        let handler = CtapHidHandler::new();
        let data = vec![0x77u8; 7609];

        let packets = handler.fragment_response(0xfedcba98, CtapHidCommand::Msg, &data);
        assert_eq!(
            packets.len(),
            129,
            "Max size message should use 129 packets"
        );

        for packet in &packets {
            assert_eq!(packet.len(), 64, "All packets should be 64 bytes");
        }
        for (i, packet) in packets.iter().enumerate().skip(1) {
            assert_eq!(packet[4] as usize, i - 1, "Sequence should increment");
            assert!(packet[4] < 128, "Sequence should not overflow");
        }
    }

    /// A host must not be able to reserve memory by *declaring* a message it never sends.
    ///
    /// `BCNT` is 16 bits, so one 64-byte init packet could declare 65535 bytes. The assembler
    /// called `Vec::with_capacity(bcnt)` and kept the buffer until the message completed, so a
    /// host that simply never sent the continuation frames held 64 KiB per channel id -- and
    /// there was no cap on channel ids either. 64 bytes on the wire bought ~1000x its own size
    /// in resident memory, indefinitely, before any user-presence decision.
    ///
    /// Remove either bound in `ctaphid.rs` and this test fails.
    #[tokio::test]
    async fn a_host_cannot_reserve_memory_by_declaring_messages_it_never_sends() {
        use ::netget::server::usb::fido2::ctaphid::{
            CtapHidCommand, CtapHidHandler, MAX_ASSEMBLING_CHANNELS, MAX_MESSAGE_SIZE,
        };

        // One init packet on channel `cid` declaring `bcnt` bytes and carrying 57 of them.
        fn init_packet(cid: u32, bcnt: u16) -> Vec<u8> {
            let mut packet = vec![0u8; 64];
            packet[0..4].copy_from_slice(&cid.to_be_bytes());
            packet[4] = (CtapHidCommand::Cbor as u8) | 0x80;
            packet[5..7].copy_from_slice(&bcnt.to_be_bytes());
            packet
        }

        let mut handler = CtapHidHandler::new();

        // A BCNT the transport cannot frame a reply to is refused outright, and the refusal
        // names the channel it happened on rather than the broadcast one.
        let rejected = handler
            .process_packet(&init_packet(0x0000_0001, u16::MAX))
            .expect_err("BCNT=65535 exceeds the 7609-byte CTAPHID maximum and must be refused");
        let rejection = ::netget::server::usb::fido2::ctaphid::rejection_of(&rejected);
        assert_eq!(
            rejection.cid, 0x0000_0001,
            "the refusal must name the host's channel"
        );
        assert_eq!(
            handler.assembling_channels(),
            0,
            "a refused message must retain nothing"
        );

        // A BCNT at the maximum is legal and does consume a channel.
        let legal = u16::try_from(MAX_MESSAGE_SIZE).expect("the maximum fits in BCNT");
        for cid in 1..=MAX_ASSEMBLING_CHANNELS as u32 {
            assert!(
                handler
                    .process_packet(&init_packet(0x1000_0000 + cid, legal))
                    .expect("a message at the maximum size is legal")
                    .is_none(),
                "an incomplete message must not be returned as complete"
            );
        }
        assert_eq!(handler.assembling_channels(), MAX_ASSEMBLING_CHANNELS);

        // One more channel is refused, so the retained memory is capped rather than unbounded.
        handler
            .process_packet(&init_packet(0xdead_beef, legal))
            .expect_err("a host must not open more concurrent assemblies than the cap allows");
        assert_eq!(
            handler.assembling_channels(),
            MAX_ASSEMBLING_CHANNELS,
            "a refused channel must not be retained"
        );

        // Re-initializing a channel already assembling replaces its buffer, so it is free.
        assert!(handler
            .process_packet(&init_packet(0x1000_0001, legal))
            .expect("re-initializing an open channel is not a new allocation")
            .is_none());
        assert_eq!(handler.assembling_channels(), MAX_ASSEMBLING_CHANNELS);
    }

    /// A reply too long to frame is refused, not silently garbled.
    ///
    /// `seq` is 7 bits, so the 129th continuation packet reused sequence 0 while `BCNT`
    /// separately wrapped through `as u16` -- a host received a well-formed-looking answer
    /// that decoded to the wrong thing. One byte past the maximum now produces the single
    /// `INVALID_LEN` error frame that says so.
    #[tokio::test]
    async fn a_reply_longer_than_the_transport_can_frame_is_refused() {
        use ::netget::server::usb::fido2::ctaphid::{
            CtapHidCommand, CtapHidHandler, MAX_MESSAGE_SIZE,
        };

        let handler = CtapHidHandler::new();
        let cid = 0x0bad_0bad_u32;

        // Exactly at the limit still fragments normally: a guard that refused everything
        // would pass the assertion below while breaking the protocol.
        let at_limit =
            handler.fragment_response(cid, CtapHidCommand::Msg, &vec![0x77u8; MAX_MESSAGE_SIZE]);
        assert_eq!(
            at_limit.len(),
            129,
            "the maximum message is 1 init + 128 continuations"
        );

        let over = handler.fragment_response(
            cid,
            CtapHidCommand::Msg,
            &vec![0x77u8; MAX_MESSAGE_SIZE + 1],
        );
        assert_eq!(over.len(), 1, "an unframeable reply is one error packet");
        assert_eq!(
            u32::from_be_bytes([over[0][0], over[0][1], over[0][2], over[0][3]]),
            cid,
            "the error must go to the channel that asked"
        );
        assert_eq!(
            over[0][4],
            (CtapHidCommand::Error as u8) | 0x80,
            "an unframeable reply is answered with CTAPHID ERROR"
        );
        assert_eq!(over[0][7], 0x03, "CTAP1_ERR_INVALID_LEN");
    }

    /// The approval manager's own contract, including the two shapes the E2E tests rely on:
    /// an unanswered request denies, and `approve`/`deny` are callable from a synchronous
    /// context (they used to need `Handle::current().block_on`, which panicked).
    #[tokio::test]
    async fn test_approval_manager_contract() {
        use ::netget::server::usb::fido2::approval::{
            ApprovalConfig, ApprovalDecision, ApprovalDetails, ApprovalManager, OperationType,
        };

        let details = |rp: &str| ApprovalDetails {
            operation: OperationType::Register,
            rp_id: rp.to_string(),
            user_name: Some("user@example.com".to_string()),
            credential_count: 0,
        };

        // Auto-approve short-circuits.
        let auto = ApprovalManager::new(ApprovalConfig {
            auto_approve: true,
            timeout: Duration::from_secs(30),
            timeout_decision: ApprovalDecision::Denied,
        });
        let (id, decision) = auto.request_approval(details("example.com"), None).await;
        assert_eq!(decision, ApprovalDecision::Approved);
        assert!(id > 0, "approval ids start at 1");

        let manager = ApprovalManager::new(ApprovalConfig {
            auto_approve: false,
            timeout: Duration::from_secs(5),
            timeout_decision: ApprovalDecision::Denied,
        });

        // Open, then resolve from outside — synchronously, with no runtime handle.
        let (id, rx) = manager.open(details("example.com"), None);
        assert_eq!(
            manager.list_pending().len(),
            1,
            "an opened request must be listed as pending"
        );
        manager.approve(id).expect("approve must find the request");
        assert_eq!(
            manager.wait(id, rx).await,
            ApprovalDecision::Approved,
            "the decision must reach the waiter"
        );
        assert!(
            manager.list_pending().is_empty(),
            "a resolved request must be removed from the pending list"
        );

        let (id, rx) = manager.open(details("deny.example"), None);
        manager.deny(id).expect("deny must find the request");
        assert_eq!(manager.wait(id, rx).await, ApprovalDecision::Denied);

        // Resolving an id that is not pending is an error naming the problem, not a silent
        // success — a silent success would let a model "approve" a request that never existed.
        assert!(
            manager.approve(9999).is_err(),
            "approving an unknown id must fail"
        );

        // And the one that matters most: nothing answers, so it denies.
        let quick = ApprovalManager::new(ApprovalConfig {
            auto_approve: false,
            timeout: Duration::from_millis(100),
            timeout_decision: ApprovalDecision::Denied,
        });
        let (_, decision) = quick
            .request_approval(details("silent.example"), None)
            .await;
        assert_eq!(
            decision,
            ApprovalDecision::Denied,
            "an unanswered request must deny; defaulting to approval is the fail-open shape \
             this codebase keeps being bitten by"
        );
    }
}
