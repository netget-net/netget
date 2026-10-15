//! EAPOL / 802.1X authenticator, end to end.
//!
//! # Why this is in-process and over UDP
//!
//! EAPOL's real transport is raw Ethernet and needs `/dev/bpf*` or `CAP_NET_RAW`. Nothing in
//! this repository has that, and the privilege gate in `server_startup` is **per protocol,
//! evaluated before startup parameters are read** — so an `open_server` for EAPOL is refused
//! on an unprivileged host even when `transport: "udp"` is requested, and the usual
//! child-process harness cannot start this server at all. This suite therefore builds a real
//! `SpawnContext` and calls `Server::spawn` directly, the way
//! `tests/server/bluetooth_ble_beacon/e2e_test.rs` and `tests/server/lldp/e2e_test.rs` do,
//! and asks the protocol for its declared `transport: "udp"` test transport.
//!
//! What that buys is the whole path: a frame arrives, `codec.rs` decodes it, the session
//! machine classifies it, the event is raised, a handler or the model answers, the action is
//! executed, a frame is built and transmitted, and the test decodes it again with the same
//! codec a supplicant would. What it does not buy is any evidence about pcap — see this
//! directory's `CLAUDE.md`.
//!
//! # What these tests are actually for
//!
//! An `EAP-Success` frame opens a switch port, so this file's centre of gravity is not the
//! happy path but the ways a fail-open authenticator gets built:
//!
//! | Test | What it would catch |
//! |---|---|
//! | [`silence_and_denial_both_deny_but_are_distinguishable`] | the OAuth2 defect verbatim — no answer becoming an approval, and a denial being indistinguishable from an outage |
//! | [`an_llm_outage_denies_and_never_admits`] | a backend failure falling through to a permissive default |
//! | [`nothing_a_supplicant_sends_can_produce_a_success`] | admission arriving from the wire rather than from a decision |
//! | [`a_success_is_refused_until_an_identity_exists`] | an explicit `send_eap_success` honoured before anyone said who they were |
//!
//! Exactly two tests admit anybody at all, and each has to be *told* to by a model action.
//!
//! # LLM budget
//!
//! **Five calls, in two tests.** Everything else either uses a static handler (no call by
//! construction) or points the client at `127.0.0.1:1` so the outcome *proves* no call
//! succeeded, rather than merely that none was counted.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features eapol \
//!       --test server server::eapol -- --test-threads=100

#![cfg(all(unix, feature = "libpcap"))]

use netget::llm::actions::protocol_trait::{Protocol, Server};
use netget::llm::OllamaClient;
use netget::protocol::{SpawnContext, StartupParams};
use netget::server::eapol::actions::EapolProtocol;
use netget::server::eapol::codec::{self, EapPacket, EapolFrame};
use netget::state::app_state::AppState;
use netget::state::server::ServerInstance;
use netget::state::ServerId;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::helpers::common::E2EResult;
use crate::helpers::mock_builder::MockLlmBuilder;
use crate::helpers::mock_ollama::MockOllamaServer;

/// An endpoint nothing listens on. Any test using it proves the outcome happened *without* a
/// successful model call — the same trick `bluetooth_ble_beacon` and `lldp` use.
const UNREACHABLE_LLM: &str = "http://127.0.0.1:1";

const ALICE: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const MALLORY: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

// ===========================================================================
// Harness
// ===========================================================================

/// A running EAPOL authenticator plus everything needed to observe it.
struct Running {
    addr: SocketAddr,
    status_rx: UnboundedReceiver<String>,
    /// Held so the mock outlives the test; `None` when no model call is expected.
    mock: Option<MockOllamaServer>,
    /// Held so the server's tasks are not dropped mid-test.
    _state: Arc<AppState>,
}

impl Running {
    /// Wait up to `secs` for a status line containing `needle`, returning it.
    ///
    /// Polls rather than sleeping: these assertions are about *which* decision was taken, and
    /// a fixed sleep long enough to be reliable under `--test-threads=100` would make every
    /// test here slow.
    async fn wait_for_status(&mut self, needle: &str, secs: u64) -> Option<String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
        let mut seen = Vec::new();
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(250), self.status_rx.recv()).await {
                Ok(Some(line)) => {
                    if line.contains(needle) {
                        return Some(line);
                    }
                    seen.push(line);
                }
                Ok(None) => break,
                Err(_) => continue,
            }
        }
        println!("status lines seen while waiting for '{needle}': {seen:#?}");
        None
    }

    /// Drain everything currently in the status stream. Used for "this was never logged"
    /// assertions, always *after* the decision under test has already been observed.
    fn drain_status(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(line) = self.status_rx.try_recv() {
            out.push(line);
        }
        out
    }
}

/// Start an EAPOL authenticator on the UDP test transport, in-process.
async fn start(
    instruction: &str,
    handlers: Option<Vec<Value>>,
    mut startup_params: Value,
    llm_url: &str,
    mock: Option<MockOllamaServer>,
) -> E2EResult<Running> {
    let state = Arc::new(AppState::new());
    // Without this, `ensure_model_selected` tries to auto-select against localhost:11434 and
    // the test would depend on the developer's machine.
    state.set_ollama_model(Some("mock-model".to_string())).await;

    let server_id = state
        .add_server(ServerInstance::new(
            ServerId::new(0),
            0,
            "EAPOL".to_string(),
            instruction.to_string(),
        ))
        .await;

    if let Some(handlers) = handlers {
        let config = netget::events::handler::EventHandler::parse_event_handlers(handlers)?;
        state
            .with_server_mut(server_id, |s| s.event_handler_config = Some(config))
            .await;
    }

    let protocol = EapolProtocol::new();
    if let Some(obj) = startup_params.as_object_mut() {
        obj.entry("transport").or_insert_with(|| json!("udp"));
    }
    let params = StartupParams::new(startup_params, protocol.get_startup_parameters())?;

    let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel();

    #[allow(deprecated)]
    let ctx = SpawnContext {
        listen_addr: "127.0.0.1:0".parse()?,
        mac_address: None,
        interface: None,
        host: Some("127.0.0.1".to_string()),
        port: Some(0),
        llm_client: OllamaClient::new(llm_url),
        state: state.clone(),
        status_tx,
        server_id,
        startup_params: Some(params),
    };

    let addr = protocol.spawn(ctx).await?;

    Ok(Running {
        addr,
        status_rx,
        mock,
        _state: state,
    })
}

/// A supplicant on the UDP test transport: `[MAC (6 octets)][EAPOL frame]`, both directions.
struct Supplicant {
    socket: UdpSocket,
    server: SocketAddr,
    mac: [u8; 6],
}

impl Supplicant {
    async fn new(server: SocketAddr, mac: [u8; 6]) -> E2EResult<Self> {
        Ok(Self {
            socket: UdpSocket::bind("127.0.0.1:0").await?,
            server,
            mac,
        })
    }

    async fn send(&self, eapol: &[u8]) -> E2EResult<()> {
        let mut datagram = Vec::with_capacity(6 + eapol.len());
        datagram.extend_from_slice(&self.mac);
        datagram.extend_from_slice(eapol);
        self.socket.send_to(&datagram, self.server).await?;
        Ok(())
    }

    /// Read one reply, or `None` if the server stayed silent for `secs`.
    async fn recv(&self, secs: u64) -> E2EResult<Option<Vec<u8>>> {
        let mut buffer = vec![0u8; 4096];
        match tokio::time::timeout(
            Duration::from_secs(secs),
            self.socket.recv_from(&mut buffer),
        )
        .await
        {
            Ok(Ok((n, _))) if n >= 6 => {
                assert_eq!(
                    &buffer[..6],
                    &self.mac,
                    "the reply must be addressed to this supplicant"
                );
                Ok(Some(buffer[6..n].to_vec()))
            }
            Ok(Ok((n, _))) => Err(format!("reply was only {} octets", n).into()),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Ok(None),
        }
    }

    /// Send and wait for the reply the server must produce.
    async fn exchange(&self, eapol: &[u8]) -> E2EResult<Vec<u8>> {
        self.send(eapol).await?;
        self.recv(30).await?.ok_or_else(|| {
            "the authenticator sent nothing; it must never leave a supplicant hanging".into()
        })
    }
}

/// Decode a reply into its EAP packet, failing loudly if it is not one.
fn eap_of(frame: &[u8]) -> EapPacket {
    let eapol = EapolFrame::decode(frame).expect("the reply must be a well-formed EAPOL frame");
    assert_eq!(
        eapol.packet_type,
        codec::EAPOL_TYPE_EAP_PACKET,
        "the reply must carry an EAP packet"
    );
    EapPacket::decode(&eapol.body).expect("the reply must be a well-formed EAP packet")
}

/// **The assertion this whole file exists for.**
///
/// Not "the reply is a Failure" — that is the same statement made twice and would pass on a
/// server that answered nothing at all. This says the Success *code* is absent from whatever
/// came back, whatever shape it took.
fn assert_not_a_success(frame: &[u8], context: &str) {
    let eapol = EapolFrame::decode(frame)
        .unwrap_or_else(|e| panic!("{}: reply is not a valid EAPOL frame: {}", context, e));
    if eapol.packet_type != codec::EAPOL_TYPE_EAP_PACKET {
        return;
    }
    if let Ok(eap) = EapPacket::decode(&eapol.body) {
        assert_ne!(
            eap.code,
            codec::EAP_CODE_SUCCESS,
            "{}: the authenticator admitted a device. Frame: {}",
            context,
            hex::encode(frame)
        );
    }
}

/// A static routing table answering every event with `actions`.
fn static_handler(pattern: &str, actions: Value) -> Value {
    json!({
        "event_pattern": pattern,
        "handler": {"type": "static", "actions": actions}
    })
}

// ===========================================================================
// The full exchange — the only path that admits anybody
// ===========================================================================

/// Start -> Request/Identity -> Response/Identity -> MD5-Challenge -> verified -> Success.
///
/// Every step is asserted on the wire, and two of them are what make an authenticator work
/// rather than merely compile:
///
/// * **the EAP identifier**, which a supplicant uses to match a Request to its Response and
///   silently discards a mismatch on — a bug that presents as a hang, not as an error;
/// * **the MD5 digest**, computed by NetGet over a challenge NetGet generated. The model is
///   handed a verdict (`md5_verified`), never a hash, and the mock branches on that verdict,
///   so a server that mis-verified would take the deny branch and fail this test.
///
/// Three LLM calls.
#[tokio::test]
async fn the_full_exchange_admits_a_verified_supplicant() -> E2EResult<()> {
    let mock_config = MockLlmBuilder::new()
        .on_event("eapol_start")
        .respond_with_actions(json!([{"type": "send_eap_request_identity"}]))
        .expect_calls(1)
        .and()
        .on_event("eapol_identity_response")
        .respond_with_actions_from_event(|event| {
            // Derived from the event: if the server mis-read the identity this becomes a
            // denial and every assertion below fails.
            if event["identity"].as_str() == Some("alice") {
                json!([{
                    "type": "send_eap_request_method",
                    "eap_type": "md5-challenge",
                    "expected_password": "hunter2"
                }])
            } else {
                json!([{"type": "send_eap_failure"}])
            }
        })
        .expect_calls(1)
        .and()
        .on_event("eapol_method_response")
        .respond_with_actions_from_event(|event| {
            // The model admits on NetGet's verdict, never on its own reading of a digest.
            if event["md5_verified"].as_bool() == Some(true) {
                json!([{"type": "send_eap_success"}])
            } else {
                json!([{"type": "send_eap_failure"}])
            }
        })
        .expect_calls(1)
        .and()
        .build();

    let mock = MockOllamaServer::start(mock_config).await?;
    let url = mock.base_url();

    let mut server = start(
        "You are an 802.1X authenticator. Admit alice if MD5 verifies with hunter2.",
        None,
        json!({}),
        &url,
        Some(mock),
    )
    .await?;
    let alice = Supplicant::new(server.addr, ALICE).await?;

    // 1. EAPOL-Start -> EAP-Request/Identity
    let reply = alice.exchange(&codec::eapol_start_frame(2)).await?;
    let request = eap_of(&reply);
    assert_eq!(request.code, codec::EAP_CODE_REQUEST);
    assert_eq!(request.eap_type, Some(codec::EAP_TYPE_IDENTITY));
    let identity_id = request.identifier;

    // 2. EAP-Response/Identity echoing that identifier -> EAP-Request/MD5-Challenge
    let reply = alice
        .exchange(&codec::eapol_wrap_eap(
            2,
            &codec::eap_response_identity(identity_id, "alice")?,
        )?)
        .await?;
    let challenge_request = eap_of(&reply);
    assert_eq!(challenge_request.code, codec::EAP_CODE_REQUEST);
    assert_eq!(
        challenge_request.eap_type,
        Some(codec::EAP_TYPE_MD5_CHALLENGE)
    );
    assert_eq!(
        challenge_request.identifier,
        identity_id.wrapping_add(1),
        "a new Request must use a fresh identifier, or the supplicant cannot tell it from the \
         one it already answered"
    );

    let (challenge, name) = codec::decode_md5_value(&challenge_request.type_data)?;
    assert_eq!(
        challenge.len(),
        codec::MD5_CHALLENGE_LEN,
        "RFC 1994 §2.2 wants a challenge at least as long as the digest"
    );
    assert_ne!(
        challenge,
        vec![0u8; codec::MD5_CHALLENGE_LEN],
        "the challenge must be generated, not defaulted"
    );
    assert_eq!(name, "netget");

    // 3. The correct digest -> EAP-Success.
    //
    // The digest is computed with the same function the server verifies with. That is
    // circular here on purpose and is not what this step proves: `codec_test.rs` pins the
    // digest against a Python-computed literal and MD5 itself against the RFC 1321 suite.
    // What this proves is that the challenge really was carried, verified, and turned into a
    // verdict the model could act on.
    let digest = codec::md5_challenge_digest(challenge_request.identifier, "hunter2", &challenge);
    let response = codec::eap_response(
        challenge_request.identifier,
        codec::EAP_TYPE_MD5_CHALLENGE,
        &codec::encode_md5_value(&digest, "alice")?,
    )?;
    let reply = alice
        .exchange(&codec::eapol_wrap_eap(2, &response)?)
        .await?;

    let success = eap_of(&reply);
    assert_eq!(
        success.code,
        codec::EAP_CODE_SUCCESS,
        "a verified supplicant the model admitted must get EAP-Success, got {}",
        codec::eap_code_name(success.code)
    );
    assert_eq!(
        success.identifier, challenge_request.identifier,
        "RFC 3748 §4.2: a Success echoes the Response it answers, or the supplicant discards \
         it and the exchange looks like a hang"
    );

    assert!(
        server
            .wait_for_status("decision=model_admit", 30)
            .await
            .is_some(),
        "the grant must be logged as the model's decision"
    );
    assert!(
        server
            .wait_for_status("is now AUTHORIZED", 30)
            .await
            .is_some(),
        "the port transition must be logged"
    );

    server.mock.as_ref().expect("mock").verify_calls().await?;
    Ok(())
}

// ===========================================================================
// The OAuth2 regression, both halves, in one run
// ===========================================================================

/// **The OAuth2 regression test.**
///
/// OAuth2 fell through to a hardcoded token when the LLM returned nothing usable, so an
/// outage silently issued credentials and a model's explicit denial was indistinguishable
/// from its silence. Both halves run against the *same* server and the *same* routing table,
/// told apart only by supplicant MAC, so the comparison is real rather than two separate runs
/// that happen to agree:
///
/// * `alice` gets an empty action list — the exact shape that became an approval in OAuth2.
/// * `mallory` gets an explicit `send_eap_failure`.
///
/// On the wire both must be EAP-Failure, which is correct: EAPOL has one way to say no. In
/// the log they must be `fail_closed_no_action` and `model_reject`, and neither may be
/// recorded as the other.
///
/// Two LLM calls.
#[tokio::test]
async fn silence_and_denial_both_deny_but_are_distinguishable() -> E2EResult<()> {
    let mock_config = MockLlmBuilder::new()
        .on_event("eapol_identity_response")
        .and_event_data_contains("source_mac", "02:00:00:00:00:01")
        // The model answers, but with no protocol action at all.
        .respond_with_actions(json!([]))
        .expect_calls(1)
        .and()
        .on_event("eapol_identity_response")
        .and_event_data_contains("source_mac", "02:00:00:00:00:02")
        .respond_with_actions(json!([{"type": "send_eap_failure"}]))
        .expect_calls(1)
        .and()
        .build();

    let mock = MockOllamaServer::start(mock_config).await?;
    let url = mock.base_url();

    let mut server = start(
        "Decide who may join the network.",
        None,
        json!({}),
        &url,
        Some(mock),
    )
    .await?;

    // Half one: the model says nothing.
    let alice = Supplicant::new(server.addr, ALICE).await?;
    let reply = alice
        .exchange(&codec::eapol_wrap_eap(
            2,
            &codec::eap_response_identity(7, "alice")?,
        )?)
        .await?;

    assert_not_a_success(&reply, "an empty action list");
    assert_eq!(
        reply,
        codec::eapol_eap_failure_frame(2, 7),
        "no decision MUST deny, echoing the identifier of the Response it answers, byte for \
         byte"
    );

    let silence_line = server
        .wait_for_status("decision=", 30)
        .await
        .expect("the silent supplicant must produce a decision line");
    assert!(
        silence_line.contains("decision=fail_closed_no_action"),
        "silence must NOT be recorded as a model decision — that conflation IS the OAuth2 \
         bug. Line: {}",
        silence_line
    );
    assert!(
        silence_line.contains("02:00:00:00:00:01"),
        "the decision line must name the supplicant it is about. Line: {}",
        silence_line
    );

    // Half two: the model says no.
    let mallory = Supplicant::new(server.addr, MALLORY).await?;
    let reply = mallory
        .exchange(&codec::eapol_wrap_eap(
            2,
            &codec::eap_response_identity(9, "mallory")?,
        )?)
        .await?;

    assert_not_a_success(&reply, "an explicit denial");
    assert_eq!(reply, codec::eapol_eap_failure_frame(2, 9));

    // The wire cannot carry the distinction — both frames are an EAP-Failure, and that is
    // correct. The log must.
    let denial_line = server
        .wait_for_status("02:00:00:00:00:02", 30)
        .await
        .expect("the denied supplicant must produce a decision line");
    assert!(
        denial_line.contains("decision=model_reject"),
        "an explicit denial must NOT be recorded as fail-closed. Line: {}",
        denial_line
    );

    for line in server.drain_status() {
        assert!(
            !line.contains("decision=model_admit"),
            "nothing in this run may have been admitted. Line: {}",
            line
        );
    }

    server.mock.as_ref().expect("mock").verify_calls().await?;
    Ok(())
}

// ===========================================================================
// Backend outage
// ===========================================================================

/// An LLM that cannot answer must deny, and be recorded as an outage rather than a decision.
///
/// The client points at `127.0.0.1:1`, where nothing listens, so an EAP-Failure arriving is
/// proof that no model call *succeeded* — not merely that none was counted. That is the
/// closest a test gets to a real backend outage, and it exercises exactly the branch one
/// would take.
///
/// Zero LLM calls, by construction.
#[tokio::test]
async fn an_llm_outage_denies_and_never_admits() -> E2EResult<()> {
    let mut server = start(
        "Decide who may join the network.",
        None,
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;
    let alice = Supplicant::new(server.addr, ALICE).await?;

    let reply = alice
        .exchange(&codec::eapol_wrap_eap(
            2,
            &codec::eap_response_identity(3, "alice")?,
        )?)
        .await?;

    assert_not_a_success(&reply, "an LLM outage");
    assert_eq!(
        reply,
        codec::eapol_eap_failure_frame(2, 3),
        "a backend that cannot answer must deny — not admit, and not go silent and leave the \
         supplicant to time out"
    );

    let line = server
        .wait_for_status("decision=", 30)
        .await
        .expect("an outage must still produce a decision line");
    assert!(
        line.contains("decision=fail_closed_llm_error"),
        "an outage must be logged as fail_closed_llm_error, distinct from a model denial. \
         Line: {}",
        line
    );

    // NetGet's retry machinery is not a stranger's business. This is the leak
    // `tests/wire_failure_test.rs` guards against elsewhere, asserted here on the actual
    // bytes — which is the only place it really matters.
    assert_eq!(
        reply.len(),
        8,
        "an EAP-Failure is eight octets and has no field an error message could hide in. \
         Frame: {}",
        hex::encode(&reply)
    );

    for line in server.drain_status() {
        assert!(
            !line.contains("decision=model_"),
            "an outage must not be recorded as any decision of the model's. Line: {}",
            line
        );
    }
    Ok(())
}

// ===========================================================================
// Nothing from the wire can produce a Success
// ===========================================================================

/// **No input at all can coax a Success out of the server without a model action.**
///
/// The routing table answers *every* event with an empty static action list, and the LLM
/// endpoint is unreachable — so nothing here can have consulted a model, and a Success could
/// only have come from the server itself. Then the supplicant tries everything it has:
///
/// * a legitimate EAPOL-Start,
/// * an `EAP-Response/Identity`,
/// * **a forged `EAP-Success` of its own**, the most direct attempt there is,
/// * a forged `EAP-Failure` and an `EAP-Request`, which only an authenticator may send,
/// * an `EAPOL-Key`, which this authenticator does not implement,
/// * a truncated frame and an invalid EAPOL version,
/// * an `EAP-Response/MD5-Challenge` to a challenge that was never issued.
///
/// Every reply must be an EAP-Failure or nothing, and the Success code must never appear.
///
/// Zero LLM calls, by construction.
#[tokio::test]
async fn nothing_a_supplicant_sends_can_produce_a_success() -> E2EResult<()> {
    let mut server = start(
        "Answer nothing, ever.",
        Some(vec![static_handler("*", json!([]))]),
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;
    let alice = Supplicant::new(server.addr, ALICE).await?;

    // Frames the server is expected to answer: each must be a denial.
    let answered: Vec<(&str, Vec<u8>)> = vec![
        ("EAPOL-Start", codec::eapol_start_frame(2)),
        (
            "EAP-Response/Identity",
            codec::eapol_wrap_eap(2, &codec::eap_response_identity(1, "alice")?)?,
        ),
    ];
    for (name, frame) in answered {
        let reply = alice.exchange(&frame).await?;
        assert_not_a_success(&reply, name);
        let eap = eap_of(&reply);
        assert_eq!(
            eap.code,
            codec::EAP_CODE_FAILURE,
            "{} answered with no action must produce EAP-Failure, got {}",
            name,
            codec::eap_code_name(eap.code)
        );
    }

    // Frames the server must ignore outright. Silence is the right answer to all of these: an
    // authenticator does not answer a Success, does not answer a Request, and does not
    // implement EAPOL-Key.
    let ignored: Vec<(&str, Vec<u8>)> = vec![
        (
            "a supplicant's own forged EAP-Success",
            codec::eapol_eap_success_frame(2, 1),
        ),
        (
            "a supplicant's own forged EAP-Failure",
            codec::eapol_eap_failure_frame(2, 1),
        ),
        (
            "an EAP-Request from the supplicant",
            codec::eapol_wrap_eap(2, &codec::eap_request_identity(1))?,
        ),
        (
            "EAPOL-Key",
            vec![0x02, codec::EAPOL_TYPE_KEY, 0x00, 0x02, 0x01, 0x00],
        ),
        ("a truncated frame", vec![0x02, 0x00]),
        ("an EAPOL version of 0", vec![0x00, 0x01, 0x00, 0x00]),
        ("an EAPOL version of 4", vec![0x04, 0x01, 0x00, 0x00]),
    ];
    for (name, frame) in ignored {
        alice.send(&frame).await?;
        if let Some(reply) = alice.recv(2).await? {
            assert_not_a_success(&reply, name);
            panic!(
                "{} must be dropped, not answered. Got: {}",
                name,
                hex::encode(&reply)
            );
        }
    }

    // An unsolicited MD5-Challenge response: a Response the session never asked for. It *is*
    // answered — it is a Response and the session exists — and answered with a denial,
    // because nothing was verified.
    let unsolicited = codec::eap_response(
        1,
        codec::EAP_TYPE_MD5_CHALLENGE,
        &codec::encode_md5_value(&[0xaa; 16], "alice")?,
    )?;
    let reply = alice
        .exchange(&codec::eapol_wrap_eap(2, &unsolicited)?)
        .await?;
    assert_not_a_success(&reply, "an unsolicited MD5-Challenge response");
    assert_eq!(eap_of(&reply).code, codec::EAP_CODE_FAILURE);

    for line in server.drain_status() {
        assert!(
            !line.contains("decision=model_admit") && !line.contains("is now AUTHORIZED"),
            "no port may have been authorized in this run. Line: {}",
            line
        );
    }
    Ok(())
}

// ===========================================================================
// The identity gate
// ===========================================================================

/// An explicit `send_eap_success` is refused until the session has produced an identity.
///
/// The routing table answers *everything* with `send_eap_success` — a deliberately reckless
/// operator, or a model that has decided to admit the world. The same action must be refused
/// on `eapol_start`, where nobody has said who they are, and honoured on
/// `eapol_identity_response`, where somebody has. One static rule, two outcomes, decided
/// entirely by what the session knows.
///
/// This is the gate that makes "an identity is a claim, not evidence" enforceable rather than
/// advisory: without it a supplicant that only ever sent EAPOL-Start could be admitted with
/// no identity attached to the port at all.
///
/// Zero LLM calls, by construction.
#[tokio::test]
async fn a_success_is_refused_until_an_identity_exists() -> E2EResult<()> {
    let mut server = start(
        "Admit everything.",
        Some(vec![static_handler(
            "*",
            json!([{"type": "send_eap_success"}]),
        )]),
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;
    let alice = Supplicant::new(server.addr, ALICE).await?;

    // No identity yet: the Success is refused and the port is denied instead.
    let reply = alice.exchange(&codec::eapol_start_frame(2)).await?;
    assert_not_a_success(&reply, "send_eap_success before any identity");
    assert_eq!(
        eap_of(&reply).code,
        codec::EAP_CODE_FAILURE,
        "an admission with nothing to admit must become a denial"
    );

    let line = server
        .wait_for_status("decision=", 30)
        .await
        .expect("the refusal must produce a decision line");
    assert!(
        line.contains("decision=fail_closed_"),
        "the refusal must be logged as the server's, not the model's. Line: {}",
        line
    );

    // Now an identity exists, and the very same action goes through. This is what makes the
    // test a gate rather than a blanket refusal: the difference is the session state, not
    // the action.
    let reply = alice
        .exchange(&codec::eapol_wrap_eap(
            2,
            &codec::eap_response_identity(1, "alice")?,
        )?)
        .await?;
    let success = eap_of(&reply);
    assert_eq!(
        success.code,
        codec::EAP_CODE_SUCCESS,
        "with an identity on the session the same action must go through, got {}",
        codec::eap_code_name(success.code)
    );
    assert_eq!(success.identifier, 1, "the Success echoes the Response");

    assert!(
        server
            .wait_for_status("decision=model_admit", 30)
            .await
            .is_some(),
        "an admission the routing table really asked for must be logged as one"
    );
    Ok(())
}

// ===========================================================================
// Identifier discipline
// ===========================================================================

/// A Response that does not echo the outstanding Request's identifier is discarded.
///
/// RFC 3748 §4.1 says so, and the failure mode if it is not enforced is a stale or replayed
/// Response being credited to a challenge it never answered. The routing table admits
/// everything, so a server that accepted the mismatched identifier would answer with a
/// Success — which is precisely what must not happen.
///
/// Zero LLM calls, by construction.
#[tokio::test]
async fn a_response_with_the_wrong_identifier_is_discarded() -> E2EResult<()> {
    let server = start(
        "Admit everything.",
        Some(vec![
            static_handler(
                "eapol_start",
                json!([{"type": "send_eap_request_identity"}]),
            ),
            static_handler("*", json!([{"type": "send_eap_success"}])),
        ]),
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;
    let alice = Supplicant::new(server.addr, ALICE).await?;

    let reply = alice.exchange(&codec::eapol_start_frame(2)).await?;
    let request = eap_of(&reply);
    assert_eq!(request.eap_type, Some(codec::EAP_TYPE_IDENTITY));

    // Answer with an identifier the authenticator never issued.
    let wrong = request.identifier.wrapping_add(50);
    alice
        .send(&codec::eapol_wrap_eap(
            2,
            &codec::eap_response_identity(wrong, "alice")?,
        )?)
        .await?;
    if let Some(reply) = alice.recv(2).await? {
        assert_not_a_success(&reply, "a Response with a mismatched identifier");
        panic!(
            "a mismatched identifier must be discarded in silence, got: {}",
            hex::encode(&reply)
        );
    }

    // The correct identifier still works, so the check is a filter and not a wall.
    let reply = alice
        .exchange(&codec::eapol_wrap_eap(
            2,
            &codec::eap_response_identity(request.identifier, "alice")?,
        )?)
        .await?;
    assert_eq!(eap_of(&reply).code, codec::EAP_CODE_SUCCESS);
    Ok(())
}

// ===========================================================================
// Logoff
// ===========================================================================

/// EAPOL-Logoff de-authorizes before the model is consulted, and silence afterwards is safe.
///
/// Ending access is not a decision to delegate: a backend outage must not be able to keep a
/// port open. The session is destroyed first, the event is raised second, and answering
/// nothing puts nothing on the wire — the one event where the fail-closed synthesised
/// EAP-Failure is deliberately suppressed, because there is no access left to deny.
///
/// That the session really was destroyed is asserted the only way it can be from outside: the
/// next Response is treated as unsolicited and the identity is gone, so the same
/// admit-everything rule that granted a Success before logoff now cannot.
///
/// Zero LLM calls, by construction.
#[tokio::test]
async fn logoff_deauthorizes_before_asking_and_then_may_stay_silent() -> E2EResult<()> {
    let mut server = start(
        "Admit everything.",
        Some(vec![
            static_handler("eapol_logoff", json!([])),
            static_handler("*", json!([{"type": "send_eap_success"}])),
        ]),
        json!({}),
        UNREACHABLE_LLM,
        None,
    )
    .await?;
    let alice = Supplicant::new(server.addr, ALICE).await?;

    // Establish an identity and get admitted, so there is something to log off from.
    let reply = alice
        .exchange(&codec::eapol_wrap_eap(
            2,
            &codec::eap_response_identity(1, "alice")?,
        )?)
        .await?;
    assert_eq!(eap_of(&reply).code, codec::EAP_CODE_SUCCESS);
    assert!(server
        .wait_for_status("decision=model_admit", 30)
        .await
        .is_some());

    // Log off. Nothing on the wire is the correct answer to an empty action list here.
    alice.send(&codec::eapol_logoff_frame(2)).await?;
    if let Some(reply) = alice.recv(2).await? {
        assert_not_a_success(&reply, "a logoff");
        panic!(
            "a logoff answered with no action must send nothing, got: {}",
            hex::encode(&reply)
        );
    }
    let line = server
        .wait_for_status("eapol_logoff", 30)
        .await
        .expect("the logoff must be logged with its decision");
    assert!(
        line.contains("decision=fail_closed_no_action"),
        "silence after a logoff is still recorded as the server's decision, not the model's. \
         Line: {}",
        line
    );
    assert!(!line.contains("decision=model_"), "Line: {}", line);
    Ok(())
}

// ===========================================================================
// Startup discipline
// ===========================================================================

/// The raw transport refuses rather than pretending.
///
/// ARP, DataLink, ICMP and IS-IS each shipped the opposite defect — a server sitting in
/// `Running` having captured nothing — and it was fixed four separate times. `spawn` must
/// return `Err` so `server_startup` records `ServerStatus::Error`.
///
/// This is also the honest bound on everything else in this file: the transport anyone would
/// actually deploy cannot be reached from here, and the error names why.
#[tokio::test]
async fn the_raw_transport_refuses_rather_than_pretending() -> E2EResult<()> {
    let state = Arc::new(AppState::new());
    state.set_ollama_model(Some("mock-model".to_string())).await;
    let server_id = state
        .add_server(ServerInstance::new(
            ServerId::new(0),
            0,
            "EAPOL".to_string(),
            String::new(),
        ))
        .await;

    let protocol = EapolProtocol::new();
    let params = StartupParams::new(
        json!({"transport": "raw"}),
        protocol.get_startup_parameters(),
    )?;
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();

    #[allow(deprecated)]
    let ctx = SpawnContext {
        listen_addr: "127.0.0.1:0".parse()?,
        mac_address: None,
        interface: Some("definitely-not-an-interface0".to_string()),
        host: Some("127.0.0.1".to_string()),
        port: Some(0),
        llm_client: OllamaClient::new(UNREACHABLE_LLM),
        state,
        status_tx,
        server_id,
        startup_params: Some(params),
    };

    let error = protocol
        .spawn(ctx)
        .await
        .expect_err("the raw transport must refuse, not report Running having captured nothing");
    let text = format!("{:#}", error);
    assert!(
        text.contains("capture") || text.contains("interface"),
        "the refusal must name what is missing so an operator can act on it. Got: {}",
        text
    );
    Ok(())
}

/// A startup parameter that makes no sense refuses the start rather than being silently
/// replaced by a default — and the error names the key.
#[tokio::test]
async fn unusable_startup_parameters_are_refused() -> E2EResult<()> {
    // An unknown transport.
    let error = start(
        "",
        None,
        json!({"transport": "carrier-pigeon"}),
        UNREACHABLE_LLM,
        None,
    )
    .await
    .err()
    .map(|e| e.to_string())
    .expect("an unknown transport must refuse the start");
    assert!(
        error.contains("carrier-pigeon") && error.contains("udp"),
        "the error must name the bad value and the usable ones. Got: {}",
        error
    );

    // A version outside 1..=3. EAPOL has three, and inventing a fourth would put a version
    // octet on the wire that no supplicant parses.
    let error = start(
        "",
        None,
        json!({"transport": "udp", "eapol_version": 9}),
        UNREACHABLE_LLM,
        None,
    )
    .await
    .err()
    .map(|e| e.to_string())
    .expect("an out-of-range eapol_version must refuse the start");
    assert!(
        error.contains("eapol_version"),
        "the error must name the key. Got: {}",
        error
    );
    Ok(())
}

/// An undeclared parameter names the declared ones, so a model can correct itself rather than
/// guessing again.
#[tokio::test]
async fn an_undeclared_parameter_names_the_declared_ones() -> E2EResult<()> {
    let protocol = EapolProtocol::new();
    let error = StartupParams::new(
        json!({"transport": "udp", "shared_secret": "hunter2"}),
        protocol.get_startup_parameters(),
    )
    .expect_err("an undeclared key must be refused")
    .to_string();

    assert!(error.contains("shared_secret"), "Got: {}", error);
    assert!(
        error.contains("transport") && error.contains("eapol_version"),
        "the error must list what IS accepted. Got: {}",
        error
    );
    Ok(())
}

/// The registry instance can describe the vocabulary but cannot encode a frame, because every
/// frame needs an EAP identifier only a received packet can supply.
///
/// This is the first of the three gates on `EAP-Success`, and it is why
/// `tests/executable_examples_test.rs` records EAPOL under its "needs a request context"
/// exemption rather than as a broken example.
#[test]
fn a_registry_instance_cannot_encode_any_frame() {
    let protocol = EapolProtocol::new();
    for action in [
        "send_eap_request_identity",
        "send_eap_success",
        "send_eap_failure",
        "send_eap_notification",
    ] {
        let error = protocol
            .execute_action(json!({"type": action, "text": "hello"}))
            .err()
            .unwrap_or_else(|| panic!("{action} must not be executable without a request"))
            .to_string();
        assert!(
            error.contains("context"),
            "{action}: the refusal must say it lacks a request context. Got: {error}"
        );
    }

    let unknown = protocol
        .execute_action(json!({"type": "send_eap_open_the_door"}))
        .expect_err("an unknown action must be refused")
        .to_string();
    assert!(
        unknown.contains("Unknown") && unknown.contains("send_eap_open_the_door"),
        "Got: {unknown}"
    );
}
