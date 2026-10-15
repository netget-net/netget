//! The declared `username` / `password` / `use_tls` startup parameters must actually reach
//! the SMTP session.
//!
//! All three are declared in `get_startup_parameters()`, and nothing read them at connect:
//! `deliver` took all three off the *action* instead, so what the caller passed when opening
//! the client was discarded. `ConnectContext::startup_params` is where those values arrive,
//! and the client now reads them there and keeps them as session defaults.
//!
//! What their absence cost, and why it never failed loudly:
//!
//!   * `use_tls` — the action's own default is `true`, so a client opened against a plaintext
//!     relay with `use_tls: false` demanded STARTTLS on **every** message and every delivery
//!     was refused. There was no way to turn it off for the session; only the model naming
//!     `use_tls: false` on each individual `send_email` worked.
//!   * `username` / `password` — credentials supplied once at connect were never sent, so a
//!     server requiring AUTH refused every message unless the model repeated the credentials
//!     on every action. A model that was never told them cannot.
//!
//! The peer here is a ~70-line listener rather than a NetGet SMTP server, for the reason
//! `command_channel_test.rs` gives: NetGet's SMTP server raises one event id for the banner
//! and for every command, so no `static` handler can drive a session to completion. This one
//! is deliberately hostile in the two ways that matter — it offers **no** STARTTLS and it
//! refuses `MAIL FROM` until a correct `AUTH PLAIN` has been accepted — so a delivery that
//! succeeds proves both parameters crossed the wire, and proves it on bytes rather than on
//! internal state.
//!
//! **Zero LLM calls**: the client's model endpoint is 127.0.0.1:1, and the connected-event
//! call is free to fail. Everything asserted here goes through `send_to_client`.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features smtp --test client -- smtp::startup_params --test-threads=100


use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use netget::cli::management::ClientForm;
use netget::state::app_state::AppState;
use netget::state::client_handles::ClientSendOutcome;
use netget::state::ClientId;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};

const AUTH_USER: &str = "postmaster@netget.test";
const AUTH_PASS: &str = "startup-param-secret";

async fn new_state() -> AppState {
    let state = AppState::new_with_options(false, "http://127.0.0.1:1".to_string());
    state
        .set_llm_client(netget::llm::OllamaClient::new(
            "http://127.0.0.1:1".to_string(),
        ))
        .await;
    state
}

async fn wait_for_client_handle(state: &AppState, id: ClientId) {
    for _ in 0..1_000 {
        if state.has_client_handle(id).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!(
        "SMTP client #{} never registered a command handle",
        id.as_u32()
    );
}

/// An SMTP peer that advertises AUTH PLAIN and **no** STARTTLS, and refuses every `MAIL FROM`
/// until the exact expected credentials have been accepted. Returns the bound port and the
/// transcript of everything the client said.
async fn start_auth_required_smtp() -> (u16, Arc<Mutex<String>>) {
    // RFC 4616: the PLAIN initial response is authzid NUL authcid NUL passwd.
    let expected_initial_response = base64::engine::general_purpose::STANDARD
        .encode(format!("\0{AUTH_USER}\0{AUTH_PASS}").as_bytes());

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    let transcript = Arc::new(Mutex::new(String::new()));
    let sink = transcript.clone();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let sink = sink.clone();
            let expected = expected_initial_response.clone();
            tokio::spawn(async move {
                let (read_half, mut write_half) = tokio::io::split(stream);
                let mut reader = BufReader::new(read_half);
                if write_half
                    .write_all(b"220 auth.netget.test ESMTP\r\n")
                    .await
                    .is_err()
                {
                    return;
                }

                let mut authenticated = false;
                let mut in_data = false;
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                    sink.lock().await.push_str(&line);

                    let owned_reply: Vec<u8>;
                    let reply: &[u8] = if in_data {
                        if line.trim_end() == "." {
                            in_data = false;
                            b"250 2.0.0 Ok: queued\r\n"
                        } else {
                            continue; // message body line
                        }
                    } else {
                        let mut fields = line.trim_end().split_whitespace();
                        let verb = fields.next().unwrap_or_default().to_uppercase();
                        match verb.as_str() {
                            // No STARTTLS is offered: a client that insists on it cannot
                            // deliver here, which is what makes `use_tls` load-bearing.
                            "EHLO" | "LHLO" => {
                                b"250-auth.netget.test\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n"
                            }
                            "HELO" => b"250 auth.netget.test\r\n",
                            "AUTH" => {
                                let mechanism = fields.next().unwrap_or_default().to_uppercase();
                                let initial_response = fields.next().unwrap_or_default();
                                if mechanism == "PLAIN" && initial_response == expected {
                                    authenticated = true;
                                    owned_reply =
                                        b"235 2.7.0 Authentication successful\r\n".to_vec();
                                } else {
                                    owned_reply =
                                        b"535 5.7.8 Authentication credentials invalid\r\n"
                                            .to_vec();
                                }
                                &owned_reply
                            }
                            "MAIL" | "RCPT" | "DATA" if !authenticated => {
                                b"530 5.7.0 Authentication required\r\n"
                            }
                            "MAIL" | "RCPT" | "RSET" | "NOOP" => b"250 2.0.0 Ok\r\n",
                            "DATA" => {
                                in_data = true;
                                b"354 End data with <CR><LF>.<CR><LF>\r\n"
                            }
                            "QUIT" => {
                                let _ = write_half.write_all(b"221 2.0.0 Bye\r\n").await;
                                return;
                            }
                            _ => b"502 5.5.2 Command not implemented\r\n",
                        }
                    };
                    if write_half.write_all(reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    (port, transcript)
}

#[tokio::test]
async fn credentials_and_use_tls_come_from_the_startup_parameters() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let (port, transcript) = start_auth_required_smtp().await;

    let client_id = ClientForm {
        protocol: "smtp".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("startup parameter probe".to_string()),
        startup_params: Some(serde_json::json!({
            "username": AUTH_USER,
            "password": AUTH_PASS,
            "use_tls": false,
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create smtp client");

    wait_for_client_handle(&state, client_id).await;

    // Nothing here names username, password or use_tls: the session defaults are the only
    // place they can come from. Before the fix this action demanded STARTTLS from a peer that
    // offers none, and sent no AUTH to a peer that requires it.
    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_email",
                "from": "sender@netget.test",
                "to": ["recipient@netget.test"],
                "subject": "startup-params-marker",
                "body": "delivered using the session's declared credentials"
            }),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client send_email");

    match &outcome {
        ClientSendOutcome::Executed { detail } => assert!(
            detail.contains("startup-params-marker"),
            "detail should name the delivered message, got {detail:?}"
        ),
        other => panic!(
            "expected the message to be delivered using the startup parameters, got {other:?}; \
             transcript was:\n{}",
            transcript.lock().await
        ),
    }

    let seen = transcript.lock().await.clone();
    assert!(
        seen.contains("AUTH PLAIN"),
        "the declared credentials should have been offered to the peer; transcript was:\n{seen}"
    );
    assert!(
        seen.contains("RCPT TO:<recipient@netget.test>"),
        "the message should have reached the peer past its AUTH gate; transcript was:\n{seen}"
    );
    assert!(
        !seen.contains("STARTTLS"),
        "use_tls:false means no STARTTLS should have been attempted; transcript was:\n{seen}"
    );
}

/// A value on the action still wins over the session default — the model may legitimately
/// authenticate as someone else for one message — so the startup parameters are defaults,
/// not overrides.
#[tokio::test]
async fn an_action_may_override_the_session_credentials() {
    let state = new_state().await;
    let (tx, _rx) = mpsc::unbounded_channel();
    let (port, transcript) = start_auth_required_smtp().await;

    let client_id = ClientForm {
        protocol: "smtp".to_string(),
        remote_addr: Some(format!("127.0.0.1:{port}")),
        instruction: Some("startup parameter probe".to_string()),
        startup_params: Some(serde_json::json!({
            "username": "wrong@netget.test",
            "password": "wrong",
            "use_tls": false,
        })),
        ..Default::default()
    }
    .create(
        &state,
        netget::llm::OllamaClient::new("http://127.0.0.1:1".to_string()),
        tx.clone(),
    )
    .await
    .expect("create smtp client");

    wait_for_client_handle(&state, client_id).await;

    let outcome = state
        .send_to_client(
            client_id,
            serde_json::json!({
                "type": "send_email",
                "from": "sender@netget.test",
                "to": ["recipient@netget.test"],
                "subject": "action-override-marker",
                "body": "delivered using the action's own credentials",
                "username": AUTH_USER,
                "password": AUTH_PASS
            }),
            Duration::from_secs(15),
        )
        .await
        .expect("send_to_client send_email");

    assert!(
        matches!(outcome, ClientSendOutcome::Executed { .. }),
        "the action's credentials must win over the session defaults, got {outcome:?}; \
         transcript was:\n{}",
        transcript.lock().await
    );
}
