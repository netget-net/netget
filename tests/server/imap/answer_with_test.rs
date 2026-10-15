//! CAPABILITY is NetGet's, every other command is told its answer, and a completed command
//! gets nothing more.
//!
//! The real-model eval (`./run-eval.sh imap`) scored `imap/list-folders` and
//! `imap/inbox-count` 0/5. llama3.1:8b answered `CAPABILITY` with a bare tagged `OK` - twice,
//! so imaplib read the second as the answer to `LOGIN` and aborted - or with an empty
//! `[CAPABILITY]` code, after which imaplib refused the server; and it answered `SELECT` with a
//! tagged `OK` and no `* n EXISTS`. This file pins each fix from the wire:
//!
//! * `CAPABILITY` is answered by NetGet from the greeting's own list, `IMAP4rev1` guaranteed,
//!   with no model call (there is no rule for it below);
//! * `LOGIN` and `SELECT` carry `answer_with`, and the rules match only on it;
//! * a reply after the tagged completion is dropped, logged
//!   `decision=duplicate_response_dropped`.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| "no IMAP reply within 20s")??;
    if n == 0 {
        return Err("IMAP connection closed without a reply".into());
    }
    Ok(line)
}

/// Every line up to and including the one carrying `tag`.
async fn read_until_tagged(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    tag: &str,
) -> E2EResult<Vec<String>> {
    let mut lines = Vec::new();
    loop {
        let line = read_line(reader).await?;
        let done = line.starts_with(&format!("{tag} "));
        lines.push(line);
        if done {
            return Ok(lines);
        }
    }
}

#[tokio::test]
async fn capability_is_netgets_and_each_command_gets_one_answer() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via imap. INBOX holds 12 messages.";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via imap")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "IMAP",
                "instruction": "INBOX holds 12 messages."
            }]))
            .expect_calls(1)
            .and()
            // A capability list without IMAP4rev1: NetGet puts it first.
            .on_event("imap_connection")
            .respond_with_actions(serde_json::json!([{
                "type": "send_imap_greeting",
                "hostname": "mail.test",
                "capabilities": ["IDLE"]
            }]))
            .expect_calls(1)
            .and()
            // Two completions for one LOGIN: the second must not answer SELECT.
            .on_event("imap_auth")
            .and_event_data_contains("answer_with", "status OK to accept the login")
            .respond_with_actions(serde_json::json!([
                {"type": "send_imap_response", "tag": "a2", "status": "OK", "message": "LOGIN completed"},
                {"type": "send_imap_response", "tag": "a2", "status": "OK", "message": "stale second reply"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("imap_command")
            .and_event_data_contains("answer_with", "send_imap_select with exists")
            .and_event_data_contains("answer_with", "INBOX")
            // The completion *before* the select block, a second completion and the block again:
            // NetGet writes the block once and the completion last, and the second completion
            // must not answer a4.
            .respond_with_actions(serde_json::json!([
                {"type": "send_imap_response", "tag": "a3", "status": "OK", "code": "READ-WRITE", "message": "SELECT completed"},
                {"type": "send_imap_select", "exists": 12},
                {"type": "send_imap_response", "tag": "a3", "status": "OK", "message": "stale second completion"},
                {"type": "send_imap_select", "exists": 12}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(server_config).await?;
    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    assert_eq!(
        read_line(&mut reader).await?,
        "* OK [CAPABILITY IMAP4rev1 IDLE] mail.test IMAP4rev1 Service Ready\r\n"
    );

    write_half.write_all(b"a1 CAPABILITY\r\n").await?;
    assert_eq!(
        read_until_tagged(&mut reader, "a1").await?,
        vec![
            "* CAPABILITY IMAP4rev1 IDLE\r\n".to_string(),
            "a1 OK CAPABILITY completed\r\n".to_string()
        ]
    );

    write_half
        .write_all(b"a2 LOGIN eval eval-password\r\n")
        .await?;
    assert_eq!(
        read_until_tagged(&mut reader, "a2").await?,
        vec!["a2 OK LOGIN completed\r\n".to_string()]
    );

    write_half.write_all(b"a3 SELECT INBOX\r\n").await?;
    let select = read_until_tagged(&mut reader, "a3").await?;
    assert!(
        !select.iter().any(|l| l.contains("stale second reply")),
        "SELECT read LOGIN's dropped second completion: {select:?}"
    );
    assert_eq!(select.first().map(String::as_str), Some("* 12 EXISTS\r\n"));
    assert_eq!(
        select.iter().filter(|l| l.ends_with(" EXISTS\r\n")).count(),
        1,
        "a repeated select block must be written once: {select:?}"
    );
    assert_eq!(
        select.last().map(String::as_str),
        Some("a3 OK [READ-WRITE] SELECT completed\r\n")
    );

    // The next command's answer is its own, not SELECT's dropped second completion.
    write_half.write_all(b"a4 CAPABILITY\r\n").await?;
    assert_eq!(
        read_until_tagged(&mut reader, "a4").await?,
        vec![
            "* CAPABILITY IMAP4rev1 IDLE\r\n".to_string(),
            "a4 OK CAPABILITY completed\r\n".to_string()
        ]
    );

    server
        .wait_for_log("decision=duplicate_response_dropped", 30)
        .await?;
    server.wait_for_log("decision=netget_answer", 30).await?;

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// A tagged response the model sent without text still carries some: RFC 3501's `resp-text` is
/// at least one character, and imaplib aborts the session on a bare `a1 OK` ("unexpected
/// response") - which the real-model eval measured on `LOGIN`.
#[test]
fn a_tagged_response_without_text_still_has_text() {
    use netget::llm::actions::protocol_trait::{ActionResult, Server};
    use netget::server::imap::actions::ImapProtocol;

    let render = |action: serde_json::Value| match ImapProtocol::new().execute_action(action) {
        Ok(ActionResult::Output(bytes)) => String::from_utf8(bytes).expect("utf8"),
        other => panic!("expected output, got {other:?}"),
    };
    assert_eq!(
        render(serde_json::json!({"type": "send_imap_response", "tag": "a1", "status": "OK"})),
        "a1 OK completed\r\n"
    );
    assert_eq!(
        render(serde_json::json!({
            "type": "send_imap_response", "tag": "a1", "status": "OK", "code": "READ-WRITE",
            "message": ""
        })),
        "a1 OK [READ-WRITE] completed\r\n"
    );
    assert_eq!(
        render(serde_json::json!({
            "type": "send_imap_response", "tag": "a1", "status": "NO", "message": "no such mailbox"
        })),
        "a1 NO no such mailbox\r\n"
    );
}

/// A completion carrying another command's tag is written with this command's tag. llama3.1:8b
/// copied the `A001` of an action example onto its LIST completion; as given, imaplib reads it
/// as a response to a command it never sent and aborts ("unexpected response"). LOGIN's own
/// completion goes through the same rewrite.
#[tokio::test]
async fn a_completion_with_another_tag_carries_the_commands_own() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via imap. Folders: INBOX, Archive.";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via imap")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "IMAP",
                "instruction": "Folders: INBOX, Archive."
            }]))
            .expect_calls(1)
            .and()
            .on_event("imap_connection")
            .respond_with_actions(serde_json::json!([{"type": "send_imap_greeting"}]))
            .expect_calls(1)
            .and()
            .on_event("imap_auth")
            .respond_with_actions(serde_json::json!([
                {"type": "send_imap_response", "tag": "A001", "status": "OK", "message": "LOGIN completed"}
            ]))
            .expect_calls(1)
            .and()
            .on_event("imap_command")
            .and_event_data_contains("command", "LIST")
            .respond_with_actions(serde_json::json!([
                {"type": "send_imap_response", "tag": "A001", "status": "OK", "message": "LIST completed"},
                {"type": "send_imap_list", "mailboxes": [
                    {"name": "INBOX", "delimiter": "/", "flags": []},
                    {"name": "Archive", "delimiter": "/", "flags": []}
                ]}
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(server_config).await?;
    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    read_line(&mut reader).await?;

    write_half
        .write_all(b"b1 LOGIN eval eval-password\r\n")
        .await?;
    assert_eq!(
        read_until_tagged(&mut reader, "b1").await?,
        vec!["b1 OK LOGIN completed\r\n".to_string()]
    );

    write_half.write_all(b"b2 LIST \"\" *\r\n").await?;
    let list = read_until_tagged(&mut reader, "b2").await?;
    assert!(
        !list.iter().any(|l| l.starts_with("A001")),
        "a line for a tag the client never sent: {list:?}"
    );
    assert_eq!(list.len(), 3, "two mailboxes and the completion: {list:?}");
    assert!(
        list[0].starts_with("* LIST") && list[0].contains("INBOX"),
        "{list:?}"
    );
    assert!(
        list[1].starts_with("* LIST") && list[1].contains("Archive"),
        "{list:?}"
    );
    assert_eq!(list[2], "b2 OK LIST completed\r\n");

    server
        .wait_for_log("decision=completion_retagged", 30)
        .await?;
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

#[test]
fn only_a_tagged_status_line_for_another_tag_is_retagged() {
    use netget::server::imap::retag_completion;
    let fixed =
        |s: &str| retag_completion(s.as_bytes(), "b7").map(|v| String::from_utf8(v).unwrap());
    assert_eq!(fixed("A001 OK done\r\n").as_deref(), Some("b7 OK done\r\n"));
    assert_eq!(fixed("A001 hello there\r\n"), None);
    assert_eq!(
        fixed("x NO [TRYCREATE] no such mailbox\r\n").as_deref(),
        Some("b7 NO [TRYCREATE] no such mailbox\r\n")
    );
    assert_eq!(fixed("a9 bad\r\n").as_deref(), Some("b7 bad\r\n"));
    // Already this command's, untagged, a continuation, or more than one line: left alone.
    assert_eq!(fixed("b7 OK done\r\n"), None);
    assert_eq!(fixed("* OK [UIDVALIDITY 1]\r\n"), None);
    assert_eq!(fixed("+ go ahead\r\n"), None);
    assert_eq!(fixed("* 3 EXISTS\r\nA001 OK done\r\n"), None);
}

/// LIST and SELECT are raised as `imap_command` offering only their own data answer and the
/// tagged response: offered all thirteen actions, llama3.1:8b answered LIST with a bare tagged
/// OK in 6 of 8 replays of one captured prompt; offered these two, 0 of 8.
#[test]
fn list_and_select_offer_their_own_answer_and_the_tagged_response() {
    use netget::server::imap::actions::{command_event, IMAP_COMMAND_EVENT};
    let names = |command: &str| -> Vec<String> {
        command_event(command)
            .actions
            .iter()
            .map(|a| a.name.clone())
            .collect()
    };
    for (command, answer) in [
        ("LIST", "send_imap_list"),
        ("lsub", "send_imap_list"),
        ("SELECT", "send_imap_select"),
        ("Examine", "send_imap_select"),
    ] {
        assert_eq!(command_event(command).id, "imap_command");
        assert_eq!(
            names(command),
            vec![answer, "send_imap_response"],
            "{command}"
        );
    }
    assert!(!command_event("LIST").description.contains("LOGIN"));
    assert_eq!(
        names("FETCH").len(),
        IMAP_COMMAND_EVENT.actions.len(),
        "a command with no narrowed event gets the declared one"
    );
}
