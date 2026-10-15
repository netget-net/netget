//! What an IRC client gets when the LLM backend fails: numeric 400, then a closed link.
//!
//! IRC has no per-command acknowledgement, so silence is not merely a delay: a client that has
//! sent NICK/USER waits for numeric 001 and has no timeout short of its own connection
//! timeout. Numeric 400 (`ERR_UNKNOWNERROR`) is the code reserved for an error with no more
//! specific numeric, and it carries the offending command as a parameter.
//!
//! It is deliberately not 421 (`ERR_UNKNOWNCOMMAND`), which would tell the client the command
//! does not exist, and it is deliberately not any registration numeric - a client cannot
//! mistake 400 for a completed registration. A non-transient failure is followed by `ERROR`
//! and a close, which is IRC's own way of saying "this link is over, here is why" and is what
//! unblocks a client mid-registration.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> E2EResult<String> {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(20), reader.read_line(&mut line))
        .await
        .map_err(|_| {
            "No IRC response within 20s - the server went silent on LLM failure, which is the \
             exact defect this test exists to catch"
        })??;
    if n == 0 {
        return Err("IRC connection closed without a response".into());
    }
    Ok(line)
}

#[tokio::test]
async fn test_irc_answers_numeric_400_when_llm_fails() -> E2EResult<()> {
    let prompt = "listen on port {AVAILABLE_PORT} via irc. Welcome clients that register";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via irc")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "IRC",
                    "instruction": "Welcome clients that register"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `irc_message_received`, so every line the client sends fails.
    });

    let server = start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half.write_all(b"NICK tester\r\n").await?;
    write_half.flush().await?;

    let reply = read_line(&mut reader).await?;
    println!("IRC reply: {}", reply.trim());

    // ":netget 400 * NICK :netget: ..." - prefix, numeric, target, command, trailing.
    let params: Vec<&str> = reply.trim().split(' ').collect();
    assert!(
        params.len() >= 4,
        "a numeric needs prefix, code, target and the offending command: {reply}"
    );
    assert_eq!(
        params[1], "400",
        "expected ERR_UNKNOWNERROR (400), got: {reply}"
    );
    assert_eq!(
        params[3], "NICK",
        "the numeric must echo the command it is refusing: {reply}"
    );
    assert!(
        !reply.contains(" 001 "),
        "a backend failure must never complete registration: {reply}"
    );
    assert!(
        reply.contains("netget"),
        "the trailing text should name the source of the failure: {reply}"
    );

    // A non-transient failure closes the link with ERROR rather than leaving a half-usable
    // session that will never answer anything.
    let error_line = read_line(&mut reader).await?;
    println!("IRC follow-up: {}", error_line.trim());
    assert!(
        error_line.starts_with("ERROR "),
        "expected ERROR before the close, got: {error_line}"
    );

    let mut trailing = String::new();
    let n = tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut trailing))
        .await
        .map_err(|_| "the server did not close the link after ERROR")??;
    assert_eq!(n, 0, "expected EOF after ERROR, got: {trailing}");

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
