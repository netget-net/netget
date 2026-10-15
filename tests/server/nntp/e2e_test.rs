//! End-to-end tests for NNTP server
//!
//! These tests verify NNTP functionality by spawning real NNTP servers
//! and connecting with real NNTP clients.


use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};

use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// Helper to read NNTP response line
async fn read_response_line(
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
) -> std::io::Result<String> {
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    Ok(line)
}

/// Helper to read multi-line NNTP response (until ".\r\n")
async fn read_multiline_response(
    reader: &mut BufReader<tokio::io::ReadHalf<TcpStream>>,
) -> std::io::Result<Vec<String>> {
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim() == "." {
            break;
        }
        lines.push(line);
    }
    Ok(lines)
}

#[tokio::test]
async fn test_nntp_basic_newsgroups() -> E2EResult<()> {
    // Start NetGet with NNTP server
    let prompt = format!(
        "listen on port {{AVAILABLE_PORT}} via nntp\n\
         Send greeting: \"200 NetGet NNTP Test Server Ready\"\n\
         Support 3 newsgroups:\n\
         - comp.lang.rust (50 articles, numbers 1-50)\n\
         - comp.lang.python (100 articles, numbers 1-100)\n\
         - misc.test (10 articles, numbers 1-10)\n\
         When client sends LIST, show all 3 newsgroups in format: name high low status\n\
         When client sends GROUP comp.lang.rust, respond: 211 50 1 50 comp.lang.rust\n\
         When client sends GROUP comp.lang.python, respond: 211 100 1 100 comp.lang.python\n\
         When client sends GROUP misc.test, respond: 211 10 1 10 misc.test\n\
         When client sends ARTICLE 1 (in any group), send a test article:\n\
         - Code: 220\n\
         - Headers: Subject: Test Article 1, From: test@example.com, Date: Mon, 1 Jan 2024 00:00:00 +0000\n\
         - Body: This is test article number 1.\n\
         When client sends QUIT, send \"205 Goodbye\" and close connection"
    );

    let server_config = NetGetConfig::new(&prompt).with_mock(|mock| {
        mock
            // Mock 0: GREETING (connection established) - MUST BE FIRST
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "GREETING")
            .respond_with_actions(serde_json::json!([
                {"type": "send_nntp_response", "code": 200, "text": "NetGet NNTP Test Server Ready"}
            ]))
            .expect_calls(1)
            .and()
            // Mock 1: LIST command
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "LIST")
            .respond_with_actions(serde_json::json!([
                {"type": "send_nntp_list", "groups": [
                    {"name": "comp.lang.rust", "high": 50, "low": 1, "status": "y"},
                    {"name": "comp.lang.python", "high": 100, "low": 1, "status": "y"},
                    {"name": "misc.test", "high": 10, "low": 1, "status": "y"}
                ]}
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: GROUP command
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "GROUP comp.lang.rust")
            .respond_with_actions(serde_json::json!([
                {"type": "send_nntp_response", "code": 211, "text": "50 1 50 comp.lang.rust"}
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: ARTICLE command
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "ARTICLE 1")
            .respond_with_actions(serde_json::json!([
                {"type": "send_nntp_article", "headers": "Subject: Test Article 1\r\nFrom: test@example.com", "body": "This is test article number 1."}
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: QUIT command
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "QUIT")
            .respond_with_actions(serde_json::json!([
                {"type": "send_nntp_response", "code": 205, "text": "Goodbye"}
            ]))
            .expect_calls(1)
            .and()
            // Mock 5: Server startup - MUST BE LAST (less specific)
            .on_prompt_containing("listen on port")
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "nntp", "instruction": "3 newsgroups"}
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = start_netget_server(server_config).await?;

    // Wait for server to start
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    // Connect to NNTP server
    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // Read greeting
    let greeting =
        tokio::time::timeout(Duration::from_secs(10), read_response_line(&mut reader)).await??;
    assert!(
        greeting.starts_with("200") || greeting.starts_with("201"),
        "Expected 200/201 greeting, got: {}",
        greeting
    );

    // Test LIST command
    write_half.write_all(b"LIST\r\n").await?;
    write_half.flush().await?;

    let list_response =
        tokio::time::timeout(Duration::from_secs(10), read_response_line(&mut reader)).await??;
    assert!(
        list_response.starts_with("215"),
        "Expected 215 list follows, got: {}",
        list_response
    );

    let newsgroups = tokio::time::timeout(
        Duration::from_secs(10),
        read_multiline_response(&mut reader),
    )
    .await??;
    assert!(
        newsgroups.len() >= 3,
        "Expected at least 3 newsgroups, got: {}",
        newsgroups.len()
    );

    // Verify newsgroups contain expected names
    let newsgroups_text = newsgroups.join("");
    assert!(
        newsgroups_text.contains("comp.lang.rust"),
        "Expected comp.lang.rust in newsgroups"
    );
    assert!(
        newsgroups_text.contains("comp.lang.python"),
        "Expected comp.lang.python in newsgroups"
    );
    assert!(
        newsgroups_text.contains("misc.test"),
        "Expected misc.test in newsgroups"
    );

    // Test GROUP command
    write_half.write_all(b"GROUP comp.lang.rust\r\n").await?;
    write_half.flush().await?;

    let group_response =
        tokio::time::timeout(Duration::from_secs(10), read_response_line(&mut reader)).await??;
    assert!(
        group_response.starts_with("211"),
        "Expected 211 group selected, got: {}",
        group_response
    );
    assert!(
        group_response.contains("comp.lang.rust"),
        "Expected group name in response, got: {}",
        group_response
    );

    // Test ARTICLE command
    write_half.write_all(b"ARTICLE 1\r\n").await?;
    write_half.flush().await?;

    let article_response =
        tokio::time::timeout(Duration::from_secs(10), read_response_line(&mut reader)).await??;
    assert!(
        article_response.starts_with("220"),
        "Expected 220 article follows, got: {}",
        article_response
    );

    let article_lines = tokio::time::timeout(
        Duration::from_secs(10),
        read_multiline_response(&mut reader),
    )
    .await??;
    let article_text = article_lines.join("");

    // Verify article has headers
    assert!(
        article_text.contains("Subject:") || article_text.contains("From:"),
        "Expected article headers, got: {}",
        article_text
    );

    // Send QUIT
    write_half.write_all(b"QUIT\r\n").await?;
    write_half.flush().await?;

    let quit_response =
        tokio::time::timeout(Duration::from_secs(10), read_response_line(&mut reader)).await??;
    assert!(
        quit_response.starts_with("205") || quit_response.starts_with("200"),
        "Expected 205 goodbye, got: {}",
        quit_response
    );

    // Cleanup
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_nntp_article_overview() -> E2EResult<()> {
    let prompt = format!(
        "listen on port {{AVAILABLE_PORT}} via nntp\n\
         Send greeting: \"200 NetGet NNTP Ready\"\n\
         Support newsgroup: comp.test\n\
         When client sends LIST, show: comp.test 5 1 y\n\
         When client sends GROUP comp.test, respond: 211 5 1 5 comp.test\n\
         When client sends XOVER 1-5, send overview for 5 articles:\n\
         - Use send_nntp_overview action\n\
         - Articles 1-5 with subjects \"Article 1\" through \"Article 5\"\n\
         - From: test@example.com for all\n\
         - Include message_id, bytes, lines\n\
         When client sends QUIT, send \"205 Goodbye\" and close"
    );

    let server_config = NetGetConfig::new(&prompt).with_mock(|mock| {
        mock
            // Mock 0: GREETING (connection established) - MUST BE FIRST
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "GREETING")
            .respond_with_actions(serde_json::json!([
                {"type": "send_nntp_response", "code": 200, "text": "NetGet NNTP Ready"}
            ]))
            .expect_calls(1)
            .and()
            // Mock 1: GROUP command
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "GROUP comp.test")
            .respond_with_actions(serde_json::json!([
                {"type": "send_nntp_response", "code": 211, "text": "5 1 5 comp.test"}
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: XOVER command
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "XOVER 1-5")
            .respond_with_actions(serde_json::json!([
                {"type": "send_nntp_overview", "articles": [
                    {"number": 1, "subject": "Article 1", "from": "test@example.com", "date": "Mon, 1 Jan 2024 00:00:00 +0000", "message_id": "<1@example.com>", "references": "", "bytes": 100, "lines": 5},
                    {"number": 2, "subject": "Article 2", "from": "test@example.com", "date": "Mon, 1 Jan 2024 00:00:00 +0000", "message_id": "<2@example.com>", "references": "", "bytes": 100, "lines": 5},
                    {"number": 3, "subject": "Article 3", "from": "test@example.com", "date": "Mon, 1 Jan 2024 00:00:00 +0000", "message_id": "<3@example.com>", "references": "", "bytes": 100, "lines": 5},
                    {"number": 4, "subject": "Article 4", "from": "test@example.com", "date": "Mon, 1 Jan 2024 00:00:00 +0000", "message_id": "<4@example.com>", "references": "", "bytes": 100, "lines": 5},
                    {"number": 5, "subject": "Article 5", "from": "test@example.com", "date": "Mon, 1 Jan 2024 00:00:00 +0000", "message_id": "<5@example.com>", "references": "", "bytes": 100, "lines": 5}
                ]}
            ]))
            .expect_calls(1)
            .and()
            // Mock 3: QUIT command
            .on_event("nntp_command_received")
            .and_event_data_contains("command", "QUIT")
            .respond_with_actions(serde_json::json!([
                {"type": "send_nntp_response", "code": 205, "text": "Goodbye"}
            ]))
            .expect_calls(1)
            .and()
            // Mock 4: Server startup - MUST BE LAST (less specific)
            .on_prompt_containing("listen on port")
            .respond_with_actions(serde_json::json!([
                {"type": "open_server", "port": 0, "base_stack": "nntp", "instruction": "comp.test newsgroup"}
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = start_netget_server(server_config).await?;

    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let stream = TcpStream::connect(format!("127.0.0.1:{}", server.port)).await?;
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // Read greeting
    let _greeting =
        tokio::time::timeout(Duration::from_secs(10), read_response_line(&mut reader)).await??;

    // Select group
    write_half.write_all(b"GROUP comp.test\r\n").await?;
    write_half.flush().await?;
    let _group_response =
        tokio::time::timeout(Duration::from_secs(10), read_response_line(&mut reader)).await??;

    // Test XOVER command
    write_half.write_all(b"XOVER 1-5\r\n").await?;
    write_half.flush().await?;

    let xover_response =
        tokio::time::timeout(Duration::from_secs(10), read_response_line(&mut reader)).await??;
    assert!(
        xover_response.starts_with("224"),
        "Expected 224 overview follows, got: {}",
        xover_response
    );

    let overview_lines = tokio::time::timeout(
        Duration::from_secs(10),
        read_multiline_response(&mut reader),
    )
    .await??;
    assert!(
        overview_lines.len() >= 1,
        "Expected at least 1 article in overview, got: {}",
        overview_lines.len()
    );

    // Verify tab-separated format
    let first_article = &overview_lines[0];
    assert!(
        first_article.contains('\t'),
        "Expected tab-separated overview format, got: {}",
        first_article
    );

    // Send QUIT
    write_half.write_all(b"QUIT\r\n").await?;
    write_half.flush().await?;
    let _quit_response =
        tokio::time::timeout(Duration::from_secs(10), read_response_line(&mut reader)).await??;

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
