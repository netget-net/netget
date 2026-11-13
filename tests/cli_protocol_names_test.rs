//! `--server` / `--client` and MCP's `start_server` / `start_client` resolve a protocol name
//! the same way.
//!
//! MCP took a name exactly (`resolve_name`); `--server` ran the free-text parser, so
//! `netget --server "a tcp server"` started TCP and a keyword several protocols declare started
//! whichever matched first. Both now accept the canonical name, or a stack name or keyword only
//! one protocol declares; a keyword several declare is refused with their names, free text with
//! suggestions. Nothing starts on a guess.
//!
//! The shared keyword is found in the registry rather than written down, so the test follows
//! the protocols' own declarations.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test cli_protocol_names_test

#[path = "helpers/child_guard.rs"]
mod child_guard;

use netget::protocol::name_match::{lookup_among, normalize, NameLookup, NameMatch};
use netget::protocol::server_registry::{registry, ProtocolLookupError};
use std::collections::BTreeMap;
use std::process::{Command, Stdio};
use std::time::Duration;

/// A keyword two or more server protocols declare that is no protocol's own name or stack
/// name, with the canonical names of the protocols declaring it.
fn shared_server_keyword() -> (String, Vec<String>) {
    let protocols = registry().all_protocols();
    let names: Vec<String> = protocols
        .iter()
        .flat_map(|(_, p)| [normalize(p.protocol_name()), normalize(p.stack_name())])
        .collect();
    let mut by_keyword: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (_, p) in &protocols {
        for keyword in p.keywords() {
            let entry = by_keyword.entry(normalize(keyword)).or_default();
            if !entry.iter().any(|n| n == p.protocol_name()) {
                entry.push(p.protocol_name().to_string());
            }
        }
    }
    by_keyword
        .into_iter()
        .filter(|(k, owners)| owners.len() > 1 && !names.contains(k) && !k.contains(['/', '>']))
        .map(|(k, mut owners)| {
            owners.sort();
            (k, owners)
        })
        .next()
        .expect("some keyword is declared by more than one server protocol")
}

#[test]
fn lookup_refuses_a_shared_keyword_and_prefers_a_canonical_name() {
    let protocols = || {
        vec![
            ("FTP", "FTP", "ETH>IP>TCP>FTP", vec!["file transfer"]),
            ("TCP", "TCP", "ETH>IP>TCP", vec!["ftp", "raw"]),
            ("UDP", "UDP", "ETH>IP>UDP", vec!["raw"]),
        ]
    };
    // A canonical name wins over another protocol's identical keyword.
    assert_eq!(
        lookup_among(&normalize("ftp"), protocols()),
        NameLookup::Found("FTP".into(), NameMatch::Canonical)
    );
    // A keyword one protocol declares names it.
    assert_eq!(
        lookup_among(&normalize("File-Transfer"), protocols()),
        NameLookup::Found("FTP".into(), NameMatch::Alias("file transfer".into()))
    );
    // A keyword two declare names neither.
    assert_eq!(
        lookup_among(&normalize("raw"), protocols()),
        NameLookup::Ambiguous(vec!["TCP".into(), "UDP".into()])
    );
}

#[test]
fn the_registry_refuses_a_keyword_several_protocols_share() {
    let (keyword, owners) = shared_server_keyword();
    match registry().resolve_name(&keyword) {
        Err(ProtocolLookupError::Ambiguous { candidates, .. }) => {
            assert_eq!(candidates, owners, "{keyword:?}");
        }
        Err(other) => panic!("{keyword:?}: expected an ambiguity, got: {other}"),
        Ok((p, how)) => panic!(
            "{keyword:?} is declared by {owners:?} but resolved to {} ({how:?})",
            p.protocol_name()
        ),
    }
}

/// Run `netget` with `args` and a closed model endpoint; it must exit non-zero within the
/// deadline. Returns stderr.
fn refused(args: &[&str]) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_netget"))
        .args(args)
        .args(["--ollama-url", "http://127.0.0.1:1", "--run-for", "5"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn netget");
    child_guard::tie_child(child.id());
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("netget {args:?} did not exit");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    child_guard::untie_child(child.id());
    let mut stderr = String::new();
    use std::io::Read;
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        !status.success(),
        "netget {args:?} must refuse, not start: {stderr}"
    );
    stderr
}

/// Handlers that answer every event, so a server that *did* start would run without a model
/// and exit 0 when `--run-for` ends — the failure this test exists to catch.
fn answer_everything() -> String {
    serde_json::json!([{"event_pattern": "*", "handler": {"type": "static", "actions": []}}])
        .to_string()
}

#[test]
fn server_refuses_free_text_and_a_shared_keyword_as_mcp_does() {
    let handlers = answer_everything();

    let stderr = refused(&[
        "--server",
        "a tcp server",
        "--port",
        "0",
        "--server-handlers",
        &handlers,
    ]);
    assert!(
        stderr.contains("Unknown protocol: 'a tcp server'") && stderr.contains("'tcp'"),
        "free text is refused with the protocol it mentions as a suggestion: {stderr}"
    );

    let (keyword, owners) = shared_server_keyword();
    let stderr = refused(&[
        "--server",
        &keyword,
        "--port",
        "0",
        "--server-handlers",
        &handlers,
    ]);
    assert!(
        stderr.contains("names more than one protocol"),
        "{keyword:?}: {stderr}"
    );
    for owner in &owners {
        assert!(
            stderr.contains(&format!("'{owner}'")),
            "{owner} listed: {stderr}"
        );
    }
}

#[test]
fn client_refuses_free_text_as_mcp_does() {
    let stderr = refused(&[
        "--client",
        "a tcp client",
        "--connect",
        "127.0.0.1:1",
        "--client-handlers",
        &answer_everything(),
    ]);
    assert!(
        stderr.contains("Unknown client protocol: 'a tcp client'") && stderr.contains("'tcp'"),
        "{stderr}"
    );
}

#[cfg(feature = "mcp-stdio")]
#[tokio::test]
async fn mcp_start_server_refuses_the_same_shared_keyword() {
    use clap::Parser;
    use rmcp::model::CallToolRequestParams;
    use rmcp::{serve_client, ServiceExt};

    let args = netget::cli::Args::parse_from(["netget", "--ollama-url", "http://127.0.0.1:1"]);
    let service = netget::mcp_stdio::tools::NetGetMcpService::new(
        &args,
        netget::settings::Settings::default(),
    )
    .await
    .expect("service");
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        if let Ok(server) = service.serve(server_io).await {
            let _ = server.waiting().await;
        }
    });
    let client = serve_client((), client_io).await.expect("handshake");

    let (keyword, owners) = shared_server_keyword();
    let mut params = CallToolRequestParams::new("start_server");
    params.arguments = serde_json::json!({"protocol": keyword, "port": 0})
        .as_object()
        .cloned();
    let result = client.call_tool(params).await.expect("call");
    let text: String = result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
        .collect();
    assert_eq!(result.is_error, Some(true), "{text}");
    assert!(text.contains("names more than one protocol"), "{text}");
    for owner in &owners {
        assert!(text.contains(&format!("'{owner}'")), "{owner}: {text}");
    }
    client.cancel().await.expect("shutdown");
}
