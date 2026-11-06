//! What an MCP caller can find out without leaving NetGet:
//!
//! - `list_protocols { query, layer, limit }` — searching the ~250-line listing, with the
//!   layer derived from each protocol's stack and search-only aliases from its metadata
//!   ("raw ip packet" finds `datalink`, the only client that injects arbitrary frames);
//! - `client_status` / `server_status` — the event handlers, counters and recent events,
//!   and no synthesized instruction shown as though the operator had written it;
//! - `list_access_logs { client_id | server_id, since_id }` — one instance's events;
//! - `list_local_listeners` — the host's listening sockets, NetGet's own servers named.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features mcp-stdio,sqlite \
//!       --test mcp_observability_test -- --test-threads=100

#![cfg(feature = "mcp-stdio")]

use std::time::Duration;

use clap::Parser;
use netget::cli::Args;
use netget::mcp_stdio::protocol_search::{
    layer_of_stack, match_query, query_terms, Layer, Searchable,
};
use netget::mcp_stdio::tools::NetGetMcpService;
use netget::settings::Settings;
use netget::state::app_state::{AccessLogOwner, AppState};
use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::{serve_client, RoleClient, ServiceExt};

type Client = rmcp::service::RunningService<RoleClient, ()>;

async fn connect() -> (Client, AppState) {
    let args = Args::parse_from(["netget"]);
    let service = NetGetMcpService::new(&args, Settings::default())
        .await
        .expect("service creation");
    let app_state = service.app_state();
    let (server_io, client_io) = tokio::io::duplex(256 * 1024);
    tokio::spawn(async move {
        if let Ok(server) = service.serve(server_io).await {
            let _ = server.waiting().await;
        }
    });
    (
        serve_client((), client_io).await.expect("client handshake"),
        app_state,
    )
}

async fn call(client: &Client, name: &'static str, args: serde_json::Value) -> CallToolResult {
    let mut params = CallToolRequestParams::new(name);
    params.arguments = args.as_object().cloned();
    client.call_tool(params).await.expect("call tool")
}

fn text_of(result: &CallToolResult) -> String {
    result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
        .collect()
}

fn number_after(text: &str, marker: &str) -> u64 {
    let idx = text
        .find(marker)
        .unwrap_or_else(|| panic!("marker {marker:?} not found in: {text}"));
    text[idx + marker.len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("no number after {marker:?} in: {text}"))
}

/// The `- **name**` lines of one section of a `list_protocols` result.
fn listed(text: &str, section: &str) -> Vec<String> {
    let start = text
        .find(section)
        .unwrap_or_else(|| panic!("no {section:?} in: {text}"));
    let rest = &text[start + section.len()..];
    let end = rest.find("\n## ").unwrap_or(rest.len());
    rest[..end]
        .lines()
        .filter_map(|l| l.strip_prefix("- **"))
        .filter_map(|l| l.split("**").next())
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------------------------
// list_protocols
// ---------------------------------------------------------------------------------------

/// Whether this build compiles the libpcap protocols (`datalink`, `arp`): the `libpcap`
/// feature, on by default and off in the `--no-default-features` MCP build.
fn has_pcap_protocols() -> bool {
    netget::protocol::CLIENT_REGISTRY
        .list_protocols()
        .iter()
        .any(|n| n.eq_ignore_ascii_case("datalink"))
}

#[test]
fn layer_is_derived_from_the_stack_name() {
    for (stack, layer) in [
        ("ETH>IP>TCP>HTTP", Layer::App),
        ("ETH>IP>UDP>DNS", Layer::App),
        ("ETH>IP>UDP|TCP>GELF", Layer::App),
        ("ETH>IP>TCP", Layer::L4),
        ("ETH>IP>UDP", Layer::L4),
        ("IP>ICMP", Layer::L3),
        ("ETH>IP(89)>OSPF", Layer::L3),
        ("TUN/TAP>IP", Layer::L3),
        ("ETH", Layer::L2),
        ("ETH>ARP", Layer::L2),
        ("ETH>LLC/SNAP>IS-IS", Layer::L2),
        ("USB>HID>Keyboard", Layer::Other),
        ("BLE>GATT", Layer::Other),
        ("UNIX_SOCKET", Layer::Other),
    ] {
        assert_eq!(layer_of_stack(stack), layer, "{stack}");
    }
    for (text, layer) in [
        ("l2", Layer::L2),
        ("Layer 2", Layer::L2),
        ("ethernet", Layer::L2),
        ("L3", Layer::L3),
        ("transport", Layer::L4),
        ("l7", Layer::App),
        ("app", Layer::App),
        ("other", Layer::Other),
    ] {
        assert_eq!(Layer::parse(text), Some(layer), "{text}");
    }
    assert_eq!(Layer::parse("l9"), None);
}

#[test]
fn query_words_match_whole_words_not_fragments() {
    let pipe = Searchable {
        name: "named_pipe",
        keywords: vec!["named pipe"],
        stack: "NAMED_PIPE",
        prose: vec!["A Windows-style pipe, zipped"],
        ..Default::default()
    };
    assert_eq!(match_query(&query_terms("ip"), &pipe), None);

    let mysql = Searchable {
        name: "mysql",
        stack: "ETH>IP>TCP>MySQL",
        prose: vec!["MySQL server"],
        ..Default::default()
    };
    // Three letters or more also match inside the name.
    let found = match_query(&query_terms("sql"), &mysql).expect("sql finds mysql");
    assert_eq!(found.matched, vec!["sql".to_string()]);
    // Plural and case are ignored.
    let frames = Searchable {
        name: "datalink",
        stack: "ETH",
        ..Default::default()
    };
    assert!(match_query(&query_terms("Ethernet FRAMES"), &frames).is_some());
}

#[tokio::test]
async fn list_protocols_query_finds_the_raw_frame_client() {
    if !has_pcap_protocols() {
        eprintln!("datalink is not in this build (no `libpcap` feature); nothing to search for");
        return;
    }
    let (client, _state) = connect().await;

    // The words from the session that could not find it.
    for query in ["IP raw packet", "ip", "raw", "packet", "ethernet", "frame"] {
        let result = call(
            &client,
            "list_protocols",
            serde_json::json!({"type": "client", "include_disabled": true, "query": query}),
        )
        .await;
        let text = text_of(&result);
        assert_ne!(result.is_error, Some(true), "{text}");
        let names = listed(&text, "## Client Protocols");
        assert!(
            names.iter().any(|n| n.eq_ignore_ascii_case("datalink")),
            "query {query:?} should surface datalink: {text}"
        );
        assert!(text.contains("Showing "), "{text}");
        assert!(text.contains(" in total"), "{text}");
    }

    // The full phrase ranks it first: it is the only client every word names.
    let text = text_of(
        &call(
            &client,
            "list_protocols",
            serde_json::json!({"type": "client", "include_disabled": true, "query": "raw ip packet injection"}),
        )
        .await,
    );
    let names = listed(&text, "## Client Protocols");
    assert!(
        names
            .first()
            .is_some_and(|n| n.eq_ignore_ascii_case("datalink")),
        "datalink should rank first: {text}"
    );
    assert!(
        text.contains("· l2 · ETH)"),
        "the line shows layer and stack: {text}"
    );
    assert!(
        text.contains("matched: raw, ip, packet, injection"),
        "{text}"
    );

    client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn list_protocols_layer_and_limit_narrow_the_listing() {
    let (client, _state) = connect().await;

    let full = text_of(&call(&client, "list_protocols", serde_json::json!({})).await);
    // No filter: the listing is unchanged — no summary line, no layer annotations.
    assert!(!full.contains("Showing "), "{full}");
    let all_servers = listed(&full, "## Server Protocols");
    let all_clients = listed(&full, "## Client Protocols");
    assert!(all_servers.len() > 50 && all_clients.len() > 50);

    let l2 = text_of(
        &call(
            &client,
            "list_protocols",
            serde_json::json!({"layer": "l2", "include_disabled": true}),
        )
        .await,
    );
    let l2_servers = listed(&l2, "## Server Protocols");
    let l2_clients = listed(&l2, "## Client Protocols");
    // EtherCAT and PROFINET carry raw Ethernet in every build; ARP and DataLink need libpcap.
    let mut l2_names = vec!["ethercat", "profinet"];
    if has_pcap_protocols() {
        l2_names.extend(["arp", "datalink"]);
        assert!(
            l2_clients
                .iter()
                .any(|n| n.eq_ignore_ascii_case("datalink")),
            "{l2}"
        );
    }
    for name in l2_names {
        assert!(
            l2_servers.iter().any(|n| n.eq_ignore_ascii_case(name)),
            "{name} is an l2 server: {l2}"
        );
    }
    assert!(
        l2_clients
            .iter()
            .any(|n| n.eq_ignore_ascii_case("ethercat")),
        "{l2}"
    );
    assert!(
        !l2_servers.iter().any(|n| n.eq_ignore_ascii_case("http")),
        "http is not l2: {l2}"
    );
    assert!(l2_servers.len() < all_servers.len() / 4, "{l2}");
    assert!(l2.contains("matching layer l2"), "{l2}");

    let l4 = text_of(
        &call(
            &client,
            "list_protocols",
            serde_json::json!({"type": "server", "layer": "transport"}),
        )
        .await,
    );
    let l4_servers = listed(&l4, "## Server Protocols");
    assert!(
        l4_servers.iter().any(|n| n.eq_ignore_ascii_case("tcp")),
        "{l4}"
    );
    assert!(
        !l4_servers.iter().any(|n| n.eq_ignore_ascii_case("dns")),
        "{l4}"
    );

    let limited = text_of(
        &call(
            &client,
            "list_protocols",
            serde_json::json!({"type": "server", "limit": 3}),
        )
        .await,
    );
    assert_eq!(
        listed(&limited, "## Server Protocols").len(),
        3,
        "{limited}"
    );
    assert!(limited.contains("more; raise `limit`"), "{limited}");
    assert!(
        limited.contains(&format!("Showing 3 of {}", all_servers.len())),
        "{limited}"
    );

    let bad = call(
        &client,
        "list_protocols",
        serde_json::json!({"layer": "l9"}),
    )
    .await;
    assert_eq!(bad.is_error, Some(true));
    assert!(
        text_of(&bad).contains("l2, l3, l4, app, other"),
        "{}",
        text_of(&bad)
    );

    let none = text_of(
        &call(
            &client,
            "list_protocols",
            serde_json::json!({"type": "client", "query": "zzqqxx"}),
        )
        .await,
    );
    assert!(none.contains("No match."), "{none}");

    client.cancel().await.expect("shutdown");
}

// ---------------------------------------------------------------------------------------
// client_status / server_status / list_access_logs
// ---------------------------------------------------------------------------------------

async fn wait_for_events(state: &AppState, owner: AccessLogOwner, at_least: u64) {
    for _ in 0..300 {
        if state.access_activity(owner).await.events >= at_least {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "{owner:?} never reached {at_least} events; log: {:#?}",
        state.list_access_logs(None).await
    );
}

#[tokio::test]
async fn client_status_shows_handlers_counters_and_recent_events() {
    let (client, state) = connect().await;

    // A server that greets each connection and then says nothing more.
    let started = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "tcp",
            "port": 0,
            // Only a send_first TCP server raises tcp_connection_opened.
            "send_first": true,
            "event_handlers": [
                {"event_pattern": "tcp_connection_opened", "handler": {"type": "static",
                    "actions": [{"type": "send_tcp_data", "data": "hello\n"}]}},
                {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
            ]
        }),
    )
    .await;
    let started_text = text_of(&started);
    assert_ne!(started.is_error, Some(true), "{started_text}");
    let server_id = number_after(&started_text, "Server #");
    let port = number_after(&started_text, "listening on 127.0.0.1:") as u16;

    // A client given handlers and no instruction: it answers the greeting once.
    let connected = call(
        &client,
        "start_client",
        serde_json::json!({
            "protocol": "tcp",
            "remote_addr": format!("127.0.0.1:{port}"),
            "event_handlers": [
                {"event_pattern": "tcp_data_received", "handler": {"type": "static",
                    "actions": [{"type": "send_tcp_data", "data": "pong\n"}]}},
                {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
            ]
        }),
    )
    .await;
    let connected_text = text_of(&connected);
    assert_ne!(connected.is_error, Some(true), "{connected_text}");
    let client_id = number_after(&connected_text, "Client #");
    let owner = AccessLogOwner::Client(client_id as u32);

    // tcp_connected + the greeting's tcp_data_received.
    wait_for_events(&state, owner, 2).await;
    // The server saw the connection and the pong.
    wait_for_events(&state, AccessLogOwner::Server(server_id as u32), 2).await;

    let status = text_of(
        &call(
            &client,
            "client_status",
            serde_json::json!({"client_id": client_id}),
        )
        .await,
    );
    // No instruction was given, and the status does not pretend one was.
    assert!(
        !status.contains("You are a tcp client connected to"),
        "the synthesized default is not shown as the operator's: {status}"
    );
    assert!(
        status.contains("- **Instruction**: (none given"),
        "{status}"
    );
    // The handlers, in match order.
    assert!(
        status.contains("### Event handlers (first match wins)"),
        "{status}"
    );
    assert!(
        status.contains("1. `tcp_data_received` → static: send_tcp_data"),
        "{status}"
    );
    assert!(
        status.contains("2. `*` → static: answer with nothing"),
        "{status}"
    );
    // Counters, and who answered.
    assert!(
        number_after(&status, "- **Events handled**: ") >= 2,
        "{status}"
    );
    assert!(status.contains("answered by: rule "), "{status}");
    assert!(
        number_after(&status, "- **Actions answered with**: ") >= 1,
        "{status}"
    );
    assert!(status.contains("- **Model calls**: 0 of "), "{status}");
    // The recent events, with what each was answered with, and where to read more.
    assert!(
        status.contains("### Recent events (newest first)"),
        "{status}"
    );
    assert!(
        status.contains("tcp_data_received — ")
            && status.contains("→ send_tcp_data (answered by rule)"),
        "{status}"
    );
    assert!(
        status.contains(&format!("list_access_logs {{\"client_id\": {client_id}}}")),
        "{status}"
    );

    // list_access_logs narrowed to this client: only its entries.
    let logs = text_of(
        &call(
            &client,
            "list_access_logs",
            serde_json::json!({"client_id": client_id}),
        )
        .await,
    );
    assert!(logs.contains(&format!("for client #{client_id}")), "{logs}");
    let lines: Vec<&str> = logs.lines().filter(|l| l.starts_with("- **#")).collect();
    assert!(lines.len() >= 2, "{logs}");
    assert!(
        lines
            .iter()
            .all(|l| l.contains(&format!("client #{client_id} (TCP)"))),
        "{logs}"
    );

    // since_id: nothing after the newest, and the newest after the one before it.
    let newest = state.list_access_logs_for(Some(owner), Some(2)).await;
    let after_newest = text_of(
        &call(
            &client,
            "list_access_logs",
            serde_json::json!({"client_id": client_id, "since_id": newest[0].id}),
        )
        .await,
    );
    assert!(
        after_newest.contains("No entries newer than"),
        "{after_newest}"
    );
    let after_second = text_of(
        &call(
            &client,
            "list_access_logs",
            serde_json::json!({"client_id": client_id, "since_id": newest[1].id}),
        )
        .await,
    );
    assert!(after_second.contains("(1 shown)"), "{after_second}");
    assert!(
        after_second.contains(&format!("**#{}**", newest[0].id)),
        "{after_second}"
    );

    let both = call(
        &client,
        "list_access_logs",
        serde_json::json!({"client_id": client_id, "server_id": server_id}),
    )
    .await;
    assert_eq!(both.is_error, Some(true));

    // The server's status carries the same sections.
    let server_status = text_of(
        &call(
            &client,
            "server_status",
            serde_json::json!({"server_id": server_id}),
        )
        .await,
    );
    assert!(
        server_status.contains("1. `tcp_connection_opened` → static: send_tcp_data"),
        "{server_status}"
    );
    assert!(
        number_after(&server_status, "- **Events handled**: ") >= 2,
        "{server_status}"
    );
    assert!(
        server_status.contains(&format!("list_access_logs {{\"server_id\": {server_id}}}")),
        "{server_status}"
    );

    client.cancel().await.expect("shutdown");
}

#[tokio::test]
async fn an_instruction_given_is_shown_and_no_handlers_says_so() {
    let (client, _state) = connect().await;

    // Something to connect to that never involves the model.
    let started = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "tcp",
            "port": 0,
            "event_handlers": [{"event_pattern": "*", "handler": {"type": "static", "actions": []}}]
        }),
    )
    .await;
    let port = number_after(&text_of(&started), "listening on 127.0.0.1:");
    // The client's model calls fail (no model in tests); its status is all this reads.
    let connected = call(
        &client,
        "start_client",
        serde_json::json!({
            "protocol": "tcp",
            "remote_addr": format!("127.0.0.1:{port}"),
            "instruction": "Say hello and wait."
        }),
    )
    .await;
    let text = text_of(&connected);
    assert_ne!(connected.is_error, Some(true), "{text}");
    let client_id = number_after(&text, "Client #");
    let status = text_of(
        &call(
            &client,
            "client_status",
            serde_json::json!({"client_id": client_id}),
        )
        .await,
    );
    assert!(
        status.contains("- **Instruction**: Say hello and wait.\n"),
        "{status}"
    );
    assert!(
        status.contains("- **Event handlers**: none — every event goes to the model"),
        "{status}"
    );
    client.cancel().await.expect("shutdown");
}

// ---------------------------------------------------------------------------------------
// list_local_listeners
// ---------------------------------------------------------------------------------------

#[tokio::test]
async fn list_local_listeners_names_this_netgets_servers() {
    let (client, _state) = connect().await;

    let started = call(
        &client,
        "start_server",
        serde_json::json!({
            "protocol": "tcp",
            "port": 0,
            "event_handlers": [{"event_pattern": "*", "handler": {"type": "static", "actions": []}}]
        }),
    )
    .await;
    let started_text = text_of(&started);
    assert_ne!(started.is_error, Some(true), "{started_text}");
    let server_id = number_after(&started_text, "Server #");
    let port = number_after(&started_text, "listening on 127.0.0.1:");

    let result = call(
        &client,
        "list_local_listeners",
        serde_json::json!({"port": port}),
    )
    .await;
    let text = text_of(&result);
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        assert_ne!(result.is_error, Some(true), "{text}");
        assert!(
            text.contains(&format!(
                "- TCP 127.0.0.1:{port} — pid {}",
                std::process::id()
            )),
            "our own listener, with our pid: {text}"
        );
        assert!(
            text.contains(&format!("**this NetGet — server #{server_id} (tcp)**")),
            "{text}"
        );
        assert!(text.contains("(1 TCP listening, 0 UDP bound)"), "{text}");

        // Filtered to UDP, the TCP listener is gone.
        let udp = text_of(
            &call(
                &client,
                "list_local_listeners",
                serde_json::json!({"port": port, "transport": "udp"}),
            )
            .await,
        );
        assert!(udp.contains("(0 TCP listening"), "{udp}");

        // The whole table lists at least our listener.
        let all = text_of(&call(&client, "list_local_listeners", serde_json::json!({})).await);
        assert!(all.contains(&format!("127.0.0.1:{port}")), "{all}");
    }

    let bad = call(
        &client,
        "list_local_listeners",
        serde_json::json!({"transport": "sctp"}),
    )
    .await;
    assert_eq!(bad.is_error, Some(true));

    client.cancel().await.expect("shutdown");
}

#[test]
fn listener_labels_distinguish_netget_from_others() {
    use netget::mcp_stdio::local_listeners::{netget_label, LocalListener, RunningServer};
    let me = std::process::id();
    let servers = vec![RunningServer {
        id: 7,
        protocol: "http".into(),
        port: 8080,
    }];
    let ours = LocalListener {
        transport: "tcp",
        addr: "127.0.0.1:8080".parse().unwrap(),
        pid: me,
        process: "netget".into(),
    };
    assert_eq!(
        netget_label(&ours, &servers).as_deref(),
        Some("this NetGet — server #7 (http)")
    );
    let ours_unmatched = LocalListener {
        addr: "127.0.0.1:9999".parse().unwrap(),
        ..ours.clone()
    };
    assert_eq!(
        netget_label(&ours_unmatched, &servers).as_deref(),
        Some("this NetGet process")
    );
    let other_netget = LocalListener {
        pid: me.wrapping_add(1),
        ..ours.clone()
    };
    assert_eq!(
        netget_label(&other_netget, &servers).as_deref(),
        Some("another NetGet process")
    );
    let stranger = LocalListener {
        pid: me.wrapping_add(1),
        process: "postgres".into(),
        ..ours
    };
    assert_eq!(netget_label(&stranger, &servers), None);
}
