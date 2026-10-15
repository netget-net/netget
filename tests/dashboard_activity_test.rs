//! The activity feed: snapshot diffs become exact events, each emitted once;
//! status lines are routed between the feed and the chat.


use netget::state::app_state::AccessLogEntry;
use netget::state::client::ClientStatus;
use netget::state::intercepts::{InterceptOwner, InterceptView};
use netget::state::server::ServerStatus;
use netget::state::{ClientId, ServerId};
use netget::tui::activity::{Activity, ActivityFeed, ActivityKind, Link, Tracker};
use netget::tui::app::UiKey;
use netget::tui::chat::{route_status_line, EntryKind, Routed};
use netget::tui::projection::{ClientRow, ConnRow, RailSnapshot, SendState, ServerRow};
use netget::ui::app::LogLevel;

fn server(id: u32, status: ServerStatus) -> ServerRow {
    ServerRow {
        id: ServerId::new(id),
        protocol: "HTTP".into(),
        port: 8080,
        local_addr: Some("127.0.0.1:8080".into()),
        status,
        instruction: String::new(),
        memory_len: 0,
        startup_params: None,
        routing: None,
        conns: Vec::new(),
        recent: Vec::new(),
        requests: Vec::new(),
        task_count: 0,
        uptime_secs: 0,
        client_counterpart: None,
        request_only: None,
        intercepts: Vec::new(),
    }
}

fn client(id: u32, status: ClientStatus) -> ClientRow {
    ClientRow {
        id: ClientId::new(id),
        protocol: "telnet".into(),
        remote_addr: "127.0.0.1:2323".into(),
        status,
        instruction: String::new(),
        memory_len: 0,
        startup_params: None,
        routing: None,
        connection: None,
        history: Vec::new(),
        requests: Vec::new(),
        task_count: 0,
        uptime_secs: 0,
        send_state: SendState::NotConnected,
        send_actions: Vec::new(),
        intercepts: Vec::new(),
    }
}

fn conn(id: u32, active: bool) -> ConnRow {
    ConnRow {
        id,
        remote_addr: format!("127.0.0.1:{}", 50000 + id),
        bytes_received: 128,
        bytes_sent: 2048,
        active,
        can_message: false,
    }
}

fn entry(id: u64, conn: Option<u32>) -> AccessLogEntry {
    AccessLogEntry {
        id,
        unix_ms: 1_700_000_000_000,
        server_id: Some(1),
        client_id: None,
        protocol: "HTTP".into(),
        connection_id: conn,
        event_type: "http_request".into(),
        request: serde_json::json!({"path": "/"}),
        response: vec![serde_json::json!({"type": "send_http_response"})],
    }
}

fn snap(servers: Vec<ServerRow>, clients: Vec<ClientRow>) -> RailSnapshot {
    RailSnapshot {
        servers,
        clients,
        ..Default::default()
    }
}

fn kinds(events: &[Activity]) -> Vec<ActivityKind> {
    events.iter().map(|e| e.kind).collect()
}

#[test]
fn the_first_snapshot_seeds_silently() {
    let mut tracker = Tracker::default();
    let mut s = server(1, ServerStatus::Running);
    s.requests.push(entry(1, None));
    let events = tracker.diff(&snap(vec![s], vec![client(4, ClientStatus::Connected)]));
    assert!(
        events.is_empty(),
        "a --load backlog is history, not activity: {events:?}"
    );
    // And the same snapshot again says nothing new.
    let mut s = server(1, ServerStatus::Running);
    s.requests.push(entry(1, None));
    let events = tracker.diff(&snap(vec![s], vec![client(4, ClientStatus::Connected)]));
    assert!(events.is_empty());
}

#[test]
fn an_instance_starting_and_changing_status_is_reported_once() {
    let mut tracker = Tracker::default();
    tracker.diff(&RailSnapshot::default());

    let events = tracker.diff(&snap(vec![server(1, ServerStatus::Starting)], Vec::new()));
    assert_eq!(kinds(&events), vec![ActivityKind::Lifecycle]);
    assert_eq!(events[0].tag, "http#1");
    assert!(events[0].text.contains("starting"));
    assert_eq!(
        events[0].link,
        Some(Link::Instance(UiKey::Server(ServerId::new(1))))
    );

    let events = tracker.diff(&snap(vec![server(1, ServerStatus::Running)], Vec::new()));
    assert_eq!(kinds(&events), vec![ActivityKind::Lifecycle]);
    assert!(events[0].text.contains("listening on 127.0.0.1:8080"));

    // Unchanged: quiet.
    assert!(tracker
        .diff(&snap(vec![server(1, ServerStatus::Running)], Vec::new()))
        .is_empty());

    let events = tracker.diff(&snap(
        vec![server(1, ServerStatus::Error("bind failed".into()))],
        Vec::new(),
    ));
    assert_eq!(kinds(&events), vec![ActivityKind::Failure]);
    assert_eq!(
        events[0].text, "bind failed",
        "the feed adds the glyph; the text must not"
    );

    // Gone.
    let events = tracker.diff(&RailSnapshot::default());
    assert_eq!(kinds(&events), vec![ActivityKind::Lifecycle]);
    assert!(events[0].text.contains("stopped"));
}

#[test]
fn a_client_reports_each_status_change_once() {
    let mut tracker = Tracker::default();
    tracker.diff(&RailSnapshot::default());
    let events = tracker.diff(&snap(Vec::new(), vec![client(4, ClientStatus::Connecting)]));
    assert_eq!(kinds(&events), vec![ActivityKind::Lifecycle]);
    assert_eq!(events[0].tag, "telnet#4");
    let events = tracker.diff(&snap(Vec::new(), vec![client(4, ClientStatus::Connected)]));
    assert!(events[0].text.contains("connected to 127.0.0.1:2323"));
    assert!(tracker
        .diff(&snap(Vec::new(), vec![client(4, ClientStatus::Connected)]))
        .is_empty());
    let events = tracker.diff(&snap(
        Vec::new(),
        vec![client(4, ClientStatus::Error("refused".into()))],
    ));
    assert_eq!(kinds(&events), vec![ActivityKind::Failure]);
}

#[test]
fn peers_connecting_and_closing_are_reported_with_their_bytes() {
    let mut tracker = Tracker::default();
    tracker.diff(&snap(vec![server(1, ServerStatus::Running)], Vec::new()));

    let mut s = server(1, ServerStatus::Running);
    s.conns.push(conn(7, true));
    let events = tracker.diff(&snap(vec![s], Vec::new()));
    assert_eq!(kinds(&events), vec![ActivityKind::Peer]);
    assert!(events[0].text.contains("⇐ 127.0.0.1:50007 connected"));

    // Marked closed but still in the map.
    let mut s = server(1, ServerStatus::Running);
    s.conns.push(conn(7, false));
    let events = tracker.diff(&snap(vec![s], Vec::new()));
    assert_eq!(kinds(&events), vec![ActivityKind::Peer]);
    assert!(events[0].text.contains("closed"));
    assert!(events[0].text.contains("↓128"), "{}", events[0].text);
    assert!(events[0].text.contains("↑2.0K"), "{}", events[0].text);

    // Reaped entirely: nothing more to say.
    assert!(tracker
        .diff(&snap(vec![server(1, ServerStatus::Running)], Vec::new()))
        .is_empty());
}

#[test]
fn requests_are_reported_once_in_id_order_with_a_link() {
    let mut tracker = Tracker::default();
    tracker.diff(&snap(vec![server(1, ServerStatus::Running)], Vec::new()));

    let mut s = server(1, ServerStatus::Running);
    s.conns.push(conn(7, true));
    s.requests.push(entry(2, Some(7)));
    s.requests.push(entry(1, None));
    let events = tracker.diff(&snap(vec![s], Vec::new()));
    // The peer connecting, then the two requests in id order.
    assert_eq!(
        kinds(&events),
        vec![
            ActivityKind::Peer,
            ActivityKind::Request,
            ActivityKind::Request
        ]
    );
    assert_eq!(
        events[1].link,
        Some(Link::Request(UiKey::Server(ServerId::new(1)), 1))
    );
    assert_eq!(
        events[2].link,
        Some(Link::Request(UiKey::Server(ServerId::new(1)), 2))
    );
    assert!(events[2].text.starts_with(":50007 "), "{}", events[2].text);
    assert!(events[2].text.contains("http_request → send_http_response"));
    assert!(
        events[1].at_unix_ms.is_some(),
        "a request carries its own time"
    );

    // Same log again: nothing; one newer entry: exactly that one.
    let mut s = server(1, ServerStatus::Running);
    s.conns.push(conn(7, true));
    s.requests.push(entry(1, None));
    s.requests.push(entry(2, Some(7)));
    assert!(tracker.diff(&snap(vec![s.clone()], Vec::new())).is_empty());
    s.requests.push(entry(3, Some(7)));
    let events = tracker.diff(&snap(vec![s], Vec::new()));
    assert_eq!(kinds(&events), vec![ActivityKind::Request]);
    assert_eq!(
        events[0].link,
        Some(Link::Request(UiKey::Server(ServerId::new(1)), 3))
    );
}

#[test]
fn a_parked_request_is_flagged_once_and_links_to_its_answer() {
    let mut tracker = Tracker::default();
    tracker.diff(&snap(vec![server(1, ServerStatus::Running)], Vec::new()));
    let mut s = server(1, ServerStatus::Running);
    s.conns.push(conn(7, true));
    s.intercepts.push(InterceptView {
        id: 42,
        owner: InterceptOwner::Server(ServerId::new(1)),
        connection_id: Some(7),
        event_type: "http_request".into(),
        description: "GET /".into(),
        event_data: None,
        created_unix_ms: 1_700_000_000_000,
        timeout_secs: 300,
    });
    let events = tracker.diff(&snap(vec![s.clone()], Vec::new()));
    assert_eq!(
        kinds(&events),
        vec![ActivityKind::Peer, ActivityKind::Waiting]
    );
    assert!(events[1].text.contains("needs YOUR answer"));
    assert!(events[1].text.contains("from :50007"), "{}", events[1].text);
    assert_eq!(
        events[1].link,
        Some(Link::Intercept(UiKey::Server(ServerId::new(1)), 42))
    );
    assert!(tracker.diff(&snap(vec![s], Vec::new())).is_empty());
}

#[test]
fn status_lines_are_routed_by_prefix() {
    assert_eq!(route_status_line("__UPDATE_UI__"), Routed::Control);
    assert_eq!(
        route_status_line("[INFO] listening"),
        Routed::Activity(LogLevel::Info, "listening".into())
    );
    assert_eq!(
        route_status_line("[ERROR] boom"),
        Routed::Activity(LogLevel::Error, "boom".into())
    );
    assert_eq!(
        route_status_line("[REASONING] thinking"),
        Routed::Chat(EntryKind::Reasoning, "thinking".into())
    );
    assert_eq!(
        route_status_line("✓ Server started"),
        Routed::Chat(EntryKind::System, "✓ Server started".into())
    );
    // Startup chatter tagged by the instance goes to the feed, not the chat.
    assert_eq!(
        route_status_line("[SERVER] Starting server #1 (TCP) on 127.0.0.1:0"),
        Routed::Activity(
            LogLevel::Info,
            "[SERVER] Starting server #1 (TCP) on 127.0.0.1:0".into()
        )
    );
}

#[test]
fn the_feed_filters_log_lines_by_level_but_never_structural_ones() {
    let mut feed = ActivityFeed::new();
    feed.push_log(LogLevel::Debug, "noise".into());
    feed.push(Activity {
        kind: ActivityKind::Request,
        owner: Some(UiKey::Server(ServerId::new(1))),
        tag: "http#1".into(),
        text: "req".into(),
        link: None,
        at_unix_ms: None,
    });
    feed.push(Activity {
        kind: ActivityKind::Lifecycle,
        owner: Some(UiKey::Client(ClientId::new(2))),
        tag: "telnet#2".into(),
        text: "connected".into(),
        link: None,
        at_unix_ms: None,
    });
    let at = |level: LogLevel, only: Option<UiKey>| -> Vec<String> {
        feed.entries
            .iter()
            .filter(|e| ActivityFeed::passes(e, level, only))
            .map(|e| e.event.text.clone())
            .collect()
    };
    assert_eq!(at(LogLevel::Info, None), vec!["req", "connected"]);
    assert_eq!(at(LogLevel::Debug, None), vec!["noise", "req", "connected"]);
    // Narrowed to one instance: its lines plus the global ones.
    assert_eq!(
        at(LogLevel::Debug, Some(UiKey::Server(ServerId::new(1)))),
        vec!["noise", "req"]
    );
}

#[test]
fn a_server_that_appears_with_peers_reports_them_too() {
    let mut tracker = Tracker::default();
    tracker.diff(&RailSnapshot::default());
    let mut s = server(1, ServerStatus::Running);
    s.conns.push(conn(7, true));
    let events = tracker.diff(&snap(vec![s], Vec::new()));
    assert_eq!(
        kinds(&events),
        vec![ActivityKind::Lifecycle, ActivityKind::Peer]
    );
    assert!(events[1].text.contains("127.0.0.1:50007 connected"));
}
