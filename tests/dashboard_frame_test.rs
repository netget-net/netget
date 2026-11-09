//! The dashboard rendered into ratatui's `TestBackend`: deterministic frames
//! without a pty, so the layout can be asserted on and read.
//!
//! The pty snapshots in `tests/terminal_snapshot/` prove the real binary
//! paints; these prove what it paints, for states a fresh process never
//! reaches in the two seconds a pty test waits (a running server with peers,
//! a client with verbs, a request parked for the human).

use ratatui::backend::TestBackend;
use ratatui::Terminal;

use netget::cli::theme::ColorPalette;
use netget::privilege::SystemCapabilities;
use netget::scripting::event_handler::EventPattern;
use netget::scripting::{EventHandler, EventHandlerConfig, EventHandlerType};
use netget::state::app_state::AccessLogEntry;
use netget::state::client::ClientStatus;
use netget::state::intercepts::{InterceptOwner, InterceptView};
use netget::state::server::ServerStatus;
use netget::state::{ClientId, ServerId};
use netget::tui::app::{DashboardApp, Focus, UiKey};
use netget::tui::cards::{Activate, InstanceAction};
use netget::tui::projection::{ClientRow, ConnRow, RailSnapshot, SendState, SendVerb, ServerRow};
use netget::tui::render;
use netget::tui::theme::Styles;

fn app() -> DashboardApp {
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();
    let (ui_tx, _ui_rx) = tokio::sync::mpsc::unbounded_channel();
    let core = netget::ui::App::new(SystemCapabilities::detect());
    DashboardApp::new(
        core,
        Styles::from_palette(&ColorPalette::dark()),
        status_tx,
        ui_tx,
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
    )
}

fn manual() -> EventHandlerConfig {
    EventHandlerConfig {
        handlers: vec![EventHandler {
            event_pattern: EventPattern::Wildcard,
            data_match: None,
            handler: EventHandlerType::Manual { timeout_secs: 300 },
        }],
    }
}

fn populated() -> RailSnapshot {
    let requests: Vec<AccessLogEntry> = (1..=3)
        .map(|id| AccessLogEntry {
            id,
            unix_ms: 1_700_000_000_000 + id * 1000,
            server_id: Some(1),
            client_id: None,
            protocol: "HTTP".into(),
            connection_id: Some(7),
            event_type: "http_request".into(),
            request: serde_json::json!({"method": "GET", "path": format!("/{id}")}),
            response: vec![serde_json::json!({"type": "send_http_response", "status": 200})],
            answered_by: None,
        })
        .collect();
    let server = ServerRow {
        history_entries: 0,
        batching: false,
        capture: None,
        id: ServerId::new(1),
        protocol: "HTTP".into(),
        port: 8080,
        local_addr: Some("127.0.0.1:8080".into()),
        status: ServerStatus::Running,
        instruction: "Serve a tiny site.".into(),
        memory_len: 0,
        startup_params: None,
        routing: Some(manual()),
        conns: vec![ConnRow {
            id: 7,
            remote_addr: "127.0.0.1:53121".into(),
            bytes_received: 1_234,
            bytes_sent: 45_678,
            active: true,
            can_message: false,
            memory_len: 0,
        }],
        recent: Vec::new(),
        requests,
        task_count: 0,
        uptime_secs: 133,
        client_counterpart: Some("HTTP".into()),
        request_only: None,
        intercepts: vec![InterceptView {
            id: 4,
            owner: InterceptOwner::Server(ServerId::new(1)),
            connection_id: Some(7),
            event_type: "http_request".into(),
            description: "GET /admin".into(),
            event_data: None,
            created_unix_ms: 1_700_000_004_000,
            timeout_secs: 300,
        }],
    };
    let broken = ServerRow {
        history_entries: 0,
        batching: false,
        capture: None,
        id: ServerId::new(2),
        protocol: "DNS".into(),
        port: 53,
        local_addr: None,
        status: ServerStatus::Error("bind 0.0.0.0:53: permission denied".into()),
        instruction: String::new(),
        memory_len: 0,
        startup_params: None,
        routing: None,
        conns: Vec::new(),
        recent: Vec::new(),
        requests: Vec::new(),
        task_count: 0,
        uptime_secs: 3,
        client_counterpart: Some("DNS".into()),
        request_only: None,
        intercepts: Vec::new(),
    };
    let client = ClientRow {
        history_entries: 0,
        batching: false,
        capture: None,
        id: ClientId::new(3),
        protocol: "telnet".into(),
        remote_addr: "127.0.0.1:2323".into(),
        status: ClientStatus::Connected,
        instruction: String::new(),
        memory_len: 0,
        startup_params: None,
        routing: None,
        connection: None,
        history: Vec::new(),
        requests: Vec::new(),
        task_count: 0,
        uptime_secs: 40,
        send_state: SendState::Ready,
        send_actions: vec![
            SendVerb {
                name: "send_command".into(),
                description: "Send a command line and wait for the prompt".into(),
            },
            SendVerb {
                name: "send_text".into(),
                description: "Send raw text".into(),
            },
        ],
        intercepts: Vec::new(),
    };
    RailSnapshot {
        servers: vec![server, broken],
        clients: vec![client],
        ..Default::default()
    }
}

/// Render one frame at `width`×`height` and return it as text lines.
fn frame(app: &mut DashboardApp, width: u16, height: u16) -> Vec<String> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal.draw(|f| render::draw(f, app)).expect("draw");
    let buffer = terminal.backend().buffer().clone();
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect()
}

fn dump(lines: &[String]) -> String {
    lines.join("\n")
}

#[test]
fn generating_indicators_animate_on_cards_chat_and_narrow_footers_then_clear() {
    use netget::server::connection::ConnectionId;
    use netget::state::app_state::ConversationSource;
    use netget::state::llm_activity::LlmActivityTracker;
    let tracker = LlmActivityTracker::default();
    let server = tracker.begin(
        ConversationSource::Network {
            server_id: ServerId::new(1),
            connection_id: Some(ConnectionId::new(7)),
        },
        "GET /answer".into(),
    );
    let user = tracker.begin(ConversationSource::User, "help".into());
    let mut app = app();
    let mut snapshot = populated();
    snapshot.servers[0].intercepts.clear();
    app.absorb_snapshot(snapshot);
    app.tick_llm_activity(tracker.snapshot());
    app.focus_card(UiKey::Server(ServerId::new(1)));

    let first_spinner = app.spinner();
    let first = dump(&frame(&mut app, 140, 46));
    eprintln!("{first}");
    assert!(first.contains(&format!("{first_spinner} #1")), "{first}");
    assert!(
        first.contains(&format!("{first_spinner} LLM generating")),
        "{first}"
    );
    assert!(
        first.contains(&format!("{first_spinner} Generating reply")),
        "{first}"
    );
    assert!(
        first.contains(&format!("{first_spinner} 2 generating")),
        "{first}"
    );
    app.dirty = false;
    app.tick_llm_activity(tracker.snapshot());
    assert!(
        app.dirty,
        "animation must request a repaint without log traffic"
    );
    assert_ne!(app.spinner(), first_spinner);

    for width in [40, 48, 80] {
        let lines = frame(&mut app, width, 24);
        assert!(
            lines.last().unwrap().contains("2 generating"),
            "{}",
            dump(&lines)
        );
        assert!(
            dump(&lines).contains("Generating reply"),
            "{}",
            dump(&lines)
        );
    }
    app.cards
        .state
        .close(&netget::tui::cards::NodeId::Card(UiKey::Server(
            ServerId::new(1),
        )));
    app.focus_card(UiKey::Server(ServerId::new(1)));
    let folded = dump(&frame(&mut app, 80, 24));
    assert!(
        folded.contains(&format!("{} #1", app.spinner())),
        "{folded}"
    );

    drop(server);
    drop(user);
    app.tick_llm_activity(tracker.snapshot());
    let done = dump(&frame(&mut app, 140, 46));
    assert!(
        !done.contains("generating") && !done.contains("Generating reply"),
        "{done}"
    );
    app.dirty = false;
    app.tick_llm_activity(tracker.snapshot());
    assert!(!app.dirty, "idle UI ticks need no animation repaint");
}

#[test]
fn generation_rows_do_not_move_the_selected_send_button() {
    use netget::state::app_state::ConversationSource;
    let mut app = app();
    app.absorb_snapshot(populated());
    let send = InstanceAction::MessagePeer(7);
    app.cards.row = app
        .rows()
        .iter()
        .position(|r| r.buttons.iter().any(|b| b.action == send))
        .unwrap();
    app.cards.col = 0;
    let tracker = netget::state::llm_activity::LlmActivityTracker::default();
    let work = tracker.begin(
        ConversationSource::Network {
            server_id: ServerId::new(1),
            connection_id: Some(netget::server::connection::ConnectionId::new(7)),
        },
        "request".into(),
    );
    app.tick_llm_activity(tracker.snapshot());
    assert_eq!(
        app.rows()[app.cards.row]
            .button_at(app.cards.col)
            .unwrap()
            .action,
        send
    );
    drop(work);
    // A full stats/sentinel refresh can observe completion before the UI tick.
    let mut refreshed = app.snapshot.clone();
    refreshed.llm_activity = tracker.snapshot();
    refreshed.active_conversations = 0;
    app.absorb_snapshot(refreshed);
    assert_eq!(
        app.rows()[app.cards.row]
            .button_at(app.cards.col)
            .unwrap()
            .action,
        send
    );
}

#[test]
fn background_work_has_a_named_indicator_when_the_stream_is_empty() {
    let tracker = netget::state::llm_activity::LlmActivityTracker::default();
    let _work = tracker.begin(
        netget::state::app_state::ConversationSource::Task {
            task_name: "cleanup".into(),
        },
        "summarize".into(),
    );
    let mut app = app();
    app.tick_llm_activity(tracker.snapshot());
    let text = dump(&frame(&mut app, 40, 24));
    assert!(
        text.contains(&format!("{} [Task:cleanup]", app.spinner())),
        "{text}"
    );
    assert!(text.contains("1 generating"), "{text}");
}

#[test]
fn input_keeps_the_cursor_and_end_of_long_multiline_text_visible() {
    use netget::cli::input_state::InputState;
    use ratatui::backend::Backend;
    let mut app = app();
    app.input = InputState::from_lines(
        (0..9)
            .map(|n| format!("{} tail-{n}", "界".repeat(30)))
            .collect(),
    );
    let mut terminal = Terminal::new(TestBackend::new(24, 7)).unwrap();
    terminal
        .draw(|f| {
            let area = f.area();
            render::chat::draw_input(f, &mut app, area);
        })
        .unwrap();
    let cursor = terminal.backend_mut().get_cursor_position().unwrap();
    assert_eq!(
        cursor.y, 5,
        "the ninth line is visible in the five-row input"
    );
    assert!(cursor.x < 23);
    let row: String = (0..24)
        .map(|x| terminal.backend().buffer()[(x, 5)].symbol())
        .collect();
    assert!(
        row.contains("tail-8"),
        "last input line must be visible: {row}"
    );
}

#[test]
fn input_cursor_uses_terminal_cells_for_wide_and_combining_text() {
    use netget::cli::input_state::InputState;
    use ratatui::backend::Backend;
    let mut app = app();
    app.input = InputState::from_lines(vec!["界e\u{301}".into()]);
    let mut terminal = Terminal::new(TestBackend::new(24, 3)).unwrap();
    terminal
        .draw(|f| {
            let area = f.area();
            render::chat::draw_input(f, &mut app, area);
        })
        .unwrap();
    let cursor = terminal.backend_mut().get_cursor_position().unwrap();
    assert_eq!((cursor.x, cursor.y), (6, 1));
}

#[test]
fn opening_the_text_editor_preserves_trailing_newlines() {
    use netget::tui::modal::text_editor::TextEditorModel;
    for initial in ["command\n", "command\n\n", "\n", "", "a\r\nb\n"] {
        let mut editor = TextEditorModel::new("text", "", initial, false);
        assert_eq!(editor.accept().as_deref(), Some(initial));
    }
}

#[test]
fn conversation_wrapping_preserves_every_wide_grapheme() {
    let mut app = app();
    app.push_system("界".repeat(30));
    let lines = frame(&mut app, 40, 30);
    let count = dump(&lines).chars().filter(|c| *c == '界').count();
    assert_eq!(count, 30, "wide glyphs must wrap before they are clipped");
}

#[test]
fn an_empty_dashboard_says_what_to_do_at_the_minimum_size() {
    let mut app = app();
    app.push_system("NetGet — a starts a server or client");
    app.absorb_snapshot(RailSnapshot::default());
    let lines = frame(&mut app, 80, 24);
    let text = dump(&lines);
    println!("{text}");
    assert!(text.contains("SERVERS 0 · CLIENTS 0"));
    assert!(text.contains("+ new server or client"));
    assert!(text.contains("ACTIVITY & CHAT"));
    assert!(text.contains("a starts a server or client"));
    assert!(
        text.contains("F1 keys"),
        "the status bar keeps its help hint at 80 columns"
    );
    assert!(!text.contains("╭ CHAT"), "one stream, not two panes");
    assert!(lines.iter().all(|l| l.chars().count() <= 80));
}

#[test]
fn a_populated_dashboard_shows_every_instance_with_its_buttons_and_sections() {
    let mut app = app();
    // The first snapshot only seeds the stream; the second is the change.
    app.absorb_snapshot(RailSnapshot::default());
    app.absorb_snapshot(populated());
    app.sample_metrics();
    app.snapshot.servers[0].conns[0].bytes_sent += 5_000;
    app.sample_metrics();
    app.focus = Focus::Cards;

    // Tall enough for all three cards with their sections open.
    let lines = frame(&mut app, 120, 60);
    let text = dump(&lines);
    println!("{text}");

    // Every instance is there, with its summary line.
    let http = lines
        .iter()
        .find(|l| l.contains("#1") && l.contains("http"))
        .expect("http row");
    assert!(http.contains("●"), "{http}");
    assert!(http.contains(":8080"), "{http}");
    assert!(http.contains("1⇄"), "{http}");
    assert!(
        http.contains("⚠1"),
        "the parked request is flagged on the row: {http}"
    );
    assert!(http.contains("MANUAL"), "{http}");
    let dns = lines
        .iter()
        .find(|l| l.contains("#2") && l.contains("dns"))
        .expect("dns row");
    assert!(dns.contains("✗"), "{dns}");
    assert!(dns.contains("permission denied"), "{dns}");
    let telnet = lines
        .iter()
        .find(|l| l.contains("#3") && l.contains("telnet"))
        .expect("telnet row");
    assert!(telnet.contains("→127.0.0.1:2323"), "{telnet}");

    // Without selecting anything: the question, the buttons, the peer, its
    // request, and the client's verbs are all on screen.
    assert!(text.contains("YOUR answer needed · http_request from :53121"));
    assert!(text.contains("[ stop"), "{text}");
    assert!(text.contains("[ driver → LLM"), "{text}");
    assert!(text.contains("127.0.0.1:53121"), "the peer");
    assert!(
        text.contains("http_request → send_http_response"),
        "its request"
    );
    assert!(text.contains("send_command"), "the client's verbs");
    assert!(text.contains("up 2m13s"));
    assert!(text.contains("↓1.2K ↑50.7K"), "{text}");

    // The stream got the diff: the instances, the peer, the question.
    assert!(text.contains("listening on 127.0.0.1:8080"));
    assert!(text.contains("⇐ 127.0.0.1:53121 connected"));
    assert!(text.contains("http_request from :53121 needs YOUR"));
    assert!(
        text.contains("1 waiting for you"),
        "the status bar counts it too"
    );
    assert!(
        lines.last().unwrap().ends_with("F1 keys"),
        "{}",
        lines.last().unwrap()
    );
    assert!(lines.iter().all(|l| l.chars().count() <= 120));
}

#[test]
fn every_section_renders_unfolded_at_the_minimum_size() {
    use netget::tui::cards::{Group, NodeId};
    let mut app = app();
    app.absorb_snapshot(populated());
    for key in [
        UiKey::Server(ServerId::new(1)),
        UiKey::Client(ClientId::new(3)),
    ] {
        for group in [
            Group::Peers,
            Group::Connections,
            Group::Send,
            Group::Rules,
            Group::Config,
        ] {
            app.cards.state.open(&NodeId::Group(key, group));
        }
    }
    app.focus = Focus::Cards;
    let rows = app.rows();
    // Walk the whole column: every stop renders within the width.
    for (index, row) in rows.iter().enumerate() {
        if row.positions() == 0 {
            continue;
        }
        app.cards.row = index;
        app.cards.col = row.positions() - 1;
        let lines = frame(&mut app, 80, 24);
        assert!(lines.iter().all(|l| l.chars().count() <= 80), "row {index}");
    }
    let text = dump(&frame(&mut app, 100, 60));
    println!("{text}");
    assert!(text.contains("[ delete"), "rule rows carry their buttons");
    assert!(text.contains("[ + add rule"), "{text}");
    assert!(text.contains("instruction"), "config rows");
    assert!(text.contains("Send a command line"), "verbs");
}

#[test]
fn the_cursor_survives_its_card_vanishing() {
    let mut app = app();
    app.absorb_snapshot(populated());
    app.focus = Focus::Cards;
    app.focus_card(UiKey::Server(ServerId::new(1)));
    assert_eq!(app.cursor_key(), Some(UiKey::Server(ServerId::new(1))));
    let mut without_first = populated();
    without_first.servers.remove(0);
    app.absorb_snapshot(without_first);
    assert!(
        app.cursor_key().is_some(),
        "the cursor lands on whatever now sits there"
    );
    let _ = frame(&mut app, 80, 24);

    // Everything gone: the cursor sits on + new server or client.
    app.absorb_snapshot(RailSnapshot::default());
    let rows = app.rows();
    assert_eq!(rows[app.cards.row].on_enter, Activate::NewInstance);
    let text = dump(&frame(&mut app, 80, 24));
    assert!(text.contains("+ new server or client"));
}

#[test]
fn the_stream_keeps_its_newest_line_visible_when_older_ones_wrap() {
    let mut app = app();
    app.absorb_snapshot(RailSnapshot::default());
    for i in 0..12 {
        app.push_system(format!(
            "line {i}: a sentence long enough to wrap twice inside a forty column pane, easily"
        ));
    }
    app.push_system("THE NEWEST LINE");
    let text = dump(&frame(&mut app, 80, 24));
    println!("{text}");
    assert!(
        text.contains("THE NEWEST LINE"),
        "the tail must be visible while following:\n{text}"
    );
}

#[test]
fn an_instance_that_just_appeared_gets_the_cursor() {
    let mut app = app();
    app.focus = Focus::Cards;
    app.absorb_snapshot(RailSnapshot::default());
    app.absorb_snapshot(populated());
    assert_eq!(
        app.cursor_key(),
        Some(UiKey::Client(ClientId::new(3))),
        "the newest arrival"
    );
    let rows = app.rows();
    assert!(
        rows[app.cards.row].header.is_some(),
        "on its header, buttons one ↓ away"
    );
}

#[test]
fn the_stream_holds_the_conversation_and_the_activity_together() {
    let mut app = app();
    app.absorb_snapshot(RailSnapshot::default());
    app.push_chat(netget::tui::chat::EntryKind::User, "start an http server");
    app.absorb_snapshot(populated());
    app.push_system("Started server #1 (http)");
    let lines = frame(&mut app, 100, 30);
    let text = dump(&lines);
    println!("{text}");
    assert!(text.contains("ACTIVITY & CHAT"));
    let asked = lines
        .iter()
        .position(|l| l.contains("▶ start an http server"))
        .expect("what was typed");
    let listening = lines
        .iter()
        .position(|l| l.contains("listening on 127.0.0.1:8080"))
        .expect("what happened");
    let answered = lines
        .iter()
        .position(|l| l.contains("Started server #1 (http)"))
        .expect("what came back");
    assert!(
        asked < listening && listening < answered,
        "one timeline, in order"
    );
}

#[test]
fn the_button_grid_walks_with_the_arrows() {
    let mut app = app();
    app.absorb_snapshot(populated());
    app.focus = Focus::Cards;
    app.focus_card(UiKey::Server(ServerId::new(1)));
    let rows = app.rows();
    let header = app.cards.row;
    let first_buttons = (header..rows.len())
        .find(|i| !rows[*i].buttons.is_empty())
        .expect("a button row");
    let row = &rows[first_buttons];
    assert!(row.spans.is_empty(), "a grid row is buttons only");
    assert_eq!(
        row.button_at(0).map(|b| b.action),
        Some(InstanceAction::Stop)
    );
    assert_eq!(row.positions(), row.buttons.len());
    app.cards.row = first_buttons;
    app.cards.col = 1;
    let lines = frame(&mut app, 80, 24);
    assert!(lines.iter().all(|l| l.chars().count() <= 80));
    assert!(dump(&lines).contains("[ edit"));
}

/// Open the picker filtered to `filter`, as `a` then typing would, with the given capabilities.
fn picker_frame(filter: &str, caps: &SystemCapabilities) -> String {
    let mut app = app();
    app.absorb_snapshot(RailSnapshot::default());
    app.modals.push(netget::tui::modal::Modal::ProtocolPicker {
        entries: netget::tui::modal::protocol_picker::all_entries(caps),
        filter: filter.to_string(),
        selected: 0,
        prefill_remote: None,
    });
    let text = dump(&frame(&mut app, 120, 40));
    println!("{text}");
    text
}

/// The picker names the port a server will start on, and it is the protocol's registered one.
#[test]
fn the_picker_shows_the_well_known_port() {
    let text = picker_frame("redis", &SystemCapabilities::detect());
    // Whether 6379 is free on this machine decides the rest of the line; the number is shown
    // either way.
    assert!(
        text.contains("well-known port 6379"),
        "the redis server entry must name its well-known port"
    );
}

/// Below 1024 without privilege, the picker says why the server will not take the port.
#[test]
fn the_picker_says_why_a_privileged_well_known_port_is_not_used() {
    let mut caps = SystemCapabilities::detect();
    caps.can_bind_privileged_ports = false;
    let text = picker_frame("dns", &caps);
    assert!(
        text.contains("well-known port 53 needs root"),
        "the dns entry must say it cannot take 53 and why"
    );
}

/// The `[ send message ]` under a live peer whose protocol registered no peer handle: still
/// there, disabled, and saying *why* — which depends on the protocol. HTTP declares
/// `request_only`, so it gives the protocol's own reason and no "yet"; a protocol that could
/// message a peer but has no path for it here says it is not implemented yet.
#[test]
fn a_peer_that_cannot_be_messaged_says_why_in_the_protocols_own_terms() {
    use netget::tui::cards::NO_PEER_HANDLE_REASON;

    let http_reason = netget::protocol::server_registry::registry()
        .request_only_reason("HTTP")
        .expect("HTTP declares request_only in its metadata");
    assert!(
        http_reason.contains("only answers requests") && !http_reason.contains("yet"),
        "{http_reason}"
    );
    assert_eq!(
        netget::protocol::server_registry::registry().request_only_reason("TCP"),
        None,
        "TCP can message a peer; it declares nothing"
    );

    let send_reason = |request_only: Option<String>| {
        let mut snap = populated();
        snap.servers[0].request_only = request_only;
        let mut app = app();
        app.absorb_snapshot(snap);
        app.focus = Focus::Cards;
        let text = dump(&frame(&mut app, 120, 60));
        assert!(
            text.contains("[ send message"),
            "the button stays on screen:\n{text}"
        );
        let rows = app.rows();
        let button = rows
            .iter()
            .flat_map(|r| r.buttons.iter())
            .find(|b| b.action == InstanceAction::MessagePeer(7))
            .expect("the peer's send button");
        assert!(!button.enabled);
        button
            .why_disabled
            .clone()
            .expect("a disabled button says why")
    };

    assert_eq!(send_reason(Some(http_reason.to_string())), http_reason);
    let other = send_reason(None);
    assert_eq!(other, NO_PEER_HANDLE_REASON);
    assert!(other.contains("not implemented here yet"), "{other}");
}

/// Narrower than 80 columns the two columns stack: the canvas on top, the stream and the input
/// box beneath it, each the full width. The browser demo sizes its terminal on a phone to a
/// readable font (about 40–48 columns) rather than to 80 columns of 6px text, so this is the
/// layout a phone visitor sees.
#[test]
fn a_narrow_terminal_stacks_the_canvas_over_the_stream() {
    for (width, height) in [(40u16, 34u16), (48, 34), (60, 30), (79, 24)] {
        let mut app = app();
        app.absorb_snapshot(RailSnapshot::default());
        app.absorb_snapshot(populated());
        app.sample_metrics();
        let lines = frame(&mut app, width, height);
        let text = dump(&lines);
        println!("--- {width}x{height}\n{text}");
        assert!(!text.contains("Terminal too small"), "{text}");
        assert!(lines.iter().all(|l| l.chars().count() <= width as usize));

        let canvas = lines
            .iter()
            .position(|l| l.contains("SERVERS"))
            .expect("the canvas's title");
        let stream = lines
            .iter()
            .position(|l| l.contains("ACTIVITY & CHAT"))
            .expect("the stream's title");
        assert!(canvas < stream, "the canvas is above the stream:\n{text}");
        // Stacked, each pane starts at the left edge and spans the width: its title row
        // opens with a corner in column 0 and closes with one in the last column.
        for row in [canvas, stream] {
            let chars: Vec<char> = lines[row].chars().collect();
            assert_eq!(chars.first(), Some(&'╭'), "{}", lines[row]);
            assert_eq!(chars.len(), width as usize, "{}", lines[row]);
            assert_eq!(chars.last(), Some(&'╮'), "{}", lines[row]);
        }
        // The first card and the stream's events are both on screen.
        assert!(text.contains("#1"), "{text}");
        assert!(
            text.contains("listening on"),
            "the stream shows its events:\n{text}"
        );
        // The input box sits under the stream, above the status line.
        let input = lines
            .iter()
            .rposition(|l| l.starts_with('╭'))
            .expect("the input box");
        assert!(input > stream && input < lines.len() - 1, "{text}");
    }

    // Below the minimum the dashboard says so instead of drawing a broken frame.
    let mut app = app();
    app.absorb_snapshot(RailSnapshot::default());
    assert!(dump(&frame(&mut app, 39, 30)).contains("Terminal too small"));
}

/// Stacked, a modal takes the whole width: at 48 columns a modal sized for a wide screen would
/// leave its content a few characters wide.
#[test]
fn a_modal_takes_the_whole_width_of_a_narrow_terminal() {
    let mut app = app();
    app.absorb_snapshot(RailSnapshot::default());
    app.modals
        .push(netget::tui::modal::Modal::Help { scroll: 0 });
    let lines = frame(&mut app, 48, 34);
    let text = dump(&lines);
    println!("{text}");
    let top = lines
        .iter()
        .find(|l| l.contains("Keys"))
        .expect("the help modal's title");
    let chars: Vec<char> = top.chars().collect();
    assert_eq!(chars.len(), 48, "{top}");
    assert!(matches!(chars.first(), Some('╭' | '┌')), "{top}");
    assert!(matches!(chars.last(), Some('╮' | '┐')), "{top}");
}

#[test]
fn activity_selection_survives_ring_eviction_by_entry_identity() {
    use netget::tui::activity::{ActivityFeed, ACTIVITY_CAPACITY};
    use netget::ui::app::LogLevel;
    let mut feed = ActivityFeed::new();
    for index in 0..ACTIVITY_CAPACITY {
        feed.push_log(LogLevel::Info, index.to_string());
    }
    let selected = feed.entries[100].seq;
    feed.cursor = Some(selected);
    for index in 0..50 {
        feed.push_log(LogLevel::Info, format!("new-{index}"));
    }
    assert_eq!(feed.cursor, Some(selected));
    assert_eq!(
        feed.entries
            .iter()
            .find(|entry| Some(entry.seq) == feed.cursor)
            .unwrap()
            .event
            .text,
        "100"
    );
    for index in 0..100 {
        feed.push_log(LogLevel::Info, format!("newer-{index}"));
    }
    assert_eq!(feed.cursor, feed.entries.front().map(|entry| entry.seq));
}

#[test]
fn scrolled_activity_keeps_its_top_line_as_new_wrapped_entries_arrive() {
    use netget::ui::app::LogLevel;
    let mut app = app();
    for index in 0..40 {
        app.activity
            .push_log(LogLevel::Info, format!("entry-{index:02}"));
    }
    app.activity.scroll_up(15);
    let mut terminal = Terminal::new(TestBackend::new(60, 10)).unwrap();
    let paint = |terminal: &mut Terminal<TestBackend>, app: &mut DashboardApp| {
        terminal
            .draw(|frame| {
                let area = frame.area();
                render::stream::draw(frame, app, area);
            })
            .unwrap();
        (0..60)
            .map(|x| terminal.backend().buffer()[(x, 1)].symbol())
            .collect::<String>()
    };
    let before = paint(&mut terminal, &mut app);
    for index in 0..10 {
        app.activity
            .push_log(LogLevel::Info, format!("appended-{index}"));
    }
    let after = paint(&mut terminal, &mut app);
    assert_eq!(
        after, before,
        "the viewport must stay anchored to retained entries"
    );
}

#[test]
fn fold_state_is_forgotten_after_instances_and_peers_disappear() {
    use netget::tui::cards::{CardState, Group, NodeId};
    let key = UiKey::Server(ServerId::new(1));
    let peer = NodeId::Peer(key, Some(7));
    let config = NodeId::Group(key, Group::Config);
    let mut state = CardState::default();
    state.close(&peer);
    state.open(&config);
    let snapshot = populated();
    state.retain_snapshot(&snapshot);
    assert!(!state.is_open(&peer));
    assert!(state.is_open(&config));
    state.retain_snapshot(&RailSnapshot::default());
    state.retain_snapshot(&snapshot);
    assert!(state.is_open(&peer));
    assert!(!state.is_open(&config));
}

/// Every cell of a rendered frame, as symbols.
fn cells(app: &mut DashboardApp, width: u16, height: u16) -> Vec<String> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal.draw(|f| render::draw(f, app)).expect("draw");
    let buffer = terminal.backend().buffer().clone();
    (0..height)
        .flat_map(|y| (0..width).map(move |x| (x, y)))
        .map(|pos| buffer[pos].symbol().to_string())
        .collect()
}

/// A peer's escape sequences never reach the terminal as cells.
///
/// ratatui's `Paragraph` writes every grapheme of width > 0 straight into the buffer and
/// `CrosstermBackend` prints each cell verbatim, and unicode-width gives ESC, C1 and BEL a
/// width of one — so until September 2026 a telnet line of `\x1b]52;c;QUJD\x07` (an OSC 52
/// clipboard write) rendered as exactly that on the operator's terminal, from the request row
/// on a card, from a `[LEVEL]` line quoting it, and from the model's reply echoing it. A DSR
/// query would even have had its answer typed into the chat box.
#[test]
fn peer_escape_sequences_are_not_painted_as_terminal_cells() {
    const HOSTILE: &str = "hi\u{1b}]52;c;QUJD\u{7}\u{9b}31m\u{1b}[2Jthere\u{1b}[6n";
    let mut app = app();
    let mut snapshot = populated();
    snapshot.servers[0].requests.push(AccessLogEntry {
        id: 99,
        unix_ms: 1_700_000_099_000,
        server_id: Some(1),
        client_id: None,
        protocol: "TELNET".into(),
        connection_id: Some(7),
        event_type: "telnet_line_received".into(),
        request: serde_json::json!({"message": HOSTILE, "connection_id": "conn-7"}),
        response: vec![serde_json::json!({"type": "send_telnet_line", "text": HOSTILE})],
        answered_by: None,
    });
    app.absorb_snapshot(snapshot);
    app.activity.push_log(
        netget::ui::app::LogLevel::Info,
        format!("SSH auth for '{HOSTILE}': decision=model_reject"),
    );
    app.push_chat(netget::tui::chat::EntryKind::System, HOSTILE.to_string());
    app.push_chat(netget::tui::chat::EntryKind::Reasoning, HOSTILE.to_string());

    for (w, h) in [(160, 48), (80, 24)] {
        let cells = cells(&mut app, w, h);
        let painted: String = cells.concat();
        assert!(
            painted.contains("hi") && painted.contains("there"),
            "the legitimate text around the escapes must still render at {w}x{h}"
        );
        let bad: Vec<&String> = cells
            .iter()
            .filter(|c| c.chars().any(char::is_control))
            .collect();
        assert!(
            bad.is_empty(),
            "control characters reached the frame buffer at {w}x{h}: {bad:?}"
        );
    }
}

/// The intercept overlay and the request detail modal pretty-print a peer's payload, and
/// `serde_json` escapes only U+0000..U+001F inside a string: DEL and the C1 range — U+009B is
/// an 8-bit CSI, U+009D an 8-bit OSC — come out raw. Neither modal may paint one as a cell,
/// and the intercept's description is the peer's text too.
#[test]
fn intercept_payload_controls_are_not_painted_as_terminal_cells() {
    const HOSTILE: &str = "hi\u{9b}31m\u{7f}\u{9d}52;c;QUJD\u{9c}there\u{1b}[2J";
    let payload = serde_json::json!({"message": HOSTILE, "connection_id": "conn-7"});

    let modal = |name: &str| match name {
        "intercept" => netget::tui::modal::Modal::Intercept(Box::new(
            netget::tui::modal::intercept::InterceptModel {
                id: 4,
                owner: UiKey::Server(ServerId::new(1)),
                protocol: "TELNET".into(),
                event_type: "telnet_line_received".into(),
                description: format!("line {HOSTILE}"),
                event_data: Some(payload.clone()),
                vocabulary: Vec::new(),
                deadline_unix_ms: None,
                error: None,
                focused: 0,
            },
        )),
        _ => netget::tui::modal::Modal::RequestDetail {
            entry: Box::new(AccessLogEntry {
                id: 98,
                unix_ms: 1_700_000_098_000,
                server_id: Some(1),
                client_id: None,
                protocol: "TELNET".into(),
                connection_id: Some(7),
                event_type: "telnet_line_received".into(),
                request: payload.clone(),
                response: vec![serde_json::json!({"type": "send_telnet_line", "text": HOSTILE})],
                answered_by: None,
            }),
            scroll: 0,
        },
    };

    for name in ["intercept", "request detail"] {
        for (w, h) in [(160, 48), (80, 24)] {
            let mut app = app();
            app.absorb_snapshot(populated());
            app.modals.push(modal(name));
            let cells = cells(&mut app, w, h);
            let bad: Vec<&String> = cells
                .iter()
                .filter(|c| c.chars().any(char::is_control))
                .collect();
            assert!(
                bad.is_empty(),
                "control characters reached the {name} frame at {w}x{h}: {bad:?}"
            );
            if (w, h) == (160, 48) {
                let painted: String = cells.concat();
                assert!(
                    painted.contains("message"),
                    "the {name} modal must still show the payload at {w}x{h}"
                );
            }
        }
    }
}

/// The left column of a frame at `width`, where the canvas sits.
fn left_column(lines: &[String], width: usize) -> Vec<String> {
    lines
        .iter()
        .map(|l| l.chars().take(width).collect())
        .collect()
}

#[test]
fn a_failure_in_the_stream_is_shown_whole_at_80_columns() {
    let mut app = app();
    app.absorb_snapshot(RailSnapshot::default());
    // What a picker start that cannot bind leaves behind: the log line and
    // the returned error, both about one sentence long.
    app.push_chat(
        netget::tui::chat::EntryKind::Log(netget::ui::app::LogLevel::Error),
        "Server #1 (redis) failed to start: bind 127.0.0.1:6379: Address already in use (os error 48)",
    );
    app.push_error("✗ could not start redis: port 6379 needs a different owner (wrapped tail)");
    // The first-launch message, which used to break inside words.
    app.push_system("✗  Ollama is not available or no models found.");
    let lines = frame(&mut app, 80, 24);
    let text = dump(&lines);
    println!("{text}");
    assert!(
        text.contains("48)"),
        "the end of the bind error is on screen:\n{text}"
    );
    assert!(
        text.contains("tail)"),
        "the end of the UI error is on screen:\n{text}"
    );
    assert!(
        text.contains("models found"),
        "a conversation entry wraps between words, not inside them:\n{text}"
    );
    assert!(lines.iter().all(|l| l.chars().count() <= 80));
}

#[test]
fn an_empty_dashboard_at_80_columns_cuts_none_of_its_guidance() {
    let mut app = app();
    app.absorb_snapshot(RailSnapshot::default());
    let lines = frame(&mut app, 80, 24);
    let left = left_column(&lines, 40);
    let text = left.join("\n");
    println!("{text}");
    assert!(
        !text.contains('…'),
        "nothing in the empty state is cut:\n{text}"
    );
    assert!(text.contains("buttons."), "{text}");
    assert!(text.contains("8080”."), "{text}");
}

#[test]
fn an_instance_error_is_shown_whole_on_its_card() {
    let mut app = app();
    let mut snapshot = populated();
    snapshot.servers.remove(0);
    snapshot.clients.clear();
    snapshot.servers[0].status = ServerStatus::Error(
        "bind 0.0.0.0:53: Permission denied (os error 13); port 53 needs root".into(),
    );
    app.absorb_snapshot(snapshot);
    app.focus = Focus::Cards;
    let lines = frame(&mut app, 80, 24);
    let text = left_column(&lines, 40).join("\n");
    println!("{text}");
    assert!(
        text.contains("needs root"),
        "the end of the error is on the card:\n{text}"
    );
}

#[test]
fn a_long_create_form_scrolls_to_its_selection_and_keeps_its_error() {
    use netget::tui::app::Section;
    use netget::tui::modal::form::FormModel;
    use netget::tui::modal::Modal;
    let mut app = app();
    app.absorb_snapshot(RailSnapshot::default());
    let mut form = FormModel::for_create(Section::Servers, "telnet", Some(23));
    form.error = Some("bind 127.0.0.1:2323: Address already in use (os error 48)".into());
    let last = form.fields.last().expect("fields").label.clone();
    let count = form.fields.len();
    form.move_selection(count as isize - 1);
    app.modals.push(Modal::Form(Box::new(form)));
    let lines = frame(&mut app, 80, 24);
    let text = dump(&lines);
    println!("{text}");
    assert!(
        lines.iter().any(|l| l.contains(&format!("▸ {last}"))),
        "the selected field ({last}, the last of {count}) is in view:\n{text}"
    );
    assert!(
        text.contains("Address already in use"),
        "the error from [ Apply ] is in view:\n{text}"
    );
    assert!(text.contains("more fields"), "it says it scrolled:\n{text}");
    assert!(text.contains("Apply"), "the buttons stay:\n{text}");
}

#[test]
fn a_parked_request_says_when_it_fails_closed() {
    let mut app = app();
    let mut snapshot = populated();
    snapshot.servers[0].intercepts[0].created_unix_ms =
        netget::state::intercepts::now_unix_ms() - 100_000;
    snapshot.servers[0].intercepts[0].timeout_secs = 300;
    app.absorb_snapshot(snapshot);
    let text = dump(&frame(&mut app, 140, 60));
    println!("{text}");
    assert!(
        text.contains("from :53121 · 3m") && text.contains("s left"),
        "the card's waiting row carries the deadline:\n{text}"
    );

    app.modals
        .push(netget::tui::modal::Modal::Intercept(Box::new(
            netget::tui::modal::intercept::InterceptModel {
                id: 4,
                owner: UiKey::Server(ServerId::new(1)),
                protocol: "HTTP".into(),
                event_type: "http_request".into(),
                description: "GET /admin".into(),
                event_data: Some(serde_json::json!({
                    "method": "GET", "path": "/admin", "headers": {"host": "x", "accept": "*/*"},
                    "connection_id": "conn-7"
                })),
                vocabulary: Vec::new(),
                deadline_unix_ms: Some(netget::state::intercepts::now_unix_ms() + 200_500),
                error: None,
                focused: 0,
            },
        )));
    let text = dump(&frame(&mut app, 80, 24));
    println!("{text}");
    assert!(
        text.contains("fails closed in 3m"),
        "the answer modal carries it too, at 80×24 with a payload:\n{text}"
    );
}

#[test]
fn the_answer_modal_draws_all_three_buttons_at_80_columns() {
    let mut app = app();
    app.absorb_snapshot(populated());
    app.modals
        .push(netget::tui::modal::Modal::Intercept(Box::new(
            netget::tui::modal::intercept::InterceptModel {
                id: 4,
                owner: UiKey::Server(ServerId::new(1)),
                protocol: "HTTP".into(),
                event_type: "http_request".into(),
                description: "GET /admin".into(),
                event_data: Some(serde_json::json!({"method": "GET", "path": "/admin"})),
                vocabulary: Vec::new(),
                deadline_unix_ms: None,
                error: None,
                focused: 2,
            },
        )));
    let text = dump(&frame(&mut app, 80, 24));
    println!("{text}");
    for button in [
        "[ Compose answer… ]",
        "[ Answer with nothing ]",
        "[ Fail closed ]",
    ] {
        assert!(
            text.contains(button),
            "{button} is drawn (Tab can focus it):\n{text}"
        );
    }
}

#[test]
fn an_llm_driven_instance_with_no_model_says_its_events_fail_closed() {
    let mut app = app();
    let mut snapshot = populated();
    // The telnet client has no rules: its driver is LLM.
    snapshot.no_model = true;
    app.absorb_snapshot(snapshot.clone());
    let text = dump(&frame(&mut app, 140, 60));
    println!("{text}");
    assert!(
        text.contains("No model is selected"),
        "the LLM driver row warns:\n{text}"
    );
    // Wide enough not to wrap, so the warning reads as one sentence. It must
    // not promise that only /model ends the failures: every event that
    // reaches the model asks the endpoint for one first, so a model pulled
    // later is auto-selected by the next event.
    let warning: Vec<String> = netget::tui::cards::rows(
        &snapshot,
        &netget::tui::cards::CardState::default(),
        &std::collections::HashMap::new(),
        400,
    )
    .iter()
    .map(|row| row.text())
    .filter(|text| text.contains("No model is selected"))
    .collect();
    assert!(!warning.is_empty());
    for line in &warning {
        assert!(
            line.contains("asks the LLM endpoint for one")
                && line.contains("fails closed while none is installed or reachable")
                && !line.contains("until /model"),
            "the warning says when events fail closed, truthfully: {line}"
        );
    }

    snapshot.no_model = false;
    app.absorb_snapshot(snapshot);
    let text = dump(&frame(&mut app, 140, 60));
    assert!(
        !text.contains("No model is selected"),
        "and only when there is no model:\n{text}"
    );
    assert!(text.contains("the model answers"), "{text}");
}

#[test]
fn help_describes_the_stream_as_it_is() {
    let lines = netget::tui::modal::help::help_lines();
    let text: Vec<String> = lines
        .iter()
        .map(|(k, t)| format!("{} {t}", k.unwrap_or("")))
        .collect();
    let text = text.join("\n");
    assert!(
        !text.contains("Activity (top right)"),
        "there is no separate activity pane:\n{text}"
    );
    assert!(
        text.contains("PageUp"),
        "how to reach the stream's lines is listed:\n{text}"
    );
}

/// A spawned action's result reaches the modal that started it and no other.
/// `c` on a server connects a client with no modal open; if the connect is slow
/// and the user opens another instance's edit form meanwhile, the result must
/// go to the stream, not close that form or write its error into it.
#[test]
fn a_spawned_result_lands_only_in_the_modal_that_started_it() {
    use netget::tui::keymap::handle_ui_msg;
    use netget::tui::modal::form::FormModel;
    use netget::tui::modal::Modal;
    use netget::tui::uimsg::{ActionTicket, UiMsg};

    let mut app = app();
    let snapshot = populated();
    let server = snapshot.servers[0].clone();
    app.absorb_snapshot(snapshot);

    // The user's edit form, opened while a `c` connect (ticket nobody holds) runs.
    app.modals
        .push(Modal::Form(Box::new(FormModel::for_edit_server(&server))));
    let connect = ActionTicket::next();

    handle_ui_msg(
        &mut app,
        UiMsg::ActionDone {
            ticket: connect,
            result: Err("connect to 127.0.0.1:8080: Connection refused".into()),
        },
    );
    let Some(Modal::Form(form)) = app.modals.last() else {
        panic!("the unrelated edit form stays open after a failed connect");
    };
    assert!(
        form.error.is_none(),
        "the connect's error is not written into it: {:?}",
        form.error
    );
    assert!(
        app.activity
            .entries
            .iter()
            .any(|e| e.event.text.contains("Connection refused")),
        "the connect's error goes to the stream"
    );

    handle_ui_msg(
        &mut app,
        UiMsg::ActionDone {
            ticket: ActionTicket::next(),
            result: Ok("client #3 connected to 127.0.0.1:8080".into()),
        },
    );
    assert!(
        matches!(app.modals.last(), Some(Modal::Form(_))),
        "a successful connect does not close the unrelated form"
    );

    // The form's own apply: its ticket, its error, wherever it sits in the stack.
    let ticket = ActionTicket::next();
    if let Some(Modal::Form(form)) = app.modals.last_mut() {
        form.pending = Some(ticket);
    }
    app.modals.push(Modal::Help { scroll: 0 });
    handle_ui_msg(
        &mut app,
        UiMsg::ActionDone {
            ticket,
            result: Err("bind 127.0.0.1:23: Address already in use".into()),
        },
    );
    assert!(matches!(app.modals.last(), Some(Modal::Help { .. })));
    let Some(Modal::Form(form)) = app.modals.first() else {
        panic!("the form is still there");
    };
    assert_eq!(
        form.error.as_deref(),
        Some("bind 127.0.0.1:23: Address already in use"),
        "its own failure is shown in it"
    );
    assert!(!form.busy(), "and it can be submitted again");

    let ticket = ActionTicket::next();
    if let Some(Modal::Form(form)) = app.modals.first_mut() {
        form.pending = Some(ticket);
    }
    handle_ui_msg(
        &mut app,
        UiMsg::ActionDone {
            ticket,
            result: Ok("server #1 updated".into()),
        },
    );
    assert!(
        !app.modals.iter().any(|m| matches!(m, Modal::Form(_))),
        "its own success closes it"
    );
    assert!(matches!(app.modals.last(), Some(Modal::Help { .. })));
}

/// `c` belongs to a server's card and `n` to a client's. Pressed on the other
/// kind they used to do nothing and say nothing; now they say what they do and
/// where, the way a disabled button says why.
#[tokio::test]
async fn a_card_letter_for_the_other_kind_says_where_it_works() {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use netget::tui::keymap::handle_key;

    let mut app = app();
    app.absorb_snapshot(populated());
    app.focus = Focus::Cards;
    let state = netget::state::AppState::new();
    let handler = netget::events::EventHandler::new(
        state.clone(),
        netget::llm::OllamaClient::new("http://127.0.0.1:1"),
    );
    let (status_tx, _status_rx) = tokio::sync::mpsc::unbounded_channel();

    let row_of = |app: &DashboardApp, client: bool| {
        app.rows()
            .iter()
            .position(|r| match r.key {
                Some(UiKey::Client(_)) => client,
                Some(UiKey::Server(_)) => !client,
                None => false,
            })
            .expect("a card of that kind")
    };
    let press = |c: char| KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
    let last_line = |app: &DashboardApp| {
        app.activity
            .entries
            .back()
            .map(|e| e.event.text.clone())
            .unwrap_or_default()
    };

    app.cards.row = row_of(&app, true);
    let before = app.activity.entries.len();
    handle_key(&mut app, press('c'), &state, &handler, &status_tx).await;
    assert!(app.modals.is_empty(), "nothing opened");
    assert_eq!(app.activity.entries.len(), before + 1, "one line says why");
    let said = last_line(&app);
    assert!(
        said.starts_with("c: ") && said.contains("server's card") && said.contains("is a client"),
        "c on a client says what it does and where: {said}"
    );

    app.cards.row = row_of(&app, false);
    handle_key(&mut app, press('n'), &state, &handler, &status_tx).await;
    assert!(app.modals.is_empty(), "nothing opened");
    let said = last_line(&app);
    assert!(
        said.starts_with("n: ")
            && said.contains("client's card")
            && said.contains("is a server")
            && said.contains("[ send message ]"),
        "n on a server says what it does, where, and what to use instead: {said}"
    );
}

/// A verb with more parameters than the composer holds at 80×24: the box
/// scrolls to the selected field, says there is more, and keeps the
/// validation error above the buttons. It used to render through ratatui's
/// `Wrap` with no scroll, so the last fields and the error fell off the box.
#[test]
fn a_composer_with_many_parameters_scrolls_to_its_selection_and_keeps_its_error() {
    use netget::llm::actions::{ActionDefinition, Parameter};
    use netget::tui::modal::composer::ComposerModel;
    use netget::tui::modal::Modal;

    let mut app = app();
    app.absorb_snapshot(RailSnapshot::default());
    let parameters: Vec<Parameter> = (1..=14)
        .map(|n| Parameter {
            name: format!("param_{n:02}"),
            type_hint: "string".into(),
            description: format!("the {n}th header of the request, sent as written"),
            required: n == 14,
        })
        .collect();
    let action = ActionDefinition {
        name: "send_request".into(),
        description: "Send one request with every header the protocol defines".into(),
        parameters,
        example: serde_json::json!({"type": "send_request"}),
        log_template: None,
    };
    let mut composer = ComposerModel::new(ClientId::new(2), "test", vec![action]);
    composer.choose();
    composer.move_selection(13);
    composer.error = Some("'param_14' is required — fill it in before [ Send ]".into());
    app.modals.push(Modal::Composer(Box::new(composer)));

    let lines = frame(&mut app, 80, 24);
    let text = dump(&lines);
    println!("{text}");
    assert!(
        lines.iter().any(|l| l.contains("▸ param_14")),
        "the selected field, the last of 14, is in view:\n{text}"
    );
    assert!(
        text.contains("before [ Send ]"),
        "the validation error is in view, whole:\n{text}"
    );
    assert!(text.contains("more fields"), "it says it scrolled:\n{text}");
    assert!(text.contains("[ Send ]"), "the buttons stay:\n{text}");
    assert!(lines.iter().all(|l| l.chars().count() <= 80));
}

/// The routing draft at 80×24 with more static actions than the box holds:
/// the selected action stays in view and the draft's error stays above the
/// buttons, as in the instance form.
#[test]
fn a_routing_draft_with_many_actions_scrolls_to_its_selection_and_keeps_its_error() {
    use netget::tui::modal::routing::{DraftFocus, HandlerKind, RoutingModel};
    use netget::tui::modal::Modal;

    let mut app = app();
    app.absorb_snapshot(RailSnapshot::default());
    let state = netget::state::AppState::new();
    let mut model = RoutingModel::new(UiKey::Server(ServerId::new(1)), "TCP", None, &state);
    model.add();
    {
        let draft = model.draft.as_mut().expect("draft open");
        draft.pattern = "tcp_data_received".into();
        draft.kind = HandlerKind::Static;
        draft.actions = (1..=16)
            .map(|n| serde_json::json!({"type": "send_tcp_data", "data": format!("line {n:02}")}))
            .collect();
        draft.focus = DraftFocus::Actions;
        draft.selected_action = 15;
        draft.error = Some(
            "action 16 (send_tcp_data) is missing a field the protocol requires: encoding".into(),
        );
    }
    app.modals.push(Modal::Routing(Box::new(model)));

    let lines = frame(&mut app, 80, 24);
    let text = dump(&lines);
    println!("{text}");
    assert!(
        text.contains("line 16"),
        "the selected action, the last of 16, is in view:\n{text}"
    );
    assert!(
        text.contains("requires: encoding"),
        "the draft's error is in view, whole:\n{text}"
    );
    assert!(text.contains("more fields"), "it says it scrolled:\n{text}");
    assert!(
        text.contains("[ Save response ]"),
        "the buttons stay:\n{text}"
    );
    assert!(lines.iter().all(|l| l.chars().count() <= 80));
}
