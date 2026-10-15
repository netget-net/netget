//! The management column, model-side: the one-line instance summary, the
//! driver badge and its rebuild, the card rows (buttons, sections, peers with
//! their requests, rules, config, send), and the throughput arithmetic behind
//! the sparklines.

use std::collections::HashMap;

use netget::scripting::event_handler::EventPattern;
use netget::scripting::{EventHandler, EventHandlerConfig, EventHandlerType};
use netget::state::app_state::AccessLogEntry;
use netget::state::client::ClientStatus;
use netget::state::intercepts::{InterceptOwner, InterceptView};
use netget::state::server::ServerStatus;
use netget::state::{ClientId, ServerId};
use netget::tui::app::UiKey;
use netget::tui::cards::{self, Activate, CardState, Group, InstanceAction, NodeId, Row};
use netget::tui::driver::{driver_of, handlers_with_driver, specific_rule_count, Driver};
use netget::tui::metrics::{human_bytes, human_duration, Throughput};
use netget::tui::projection::{ClientRow, ConnRow, RailSnapshot, SendState, SendVerb, ServerRow};
use netget::tui::rail::{self, fit};

fn entry(id: u64, conn: Option<u32>) -> AccessLogEntry {
    AccessLogEntry {
        id,
        unix_ms: 1_700_000_000_000 + id,
        server_id: Some(1),
        client_id: None,
        protocol: "TCP".into(),
        connection_id: conn,
        event_type: "tcp_data_received".into(),
        request: serde_json::json!({"data": format!("payload-{id}")}),
        response: vec![serde_json::json!({"type": "send_tcp_data", "data": "pong"})],
    }
}

fn conn(id: u32, active: bool, can_message: bool) -> ConnRow {
    ConnRow {
        id,
        remote_addr: format!("127.0.0.1:{}", 40000 + id),
        bytes_received: 10,
        bytes_sent: 20,
        active,
        can_message,
    }
}

fn wildcard(handler: EventHandlerType) -> EventHandlerConfig {
    EventHandlerConfig {
        handlers: vec![EventHandler {
            event_pattern: EventPattern::Wildcard,
            handler,
        }],
    }
}

fn specific(id: &str) -> EventHandler {
    EventHandler {
        event_pattern: EventPattern::Specific(id.to_string()),
        handler: EventHandlerType::Static {
            actions: vec![serde_json::json!({"type": "send_tcp_data", "data": "hi"})],
        },
    }
}

fn server(conns: Vec<ConnRow>, requests: Vec<AccessLogEntry>) -> ServerRow {
    ServerRow {
        id: ServerId::new(1),
        protocol: "TCP".into(),
        port: 8080,
        local_addr: Some("127.0.0.1:8080".into()),
        status: ServerStatus::Running,
        instruction: "be a server".into(),
        memory_len: 0,
        startup_params: Some(serde_json::json!({"send_first": false})),
        routing: Some(wildcard(EventHandlerType::Manual { timeout_secs: 300 })),
        conns,
        recent: Vec::new(),
        requests,
        task_count: 0,
        uptime_secs: 133,
        client_counterpart: Some("TCP".into()),
        request_only: None,
        intercepts: Vec::new(),
    }
}

fn client(status: ClientStatus, send_state: SendState) -> ClientRow {
    ClientRow {
        id: ClientId::new(4),
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
        uptime_secs: 5,
        send_state,
        send_actions: vec![
            SendVerb {
                name: "send_command".into(),
                description: "Send a command line".into(),
            },
            SendVerb {
                name: "send_text".into(),
                description: "Send raw text".into(),
            },
        ],
        intercepts: Vec::new(),
    }
}

fn snapshot(servers: Vec<ServerRow>, clients: Vec<ClientRow>) -> RailSnapshot {
    RailSnapshot {
        servers,
        clients,
        ..Default::default()
    }
}

fn rows_for(snap: &RailSnapshot, state: &CardState, width: usize) -> Vec<Row> {
    cards::rows(snap, state, &HashMap::new(), width)
}

#[test]
fn generation_is_nested_under_the_owning_peer_and_survives_folding() {
    use netget::server::connection::ConnectionId;
    use netget::state::app_state::ConversationSource;
    use netget::state::llm_activity::LlmActivityTracker;
    let tracker = LlmActivityTracker::default();
    let _work = tracker.begin(
        ConversationSource::Network {
            server_id: ServerId::new(1),
            connection_id: Some(ConnectionId::new(2)),
        },
        "tcp_data_received".into(),
    );
    let mut snap = snapshot(
        vec![server(
            vec![conn(1, true, true), conn(2, true, true)],
            vec![],
        )],
        vec![],
    );
    snap.llm_activity = tracker.snapshot();
    let key = UiKey::Server(ServerId::new(1));
    let peer = NodeId::Peer(key, Some(2));
    let mut state = CardState::default();
    let rows = rows_for(&snap, &state, 60);
    let index = rows
        .iter()
        .position(|r| r.on_enter == Activate::Toggle(peer.clone()))
        .unwrap();
    let generating = rows
        .iter()
        .position(|r| r.text().contains("LLM generating"))
        .unwrap();
    assert!(generating > index);
    assert_eq!(rows[generating].depth, 3);
    assert!(rows[generating].busy);
    assert!(rows[generating].text().contains("tcp_data_received"));
    assert_eq!(
        rows.iter().filter(|r| r.busy).count(),
        1,
        "the other peer is idle"
    );
    assert_eq!(
        rows[generating].positions(),
        0,
        "status is not a keyboard stop"
    );

    state.close(&peer);
    let rows = rows_for(&snap, &state, 60);
    assert!(
        rows.iter()
            .find(|r| r.on_enter == Activate::Toggle(peer.clone()))
            .unwrap()
            .busy
    );
    assert!(!rows.iter().any(|r| r.text().contains("LLM generating")));
    state.close(&NodeId::Group(key, Group::Peers));
    let rows = rows_for(&snap, &state, 60);
    assert!(group_row(&rows, key, Group::Peers).busy);

    snap.llm_activity.clear();
    assert!(!rows_for(&snap, &state, 60).iter().any(|r| r.busy));
}

#[test]
fn connectionless_work_appears_before_the_first_completed_request() {
    use netget::state::app_state::ConversationSource;
    let tracker = netget::state::llm_activity::LlmActivityTracker::default();
    let _work = tracker.begin(
        ConversationSource::Network {
            server_id: ServerId::new(1),
            connection_id: None,
        },
        "dns_query".into(),
    );
    let mut snap = snapshot(vec![server(vec![], vec![])], vec![]);
    snap.llm_activity = tracker.snapshot();
    let rows = rows_for(&snap, &CardState::default(), 60);
    assert!(rows.iter().any(|r| r.text().contains("connectionless")));
    assert!(rows
        .iter()
        .any(|r| r.busy && r.depth == 3 && r.text().contains("dns_query")));
    assert!(!rows.iter().any(|r| r.text().contains("no connections yet")));
}

#[test]
fn client_generation_is_nested_under_its_connection() {
    use netget::state::app_state::ConversationSource;
    let tracker = netget::state::llm_activity::LlmActivityTracker::default();
    let _work = tracker.begin(
        ConversationSource::Client {
            client_id: ClientId::new(4),
        },
        "tcp_data_received".into(),
    );
    let mut client = client(ClientStatus::Connected, SendState::Ready);
    client.connection = Some(conn(9, true, false));
    let mut snap = snapshot(vec![], vec![client]);
    snap.llm_activity = tracker.snapshot();
    let rows = rows_for(&snap, &CardState::default(), 60);
    let connection = rows
        .iter()
        .position(|r| {
            r.on_enter == Activate::Toggle(NodeId::Attempt(UiKey::Client(ClientId::new(4)), 0))
        })
        .unwrap();
    let generating = rows.iter().position(|r| r.busy).unwrap();
    assert!(generating > connection);
    assert_eq!(rows[generating].depth, 3);
    assert!(rows[generating + 1]
        .buttons
        .iter()
        .any(|b| b.label == "send message"));
}

/// The rows of one card, from its header to the next header (or the end).
fn card_rows<'a>(rows: &'a [Row], key: UiKey) -> &'a [Row] {
    let start = cards::header_index(rows, key).expect("card header");
    let end = rows[start + 1..]
        .iter()
        .position(|r| r.header.is_some() || r.key.is_none())
        .map(|i| start + 1 + i)
        .unwrap_or(rows.len());
    &rows[start..end]
}

fn buttons_of(rows: &[Row]) -> Vec<InstanceAction> {
    rows.iter()
        .flat_map(|r| r.buttons.iter().map(|b| b.action))
        .collect()
}

fn group_row<'a>(rows: &'a [Row], key: UiKey, group: Group) -> &'a Row {
    rows.iter()
        .find(|r| r.on_enter == Activate::Toggle(NodeId::Group(key, group)))
        .expect("group row")
}

// ------------------------------------------------------------ the summary

#[test]
fn a_server_line_carries_status_port_peers_and_driver() {
    let line = rail::server_line(&server(
        vec![conn(1, true, false), conn(2, false, false)],
        Vec::new(),
    ));
    assert_eq!(line.glyph, "●");
    assert_eq!(line.protocol, "tcp");
    assert_eq!(line.target, ":8080");
    assert_eq!(line.peers, "1⇄", "only live peers count");
    assert_eq!(line.driver, Driver::Manual);
    assert_eq!(line.error, None);

    let mut broken = server(Vec::new(), Vec::new());
    broken.status = ServerStatus::Error("bind failed".into());
    let line = rail::server_line(&broken);
    assert_eq!(line.glyph, "✗");
    assert_eq!(line.error.as_deref(), Some("bind failed"));
}

#[test]
fn a_client_line_points_at_its_remote_and_defaults_to_the_model() {
    let line = rail::client_line(&client(ClientStatus::Disconnected, SendState::NotConnected));
    assert_eq!(line.glyph, "○");
    assert_eq!(line.target, "→127.0.0.1:2323");
    assert!(line.peers.is_empty());
    assert_eq!(line.driver, Driver::Llm, "no rules at all means the model");
}

#[test]
fn fit_truncates_with_an_ellipsis_by_chars() {
    assert_eq!(fit("hello", 10), "hello");
    assert_eq!(fit("hello world", 5), "hell…");
    assert_eq!(fit("héllo wörld", 6), "héllo…");
    assert_eq!(fit("x", 0), "");
}

// -------------------------------------------------------------- the driver

#[test]
fn the_driver_is_read_off_the_wildcard_rule() {
    assert_eq!(driver_of(None), Driver::Llm);
    assert_eq!(
        driver_of(Some(&wildcard(EventHandlerType::Manual {
            timeout_secs: 1
        }))),
        Driver::Manual
    );
    assert_eq!(
        driver_of(Some(&wildcard(EventHandlerType::Static {
            actions: Vec::new()
        }))),
        Driver::Silent
    );
    assert_eq!(
        driver_of(Some(&wildcard(EventHandlerType::Static {
            actions: vec![serde_json::json!({"type": "x"})]
        }))),
        Driver::Rules
    );
    assert_eq!(
        driver_of(Some(&wildcard(EventHandlerType::Llm {
            instruction: "answer".into()
        }))),
        Driver::Llm
    );
    let only_specific = EventHandlerConfig {
        handlers: vec![specific("tcp_connection_opened")],
    };
    assert_eq!(driver_of(Some(&only_specific)), Driver::Llm);
    assert_eq!(specific_rule_count(Some(&only_specific)), 1);
}

#[test]
fn cycling_the_driver_rewrites_only_the_wildcard_and_keeps_it_last() {
    let mut config = wildcard(EventHandlerType::Manual { timeout_secs: 300 });
    config.handlers.insert(0, specific("tcp_connection_opened"));

    let llm = handlers_with_driver(Some(&config), Driver::Llm);
    assert_eq!(llm.len(), 1);
    assert_eq!(llm[0]["event_pattern"], "tcp_connection_opened");

    let silent = handlers_with_driver(Some(&config), Driver::Silent);
    assert_eq!(silent.len(), 2);
    assert_eq!(silent[1]["event_pattern"], "*");
    assert_eq!(silent[1]["handler"]["type"], "static");
    assert_eq!(silent[1]["handler"]["actions"], serde_json::json!([]));

    let manual = handlers_with_driver(Some(&config), Driver::Manual);
    assert_eq!(manual[1]["handler"]["type"], "manual");

    for table in [&llm, &silent, &manual] {
        for rule in table {
            let _: EventHandler =
                serde_json::from_value(rule.clone()).expect("rebuilt rule must be a valid handler");
        }
    }

    assert_eq!(Driver::Manual.next(), Driver::Llm);
    assert_eq!(Driver::Llm.next(), Driver::Silent);
    assert_eq!(Driver::Silent.next(), Driver::Manual);
    assert_eq!(Driver::Rules.next(), Driver::Manual);
}

// --------------------------------------------------------------- the cards

#[test]
fn every_card_is_always_there_and_the_new_row_comes_last() {
    let snap = snapshot(
        vec![server(Vec::new(), Vec::new())],
        vec![client(ClientStatus::Connected, SendState::Ready)],
    );
    let rows = rows_for(&snap, &CardState::default(), 60);
    let headers: Vec<UiKey> = rows
        .iter()
        .filter_map(|r| r.header.as_ref().map(|_| r.key.unwrap()))
        .collect();
    assert_eq!(
        headers,
        vec![
            UiKey::Server(ServerId::new(1)),
            UiKey::Client(ClientId::new(4))
        ],
        "one header per instance, servers first"
    );
    let last = rows.last().unwrap();
    assert_eq!(last.on_enter, Activate::NewInstance);
    assert!(last.text().contains("+ new server or client"));
    // Nothing needs selecting: every card is unfolded with its buttons and
    // sections, so the column has far more rows than instances.
    assert!(rows.len() > 12, "{} rows", rows.len());
}

#[test]
fn a_card_shows_facts_then_an_aligned_button_grid_then_its_sections() {
    let snap = snapshot(vec![server(Vec::new(), Vec::new())], Vec::new());
    let rows = rows_for(&snap, &CardState::default(), 44);
    let key = UiKey::Server(ServerId::new(1));
    let card = card_rows(&rows, key);

    // Header, facts (status + uptime + traffic), driver, then buttons.
    assert!(card[0].header.is_some());
    assert!(card[1].text().contains("Running"), "{}", card[1].text());
    assert!(card[1].text().contains("up 2m13s"));
    assert_eq!(card[1].positions(), 0, "facts are not cursor stops");
    assert!(card[2].text().contains("MANUAL"), "{}", card[2].text());

    // The card's ACTION GRID, which is what this test is about — not every button-bearing
    // row in the card. `button_width == 0` is the renderer's marker for a standalone
    // affordance that must NOT be padded into a column (`src/tui/render/cards.rs`), and a
    // server card now ends with one: `[ + tcp client ]` at the foot of its peers. Including
    // it made this assertion compare a grid cell against a deliberate non-cell.
    let button_rows: Vec<&Row> = card
        .iter()
        .filter(|r| {
            r.header.is_none() && !r.buttons.is_empty() && r.spans.is_empty() && r.button_width > 0
        })
        .collect();
    assert!(
        button_rows.len() >= 2,
        "at 44 columns the seven buttons need two rows"
    );
    let cell = button_rows[0].button_width;
    assert!(cell > 0);
    assert!(
        button_rows.iter().all(|r| r.button_width == cell),
        "every row of the grid shares one cell width, so the columns line up"
    );
    let actions = buttons_of(&card);
    for wanted in [
        InstanceAction::Stop,
        InstanceAction::Edit,
        InstanceAction::Rules,
        InstanceAction::CycleDriver,
        InstanceAction::Wireshark,
        InstanceAction::Docs,
    ] {
        assert!(
            actions.contains(&wanted),
            "{wanted:?} missing from {actions:?}"
        );
    }
    let driver = card
        .iter()
        .flat_map(|r| r.buttons.iter())
        .find(|b| b.action == InstanceAction::CycleDriver)
        .unwrap();
    assert_eq!(
        driver.label, "driver → LLM",
        "the button says where it goes"
    );
    assert_eq!(driver.key, Some('m'));

    // Sections: peers open, rules and config folded.
    assert_eq!(group_row(card, key, Group::Peers).expanded, Some(true));
    assert_eq!(group_row(card, key, Group::Rules).expanded, Some(false));
    assert_eq!(group_row(card, key, Group::Config).expanded, Some(false));
    assert!(card.iter().any(|r| r.text().contains("no connections yet")));
}

#[test]
fn a_wider_column_puts_the_buttons_on_one_row() {
    let snap = snapshot(vec![server(Vec::new(), Vec::new())], Vec::new());
    let rows = rows_for(&snap, &CardState::default(), 160);
    let card = card_rows(&rows, UiKey::Server(ServerId::new(1)));
    // Grid rows only, for the same reason as above: `[ + tcp client ]` is a standalone
    // affordance with no grid width and is never part of the action row.
    let button_rows = card
        .iter()
        .filter(|r| !r.buttons.is_empty() && r.spans.is_empty() && r.button_width > 0)
        .count();
    assert_eq!(
        button_rows, 1,
        "at 160 columns every action fits on one row"
    );
}

#[test]
fn a_folded_card_is_one_row() {
    let snap = snapshot(
        vec![server(vec![conn(1, true, true)], Vec::new())],
        Vec::new(),
    );
    let mut state = CardState::default();
    let key = UiKey::Server(ServerId::new(1));
    state.toggle(&NodeId::Card(key));
    let rows = rows_for(&snap, &state, 60);
    assert_eq!(card_rows(&rows, key).len(), 1);
    assert_eq!(rows[0].expanded, Some(false));
}

#[test]
fn the_waiting_request_comes_right_under_the_header() {
    let mut row = server(vec![conn(1, true, true)], Vec::new());
    row.intercepts.push(InterceptView {
        id: 9,
        owner: InterceptOwner::Server(row.id),
        connection_id: Some(1),
        event_type: "tcp_data_received".into(),
        description: "data".into(),
        event_data: None,
        created_unix_ms: 0,
        timeout_secs: 300,
    });
    let snap = snapshot(vec![row], Vec::new());
    let rows = rows_for(&snap, &CardState::default(), 60);
    let card = card_rows(&rows, UiKey::Server(ServerId::new(1)));
    assert_eq!(
        card[1].on_enter,
        Activate::Action(InstanceAction::Answer(9))
    );
    assert!(card[1].text().contains("YOUR answer needed"));
    assert!(card[1].text().contains("from :40001"), "{}", card[1].text());
    let peer = card
        .iter()
        .find(|r| r.text().contains("127.0.0.1:40001"))
        .unwrap();
    assert!(peer.text().contains("⚠ waiting"), "{}", peer.text());
}

#[test]
fn peers_carry_their_buttons_and_unfold_into_their_requests() {
    let snap = snapshot(
        vec![server(
            vec![
                conn(1, true, true),
                conn(2, true, false),
                conn(3, false, false),
            ],
            vec![entry(1, Some(1)), entry(2, Some(1)), entry(3, None)],
        )],
        Vec::new(),
    );
    let key = UiKey::Server(ServerId::new(1));
    let rows = rows_for(&snap, &CardState::default(), 80);
    let card = card_rows(&rows, key);

    let peer1 = card
        .iter()
        .find(|r| r.on_enter == Activate::Toggle(NodeId::Peer(key, Some(1))))
        .unwrap();
    // `· N` is the request count. The peer row used to spell it `2 req`; it converged on the
    // same `· N` form the loose-requests row further down has always used, and this assertion
    // was the only place still expecting the old spelling.
    assert!(peer1.text().contains("· 2"), "{}", peer1.text());
    assert_eq!(
        peer1.expanded,
        Some(true),
        "a peer's requests are open by default"
    );
    // The peer row itself carries `[ disconnect ]`. `[ send message ]` used to sit here too
    // and now has its own row *under the conversation*, which is where a reply belongs —
    // the composer opens beneath what it is replying to rather than above it.
    let actions: Vec<InstanceAction> = peer1.buttons.iter().map(|b| b.action).collect();
    assert_eq!(actions, vec![InstanceAction::DisconnectPeer(1)]);
    assert!(peer1.buttons.iter().all(|b| b.enabled));
    assert_eq!(peer1.positions(), 2, "the label and one button");

    // And the send row really is there, beneath, enabled because this peer can be messaged.
    // Asserting both halves is the point: without this, moving the button off the peer row
    // and losing it entirely would look identical.
    let send = card
        .iter()
        .find(|r| {
            r.buttons
                .iter()
                .any(|b| b.action == InstanceAction::MessagePeer(1))
        })
        .unwrap_or_else(|| {
            panic!(
                "no row offers MessagePeer(1); rows were: {:?}",
                card.iter().map(|r| r.text()).collect::<Vec<_>>()
            )
        });
    assert!(
        send.buttons.iter().all(|b| b.enabled),
        "this peer registered a handle, so the button is live"
    );

    // Its conversation sits right beneath it, **oldest first**, and each entry opens on
    // Enter. Two changes since this was written, both deliberate and both documented in
    // `src/tui/CLAUDE.md`: the order went newest-first to oldest-first, because this is a
    // conversation and not a list; and each entry renders as TWO rows, one for the message
    // in and one for the message out. Asserting the sequence of distinct ids says what the
    // test means without pinning either of those.
    let at = card.iter().position(|r| std::ptr::eq(r, peer1)).unwrap();
    // Bounded to this peer's own subtree: the rows beneath it sit at depth 3, and the next
    // peer's row comes back up to depth 2. Walking to the end of the card instead picks up
    // the neighbouring peer's conversation, which is how this first read as [1, 2, 3].
    let mut order: Vec<u64> = Vec::new();
    for row in card[at + 1..].iter().take_while(|r| r.depth >= 3) {
        if let Activate::Action(InstanceAction::OpenRequest(id)) = row.on_enter {
            if order.last() != Some(&id) {
                order.push(id);
            }
        }
    }
    assert_eq!(
        order,
        vec![1, 2],
        "the conversation reads oldest first, like a transcript"
    );
    assert_eq!(card[at + 1].depth, 3);

    // A live peer without a handle keeps the buttons, disabled, with the reason.
    let peer2 = card
        .iter()
        .find(|r| r.on_enter == Activate::Toggle(NodeId::Peer(key, Some(2))))
        .unwrap();
    assert!(peer2.buttons.iter().all(|b| !b.enabled));
    // The "not implemented here yet" reason lives on the send row now, not on the peer row — the peer
    // row's own button is `[ disconnect ]`. Asserting it where it actually is keeps the real
    // guarantee: a peer whose protocol registered no handle still SHOWS the affordance, and
    // says why it is dead, rather than hiding it.
    let peer2_send = card
        .iter()
        .find(|r| {
            r.buttons
                .iter()
                .any(|b| b.action == InstanceAction::MessagePeer(2))
        })
        .expect("a peer without a handle still offers a disabled send row");
    assert!(peer2_send.buttons.iter().all(|b| !b.enabled));
    assert!(peer2_send.buttons[0]
        .why_disabled
        .as_deref()
        .unwrap_or("")
        .contains("not implemented here yet"));

    // A closed peer has no buttons; the connectionless bucket collects the rest.
    let peer3 = card
        .iter()
        .find(|r| r.on_enter == Activate::Toggle(NodeId::Peer(key, Some(3))))
        .unwrap();
    assert!(peer3.buttons.is_empty());
    assert!(peer3.text().contains("(closed)"));
    let loose = card
        .iter()
        .find(|r| r.on_enter == Activate::Toggle(NodeId::Peer(key, None)))
        .unwrap();
    assert!(loose.text().contains("· 1"));
}

#[test]
fn a_busy_peer_is_capped_with_a_show_all_row() {
    let requests: Vec<AccessLogEntry> = (1..=9).map(|i| entry(i, Some(1))).collect();
    let snap = snapshot(
        vec![server(vec![conn(1, true, false)], requests)],
        Vec::new(),
    );
    let key = UiKey::Server(ServerId::new(1));
    let rows = rows_for(&snap, &CardState::default(), 80);
    // Count ENTRIES, not rows. `message_rows` emits one row for the message in and one for
    // the message out, so five capped entries are ten rows — the cap is doing its job and
    // this assertion was counting the wrong unit. Distinct `OpenRequest` ids is the entry
    // count however many rows each entry renders as.
    let shown = rows
        .iter()
        .filter_map(|r| match r.on_enter {
            Activate::Action(InstanceAction::OpenRequest(id)) => Some(id),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    assert_eq!(shown, cards::CHILD_LIMIT);
    // "earlier", not "more": these rows are a conversation, and the hidden ones are the
    // older messages above rather than extra items below. The wording changed with the
    // meaning when per-connection conversations landed.
    let more = rows
        .iter()
        .find(|r| r.text().contains("… 4 earlier"))
        .unwrap_or_else(|| {
            panic!(
                "no '… 4 earlier' row; saw: {:?}",
                rows.iter().map(|r| r.text()).collect::<Vec<_>>()
            )
        });
    assert_eq!(more.on_enter, Activate::ShowAll(NodeId::Peer(key, Some(1))));

    let mut state = CardState::default();
    state.show_all(&NodeId::Peer(key, Some(1)));
    let rows = rows_for(&snap, &state, 80);
    // Entries again, not rows — same reason as above.
    let shown = rows
        .iter()
        .filter_map(|r| match r.on_enter {
            Activate::Action(InstanceAction::OpenRequest(id)) => Some(id),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    assert_eq!(shown, 9, "show-all lifts the cap to every entry");
}

#[test]
fn rules_unfold_into_rows_with_their_own_buttons() {
    let mut row = server(Vec::new(), Vec::new());
    let mut config = wildcard(EventHandlerType::Manual { timeout_secs: 300 });
    config.handlers.insert(0, specific("tcp_connection_opened"));
    row.routing = Some(config);
    let key = UiKey::Server(ServerId::new(1));
    let snap = snapshot(vec![row], Vec::new());
    let mut state = CardState::default();
    state.toggle(&NodeId::Group(key, Group::Rules));
    let rows = rows_for(&snap, &state, 80);
    let card = card_rows(&rows, key);

    let rule_rows: Vec<&Row> = card
        .iter()
        .filter(|r| matches!(r.on_enter, Activate::Action(InstanceAction::EditRule(_))))
        .collect();
    assert_eq!(rule_rows.len(), 2);
    assert!(
        rule_rows[0]
            .text()
            .contains("tcp_connection_opened → STATIC"),
        "{}",
        rule_rows[0].text()
    );
    assert!(
        rule_rows[1].text().contains("* → MANUAL"),
        "{}",
        rule_rows[1].text()
    );
    let actions: Vec<InstanceAction> = rule_rows[1].buttons.iter().map(|b| b.action).collect();
    assert_eq!(
        actions,
        vec![
            InstanceAction::DeleteRule(1),
            InstanceAction::MoveRule(1, -1),
            InstanceAction::MoveRule(1, 1)
        ]
    );
    assert!(buttons_of(card).contains(&InstanceAction::AddRule));
    assert!(
        !card.iter().any(|r| r.text().contains("otherwise")),
        "a wildcard leaves nothing to fall through"
    );
}

#[test]
fn config_unfolds_into_settings_that_open_the_form() {
    let key = UiKey::Server(ServerId::new(1));
    let snap = snapshot(vec![server(Vec::new(), Vec::new())], Vec::new());
    let mut state = CardState::default();
    state.toggle(&NodeId::Group(key, Group::Config));
    let rows = rows_for(&snap, &state, 80);
    let names: Vec<String> = card_rows(&rows, key)
        .iter()
        .filter(|r| r.on_enter == Activate::Action(InstanceAction::Edit))
        .map(|r| {
            r.spans
                .first()
                .map(|s| s.0.trim().to_string())
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(
        names,
        vec!["port", "host", "send_first", "instruction", "memory"]
    );
    let port = card_rows(&rows, key)
        .iter()
        .find(|r| r.spans.first().is_some_and(|s| s.0.trim() == "port"))
        .unwrap();
    assert!(port.text().contains("8080"));
}

#[test]
fn a_client_lists_its_verbs_and_offers_connect_when_down() {
    let key = UiKey::Client(ClientId::new(4));
    let snap = snapshot(
        Vec::new(),
        vec![client(ClientStatus::Connected, SendState::Ready)],
    );
    let rows = rows_for(&snap, &CardState::default(), 80);
    let card = card_rows(&rows, key);
    let verbs: Vec<&Row> = card
        .iter()
        .filter(|r| matches!(r.on_enter, Activate::Action(InstanceAction::SendAction(_))))
        .collect();
    assert_eq!(verbs.len(), 2);
    assert!(verbs[1].text().contains("send_text"));
    assert!(verbs[1].text().contains("Send raw text"));
    assert_eq!(group_row(card, key, Group::Send).expanded, Some(true));
    let actions = buttons_of(card);
    assert_eq!(actions[0], InstanceAction::Disconnect);
    assert!(actions.contains(&InstanceAction::Send));

    let snap = snapshot(
        Vec::new(),
        vec![client(ClientStatus::Disconnected, SendState::NotConnected)],
    );
    let rows = rows_for(&snap, &CardState::default(), 80);
    let card = card_rows(&rows, key);
    let actions = buttons_of(card);
    assert_eq!(actions[0], InstanceAction::Connect);
    let send = card
        .iter()
        .flat_map(|r| r.buttons.iter())
        .find(|b| b.action == InstanceAction::Send)
        .unwrap();
    assert!(!send.enabled);
    assert_eq!(send.why_disabled.as_deref(), Some("not connected"));
    assert_eq!(send.key, Some('n'));
    // The verbs stay listed but cannot be composed until connected.
    assert!(card.iter().any(|r| r.text().contains("send_command")));
    assert!(!card
        .iter()
        .any(|r| matches!(r.on_enter, Activate::Action(InstanceAction::SendAction(_)))));
}

// -------------------------------------------------------------- the metrics

#[test]
fn throughput_samples_are_deltas_and_the_sparkline_scales_to_the_peak() {
    let mut t = Throughput::default();
    assert!(t.is_idle());
    t.sample(0, 0);
    t.sample(100, 50);
    t.sample(100, 50);
    t.sample(400, 50);
    assert_eq!(t.rate(), (300, 0));
    assert!(!t.is_idle());
    let spark = t.sparkline(4);
    assert_eq!(spark.chars().count(), 4);
    let glyphs: Vec<char> = spark.chars().collect();
    assert_eq!(glyphs[0], ' ', "a missing sample is blank, not zero");
    assert_eq!(glyphs[2], '▁', "an idle second is the floor");
    assert_eq!(glyphs[3], '█', "the peak is the top");
    assert!(
        glyphs[1] > '▁' && glyphs[1] < '█',
        "a smaller sample sits between"
    );
    t.sample(10, 10);
    assert_eq!(t.rate(), (0, 0));
}

#[test]
fn byte_and_duration_formatting_is_compact() {
    assert_eq!(human_bytes(0), "0");
    assert_eq!(human_bytes(999), "999");
    assert_eq!(human_bytes(1_200), "1.2K");
    assert_eq!(human_bytes(123_456), "123K");
    assert_eq!(human_bytes(4_500_000), "4.5M");
    assert_eq!(human_duration(12), "12s");
    assert_eq!(human_duration(133), "2m13s");
    assert_eq!(human_duration(3_840), "1h04m");
}

#[test]
fn payload_summaries_read_as_what_crossed_the_wire() {
    use netget::tui::cards::payload_summary;
    assert_eq!(
        payload_summary(&serde_json::json!({"data": "hello\n"})),
        "hello⏎"
    );
    assert_eq!(
        payload_summary(
            &serde_json::json!({"method": "GET", "path": "/index.html", "headers": {}})
        ),
        "GET /index.html"
    );
    assert_eq!(
        payload_summary(&serde_json::json!({"type": "send_http_response", "status": 200})),
        "status=200"
    );
    assert_eq!(
        payload_summary(&serde_json::json!({"command": "ls -la", "encoding": "utf8"})),
        "ls -la"
    );
    assert_eq!(payload_summary(&serde_json::json!("raw")), "raw");
}

#[test]
fn a_client_connection_shows_its_conversation_with_a_send_button() {
    let mut row = client(ClientStatus::Connected, SendState::Ready);
    row.connection = Some(netget::tui::projection::ConnRow {
        id: 1,
        remote_addr: "127.0.0.1:2323".into(),
        bytes_received: 5,
        bytes_sent: 6,
        active: true,
        can_message: false,
    });
    row.requests = vec![
        AccessLogEntry {
            id: 1,
            unix_ms: 1_700_000_000_000,
            server_id: None,
            client_id: Some(4),
            protocol: "telnet".into(),
            connection_id: None,
            event_type: "telnet_data_received".into(),
            request: serde_json::json!({"text": "login: "}),
            response: vec![serde_json::json!({"type": "send_text", "text": "admin"})],
        },
        AccessLogEntry {
            id: 2,
            unix_ms: 1_700_000_001_000,
            server_id: None,
            client_id: Some(4),
            protocol: "telnet".into(),
            connection_id: None,
            event_type: "injected_action".into(),
            request: serde_json::json!({"type": "send_command", "command": "ls"}),
            response: vec![serde_json::json!({"Sent": {"bytes_sent": 3}})],
        },
    ];
    let key = UiKey::Client(ClientId::new(4));
    let snap = snapshot(Vec::new(), vec![row]);
    let rows = rows_for(&snap, &CardState::default(), 80);
    let card = card_rows(&rows, key);
    let conn = card
        .iter()
        .position(|r| r.on_enter == Activate::Toggle(NodeId::Attempt(key, 0)))
        .expect("the live connection row");
    assert!(
        card[conn + 1]
            .text()
            .contains("← telnet_data_received login: "),
        "{}",
        card[conn + 1].text()
    );
    assert!(
        card[conn + 2].text().contains("→ send_text admin"),
        "{}",
        card[conn + 2].text()
    );
    assert!(
        card[conn + 3].text().contains("→ send_command ls"),
        "an injected send is one outgoing row: {}",
        card[conn + 3].text()
    );
    let send = &card[conn + 4];
    assert_eq!(send.buttons[0].action, InstanceAction::Send);
    assert_eq!(send.buttons[0].label, "send message");
    assert!(send.buttons[0].enabled);
}
