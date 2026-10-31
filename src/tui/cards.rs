//! The instance canvas: every server and client, always visible, each as a
//! card with its buttons and its sub-sections.
//!
//! There is no selection step. The whole column is one list of rows: a
//! card's header, the requests parked for the human, its facts, its buttons
//! (an aligned grid, never a ragged wrap), then collapsible sections —
//! `peers` with the conversation on each peer beneath it and a send button
//! under that, `rules`, `config`, and for a client `send` and `connections`. ↑/↓ walk the rows, ←/→ walk the
//! buttons on a row, Enter acts on whatever the cursor is on. Everything
//! that *does* something is an [`InstanceAction`] run by `actions::run`, so a
//! letter, a button and a click cannot diverge.

use std::collections::{HashMap, HashSet};

use crate::state::app_state::AccessLogEntry;
use crate::state::llm_activity::LlmActivity;
use crate::tui::app::{InstanceRef, UiKey};
use crate::tui::driver::{driver_of, specific_rule_count};
use crate::tui::llm_activity;
use crate::tui::metrics::{clock, human_bytes, human_duration, human_rate, Throughput};
use crate::tui::projection::{ClientRow, RailSnapshot, SendState, ServerRow};
use crate::tui::rail::{client_line, fit, server_line, InstanceLine, Tone};

/// Everything the dashboard can do to an instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstanceAction {
    /// Stop a server / remove a client.
    Stop,
    /// Open the config form.
    Edit,
    /// Open the routing editor on the table.
    Rules,
    /// Open the routing editor on a fresh rule.
    AddRule,
    /// Open the routing editor on one rule.
    EditRule(usize),
    /// Delete one rule and apply.
    DeleteRule(usize),
    /// Move one rule earlier (-1) or later (+1) and apply.
    MoveRule(usize, i8),
    /// Turn the instance's model-authored answers into rules and apply them
    /// (`llm::rule_export`), keeping the instance's own fallback.
    ExportRules,
    /// Cycle MANUAL → LLM → SILENT and apply.
    CycleDriver,
    /// Connect a client of the counterpart protocol to this server.
    ConnectClient,
    /// Open the composer on the action list.
    Send,
    /// Open the composer on one action, by index into `send_actions`.
    SendAction(usize),
    /// Compose for one live server connection.
    MessagePeer(u32),
    /// Close one live server connection from our side.
    DisconnectPeer(u32),
    /// Hang up a client but keep it.
    Disconnect,
    /// Redial a disconnected client.
    Connect,
    Wireshark,
    /// Protocol description and maturity, into the stream.
    Docs,
    /// Open the answer modal for a parked request.
    Answer(u64),
    /// Open the request/response detail for one access-log entry.
    OpenRequest(u64),
}

/// The letter that runs an action without a button.
pub fn shortcut(action: InstanceAction) -> Option<char> {
    match action {
        InstanceAction::Stop => Some('x'),
        InstanceAction::Edit => Some('e'),
        InstanceAction::Rules => Some('r'),
        InstanceAction::CycleDriver => Some('m'),
        InstanceAction::ConnectClient => Some('c'),
        InstanceAction::Send => Some('n'),
        InstanceAction::Wireshark => Some('w'),
        InstanceAction::Docs => Some('d'),
        _ => None,
    }
}

/// One button on a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Button {
    pub action: InstanceAction,
    pub label: String,
    pub key: Option<char>,
    /// A disabled button stays visible (so the capability is discoverable)
    /// and says why when pressed.
    pub enabled: bool,
    pub why_disabled: Option<String>,
}

impl Button {
    pub fn on(action: InstanceAction, label: impl Into<String>) -> Self {
        Self {
            action,
            label: label.into(),
            key: shortcut(action),
            enabled: true,
            why_disabled: None,
        }
    }

    pub fn off(action: InstanceAction, label: impl Into<String>, why: impl Into<String>) -> Self {
        Self {
            action,
            label: label.into(),
            key: shortcut(action),
            enabled: false,
            why_disabled: Some(why.into()),
        }
    }
}

/// A card's sub-sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Group {
    Peers,
    Connections,
    Send,
    Rules,
    Config,
}

impl Group {
    pub fn label(&self) -> &'static str {
        match self {
            Group::Peers => "peers",
            Group::Connections => "connections",
            Group::Send => "send",
            Group::Rules => "rules",
            Group::Config => "config",
        }
    }
}

/// Identity of a collapsible node, stable across re-polls.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeId {
    Card(UiKey),
    Group(UiKey, Group),
    /// A server connection; `None` is the connectionless bucket.
    Peer(UiKey, Option<u32>),
    /// A client connection attempt, by start time.
    Attempt(UiKey, u64),
}

/// What is folded and what is unfolded, across every card.
#[derive(Debug, Default, Clone)]
pub struct CardState {
    /// Open-by-default nodes the user closed.
    collapsed: HashSet<NodeId>,
    /// Closed-by-default nodes the user opened.
    opened: HashSet<NodeId>,
    /// Nodes whose child cap has been lifted.
    show_all: HashSet<NodeId>,
}

impl CardState {
    /// Settings are consulted sometimes; traffic is what the dashboard is
    /// for. Rules and config start folded, everything else open.
    pub fn defaults_closed(node: &NodeId) -> bool {
        matches!(
            node,
            NodeId::Group(_, Group::Rules) | NodeId::Group(_, Group::Config)
        )
    }

    pub fn is_open(&self, node: &NodeId) -> bool {
        if Self::defaults_closed(node) {
            self.opened.contains(node)
        } else {
            !self.collapsed.contains(node)
        }
    }

    pub fn toggle(&mut self, node: &NodeId) {
        let set = if Self::defaults_closed(node) {
            &mut self.opened
        } else {
            &mut self.collapsed
        };
        if !set.remove(node) {
            set.insert(node.clone());
        }
    }

    pub fn open(&mut self, node: &NodeId) {
        if Self::defaults_closed(node) {
            self.opened.insert(node.clone());
        } else {
            self.collapsed.remove(node);
        }
    }

    pub fn close(&mut self, node: &NodeId) {
        if Self::defaults_closed(node) {
            self.opened.remove(node);
        } else {
            self.collapsed.insert(node.clone());
        }
    }

    pub fn show_all(&mut self, node: &NodeId) {
        self.show_all.insert(node.clone());
    }

    /// Forget folds for removed instances, evicted peers and old attempts.
    pub fn retain_snapshot(&mut self, snapshot: &RailSnapshot) {
        let mut valid = HashSet::new();
        for server in &snapshot.servers {
            let key = UiKey::Server(server.id);
            valid.insert(NodeId::Card(key));
            for group in [
                Group::Peers,
                Group::Connections,
                Group::Send,
                Group::Rules,
                Group::Config,
            ] {
                valid.insert(NodeId::Group(key, group));
            }
            for id in server
                .conns
                .iter()
                .map(|c| c.id)
                .chain(server.recent.iter().map(|c| c.id))
            {
                valid.insert(NodeId::Peer(key, Some(id)));
            }
            if server.requests.iter().any(|r| r.connection_id.is_none())
                || snapshot.llm_activity.iter().any(|work| {
                    llm_activity::owner(work) == Some(key)
                        && llm_activity::connection(work).is_none()
                })
            {
                valid.insert(NodeId::Peer(key, None));
            }
        }
        for client in &snapshot.clients {
            let key = UiKey::Client(client.id);
            valid.insert(NodeId::Card(key));
            for group in [
                Group::Peers,
                Group::Connections,
                Group::Send,
                Group::Rules,
                Group::Config,
            ] {
                valid.insert(NodeId::Group(key, group));
            }
            if client.history.is_empty() && client.connection.is_some() {
                valid.insert(NodeId::Attempt(key, 0));
            }
            for attempt in &client.history {
                valid.insert(NodeId::Attempt(key, attempt.started_unix_ms));
            }
        }
        self.collapsed.retain(|node| valid.contains(node));
        self.opened.retain(|node| valid.contains(node));
        self.show_all.retain(|node| valid.contains(node));
    }

    fn limit_for(&self, node: &NodeId) -> usize {
        if self.show_all.contains(node) {
            usize::MAX
        } else {
            CHILD_LIMIT
        }
    }
}

/// How many children a list shows before "… N more".
pub const CHILD_LIMIT: usize = 5;

/// What a live peer's disabled `[ send message ]` says when its protocol registered no peer
/// handle and does not declare [`crate::protocol::metadata::ProtocolMetadataV2::request_only`]:
/// the protocol could message a peer, NetGet just has no path for it yet. A request-only
/// protocol says its own reason instead, because for it there is no "yet".
pub const NO_PEER_HANDLE_REASON: &str =
    "not implemented here yet: this protocol has no way to message a peer from the dashboard";

/// What Enter does on a row's label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Activate {
    None,
    Toggle(NodeId),
    ShowAll(NodeId),
    Action(InstanceAction),
    NewInstance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The card this row belongs to; `None` for the canvas's own rows.
    pub key: Option<UiKey>,
    pub depth: u16,
    /// A card header, rendered as the one-line instance summary.
    pub header: Option<InstanceLine>,
    pub spans: Vec<(String, Tone)>,
    pub buttons: Vec<Button>,
    /// Buttons on this row are padded to this many columns, so the rows of
    /// a card's button grid line up. Zero means natural width.
    pub button_width: usize,
    pub on_enter: Activate,
    /// Present on collapsible rows.
    pub expanded: Option<bool>,
    /// Animate before the label without changing the row's identity or actions.
    pub busy: bool,
}

impl Row {
    fn new(key: Option<UiKey>, depth: u16) -> Self {
        Self {
            key,
            depth,
            header: None,
            spans: Vec::new(),
            buttons: Vec::new(),
            button_width: 0,
            on_enter: Activate::None,
            expanded: None,
            busy: false,
        }
    }

    fn note(key: UiKey, depth: u16, text: impl Into<String>, tone: Tone) -> Self {
        let mut row = Row::new(Some(key), depth);
        row.spans = vec![(text.into(), tone)];
        row
    }

    /// Whether the label itself is a cursor stop.
    pub fn has_label_stop(&self) -> bool {
        self.on_enter != Activate::None
    }

    /// Cursor positions on this row: the label (when it acts) then each
    /// button. Zero means the cursor skips the row.
    pub fn positions(&self) -> usize {
        usize::from(self.has_label_stop()) + self.buttons.len()
    }

    /// The button at cursor column `col`, if `col` names one.
    pub fn button_at(&self, col: usize) -> Option<&Button> {
        let offset = usize::from(self.has_label_stop());
        col.checked_sub(offset).and_then(|i| self.buttons.get(i))
    }

    pub fn text(&self) -> String {
        self.spans.iter().map(|(s, _)| s.as_str()).collect()
    }
}

/// `:53121` for `127.0.0.1:53121` — the port is what tells peers apart.
fn port_of(addr: &str) -> String {
    addr.rsplit_once(':')
        .map(|(_, p)| format!(":{p}"))
        .unwrap_or_else(|| addr.to_string())
}

/// The card's own buttons, whichever section is open.
pub fn instance_buttons(instance: InstanceRef<'_>) -> Vec<Button> {
    let driver = driver_of(instance.routing());
    let driver_button = Button::on(
        InstanceAction::CycleDriver,
        format!("driver → {}", driver.next().label()),
    );
    match instance {
        InstanceRef::Server(_) => {
            let mut buttons = vec![
                Button::on(InstanceAction::Stop, "stop"),
                Button::on(InstanceAction::Edit, "edit"),
                Button::on(InstanceAction::Rules, "rules"),
                driver_button,
            ];
            buttons.push(Button::on(InstanceAction::Wireshark, "wireshark"));
            buttons.push(Button::on(InstanceAction::Docs, "docs"));
            buttons
        }
        InstanceRef::Client(row) => {
            let mut buttons = Vec::new();
            match row.send_state {
                SendState::NotConnected => {
                    buttons.push(Button::on(InstanceAction::Connect, "connect"))
                }
                _ => buttons.push(Button::on(InstanceAction::Disconnect, "disconnect")),
            }
            buttons.push(match row.send_state {
                SendState::Ready if !row.send_actions.is_empty() => {
                    Button::on(InstanceAction::Send, "send…")
                }
                SendState::Ready => Button::off(
                    InstanceAction::Send,
                    "send…",
                    "this protocol declares no client verbs",
                ),
                SendState::NotConnected => {
                    Button::off(InstanceAction::Send, "send…", "not connected")
                }
                SendState::ProtocolUnsupported => Button::off(
                    InstanceAction::Send,
                    "send…",
                    "this client's loop has no command channel yet",
                ),
            });
            buttons.push(Button::on(InstanceAction::Stop, "remove"));
            buttons.push(Button::on(InstanceAction::Edit, "edit"));
            buttons.push(Button::on(InstanceAction::Rules, "rules"));
            buttons.push(driver_button);
            buttons.push(Button::on(InstanceAction::Wireshark, "wireshark"));
            buttons.push(Button::on(InstanceAction::Docs, "docs"));
            buttons
        }
    }
}

/// Lay a card's buttons out as an aligned grid: every cell as wide as the
/// widest label, as many per row as fit, so ←/→ walks a row and ↑/↓ the
/// grid — nothing wraps mid-list.
fn button_rows(key: UiKey, depth: u16, buttons: Vec<Button>, width: usize) -> Vec<Row> {
    if buttons.is_empty() {
        return Vec::new();
    }
    let cell = buttons
        .iter()
        .map(|b| b.label.chars().count() + 4)
        .max()
        .unwrap_or(4);
    let indent = depth as usize * 2 + 2;
    let per_row = (width.saturating_sub(indent) / (cell + 1)).max(1);
    let mut rows = Vec::new();
    for chunk in buttons.chunks(per_row) {
        let mut row = Row::new(Some(key), depth);
        row.buttons = chunk.to_vec();
        row.button_width = cell;
        rows.push(row);
    }
    rows
}

fn group_row(key: UiKey, group: Group, state: &CardState, detail: String) -> (Row, bool) {
    let node = NodeId::Group(key, group);
    let open = state.is_open(&node);
    let mut row = Row::new(Some(key), 1);
    row.spans = vec![
        (group.label().to_string(), Tone::Title),
        (format!("  {detail}"), Tone::Dim),
    ];
    row.on_enter = Activate::Toggle(node);
    row.expanded = Some(open);
    (row, open)
}

/// The keys a protocol's payload is most likely to carry its text under,
/// in the order they are tried.
const PAYLOAD_KEYS: [&str; 14] = [
    "data", "text", "command", "line", "message", "body", "payload", "query", "path", "url",
    "domain", "name", "key", "value",
];

/// One line for a request or an action: the payload's text if there is an
/// obvious one, else the object compacted. What crossed the wire, not the
/// JSON around it.
pub fn payload_summary(value: &serde_json::Value) -> String {
    let text = match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(map) => {
            // A request line reads as one: `GET /index.html`.
            let request_line = match (
                map.get("method").and_then(|v| v.as_str()),
                map.get("path")
                    .or_else(|| map.get("uri"))
                    .and_then(|v| v.as_str()),
            ) {
                (Some(method), Some(path)) => Some(format!("{method} {path}")),
                _ => None,
            };
            let picked = PAYLOAD_KEYS.iter().find_map(|k| map.get(*k));
            match (request_line, picked) {
                (Some(line), _) => line,
                (None, picked) => match picked {
                    Some(serde_json::Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                    None => {
                        let rest: Vec<String> = map
                            .iter()
                            .filter(|(k, _)| *k != "type" && *k != "connection_id")
                            .map(|(k, v)| match v {
                                serde_json::Value::String(s) => format!("{k}={s}"),
                                other => format!("{k}={other}"),
                            })
                            .collect();
                        rest.join(" ")
                    }
                },
            }
        }
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    };
    // A peer's bytes, so ESC/C1/BEL go too (a space each, as `line_field` does for a value
    // that must stay one row): ratatui's `Paragraph` would otherwise hand them to the
    // operator's terminal as the escape sequences they are.
    crate::utils::sanitize::line_field(&text.replace('\r', "").replace('\n', "⏎"))
}

/// An access-log entry as the messages that crossed the wire: what came in
/// (the event), then what went out (each action). An injected send is
/// recorded with the action as its request, so it is one outgoing row.
fn message_rows(key: UiKey, depth: u16, entry: &AccessLogEntry) -> Vec<Row> {
    let time = format!("{} ", clock(entry.unix_ms));
    let open = Activate::Action(InstanceAction::OpenRequest(entry.id));
    let mut rows = Vec::new();
    if entry.event_type == "injected_action" {
        let kind = entry
            .request
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("action");
        let mut row = Row::new(Some(key), depth);
        row.spans = vec![
            (time, Tone::Dim),
            ("→ ".to_string(), Tone::Good),
            (format!("{kind} "), Tone::Dim),
            (payload_summary(&entry.request), Tone::Normal),
        ];
        row.on_enter = open;
        rows.push(row);
        return rows;
    }
    let mut incoming = Row::new(Some(key), depth);
    incoming.spans = vec![
        (time.clone(), Tone::Dim),
        ("← ".to_string(), Tone::Accent),
        (format!("{} ", entry.event_type), Tone::Dim),
        (payload_summary(&entry.request), Tone::Normal),
    ];
    incoming.on_enter = open.clone();
    rows.push(incoming);
    for action in &entry.response {
        let kind = action
            .get("type")
            .and_then(|t| t.as_str())
            .map(|t| t.to_string())
            .unwrap_or_else(|| {
                // Failure envelopes and outcomes: their single key names them.
                action
                    .as_object()
                    .and_then(|o| o.keys().next().cloned())
                    .unwrap_or_else(|| "action".to_string())
            });
        let mut outgoing = Row::new(Some(key), depth);
        outgoing.spans = vec![
            ("         ".to_string(), Tone::Dim),
            ("→ ".to_string(), Tone::Good),
            (format!("{kind} "), Tone::Dim),
            (payload_summary(action), Tone::Normal),
        ];
        outgoing.on_enter = open.clone();
        rows.push(outgoing);
    }
    rows
}

/// The conversation on one connection, oldest first, capped to the latest
/// entries with an "… N earlier" row that lifts the cap.
fn conversation(
    rows: &mut Vec<Row>,
    state: &CardState,
    node: &NodeId,
    key: UiKey,
    depth: u16,
    entries: &[&AccessLogEntry],
) {
    let limit = state.limit_for(node);
    let total = entries.len();
    let shown = total.min(limit);
    if total > shown {
        let mut more = Row::note(
            key,
            depth,
            format!("… {} earlier", total - shown),
            Tone::Dim,
        );
        more.on_enter = Activate::ShowAll(node.clone());
        rows.push(more);
    }
    for entry in &entries[total - shown..] {
        rows.extend(message_rows(key, depth, entry));
    }
    if total == 0 {
        rows.push(Row::note(key, depth, "(nothing exchanged yet)", Tone::Dim));
    }
}

fn waiting_rows(instance: InstanceRef<'_>, rows: &mut Vec<Row>) {
    let key = instance.key();
    for view in instance.intercepts() {
        let peer = match instance {
            InstanceRef::Server(row) => view
                .connection_id
                .and_then(|c| row.conns.iter().find(|x| x.id == c))
                .map(|c| format!(" from {}", port_of(&c.remote_addr)))
                .unwrap_or_default(),
            InstanceRef::Client(_) => String::new(),
        };
        let mut row = Row::new(Some(key), 1);
        row.spans = vec![
            ("⚠ YOUR answer needed".to_string(), Tone::Bad),
            (format!(" · {}{peer}", view.event_type), Tone::Normal),
        ];
        row.on_enter = Activate::Action(InstanceAction::Answer(view.id));
        rows.push(row);
    }
}

fn traffic_text(rx: u64, tx: u64, metrics: Option<&Throughput>) -> String {
    let mut text = format!("↓{} ↑{}", human_bytes(rx), human_bytes(tx));
    if let Some(m) = metrics {
        let (rrx, rtx) = m.rate();
        if rrx > 0 || rtx > 0 {
            text.push_str(&format!(" · now ↓{} ↑{}", human_rate(rrx), human_rate(rtx)));
        }
    }
    text
}

fn driver_row(instance: InstanceRef<'_>) -> Row {
    let driver = driver_of(instance.routing());
    let specific = specific_rule_count(instance.routing());
    let suffix = match specific {
        0 => String::new(),
        1 => " · 1 specific rule first".to_string(),
        n => format!(" · {n} specific rules first"),
    };
    let mut row = Row::new(Some(instance.key()), 1);
    row.spans = vec![
        ("driver ".to_string(), Tone::Dim),
        (driver.label().to_string(), driver.tone()),
        (format!(" — {}{suffix}", driver.describe()), Tone::Dim),
    ];
    row
}

fn rule_rows(instance: InstanceRef<'_>, state: &CardState, rows: &mut Vec<Row>) {
    use crate::scripting::event_handler::EventPattern;
    use crate::scripting::EventHandlerType;

    let key = instance.key();
    let count = instance.routing().map(|c| c.handlers.len()).unwrap_or(0);
    let driver = driver_of(instance.routing());
    let (row, open) = group_row(
        key,
        Group::Rules,
        state,
        format!(
            "{count} rule{} · driver {}",
            if count == 1 { "" } else { "s" },
            driver.label()
        ),
    );
    rows.push(row);
    if !open {
        return;
    }
    let mut has_wildcard = false;
    if let Some(config) = instance.routing() {
        for (index, handler) in config.handlers.iter().enumerate() {
            if matches!(handler.event_pattern, EventPattern::Wildcard)
                && handler.data_match.is_none()
            {
                has_wildcard = true;
            }
            let pattern = handler.describe();
            let (kind, tone, detail) = match &handler.handler {
                EventHandlerType::Llm { instruction } => (
                    "LLM",
                    Tone::Reasoning,
                    crate::utils::truncate_for_log(instruction, 40),
                ),
                EventHandlerType::Script {
                    language, resident, ..
                } => (
                    "SCRIPT",
                    Tone::Good,
                    format!("{language}{}", if *resident { ", resident" } else { "" }),
                ),
                EventHandlerType::Static { actions } => {
                    let names: Vec<&str> = actions
                        .iter()
                        .filter_map(|a| a.get("type").and_then(|t| t.as_str()))
                        .collect();
                    (
                        if actions.is_empty() {
                            "SILENT"
                        } else {
                            "STATIC"
                        },
                        if actions.is_empty() {
                            Tone::Dim
                        } else {
                            Tone::Good
                        },
                        if names.is_empty() {
                            "answer with nothing".to_string()
                        } else {
                            names.join(", ")
                        },
                    )
                }
                EventHandlerType::Manual { timeout_secs } => (
                    "MANUAL",
                    Tone::Warn,
                    format!("you answer · {timeout_secs}s"),
                ),
            };
            let mut row = Row::new(Some(key), 2);
            row.spans = vec![
                (format!("{}  ", index + 1), Tone::Dim),
                (format!("{pattern} → "), Tone::Normal),
                (kind.to_string(), tone),
                (format!("  {detail}"), Tone::Dim),
            ];
            row.on_enter = Activate::Action(InstanceAction::EditRule(index));
            row.buttons
                .push(Button::on(InstanceAction::DeleteRule(index), "delete"));
            if count > 1 {
                row.buttons
                    .push(Button::on(InstanceAction::MoveRule(index, -1), "↑"));
                row.buttons
                    .push(Button::on(InstanceAction::MoveRule(index, 1), "↓"));
            }
            rows.push(row);
        }
    }
    if !has_wildcard {
        rows.push(Row::note(
            key,
            2,
            "otherwise → LLM, from the instance instruction",
            Tone::Dim,
        ));
    }
    let mut add = Row::new(Some(key), 2);
    add.buttons
        .push(Button::on(InstanceAction::AddRule, "+ add rule"));
    add.buttons.push(Button::on(
        InstanceAction::ExportRules,
        "rules from model answers",
    ));
    rows.push(add);
}

fn config_rows(instance: InstanceRef<'_>, state: &CardState, width: usize, rows: &mut Vec<Row>) {
    let key = instance.key();
    let (params, instruction, memory_len, tasks) = match instance {
        InstanceRef::Server(row) => (
            row.startup_params.as_ref(),
            &row.instruction,
            row.memory_len,
            row.task_count,
        ),
        InstanceRef::Client(row) => (
            row.startup_params.as_ref(),
            &row.instruction,
            row.memory_len,
            row.task_count,
        ),
    };
    let param_count = params
        .and_then(|p| p.as_object())
        .map(|m| m.len())
        .unwrap_or(0);
    let (row, open) = group_row(
        key,
        Group::Config,
        state,
        format!(
            "{} setting{}",
            param_count + 2,
            if param_count + 2 == 1 { "" } else { "s" }
        ),
    );
    rows.push(row);
    if !open {
        return;
    }
    let value_width = width.saturating_sub(20);
    let mut push = |name: &str, value: String, tone: Tone| {
        let mut row = Row::new(Some(key), 2);
        row.spans = vec![
            (format!("{name:<12} "), Tone::Dim),
            (fit(&value, value_width), tone),
        ];
        row.on_enter = Activate::Action(InstanceAction::Edit);
        rows.push(row);
    };
    match instance {
        InstanceRef::Server(row) => {
            push(
                "port",
                row.local_addr
                    .as_deref()
                    .and_then(|a| a.rsplit_once(':').map(|(_, p)| p.to_string()))
                    .unwrap_or_else(|| row.port.to_string()),
                Tone::Normal,
            );
            push(
                "host",
                row.local_addr
                    .as_deref()
                    .and_then(|a| a.rsplit_once(':').map(|(h, _)| h.to_string()))
                    .unwrap_or_else(|| "(default)".to_string()),
                Tone::Normal,
            );
        }
        InstanceRef::Client(row) => push("remote", row.remote_addr.clone(), Tone::Normal),
    }
    if let Some(map) = params.and_then(|p| p.as_object()) {
        for (k, v) in map {
            let shown = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            push(k, shown, Tone::Normal);
        }
    }
    let brief = instruction.trim();
    push(
        "instruction",
        if brief.is_empty() {
            "(none)".to_string()
        } else {
            brief.lines().next().unwrap_or("").to_string()
        },
        if brief.is_empty() {
            Tone::Dim
        } else {
            Tone::Normal
        },
    );
    push("memory", format!("{memory_len} chars"), Tone::Dim);
    if tasks > 0 {
        push("tasks", format!("{tasks} scheduled"), Tone::Dim);
    }
}

fn generating_rows(rows: &mut Vec<Row>, key: UiKey, depth: u16, activity: &[&LlmActivity]) {
    for work in activity {
        let mut row = Row::note(key, depth, llm_activity::label(work), Tone::Reasoning);
        row.busy = true;
        rows.push(row);
    }
}

fn server_rows(
    row: &ServerRow,
    state: &CardState,
    metrics: Option<&Throughput>,
    width: usize,
    activity: &[&LlmActivity],
) -> Vec<Row> {
    let key = UiKey::Server(row.id);
    let instance = InstanceRef::Server(row);
    let card = NodeId::Card(key);
    let open = state.is_open(&card);
    let mut rows = Vec::new();

    let mut header = Row::new(Some(key), 0);
    header.header = Some(server_line(row));
    header.on_enter = Activate::Toggle(card.clone());
    header.expanded = Some(open);
    rows.push(header);
    if !open {
        return rows;
    }

    waiting_rows(instance, &mut rows);

    // Facts.
    use crate::state::server::ServerStatus;
    let (status, tone) = match &row.status {
        ServerStatus::Running => ("Running", Tone::Good),
        ServerStatus::Starting => ("Starting", Tone::Warn),
        ServerStatus::Stopped => ("Stopped", Tone::Dim),
        ServerStatus::Error(_) => ("Error", Tone::Bad),
    };
    let (rx, tx) = row.conns.iter().fold((0u64, 0u64), |(a, b), c| {
        (a + c.bytes_received, b + c.bytes_sent)
    });
    let mut facts = Row::new(Some(key), 1);
    facts.spans = vec![
        (status.to_string(), tone),
        (
            format!(
                " · up {} · {} · {} req",
                human_duration(row.uptime_secs),
                traffic_text(rx, tx, metrics),
                row.requests.len()
            ),
            Tone::Dim,
        ),
    ];
    rows.push(facts);
    if let ServerStatus::Error(e) = &row.status {
        rows.push(Row::note(
            key,
            1,
            fit(e, width.saturating_sub(4)),
            Tone::Bad,
        ));
    }
    rows.push(driver_row(instance));

    rows.extend(button_rows(key, 1, instance_buttons(instance), width));

    // Peers, each with the conversation on it beneath.
    let live = row.conns.iter().filter(|c| c.active).count();
    let (mut group, open) = group_row(
        key,
        Group::Peers,
        state,
        format!("{live} live · {} recent", row.recent.len()),
    );
    group.busy = !open && !activity.is_empty();
    rows.push(group);
    if open {
        let mut any = false;
        for conn in &row.conns {
            any = true;
            let node = NodeId::Peer(key, Some(conn.id));
            let mine: Vec<&AccessLogEntry> = row
                .requests
                .iter()
                .filter(|r| r.connection_id == Some(conn.id))
                .collect();
            let waiting = row
                .intercepts
                .iter()
                .any(|v| v.connection_id == Some(conn.id));
            let peer_open = state.is_open(&node);
            let generating: Vec<_> = activity
                .iter()
                .copied()
                .filter(|work| llm_activity::connection(work) == Some(conn.id))
                .collect();
            let mut peer = Row::new(Some(key), 2);
            peer.busy = !peer_open && !generating.is_empty();
            peer.spans = vec![
                (
                    if conn.active { "● " } else { "○ " }.to_string(),
                    if conn.active { Tone::Good } else { Tone::Dim },
                ),
                (
                    conn.remote_addr.clone(),
                    if conn.active { Tone::Normal } else { Tone::Dim },
                ),
                (
                    format!(
                        " ↓{} ↑{} · {}{}",
                        human_bytes(conn.bytes_received),
                        human_bytes(conn.bytes_sent),
                        mine.len(),
                        if conn.active { "" } else { " (closed)" }
                    ),
                    Tone::Dim,
                ),
            ];
            if waiting {
                peer.spans.push((" ⚠ waiting".to_string(), Tone::Bad));
            }
            peer.on_enter = Activate::Toggle(node.clone());
            peer.expanded = Some(peer_open);
            if conn.active {
                peer.buttons.push(if conn.can_message {
                    Button::on(InstanceAction::DisconnectPeer(conn.id), "disconnect")
                } else {
                    Button::off(
                        InstanceAction::DisconnectPeer(conn.id),
                        "disconnect",
                        "this protocol cannot disconnect a peer from here yet",
                    )
                });
            }
            rows.push(peer);
            if peer_open {
                conversation(&mut rows, state, &node, key, 3, &mine);
                generating_rows(&mut rows, key, 3, &generating);
                if conn.active {
                    let mut send = Row::new(Some(key), 3);
                    send.buttons.push(if conn.can_message {
                        Button::on(InstanceAction::MessagePeer(conn.id), "send message")
                    } else {
                        Button::off(
                            InstanceAction::MessagePeer(conn.id),
                            "send message",
                            row.request_only
                                .clone()
                                .unwrap_or_else(|| NO_PEER_HANDLE_REASON.to_string()),
                        )
                    });
                    rows.push(send);
                }
            }
        }
        for closed in &row.recent {
            any = true;
            let node = NodeId::Peer(key, Some(closed.id));
            let mine: Vec<&AccessLogEntry> = row
                .requests
                .iter()
                .filter(|r| r.connection_id == Some(closed.id))
                .collect();
            let peer_open = state.is_open(&node);
            let generating: Vec<_> = activity
                .iter()
                .copied()
                .filter(|work| llm_activity::connection(work) == Some(closed.id))
                .collect();
            let mut peer = Row::new(Some(key), 2);
            peer.busy = !peer_open && !generating.is_empty();
            peer.spans = vec![
                ("○ ".to_string(), Tone::Dim),
                (closed.remote_addr.clone(), Tone::Dim),
                (
                    format!(
                        " ↓{} ↑{} · {} (closed)",
                        human_bytes(closed.bytes_received),
                        human_bytes(closed.bytes_sent),
                        mine.len()
                    ),
                    Tone::Dim,
                ),
            ];
            peer.on_enter = Activate::Toggle(node.clone());
            peer.expanded = Some(peer_open);
            rows.push(peer);
            if peer_open {
                conversation(&mut rows, state, &node, key, 3, &mine);
                generating_rows(&mut rows, key, 3, &generating);
            }
        }
        let loose: Vec<&AccessLogEntry> = row
            .requests
            .iter()
            .filter(|r| r.connection_id.is_none())
            .collect();
        let generating: Vec<_> = activity
            .iter()
            .copied()
            .filter(|work| llm_activity::connection(work).is_none())
            .collect();
        if !loose.is_empty() || !generating.is_empty() {
            any = true;
            let node = NodeId::Peer(key, None);
            let bucket_open = state.is_open(&node);
            let mut bucket = Row::new(Some(key), 2);
            bucket.busy = !bucket_open && !generating.is_empty();
            bucket.spans = vec![
                ("· (connectionless)".to_string(), Tone::Dim),
                (format!(" · {}", loose.len()), Tone::Dim),
            ];
            bucket.on_enter = Activate::Toggle(node.clone());
            bucket.expanded = Some(bucket_open);
            rows.push(bucket);
            if bucket_open {
                conversation(&mut rows, state, &node, key, 3, &loose);
                generating_rows(&mut rows, key, 3, &generating);
            }
        }
        // A connection can disappear before its last model call completes.
        let orphaned: Vec<_> = activity
            .iter()
            .copied()
            .filter(|work| {
                llm_activity::connection(work).is_some_and(|id| {
                    !row.conns.iter().any(|c| c.id == id) && !row.recent.iter().any(|c| c.id == id)
                })
            })
            .collect();
        generating_rows(&mut rows, key, 2, &orphaned);
        any |= !orphaned.is_empty();
        if !any {
            rows.push(Row::note(
                key,
                2,
                format!(
                    "(no connections yet — listening on {})",
                    row.local_addr
                        .clone()
                        .unwrap_or_else(|| format!(":{}", row.port))
                ),
                Tone::Dim,
            ));
        }
        // Connecting a client belongs with the peers it will join.
        let mut add = Row::new(Some(key), 2);
        add.buttons.push(match &row.client_counterpart {
            Some(p) => Button::on(
                InstanceAction::ConnectClient,
                format!("+ {} client", p.to_lowercase()),
            ),
            None => Button::off(
                InstanceAction::ConnectClient,
                "+ client",
                "no client implementation for this protocol is compiled in",
            ),
        });
        rows.push(add);
    }

    rule_rows(instance, state, &mut rows);
    config_rows(instance, state, width, &mut rows);
    rows
}

fn client_rows(
    row: &ClientRow,
    state: &CardState,
    metrics: Option<&Throughput>,
    width: usize,
    activity: &[&LlmActivity],
) -> Vec<Row> {
    let key = UiKey::Client(row.id);
    let instance = InstanceRef::Client(row);
    let card = NodeId::Card(key);
    let open = state.is_open(&card);
    let mut rows = Vec::new();

    let mut header = Row::new(Some(key), 0);
    header.header = Some(client_line(row));
    header.on_enter = Activate::Toggle(card.clone());
    header.expanded = Some(open);
    rows.push(header);
    if !open {
        return rows;
    }

    waiting_rows(instance, &mut rows);

    use crate::state::client::ClientStatus;
    let (status, tone) = match &row.status {
        ClientStatus::Connected => ("Connected", Tone::Good),
        ClientStatus::Connecting => ("Connecting", Tone::Warn),
        ClientStatus::Disconnected => ("Disconnected", Tone::Dim),
        ClientStatus::Error(_) => ("Error", Tone::Bad),
    };
    let (rx, tx) = row
        .connection
        .as_ref()
        .map(|c| (c.bytes_received, c.bytes_sent))
        .unwrap_or((0, 0));
    let mut facts = Row::new(Some(key), 1);
    facts.spans = vec![
        (status.to_string(), tone),
        (
            format!(
                " · up {} · {} · {} req",
                human_duration(row.uptime_secs),
                traffic_text(rx, tx, metrics),
                row.requests.len()
            ),
            Tone::Dim,
        ),
    ];
    rows.push(facts);
    if let ClientStatus::Error(e) = &row.status {
        rows.push(Row::note(
            key,
            1,
            fit(e, width.saturating_sub(4)),
            Tone::Bad,
        ));
    }
    rows.push(driver_row(instance));

    rows.extend(button_rows(key, 1, instance_buttons(instance), width));

    // Send: the client's own verbs.
    let (group, open) = group_row(
        key,
        Group::Send,
        state,
        match row.send_state {
            SendState::Ready => format!("{} verb(s)", row.send_actions.len()),
            SendState::NotConnected => "not connected".to_string(),
            SendState::ProtocolUnsupported => "no command channel yet".to_string(),
        },
    );
    rows.push(group);
    if open {
        match row.send_state {
            SendState::Ready => {}
            SendState::NotConnected => rows.push(Row::note(
                key,
                2,
                "(cannot send — not connected; connect redials)",
                Tone::Dim,
            )),
            SendState::ProtocolUnsupported => rows.push(Row::note(
                key,
                2,
                "(cannot send — this client's loop has no command channel yet)",
                Tone::Dim,
            )),
        }
        if row.send_actions.is_empty() {
            rows.push(Row::note(
                key,
                2,
                "(this protocol declares no client verbs)",
                Tone::Dim,
            ));
        }
        for (index, verb) in row.send_actions.iter().enumerate() {
            let mut r = Row::new(Some(key), 2);
            r.spans = vec![
                (format!("{:<18} ", fit(&verb.name, 18)), Tone::Accent),
                (verb.description.clone(), Tone::Dim),
            ];
            r.on_enter = if row.send_state == SendState::Ready {
                Activate::Action(InstanceAction::SendAction(index))
            } else {
                Activate::None
            };
            rows.push(r);
        }
    }

    // Connections: every attempt, the conversation on it beneath (attributed
    // by time), and the way to add to it.
    let connection_count = row.history.len().max(usize::from(row.connection.is_some()));
    let (mut group, open) = group_row(
        key,
        Group::Connections,
        state,
        format!("{connection_count} · {} messages", row.requests.len()),
    );
    group.busy = !open && !activity.is_empty();
    rows.push(group);
    if open {
        let send_button = || match row.send_state {
            SendState::Ready if !row.send_actions.is_empty() => {
                Button::on(InstanceAction::Send, "send message")
            }
            SendState::Ready => Button::off(
                InstanceAction::Send,
                "send message",
                "this protocol declares no client verbs",
            ),
            SendState::NotConnected => {
                Button::off(InstanceAction::Send, "send message", "not connected")
            }
            SendState::ProtocolUnsupported => Button::off(
                InstanceAction::Send,
                "send message",
                "this client's loop has no command channel yet",
            ),
        };
        if row.history.is_empty() {
            match &row.connection {
                Some(c) => {
                    let node = NodeId::Attempt(key, 0);
                    let conn_open = state.is_open(&node);
                    let mut r = Row::new(Some(key), 2);
                    r.busy = !conn_open && !activity.is_empty();
                    r.spans = vec![
                        ("● ".to_string(), Tone::Good),
                        (c.remote_addr.clone(), Tone::Normal),
                        (
                            format!(
                                " ↓{} ↑{} · {}",
                                human_bytes(c.bytes_received),
                                human_bytes(c.bytes_sent),
                                row.requests.len()
                            ),
                            Tone::Dim,
                        ),
                    ];
                    r.on_enter = Activate::Toggle(node.clone());
                    r.expanded = Some(conn_open);
                    rows.push(r);
                    if conn_open {
                        let all: Vec<&AccessLogEntry> = row.requests.iter().collect();
                        conversation(&mut rows, state, &node, key, 3, &all);
                        generating_rows(&mut rows, key, 3, activity);
                        let mut send = Row::new(Some(key), 3);
                        send.buttons.push(send_button());
                        rows.push(send);
                    }
                }
                None => {
                    generating_rows(&mut rows, key, 2, activity);
                    if activity.is_empty() {
                        rows.push(Row::note(key, 2, "(no connections yet)", Tone::Dim));
                    }
                }
            }
        } else {
            let starts: Vec<u64> = row.history.iter().map(|a| a.started_unix_ms).collect();
            let last = row.history.len() - 1;
            for (index, attempt) in row.history.iter().enumerate().rev() {
                let from = if index == 0 { 0 } else { starts[index] };
                let to = starts.get(index + 1).copied().unwrap_or(u64::MAX);
                let mine: Vec<&AccessLogEntry> = row
                    .requests
                    .iter()
                    .filter(|r| r.unix_ms >= from && r.unix_ms < to)
                    .collect();
                let live =
                    index == last && attempt.ended_unix_ms.is_none() && row.connection.is_some();
                let node = NodeId::Attempt(key, attempt.started_unix_ms);
                let conn_open = state.is_open(&node);
                let mut r = Row::new(Some(key), 2);
                r.busy = index == last && !conn_open && !activity.is_empty();
                r.spans = vec![
                    (
                        if live { "● " } else { "○ " }.to_string(),
                        if live { Tone::Good } else { Tone::Dim },
                    ),
                    (
                        format!("{} {}", clock(attempt.started_unix_ms), attempt.remote_addr),
                        if live { Tone::Normal } else { Tone::Dim },
                    ),
                    (
                        if live {
                            let c = row.connection.as_ref().expect("checked above");
                            format!(
                                " ↓{} ↑{} · {}",
                                human_bytes(c.bytes_received),
                                human_bytes(c.bytes_sent),
                                mine.len()
                            )
                        } else {
                            format!(" {} · {}", attempt.outcome, mine.len())
                        },
                        Tone::Dim,
                    ),
                ];
                r.on_enter = Activate::Toggle(node.clone());
                r.expanded = Some(conn_open);
                rows.push(r);
                if conn_open {
                    conversation(&mut rows, state, &node, key, 3, &mine);
                    if index == last {
                        generating_rows(&mut rows, key, 3, activity);
                    }
                    if live {
                        let mut send = Row::new(Some(key), 3);
                        send.buttons.push(send_button());
                        rows.push(send);
                    }
                }
            }
        }
    }

    rule_rows(instance, state, &mut rows);
    config_rows(instance, state, width, &mut rows);
    rows
}

/// Every card's rows, then the row that starts a new instance.
pub fn rows(
    snapshot: &RailSnapshot,
    state: &CardState,
    metrics: &HashMap<UiKey, Throughput>,
    width: usize,
) -> Vec<Row> {
    let mut rows = Vec::new();
    for server in &snapshot.servers {
        let activity: Vec<_> = snapshot
            .llm_activity
            .iter()
            .filter(|work| llm_activity::owner(work) == Some(UiKey::Server(server.id)))
            .collect();
        rows.extend(server_rows(
            server,
            state,
            metrics.get(&UiKey::Server(server.id)),
            width,
            &activity,
        ));
    }
    for client in &snapshot.clients {
        let activity: Vec<_> = snapshot
            .llm_activity
            .iter()
            .filter(|work| llm_activity::owner(work) == Some(UiKey::Client(client.id)))
            .collect();
        rows.extend(client_rows(
            client,
            state,
            metrics.get(&UiKey::Client(client.id)),
            width,
            &activity,
        ));
    }
    let mut new = Row::new(None, 0);
    new.spans = vec![("+ new server or client".to_string(), Tone::Accent)];
    new.on_enter = Activate::NewInstance;
    rows.push(new);
    if snapshot.servers.is_empty() && snapshot.clients.is_empty() {
        for text in [
            "",
            "Nothing is running yet.",
            "",
            "That row, or a, picks a protocol",
            "and starts it. The instance shows",
            "up here with its buttons, peers,",
            "rules and config, and stays.",
            "↑↓ walk the rows, ←→ the buttons.",
            "",
            "Or ask the model in the chat:",
            "“start an http server on 8080”.",
        ] {
            let mut note = Row::new(None, 0);
            note.spans = vec![(format!("  {text}"), Tone::Dim)];
            rows.push(note);
        }
    }
    rows
}

/// The index of `key`'s header row.
pub fn header_index(rows: &[Row], key: UiKey) -> Option<usize> {
    rows.iter()
        .position(|r| r.key == Some(key) && r.header.is_some())
}
