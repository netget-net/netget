//! Every instance action, executed in one place.
//!
//! A letter on the list, Enter on an action-bar button, a click on that
//! button, a click and Enter on a row all produce an [`InstanceAction`]
//! and land here, so what they do cannot drift apart. Anything that touches
//! the network is spawned and reports back through `uimsg` — see that
//! module for why nothing here may await a connect.

use crate::state::app_state::AppState;
use crate::tui::app::{DashboardApp, Section, UiKey};
use crate::tui::cards::InstanceAction;
use crate::tui::modal::{confirm, Modal, PendingAction};
use crate::tui::uimsg::{ActionOrigin, UiMsg};

/// Run `action` against `key`.
pub async fn run(app: &mut DashboardApp, key: UiKey, action: InstanceAction, state: &AppState) {
    app.dirty = true;
    match action {
        InstanceAction::Stop => stop_instance(app, key, state).await,
        InstanceAction::Edit => open_editor(app, key),
        InstanceAction::Rules => open_routing_at(app, key, state, RouteTarget::List),
        InstanceAction::AddRule => open_routing_at(app, key, state, RouteTarget::New),
        InstanceAction::EditRule(index) => {
            open_routing_at(app, key, state, RouteTarget::Edit(index))
        }
        InstanceAction::DeleteRule(index) => edit_rules_headless(app, key, state, |model| {
            if index < model.handlers.len() {
                model.selected = index;
                model.delete_selected();
                Some(format!("deleted rule {}", index + 1))
            } else {
                None
            }
        }),
        InstanceAction::MoveRule(index, delta) => edit_rules_headless(app, key, state, |model| {
            if index < model.handlers.len() {
                model.selected = index;
                let before = model.selected;
                model.reorder(delta as isize);
                if model.selected != before {
                    Some(format!(
                        "moved rule {} to position {}",
                        index + 1,
                        model.selected + 1
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        }),
        InstanceAction::ExportRules => export_rules(app, key, state),
        InstanceAction::CycleDriver => cycle_driver(app, key, state),
        InstanceAction::ConnectClient => {
            if let UiKey::Server(id) = key {
                open_client_for_server(app, id, state).await;
            }
        }
        InstanceAction::Send => {
            if let UiKey::Client(id) = key {
                open_composer(app, id, None, state).await;
            }
        }
        InstanceAction::SendAction(index) => {
            if let UiKey::Client(id) = key {
                open_composer(app, id, Some(index), state).await;
            }
        }
        InstanceAction::MessagePeer(conn) => {
            if let UiKey::Server(id) = key {
                open_peer_composer(app, id, conn);
            }
        }
        InstanceAction::DisconnectPeer(conn) => {
            if let UiKey::Server(id) = key {
                disconnect_peer(app, id, conn, state);
            }
        }
        InstanceAction::Disconnect => {
            if let UiKey::Client(id) = key {
                disconnect_client(app, id, state).await;
            }
        }
        InstanceAction::Connect => {
            if let UiKey::Client(id) = key {
                connect_client(app, id, state);
            }
        }
        InstanceAction::Wireshark => open_wireshark(app, key),
        InstanceAction::Docs => show_docs(app, key),
        InstanceAction::Answer(id) => open_intercept(app, key, id, state),
        InstanceAction::OpenRequest(id) => open_request(app, key, id),
    }
}

/// Stop an instance immediately — no confirmation. Stopping is cheap to redo
/// (recreate from the picker) and the dialog was pure friction; only the bulk
/// actions (stop all, quit) keep a confirm.
async fn stop_instance(app: &mut DashboardApp, key: UiKey, state: &AppState) {
    let action = match key {
        UiKey::Server(id) => PendingAction::StopServer(id),
        UiKey::Client(id) => PendingAction::StopClient(id),
    };
    let line = confirm::execute(&action, state).await;
    app.push_system(line);
}

/// Hang up a client's connection, keeping the row for `[ connect ]` later.
async fn disconnect_client(app: &mut DashboardApp, id: crate::state::ClientId, state: &AppState) {
    if state.disconnect_client(id).await {
        app.push_system(format!(
            "client #{} disconnected — [ connect ] re-establishes it",
            id.as_u32()
        ));
    } else {
        app.push_system(format!("client #{} is already gone", id.as_u32()));
    }
}

/// (Re)connect a disconnected client. Spawned: connecting is network I/O and
/// must not block the event loop (see `crate::tui::uimsg`).
fn connect_client(app: &mut DashboardApp, id: crate::state::ClientId, state: &AppState) {
    app.push_system(format!("connecting client #{}…", id.as_u32()));
    let llm = app.llm_client.clone();
    let status_tx = app.status_tx.clone();
    let ui_tx = app.ui_tx.clone();
    let state = state.clone();
    tokio::spawn(async move {
        let message = match crate::cli::client_startup::start_client_by_id(
            &state, id, &llm, &status_tx,
        )
        .await
        {
            Ok(_) => format!("client #{} connected", id.as_u32()),
            Err(e) => format!("client #{} failed to connect: {e}", id.as_u32()),
        };
        let _ = ui_tx.send(UiMsg::Chat(message));
    });
}

fn show_docs(app: &mut DashboardApp, key: UiKey) {
    let Some(instance) = app.instance(key) else {
        return;
    };
    let protocol = instance.protocol().to_string();
    let text = match key {
        UiKey::Server(_) => crate::protocol::server_registry::registry()
            .resolve(&protocol)
            .map(|p| {
                format!(
                    "{} — {}\n{}",
                    p.protocol_name(),
                    p.description(),
                    p.metadata().summary()
                )
            })
            .unwrap_or_else(|e| e.to_string()),
        UiKey::Client(_) => crate::protocol::CLIENT_REGISTRY
            .resolve(&protocol)
            .map(|p| {
                format!(
                    "{} client — {}\n{}",
                    p.protocol_name(),
                    p.description(),
                    p.metadata().summary()
                )
            })
            .unwrap_or_else(|e| e.to_string()),
    };
    app.push_system(text);
}

/// Open the full request/response for one access-log entry.
fn open_request(app: &mut DashboardApp, key: UiKey, id: u64) {
    let entry = app
        .instance(key)
        .and_then(|i| i.requests().iter().find(|r| r.id == id).cloned());
    match entry {
        Some(entry) => app.modals.push(Modal::RequestDetail {
            entry: Box::new(entry),
            scroll: 0,
        }),
        None => app.push_system(format!(
            "request #{id} is no longer in the log (the per-instance log keeps the latest 100)"
        )),
    }
}

/// Open the answer modal for a pending intercept.
pub fn open_intercept(app: &mut DashboardApp, key: UiKey, intercept_id: u64, state: &AppState) {
    use crate::tui::modal::intercept::InterceptModel;

    let Some(instance) = app.instance(key) else {
        return;
    };
    let protocol = instance.protocol().to_string();
    let view = instance
        .intercepts()
        .iter()
        .find(|v| v.id == intercept_id)
        .cloned();
    let Some(view) = view else {
        app.push_system(format!(
            "request #{intercept_id} is no longer waiting (answered or timed out)"
        ));
        return;
    };
    let (_events, vocabulary) = crate::tui::modal::routing::vocabulary(key, &protocol, state);
    app.modals.push(Modal::Intercept(Box::new(InterceptModel {
        id: view.id,
        owner: key,
        protocol,
        event_type: view.event_type,
        description: view.description,
        event_data: view.event_data,
        vocabulary,
        error: None,
        focused: 0,
    })));
}

/// Which handler the routing editor should open on.
pub enum RouteTarget {
    /// The table itself, nothing opened.
    List,
    /// Edit an existing handler by index.
    Edit(usize),
    /// Start a new handler.
    New,
}

fn open_editor(app: &mut DashboardApp, key: UiKey) {
    use crate::tui::modal::form::FormModel;
    let model = match key {
        UiKey::Server(id) => app.server_row(id).map(FormModel::for_edit_server),
        UiKey::Client(id) => app.client_row(id).map(FormModel::for_edit_client),
    };
    if let Some(model) = model {
        app.modals.push(Modal::Form(Box::new(model)));
    }
}

/// Open the routing editor, optionally landing straight on one handler.
pub fn open_routing_at(app: &mut DashboardApp, key: UiKey, state: &AppState, target: RouteTarget) {
    use crate::tui::modal::routing::RoutingModel;
    let model = app
        .instance(key)
        .map(|i| RoutingModel::new(key, i.protocol(), i.routing(), state));
    if let Some(mut model) = model {
        match target {
            RouteTarget::List => {}
            RouteTarget::New => model.add(),
            RouteTarget::Edit(index) => {
                if index < model.handlers.len() {
                    model.selected = index;
                    model.edit_selected();
                }
            }
        }
        app.modals.push(Modal::Routing(Box::new(model)));
    }
}

/// Change the handler table without opening the editor: build the same
/// model the editor uses, apply `change`, and submit it the same way. The
/// change is described in chat; a failure lands there too.
fn edit_rules_headless(
    app: &mut DashboardApp,
    key: UiKey,
    state: &AppState,
    change: impl FnOnce(&mut crate::tui::modal::routing::RoutingModel) -> Option<String>,
) {
    use crate::tui::modal::routing::RoutingModel;
    let Some(mut model) = app
        .instance(key)
        .map(|i| RoutingModel::new(key, i.protocol(), i.routing(), state))
    else {
        return;
    };
    let Some(description) = change(&mut model) else {
        return;
    };
    app.push_system(format!("{}: {description}…", key.describe()));
    spawn_routing_apply(app, model, state);
}

fn spawn_routing_apply(
    app: &mut DashboardApp,
    model: crate::tui::modal::routing::RoutingModel,
    state: &AppState,
) {
    let llm = app.llm_client.clone();
    let status_tx = app.status_tx.clone();
    let ui_tx = app.ui_tx.clone();
    let state = state.clone();
    tokio::spawn(async move {
        let message = match model.apply(&state, llm, &status_tx).await {
            Ok(summary) => summary,
            Err(e) => format!("✗ {e}"),
        };
        let _ = ui_tx.send(UiMsg::Chat(message));
    });
}

/// Derive rules from the instance's model-authored answers and apply them in front of its
/// existing rules, keeping its fallback. What was derived, left undetermined or skipped goes
/// into the stream.
fn export_rules(app: &mut DashboardApp, key: UiKey, state: &AppState) {
    use crate::llm::rule_export::{apply_export, describe_export, export_rules, Fallback};
    let owner = match key {
        UiKey::Server(id) => crate::state::AccessLogOwner::Server(id.as_u32()),
        UiKey::Client(id) => crate::state::AccessLogOwner::Client(id.as_u32()),
    };
    app.push_system(format!(
        "{}: deriving rules from the model's answers…",
        key.describe()
    ));
    let llm = app.llm_client.clone();
    let ui_tx = app.ui_tx.clone();
    let state = state.clone();
    tokio::spawn(async move {
        let message = match export_rules(&state, owner, Fallback::Keep).await {
            Ok(export) if export.derived.rules.is_empty() => describe_export(&export),
            Ok(export) => match apply_export(&state, owner, &export, llm).await {
                Ok(outcome) => format!("{}{}", describe_export(&export), outcome.summary),
                Err(e) => format!("{}✗ {e}", describe_export(&export)),
            },
            Err(e) => format!("✗ {e}"),
        };
        let _ = ui_tx.send(UiMsg::Chat(message));
    });
}

/// MANUAL → LLM → SILENT → MANUAL, applied as a hot handler-table swap.
fn cycle_driver(app: &mut DashboardApp, key: UiKey, state: &AppState) {
    use crate::cli::management::{self, ClientForm, ServerForm};
    use crate::tui::driver::{driver_of, handlers_with_driver};

    let Some(instance) = app.instance(key) else {
        return;
    };
    let current = driver_of(instance.routing());
    let next = current.next();
    let handlers = handlers_with_driver(instance.routing(), next);
    let protocol = instance.protocol().to_string();
    app.push_system(format!(
        "{}: driver {} → {} — {}",
        key.describe(),
        current.label(),
        next.label(),
        next.describe()
    ));

    let llm = app.llm_client.clone();
    let status_tx = app.status_tx.clone();
    let ui_tx = app.ui_tx.clone();
    let state = state.clone();
    tokio::spawn(async move {
        let result = match key {
            UiKey::Server(id) => management::update_server(
                &state,
                id,
                ServerForm {
                    protocol,
                    event_handlers: Some(handlers),
                    ..Default::default()
                },
                status_tx,
            )
            .await
            .map(|o| o.summary),
            UiKey::Client(id) => management::update_client(
                &state,
                id,
                ClientForm {
                    protocol,
                    event_handlers: Some(handlers),
                    ..Default::default()
                },
                llm,
                status_tx,
            )
            .await
            .map(|o| o.summary),
        };
        let message = match result {
            Ok(summary) => summary,
            Err(e) => format!("✗ could not change the driver: {e}"),
        };
        let _ = ui_tx.send(UiMsg::Chat(message));
    });
}

/// The create form `[ + <proto> client ]` applies for a server: a client of the server
/// protocol's compiled counterpart (`protocol::compiled_client_protocol_for_server`), pointed
/// at 127.0.0.1 on the port the server actually bound, with an instruction naming the pair.
/// Copies usable server configuration (OpenAPI spec) and supplies known local endpoints.
/// `Err` says why there is none. Shared with the browser build's page API, so a page that
/// connects a client to one of its servers goes through exactly what the button does.
pub fn client_form_for_server(
    server_id: crate::state::ServerId,
    server_protocol: &str,
    local_addr: Option<&str>,
    port: u16,
    server_startup_params: Option<&serde_json::Value>,
) -> Result<crate::tui::modal::form::FormModel, String> {
    use crate::tui::modal::form::{FieldTarget, FormModel};
    let Some(client_protocol) =
        crate::protocol::compiled_client_protocol_for_server(server_protocol)
    else {
        return Err(format!(
            "{server_protocol} has no client implementation compiled into this build"
        ));
    };
    let address = loopback_target(local_addr, port);
    let http_url = format!("http://{address}");
    // These clients either default a bare address to HTTPS or require an absolute URL.
    // Our paired servers listen on plain HTTP, so make that choice explicit.
    let remote = match client_protocol.to_ascii_lowercase().as_str() {
        "npm" | "pypi" | "maven" | "openidconnect" => http_url.clone(),
        _ => address,
    };

    let mut model = FormModel::for_create(Section::Clients, &client_protocol, None);
    model.set_field_value(&FieldTarget::RemoteAddr, remote.clone());
    match client_protocol.to_ascii_lowercase().as_str() {
        "openapi" => {
            if let Some(spec) = server_startup_params
                .and_then(|params| params.get("spec"))
                .and_then(|spec| spec.as_str())
            {
                model.set_field_value(&FieldTarget::StartupParam("spec".into()), spec.into());
            }
            model.set_field_value(&FieldTarget::StartupParam("base_url".into()), http_url);
        }
        "oauth2" => {
            model.set_field_value(
                &FieldTarget::StartupParam("auth_url".into()),
                format!("{http_url}/authorize"),
            );
            model.set_field_value(
                &FieldTarget::StartupParam("token_url".into()),
                format!("{http_url}/token"),
            );
        }
        _ => {}
    }
    model.set_field_value(
        &FieldTarget::Instruction,
        format!(
            "You are a {client_protocol} client connected to our own server #{} at {remote}.",
            server_id.as_u32()
        ),
    );
    Ok(model)
}

/// Where a client of our own server connects: 127.0.0.1 on the port the server actually
/// bound (its configured port may be 0).
fn loopback_target(local_addr: Option<&str>, port: u16) -> String {
    let port = local_addr
        .and_then(|a| a.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()))
        .unwrap_or(port);
    format!("127.0.0.1:{port}")
}

/// `[ + client ]` on a server: create a client of the counterpart protocol
/// pointed at that very server, so the pair can talk to each other.
async fn open_client_for_server(
    app: &mut DashboardApp,
    server_id: crate::state::ServerId,
    state: &AppState,
) {
    let Some(row) = app.server_row(server_id) else {
        return;
    };
    let mut model = match client_form_for_server(
        server_id,
        &row.protocol,
        row.local_addr.as_deref(),
        row.port,
        row.startup_params.as_ref(),
    ) {
        Ok(model) => model,
        Err(why) => {
            app.push_system(why);
            return;
        }
    };
    let client_protocol = model.protocol.clone();
    let remote = loopback_target(row.local_addr.as_deref(), row.port);

    // When everything this client needs is known, connect it rather than
    // showing a form with nothing left to fill in. A client whose protocol
    // declares a required startup parameter (openai's api_key, say) cannot be
    // defaulted: show the form pre-filled, the cursor on the missing field.
    if let Some(missing) = model.missing_required() {
        model.focus_first_missing_required();
        model.error = Some(format!(
            "{client_protocol} needs {missing} before it can connect — fill it in and press [ Apply ]"
        ));
        app.modals.push(Modal::Form(Box::new(model)));
        return;
    }
    app.push_system(format!(
        "Connecting a {client_protocol} client to {remote}…"
    ));
    spawn_form_apply(app, model, state);
}

/// Apply a create/edit form off the event loop; the result closes the form
/// (success) or shows in it (failure) via `handle_ui_msg`.
pub fn spawn_form_apply(
    app: &mut DashboardApp,
    model: crate::tui::modal::form::FormModel,
    state: &AppState,
) {
    let llm = app.llm_client.clone();
    let status_tx = app.status_tx.clone();
    let ui_tx = app.ui_tx.clone();
    let state = state.clone();
    tokio::spawn(async move {
        let result = model
            .apply(&state, llm, &status_tx)
            .await
            .map_err(|e| e.to_string());
        let _ = ui_tx.send(UiMsg::ActionDone {
            origin: ActionOrigin::Form,
            result,
        });
    });
}

/// Compose an action for one live server connection. The vocabulary is the
/// server protocol's sync actions — its wire verbs (send_tcp_data and
/// friends), not its management ones.
fn open_peer_composer(
    app: &mut DashboardApp,
    server_id: crate::state::ServerId,
    connection_id: u32,
) {
    use crate::tui::modal::composer::ComposerModel;
    let Some(row) = app.server_row(server_id) else {
        return;
    };
    let Ok(protocol) = crate::protocol::server_registry::registry().resolve(&row.protocol) else {
        app.push_system(format!("{} is not a registered protocol", row.protocol));
        return;
    };
    let actions = protocol.get_sync_actions();
    if actions.is_empty() {
        app.push_system(format!("{} declares no wire actions to send", row.protocol));
        return;
    }
    let protocol_name = row.protocol.clone();
    app.modals
        .push(Modal::Composer(Box::new(ComposerModel::for_peer(
            server_id,
            connection_id,
            &protocol_name,
            actions,
        ))));
}

/// Close one live server connection from the server's side, through the
/// peer handle with the protocol's own `close_connection` action.
fn disconnect_peer(
    app: &mut DashboardApp,
    server_id: crate::state::ServerId,
    connection_id: u32,
    state: &AppState,
) {
    use crate::tui::modal::composer::{ComposerModel, ComposerTarget};
    let target = ComposerTarget::Peer {
        server: server_id,
        connection: connection_id,
    };
    app.push_system(format!("{}: disconnecting…", target.describe()));
    let ui_tx = app.ui_tx.clone();
    let state = state.clone();
    tokio::spawn(async move {
        let message = match ComposerModel::deliver(
            target,
            &state,
            serde_json::json!({"type": "close_connection"}),
        )
        .await
        {
            Ok(outcome) => format!(
                "{}: {}",
                target.describe(),
                crate::tui::modal::composer::describe(&outcome)
            ),
            Err(e) => e.to_string(),
        };
        let _ = ui_tx.send(UiMsg::Chat(message));
    });
}

/// Open the send composer for a client, optionally straight on one verb.
async fn open_composer(
    app: &mut DashboardApp,
    client_id: crate::state::ClientId,
    action_index: Option<usize>,
    state: &AppState,
) {
    let Some(row) = app.client_row(client_id) else {
        return;
    };
    match row.send_state {
        crate::tui::projection::SendState::Ready => {}
        crate::tui::projection::SendState::NotConnected => {
            app.push_system(format!(
                "client #{} is not connected — nothing to send through",
                client_id.as_u32()
            ));
            return;
        }
        crate::tui::projection::SendState::ProtocolUnsupported => {
            app.push_system(format!(
                "the {} client cannot take injected actions yet: its connection loop has not \
                 adopted the command channel (see src/client/command_support.rs)",
                row.protocol
            ));
            return;
        }
    }
    use crate::tui::modal::composer::ComposerModel;
    let protocol = row.protocol.clone();
    let wanted = action_index.and_then(|i| row.send_actions.get(i).map(|v| v.name.clone()));
    let actions = ComposerModel::vocabulary(&protocol, state);
    if actions.is_empty() {
        app.push_system(format!("{protocol} declares no client actions"));
        return;
    }
    let mut model = ComposerModel::new(client_id, &protocol, actions);
    if let Some(name) = wanted {
        // Look the verb up by name: the send section's rows are the vocabulary
        // minus response-only verbs, so their indices are not the composer's.
        if let Some(index) = model.actions.iter().position(|a| a.name == name) {
            model.selected = index;
            model.choose();
        }
    }
    app.modals.push(Modal::Composer(Box::new(model)));
}

/// Open the Wireshark recipe for a running instance, from the snapshot.
fn open_wireshark(app: &mut DashboardApp, key: UiKey) {
    use crate::tui::wireshark::{CapturePlan, CaptureTarget, Platform, Role};

    let target = match key {
        UiKey::Server(id) => {
            let Some(row) = app.server_row(id) else {
                return;
            };
            let bound: Option<std::net::SocketAddr> =
                row.local_addr.as_deref().and_then(|a| a.parse().ok());
            let param = |name: &str| -> Option<String> {
                row.startup_params
                    .as_ref()
                    .and_then(|p| p.get(name))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            };
            CaptureTarget {
                protocol: row.protocol.clone(),
                role: Role::Server,
                host: bound.map(|a| a.ip().to_string()).or_else(|| param("host")),
                port: bound.map(|a| a.port()).or(Some(row.port)),
                interface: param("interface"),
            }
        }
        UiKey::Client(id) => {
            let Some(row) = app.client_row(id) else {
                return;
            };
            CaptureTarget::client(&row.protocol, Some(&row.remote_addr))
        }
    };
    let plan = CapturePlan::build(target, Platform::current());
    app.modals.push(Modal::Wireshark {
        plan: Box::new(plan),
        scroll: 0,
    });
}

/// Open the protocol picker — servers and clients in one list. `prefill_remote`
/// aims a new client at a specific address.
pub async fn open_protocol_picker(
    app: &mut DashboardApp,
    prefill_remote: Option<String>,
    state: &AppState,
) {
    let caps = state.get_system_capabilities().await;
    let entries = crate::tui::modal::protocol_picker::all_entries(&caps);
    if entries.is_empty() {
        app.push_system("No protocols compiled into this build.");
        return;
    }
    app.modals.push(Modal::ProtocolPicker {
        entries,
        filter: String::new(),
        selected: 0,
        prefill_remote,
    });
}

/// Jump to the oldest parked request anywhere and open its answer modal.
pub fn answer_next_waiting(app: &mut DashboardApp, state: &AppState) {
    let mut oldest: Option<(u64, UiKey, u64)> = None;
    for s in &app.snapshot.servers {
        for v in &s.intercepts {
            if oldest
                .map(|(t, _, _)| v.created_unix_ms < t)
                .unwrap_or(true)
            {
                oldest = Some((v.created_unix_ms, UiKey::Server(s.id), v.id));
            }
        }
    }
    for c in &app.snapshot.clients {
        for v in &c.intercepts {
            if oldest
                .map(|(t, _, _)| v.created_unix_ms < t)
                .unwrap_or(true)
            {
                oldest = Some((v.created_unix_ms, UiKey::Client(c.id), v.id));
            }
        }
    }
    match oldest {
        Some((_, key, id)) => {
            app.focus_card(key);
            open_intercept(app, key, id, state);
        }
        None => app.push_system("nothing is waiting for you"),
    }
}
