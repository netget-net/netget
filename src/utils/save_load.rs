//! Save/load utility for persisting server and client configurations
//!
//! This module handles serializing server/client state to action arrays
//! and saving them to `.netget` files, as well as loading and parsing them.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use crate::state::app_state::AppState;
use crate::state::client::ClientId;
use crate::state::server::ServerId;

/// File extension for NetGet save files
pub const NETGET_EXTENSION: &str = ".netget";
pub const MAX_SESSION_BYTES: usize = 16 * 1024 * 1024;

/// Normalize a filename to ensure it has the correct extension
/// Strips any existing extension and adds .netget
pub fn normalize_filename(name: &str) -> String {
    let name = name.trim();
    if name.is_empty() {
        return NETGET_EXTENSION.to_string();
    }
    if name.ends_with(NETGET_EXTENSION) {
        return name.to_string();
    }
    // Replace only the extension, retaining the caller's directory. Using file_stem()
    // alone redirected `/some/directory/config.json` into the working directory.
    Path::new(name)
        .with_extension(&NETGET_EXTENSION[1..])
        .to_string_lossy()
        .into_owned()
}

/// Convert a server instance to an open_server action
fn server_to_action(server: &crate::state::server::ServerInstance) -> Value {
    let mut action = json!({
        "type": "open_server",
        "port": server.port,
        "base_stack": server.protocol_name,
        "instruction": server.instruction,
    });

    if let Some(address) = server.local_addr {
        action["host"] = json!(address.ip().to_string());
    }

    // Add optional fields if present
    if !server.memory.is_empty() {
        action["initial_memory"] = json!(server.memory);
    }

    if let Some(ref params) = server.startup_params {
        action["startup_params"] = params.clone();
    }

    if let Some(ref config) = server.event_handler_config {
        action["event_handlers"] = json!(config.handlers);
    }
    if let Some(ref instruction) = server.feedback_instructions {
        action["feedback_instructions"] = json!(instruction);
    }
    let declared = crate::protocol::server_registry::registry()
        .resolve(&server.protocol_name)
        .ok()
        .map(|p| p.metadata());
    record_conversation(
        &mut action,
        declared.as_ref(),
        server.history_entries,
        server.batching,
    );

    // Note: send_first is protocol-specific and not stored in ServerInstance
    // It will use protocol defaults when recreated

    action
}

/// Convert a client instance to an open_client action
fn client_to_action(client: &crate::state::client::ClientInstance) -> Value {
    let mut action = json!({
        "type": "open_client",
        "protocol": client.protocol_name,
        "remote_addr": client.remote_addr,
        "instruction": client.instruction,
    });

    // Add optional fields if present
    if !client.memory.is_empty() {
        action["initial_memory"] = json!(client.memory);
    }

    if let Some(ref params) = client.startup_params {
        action["startup_params"] = params.clone();
    }

    if let Some(ref config) = client.event_handler_config {
        action["event_handlers"] = json!(config.handlers);
    }
    if let Some(ref instruction) = client.feedback_instructions {
        action["feedback_instructions"] = json!(instruction);
    }
    let declared = crate::protocol::CLIENT_REGISTRY
        .resolve(&client.protocol_name)
        .ok()
        .map(|p| p.metadata());
    record_conversation(
        &mut action,
        declared.as_ref(),
        client.history_entries,
        client.batching,
    );

    action
}

/// Save `history` / `batching` only where the instance departs from its protocol's declared
/// default, so a saved file follows the protocol if the default is later changed.
fn record_conversation(
    action: &mut Value,
    declared: Option<&crate::protocol::metadata::ProtocolMetadataV2>,
    history_entries: u16,
    batching: bool,
) {
    let (default_history, default_batching) = declared
        .map(|m| (m.history.entries(), m.batching.default_enabled()))
        .unwrap_or((0, false));
    if history_entries != default_history {
        action["history"] = json!(history_entries);
    }
    if batching != default_batching {
        action["batching"] = json!(batching);
    }
}

/// Save all servers and clients to a file
pub async fn save_all(state: &AppState, filename: &str) -> Result<PathBuf> {
    let mut servers = state.get_all_servers().await;
    let mut clients = state.get_all_clients().await;
    servers.sort_by_key(|item| item.id.as_u32());
    clients.sort_by_key(|item| item.id.as_u32());
    let tasks = state.get_all_tasks().await;
    let pipes = state.list_pipes().await;
    let easy = state.get_all_easy_instances().await;
    let mut actions = Vec::new();
    let mut resources = Vec::new();
    for server in servers {
        let mut action = server_to_action(&server);
        attach_tasks(
            &mut action,
            &tasks,
            &crate::state::task::TaskScope::Server(server.id),
        )?;
        resources.push(json!({"key": server.id.as_u32(), "action": action}));
        actions.push(action);
    }
    for client in clients {
        let mut action = client_to_action(&client);
        attach_tasks(
            &mut action,
            &tasks,
            &crate::state::task::TaskScope::Client(client.id),
        )?;
        resources.push(json!({"key": client.id.as_u32(), "action": action}));
        actions.push(action);
    }
    let global_tasks: Vec<_> = tasks
        .iter()
        .filter(|task| matches!(task.scope, crate::state::task::TaskScope::Global))
        .filter_map(task_definition)
        .collect();
    if !pipes.is_empty() || !easy.is_empty() || !global_tasks.is_empty() {
        let wrappers: Vec<_> = easy
            .into_iter()
            .filter(|item| {
                item.underlying_server_id.is_some() || item.underlying_client_id.is_some()
            })
            .map(|item| {
                json!({
                    "protocol": item.protocol_name, "underlying_protocol": item.underlying_protocol,
                    "instruction": item.user_instruction,
                    "server": item.underlying_server_id.map(|id| id.as_u32()),
                    "client": item.underlying_client_id.map(|id| id.as_u32()),
                })
            })
            .collect();
        actions = vec![json!({"type": "restore_session", "session": {
            "version": 2, "resources": resources, "pipes": pipes,
            "easy": wrappers, "global_tasks": global_tasks,
        }})];
    }
    save_actions(actions, filename).await
}

/// Save a specific server to a file
pub async fn save_server(state: &AppState, server_id: ServerId, filename: &str) -> Result<PathBuf> {
    let server = state
        .get_server(server_id)
        .await
        .context("Server not found")?;

    let mut action = server_to_action(&server);
    attach_tasks(
        &mut action,
        &state.get_all_tasks().await,
        &crate::state::task::TaskScope::Server(server_id),
    )?;
    let actions = vec![action];
    save_actions(actions, filename).await
}

/// Save a specific client to a file
pub async fn save_client(state: &AppState, client_id: ClientId, filename: &str) -> Result<PathBuf> {
    let client = state
        .get_client(client_id)
        .await
        .context("Client not found")?;

    let mut action = client_to_action(&client);
    attach_tasks(
        &mut action,
        &state.get_all_tasks().await,
        &crate::state::task::TaskScope::Client(client_id),
    )?;
    let actions = vec![action];
    save_actions(actions, filename).await
}

/// Save one server or client to a `.netget` file with `event_handlers` replaced by
/// `handlers` — the table `export_rules` builds — so `--load` starts it answering from those
/// rules. Everything else is saved as [`save_server`] / [`save_client`] would save it.
pub async fn save_with_handlers(
    state: &AppState,
    owner: crate::state::AccessLogOwner,
    handlers: &[Value],
    filename: &str,
) -> Result<PathBuf> {
    let (mut action, scope) = match owner {
        crate::state::AccessLogOwner::Server(id) => {
            let server = state
                .get_server(ServerId::new(id))
                .await
                .context("Server not found")?;
            (
                server_to_action(&server),
                crate::state::task::TaskScope::Server(server.id),
            )
        }
        crate::state::AccessLogOwner::Client(id) => {
            let client = state
                .get_client(ClientId::new(id))
                .await
                .context("Client not found")?;
            (
                client_to_action(&client),
                crate::state::task::TaskScope::Client(client.id),
            )
        }
    };
    action["event_handlers"] = Value::Array(handlers.to_vec());
    attach_tasks(&mut action, &state.get_all_tasks().await, &scope)?;
    save_actions(vec![action], filename).await
}

/// Save an array of actions to a file
async fn save_actions(actions: Vec<Value>, filename: &str) -> Result<PathBuf> {
    let filename = normalize_filename(filename);
    let path = PathBuf::from(&filename);

    // Wrap actions in the standard LLM format: {"actions": [...]}
    let wrapped = json!({
        "actions": actions
    });

    // Serialize to pretty JSON
    let json =
        serde_json::to_string_pretty(&wrapped).context("Failed to serialize actions to JSON")?;

    if json.len() > MAX_SESSION_BYTES {
        anyhow::bail!("session exceeds the 16 MiB save limit");
    }
    crate::utils::file_io::write_atomic_async(&path, json.into_bytes())
        .await
        .with_context(|| format!("Failed to save {}", path.display()))?;

    Ok(path)
}

/// Load actions from a file
pub async fn load_actions(filename: &str) -> Result<Vec<Value>> {
    // Normalize filename (add .netget if missing)
    let filename = normalize_filename(filename);

    // Read file
    let content = crate::utils::file_io::read_text_async(Path::new(&filename), MAX_SESSION_BYTES)
        .await
        .context(format!("Failed to read file: {}", filename))?;

    // Parse JSON - expect {"actions": [...]} format
    let parsed: Value = serde_json::from_str(&content)
        .context(format!("Failed to parse JSON from file: {}", filename))?;

    // Extract actions array
    let actions = parsed
        .get("actions")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("File must contain {{\"actions\": [...]}} format"))?
        .clone();

    Ok(actions)
}

/// Check if a string is a valid actions JSON in {"actions": [...]} format
pub fn is_actions_json(input: &str) -> bool {
    // Try to parse as JSON object
    if let Ok(value) = serde_json::from_str::<Value>(input) {
        // Check for {"actions": [...]} format
        if let Some(actions) = value.get("actions").and_then(|v| v.as_array()) {
            // Check if all elements have a "type" field
            return !actions.is_empty()
                && actions.iter().all(|item| {
                    item.as_object()
                        .and_then(|obj| obj.get("type"))
                        .and_then(|t| t.as_str())
                        .is_some()
                });
        }
    }
    false
}

fn task_definition(
    task: &crate::state::task::ScheduledTask,
) -> Option<crate::llm::actions::common::ServerTaskDefinition> {
    use crate::state::task::{TaskStatus, TaskType};
    if !matches!(task.status, TaskStatus::Scheduled | TaskStatus::Executing) {
        return None;
    }
    let (recurring, interval_secs, max_executions) = match task.task_type {
        TaskType::OneShot { .. } => (false, None, None),
        TaskType::Recurring {
            interval_secs,
            max_executions,
            executions_count,
        } => {
            let remaining = max_executions.map(|max| max.saturating_sub(executions_count));
            if remaining == Some(0) {
                return None;
            }
            (true, Some(interval_secs), remaining)
        }
    };
    let delay = task
        .next_execution
        .saturating_duration_since(crate::utils::clock::Instant::now());
    let delay_secs = delay
        .as_secs()
        .saturating_add(u64::from(delay.subsec_nanos() != 0));
    Some(crate::llm::actions::common::ServerTaskDefinition {
        task_id: task.name.clone(),
        recurring,
        delay_secs: Some(delay_secs),
        interval_secs,
        max_executions,
        instruction: task.instruction.clone(),
        context: task.context.clone(),
    })
}

fn attach_tasks(
    action: &mut Value,
    tasks: &[crate::state::task::ScheduledTask],
    scope: &crate::state::task::TaskScope,
) -> Result<()> {
    use crate::state::task::TaskScope;
    let definitions: Vec<_> = tasks
        .iter()
        .filter(|task| match (&task.scope, scope) {
            (TaskScope::Server(a), TaskScope::Server(b)) => a == b,
            (TaskScope::Client(a), TaskScope::Client(b)) => a == b,
            _ => false,
        })
        .filter_map(task_definition)
        .collect();
    if !definitions.is_empty() {
        action["scheduled_tasks"] = serde_json::to_value(definitions)?;
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedResource {
    key: u32,
    action: Value,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedEasy {
    protocol: String,
    underlying_protocol: String,
    instruction: Option<String>,
    server: Option<u32>,
    client: Option<u32>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedSession {
    version: u32,
    resources: Vec<SavedResource>,
    #[serde(default)]
    pipes: Vec<crate::pipe::PipeSpec>,
    #[serde(default)]
    easy: Vec<SavedEasy>,
    #[serde(default)]
    global_tasks: Vec<crate::llm::actions::common::ServerTaskDefinition>,
}

/// Restore configuration relationships using newly allocated IDs. Connections,
/// transient request queues and in-flight responses are deliberately not resumed.
/// On startup failure, remove resources created by this restore; existing state
/// is never used as a rollback target.
pub async fn restore_session(
    state: &AppState,
    llm: &crate::llm::OllamaClient,
    value: &Value,
) -> Result<()> {
    use crate::cli::management::{ClientForm, ServerForm};
    use crate::state::task::{prepare_tasks, TaskScope};
    use crate::state::{EasyId, EasyInstance, EasyStatus};
    use std::collections::{HashMap, HashSet};
    if !crate::utils::json_budget::within_budget(value, MAX_SESSION_BYTES * 4, 100_000, 64) {
        anyhow::bail!("session exceeds the structural budget");
    }
    let session: SavedSession =
        serde_json::from_value(value.clone()).context("invalid session format")?;
    if session.version != 2 {
        anyhow::bail!("unsupported session version {}", session.version);
    }
    enum Form {
        Server(u32, ServerForm),
        Client(u32, ClientForm),
    }
    let mut forms = Vec::new();
    let mut server_keys = HashSet::new();
    let mut client_keys = HashSet::new();
    let mut all_keys = HashSet::new();
    let mut protocols = HashMap::new();
    for resource in session.resources {
        if !all_keys.insert(resource.key) {
            anyhow::bail!("duplicate saved resource key {}", resource.key);
        }
        let mut action = resource.action;
        let object = action
            .as_object_mut()
            .context("saved resource action must be an object")?;
        if !object.contains_key("protocol") {
            object.insert(
                "protocol".into(),
                object.get("base_stack").cloned().unwrap_or(Value::Null),
            );
        }
        match action["type"].as_str() {
            Some("open_server") => {
                let form: ServerForm = serde_json::from_value(action)?;
                prepare_tasks(form.scheduled_tasks.as_deref(), TaskScope::Global)?;
                protocols.insert(resource.key, form.protocol.clone());
                server_keys.insert(resource.key);
                forms.push(Form::Server(resource.key, form));
            }
            Some("open_client") => {
                let form: ClientForm = serde_json::from_value(action)?;
                prepare_tasks(form.scheduled_tasks.as_deref(), TaskScope::Global)?;
                protocols.insert(resource.key, form.protocol.clone());
                client_keys.insert(resource.key);
                forms.push(Form::Client(resource.key, form));
            }
            _ => anyhow::bail!("session resources must be open_server or open_client"),
        }
    }
    let global_tasks = prepare_tasks(Some(&session.global_tasks), TaskScope::Global)?;
    let mut checked_pipes = Vec::new();
    for pipe in &session.pipes {
        if !server_keys.contains(&pipe.from) || !server_keys.contains(&pipe.to) {
            anyhow::bail!("saved pipe references a missing server");
        }
        if crate::pipe::would_create_cycle(&checked_pipes, pipe.from, pipe.to) {
            anyhow::bail!("saved pipe graph contains a cycle");
        }
        checked_pipes.push(pipe.clone());
    }
    let mut wrapped_keys = HashSet::new();
    for easy in &session.easy {
        let known = crate::protocol::EASY_REGISTRY
            .get_by_name(&easy.protocol)
            .with_context(|| format!("unknown saved easy protocol {}", easy.protocol))?;
        if known.underlying_protocol() != easy.underlying_protocol {
            anyhow::bail!("saved easy underlying protocol does not match its registry");
        }
        if easy.server.is_some() == easy.client.is_some()
            || easy.server.is_some_and(|key| !server_keys.contains(&key))
            || easy.client.is_some_and(|key| !client_keys.contains(&key))
        {
            anyhow::bail!("saved easy wrapper must reference exactly one existing resource");
        }
        let key = easy
            .server
            .or(easy.client)
            .expect("validated resource reference");
        if !protocols[&key].eq_ignore_ascii_case(&easy.underlying_protocol) {
            anyhow::bail!("saved easy wrapper protocol differs from its resource");
        }
        if !wrapped_keys.insert(key) {
            anyhow::bail!("multiple easy wrappers reference the same resource");
        }
    }
    let mut servers = HashMap::new();
    let mut clients = HashMap::new();
    let mut ownership = RestoreOwnership::new(state.clone());
    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel();
    ownership.printer = Some(tokio::spawn(async move {
        while let Some(line) = status_rx.recv().await {
            tracing::info!("{line}");
        }
    }));
    let result: Result<()> = async {
        for form in forms {
            match form {
                Form::Server(key, form) => {
                    let id = form.create(state, status_tx.clone()).await?;
                    ownership.servers.push(id);
                    servers.insert(key, id);
                }
                Form::Client(key, form) => {
                    let id = form.create(state, llm.clone(), status_tx.clone()).await?;
                    ownership.clients.push(id);
                    clients.insert(key, id);
                }
            }
        }
        for pipe in session.pipes {
            state
                .add_pipe(
                    servers[&pipe.from],
                    pipe.on,
                    servers[&pipe.to],
                    pipe.as_action,
                    pipe.map,
                )
                .await?;
        }
        for easy in session.easy {
            let instance = EasyInstance::new(
                EasyId::new(0),
                easy.protocol,
                easy.underlying_protocol,
                easy.instruction,
            );
            let id = state.add_easy_instance(instance).await;
            ownership.easy.push(id);
            if let Some(key) = easy.server {
                state.link_server_to_easy(servers[&key], id).await;
            }
            if let Some(key) = easy.client {
                state.link_client_to_easy(clients[&key], id).await;
            }
            state.update_easy_status(id, EasyStatus::Running).await;
        }
        for task in global_tasks {
            ownership.tasks.push(state.add_task(task).await);
        }
        Ok(())
    }
    .await;
    drop(status_tx);
    if let Some(printer) = ownership.printer.take() {
        printer.abort();
    }
    if result.is_err() {
        ownership.rollback().await;
    } else {
        ownership.committed = true;
    }
    result
}

struct RestoreOwnership {
    state: AppState,
    servers: Vec<ServerId>,
    clients: Vec<ClientId>,
    easy: Vec<crate::state::EasyId>,
    tasks: Vec<crate::state::task::TaskId>,
    printer: Option<tokio::task::JoinHandle<()>>,
    committed: bool,
}
impl RestoreOwnership {
    fn new(state: AppState) -> Self {
        Self {
            state,
            servers: Vec::new(),
            clients: Vec::new(),
            easy: Vec::new(),
            tasks: Vec::new(),
            printer: None,
            committed: false,
        }
    }
    async fn rollback(&mut self) {
        while let Some(id) = self.tasks.last().copied() {
            self.state.remove_task(id).await;
            self.tasks.pop();
        }
        while let Some(id) = self.easy.last().copied() {
            self.state.remove_easy_instance(id).await;
            self.easy.pop();
        }
        while let Some(id) = self.clients.last().copied() {
            self.state.remove_client(id).await;
            self.clients.pop();
        }
        while let Some(id) = self.servers.last().copied() {
            self.state.remove_server(id).await;
            self.servers.pop();
        }
        self.committed = true;
    }
}
impl Drop for RestoreOwnership {
    fn drop(&mut self) {
        if let Some(printer) = self.printer.take() {
            printer.abort();
        }
        if self.committed {
            return;
        }
        let mut cleanup = Self::new(self.state.clone());
        cleanup.servers = std::mem::take(&mut self.servers);
        cleanup.clients = std::mem::take(&mut self.clients);
        cleanup.easy = std::mem::take(&mut self.easy);
        cleanup.tasks = std::mem::take(&mut self.tasks);
        cleanup.committed = true; // Runtime shutdown must not recursively spawn cleanup.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                cleanup.rollback().await;
            });
        }
    }
}
