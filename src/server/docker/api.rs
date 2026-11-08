//! Docker Engine API routing and response rendering.
//!
//! Everything here is pure: a path in, a [`Route`] out; a model's structured answer in, the JSON
//! document the Docker CLI decodes out. The model names the things that matter to a user —
//! container names, images, states, ports — and NetGet fills the fields a Go decoder needs but
//! nobody reads (`HostConfig`, `NetworkSettings`, `SharedSize`, the `Components` list) with valid
//! defaults, so a model that forgets one cannot make `docker ps` fail to decode.
//!
//! Every renderer validates first and returns a reason on refusal: an unknown container state,
//! a port outside 1..=65535, a name with characters Docker itself refuses. Recursion: none.

use serde_json::{json, Map, Value};

/// Oldest API version accepted in a `/v1.xx/` path prefix. The Docker CLI negotiates down to
/// whatever `/_ping` advertises, and 1.24 is the floor every current daemon still honours.
pub const MIN_API_VERSION: &str = "1.24";

/// What a request path resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// `GET`/`HEAD /_ping` — served statically, it is how the client negotiates.
    Ping,
    /// `GET /version`
    Version,
    /// `GET /info`
    Info,
    /// `GET /containers/json`
    ContainerList,
    /// `GET /containers/{id}/json`
    ContainerInspect(String),
    /// `GET /images/json`
    ImageList,
    /// `GET /networks`
    NetworkList,
    /// `GET /volumes`
    VolumeList,
    /// A method that changes state (create, start, exec, pull, delete…). Refused with 501.
    Mutating,
    /// Anything else. 404.
    NotFound,
}

impl Route {
    /// The `resource` field of the event, or `None` for routes that never reach the model.
    pub fn resource(&self) -> Option<&'static str> {
        match self {
            Route::Version => Some("version"),
            Route::Info => Some("info"),
            Route::ContainerList => Some("containers"),
            Route::ContainerInspect(_) => Some("container"),
            Route::ImageList => Some("images"),
            Route::NetworkList => Some("networks"),
            Route::VolumeList => Some("volumes"),
            Route::Ping | Route::Mutating | Route::NotFound => None,
        }
    }

    /// The one action that answers this route (besides `send_docker_error`).
    pub fn answering_action(&self) -> Option<&'static str> {
        match self {
            Route::Version => Some("send_docker_version"),
            Route::Info => Some("send_docker_info"),
            Route::ContainerList => Some("send_docker_containers"),
            Route::ContainerInspect(_) => Some("send_docker_container"),
            Route::ImageList => Some("send_docker_images"),
            Route::NetworkList => Some("send_docker_networks"),
            Route::VolumeList => Some("send_docker_volumes"),
            Route::Ping | Route::Mutating | Route::NotFound => None,
        }
    }

    /// The event's `answer_with`: which action answers this request, and what it must say.
    ///
    /// The event description maps every resource to its action, but a small model answering
    /// one request reads the request, not the table: asked to inspect a container that did not
    /// exist, llama3.1:8b answered with `send_docker_version`. Naming the action, and the 404
    /// for a missing container, in the request itself is what it follows.
    ///
    /// A list route names the array the action carries, not just the action: told only
    /// "send_docker_containers with the running containers", the same model answered with
    /// `{"type": "send_docker_containers"}` and nothing in it, 13 times in 15.
    pub fn answer_with(&self, query: &Value) -> Option<String> {
        let all = query.get("all").and_then(Value::as_str) == Some("1");
        Some(match self {
            Route::Version => "send_docker_version".to_string(),
            Route::Info => "send_docker_info".to_string(),
            Route::ContainerList if all => "send_docker_containers with a containers array \
                 holding every container, running or not, each with its names, image and state \
                 (a stopped container has state exited and its exit_code)"
                .to_string(),
            Route::ContainerList => "send_docker_containers with a containers array holding \
                 the running containers, each with its names, image and state"
                .to_string(),
            Route::ContainerInspect(id) => format!(
                "send_docker_container with the fields of the container named {id} (or whose \
                 ID starts with {id}); if there is no such container, send_docker_error with \
                 status 404 and message \"No such container: {id}\""
            ),
            Route::ImageList => "send_docker_images with an images array".to_string(),
            Route::NetworkList => "send_docker_networks with a networks array".to_string(),
            Route::VolumeList => "send_docker_volumes with a volumes array".to_string(),
            Route::Ping | Route::Mutating | Route::NotFound => return None,
        })
    }
}

/// Split an optional `/v<major>.<minor>` prefix off a path.
///
/// Returns the version as written (`"1.45"`) and the rest of the path. A first segment that
/// starts with `v` but is not a version is left alone, so it routes to a 404 rather than being
/// mistaken for one.
pub fn split_version(path: &str) -> (Option<String>, String) {
    let trimmed = path.trim_start_matches('/');
    let (first, rest) = match trimmed.split_once('/') {
        Some((f, r)) => (f, format!("/{r}")),
        None => (trimmed, "/".to_string()),
    };
    if let Some(v) = first.strip_prefix('v') {
        if parse_version(v).is_some() {
            return (Some(v.to_string()), rest);
        }
    }
    (None, path.to_string())
}

/// `"1.45"` → `(1, 45)`.
pub fn parse_version(v: &str) -> Option<(u32, u32)> {
    let (major, minor) = v.split_once('.')?;
    if major.is_empty() || minor.is_empty() || major.len() > 3 || minor.len() > 3 {
        return None;
    }
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Resolve a method and an unversioned path.
pub fn resolve(method: &str, path: &str) -> Route {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let is_read = method == "GET" || method == "HEAD";
    match segments.as_slice() {
        ["_ping"] if is_read => Route::Ping,
        _ if !is_read => Route::Mutating,
        ["version"] => Route::Version,
        ["info"] => Route::Info,
        ["containers", "json"] => Route::ContainerList,
        ["containers", id, "json"] if !id.is_empty() => Route::ContainerInspect(id.to_string()),
        ["images", "json"] => Route::ImageList,
        ["networks"] => Route::NetworkList,
        ["volumes"] => Route::VolumeList,
        _ => Route::NotFound,
    }
}

/// The body of every Docker error: `{"message": "..."}`.
pub fn error_body(message: &str) -> Value {
    json!({ "message": message })
}

// ---------------------------------------------------------------------------
// Field helpers
// ---------------------------------------------------------------------------

/// First present key among `names` — models write both `image` and Docker's own `Image`.
fn field<'a>(obj: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names
        .iter()
        .find_map(|n| obj.get(*n))
        .filter(|v| !v.is_null())
}

fn str_field(obj: &Value, names: &[&str]) -> Option<String> {
    field(obj, names).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn u64_field(obj: &Value, names: &[&str], what: &str) -> Result<Option<u64>, String> {
    match field(obj, names) {
        None => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{what} must be a non-negative integer")),
        Some(Value::String(s)) => s
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| format!("{what} must be a non-negative integer, got {s:?}")),
        Some(_) => Err(format!("{what} must be a number")),
    }
}

fn string_map(obj: &Value, names: &[&str], what: &str) -> Result<Map<String, Value>, String> {
    match field(obj, names) {
        None => Ok(Map::new()),
        Some(Value::Object(m)) => {
            let mut out = Map::new();
            for (k, v) in m {
                let text = match v {
                    Value::String(s) => s.clone(),
                    Value::Null => String::new(),
                    other => other.to_string(),
                };
                out.insert(k.clone(), Value::String(text));
            }
            Ok(out)
        }
        Some(_) => Err(format!("{what} must be an object of strings")),
    }
}

fn string_list(obj: &Value, names: &[&str]) -> Vec<String> {
    match field(obj, names) {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// A 64-hex identifier derived from `seed`, for objects the model named but gave no ID.
///
/// Deterministic, so the same container keeps the same ID across `ps` and `inspect`. Not a
/// digest of anything, and nothing treats it as one.
pub fn derived_id(seed: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut out = String::with_capacity(64);
    for round in 0u8..4 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        (round, seed).hash(&mut h);
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_alphanumeric())
}

/// The ID a container or image is rendered with, from the `id` the model gave.
///
/// Letters and digits are used as given. A model very often writes the object's *name* as its
/// ID (`"id": "eval-web"`); that is not an ID Docker would ever report, and it is not an error
/// either, so a name-shaped value stands in for the seed a missing ID is derived from — the
/// same 64-hex ID as omitting it, so `ps` and `inspect` still agree. Anything else (spaces,
/// slashes, punctuation) is refused. Either way the client only ever receives letters and
/// digits.
fn id_from(given: &str, kind: &str, what: &str) -> Result<String, String> {
    let bare = given.trim_start_matches("sha256:");
    if valid_id(bare) {
        Ok(bare.to_string())
    } else if valid_name(bare) {
        Ok(derived_id(&format!("{kind}:{bare}")))
    } else {
        Err(format!(
            "{what}: id {given:?} must be letters and digits (or omit it and NetGet derives one)"
        ))
    }
}

/// Docker's own rule for container names: `[a-zA-Z0-9][a-zA-Z0-9_.-]+`.
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        && name.len() <= 255
}

fn now_unix() -> i64 {
    crate::utils::clock::SystemTime::now()
        .duration_since(crate::utils::clock::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A creation time given as unix seconds or RFC 3339, as unix seconds.
///
/// A blank string is no creation time, the same as leaving the field out. Told only which
/// containers exist, llama3.1:8b fills every field of the example with an empty value
/// (`"created": ""`, `"status": ""`, `"ip": ""`), and refusing the whole listing over the one
/// field the instruction never mentioned failed `docker ps -a` on two seeds in five.
fn created_unix(obj: &Value, what: &str) -> Result<i64, String> {
    match field(obj, &["created", "Created", "created_at", "CreatedAt"]) {
        None => Ok(now_unix()),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(now_unix()),
        Some(Value::Number(n)) => n
            .as_i64()
            .ok_or_else(|| format!("{what} created must be unix seconds or RFC 3339")),
        Some(Value::String(s)) => chrono::DateTime::parse_from_rfc3339(s.trim())
            .map(|t| t.timestamp())
            .or_else(|_| s.trim().parse::<i64>())
            .map_err(|_| format!("{what} created {s:?} is neither unix seconds nor RFC 3339")),
        Some(_) => Err(format!("{what} created must be unix seconds or RFC 3339")),
    }
}

fn rfc3339(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
        .unwrap_or_else(|| "0001-01-01T00:00:00Z".to_string())
}

const STATES: &[&str] = &[
    "created",
    "running",
    "paused",
    "restarting",
    "removing",
    "exited",
    "dead",
];

fn state_of(obj: &Value, what: &str) -> Result<String, String> {
    let raw = match field(obj, &["state", "State"]) {
        None => "running".to_string(),
        Some(Value::String(s)) => s.to_ascii_lowercase(),
        // An inspect-shaped State object from a model that copied `docker inspect`.
        Some(Value::Object(o)) => o
            .get("Status")
            .or_else(|| o.get("status"))
            .and_then(Value::as_str)
            .unwrap_or("running")
            .to_ascii_lowercase(),
        Some(_) => return Err(format!("{what} state must be a string")),
    };
    // `docker stop` leaves a container `exited`; "stopped" is what people call that, and
    // what a model writes when told a container is stopped.
    let raw = if raw == "stopped" {
        "exited".to_string()
    } else {
        raw
    };
    if STATES.contains(&raw.as_str()) {
        Ok(raw)
    } else {
        Err(format!(
            "{what} state {raw:?} is not one of {}",
            STATES.join(", ")
        ))
    }
}

fn default_status(state: &str, exit_code: i64) -> String {
    match state {
        "running" => "Up".to_string(),
        "paused" => "Up (Paused)".to_string(),
        "restarting" => "Restarting".to_string(),
        "exited" => format!("Exited ({exit_code})"),
        "created" => "Created".to_string(),
        "removing" => "Removal In Progress".to_string(),
        _ => "Dead".to_string(),
    }
}

/// The `Status` column. The model's own wording is kept, except that an exited container's
/// always carries its exit code the way the daemon writes it — `Exited (0) 10 minutes ago` —
/// because that code is the one fact the column exists to show, and a model writing
/// "Exited 10 minutes ago" or "Stopped" leaves it out.
fn status_of(given: Option<String>, state: &str, exit_code: i64) -> String {
    let Some(given) = given.filter(|s| !s.trim().is_empty()) else {
        return default_status(state, exit_code);
    };
    if state != "exited" || given.starts_with("Exited (") {
        return given;
    }
    let lower = given.to_ascii_lowercase();
    let ago = lower.find(" ago").and_then(|end| {
        let words: Vec<&str> = given[..end].split_whitespace().collect();
        // "… 10 minutes ago", "… About an hour ago": the last two words before "ago".
        (words.len() >= 2)
            .then(|| format!("{} {} ago", words[words.len() - 2], words[words.len() - 1]))
    });
    match ago {
        Some(ago) => format!("Exited ({exit_code}) {ago}"),
        None => default_status(state, exit_code),
    }
}

/// `[{private_port, public_port?, type?, ip?}]` → the list shape `docker ps` renders.
fn ports(obj: &Value, what: &str) -> Result<Vec<Value>, String> {
    let Some(list) = field(obj, &["ports", "Ports"]) else {
        return Ok(Vec::new());
    };
    let Value::Array(list) = list else {
        return Err(format!("{what} ports must be an array"));
    };
    let mut out = Vec::with_capacity(list.len());
    for p in list {
        let private = u64_field(
            p,
            &["private_port", "PrivatePort", "container_port"],
            "private_port",
        )?
        .ok_or_else(|| format!("{what} port entry needs a private_port"))?;
        if !(1..=65535).contains(&private) {
            return Err(format!("{what} private_port {private} is not a port"));
        }
        let kind = str_field(p, &["type", "Type", "protocol"])
            .unwrap_or_else(|| "tcp".to_string())
            .to_ascii_lowercase();
        if !matches!(kind.as_str(), "tcp" | "udp" | "sctp") {
            return Err(format!("{what} port type {kind:?} is not tcp, udp or sctp"));
        }
        let mut entry = json!({"PrivatePort": private, "Type": kind});
        if let Some(public) = u64_field(
            p,
            &["public_port", "PublicPort", "host_port"],
            "public_port",
        )? {
            if !(1..=65535).contains(&public) {
                return Err(format!("{what} public_port {public} is not a port"));
            }
            entry["PublicPort"] = json!(public);
            entry["IP"] = json!(
                str_field(p, &["ip", "IP", "host_ip"]).unwrap_or_else(|| "0.0.0.0".to_string())
            );
        }
        out.push(entry);
    }
    Ok(out)
}

/// The command as one string (`docker ps`) and as path + args (`docker inspect`).
fn command_of(obj: &Value) -> (String, String, Vec<String>) {
    match field(obj, &["command", "Command", "cmd", "Cmd"]) {
        Some(Value::Array(parts)) => {
            let parts: Vec<String> = parts
                .iter()
                .filter_map(|p| p.as_str().map(str::to_string))
                .collect();
            let path = parts.first().cloned().unwrap_or_default();
            (parts.join(" "), path, parts.into_iter().skip(1).collect())
        }
        Some(Value::String(s)) => {
            let mut words = s.split_whitespace().map(str::to_string);
            let path = words.next().unwrap_or_default();
            (s.clone(), path, words.collect())
        }
        _ => (String::new(), String::new(), Vec::new()),
    }
}

struct Container {
    id: String,
    name: String,
    image: String,
    image_id: String,
    command: String,
    path: String,
    args: Vec<String>,
    state: String,
    status: String,
    exit_code: i64,
    created: i64,
    ports: Vec<Value>,
    labels: Map<String, Value>,
    env: Vec<String>,
    ip: String,
}

fn container(obj: &Value, index: usize) -> Result<Container, String> {
    if !obj.is_object() {
        return Err(format!("container {index} must be an object"));
    }
    let names = string_list(obj, &["names", "Names", "name", "Name"]);
    let name = names
        .first()
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_default();
    let what = if name.is_empty() {
        format!("container {index}")
    } else {
        format!("container '{name}'")
    };
    if name.is_empty() {
        return Err(format!("{what} needs a name"));
    }
    if !valid_name(&name) {
        return Err(format!(
            "{what}: name must match [a-zA-Z0-9][a-zA-Z0-9_.-]* as Docker requires"
        ));
    }
    // A blank ID is no ID, as a blank `created` is no creation time.
    let id = match str_field(obj, &["id", "Id", "ID"]).filter(|id| !id.trim().is_empty()) {
        Some(id) => id_from(&id, "container", &what)?,
        None => derived_id(&format!("container:{name}")),
    };
    let image = str_field(obj, &["image", "Image"]).unwrap_or_default();
    if image.is_empty() {
        return Err(format!("{what} needs an image"));
    }
    let state = state_of(obj, &what)?;
    let exit_code = field(obj, &["exit_code", "ExitCode"])
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let status = status_of(str_field(obj, &["status", "Status"]), &state, exit_code);
    let (command, path, args) = command_of(obj);
    let env = string_list(obj, &["env", "Env"]);
    Ok(Container {
        image_id: format!("sha256:{}", derived_id(&format!("image:{image}"))),
        id,
        name,
        image,
        command,
        path,
        args,
        state,
        status,
        exit_code,
        created: created_unix(obj, &what)?,
        ports: ports(obj, &what)?,
        labels: string_map(obj, &["labels", "Labels"], "labels")?,
        env,
        ip: str_field(obj, &["ip", "ip_address", "IPAddress"]).unwrap_or_default(),
    })
}

/// `GET /containers/json` body.
pub fn render_container_list(containers: &Value) -> Result<Value, String> {
    let list = containers
        .as_array()
        .ok_or("'containers' must be an array")?;
    let mut out = Vec::with_capacity(list.len());
    let mut seen_short_ids: Vec<String> = Vec::with_capacity(list.len());
    for (i, c) in list.iter().enumerate() {
        let mut c = container(c, i)?;
        // Two containers never share an ID, and the CLI tells them apart by its first 12
        // characters. A model copying one ID onto every container (llama3.1:8b copied the
        // action example's 64-hex ID onto every container of a `ps -a`) would otherwise
        // show two rows `docker inspect` cannot tell apart, so a repeated ID is replaced by
        // the one derived from the container's name - what omitting it would have given.
        let short: String = c.id.chars().take(12).collect();
        if seen_short_ids.contains(&short) {
            c.id = derived_id(&format!("container:{}", c.name));
        }
        seen_short_ids.push(c.id.chars().take(12).collect());
        out.push(json!({
            "Id": c.id,
            "Names": [format!("/{}", c.name)],
            "Image": c.image,
            "ImageID": c.image_id,
            "Command": c.command,
            "Created": c.created,
            "Ports": c.ports,
            "Labels": c.labels,
            "State": c.state,
            "Status": c.status,
            "HostConfig": {"NetworkMode": "bridge"},
            "NetworkSettings": {"Networks": {}},
            "Mounts": [],
        }));
    }
    Ok(Value::Array(out))
}

/// `GET /containers/{id}/json` body.
pub fn render_container(container_value: &Value) -> Result<Value, String> {
    let c = container(container_value, 0)?;
    let running = c.state == "running" || c.state == "paused";
    let started = if c.state == "created" {
        "0001-01-01T00:00:00Z".to_string()
    } else {
        rfc3339(c.created)
    };
    let mut exposed = Map::new();
    let mut bindings = Map::new();
    for p in &c.ports {
        let key = format!(
            "{}/{}",
            p["PrivatePort"],
            p["Type"].as_str().unwrap_or("tcp")
        );
        exposed.insert(key.clone(), json!({}));
        let binding = match p.get("PublicPort") {
            Some(public) => json!([{"HostIp": p["IP"], "HostPort": public.to_string()}]),
            None => Value::Null,
        };
        bindings.insert(key, binding);
    }
    Ok(json!({
        "Id": c.id,
        "Created": rfc3339(c.created),
        "Path": c.path,
        "Args": c.args,
        "State": {
            "Status": c.state,
            "Running": running,
            "Paused": c.state == "paused",
            "Restarting": c.state == "restarting",
            "OOMKilled": false,
            "Dead": c.state == "dead",
            "Pid": if running { 4242 } else { 0 },
            "ExitCode": c.exit_code,
            "Error": "",
            "StartedAt": started,
            "FinishedAt": if running || c.state == "created" {
                "0001-01-01T00:00:00Z".to_string()
            } else {
                rfc3339(c.created)
            },
        },
        "Image": c.image_id,
        "Name": format!("/{}", c.name),
        "RestartCount": 0,
        "Driver": "overlay2",
        "Platform": "linux",
        "MountLabel": "",
        "ProcessLabel": "",
        "AppArmorProfile": "",
        "HostConfig": {"NetworkMode": "bridge", "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}},
        "Mounts": [],
        "Config": {
            "Hostname": c.id.chars().take(12).collect::<String>(),
            "Image": c.image,
            "Cmd": std::iter::once(c.path.clone()).chain(c.args.iter().cloned())
                .filter(|s| !s.is_empty()).collect::<Vec<_>>(),
            "Env": c.env,
            "Labels": c.labels,
            "ExposedPorts": exposed,
            "Tty": false,
            "OpenStdin": false,
        },
        "NetworkSettings": {
            "Ports": bindings,
            "IPAddress": c.ip,
            "Networks": {},
        },
    }))
}

/// `GET /images/json` body.
pub fn render_images(images: &Value) -> Result<Value, String> {
    let list = images.as_array().ok_or("'images' must be an array")?;
    let mut out = Vec::with_capacity(list.len());
    for (i, img) in list.iter().enumerate() {
        if !img.is_object() {
            return Err(format!("image {i} must be an object"));
        }
        let tags = string_list(img, &["repo_tags", "RepoTags", "tags", "tag"]);
        for t in &tags {
            // The characters an image reference may contain: name components, `:` before a
            // tag, `@` before a digest, `/` between path components.
            let reference_char = |c: char| c.is_ascii_alphanumeric() || "._-:/@".contains(c);
            if t.is_empty() || t.len() > 255 || !t.chars().all(reference_char) {
                return Err(format!("image {i}: tag {t:?} is not a valid reference"));
            }
        }
        let seed = tags
            .first()
            .cloned()
            .unwrap_or_else(|| format!("image-{i}"));
        let id = match str_field(img, &["id", "Id", "ID"]) {
            Some(id) => format!("sha256:{}", id_from(&id, "image", &format!("image {i}"))?),
            None => format!("sha256:{}", derived_id(&format!("image:{seed}"))),
        };
        let size = u64_field(img, &["size", "Size"], "size")?.unwrap_or(0);
        out.push(json!({
            "Id": id,
            "ParentId": "",
            "RepoTags": tags,
            "RepoDigests": string_list(img, &["repo_digests", "RepoDigests"]),
            "Created": created_unix(img, &format!("image {i}"))?,
            "Size": size,
            "SharedSize": -1,
            "Labels": string_map(img, &["labels", "Labels"], "labels")?,
            "Containers": -1,
        }));
    }
    Ok(Value::Array(out))
}

/// `GET /networks` body.
pub fn render_networks(networks: &Value) -> Result<Value, String> {
    let list = networks.as_array().ok_or("'networks' must be an array")?;
    let mut out = Vec::with_capacity(list.len());
    for (i, n) in list.iter().enumerate() {
        let name = str_field(n, &["name", "Name"])
            .filter(|s| valid_name(s))
            .ok_or_else(|| format!("network {i} needs a valid name"))?;
        let id = str_field(n, &["id", "Id", "ID"])
            .filter(|s| valid_id(s))
            .unwrap_or_else(|| derived_id(&format!("network:{name}")));
        out.push(json!({
            "Name": name,
            "Id": id,
            "Created": rfc3339(created_unix(n, &format!("network '{name}'"))?),
            "Scope": str_field(n, &["scope", "Scope"]).unwrap_or_else(|| "local".to_string()),
            "Driver": str_field(n, &["driver", "Driver"]).unwrap_or_else(|| "bridge".to_string()),
            "EnableIPv6": false,
            "IPAM": {"Driver": "default", "Options": null, "Config": []},
            "Internal": field(n, &["internal", "Internal"]).and_then(Value::as_bool).unwrap_or(false),
            "Attachable": false,
            "Ingress": false,
            "ConfigFrom": {"Network": ""},
            "ConfigOnly": false,
            "Containers": {},
            "Options": {},
            "Labels": string_map(n, &["labels", "Labels"], "labels")?,
        }));
    }
    Ok(Value::Array(out))
}

/// `GET /volumes` body.
pub fn render_volumes(volumes: &Value) -> Result<Value, String> {
    let list = volumes.as_array().ok_or("'volumes' must be an array")?;
    let mut out = Vec::with_capacity(list.len());
    for (i, v) in list.iter().enumerate() {
        let name = str_field(v, &["name", "Name"])
            .filter(|s| valid_name(s))
            .ok_or_else(|| format!("volume {i} needs a valid name"))?;
        out.push(json!({
            "Name": name,
            "Driver": str_field(v, &["driver", "Driver"]).unwrap_or_else(|| "local".to_string()),
            "Mountpoint": format!("/var/lib/docker/volumes/{name}/_data"),
            "CreatedAt": rfc3339(created_unix(v, &format!("volume '{name}'"))?),
            "Labels": string_map(v, &["labels", "Labels"], "labels")?,
            "Scope": "local",
            "Options": {},
        }));
    }
    Ok(json!({"Volumes": out, "Warnings": []}))
}

/// Server identity used to fill `/version` and `/info` defaults.
#[derive(Clone, Debug)]
pub struct EngineIdentity {
    pub engine_version: String,
    pub api_version: String,
}

fn text_or(obj: &Value, names: &[&str], default: &str) -> String {
    str_field(obj, names).unwrap_or_else(|| default.to_string())
}

/// `GET /version` body.
pub fn render_version(data: &Value, id: &EngineIdentity) -> Result<Value, String> {
    let version = text_or(data, &["version", "Version"], &id.engine_version);
    let api = text_or(data, &["api_version", "ApiVersion"], &id.api_version);
    if parse_version(&api).is_none() {
        return Err(format!("api_version {api:?} must look like 1.47"));
    }
    let os = text_or(data, &["os", "Os"], "linux");
    let arch = text_or(data, &["arch", "Arch"], "amd64");
    let kernel = text_or(data, &["kernel_version", "KernelVersion"], "6.8.0-netget");
    let go = text_or(data, &["go_version", "GoVersion"], "go1.22.10");
    let commit = text_or(data, &["git_commit", "GitCommit"], "netget");
    let built = text_or(
        data,
        &["build_time", "BuildTime"],
        "2025-01-01T00:00:00.000000000+00:00",
    );
    Ok(json!({
        "Platform": {"Name": text_or(data, &["platform", "Platform"], "Docker Engine - Community")},
        "Components": [{
            "Name": "Engine",
            "Version": version,
            "Details": {
                "ApiVersion": api,
                "Arch": arch,
                "BuildTime": built,
                "Experimental": "false",
                "GitCommit": commit,
                "GoVersion": go,
                "KernelVersion": kernel,
                "MinAPIVersion": MIN_API_VERSION,
                "Os": os,
            }
        }],
        "Version": version,
        "ApiVersion": api,
        "MinAPIVersion": MIN_API_VERSION,
        "GitCommit": commit,
        "GoVersion": go,
        "Os": os,
        "Arch": arch,
        "KernelVersion": kernel,
        "BuildTime": built,
    }))
}

/// `GET /info` body.
pub fn render_info(data: &Value, id: &EngineIdentity) -> Result<Value, String> {
    let count = |names: &[&str], what: &str| -> Result<u64, String> {
        Ok(u64_field(data, names, what)?.unwrap_or(0))
    };
    let running = count(
        &["containers_running", "ContainersRunning"],
        "containers_running",
    )?;
    let paused = count(
        &["containers_paused", "ContainersPaused"],
        "containers_paused",
    )?;
    let stopped = count(
        &["containers_stopped", "ContainersStopped"],
        "containers_stopped",
    )?;
    let total = u64_field(data, &["containers", "Containers"], "containers")?
        .unwrap_or(running + paused + stopped);
    let name = text_or(data, &["name", "Name"], "netget");
    // Two literals merged, because one of this size exceeds `json!`'s macro recursion limit.
    let mut info = json!({
        "ID": text_or(data, &["id", "ID"], &derived_id(&format!("engine:{name}"))[..36]),
        "Containers": total,
        "ContainersRunning": running,
        "ContainersPaused": paused,
        "ContainersStopped": stopped,
        "Images": count(&["images", "Images"], "images")?,
        "Driver": text_or(data, &["driver", "Driver"], "overlay2"),
        "DriverStatus": [["Backing Filesystem", "extfs"]],
        "Plugins": {
            "Volume": ["local"],
            "Network": ["bridge", "host", "null"],
            "Authorization": null,
            "Log": ["json-file", "local"],
        },
        "MemoryLimit": true,
        "SwapLimit": true,
        "CpuCfsPeriod": true,
        "CpuCfsQuota": true,
        "CPUShares": true,
        "CPUSet": true,
        "PidsLimit": true,
        "IPv4Forwarding": true,
        "Debug": false,
        "NFd": 30,
        "OomKillDisable": false,
        "NGoroutines": 40,
        "SystemTime": rfc3339(now_unix()),
        "LoggingDriver": "json-file",
        "CgroupDriver": "systemd",
        "CgroupVersion": "2",
        "NEventsListener": 0,
    });
    let rest = json!({
        "KernelVersion": text_or(data, &["kernel_version", "KernelVersion"], "6.8.0-netget"),
        "OperatingSystem": text_or(data, &["operating_system", "OperatingSystem"], "NetGet Linux"),
        "OSVersion": text_or(data, &["os_version", "OSVersion"], ""),
        "OSType": text_or(data, &["os_type", "OSType"], "linux"),
        "Architecture": text_or(data, &["architecture", "Architecture"], "x86_64"),
        "IndexServerAddress": "https://index.docker.io/v1/",
        "RegistryConfig": {
            "IndexConfigs": {},
            "InsecureRegistryCIDRs": ["127.0.0.0/8"],
            "Mirrors": [],
        },
        "NCPU": u64_field(data, &["ncpu", "NCPU", "cpus"], "ncpu")?.unwrap_or(4),
        "MemTotal": u64_field(data, &["mem_total", "MemTotal", "memory_bytes"], "mem_total")?
            .unwrap_or(8 * 1024 * 1024 * 1024),
        "DockerRootDir": "/var/lib/docker",
        "Name": name,
        "Labels": string_list(data, &["labels", "Labels"]),
        "ExperimentalBuild": false,
        "ServerVersion": text_or(data, &["server_version", "ServerVersion", "version"], &id.engine_version),
        "Runtimes": {"runc": {"path": "runc"}},
        "DefaultRuntime": "runc",
        "Swarm": {"NodeID": "", "NodeAddr": "", "LocalNodeState": "inactive", "ControlAvailable": false, "Error": "", "RemoteManagers": null},
        "LiveRestoreEnabled": false,
        "Isolation": "",
        "InitBinary": "docker-init",
        "SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"],
        "Warnings": [],
    });
    if let (Some(a), Value::Object(b)) = (info.as_object_mut(), rest) {
        a.extend(b);
    }
    Ok(info)
}
