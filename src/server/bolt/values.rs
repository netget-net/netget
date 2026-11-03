//! The model's JSON answers → PackStream, and the client's PackStream parameters → JSON.
//!
//! **Model → wire.** A record value is plain JSON: strings, numbers, booleans, null, arrays and
//! objects become PackStream strings, integers or floats, booleans, null, lists and maps. Three
//! single-key objects are graph values instead, so a client renders them as nodes, relationships
//! and paths rather than as maps:
//!
//! ```json
//! {"$node": {"id": 1, "labels": ["Person"], "properties": {"name": "Alice"}}}
//! {"$relationship": {"id": 7, "type": "KNOWS", "start": 1, "end": 2, "properties": {}}}
//! {"$path": {"nodes": [{"id": 1, "labels": ["Person"]}, {"id": 2, "labels": ["Person"]}],
//!            "relationships": [{"id": 7, "type": "KNOWS", "start": 1, "end": 2}]}}
//! ```
//!
//! `element_id` (and a relationship's `start_element_id` / `end_element_id`) may be given; each
//! defaults to the decimal string of the matching integer id. A path's `relationships[i]` must
//! connect `nodes[i]` and `nodes[i + 1]` in either direction, and NetGet computes the Bolt path
//! index sequence (1-based relationship index, negative when traversed backwards; 0-based node
//! index) itself. Temporal and spatial values are not in the set — give them as strings.
//!
//! **Client → model.** RUN's parameters arrive as PackStream and reach the model as JSON. Bytes
//! become `{"$bytes_length": n}` (never the bytes: the event-design rule) and any structure
//! becomes `{"$structure": "<name>", "fields": [...]}` using Bolt's structure names.
//!
//! Both directions are bounded to [`MAX_PACKSTREAM_DEPTH`], so NetGet never emits a value its own
//! decoder would refuse.

use super::packstream::{Value, MAX_PACKSTREAM_DEPTH};
use serde_json::Value as Json;

/// Bolt structure tags for the graph types.
pub const TAG_NODE: u8 = 0x4E;
pub const TAG_RELATIONSHIP: u8 = 0x52;
pub const TAG_UNBOUND_RELATIONSHIP: u8 = 0x72;
pub const TAG_PATH: u8 = 0x50;

/// Convert a JSON value the model wrote into a PackStream value.
pub fn json_to_value(json: &Json) -> Result<Value, String> {
    to_value(json, 1)
}

fn to_value(json: &Json, depth: usize) -> Result<Value, String> {
    Ok(match json {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if n.is_u64() {
                return Err(format!(
                    "integer {n} does not fit a PackStream INT_64 (max {})",
                    i64::MAX
                ));
            } else {
                Value::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Json::String(s) => Value::String(s.clone()),
        Json::Array(items) => {
            check_depth(depth)?;
            Value::List(
                items
                    .iter()
                    .map(|v| to_value(v, depth + 1))
                    .collect::<Result<_, _>>()?,
            )
        }
        Json::Object(map) => {
            check_depth(depth)?;
            if map.len() == 1 {
                if let Some(node) = map.get("$node") {
                    return node_value(node, depth + 1).map(|n| n.value);
                }
                if let Some(rel) = map.get("$relationship") {
                    return relationship_value(rel, depth + 1).map(|r| r.bound);
                }
                if let Some(path) = map.get("$path") {
                    return path_value(path, depth + 1);
                }
            }
            Value::Map(
                map.iter()
                    .map(|(k, v)| Ok((k.clone(), to_value(v, depth + 1)?)))
                    .collect::<Result<_, String>>()?,
            )
        }
    })
}

fn check_depth(depth: usize) -> Result<(), String> {
    if depth > MAX_PACKSTREAM_DEPTH {
        Err(format!(
            "value nests deeper than {MAX_PACKSTREAM_DEPTH} levels"
        ))
    } else {
        Ok(())
    }
}

fn object<'a>(json: &'a Json, what: &str) -> Result<&'a serde_json::Map<String, Json>, String> {
    json.as_object()
        .ok_or_else(|| format!("{what} must be an object"))
}

fn int_field(map: &serde_json::Map<String, Json>, key: &str, what: &str) -> Result<i64, String> {
    map.get(key)
        .and_then(Json::as_i64)
        .ok_or_else(|| format!("{what} needs an integer '{key}'"))
}

fn element_id(map: &serde_json::Map<String, Json>, key: &str, fallback: i64) -> Value {
    Value::String(
        map.get(key)
            .and_then(Json::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| fallback.to_string()),
    )
}

fn properties(
    map: &serde_json::Map<String, Json>,
    what: &str,
    depth: usize,
) -> Result<Value, String> {
    match map.get("properties") {
        None | Some(Json::Null) => Ok(Value::Map(Vec::new())),
        Some(Json::Object(_)) => to_value(&map["properties"], depth),
        Some(_) => Err(format!("{what} 'properties' must be an object")),
    }
}

struct Node {
    id: i64,
    value: Value,
}

/// `{"id", "labels"?, "properties"?, "element_id"?}` → Node, accepting the `{"$node": …}`
/// wrapper too (inside a path).
fn node_value(json: &Json, depth: usize) -> Result<Node, String> {
    check_depth(depth)?;
    let json = json.get("$node").unwrap_or(json);
    let map = object(json, "$node")?;
    let id = int_field(map, "id", "$node")?;
    let labels = match map.get("labels") {
        None | Some(Json::Null) => Vec::new(),
        Some(Json::Array(labels)) => labels
            .iter()
            .map(|l| {
                l.as_str()
                    .map(Value::string)
                    .ok_or_else(|| "$node 'labels' must be strings".to_string())
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err("$node 'labels' must be an array of strings".to_string()),
    };
    Ok(Node {
        id,
        value: Value::Struct {
            tag: TAG_NODE,
            fields: vec![
                Value::Int(id),
                Value::List(labels),
                properties(map, "$node", depth + 1)?,
                element_id(map, "element_id", id),
            ],
        },
    })
}

struct Relationship {
    id: i64,
    start: i64,
    end: i64,
    bound: Value,
    unbound: Value,
}

/// `{"id", "type", "start", "end", "properties"?, "element_id"?, "start_element_id"?,
/// "end_element_id"?}` → Relationship (and its unbound form for paths).
fn relationship_value(json: &Json, depth: usize) -> Result<Relationship, String> {
    check_depth(depth)?;
    let json = json.get("$relationship").unwrap_or(json);
    let map = object(json, "$relationship")?;
    let id = int_field(map, "id", "$relationship")?;
    let start = int_field(map, "start", "$relationship")?;
    let end = int_field(map, "end", "$relationship")?;
    let rel_type = map
        .get("type")
        .and_then(Json::as_str)
        .filter(|t| !t.is_empty())
        .ok_or("$relationship needs a non-empty string 'type'")?
        .to_string();
    let props = properties(map, "$relationship", depth + 1)?;
    let eid = element_id(map, "element_id", id);
    Ok(Relationship {
        id,
        start,
        end,
        bound: Value::Struct {
            tag: TAG_RELATIONSHIP,
            fields: vec![
                Value::Int(id),
                Value::Int(start),
                Value::Int(end),
                Value::String(rel_type.clone()),
                props.clone(),
                eid.clone(),
                element_id(map, "start_element_id", start),
                element_id(map, "end_element_id", end),
            ],
        },
        unbound: Value::Struct {
            tag: TAG_UNBOUND_RELATIONSHIP,
            fields: vec![Value::Int(id), Value::String(rel_type), props, eid],
        },
    })
}

fn path_value(json: &Json, depth: usize) -> Result<Value, String> {
    check_depth(depth)?;
    let map = object(json, "$path")?;
    let nodes = map
        .get("nodes")
        .and_then(Json::as_array)
        .ok_or("$path needs a 'nodes' array")?;
    let rels = match map.get("relationships") {
        None | Some(Json::Null) => Vec::new(),
        Some(Json::Array(r)) => r.clone(),
        Some(_) => return Err("$path 'relationships' must be an array".to_string()),
    };
    if nodes.is_empty() {
        return Err("$path needs at least one node".to_string());
    }
    if rels.len() + 1 != nodes.len() {
        return Err(format!(
            "$path with {} nodes needs {} relationships, got {}",
            nodes.len(),
            nodes.len() - 1,
            rels.len()
        ));
    }
    let nodes: Vec<Node> = nodes
        .iter()
        .map(|n| node_value(n, depth + 1))
        .collect::<Result<_, _>>()?;
    let rels: Vec<Relationship> = rels
        .iter()
        .map(|r| relationship_value(r, depth + 1))
        .collect::<Result<_, _>>()?;

    // Distinct nodes and relationships in order of first appearance; the index sequence refers
    // into these lists.
    let mut unique_nodes: Vec<&Node> = Vec::new();
    for node in &nodes {
        if !unique_nodes.iter().any(|n| n.id == node.id) {
            unique_nodes.push(node);
        }
    }
    let mut unique_rels: Vec<&Relationship> = Vec::new();
    for rel in &rels {
        if !unique_rels.iter().any(|r| r.id == rel.id) {
            unique_rels.push(rel);
        }
    }

    let mut indices = Vec::with_capacity(rels.len() * 2);
    for (i, rel) in rels.iter().enumerate() {
        let (from, to) = (nodes[i].id, nodes[i + 1].id);
        let rel_index = unique_rels
            .iter()
            .position(|r| r.id == rel.id)
            .map(|p| p as i64 + 1)
            .unwrap_or(1);
        let signed = if rel.start == from && rel.end == to {
            rel_index
        } else if rel.start == to && rel.end == from {
            -rel_index
        } else {
            return Err(format!(
                "$path relationship {} ({}->{}) does not connect nodes {} and {}",
                rel.id, rel.start, rel.end, from, to
            ));
        };
        let node_index = unique_nodes
            .iter()
            .position(|n| n.id == to)
            .map(|p| p as i64)
            .unwrap_or(0);
        indices.push(Value::Int(signed));
        indices.push(Value::Int(node_index));
    }

    Ok(Value::Struct {
        tag: TAG_PATH,
        fields: vec![
            Value::List(unique_nodes.iter().map(|n| n.value.clone()).collect()),
            Value::List(unique_rels.iter().map(|r| r.unbound.clone()).collect()),
            Value::List(indices),
        ],
    })
}

/// Bolt's name for a structure tag, for describing parameters to the model.
pub fn structure_name(tag: u8) -> String {
    match tag {
        TAG_NODE => "Node".to_string(),
        TAG_RELATIONSHIP => "Relationship".to_string(),
        TAG_UNBOUND_RELATIONSHIP => "UnboundRelationship".to_string(),
        TAG_PATH => "Path".to_string(),
        0x44 => "Date".to_string(),
        0x54 => "Time".to_string(),
        0x74 => "LocalTime".to_string(),
        0x49 => "DateTime".to_string(),
        0x69 => "DateTimeZoneId".to_string(),
        0x64 => "LocalDateTime".to_string(),
        0x45 => "Duration".to_string(),
        0x58 => "Point2D".to_string(),
        0x59 => "Point3D".to_string(),
        other => format!("0x{other:02X}"),
    }
}

/// A decoded PackStream value as JSON for an event. Never carries raw bytes.
pub fn value_to_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Int(i) => Json::from(*i),
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(Json::Number)
            .unwrap_or_else(|| Json::String(f.to_string())),
        Value::Bytes(b) => serde_json::json!({"$bytes_length": b.len()}),
        Value::String(s) => Json::String(s.clone()),
        Value::List(items) => Json::Array(items.iter().map(value_to_json).collect()),
        Value::Map(entries) => Json::Object(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), value_to_json(v)))
                .collect(),
        ),
        Value::Struct { tag, fields } => serde_json::json!({
            "$structure": structure_name(*tag),
            "fields": fields.iter().map(value_to_json).collect::<Vec<_>>(),
        }),
    }
}

/// Query statistics Bolt reports in a result summary, as Neo4j names them on the wire.
pub const STAT_COUNTERS: &[&str] = &[
    "nodes-created",
    "nodes-deleted",
    "relationships-created",
    "relationships-deleted",
    "properties-set",
    "labels-added",
    "labels-removed",
    "indexes-added",
    "indexes-removed",
    "constraints-added",
    "constraints-removed",
    "system-updates",
];

/// The model's `stats` object (`nodes_created` or `nodes-created`, integer counts) → Bolt's
/// `stats` map, with `contains-updates` / `contains-system-updates` derived. Unknown keys and
/// negative counts are refused.
pub fn stats_value(json: Option<&Json>) -> Result<Option<Value>, String> {
    let map = match json {
        None | Some(Json::Null) => return Ok(None),
        Some(Json::Object(map)) => map,
        Some(_) => return Err("'stats' must be an object".to_string()),
    };
    let mut entries = Vec::new();
    let mut updates = false;
    let mut system_updates = false;
    for (key, value) in map {
        let wire = key.replace('_', "-");
        if !STAT_COUNTERS.contains(&wire.as_str()) {
            return Err(format!(
                "unknown stats key '{key}' (allowed: {})",
                STAT_COUNTERS
                    .iter()
                    .map(|k| k.replace('-', "_"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let count = value
            .as_i64()
            .filter(|c| *c >= 0)
            .ok_or_else(|| format!("stats '{key}' must be a non-negative integer"))?;
        if count == 0 {
            continue;
        }
        if wire == "system-updates" {
            system_updates = true;
        } else {
            updates = true;
        }
        let wire_key = STAT_COUNTERS
            .iter()
            .find(|k| **k == wire)
            .copied()
            .unwrap_or("nodes-created");
        entries.push((wire_key.to_string(), Value::Int(count)));
    }
    if entries.is_empty() {
        return Ok(None);
    }
    if updates {
        entries.push(("contains-updates".to_string(), Value::Bool(true)));
    }
    if system_updates {
        entries.push(("contains-system-updates".to_string(), Value::Bool(true)));
    }
    Ok(Some(Value::Map(entries)))
}

/// A Neo4j status code the model may send in a FAILURE: `Neo.<Classification>.<Category>.<Title>`
/// with the classification one of ClientError, TransientError or DatabaseError.
pub fn valid_failure_code(code: &str) -> bool {
    let parts: Vec<&str> = code.split('.').collect();
    let word = |s: &str| {
        !s.is_empty()
            && s.len() <= 64
            && s.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && s.chars().all(|c| c.is_ascii_alphanumeric())
    };
    parts.len() == 4
        && parts[0] == "Neo"
        && matches!(parts[1], "ClientError" | "TransientError" | "DatabaseError")
        && word(parts[2])
        && word(parts[3])
}

/// A validated answer to one query: column names, rows, and the summary it ends with.
#[derive(Debug, Clone)]
pub struct QueryAnswer {
    pub fields: Vec<String>,
    pub records: Vec<Vec<Value>>,
    pub stats: Option<Value>,
    pub query_type: &'static str,
}

/// Preflight handler values before recursive copies or conversion. The JSON action
/// envelope and graph wrappers need four additional levels beyond wire containers.
pub const MAX_ACTION_DEPTH: usize = MAX_PACKSTREAM_DEPTH + 4;
pub const MAX_ACTION_NODES: usize = 65536;
pub const MAX_ACTION_RETAINED_BYTES: usize = 8 * 1024 * 1024;
pub fn action_within_budget(action: &Json) -> bool {
    crate::utils::json_budget::within_budget(
        action,
        MAX_ACTION_RETAINED_BYTES,
        MAX_ACTION_NODES,
        MAX_ACTION_DEPTH,
    )
}

/// Check the actual encoded container shape, including the RECORD structure and row list.
fn within_wire_depth(value: &Value, depth: usize) -> bool {
    let mut pending = vec![(value, depth)];
    while let Some((value, depth)) = pending.pop() {
        let children = match value {
            Value::List(v) | Value::Struct { fields: v, .. } => Some(v.as_slice()),
            Value::Map(v) => {
                if depth > MAX_PACKSTREAM_DEPTH {
                    return false;
                }
                pending.extend(v.iter().map(|(_, v)| (v, depth + 1)));
                None
            }
            _ => None,
        };
        if let Some(children) = children {
            if depth > MAX_PACKSTREAM_DEPTH {
                return false;
            }
            pending.extend(children.iter().map(|v| (v, depth + 1)));
        }
    }
    true
}

/// Build a [`QueryAnswer`] from a `send_bolt_records` action, refusing anything a client would
/// misread: a record whose width differs from `fields`, a duplicate or empty column name, an
/// unknown `query_type` or statistic.
pub fn query_answer(action: &Json) -> Result<QueryAnswer, String> {
    if !action_within_budget(action) {
        return Err("Bolt answer exceeds the in-memory depth/node/retained-content budget".into());
    }
    let fields: Vec<String> = match action.get("fields") {
        Some(Json::Array(fields)) => fields
            .iter()
            .map(|f| {
                f.as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .ok_or_else(|| "every entry in 'fields' must be a non-empty string".to_string())
            })
            .collect::<Result<_, _>>()?,
        None | Some(Json::Null) => Vec::new(),
        Some(_) => return Err("'fields' must be an array of column names".to_string()),
    };
    for (i, f) in fields.iter().enumerate() {
        if fields[..i].contains(f) {
            return Err(format!("column '{f}' appears twice in 'fields'"));
        }
    }
    let rows = match action.get("records") {
        None | Some(Json::Null) => Vec::new(),
        Some(Json::Array(rows)) => rows.iter().collect::<Vec<_>>(),
        Some(_) => return Err("'records' must be an array of rows".to_string()),
    };
    let mut records = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        let cells: Vec<&Json> = match row {
            Json::Array(cells) => cells.iter().collect(),
            // The same row written as a map from column name to value. llama3.1:8b answered
            // `MATCH (p:Person) RETURN p.name AS name` with `[{"name": "Ada"}, …]` in every
            // run of the real-model eval's `bolt/people-by-name` - the shape a Neo4j driver
            // hands back as a record - and refusing it failed every query. Only an object
            // whose keys are exactly the fields is read this way, so nothing is guessed.
            Json::Object(map)
                if map.len() == fields.len() && fields.iter().all(|f| map.contains_key(f)) =>
            {
                fields.iter().map(|f| &map[f]).collect()
            }
            _ => {
                return Err(format!(
                    "record {i} must be an array with one value per field, in field order (or \
                     an object whose keys are exactly the field names)"
                ))
            }
        };
        if cells.len() != fields.len() {
            return Err(format!(
                "record {i} has {} values but there are {} fields",
                cells.len(),
                fields.len()
            ));
        }
        records.push(
            cells
                .into_iter()
                .map(|c| {
                    let value = json_to_value(c).map_err(|e| format!("record {i}: {e}"))?;
                    if !within_wire_depth(&value, 3) {
                        return Err(format!(
                            "record {i}: encoded value exceeds wire depth {MAX_PACKSTREAM_DEPTH}"
                        ));
                    }
                    Ok(value)
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    let query_type = match action.get("query_type").and_then(Json::as_str) {
        None => "r",
        Some("r") => "r",
        Some("w") => "w",
        Some("rw") => "rw",
        Some("s") => "s",
        Some(other) => {
            return Err(format!(
                "query_type must be r (read), w (write), rw (read-write) or s (schema), got \
                 '{other}'"
            ))
        }
    };
    Ok(QueryAnswer {
        fields,
        records,
        stats: stats_value(action.get("stats"))?,
        query_type,
    })
}
