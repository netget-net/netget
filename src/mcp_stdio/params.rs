//! Tool-argument extraction that names the argument that is wrong.
//!
//! rmcp's own `Parameters<P>` deserializes a tool's arguments with `serde_json::from_value`
//! and reports serde's message alone, so `start_server {"port": "abc"}` answered
//! `failed to deserialize parameters: invalid digit found in string` — no tool, no field, no
//! type. This `Parameters<P>` is a drop-in replacement: the `#[tool]` macro finds the
//! parameter type by its last path segment being `Parameters`, so `tools.rs` imports this one
//! and every tool gets it without a change to its signature.
//!
//! On failure it deserializes through `serde_path_to_error` to learn which argument failed,
//! reads that argument's expected type out of the tool's own input schema (the one
//! `tools/list` advertises, so the message and the schema cannot disagree), and says what was
//! received:
//!
//! ```text
//! start_server: argument `port` must be an integer from 0 to 65535; got the string "abc"
//! ```
//!
//! It stays an `invalid_params` JSON-RPC error, as rmcp's was.

use rmcp::handler::server::common::FromContextPart;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::ErrorData as McpError;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

/// A tool's arguments, deserialized into `P`, with errors that name the tool and the argument.
#[derive(Debug, Clone)]
pub struct Parameters<P>(pub P);

impl<P: JsonSchema> JsonSchema for Parameters<P> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        P::schema_name()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        P::json_schema(generator)
    }
}

impl<S, P> FromContextPart<ToolCallContext<'_, S>> for Parameters<P>
where
    P: DeserializeOwned + JsonSchema + 'static,
{
    fn from_context_part(context: &mut ToolCallContext<S>) -> Result<Self, McpError> {
        let arguments = context.arguments.take().unwrap_or_default();
        parse_arguments::<P>(&context.name, arguments)
            .map(Parameters)
            .map_err(|message| McpError::invalid_params(message, None))
    }
}

/// Deserialize `arguments` as `P`, or explain — naming `tool`, the argument, its expected type
/// and what was given — why not.
pub fn parse_arguments<P>(tool: &str, arguments: Map<String, Value>) -> Result<P, String>
where
    P: DeserializeOwned + JsonSchema + 'static,
{
    let value = Value::Object(arguments);
    match serde_path_to_error::deserialize::<_, P>(&value) {
        Ok(parsed) => Ok(parsed),
        Err(error) => {
            let schema = rmcp::handler::server::common::schema_for_type::<P>();
            Err(explain(tool, &value, &schema, &error))
        }
    }
}

fn explain(
    tool: &str,
    arguments: &Value,
    schema: &Map<String, Value>,
    error: &serde_path_to_error::Error<serde_json::Error>,
) -> String {
    let root = Value::Object(schema.clone());
    let properties = schema.get("properties").and_then(Value::as_object);
    let inner = error.inner().to_string();
    let mut segments = error.path().iter();
    let first = segments.next();

    let mut message = match first {
        // A missing required argument is reported against the object that lacks it.
        None if inner.starts_with("missing field `") => {
            let field = inner
                .trim_start_matches("missing field `")
                .split('`')
                .next()
                .unwrap_or_default();
            let expected = properties
                .and_then(|p| p.get(field))
                .map(|s| format!(" ({})", describe_schema(s, &root)))
                .unwrap_or_default();
            format!("{tool}: missing required argument `{field}`{expected}")
        }
        Some(serde_path_to_error::Segment::Map { key }) => {
            let given = arguments.get(key.as_str()).map(describe_value);
            let expected = properties.and_then(|p| p.get(key.as_str()));
            let nested = segments.next().is_some();
            match (expected, given) {
                (Some(schema), Some(given)) if !nested => format!(
                    "{tool}: argument `{key}` must be {}; got {given}",
                    describe_schema(schema, &root)
                ),
                (Some(schema), _) => format!(
                    "{tool}: argument `{key}` must be {} — at `{}`: {inner}",
                    describe_schema(schema, &root),
                    error.path()
                ),
                (None, _) => format!("{tool}: argument `{}`: {inner}", error.path()),
            }
        }
        _ => format!("{tool}: invalid arguments: {inner}"),
    };

    // A misspelled argument is silently ignored on success; when something already failed,
    // name the keys the tool does not take, since one of them is often the intended field.
    if let (Some(properties), Some(given)) = (properties, arguments.as_object()) {
        let unknown: Vec<String> = given
            .keys()
            .filter(|k| !properties.contains_key(k.as_str()))
            .map(|k| format!("`{k}`"))
            .collect();
        if !unknown.is_empty() {
            message.push_str(&format!(
                ". Not arguments of {tool}: {}",
                unknown.join(", ")
            ));
        }
    }
    message
}

/// What a JSON-schema node accepts, in words: "an integer from 0 to 65535", "a string",
/// "true or false", "one of \"server\", \"client\"".
pub fn describe_schema(schema: &Value, root: &Value) -> String {
    let Some(object) = schema.as_object() else {
        // `true` (or `false`) as a schema: anything (nothing).
        return "any JSON value".to_string();
    };
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let name = reference.rsplit('/').next().unwrap_or(reference);
        if let Some(target) = root
            .get("$defs")
            .and_then(|d| d.get(name))
            .or_else(|| root.get("definitions").and_then(|d| d.get(name)))
        {
            return describe_schema(target, root);
        }
        return format!("a `{name}`");
    }
    if let Some(values) = object.get("enum").and_then(Value::as_array) {
        let listed: Vec<String> = values
            .iter()
            .filter(|v| !v.is_null())
            .map(|v| v.to_string())
            .collect();
        return format!("one of {}", listed.join(", "));
    }
    for key in ["anyOf", "oneOf"] {
        if let Some(variants) = object.get(key).and_then(Value::as_array) {
            let described: Vec<String> = variants
                .iter()
                .filter(|v| v.get("type").and_then(Value::as_str) != Some("null"))
                .map(|v| describe_schema(v, root))
                .collect();
            if !described.is_empty() {
                return described.join(" or ");
            }
        }
    }
    let types: Vec<&str> = match object.get("type") {
        Some(Value::String(t)) => vec![t.as_str()],
        Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    let types: Vec<&str> = types.into_iter().filter(|t| *t != "null").collect();
    if types.is_empty() {
        return "any JSON value".to_string();
    }
    let words: Vec<String> = types
        .iter()
        .map(|t| match *t {
            "integer" => describe_integer(object),
            "number" => "a number".to_string(),
            "string" => "a string".to_string(),
            "boolean" => "true or false".to_string(),
            "object" => "a JSON object".to_string(),
            "array" => match object.get("items") {
                Some(items) if items.get("type").is_some() || items.get("$ref").is_some() => {
                    format!("an array, each item {}", describe_schema(items, root))
                }
                _ => "an array".to_string(),
            },
            other => format!("a {other}"),
        })
        .collect();
    words.join(" or ")
}

fn describe_integer(object: &Map<String, Value>) -> String {
    let min = object.get("minimum").and_then(Value::as_i64);
    let max = object
        .get("maximum")
        .and_then(Value::as_u64)
        .map(|m| m.to_string());
    match (min, max) {
        (Some(min), Some(max)) => format!("an integer from {min} to {max}"),
        (Some(0), None) => "a non-negative integer".to_string(),
        (Some(min), None) => format!("an integer of at least {min}"),
        (None, Some(max)) => format!("an integer of at most {max}"),
        (None, None) => "an integer".to_string(),
    }
}

/// What the caller sent, in words: `the string "abc"`, `the number 70000`, `an array`.
pub fn describe_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => format!("the boolean {b}"),
        Value::Number(n) => format!("the number {n}"),
        Value::String(s) => {
            let shown: String = s.chars().take(60).collect();
            let ellipsis = if s.chars().count() > 60 { "…" } else { "" };
            format!("the string {:?}", format!("{shown}{ellipsis}"))
        }
        Value::Array(_) => "an array".to_string(),
        Value::Object(_) => "a JSON object".to_string(),
    }
}
