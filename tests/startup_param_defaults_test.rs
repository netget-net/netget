//! A startup parameter's declared `default` must be a value the parameter accepts, and must
//! come from the constant the code falls back to.
//!
//! `ParameterDefinition::default` is shown to three audiences — pre-filled in the dashboard's
//! create form, printed by MCP `get_protocol_docs`, and given to the model in the prompt — and
//! all three take it at its word. A default that does not parse as the parameter's own
//! `type_hint` would be pre-filled into a form that then submits a value `StartupParams`
//! rejects; a default written as a literal beside a constant is a second copy of the number,
//! and the two drift.
//!
//! Two checks, deliberately split by what each can see:
//!
//! 1. **Registry walk** — every compiled server and client: the default is present only on an
//!    optional parameter, has the JSON shape its `type_hint` names, and `StartupParams::new`
//!    accepts it. This evaluates the real value, so it only covers what the build compiled;
//!    the blocking CI job compiles six protocols and `registry-audit` compiles all of them.
//! 2. **Source scan** — every `default: Some(…)` under `src/` names a constant or a path rather
//!    than a bare literal, at every feature set.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp \
//!       --test startup_param_defaults_test

use netget::llm::actions::ParameterDefinition;
use netget::protocol::StartupParams;

/// What a `type_hint` promises about a value's JSON shape.
fn shape_error(type_hint: &str, value: &serde_json::Value) -> Option<String> {
    let hint = type_hint.trim().to_ascii_lowercase();
    let ok = match hint.as_str() {
        "integer" | "u16" | "u32" | "u64" | "usize" | "i64" => value.is_i64() || value.is_u64(),
        "number" | "float" => value.is_number(),
        "boolean" | "bool" => value.is_boolean(),
        "string" => value.is_string(),
        "object" => value.is_object(),
        h if h.starts_with("array") => value.is_array(),
        other => {
            return Some(format!(
                "type_hint '{other}' is not one this check knows — teach shape_error what it \
                 promises"
            ))
        }
    };
    (!ok).then(|| format!("default {value} is not a {type_hint}"))
}

fn audit(owner: &str, schema: &[ParameterDefinition], problems: &mut Vec<String>) -> usize {
    let mut declared = 0;
    for param in schema {
        let Some(default) = &param.default else {
            continue;
        };
        declared += 1;
        let at = format!("{owner}.{}", param.name);
        if param.required {
            problems.push(format!(
                "{at}: required, yet declares a default — a required parameter has no fallback"
            ));
        }
        if let Some(e) = shape_error(&param.type_hint, default) {
            problems.push(format!("{at}: {e}"));
        }
        let object = serde_json::json!({ param.name.clone(): default.clone() });
        if let Err(e) = StartupParams::new(object, schema.to_vec()) {
            problems.push(format!("{at}: StartupParams refuses its own default: {e}"));
        }
    }
    declared
}

#[test]
fn every_declared_default_is_a_value_its_parameter_accepts() {
    let mut problems = Vec::new();
    let mut declared = 0;

    let servers = netget::protocol::server_registry::registry();
    for (name, protocol) in servers.all_protocols() {
        declared += audit(
            &format!("server {name}"),
            &protocol.get_startup_parameters(),
            &mut problems,
        );
    }
    let clients = &netget::protocol::CLIENT_REGISTRY;
    for name in clients.list_protocols() {
        if let Some(client) = clients.get(&name) {
            declared += audit(
                &format!("client {name}"),
                &client.get_startup_parameters(),
                &mut problems,
            );
        }
    }

    assert!(
        problems.is_empty(),
        "declared startup-parameter defaults that are not values their parameter accepts:\n  {}",
        problems.join("\n  ")
    );
    println!("{declared} declared defaults checked");
}

/// tcp is in every CI feature set; if the walk sees none of its defaults, the walk is broken
/// rather than the tree clean.
#[test]
fn the_walk_sees_tcps_declared_defaults() {
    let tcp = netget::protocol::server_registry::registry()
        .get("TCP")
        .expect("tcp is compiled in");
    let schema = tcp.get_startup_parameters();
    let default_of = |name: &str| {
        schema
            .iter()
            .find(|p| p.name == name)
            .and_then(|p| p.default.clone())
    };
    assert_eq!(
        default_of("first_byte_timeout_secs"),
        Some(serde_json::json!(300))
    );
    assert_eq!(
        default_of("idle_timeout_secs"),
        Some(serde_json::json!(900))
    );
}

/// Strip `//` comments, leaving `//` inside a string literal alone.
fn strip_comments(src: &str) -> String {
    src.lines()
        .map(|line| {
            let bytes = line.as_bytes();
            let mut in_string = false;
            let mut i = 0usize;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' if in_string => i += 1,
                    b'"' => in_string = !in_string,
                    b'/' if !in_string && bytes.get(i + 1) == Some(&b'/') => {
                        return line[..i].to_string()
                    }
                    _ => {}
                }
                i += 1;
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// A declared default names the constant the code falls back to — never a literal copy of it.
///
/// The failure this prevents is silent: someone changes `IDLE_TIMEOUT` from 600 to 300, the
/// server now closes at 300, and the form, the docs and the prompt all go on saying 600.
#[test]
fn every_declared_default_names_a_constant_rather_than_repeating_a_literal() {
    let literal = regex::Regex::new(
        r#"(?s)\bdefault:\s*Some\(\s*(?:serde_json::)?json!\(\s*(-?[0-9][0-9_.]*|true|false|"[^"]*")\s*\)\s*\)"#,
    )
    .expect("regex");
    let mut files = Vec::new();
    rust_files(std::path::Path::new("src"), &mut files);
    let mut offenders = Vec::new();
    let mut seen = 0;
    for path in files {
        let src = strip_comments(&std::fs::read_to_string(&path).unwrap_or_default());
        if !src.contains("ParameterDefinition") {
            continue;
        }
        seen += src.matches("default: Some(").count();
        for m in literal.captures_iter(&src) {
            offenders.push(format!("{}: default {}", path.display(), &m[1]));
        }
    }
    assert!(
        offenders.is_empty(),
        "these declared defaults repeat a literal instead of naming the constant the code \
         falls back to — point them at it (`Some(json!(super::IDLE_TIMEOUT.as_secs()))`):\n  {}",
        offenders.join("\n  ")
    );
    assert!(seen > 0, "the scan found no declared defaults at all");
}
