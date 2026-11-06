//! Protocol type definitions
//!
//! The application supports multiple protocol implementations.
//! Protocol behavior is controlled by the LLM based on the chosen protocol and instructions.

pub mod binding_defaults;
pub mod client_registry;
pub mod connect_context;
pub mod default_port;
pub mod dependencies;
pub mod docs;
pub mod dual;
pub mod easy_registry;
pub mod event_logger;
pub mod event_type;
pub mod log_template;
pub mod metadata;
pub mod name_match;
pub mod server_registry;
pub mod spawn_context;

pub use binding_defaults::BindingDefaults;
pub use client_registry::CLIENT_REGISTRY;
pub use connect_context::ConnectContext;
pub use dependencies::ProtocolDependency;
pub use docs::render_all_protocol_docs;
pub use dual::{client_protocol_for_server, compiled_client_protocol_for_server};
pub use easy_registry::EASY_REGISTRY;
pub use event_logger::{log_action_result, EventLogContext};
pub use event_type::{Event, EventType};
pub use log_template::{LogLevel, LogTemplate};
pub use metadata::{DevelopmentState, ProtocolMetadata, ProtocolMetadataV2};
pub use server_registry::registry;
pub use spawn_context::{SpawnContext, StartupParamError, StartupParamResult, StartupParams};

/// Build a human-readable listing of every registered server and client
/// protocol, grouped by its declared [`DevelopmentState`], most-mature first.
///
/// Both registries are read at runtime, so the output always reflects the
/// compiled-in feature set — nothing here is hardcoded. Each line shows the
/// protocol name, its state, a `[blocked by --min-stability]` marker when
/// `min_stability` would refuse it, and the one-line `notes` from its metadata
/// when present. Backs the `/stability` (aka `/protocols`) slash command.
pub fn stability_report(min_stability: Option<DevelopmentState>) -> Vec<String> {
    fn one_line_note(notes: Option<&'static str>) -> Option<String> {
        let raw = notes?;
        let first = raw.lines().next().unwrap_or(raw).trim();
        if first.is_empty() {
            return None;
        }
        Some(crate::utils::truncate::truncate_with_suffix(
            first, 120, "…",
        ))
    }

    // (state, name, one-line note) for each registered protocol.
    let mut server_rows: Vec<(DevelopmentState, String, Option<String>)> = registry()
        .all_protocols()
        .into_iter()
        .map(|(name, p)| {
            let m = p.metadata();
            (m.state, name, one_line_note(m.notes))
        })
        .collect();
    let mut client_rows: Vec<(DevelopmentState, String, Option<String>)> = CLIENT_REGISTRY
        .get_all()
        .into_iter()
        .map(|p| {
            let m = p.metadata();
            (
                m.state,
                p.protocol_name().to_string(),
                one_line_note(m.notes),
            )
        })
        .collect();

    // Alphabetical within each maturity group.
    server_rows.sort_by_key(|r| r.1.to_lowercase());
    client_rows.sort_by_key(|r| r.1.to_lowercase());

    let mut lines = Vec::new();
    match min_stability {
        Some(min) => lines.push(format!(
            "Minimum stability to start (--min-stability): {} — protocols below this are refused",
            min.as_str()
        )),
        None => lines.push(
            "Minimum stability to start (--min-stability): not set (only Incomplete is hidden from the model)"
                .to_string(),
        ),
    }

    for (label, rows) in [("Servers", &server_rows), ("Clients", &client_rows)] {
        lines.push(String::new());
        lines.push(format!("=== {} ({}) ===", label, rows.len()));
        // Most-mature first.
        for state in DevelopmentState::ALL.iter().rev().copied() {
            let group: Vec<_> = rows.iter().filter(|r| r.0 == state).collect();
            if group.is_empty() {
                continue;
            }
            lines.push(format!("-- {} ({}) --", state.as_str(), group.len()));
            for (st, name, note) in group {
                let blocked = min_stability.map(|min| *st < min).unwrap_or(false);
                let marker = if blocked {
                    " [blocked by --min-stability]"
                } else {
                    ""
                };
                match note {
                    Some(n) => {
                        lines.push(format!("  {} [{}]{} — {}", name, st.as_str(), marker, n))
                    }
                    None => lines.push(format!("  {} [{}]{}", name, st.as_str(), marker)),
                }
            }
        }
    }

    lines
}
