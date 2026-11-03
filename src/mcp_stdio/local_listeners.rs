//! The MCP `list_local_listeners` tool: what is listening on this host, so a caller looking
//! for something to point a client at need not shell out to `lsof` or `ss`.
//!
//! Read-only. The socket table comes from the `listeners` crate (procfs on Linux, libproc on
//! macOS, the IP Helper API on Windows, sysctl on the BSDs); elsewhere the tool says it is
//! unsupported. Each socket is matched against this process's running servers by port, so a
//! NetGet server is named as one.

use std::net::SocketAddr;

/// One listening TCP socket or bound UDP socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalListener {
    /// `"tcp"` or `"udp"`.
    pub transport: &'static str,
    pub addr: SocketAddr,
    pub pid: u32,
    pub process: String,
}

/// Every TCP socket in LISTEN and every UDP socket bound to a port, sorted by transport,
/// port and address. `Err` names why the table could not be read.
#[cfg(not(target_arch = "wasm32"))]
pub fn local_listeners() -> Result<Vec<LocalListener>, String> {
    if !listeners::IS_OS_SUPPORTED {
        return Err(format!(
            "listing local sockets is not supported on {}",
            std::env::consts::OS
        ));
    }
    let all = listeners::get_all().map_err(|e| e.to_string())?;
    let mut out: Vec<LocalListener> = all
        .into_iter()
        .filter_map(|l| {
            let transport = match l.protocol {
                listeners::Protocol::TCP if l.state == listeners::SocketState::Listen => "tcp",
                listeners::Protocol::UDP if l.socket.port() != 0 => "udp",
                _ => return None,
            };
            Some(LocalListener {
                transport,
                addr: l.socket,
                pid: l.process.pid,
                process: l.process.name,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        (a.transport, a.addr.port(), a.addr.to_string(), a.pid).cmp(&(
            b.transport,
            b.addr.port(),
            b.addr.to_string(),
            b.pid,
        ))
    });
    out.dedup();
    Ok(out)
}

/// Not available in the browser build: there is no host socket table to read.
#[cfg(target_arch = "wasm32")]
pub fn local_listeners() -> Result<Vec<LocalListener>, String> {
    Err("listing local sockets is not available in the browser build".to_string())
}

/// A running NetGet server, as a listener is matched against it.
#[derive(Debug, Clone)]
pub struct RunningServer {
    pub id: u32,
    pub protocol: String,
    pub port: u16,
}

/// What a listener is, as far as NetGet can tell: one of this process's servers, this
/// process otherwise, another NetGet process, or nothing NetGet knows.
pub fn netget_label(listener: &LocalListener, servers: &[RunningServer]) -> Option<String> {
    if listener.pid == std::process::id() {
        let matched: Vec<String> = servers
            .iter()
            .filter(|s| s.port == listener.addr.port())
            .map(|s| format!("server #{} ({})", s.id, s.protocol.to_lowercase()))
            .collect();
        return Some(if matched.is_empty() {
            "this NetGet process".to_string()
        } else {
            format!("this NetGet — {}", matched.join(", "))
        });
    }
    if listener.process.to_ascii_lowercase().contains("netget") {
        return Some("another NetGet process".to_string());
    }
    None
}

/// The tool's text: one line per socket, filtered by transport and port.
pub fn render(
    listeners: &[LocalListener],
    servers: &[RunningServer],
    transport: Option<&str>,
    port: Option<u16>,
) -> String {
    let shown: Vec<&LocalListener> = listeners
        .iter()
        .filter(|l| transport.is_none_or(|t| t == l.transport))
        .filter(|l| port.is_none_or(|p| p == l.addr.port()))
        .collect();
    let tcp = shown.iter().filter(|l| l.transport == "tcp").count();
    let udp = shown.len() - tcp;
    let mut out = format!("## Local listeners ({tcp} TCP listening, {udp} UDP bound)\n\n");
    if shown.is_empty() {
        out.push_str("Nothing matches.\n");
    }
    for l in &shown {
        let netget = netget_label(l, servers)
            .map(|label| format!(" — **{label}**"))
            .unwrap_or_default();
        out.push_str(&format!(
            "- {} {} — pid {} {}{}\n",
            l.transport.to_ascii_uppercase(),
            l.addr,
            l.pid,
            if l.process.is_empty() {
                "(unknown process)".to_string()
            } else {
                format!("`{}`", l.process)
            },
            netget
        ));
    }
    out.push_str(
        "\nOnly sockets of processes this user may inspect are listed: without root, other \
         users' processes (system daemons included) are missing. A wildcard \
         address (0.0.0.0, [::]) accepts on every interface; 127.0.0.1 / [::1] only locally.\n",
    );
    out
}
