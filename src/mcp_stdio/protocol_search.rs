//! Search and layer filtering for the MCP `list_protocols` tool.
//!
//! The full listing is ~250 lines per half, too long to read through for "which client can
//! put a raw IP packet on the wire". `query` ranks protocols by how many of its words they
//! match, and `layer` narrows to one layer of the network stack.
//!
//! Nothing here is a per-protocol table. A protocol's layer is derived from its
//! `stack_name()` ([`layer_of_stack`]); the words it is found by are its name, its
//! `keywords()`, its metadata's `search_terms` (search-only aliases that, unlike keywords,
//! never take part in protocol-name resolution), its group, its layer's vocabulary
//! ([`Layer::vocabulary`]) and, more weakly, its description.

use std::collections::BTreeSet;

/// One layer of the network stack, as `list_protocols { layer }` filters by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Link layer: Ethernet frames and what rides directly on them (ARP, LLDP, STP, IS-IS).
    L2,
    /// Network layer: IP and what rides directly on it (ICMP, GRE, OSPF, VRRP), tunnels.
    L3,
    /// Transport layer: TCP, UDP, SCTP, QUIC with nothing above them.
    L4,
    /// An application protocol above a transport.
    App,
    /// Not on an IP stack at all: USB, Bluetooth, CAN, serial, pipes, PTYs, Unix sockets.
    Other,
}

impl Layer {
    /// Every layer, in stack order.
    pub const ALL: [Layer; 5] = [Layer::L2, Layer::L3, Layer::L4, Layer::App, Layer::Other];

    /// The name `list_protocols` prints and accepts.
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::L2 => "l2",
            Layer::L3 => "l3",
            Layer::L4 => "l4",
            Layer::App => "app",
            Layer::Other => "other",
        }
    }

    /// Parse a `layer` argument. Accepts the printed names plus the usual synonyms
    /// (`2`, `link`, `ethernet`; `3`, `network`, `ip`; `4`, `transport`; `7`, `l7`,
    /// `application`; `local`, `non-ip`).
    pub fn parse(text: &str) -> Option<Layer> {
        let lower = text.trim().to_ascii_lowercase();
        let compact: String = lower
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        match compact.as_str() {
            "l2" | "2" | "layer2" | "link" | "datalink" | "ethernet" | "eth" => Some(Layer::L2),
            "l3" | "3" | "layer3" | "network" | "ip" => Some(Layer::L3),
            "l4" | "4" | "layer4" | "transport" => Some(Layer::L4),
            "app" | "l7" | "7" | "layer7" | "application" => Some(Layer::App),
            "other" | "local" | "nonip" => Some(Layer::Other),
            _ => None,
        }
    }

    /// Words that name this layer; a protocol at this layer matches them in a query.
    pub fn vocabulary(self) -> &'static [&'static str] {
        match self {
            Layer::L2 => &["l2", "layer2", "link", "ethernet", "frame", "frames"],
            Layer::L3 => &["l3", "layer3", "network", "ip"],
            Layer::L4 => &["l4", "layer4", "transport"],
            Layer::App => &["l7", "layer7", "application", "app"],
            Layer::Other => &["local"],
        }
    }
}

/// The layer a protocol sits at, derived from its `stack_name()`
/// (`"ETH>IP>TCP>HTTP"` is app, `"ETH>IP>UDP"` l4, `"IP>ICMP"` l3, `"ETH>ARP"` l2,
/// `"USB>HID>Keyboard"` other).
pub fn layer_of_stack(stack: &str) -> Layer {
    let tokens: Vec<String> = stack
        .split('>')
        .flat_map(|part| part.split('|'))
        .map(|part| {
            let part = part.trim();
            // `IP(89)`, `ETH(802.3)`: the parenthesised number qualifies the layer.
            let part = part.split('(').next().unwrap_or(part);
            part.trim().to_ascii_uppercase()
        })
        .filter(|t| !t.is_empty())
        .collect();

    const TRANSPORT: &[&str] = &["TCP", "UDP", "SCTP", "QUIC"];
    const NETWORK: &[&str] = &[
        "IP", "IPV4", "IPV6", "ICMP", "ICMPV6", "GRE", "IGMP", "OSPF", "VRRP", "NDP", "NETWORK",
        "VPN",
    ];
    const LINK: &[&str] = &["ETH", "ETHERNET", "LLC", "LLC/SNAP", "ARP", "LLDP", "EAPOL"];

    if let Some(last_transport) = tokens.iter().rposition(|t| TRANSPORT.contains(&t.as_str())) {
        // Anything after the last transport (TLS, HTTP, DNS…) is an application protocol.
        return if last_transport + 1 == tokens.len() {
            Layer::L4
        } else {
            Layer::App
        };
    }
    if tokens.iter().any(|t| NETWORK.contains(&t.as_str())) {
        return Layer::L3;
    }
    if tokens.iter().any(|t| LINK.contains(&t.as_str())) {
        return Layer::L2;
    }
    if tokens
        .iter()
        .any(|t| t == "APPLICATION" || t == "APP" || t == "TOR")
    {
        return Layer::App;
    }
    Layer::Other
}

/// The words of a query, lowercased and deduplicated, in the order given.
pub fn query_terms(query: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    words(query)
        .into_iter()
        .filter(|w| seen.insert(w.clone()))
        .collect()
}

/// What a protocol is searched by. Built from the protocol's own declarations.
#[derive(Debug, Clone, Default)]
pub struct Searchable<'a> {
    pub name: &'a str,
    pub keywords: Vec<&'a str>,
    pub search_terms: &'a [&'a str],
    pub group: &'a str,
    pub stack: &'a str,
    /// Prose: the description (and, for a server, its implementation note).
    pub prose: Vec<&'a str>,
}

/// How well a protocol matched a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryMatch {
    /// The query words it matched, in query order.
    pub matched: Vec<String>,
    /// How many of those matched its name, keywords, search terms, group or layer rather
    /// than only its description.
    pub strong: usize,
}

impl QueryMatch {
    /// Sort key: more words matched first, then more of them strong.
    pub fn rank(&self) -> (usize, usize) {
        (self.matched.len(), self.strong)
    }
}

/// Match `terms` (from [`query_terms`]) against a protocol. `None` when no word matches.
///
/// A word matches as a whole word (case-insensitive, a trailing plural `s` ignored), so
/// `ip` does not match `pipe` or `zip`. A word of three letters or more also matches inside
/// the protocol's name (`sql` finds `mysql`).
pub fn match_query(terms: &[String], protocol: &Searchable<'_>) -> Option<QueryMatch> {
    let name = protocol.name.to_ascii_lowercase();
    let mut strong_words: BTreeSet<String> = BTreeSet::new();
    let mut add_strong = |text: &str| {
        for w in words(text) {
            strong_words.insert(singular(&w));
        }
    };
    add_strong(protocol.name);
    for k in &protocol.keywords {
        add_strong(k);
    }
    for t in protocol.search_terms {
        add_strong(t);
    }
    add_strong(protocol.group);
    for v in layer_of_stack(protocol.stack).vocabulary() {
        add_strong(v);
    }
    let weak_words: BTreeSet<String> = protocol
        .prose
        .iter()
        .flat_map(|p| words(p))
        .map(|w| singular(&w))
        .collect();

    let mut matched = Vec::new();
    let mut strong = 0;
    for term in terms {
        let key = singular(term);
        if strong_words.contains(&key) || (term.len() >= 3 && name.contains(term.as_str())) {
            matched.push(term.clone());
            strong += 1;
        } else if weak_words.contains(&key) {
            matched.push(term.clone());
        }
    }
    if matched.is_empty() {
        None
    } else {
        Some(QueryMatch { matched, strong })
    }
}

fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_lowercase())
        .collect()
}

fn singular(word: &str) -> String {
    match word.strip_suffix('s') {
        Some(stem) if stem.len() >= 3 && !stem.ends_with('s') => stem.to_string(),
        _ => word.to_string(),
    }
}

/// One protocol's line in a `list_protocols` section, with its sort key.
#[derive(Debug, Clone)]
pub struct ProtocolRow {
    pub line: String,
    /// [`QueryMatch::rank`], or `(0, 0)` with no query.
    pub rank: (usize, usize),
    pub name: String,
}

/// The `list_protocols` filters, applied the same way to both sections.
#[derive(Debug, Clone, Copy)]
pub struct ProtocolFilters<'a> {
    pub terms: &'a [String],
    pub layer: Option<Layer>,
    pub limit: Option<usize>,
    /// Any of the above given. Without it the listing is the unfiltered one, unchanged.
    pub filtering: bool,
}

impl ProtocolFilters<'_> {
    /// The protocol's row if it passes the layer filter and the query. `text` is what the
    /// line says about it (the description, or a server's implementation note).
    pub fn row(&self, protocol: &Searchable<'_>, state: &str, text: &str) -> Option<ProtocolRow> {
        let layer = layer_of_stack(protocol.stack);
        if self.layer.is_some_and(|wanted| wanted != layer) {
            return None;
        }
        let found = if self.terms.is_empty() {
            None
        } else {
            Some(match_query(self.terms, protocol)?)
        };
        let line = if self.filtering {
            let matched = found
                .as_ref()
                .map(|m| format!(" — matched: {}", m.matched.join(", ")))
                .unwrap_or_default();
            format!(
                "- **{}** ({} · {} · {}) - {}{}\n",
                protocol.name,
                state,
                layer.as_str(),
                protocol.stack,
                text,
                matched
            )
        } else {
            format!("- **{}** ({}) - {}\n", protocol.name, state, text)
        };
        Some(ProtocolRow {
            line,
            rank: found.map_or((0, 0), |m| m.rank()),
            name: protocol.name.to_string(),
        })
    }

    /// Write one section's rows. Filtered, they are ranked (with a query), cut at `limit`,
    /// and preceded by a line saying how many of how many are shown.
    pub fn render(&self, kind: &str, total: usize, mut rows: Vec<ProtocolRow>, out: &mut String) {
        if !self.filtering {
            for row in &rows {
                out.push_str(&row.line);
            }
            return;
        }
        if !self.terms.is_empty() {
            rows.sort_by(|a, b| b.rank.cmp(&a.rank).then_with(|| a.name.cmp(&b.name)));
        }
        let matching = rows.len();
        let shown = self.limit.map_or(matching, |l| l.min(matching));
        let mut criteria = Vec::new();
        if !self.terms.is_empty() {
            criteria.push(format!("query \"{}\"", self.terms.join(" ")));
        }
        if let Some(layer) = self.layer {
            criteria.push(format!("layer {}", layer.as_str()));
        }
        let criteria = if criteria.is_empty() {
            String::new()
        } else {
            format!(" matching {}", criteria.join(", "))
        };
        let order = if self.terms.is_empty() {
            ""
        } else {
            "; best match first"
        };
        out.push_str(&format!(
            "Showing {shown} of {matching} {kind} protocol(s){criteria}, out of {total} in total{order}.\n\n"
        ));
        for row in rows.iter().take(shown) {
            out.push_str(&row.line);
        }
        if shown < matching {
            out.push_str(&format!(
                "- … {} more; raise `limit` or narrow the query\n",
                matching - shown
            ));
        }
        if matching == 0 {
            out.push_str(
                "No match. Try fewer or broader words, or a `layer` (l2, l3, l4, app, other).\n",
            );
        }
    }
}
