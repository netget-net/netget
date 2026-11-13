//! Matching a protocol *name* against the registries, and matching keywords as whole words.
//!
//! Two kinds of caller hand the registries a string:
//!
//! - **Free text** — a prompt, a model's `base_stack` — goes through `parse_from_str` /
//!   `resolve`, which look for a declared keyword anywhere in the input. They match keywords
//!   as whole words ([`contains_words`]): `mptcp` used to resolve to `tcp` because the client
//!   registry tested `"mptcp".contains("tcp")` and the server registry ended with "anything
//!   containing `tcp` is TCP".
//! - **A name** — MCP `get_protocol_docs` / `start_server` / `start_client`, the CLI's
//!   `--server` / `--client`, the model's `read_documentation` — goes through `resolve_name`,
//!   which accepts only the canonical name, or a stack name or declared keyword equal to the
//!   whole input that belongs to exactly one protocol ([`lookup_among`]). A stack name or
//!   keyword several protocols share is refused with their names; anything else is an error
//!   with did-you-mean suggestions, never the closest substring hit: a caller asking for a
//!   protocol by name must get that protocol or be told it does not exist.

/// Lowercase, trimmed, with `-` and spaces folded to `_`: `"SSH Agent"`, `"ssh-agent"` and
/// `"ssh_agent"` all compare equal.
pub fn normalize(s: &str) -> String {
    s.trim().to_lowercase().replace(['-', ' '], "_")
}

/// How an input named a protocol in an exact-name lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameMatch {
    /// The protocol's own name, in any case or `-`/`_`/space spelling.
    Canonical,
    /// Its stack name, e.g. `ETH>IP>TCP>HTTP`.
    StackName,
    /// One of its declared keywords, as declared.
    Alias(String),
}

impl NameMatch {
    /// The keyword the input matched, when it named the protocol by an alias.
    pub fn alias(&self) -> Option<&str> {
        match self {
            NameMatch::Alias(a) => Some(a),
            _ => None,
        }
    }
}

/// The outcome of an exact-name lookup (`ServerRegistry::lookup_name` /
/// `ClientRegistry::lookup_name`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameLookup {
    /// The input names exactly one protocol (registry key, and how it was named).
    Found(String, NameMatch),
    /// The input is a stack name or a declared keyword of more than one protocol. Picking one
    /// would start something the operator may not have meant, so the caller is refused and
    /// shown these canonical names, sorted.
    Ambiguous(Vec<String>),
    /// No protocol has this name, stack name or keyword.
    NotFound,
}

/// Find the one protocol `wanted` (already [`normalize`]d) names among `protocols` — `(registry
/// key, canonical name, stack name, keywords)` — or say that it names several or none.
///
/// A canonical name always wins: it is unique by construction and an operator who types it
/// means that protocol even when another protocol happens to declare the same word as a
/// keyword. A stack name or keyword shared by more than one protocol is
/// [`NameLookup::Ambiguous`] rather than whichever sorts first.
pub fn lookup_among<'a, I>(wanted: &str, protocols: I) -> NameLookup
where
    I: IntoIterator<Item = (&'a str, &'a str, &'a str, Vec<&'a str>)>,
{
    if wanted.is_empty() {
        return NameLookup::NotFound;
    }
    let mut stack_hits: Vec<(&str, &str)> = Vec::new();
    let mut alias_hits: Vec<(&str, &str, &str)> = Vec::new();
    for (key, canonical, stack, keywords) in protocols {
        if normalize(canonical) == wanted || normalize(key) == wanted {
            return NameLookup::Found(key.to_string(), NameMatch::Canonical);
        }
        if normalize(stack) == wanted {
            stack_hits.push((key, canonical));
        }
        if let Some(keyword) = keywords.into_iter().find(|k| normalize(k) == wanted) {
            alias_hits.push((key, canonical, keyword));
        }
    }
    let ambiguous = |mut names: Vec<String>| {
        names.sort();
        names.dedup();
        NameLookup::Ambiguous(names)
    };
    match stack_hits.as_slice() {
        [(key, _)] => return NameLookup::Found(key.to_string(), NameMatch::StackName),
        [] => {}
        several => {
            return ambiguous(several.iter().map(|(_, c)| c.to_string()).collect());
        }
    }
    match alias_hits.as_slice() {
        [(key, _, keyword)] => {
            NameLookup::Found(key.to_string(), NameMatch::Alias(keyword.to_string()))
        }
        [] => NameLookup::NotFound,
        several => ambiguous(several.iter().map(|(_, c, _)| c.to_string()).collect()),
    }
}

/// A character that may not sit next to a keyword for the keyword to count as a whole word.
fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Whether `keyword` occurs in `input` as whole words: not preceded or followed by a letter,
/// digit, `_` or `-`. Every occurrence is tried, so `"tcpx tcp"` contains `"tcp"`. A
/// multi-word keyword (`"mail server"`) is bounded the same way at both ends, so it does not
/// match inside `"email server"`. Both sides are compared as given; lowercase them first.
pub fn contains_words(input: &str, keyword: &str) -> bool {
    if keyword.is_empty() {
        return false;
    }
    let bytes = input.as_bytes();
    let mut from = 0;
    while let Some(off) = input[from..].find(keyword) {
        let pos = from + off;
        let end = pos + keyword.len();
        let before_ok = pos == 0 || !is_word_char(bytes[pos - 1]);
        let after_ok = end >= bytes.len() || !is_word_char(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        // Advance past this occurrence's first character, staying on a char boundary.
        from = pos + input[pos..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// Up to three did-you-mean candidates for an input no protocol is named by: protocols whose
/// keywords occur in it as whole words (`free_text_hit`, from the registry's free-text
/// parser), then names within a typo's edit distance of it.
pub fn suggestions(
    input: &str,
    free_text_hit: Option<String>,
    known_names: &[&str],
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(hit) = free_text_hit {
        out.push(hit);
    }
    let input_norm = normalize(input);
    let threshold = (input_norm.chars().count() / 3).max(2);
    let mut close: Vec<(usize, &str)> = known_names
        .iter()
        .map(|name| (levenshtein(&input_norm, &normalize(name)), *name))
        .filter(|(d, _)| *d <= threshold)
        .collect();
    close.sort();
    for (_, name) in close {
        if out.len() >= 3 {
            break;
        }
        if !out.iter().any(|o| normalize(o) == normalize(name)) {
            out.push(name.to_string());
        }
    }
    out
}

/// `'a'`, `'a' or 'b'`, `'a', 'b' or 'c'`.
pub fn or_list(names: &[String]) -> String {
    let quoted: Vec<String> = names.iter().map(|n| format!("'{n}'")).collect();
    match quoted.split_last() {
        None => String::new(),
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} or {}", rest.join(", "), last),
    }
}

/// Levenshtein edit distance.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut dp: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut prev = dp[0];
        dp[0] = i;
        for j in 1..=b.len() {
            let tmp = dp[j];
            dp[j] = if a[i - 1] == b[j - 1] {
                prev
            } else {
                1 + prev.min(dp[j]).min(dp[j - 1])
            };
            prev = tmp;
        }
    }
    dp[b.len()]
}
