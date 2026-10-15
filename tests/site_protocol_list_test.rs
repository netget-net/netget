//! The landing page's protocol table lists every protocol, and this keeps it that way.
//!
//! `site/index.html` lists every protocol in a hand-grouped table. It drifts silently — a
//! protocol lands in the registries and nobody thinks of the website — so this walks the files
//! a visitor's claims rest on: every registered protocol is on the page, and nothing on the
//! page is a protocol that no longer exists. Whole-tree source scan.
//!
//! A protocol's identity on the page is its id in `scripts/site_protocol_ids.json`, one entry
//! per `register()` call in either registry. Protocols are not Cargo features, so that file is
//! where the id lives; a new protocol adds its registrations there and its link here.
//!
//! The same number is the headline: every "<N> Protocols" / "<N> network protocols" /
//! "<N> protocol features" on the page and in the README must be exactly the count of
//! protocols, and a rounded-down "150+" is a failure that names the line to fix.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

/// Every registration in both registries, as `role::path` (the id map's keys).
fn registrations() -> BTreeSet<String> {
    let mut all = BTreeSet::new();
    for role in ["server", "client"] {
        let source = fs::read_to_string(format!("src/protocol/{role}_registry.rs")).unwrap();
        let needle = format!("self.register(Arc::new(");
        let mut rest = source.as_str();
        while let Some(i) = rest.find(&needle) {
            let after = rest[i + needle.len()..].trim_start();
            let path = after
                .strip_prefix(&format!("crate::{role}::"))
                .unwrap_or_else(|| panic!("unrecognised {role} registration: {}", &after[..60]));
            let end = path
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
                .unwrap();
            all.insert(format!("{role}::{}", &path[..end]));
            rest = &rest[i + needle.len()..];
        }
    }
    all
}

fn site_ids() -> BTreeMap<String, String> {
    serde_json::from_str(&fs::read_to_string("scripts/site_protocol_ids.json").unwrap()).unwrap()
}

fn protocol_features() -> BTreeSet<String> {
    site_ids().into_values().collect()
}

#[test]
fn every_registration_has_a_site_id() {
    let ids = site_ids();
    let registered = registrations();
    assert!(registered.len() > 200, "registry scan found only {}", registered.len());
    let missing: Vec<_> = registered.iter().filter(|r| !ids.contains_key(*r)).collect();
    let stale: Vec<_> = ids.keys().filter(|k| !registered.contains(*k)).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "scripts/site_protocol_ids.json drifted from the registries.\n  registered without an id: \
         {missing:?}\n  ids for no registration: {stale:?}"
    );
}

/// Every token in the page's protocol table.
fn page_tokens() -> BTreeSet<String> {
    let page = fs::read_to_string("site/index.html").expect("site/index.html");
    let mut all = BTreeSet::new();
    let mut rest = page.as_str();
    while let Some(i) = rest.find("<span class=\"proto-list\">") {
        let after = &rest[i + "<span class=\"proto-list\">".len()..];
        let end = after.find("</span>").expect("proto-list closes");
        let inner = &after[..end];
        let mut links = inner;
        while let Some(start) = links.find("<a ") {
            let link = &links[start..];
            let tag_end = link.find('>').expect("protocol anchor opens");
            let tag = &link[..tag_end];
            assert!(
                tag.contains("href=\"https://en.wikipedia.org/wiki/"),
                "Wikipedia link: {tag}"
            );
            assert!(tag.contains("target=\"_blank\""), "opens a new tab: {tag}");
            assert!(
                tag.contains("rel=\"noopener noreferrer\""),
                "safe external link: {tag}"
            );
            let (_, feature) = tag
                .split_once(" · protocol: ")
                .expect("protocol identity in title");
            let feature = feature.split('"').next().unwrap();
            assert!(
                all.insert(feature.to_string()),
                "duplicate protocol: {feature}"
            );
            let close = link.find("</a>").expect("protocol anchor closes");
            assert!(
                !link[tag_end + 1..close].trim().is_empty(),
                "display name: {feature}"
            );
            links = &link[close + 4..];
        }
        rest = &after[end..];
    }
    all
}

#[test]
fn every_protocol_feature_is_on_the_landing_page_and_nothing_else_is() {
    let features = protocol_features();
    let on_page = page_tokens();
    assert!(
        features.len() > 100,
        "feature scan found only {}",
        features.len()
    );
    let missing: Vec<_> = features.difference(&on_page).cloned().collect();
    let stale: Vec<_> = on_page.difference(&features).cloned().collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "site/index.html's protocol table drifted from scripts/site_protocol_ids.json.\n  missing from the page: {missing:?}\n  on the page but not a protocol: {stale:?}\n\
         Add each missing protocol to the fitting row of the table, and remove stale ones."
    );
}

/// Every protocol-count claim in `text`: a number, with or without a `+`, followed by
/// "protocol…" or "network protocol…". Returns (1-based line, the claim as written, the
/// number, whether it carried a `+`).
fn count_claims(text: &str) -> Vec<(usize, String, usize, bool)> {
    let mut claims = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let words: Vec<&str> = line.split_whitespace().collect();
        for (j, word) in words.iter().enumerate() {
            // A tag or an attribute can sit right before the number (`>179`, `"179`).
            let word = word.rsplit(['>', '"', '(']).next().unwrap_or(word);
            let (digits, plus) = match word.strip_suffix('+') {
                Some(d) => (d, true),
                None => (word, false),
            };
            let Ok(n) = digits.parse::<usize>() else {
                continue;
            };
            let next = words.get(j + 1).copied().unwrap_or("");
            let after = words.get(j + 2).copied().unwrap_or("");
            // Headings capitalise ("240 Protocols", "50+ Network Protocols").
            let (lnext, lafter) = (next.to_lowercase(), after.to_lowercase());
            let names_protocols = lnext.starts_with("protocol")
                || (lnext == "network" && lafter.starts_with("protocol"));
            if names_protocols {
                let claim = if lnext == "network" {
                    format!("{word} {next} {after}")
                } else {
                    format!("{word} {next}")
                };
                claims.push((i + 1, claim, n, plus));
            }
        }
    }
    claims
}

/// The headline count is stated on the page's Protocols heading and twice in the README (its
/// opening sentence and its feature list), and each must be the exact number of protocol
/// features, not a rounded-down "150+". The redesigned page's meta, og and hero text state no
/// count, so they are not required to.
#[test]
fn every_headline_count_is_the_exact_number() {
    let n = protocol_features().len();
    let mut problems = Vec::new();
    let mut seen = 0;
    for file in ["site/index.html", "README.md"] {
        let text = fs::read_to_string(file).expect(file);
        let claims = count_claims(&text);
        assert!(
            !claims.is_empty(),
            "{file} states no protocol count at all; the scan in this test has gone blind"
        );
        for (line, claim, count, plus) in claims {
            seen += 1;
            if plus || count != n {
                problems.push(format!(
                    "  {file}:{line}: \"{claim}\" — write the exact count, {n} (the protocol \
                     ids in scripts/site_protocol_ids.json), with no \"+\""
                ));
            }
        }
    }
    assert!(
        seen >= 3,
        "expected the count in at least three places (the Protocols heading, the README's opening sentence and feature list), found {seen}"
    );
    assert!(
        problems.is_empty(),
        "a protocol count on the site or in the README is not the exact number ({n}):\n{}",
        problems.join("\n")
    );
}
