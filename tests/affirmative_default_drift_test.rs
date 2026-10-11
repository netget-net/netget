//! An omitted field must never read as a yes.
//!
//! `action.get("sw1").and_then(|v| v.as_u64()).unwrap_or(0x90)` is the single most dangerous
//! line shape in this repository, because every part of it looks defensive. There is a lookup,
//! there is a type check, and there is a default so nothing panics. What it actually says is
//! *when the model says nothing, approve* — and in a smartcard that is `90 00`, the status word
//! an ISO 7816 VERIFY returns when the PIN was correct.
//!
//! Programme 2 found it three times, in protocols that share no code:
//!
//! * **`nfc`** and **`usb/smartcard`** each defaulted an APDU status word to `90 00`, and each
//!   did it in *two* layers — so removing one left the other approving. An LLM that returned no
//!   `sw1`/`sw2` at all, or whose answer failed to parse into them, authenticated the card.
//! * **`oauth2`** answered token introspection `{"active": true}` for every bearer token,
//!   including one the server had never issued. Its own `CLAUDE.md` described this as a feature
//!   ("ensures the server always responds correctly").
//!
//! All three are fixed. This test exists so the fourth fails the build instead of shipping.
//!
//! # The rule
//!
//! Over every `.rs` under `src/server` and `src/client`, a `.unwrap_or(X)` / `.unwrap_or_else(||
//! X)` / `.map_or(X, ..)` is flagged when **all** of these hold:
//!
//! 1. the receiver chain traces back to a JSON lookup — `<something>.get("<key>")` or
//!    `<something>["<key>"]` — so the value is one the *model* supplied;
//! 2. the **last** such key in that chain (the innermost lookup, i.e. the field actually being
//!    unwrapped) has a segment in [`VERDICT_SEGMENTS`];
//! 3. `X` is affirmative *for that key* — see [`is_affirmative`]. Affirmativeness is per
//!    (name, literal), not per literal: `0` is success for an `error_code` and garbage for a
//!    SIP `status_code`, and `sip` says so in a comment beside its deliberate `unwrap_or(0)`.
//!
//! # Why the key vocabulary is narrow, and why the last key is the one that counts
//!
//! `unwrap_or(true)` appears 40 times in this tree, on `eof`, `on_link`, `join_multicast`,
//! `write_protect`, `incremental`, `nullable`, `use_tls`, `enable_user_plane` and the like.
//! Defaulting any of those to `true` is a product decision, not a fail-open — none of them is
//! the answer to "may this peer proceed". Flagging them would put ~40 entries in the baseline
//! that nobody would ever remove, and `startup_param_drift_test.rs` records what happens next:
//! its strict first version flagged 57 parameters and was abandoned, because a false positive
//! in a build-failing check trains people to edit the baseline instead of the code. So the
//! vocabulary is verdicts only.
//!
//! Taking the **last** key rather than the first matters as much. `item.get("status").and_then(
//! |s| s.get("replicas")).unwrap_or(0)` is a Kubernetes table cell, not a status: the value
//! being defaulted is `replicas`, and `status` is only a path segment on the way to it. An
//! earlier version of this rule took the first decision-shaped key it found anywhere in the
//! chain and reported both of `kubernetes/table.rs`'s cell helpers plus `snmp`'s `error_index`.
//!
//! **The baseline may only shrink.** The fix is to make the absence of the field a refusal:
//! `.context("send_x_response needs an explicit status_code")?`, or a fail-closed value, and
//! for a verdict the two must not share a code path — see `radius`, where nothing in
//! `actions.rs` can synthesise an Access-Accept at all.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp --test affirmative_default_drift_test

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// `role:protocol:file:line:key=literal` for every model-supplied verdict with an affirmative
/// default.
///
/// Each of these is a true positive of the rule: the model omits the field, and the peer is
/// told yes. They are recorded rather than fixed because each fix is a behaviour change to a
/// protocol's action contract, which belongs with that protocol's owner — but none of them may
/// be *added* to, and the next one fails the build.
///
/// **The HTTP-status family** (`couchdb`, `dynamo`, `elasticsearch`, `hls`, `http2`,
/// `ipp`'s `http_status`, `kubernetes`, `s3`, `spark`, `sqs`, `yarn`). The model emits a
/// `<proto>_response` action and omits `status`; the peer reads `200 OK` with whatever body
/// came along. `s3` argues the case for this in a comment at the site — emitting the action at
/// all is the assertion, and the status refines it — and that argument is worth reading before
/// changing any of them. The fix where it is not deliberate is `.context("… needs an explicit
/// status")?`: a model that meant 404 and mistyped the key currently ships a 200.
///
/// **`ipp_status` → `"successful-ok"`** (three sites). IPP carries its own status independently
/// of the HTTP one, so an omitted `ipp_status` says the print job succeeded inside an HTTP 200
/// that says nothing of the sort. Fix: require it, or default to `server-error-internal-error`,
/// which is the fail-closed value IPP actually defines.
///
/// **`mqtt` `return_code` → `0`.** MQTT 3.1.1 CONNACK code 0 is *Connection Accepted*; 5 is
/// *not authorized*. A model that answered a CONNECT with an action missing `return_code`
/// admits the client. The executor already range-checks `> 5` two lines later, so the fix is
/// one line: make the field required rather than defaulted.
///
/// **`zookeeper` `error_code` → `0`** (two sites). ZooKeeper `Ok` is 0, and `mod.rs` computes
/// `is_error` from it, so an omitted error code turns a refusal into a successful reply.
// Fixed 15 Sep 2026 and removed from this list rather than re-pointed at their new lines:
// `spark`'s `status` (which was also an unchecked `as u16`, so 65736 became 200) and
// `zookeeper`'s two `error_code` sites now default to failure - 500 and `SystemError` (-1) -
// because a reply the model did not finish describing is not a success. They were caught by
// this ratchet firing on merged code whose lines had shifted, which is the shrink-only half
// doing its job in both directions at once.
const AFFIRMATIVE_DEFAULT_BASELINE: &[&str] = &[
    "server:couchdb:mod.rs:status=200",
    "server:dynamo:mod.rs:status=200",
    "server:elasticsearch:mod.rs:status=200",
    "server:hls:mod.rs:status_code=200",
    "server:hls:mod.rs:status_code=200",
    "server:http2:h2_server.rs:status=200",
    "server:ipp:actions.rs:ipp_status=\"successful-ok\"",
    "server:ipp:actions.rs:ipp_status=\"successful-ok\"",
    "server:ipp:actions.rs:ipp_status=\"successful-ok\"",
    "server:ipp:mod.rs:http_status=200",
    "server:kubernetes:actions.rs:status_code=200",
    "server:s3:actions.rs:status_code=200",
    "server:s3:mod.rs:status_code=200",
    "server:sqs:mod.rs:status=200",
    "server:yarn:mod.rs:status=200",
];

/// Key-name segments that mean "this field *is* the verdict".
///
/// A `status`, a `code`, a `result`, an APDU `sw1`/`sw2`, and the plain adjectives
/// (`ok`/`success`/`allowed`/`active`/`valid`/`authorized`/…) share the property that the value
/// is the whole answer: there is no other field the peer consults to learn whether it may
/// proceed. `eof`, `nullable`, `incremental` and their kin do not, which is why they are absent
/// — see the module docs.
const VERDICT_SEGMENTS: &[&str] = &[
    "status",
    "code",
    "result",
    "sw",
    "sw1",
    "sw2",
    "ok",
    "success",
    "allowed",
    "active",
    "valid",
    "authorized",
    "authorised",
    "approved",
    "granted",
    "permitted",
    "authenticated",
    "rcode",
    "rc",
];

/// Literals that are affirmative whatever the field is called.
const AFFIRMATIVE_ANYWHERE: &[&str] = &[
    "true",
    "\"true\"",
    "\"yes\"",
    "\"ok\"",
    "\"OK\"",
    "\"success\"",
    "\"Success\"",
    "\"SUCCESS\"",
    "\"successful-ok\"",
    "\"active\"",
    "\"valid\"",
    "\"allowed\"",
    "\"granted\"",
    "\"approved\"",
];

/// Final name segments for which a literal `0` means *no error*.
///
/// `error_code: 0`, `return_code: 0` and `rcode: 0` are success in ZooKeeper, MQTT and DNS
/// respectively. A bare `status_code: 0` is not success anywhere — it is not a code at all —
/// which is why `sip`'s deliberate `unwrap_or(0)`, sitting under a comment explaining that a
/// missing status must *not* read as 200, is correctly not flagged.
const ZERO_IS_SUCCESS_LAST: &[&str] = &["code", "result", "rc", "rcode", "sw", "sw1", "sw2"];

/// Name tokens that make a `0` a verdict rather than an index or a count.
///
/// `error_subcode: 0` is BGP's "Unspecific" *inside* a NOTIFICATION that is already a refusal,
/// and `error_index: 0` is the SNMP varbind index that goes with `error_status` — neither is
/// the decision, and both were false positives of an earlier version that keyed on the final
/// segment alone.
const ZERO_VERDICT_TOKENS: &[&str] = &["error", "return", "result", "rcode", "rc", "sw"];

fn is_verdict_key(key: &str) -> bool {
    key.split('_')
        .any(|seg| VERDICT_SEGMENTS.contains(&seg.to_ascii_lowercase().as_str()))
}

/// Is `literal` an affirmative default for a field called `key`?
fn is_affirmative(key: &str, literal: &str) -> bool {
    if AFFIRMATIVE_ANYWHERE.contains(&literal) {
        return true;
    }
    let name = key.to_ascii_lowercase();
    let last = name.rsplit('_').next().unwrap_or(&name).to_string();

    // HTTP/SIP/IPP success.
    if matches!(literal, "200" | "\"200\"") && (name.contains("status") || name.contains("code")) {
        return true;
    }
    // "No error".
    if matches!(
        literal,
        "0" | "\"0\"" | "0u8" | "0u16" | "0u32" | "0i32" | "0i64" | "0u64" | "0x0" | "0x00"
    ) {
        return ZERO_IS_SUCCESS_LAST.contains(&last.as_str())
            && ZERO_VERDICT_TOKENS.iter().any(|t| name.contains(t));
    }
    // ISO 7816 `90 00` — the smartcard/NFC defect, in each of the spellings the tree used.
    if matches!(
        literal,
        "0x90" | "144" | "\"90\"" | "\"9000\"" | "\"90 00\"" | "0x9000" | "36864"
    ) {
        return name.contains("sw") || name.contains("status");
    }
    false
}

// ---------------------------------------------------------------------------
// Source scanning
// ---------------------------------------------------------------------------

/// Remove `//` comments **without** cutting inside a string literal.
///
/// The obvious line-wise `split("//")` version is wrong, and wrong in the silent direction: any
/// line carrying a URL is truncated at the `//` in its own literal, so everything after it —
/// including the `.unwrap_or(…)` this scan is looking for — disappears. That cost `tests/
/// vendor_default_fallback_test.rs` a whole limb before it was noticed there. It changes
/// nothing in this file's findings today, but the next site to land on such a line would have
/// been invisible.
fn strip_comments(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0usize;
    let mut in_string = false;
    while i < b.len() {
        let c = b[i];
        if in_string {
            // An escape can hide a closing quote; blank both halves so the literal's own
            // length is preserved and `\"` cannot end the string.
            if c == '\\' && i + 1 < b.len() {
                // Blank both halves, but keep a newline: Rust's line continuation (a `\`
                // at end of line inside a literal) is an escape whose second character IS
                // the newline, and swallowing it silently shifted every line number below
                // it — nine of them in `ipp/actions.rs` alone.
                out.push(' ');
                out.push(if b[i + 1] == '\n' { '\n' } else { ' ' });
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            out.push(c);
            i += 1;
            continue;
        }
        // A char literal may *be* a quote (`'\"'`), and reading it as the start of a
        // string inverts the quote parity for the rest of the file. Lifetimes (`'a`) are
        // left alone, which is why the closing `'` has to be where a char literal puts it.
        if c == '\'' {
            let simple = i + 2 < b.len() && b[i + 2] == '\'';
            let escaped = i + 3 < b.len() && b[i + 1] == '\\' && b[i + 3] == '\'';
            if simple || escaped {
                let n = if simple { 3 } else { 4 };
                for k in 0..n {
                    out.push(if b[i + k] == '\n' { '\n' } else { ' ' });
                }
                i += n;
                continue;
            }
        }
        if c == '"' {
            in_string = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < b.len() && b[i + 1] == '/' {
            while i < b.len() && b[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Start of the receiver chain ending at `pos`, balancing brackets and stopping at any
/// statement or operator boundary — the same walk `narrowing_cast_drift_test` uses.
fn chain_before(chars: &[char], pos: usize) -> usize {
    let mut depth = 0i32;
    let mut i = pos;
    while i > 0 {
        let c = chars[i - 1];
        match c {
            ')' | ']' | '}' => depth += 1,
            '(' | '[' | '{' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            ';' | ',' | '=' | '+' | '-' | '*' | '/' | '%' | '|' | '&' | '^' | '<' | '>' | '!'
                if depth == 0 =>
            {
                break
            }
            _ => {}
        }
        i -= 1;
    }
    i
}

/// Every `X.get("key")` / `X["key"]` in a slice of source, in order.
///
/// Only a literal in lookup position counts. The `.context("Missing 'code'")` message that
/// almost every one of these chains carries is a string too, and reading it as a lookup would
/// double every finding and misattribute half of them.
fn json_keys(chunk: &str) -> Vec<String> {
    let b: Vec<char> = chunk.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == '"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != '"' {
                j += 1;
            }
            if j < b.len() {
                let key: String = b[i + 1..j].iter().collect();
                // Only the few characters before the literal decide whether it is in lookup
                // position, and taking the whole prefix here made the scan quadratic.
                let before: String = b[..i].iter().rev().take(16).collect::<String>();
                let before: String = before.chars().rev().collect();
                let before = before.trim_end();
                let after: String = b[j + 1..].iter().take(8).collect();
                let after = after.trim_start();
                let opens = before.ends_with(".get(") || before.ends_with('[');
                let closes = after.starts_with(')') || after.starts_with(']');
                if opens && closes && !key.is_empty() && key.chars().all(is_ident_char) {
                    out.push(key);
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// A model-supplied verdict with an affirmative default.
struct Site {
    line: usize,
    key: String,
    literal: String,
}

/// The combinators whose first argument is the value used when the lookup produced nothing.
const DEFAULTING: &[&str] = &[".unwrap_or_else(", ".unwrap_or(", ".map_or("];

fn scan_file(path: &Path) -> Vec<Site> {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let src = strip_comments(&raw);
    let chars: Vec<char> = src.chars().collect();

    let mut line_of = Vec::with_capacity(chars.len() + 1);
    let mut line = 1usize;
    for &c in &chars {
        line_of.push(line);
        if c == '\n' {
            line += 1;
        }
    }
    line_of.push(line);

    let mut sites = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        let Some(call) = DEFAULTING.iter().find(|pat| {
            let p: Vec<char> = pat.chars().collect();
            i + p.len() <= chars.len() && chars[i..i + p.len()] == p[..]
        }) else {
            i += 1;
            continue;
        };
        let recv_end = i;
        let mut a = i + call.chars().count();
        i = a;

        // The default expression: skip whitespace, an `|| ` closure head, then take one token.
        while a < chars.len() && chars[a].is_whitespace() {
            a += 1;
        }
        if a + 1 < chars.len() && chars[a] == '|' && chars[a + 1] == '|' {
            a += 2;
            while a < chars.len() && chars[a].is_whitespace() {
                a += 1;
            }
        }
        let mut b = a;
        if b < chars.len() && chars[b] == '"' {
            b += 1;
            while b < chars.len() && chars[b] != '"' {
                b += 1;
            }
            b = (b + 1).min(chars.len());
        } else {
            while b < chars.len() && (is_ident_char(chars[b]) || chars[b] == '.') {
                b += 1;
            }
        }
        if b == a {
            continue;
        }
        // Only a bare literal counts; anything else (a call, an expression) is not this class.
        let mut t = b;
        while t < chars.len() && chars[t].is_whitespace() {
            t += 1;
        }
        if t >= chars.len() || (chars[t] != ')' && chars[t] != ',') {
            continue;
        }
        let literal: String = chars[a..b].iter().collect();

        let start = chain_before(&chars, recv_end);
        let chunk: String = chars[start..recv_end].iter().collect();
        // The *last* lookup in the chain is the field being defaulted; earlier ones are the
        // path taken to reach it.
        let Some(key) = json_keys(&chunk).pop() else {
            continue;
        };
        if !is_verdict_key(&key) || !is_affirmative(&key, &literal) {
            continue;
        }
        sites.push(Site {
            line: line_of[recv_end],
            key,
            literal,
        });
    }
    sites
}

fn rust_files(root: &Path) -> Vec<(String, String, PathBuf)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String, PathBuf)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                walk(&p, root, out);
            } else if p.extension().is_some_and(|e| e == "rs") {
                let parent = p.parent().unwrap();
                out.push((
                    parent
                        .strip_prefix(root)
                        .unwrap_or(parent)
                        .to_string_lossy()
                        .to_string(),
                    p.file_name().unwrap().to_string_lossy().to_string(),
                    p.clone(),
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn survey() -> BTreeSet<String> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = BTreeSet::new();
    for (role, dir) in [("server", "src/server"), ("client", "src/client")] {
        let root = manifest.join(dir);
        for (protocol, file, path) in rust_files(&root) {
            if protocol.is_empty() {
                continue;
            }
            for s in scan_file(&path) {
                // Deliberately NOT keyed on the line number.
                //
                // It was, and that made the baseline break on edits that had nothing to do
                // with it: the September spawn-registration sweep touched 113 `mod.rs` files
                // and every baselined entry below it shifted, so each one appeared as "new" at
                // one line and "gone" at another, and the ratchet went red twice in a day for
                // code nobody had changed. A reviewer who sees that twice stops reading the
                // output, which is the failure mode a build-failing check can least afford.
                //
                // `protocol:file:field=literal` is stable under every edit that does not
                // change what the defaulting does. The cost is that two identical defaults on
                // the same field in one file collapse to one entry — acceptable, because the
                // fix for one is the fix for both.
                found.insert(format!("{role}:{protocol}:{file}:{}={}", s.key, s.literal));
            }
        }
    }
    found
}

// ---------------------------------------------------------------------------
// The ratchet
// ---------------------------------------------------------------------------

#[test]
fn no_new_affirmative_default_on_a_verdict_field() {
    let found = survey();
    let found_refs: BTreeSet<&str> = found.iter().map(String::as_str).collect();
    let baseline: BTreeSet<&str> = AFFIRMATIVE_DEFAULT_BASELINE.iter().copied().collect();

    let new: Vec<_> = found_refs.difference(&baseline).copied().collect();
    assert!(
        new.is_empty(),
        "these default a model-supplied verdict to an affirmative value, so an omitted or \
         unparseable field tells the peer yes: {new:?}\n\
         `sw1` defaulted to 0x90 is an ISO 7816 'PIN correct'; `active` defaulted to true is an \
         OAuth2 token the server never issued; `error_code` defaulted to 0 is ZooKeeper 'Ok'. \
         Make the absence of the field a refusal — `.context(\"… requires an explicit \
         <field>\")?` — or default to the value the protocol defines for failure. And keep the \
         model's rejection path structurally distinct from its no-answer path, so a backend \
         outage cannot be mistaken for approval: `radius` is the worked example."
    );

    let fixed: Vec<_> = baseline.difference(&found_refs).copied().collect();
    assert!(
        fixed.is_empty(),
        "these are gone or moved — update AFFIRMATIVE_DEFAULT_BASELINE so the ratchet keeps \
         its grip: {fixed:?}"
    );
}

/// A scan that quietly matches nothing passes forever.
#[test]
fn the_scan_is_reading_real_source() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (dir, min) in [("src/server", 300usize), ("src/client", 200)] {
        let n = rust_files(&manifest.join(dir)).len();
        assert!(n >= min, "{dir}: {n} .rs files, expected at least {min}");
    }
    let found = survey();
    // 13, not the 19 this started at, and the drop is arithmetic rather than progress: the
    // key stopped carrying a line number (see `survey`), so several identical defaults on the
    // same field in the same file collapsed into one entry. Three real fixes came out too —
    // spark, and zookeeper's two — which is the rest of the difference.
    //
    // The floor exists to catch the `.get("…")` anchor silently ceasing to resolve, which
    // would take this to zero. It is set below the true count and not at it, so an actual
    // fix does not have to edit this line to land.
    assert!(
        found.len() >= 10,
        "the survey found {} affirmative defaults on verdict fields; there were 13 after the \
         September rekey, so a number this low means the `.get(\"…\")` anchor stopped \
         resolving rather than that the code got better",
        found.len()
    );
}

/// What the rule does on inputs whose right answer is known.
///
/// The tree is the ratchet's subject and cannot also be its test. Cases 1 and 2 are the
/// historical defects verbatim; the rest are the shapes that must *not* fire, each one drawn
/// from something this scan reported while it was being written.
#[test]
fn the_rule_flags_the_historical_defects_and_not_their_neighbours() {
    fn sites(body: &str) -> Vec<(String, String)> {
        let dir = std::env::temp_dir().join(format!(
            "netget-affirmative-default-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("scan.rs");
        std::fs::write(&f, body).unwrap();
        let out = scan_file(&f)
            .into_iter()
            .map(|s| (s.key, s.literal))
            .collect();
        let _ = std::fs::remove_file(&f);
        out
    }

    // 1. `nfc` / `usb-smartcard`: the APDU status word, in both layers' spellings.
    assert_eq!(
        sites(
            r#"fn f() { let sw1 = action.get("sw1").and_then(|v| v.as_u64()).unwrap_or(0x90) as u8; }"#
        ),
        vec![("sw1".to_string(), "0x90".to_string())],
        "a status word defaulted to 0x90 is an ISO 7816 'PIN correct' and must be flagged"
    );
    assert_eq!(
        sites(
            r#"fn f() { let sw = action.get("status_word").and_then(|v| v.as_str()).unwrap_or("9000"); }"#
        ),
        vec![("status_word".to_string(), "\"9000\"".to_string())],
        "the string spelling of the same default must be flagged too"
    );

    // 2. `oauth2`: introspection answering yes for every token.
    assert_eq!(
        sites(
            r#"fn f() { let active = action.get("active").and_then(|v| v.as_bool()).unwrap_or(true); }"#
        ),
        vec![("active".to_string(), "true".to_string())],
        "`active` defaulted to true is the OAuth2 introspection defect"
    );

    // 3. The fix: absence is a refusal, so there is no default to flag.
    assert!(
        sites(r#"fn f() { let sw1 = action.get("sw1").and_then(|v| v.as_u64()).context("needs sw1")?; }"#)
            .is_empty(),
        "requiring the field is the fix and must not be reported"
    );

    // 4. Fail-closed default: the same shape, the opposite value.
    assert!(
        sites(
            r#"fn f() { let sw1 = action.get("sw1").and_then(|v| v.as_u64()).unwrap_or(0x69); }"#
        )
        .is_empty(),
        "0x69 is 'command not allowed'; defaulting *to a refusal* is the recommended fix"
    );

    // 5. Not a verdict. `unwrap_or(true)` on these is a product decision and there are ~40 of
    //    them; flagging them is how a baseline becomes something people edit instead of read.
    for body in [
        r#"fn f() { let eof = action.get("eof").and_then(|v| v.as_bool()).unwrap_or(true); }"#,
        r#"fn f() { let x = action.get("write_protect").and_then(|v| v.as_bool()).unwrap_or(true); }"#,
        r#"fn f() { let x = action.get("join_multicast").and_then(|v| v.as_bool()).unwrap_or(true); }"#,
    ] {
        assert!(sites(body).is_empty(), "not a verdict field: {body}");
    }

    // 6. `kubernetes/table.rs`: `status` is a path segment, `replicas` is the value. Keying on
    //    the first decision-shaped name in the chain reported both of its cell helpers.
    assert!(
        sites(r#"fn f() { let r = item.get("status").and_then(|s| s.get("replicas")).and_then(Value::as_i64).unwrap_or(0); }"#)
            .is_empty(),
        "the innermost lookup is the field being defaulted, not the path taken to reach it"
    );

    // 7. `bgp` / `snmp`: a qualifier that travels *with* a verdict is not itself the verdict.
    for body in [
        r#"fn f() { let s = action.get("error_subcode").and_then(|v| v.as_u64()).unwrap_or(0); }"#,
        r#"fn f() { let i = action.get("error_index").and_then(|v| v.as_u64()).unwrap_or(0); }"#,
    ] {
        assert!(
            sites(body).is_empty(),
            "a subcode/index is not the decision: {body}"
        );
    }

    // 8. `sip`: a missing status is answered 500 elsewhere, and 0 is deliberately *not* 200.
    assert!(
        sites(
            r#"fn f() { let c = action.get("status_code").and_then(|v| v.as_u64()).unwrap_or(0); }"#
        )
        .is_empty(),
        "0 is not a SIP success code; affirmativeness is per (field, literal), not per literal"
    );

    // 9. Nothing the model supplied — the anchor is the lookup, not the combinator.
    assert!(
        sites(r#"fn f() { let s = self.last_status.unwrap_or(200); }"#).is_empty(),
        "a default on a value that never came from the model's JSON is not this class"
    );

    // 10. A neighbouring string that merely mentions a field name.
    assert_eq!(
        sites(
            r#"fn f() { let s = d.get("status").and_then(|v| v.as_u64()).context("no 'code'").unwrap_or(200); }"#
        ),
        vec![("status".to_string(), "200".to_string())],
        "only a literal in `.get(\"k\")` position counts as a lookup"
    );
}

/// The comment stripper must preserve line numbering exactly, and quote parity with it.
///
/// Both halves of this were real bugs found while writing these ratchets, and both were silent.
/// A line-wise `split("//")` truncates any line carrying a URL at the `//` in its own literal,
/// hiding everything after it. Replacing it with a string-aware scanner then introduced the
/// opposite fault: a Rust *line continuation* is a `\` whose escaped character is the newline,
/// so blanking the pair swallowed the line break — nine of them before `ipp/actions.rs`'s first
/// finding, which moved every reported line number up by nine while the findings themselves
/// were unchanged. A baseline keyed on line numbers turns that into a confusing false failure.
#[test]
fn the_comment_stripper_preserves_lines_and_quote_parity() {
    fn lines(s: &str) -> usize {
        s.matches('\n').count()
    }

    // A comment is removed…
    assert!(!strip_comments("let x = 1; // secret").contains("secret"));
    // …but a `//` inside a literal is not a comment, and what follows it must survive.
    let url_line = "let u = \"https://example.com\"; let s = d.get(\"status\").unwrap_or(200);";
    assert!(
        strip_comments(url_line).contains("get(\"status\")"),
        "the `//` in a URL must not truncate the rest of the line"
    );

    // Line count is preserved through every construct that can consume characters.
    for src in [
        "a\nb\nc\n",
        "let s = \"multi \\\n    line\"; // c\nnext\n",
        "// comment\n// comment\ncode\n",
        "let c = '\"'; let d = \"then\";\nnext\n",
        "let e = '\\n'; let f = \"then\";\nnext\n",
    ] {
        assert_eq!(
            lines(&strip_comments(src)),
            lines(src),
            "line count changed for {src:?}"
        );
    }

    // A char literal that *is* a quote must not open a string; if it did, every `//` after it
    // would stop being recognised as a comment for the rest of the file.
    assert!(
        !strip_comments("let q = '\"'; // hidden\nlet r = 1;").contains("hidden"),
        "a `'\\\"'` char literal must not invert quote parity"
    );
    // A lifetime is not a char literal and must be left intact.
    assert!(
        strip_comments("fn f<'a>(x: &'a str) {}").contains("'a"),
        "lifetimes must survive the char-literal skip"
    );
}
