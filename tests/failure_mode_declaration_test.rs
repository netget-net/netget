//! A server's behaviour on LLM failure must be **declared**, not described in prose.
//!
//! The root `CLAUDE.md` carried a list of ~20 "deliberately silent" protocols. That list was
//! wrong in both directions when it was audited: NDP logged its own *transmit* failure as
//! `decision=model_silent`, so `grep decision=fail_closed_` found nothing for a real outage;
//! `radius`, `stun` and five BLE profiles were on it while answering on the wire (Access-Reject,
//! a Binding Success, ATT Unlikely Error); and fifteen servers that really were silent — the L2
//! announcement family, the discovery responders, `icmp`, `wol`, `rawip`, `tuntap` — were on no
//! list at all. A paragraph in a shared document cannot be checked against 140 servers. A
//! `FailureMode` on the metadata can.
//!
//! The distinction is not stylistic. It turns on one question: **is every reply this protocol
//! can send a positive assertion?** `openvpn` is the case to remember — its only pre-TLS server
//! message is `P_CONTROL_HARD_RESET_SERVER_V2`, and sending it *is* admitting the peer, so
//! "fixing the silence" there would convert a backend outage into an authentication bypass.
//! Where the answer is no — HTTP has a 503, RESP has `-LOADING`, DHCPv6 has UnspecFail, NBNS has
//! SRV_ERR — silence merely makes the peer wait out its own timeout, and answering is strictly
//! better. That is why `FailureMode::Answers` is the default: the August 2026 sweep found 64 of
//! 135 servers silent when they should have answered.
//!
//! # What this file enforces
//!
//! 1. Every protocol documented here as silent declares `.deliberately_silent()`.
//! 2. Every protocol documented here as answering does **not** declare it, and declares
//!    `.answers_on_failure()`.
//! 3. **Every connectionless server declares one or the other explicitly.** This is the rule
//!    that would have found the fifteen, and the reason it is scoped to connectionless servers
//!    is where silence comes from. On a datagram protocol there is no connection to close, so a
//!    failure arm that writes nothing produces silence *by default*, and the default
//!    `FailureMode::Answers` cannot tell "someone wrote the answer" from "nobody looked". On a
//!    connection protocol the same arm at least ends in a close the peer can see. All fifteen
//!    undeclared-silent servers were connectionless, as were all eleven in the old baseline
//!    except the BLE and USB families, which are covered by (1) and (2).
//! 4. A silent protocol still logs a `fail_closed_` decision token, because the log is the only
//!    place the distinction survives.
//!
//! # Why not detect a silent failure arm directly
//!
//! It was tried, and it is not conservative in either direction. The obvious mechanical rule —
//! find the `Err` arm after a `call_llm`, and flag it when it writes nothing — cannot be written
//! by reading source: half the servers route the outcome through a `decide()` helper that
//! returns bytes to a caller that writes them, so the arm itself never writes even when the
//! server answers. A phrase heuristic (a `fail_closed_llm_error` log line whose string says
//! "nothing sent" / "no reply" / "no advertisement") was measured against the unfixed tree: it
//! found 9 of the 15 undeclared-silent servers and flagged `ident`, `m3ua` and `usb/fido2`,
//! which all answer (an IDENT `ERROR`, an M3UA observational event that defines no reply, a
//! CTAP2 `OPERATION_DENIED`). A build-failing check that misses a third of its targets and
//! invents three more trains people to edit the baseline. Rule 3 asks for a *decision* instead,
//! which a reader can check in one line and a scan can check exactly.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Protocols that write nothing on LLM failure and have **not yet declared it**.
///
/// Shrink-only, and empty. **Do not add to this list.** A new protocol that writes nothing on
/// failure declares `.deliberately_silent()`.
const UNDECLARED_SILENT_BASELINE: &[&str] = &[];

/// Connectionless servers that have not yet declared a failure mode either way.
///
/// Shrink-only, and empty. A new connectionless server declares `.deliberately_silent()` or
/// `.answers_on_failure()`, with the reason in a comment beside the call.
const UNDECLARED_CONNECTIONLESS_BASELINE: &[&str] = &[];

/// Protocols that write nothing on LLM failure, deliberately. Each declares it in `metadata()`
/// with its reason; the per-protocol `CLAUDE.md` failure section says why.
const DOCUMENTED_SILENT: &[&str] = &[
    // A2S defines no error reply: every response asserts a server's info, players or rules.
    "a2s",
    "arp",
    // RFC 7854 defines no collector-to-router message; failed handling closes the session.
    "bmp",
    "bootp",
    "can",
    "cdp",
    "datalink",
    "dhcp",
    // Forward has no negative ACK; failed handling closes without acknowledgement.
    "fluent_forward",
    // GELF TCP and UDP collectors define no application acknowledgement or negative reply.
    "gelf",
    // One-way Carbon metrics have no application acknowledgement or negative reply.
    "graphite",
    "hsrp",
    "icmp",
    "igmp",
    // RFC 7011 UDP collection has no acknowledgement or negative response.
    "ipfix",
    // A group read answered by nobody is silence on a real bus; an invented value would be a
    // device that does not exist.
    "knx",
    // sFlow v5 UDP collection has no application reply or negative acknowledgement.
    "sflow",
    // BFD has no refusal: a session the model does not accept is one the speaker never
    // answers, and any Control packet it sent would move the peer's session towards Up.
    "bfd",
    // RFC 3954 UDP flow collection has no acknowledgement or refusal message.
    "netflow_v9",
    "ipsec",
    "isis",
    "lldp",
    "llmnr",
    "mdns",
    "ndp",
    // Every controller message is an instruction (PACKET_OUT forwards, FLOW_MOD installs); an
    // unanswered PACKET_IN is left unforwarded, never flooded.
    "openflow",
    "openvpn",
    "ospf",
    "rawip",
    "rip",
    "rtp",
    "ssdp",
    // StatsD and DogStatsD are one-way UDP; neither defines an acknowledgment or error reply.
    "statsd",
    "stp",
    "syslog",
    "tuntap",
    "udp",
    "usb/keyboard",
    "usb/mouse",
    "vrrp",
    // A VXLAN/Geneve overlay host that does not exist is silence: every ARP, echo or UDP reply
    // asserts that a host is there.
    "vxlan",
    "wol",
    // WS-Discovery has no negative reply: a target that does not match says nothing, and every
    // message it could send (ProbeMatches, ResolveMatches, Hello) claims a service exists.
    "wsdiscovery",
];

/// Protocols that answer on LLM failure and were, at some point, believed or listed to be
/// silent — or are silent only for some messages. Pinned so the belief cannot come back:
/// declaring any of these silent would be a false statement about the wire.
const DOCUMENTED_ANSWERS: &[&str] = &[
    // Access-Reject, correctly signed. Was on the root CLAUDE.md's silent list.
    "radius",
    // A Binding Success reporting the address the server observed itself.
    "stun",
    // ATT Unlikely Error (0x0E) from the base stack. On the silent list by family membership.
    "bluetooth_ble_battery",
    "bluetooth_ble_heart_rate",
    "bluetooth_ble_keyboard",
    "bluetooth_ble_mouse",
    "bluetooth_ble_remote",
    // UnspecFail REPLY; SOLICIT silent.
    "dhcpv6",
    // SRV_ERR to a request addressed to the NBNS; broadcast silent.
    "netbios_ns",
    // A refusing cause; Echo and G-PDU silent.
    "gtp",
    // EAP-Failure; Logoff silent.
    "eapol",
];

/// Strip `//` comments, leaving `//` inside a string literal alone — so a comment that merely
/// mentions `.deliberately_silent()` is not mistaken for the declaration.
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
                        return &line[..i];
                    }
                    _ => {}
                }
                i += 1;
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every `src/server/<p>/actions.rs` and `src/server/<p>/<q>/actions.rs`, named `<p>` and
/// `<p>/<q>`.
///
/// One level of nesting, like the other source ratchets: `usb/keyboard` and `usb/mouse` live
/// there, and a flat walk never saw them — which is how they sat in a "not yet declared"
/// baseline with no way for the declaration to be checked when it arrived.
fn server_action_files() -> Vec<(String, PathBuf)> {
    // Read at runtime, falling back to the compile-time value, so the built test binary can be
    // pointed at another checkout (`CARGO_MANIFEST_DIR=<older tree> <binary>`) to show what the
    // rules flag there.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string());
    let root = Path::new(&manifest_dir).join("src/server");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return out;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let name = dir
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let actions = dir.join("actions.rs");
        if actions.is_file() {
            out.push((name.clone(), actions));
        }
        let Ok(children) = std::fs::read_dir(&dir) else {
            continue;
        };
        for child in children.flatten() {
            let child_dir = child.path();
            let nested = child_dir.join("actions.rs");
            if child_dir.is_dir() && nested.is_file() {
                let child_name = child_dir
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                out.push((format!("{name}/{child_name}"), nested));
            }
        }
    }
    out.sort();
    out
}

/// Declaration forms, builder and struct literal. The literal form is rare (one client uses it
/// for other fields) but a scan that misses it reads as "declares nothing", so it is matched.
fn declares_silent(src: &str) -> bool {
    src.contains(".deliberately_silent()") || src.contains("FailureMode::DeliberatelySilent")
}

fn declares_answers(src: &str) -> bool {
    src.contains(".answers_on_failure()") || src.contains("failure_mode: FailureMode::Answers")
}

fn declares_connectionless(src: &str) -> bool {
    src.contains(".connectionless()") || src.contains("connectionless: true")
}

struct Scan {
    silent: BTreeSet<String>,
    answers: BTreeSet<String>,
    connectionless: BTreeSet<String>,
    files: usize,
}

fn scan() -> Scan {
    let mut s = Scan {
        silent: BTreeSet::new(),
        answers: BTreeSet::new(),
        connectionless: BTreeSet::new(),
        files: 0,
    };
    for (name, file) in server_action_files() {
        let Ok(raw) = std::fs::read_to_string(&file) else {
            continue;
        };
        s.files += 1;
        let src = strip_comments(&raw);
        if declares_silent(&src) {
            s.silent.insert(name.clone());
        }
        if declares_answers(&src) {
            s.answers.insert(name.clone());
        }
        if declares_connectionless(&src) {
            s.connectionless.insert(name);
        }
    }
    s
}

/// The scan must be looking at the tree, including the nested directories.
#[test]
fn the_scan_reaches_nested_protocols() {
    let names: BTreeSet<String> = server_action_files().into_iter().map(|(n, _)| n).collect();
    assert!(
        names.len() > 100,
        "only {} server actions.rs files found; this test is not reaching the source tree",
        names.len()
    );
    for nested in ["usb/keyboard", "usb/mouse"] {
        assert!(
            names.contains(nested),
            "{nested} was not found: the walk is flat again, and every nested protocol is \
             outside this ratchet"
        );
    }
}

/// Rule 1 and the shrink-only baseline.
///
/// Source-reading rather than registry-walking, so it holds at the six-protocol CI gate — a
/// registry-walking version of this check sees 6 of 116 and passes by inspecting almost
/// nothing.
#[test]
fn every_deliberately_silent_protocol_declares_it() {
    let s = scan();
    let baseline: BTreeSet<&str> = UNDECLARED_SILENT_BASELINE.iter().copied().collect();

    let missing: Vec<_> = DOCUMENTED_SILENT
        .iter()
        .filter(|p| !s.silent.contains(**p) && !baseline.contains(**p))
        .collect();
    assert!(
        missing.is_empty(),
        "these protocols are documented as writing nothing on LLM failure but do not declare \
         FailureMode::DeliberatelySilent: {missing:?}\n\
         Add `.deliberately_silent()` to the metadata builder with the reason in a comment, or \
         - if the protocol does in fact answer - move it to DOCUMENTED_ANSWERS."
    );

    let stale: Vec<_> = baseline.iter().filter(|b| s.silent.contains(**b)).collect();
    assert!(
        stale.is_empty(),
        "these protocols now declare deliberately_silent and must be removed from \
         UNDECLARED_SILENT_BASELINE: {stale:?}"
    );

    // The documented list and the declarations must be the same set, in both directions: a
    // protocol that declares silence without being listed here is one nobody reviewed.
    let undocumented: Vec<_> = s
        .silent
        .iter()
        .filter(|p| !DOCUMENTED_SILENT.contains(&p.as_str()))
        .collect();
    assert!(
        undocumented.is_empty(),
        "these protocols declare deliberately_silent but are not in DOCUMENTED_SILENT: \
         {undocumented:?}. Add them, having checked that every reply they could send is a \
         positive assertion."
    );

    assert!(
        !s.silent.is_empty(),
        "no protocol declares deliberately_silent, so this test is passing by inspecting \
         nothing - exactly the failure it exists to prevent"
    );
}

/// Rule 2: a protocol that answers must never be declared silent.
#[test]
fn a_protocol_that_answers_is_not_declared_silent() {
    let s = scan();
    for p in DOCUMENTED_ANSWERS {
        assert!(
            !s.silent.contains(*p),
            "{p} answers the peer on LLM failure but declares deliberately_silent - that is a \
             false statement about the wire"
        );
        assert!(
            s.answers.contains(*p),
            "{p} answers the peer on LLM failure and should say so with \
             `.answers_on_failure()`, with what the peer receives in a comment beside it"
        );
    }
    let both: Vec<_> = s.silent.intersection(&s.answers).collect();
    assert!(
        both.is_empty(),
        "these protocols declare both deliberately_silent and answers_on_failure: {both:?}"
    );
}

/// Rule 3: every connectionless server has decided what a failure puts on the wire.
#[test]
fn every_connectionless_server_declares_its_failure_mode() {
    let s = scan();
    let baseline: BTreeSet<&str> = UNDECLARED_CONNECTIONLESS_BASELINE.iter().copied().collect();

    let undeclared: Vec<_> = s
        .connectionless
        .iter()
        .filter(|p| !s.silent.contains(*p) && !s.answers.contains(*p))
        .filter(|p| !baseline.contains(p.as_str()))
        .collect();
    assert!(
        undeclared.is_empty(),
        "these connectionless servers declare no failure mode: {undeclared:?}\n\
         On a datagram protocol a failure arm that writes nothing is silence by default, so \
         the default FailureMode::Answers is not evidence that anyone decided. Read the LLM-error \
         path, then declare `.answers_on_failure()` (it answers - say with what) or \
         `.deliberately_silent()` (every reply it could send is a positive assertion - say why, \
         and log decision=fail_closed_llm_error)."
    );

    let stale: Vec<_> = baseline
        .iter()
        .filter(|b| s.silent.contains(**b) || s.answers.contains(**b))
        .collect();
    assert!(
        stale.is_empty(),
        "these connectionless servers now declare a failure mode and must be removed from \
         UNDECLARED_CONNECTIONLESS_BASELINE: {stale:?}"
    );

    assert!(
        s.connectionless.len() >= 20,
        "found only {} connectionless servers; the `.connectionless()` match may have stopped \
         working",
        s.connectionless.len()
    );
}

/// Rule 4: a protocol that declares silence still owes the **log** the distinction the wire
/// cannot carry.
///
/// This is the half that is easy to get wrong, and NDP got it wrong: it logged its own
/// build-and-transmit failure as `decision=model_silent`, so a genuine outage was recorded as
/// the model choosing to say nothing and `grep decision=fail_closed_` found nothing at all.
/// Silence on the wire is not silence in the log.
#[test]
fn a_silent_protocol_still_tags_its_failures_in_the_log() {
    let s = scan();
    let mut untagged = Vec::new();

    for (name, file) in server_action_files() {
        if !s.silent.contains(&name) {
            continue;
        }
        let dir = file.parent().expect("actions.rs has a parent");
        // The tag may live in any file of the protocol's own directory; several decide in
        // `mod.rs` and describe in `actions.rs`. Comments do not count.
        let mut own = String::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_file() && p.extension().is_some_and(|x| x == "rs") {
                    own.push_str(&strip_comments(
                        &std::fs::read_to_string(&p).unwrap_or_default(),
                    ));
                }
            }
        }
        if !(own.contains("decision=") && own.contains("fail_closed_")) {
            untagged.push(name);
        }
    }

    assert!(
        untagged.is_empty(),
        "these protocols write nothing on the wire on failure and carry no `decision=` / \
         `fail_closed_` tag, so a backend outage, a model refusal and a model that answered \
         with nothing are indistinguishable in the log as well: {untagged:?}\n\
         `src/server/radius/` is the worked example of the vocabulary."
    );
}

/// The comment stripper must not count a comment as a declaration, and must keep code.
#[test]
fn a_comment_is_not_a_declaration() {
    assert!(!declares_silent(&strip_comments(
        "    // TODO: add .deliberately_silent() once decided"
    )));
    assert!(declares_silent(&strip_comments(
        "            .deliberately_silent() // every reply asserts a route"
    )));
    assert!(declares_answers(&strip_comments(
        "            .answers_on_failure()"
    )));
}
