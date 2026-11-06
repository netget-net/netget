//! Protocol name resolution must be deterministic and specificity-ordered.
//!
//! Both registries resolve a user- or LLM-supplied string to a protocol by
//! substring-matching a keyword map. That map is a `HashMap`, whose iteration
//! order is unspecified, and the matchers used to return the *first* hit — so an
//! input matching two protocols' keywords resolved to whichever the hash order
//! happened to yield, and could differ between runs, between feature sets, and
//! between builds.
//!
//! The live case: `"ssh_agent"` contains both SSH's `"ssh"` keyword and SSH
//! Agent's `"agent"` keyword. Creating an ssh_agent client through the dashboard
//! or MCP could therefore silently produce an **SSH** client instead. It surfaced
//! as `tests/client/ssh_agent/command_channel_test.rs` passing under
//! `--features bgp,ssh-agent,torrent-peer,tor` and failing under
//! `--features all-protocols` with "Missing required startup parameters for SSH
//! client" — the SSH client's error, raised for an ssh_agent request.
//!
//! The server registry had grown a hand-maintained ladder of special cases for
//! exactly this (mDNS before DNS, SNMP before SSH-Agent, PostgreSQL before MySQL,
//! the AWS services before HTTP), several of whose comments name hash order as
//! the reason. Resolution is now longest-matching-keyword-wins with a name
//! tie-break, which is specificity-ordered and identical on every run.

#![cfg(unix)]

use netget::protocol::client_registry::CLIENT_REGISTRY;

/// The exact collision that broke ssh_agent: a longer, more specific keyword must
/// beat a shorter one that happens to be a substring of the same input.
#[test]
fn ssh_agent_never_resolves_to_the_ssh_client() {
    for input in ["ssh_agent", "ssh-agent", "SSH Agent", "SSH_AGENT"] {
        let resolved = CLIENT_REGISTRY
            .resolve(input)
            .unwrap_or_else(|e| panic!("{input:?} did not resolve: {e}"));
        assert_eq!(
            resolved.protocol_name(),
            "SSH Agent",
            "{input:?} resolved to {:?}; \"ssh\" is a substring of it, and resolving \
             to the SSH client would create the wrong protocol",
            resolved.protocol_name()
        );
    }
}

/// Plain "ssh" must still reach the SSH client — the fix must not over-correct.
#[test]
fn plain_ssh_still_resolves_to_the_ssh_client() {
    let resolved = CLIENT_REGISTRY.resolve("ssh").expect("resolve ssh");
    assert_eq!(resolved.protocol_name(), "SSH");
}

/// Resolution must not depend on hash order. A `HashMap` is reseeded per process,
/// so repeating the lookup within one process cannot prove determinism on its own;
/// what this pins is that every colliding input has exactly one stable answer, and
/// the CI job running it across many processes is what samples the seeds.
#[test]
fn colliding_inputs_resolve_consistently() {
    let registry = &*CLIENT_REGISTRY;
    for input in ["ssh_agent", "ssh", "ssh keys", "secure shell"] {
        let first = registry.parse_from_str(input);
        for _ in 0..64 {
            assert_eq!(
                registry.parse_from_str(input),
                first,
                "{input:?} resolved inconsistently within a single process"
            );
        }
        assert!(first.is_some(), "{input:?} resolved to nothing");
    }
}

// ---------------------------------------------------------------------------
// Exact-name resolution (`resolve_name`) and whole-word keyword matching
// ---------------------------------------------------------------------------
//
// `get_protocol_docs` with "mptcp" used to return TCP's page headed "`mptcp` — MCP reference":
// the client registry matched keywords as raw substrings ("mptcp" contains "tcp") and the
// server registry ended with "anything containing tcp is TCP". A caller naming a protocol now
// gets that protocol, an alias reported as one, or an error with suggestions.

use netget::protocol::name_match::{contains_words, NameMatch};
use netget::protocol::server_registry::registry;

#[test]
fn keywords_match_only_as_whole_words() {
    assert!(contains_words("tcp", "tcp"));
    assert!(contains_words("a tcp server", "tcp"));
    assert!(
        contains_words("tcpx tcp", "tcp"),
        "every occurrence is tried"
    );
    assert!(!contains_words("mptcp", "tcp"));
    assert!(!contains_words("tcp_client", "tcp"));
    assert!(!contains_words("email server", "mail server"));
    assert!(contains_words("a mail server here", "mail server"));
}

#[test]
fn free_text_parsing_no_longer_finds_tcp_inside_other_words() {
    for input in ["zztcpzz", "xtcp", "tcpish"] {
        assert_eq!(registry().parse_from_str(input), None, "server: {input:?}");
        assert_eq!(
            CLIENT_REGISTRY.parse_from_str(input),
            None,
            "client: {input:?}"
        );
    }
    // Free text that names tcp as a word still resolves.
    assert_eq!(
        registry().parse_from_str("a raw tcp server").as_deref(),
        Some("TCP")
    );
    assert_eq!(
        CLIENT_REGISTRY
            .parse_from_str("connect over tcp please")
            .as_deref(),
        Some("TCP")
    );
}

#[test]
fn exact_names_resolve_canonically_and_aliases_say_so() {
    for input in ["tcp", "TCP", " Tcp "] {
        let (p, how) = registry().resolve_name(input).expect(input);
        assert_eq!((p.protocol_name(), how), ("TCP", NameMatch::Canonical));
        let (c, how) = CLIENT_REGISTRY.resolve_name(input).expect(input);
        assert_eq!((c.protocol_name(), how), ("TCP", NameMatch::Canonical));
    }
    let (p, how) = registry().resolve_name("eth>ip>tcp").expect("stack name");
    assert_eq!((p.protocol_name(), how), ("TCP", NameMatch::StackName));

    for input in ["mptcp", "MPTCP", "multipath tcp", "multipath-tcp"] {
        let (p, how) = registry().resolve_name(input).expect(input);
        assert_eq!(p.protocol_name(), "TCP");
        assert!(
            matches!(how, NameMatch::Alias(_)),
            "{input:?} is an alias: {how:?}"
        );
        let (c, how) = CLIENT_REGISTRY.resolve_name(input).expect(input);
        assert_eq!(c.protocol_name(), "TCP");
        assert!(
            matches!(how, NameMatch::Alias(_)),
            "{input:?} is an alias: {how:?}"
        );
    }
    // Multi-word canonical names fold spaces, hyphens and underscores.
    let (c, _) = CLIENT_REGISTRY
        .resolve_name("ssh-agent")
        .expect("ssh-agent");
    assert_eq!(c.protocol_name(), "SSH Agent");
}

#[test]
fn a_near_miss_is_an_error_with_suggestions_not_a_guess() {
    // Free-text parsing would map "a tcp server" to TCP; a name lookup must not.
    let err = registry()
        .resolve_name("a tcp server")
        .err()
        .expect("not a name")
        .to_string();
    assert!(
        err.contains("Unknown protocol") && err.contains("'tcp'"),
        "{err}"
    );
    let err = CLIENT_REGISTRY
        .resolve_name("a tcp client")
        .err()
        .expect("not a name")
        .to_string();
    assert!(err.contains("'tcp'"), "{err}");

    // A typo gets an edit-distance suggestion.
    let err = registry()
        .resolve_name("tccp")
        .err()
        .expect("typo")
        .to_string();
    assert!(err.contains("Did you mean"), "{err}");

    // Nothing close: no suggestion, still an error.
    let err = registry()
        .resolve_name("definitely_not_a_protocol")
        .err()
        .expect("unknown")
        .to_string();
    assert!(err.starts_with("Unknown protocol"), "{err}");
}
