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
