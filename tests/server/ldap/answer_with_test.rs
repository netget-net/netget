//! The `answer_with` hint `ldap_bind` carries, and the actions it offers.
//!
//! Told "accept anonymous connections", llama3.1:8b refused `ldapsearch -x`'s anonymous bind
//! in every run of the real-model eval: nothing in the event said that an empty DN and
//! password *is* the anonymous connection the instructions accept. Offered `close_connection`
//! beside the BindResponse, it also hung up after the bind, before the search ldapsearch had
//! already pipelined.

use netget::server::ldap::actions::{bind_answer_with, LDAP_BIND_EVENT};

#[test]
fn the_bind_hint_names_the_kind_of_bind() {
    let anonymous = bind_answer_with("", "", "simple");
    assert!(
        anonymous.starts_with("this is an anonymous bind (no DN, no password)"),
        "{anonymous}"
    );
    assert!(anonymous.contains("success true, unless"), "{anonymous}");
    assert!(anonymous.contains("never here"), "{anonymous}");

    let named = bind_answer_with("cn=admin,dc=example,dc=com", "secret", "simple");
    assert!(
        named.starts_with("a bind as \"cn=admin,dc=example,dc=com\" with a password"),
        "{named}"
    );
    assert!(!named.contains("anonymous"), "{named}");

    let unauthenticated = bind_answer_with("cn=x", "", "simple");
    assert!(unauthenticated.contains("no password"), "{unauthenticated}");

    let sasl = bind_answer_with("", "", "sasl:GSSAPI");
    assert!(sasl.contains("success false"), "{sasl}");
}

#[test]
fn a_bind_is_answered_by_the_bind_response_alone() {
    let offered: Vec<&str> = LDAP_BIND_EVENT
        .actions
        .iter()
        .map(|a| a.name.as_str())
        .collect();
    assert_eq!(offered, ["ldap_bind_response"]);
    assert!(LDAP_BIND_EVENT
        .parameters
        .iter()
        .any(|p| p.name == "answer_with"));
}
