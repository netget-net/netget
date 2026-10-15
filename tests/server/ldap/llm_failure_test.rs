//! What an LDAP client gets when the LLM backend fails: `unavailable` (52).
//!
//! LDAP always answered *something* on this path, but it answered the per-operation default:
//! `invalidCredentials` for a bind and an empty **successful** result set for a search. Both
//! misreport an outage as a decision the directory made, and the search case is the dangerous
//! one - resultCode 0 with no entries is a valid answer meaning "nothing matched".
//!
//! RFC 4511 §4.1.9 has the right code: `unavailable` (52), "the server is shutting down or a
//! subsystem is not operational". It is never a success, so it cannot be mistaken for an empty
//! directory, and it is distinct from any code the model itself can return.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use ldap3::{LdapConnAsync, Scope};
use std::time::Duration;

/// RFC 4511 resultCode 52.
const RESULT_UNAVAILABLE: u32 = 52;

#[tokio::test]
async fn test_ldap_answers_unavailable_when_llm_fails() -> E2EResult<()> {
    let prompt = "Start LDAP server on port 0. Accept binds and answer searches.";

    let server_config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("LDAP server")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "LDAP",
                    "instruction": "Accept binds and answer searches"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for `ldap_bind` / `ldap_search`: the mock answers 500.
    });

    let server = start_netget_server(server_config).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;

    let (conn, mut ldap) = LdapConnAsync::new(&format!("ldap://127.0.0.1:{}", server.port)).await?;
    ldap3::drive!(conn);

    // Bind: must be a refusal, and specifically `unavailable` rather than the
    // `invalidCredentials` a real policy decision would produce.
    let bind = tokio::time::timeout(
        Duration::from_secs(20),
        ldap.simple_bind("cn=admin,dc=example,dc=com", "secret"),
    )
    .await
    .map_err(|_| {
        "No LDAP BindResponse within 20s - the server went silent on LLM failure, which is the \
         exact defect this test exists to catch"
    })??;
    println!("bind rc={} msg={:?}", bind.rc, bind.text);
    assert_eq!(
        bind.rc, RESULT_UNAVAILABLE,
        "an LLM failure must be reported as unavailable (52), not as a credentials decision"
    );

    // Search: must not come back as resultCode 0 with an empty entry list, which a client reads
    // as a valid "nothing matched".
    let search = tokio::time::timeout(
        Duration::from_secs(20),
        ldap.search(
            "dc=example,dc=com",
            Scope::Subtree,
            "(objectClass=person)",
            vec!["cn"],
        ),
    )
    .await
    .map_err(|_| "No LDAP SearchResultDone within 20s")??;
    // ldap3 turns a non-zero result code into an error carrying the LdapResult, so the
    // refusal we are asserting on arrives through `Err` while a success arrives through `Ok`.
    let (entries, result) = match search.success() {
        Ok((entries, result)) => (entries, result),
        Err(ldap3::LdapError::LdapResult { result }) => (Vec::new(), result),
        Err(other) => panic!("unexpected LDAP error: {other:?}"),
    };
    println!("search rc={} entries={}", result.rc, entries.len());
    assert_eq!(
        result.rc, RESULT_UNAVAILABLE,
        "a failed search must report unavailable (52), never success with zero entries"
    );
    assert!(
        entries.is_empty(),
        "a failed search must not return entries"
    );

    ldap.unbind().await?;
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
