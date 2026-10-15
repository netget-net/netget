//! mDNS is the case where silence is the *right* answer - and this test pins that down.
//!
//! Every other protocol in this sweep answers its peer when the LLM backend fails, because a
//! peer blocked on a reply is worse off than one told no. mDNS is not that shape twice over:
//!
//! * There is no peer waiting. The LLM call here is a **startup** event asking which services
//!   to advertise, not a reply to a querier. Nobody is holding a socket open for it.
//! * An mDNS answer is multicast to the whole link, and every listener caches the record for
//!   its TTL. A fabricated PTR/SRV/A set would advertise a service that does not exist to
//!   every machine on the subnet and keep it there after the backend recovered. That is the
//!   `udp` argument - an invented reply may be parsed as a real one - one step worse, because
//!   the damage outlives the outage and reaches hosts that never asked.
//!
//! So the responder comes up advertising nothing. What must *not* happen, and used to, is
//! swallowing the failure: `if let Ok(..)` discarded the error entirely, so the daemon ran and
//! said nothing about why it had no services. This test asserts both halves - the responder
//! starts, and the failure is reported at ERROR on the status channel with
//! `decision=fail_closed_llm_error`.
//!
//! The wire half of that pair cannot be a `recv()` that times out: this server binds no socket
//! of its own (`mdns-sd` owns them and exposes none), and the only thing it could put on the
//! link is an announcement. So "nothing reached the wire" is asserted as "no service was ever
//! registered with the daemon" - if nothing is registered there is nothing to announce - which
//! is the strongest statement available without a second host on the link.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

#[tokio::test]
async fn test_mdns_stays_silent_but_reports_the_failure() -> E2EResult<()> {
    let prompt = "listen via mdns on port {AVAILABLE_PORT}. Advertise a printer service";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("via mdns")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "mDNS",
                    "instruction": "Advertise a printer service"
                }
            ]))
            .expect_calls(1)
            .and()
        // No rule for the mDNS startup event, so the service list cannot be produced.
    });

    let server = start_netget_server(config).await?;

    // The responder must still be up: refusing to start would be a different, larger change,
    // and an mDNS responder advertising nothing is a valid one.
    server
        .wait_for_log("mDNS advertising nothing", 20)
        .await
        .map_err(|_| {
            "the mDNS service-registration failure was not reported on the status channel - \
             staying silent on the wire is correct here, staying silent about it is not"
        })?;

    // Nothing was advertised, so nothing should be flowing. There is no positive assertion
    // available for "no multicast was sent" that does not require a second host on the link;
    // what this checks is that the server did not fabricate a service list and keep running as
    // if it had one.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !server.output_contains("register_mdns_service").await,
        "no service may be registered when the handler never produced one"
    );
    assert!(
        !server.output_contains("mDNS registered service").await,
        "nothing may be announced on the LLM-failure path"
    );

    // The wire carries nothing on any of the three ways this server can end up advertising
    // nothing, so the log is the only place they can be told apart. `fail_closed_llm_error`
    // is the backend one; `model_silent` (handler ran, asked for no services) and
    // `operator_config` (startup parameters, no model call) are the others.
    server
        .wait_for_any(&["decision=fail_closed_llm_error"], 30)
        .await;
    let lines = server.get_output().await;
    assert!(
        lines
            .iter()
            .any(|l| l.contains("decision=fail_closed_llm_error")),
        "a backend failure must be logged with decision=fail_closed_llm_error — silence on \
         the wire is correct here, so an untagged log line leaves an outage and a handler \
         that chose to advertise nothing identical. Output was:\n{}",
        lines.join("\n")
    );
    assert!(
        !lines.iter().any(|l| l.contains("decision=model_silent")),
        "the handler never ran, so this is not the model's silence. Output was:\n{}",
        lines.join("\n")
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}
