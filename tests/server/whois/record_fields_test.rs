//! What `send_whois_record` puts on the wire, field by field.
//!
//! The real-model eval told the model to "report the registrant organisation as Example Holdings
//! Ltd and the domain status as clientTransferProhibited", and it did — as `registrant` and
//! `domain_status` — but the action had no field that rendered either an organisation or a
//! status, so the status was dropped and the organisation printed as `Registrant Name`
//! (`whois/registrant-and-status` 2/5). The action now carries both as structured fields, plus a
//! bounded `extra_fields` for everything else, and prints only what it was given.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features whois --test server -- whois::record_fields --test-threads=100


use netget::llm::actions::protocol_trait::{ActionResult, Server};
use netget::server::whois::actions::{WhoisProtocol, MAX_EXTRA_FIELDS};
use serde_json::json;

fn render(action: serde_json::Value) -> anyhow::Result<String> {
    match WhoisProtocol::new().execute_action(action)? {
        ActionResult::Output(bytes) => Ok(String::from_utf8(bytes).expect("a record is text")),
        other => panic!("send_whois_record must write a record, got {other:?}"),
    }
}

#[test]
fn every_structured_field_renders_as_its_own_standard_line() {
    let record = render(json!({
        "type": "send_whois_record",
        "domain": "netget.example",
        "registrar": "NETGET-EVAL-REGISTRAR",
        "registrant": "Alice Liddell",
        "registrant_organization": "Example Holdings Ltd",
        "domain_status": ["clientTransferProhibited", "clientDeleteProhibited"],
        "admin_contact": "Bob",
        "extra_fields": {"Creation Date": "2020-01-01"},
        "name_servers": ["ns1.netget.example"]
    }))
    .expect("a complete record is accepted");

    assert_eq!(
        record,
        "Domain Name: netget.example\r\n\
         Registrar: NETGET-EVAL-REGISTRAR\r\n\
         Domain Status: clientTransferProhibited\r\n\
         Domain Status: clientDeleteProhibited\r\n\
         Registrant Name: Alice Liddell\r\n\
         Registrant Organization: Example Holdings Ltd\r\n\
         Admin Name: Bob\r\n\
         Creation Date: 2020-01-01\r\n\
         Name Server: ns1.netget.example\r\n\
         \r\n"
    );
}

#[test]
fn one_status_may_be_a_string_and_the_short_organisation_name_is_accepted() {
    let record = render(json!({
        "type": "send_whois_record",
        "domain": "netget.example",
        "registrant_org": "Example Holdings Ltd",
        "domain_status": "clientTransferProhibited"
    }))
    .expect("accepted");
    assert!(
        record.contains("Registrant Organization: Example Holdings Ltd\r\n"),
        "{record}"
    );
    assert!(
        record.contains("Domain Status: clientTransferProhibited\r\n"),
        "{record}"
    );
}

#[test]
fn a_field_the_model_did_not_give_is_not_invented() {
    let record = render(json!({"type": "send_whois_record", "domain": "netget.example"}))
        .expect("a domain alone is a record");
    assert_eq!(
        record, "Domain Name: netget.example\r\n\r\n",
        "omitted fields used to print as `Example Registrar, Inc.`, `Registrant Contact` and \
         `Admin Contact` - assertions nobody made"
    );
}

#[test]
fn extra_fields_are_bounded_and_refused_past_the_bound_not_truncated() {
    let fields = |n: usize| -> serde_json::Map<String, serde_json::Value> {
        (0..n)
            .map(|i| (format!("Field {i:02}"), json!("x")))
            .collect()
    };
    let at_bound = render(json!({
        "type": "send_whois_record",
        "domain": "netget.example",
        "extra_fields": fields(MAX_EXTRA_FIELDS)
    }))
    .expect("exactly MAX_EXTRA_FIELDS is accepted");
    assert_eq!(at_bound.matches(": x\r\n").count(), MAX_EXTRA_FIELDS);

    let err = render(json!({
        "type": "send_whois_record",
        "domain": "netget.example",
        "extra_fields": fields(MAX_EXTRA_FIELDS + 1)
    }))
    .expect_err("one past the bound is refused");
    assert!(
        err.to_string().contains("send_whois_response"),
        "the refusal must say where the rest belongs: {err}"
    );
}

#[test]
fn an_extra_field_cannot_forge_a_line_through_its_key_or_value() {
    let record = render(json!({
        "type": "send_whois_record",
        "domain": "netget.example",
        "extra_fields": {"Note\r\nRegistrant Name": "Mallory\r\nRegistrar: Evil"}
    }))
    .expect("accepted, sanitised");
    assert!(
        !record.contains("\r\nRegistrant Name") && !record.contains("\r\nRegistrar: Evil"),
        "a CR/LF in an extra field forged a line: {record:?}"
    );
}
