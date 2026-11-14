//! The DoT client reports every record of a response without panicking on one whose record
//! data cannot be displayed.
//!
//! hickory-proto's `RData::OPT` returns `fmt::Error` from `Display`, and `format!` turns that
//! into a panic ("a Display implementation returned an error unexpectedly") — inside the
//! client's read task, which would die with the connection still registered. Under
//! hickory-proto 0.26 a decoded response cannot carry an OPT record in a section, so the record
//! is built in memory here and handed to `record_json`, the one function the read loop formats
//! every answer, authority and additional record through.

use std::str::FromStr;

use hickory_proto::rr::rdata::opt::OPT;
use hickory_proto::rr::{rdata, Name, RData, Record};
use netget::client::dot::record_json;

#[test]
fn a_record_whose_display_fails_is_reported_by_type_instead_of_panicking() {
    let opt = Record::from_rdata(Name::root(), 0, RData::OPT(OPT::new(Vec::new())));
    let json = record_json(&opt);
    assert_eq!(json["type"], "OPT", "{json}");
    assert_eq!(
        json["data"], "<OPT record data that cannot be displayed>",
        "{json}"
    );
}

#[test]
fn an_ordinary_record_still_carries_its_data() {
    let a = Record::from_rdata(
        Name::from_str("dot.example.").expect("valid name"),
        60,
        RData::A(rdata::A::new(192, 0, 2, 7)),
    );
    let json = record_json(&a);
    assert_eq!(json["name"], "dot.example.", "{json}");
    assert_eq!(json["type"], "A", "{json}");
    assert_eq!(json["ttl"], 60, "{json}");
    assert_eq!(json["data"], "192.0.2.7", "{json}");
}
