//! The result decoder alone: responses **captured** from fakesnow 0.11.22 (Arrow) and
//! snowflake-emulator v0.0.9 (JSON) by `capture_fixtures.py`, a JSON rowset written to
//! Snowflake's documented encodings, and every bound. No server, no model.

use netget::client::snowflake::arrow;
use netget::client::snowflake::resolve_endpoint;
use netget::client::snowflake::result::{self, MAX_CELL_BYTES, MAX_COLUMNS, MAX_VARIANT_DEPTH};
use serde_json::{json, Value};

fn fixture(name: &str) -> Value {
    let path = format!(
        "{}/tests/client/snowflake/fixtures/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect(&path)).expect("fixture JSON")
}

fn data(name: &str) -> Value {
    fixture(name)["data"].clone()
}

#[test]
fn fakesnow_arrow_rows_decode_to_typed_values() {
    let out = result::decode(&data("fakesnow_select"), 100).unwrap();
    assert_eq!(out["result_format"], "arrow");
    assert_eq!(out["row_count"], 2);
    assert_eq!(out["truncated"], false);
    assert_eq!(out["decode_warning_count"], 0, "{out:#}");
    assert_eq!(
        out["rows"][0],
        json!({
            "ID": 1,
            "AMOUNT": "123.45",
            "BODY": "hello",
            "OK": true,
            "DV": "2026-10-14",
            "TV": "12:34:56.000000000",
            "TS": "2026-10-14T12:34:56.123456000",
            "RATIO": 1.5,
            "V": null,
            "BIG": 3000000000i64,
        })
    );
    let nulls = out["rows"][1].as_object().unwrap();
    assert_eq!(nulls["ID"], 2);
    assert_eq!(nulls.values().filter(|v| v.is_null()).count(), 9);
    assert_eq!(out["columns"][1]["type"], "fixed");
    assert_eq!(out["columns"][1]["scale"], 2);
}

#[test]
fn fakesnow_arrow_variants_zones_binary_and_duplicate_names() {
    let out = result::decode(&data("fakesnow_zones"), 100).unwrap();
    assert_eq!(out["decode_warning_count"], 0, "{out:#}");
    let row = &out["rows"][0];
    assert_eq!(row["V"], json!({"a": [1, 2], "b": {"c": null}}));
    // fakesnow keeps TIMESTAMP_TZ in UTC (zone field 1440, offset 0).
    assert_eq!(row["TZ"], "2026-10-14T10:34:56.500000000+00:00");
    assert_eq!(row["BIN"], json!({"binary_length": 2}));
    assert_eq!(row["NEG"], "-12.500");
    assert_eq!(row["BEFORE_EPOCH"], "1969-12-31");
    assert_eq!(row["DUP"], 1);
    assert_eq!(row["DUP_2"], 2);
}

#[test]
fn a_dml_result_reports_rows_affected() {
    let out = result::decode(&data("fakesnow_insert"), 100).unwrap();
    assert_eq!(out["result_format"], "json");
    assert_eq!(out["rows_affected"], 2);
    assert_eq!(out["rows"][0]["number of rows inserted"], 2);
}

#[test]
fn emulator_json_rows_decode_and_its_deviations_are_reported_not_guessed() {
    let out = result::decode(&data("emulator_select"), 100).unwrap();
    assert_eq!(out["result_format"], "json");
    let row = &out["rows"][0];
    assert_eq!(row["id"], 1);
    assert_eq!(row["amount"], "123.45");
    assert_eq!(row["body"], "hello");
    assert_eq!(row["ok"], true);
    assert_eq!(row["ratio"], 1.5);
    assert_eq!(row["big"], 3000000000i64);
    // The emulator writes NULL as "": a number column cannot read it, and says so.
    assert_eq!(out["rows"][1]["big"], "");
    assert!(
        out["decode_warning_count"].as_u64().unwrap() >= 3,
        "{out:#}"
    );

    // A DATE written as a Go time string is not a day count: handed on as sent, with a warning.
    let dates = result::decode(&data("emulator_dates"), 100).unwrap();
    assert_eq!(dates["rows"][0]["dv"], "2026-10-14 00:00:00 +0000 UTC");
    assert_eq!(dates["decode_warnings"][0]["column"], "dv");
}

/// The JSON encodings Snowflake documents (and its drivers decode): DATE as a day count,
/// TIME and TIMESTAMP as seconds with the column's scale of fraction digits, TIMESTAMP_TZ with
/// its zone piggybacked as minutes plus 1440, BINARY as hex.
#[test]
fn snowflake_json_encodings_decode() {
    let rowtype = json!([
        {"name": "ID", "type": "fixed", "scale": 0},
        {"name": "AMOUNT", "type": "fixed", "scale": 2},
        {"name": "OK", "type": "boolean"},
        {"name": "DV", "type": "date"},
        {"name": "TV", "type": "time", "scale": 3},
        {"name": "TS", "type": "timestamp_ntz", "scale": 6},
        {"name": "TL", "type": "timestamp_ltz", "scale": 3},
        {"name": "TZ", "type": "timestamp_tz", "scale": 0},
        {"name": "V", "type": "variant"},
        {"name": "B", "type": "binary"},
        {"name": "R", "type": "real"},
        {"name": "HUGE", "type": "fixed", "scale": 0}
    ]);
    let data = json!({
        "queryResultFormat": "json",
        "rowtype": rowtype,
        "rowset": [["1", "123.45", "1", "20740", "45296.789", "1791981296.123456",
                    "1791981296.500", "1791981296 1560", "{\"k\":[true]}", "abcd", "1.5e0",
                    "123456789012345678901234567890"],
                   [null, null, "0", "-1", "0", "-1.5", "0", "0 1440", null, null, "NaN", null]],
        "total": 2
    });
    let out = result::decode(&data, 100).unwrap();
    assert_eq!(out["decode_warning_count"], 0, "{out:#}");
    assert_eq!(
        out["rows"][0],
        json!({
            "ID": 1, "AMOUNT": "123.45", "OK": true, "DV": "2026-10-14",
            "TV": "12:34:56.789", "TS": "2026-10-14T12:34:56.123456",
            "TL": "2026-10-14T12:34:56.500Z", "TZ": "2026-10-14T14:34:56+02:00",
            "V": {"k": [true]}, "B": {"binary_length": 2}, "R": 1.5,
            "HUGE": "123456789012345678901234567890"
        })
    );
    let r = &out["rows"][1];
    assert_eq!(r["OK"], false);
    assert_eq!(r["DV"], "1969-12-31");
    assert_eq!(r["TS"], "1969-12-31T23:59:58.500000");
    assert_eq!(r["TZ"], "1970-01-01T00:00:00+00:00");
    assert_eq!(r["R"], "NaN");
}

#[test]
fn a_cell_that_is_not_its_type_is_handed_on_with_a_warning() {
    let data = json!({
        "rowtype": [{"name": "N", "type": "fixed", "scale": 0},
                    {"name": "D", "type": "date"},
                    {"name": "AMT", "type": "fixed", "scale": 2}],
        "rowset": [["twelve", "yesterday", "1.234"]]
    });
    let out = result::decode(&data, 10).unwrap();
    assert_eq!(
        out["rows"][0],
        json!({"N": "twelve", "D": "yesterday", "AMT": "1.234"})
    );
    assert_eq!(out["decode_warning_count"], 3);
}

#[test]
fn rows_past_max_rows_are_not_delivered_and_say_so() {
    let rowset: Vec<Value> = (0..50).map(|i| json!([i.to_string()])).collect();
    let body = json!({"rowtype": [{"name": "N", "type": "fixed", "scale": 0}], "rowset": rowset});
    let out = result::decode(&body, 7).unwrap();
    assert_eq!(out["row_count"], 7);
    assert_eq!(out["truncated"], true);
    assert_eq!(out["rows"][6]["N"], 6);

    let arrow = result::decode(&data("fakesnow_select"), 1).unwrap();
    assert_eq!(arrow["row_count"], 1);
    assert_eq!(arrow["truncated"], true);
}

#[test]
fn chunks_are_counted_never_fetched() {
    let data = json!({
        "rowtype": [{"name": "N", "type": "fixed", "scale": 0}],
        "rowset": [["1"]],
        "chunks": [{"url": "https://example-bucket.s3.amazonaws.com/x", "rowCount": 5000}]
    });
    let out = result::decode(&data, 10).unwrap();
    assert_eq!(out["chunks_not_fetched"], 1);
    assert_eq!(out["rows_in_chunks"], 5000);
    assert_eq!(out["truncated"], true);
}

#[test]
fn bounds_on_columns_cells_and_nesting() {
    let rowtype: Vec<Value> = (0..=MAX_COLUMNS)
        .map(|i| json!({"name": format!("C{i}"), "type": "text"}))
        .collect();
    let err = result::decode(&json!({"rowtype": rowtype, "rowset": []}), 10).unwrap_err();
    assert!(format!("{err:#}").contains("columns"), "{err:#}");

    let long = "x".repeat(MAX_CELL_BYTES + 100);
    let deep = format!(
        "{}{}",
        "[".repeat(MAX_VARIANT_DEPTH + 1),
        "]".repeat(MAX_VARIANT_DEPTH + 1)
    );
    let fine = format!(
        "{}{}",
        "[".repeat(MAX_VARIANT_DEPTH),
        "]".repeat(MAX_VARIANT_DEPTH)
    );
    let data = json!({
        "rowtype": [{"name": "T", "type": "text"}, {"name": "V", "type": "variant"},
                    {"name": "W", "type": "array"}],
        "rowset": [[long, deep, fine]]
    });
    let out = result::decode(&data, 10).unwrap();
    assert_eq!(out["truncated_cells"], 1);
    assert!(out["rows"][0]["T"].as_str().unwrap().len() <= MAX_CELL_BYTES + 3);
    assert!(out["rows"][0]["V"].is_string(), "too deep is text");
    assert!(out["rows"][0]["W"].is_array(), "at the bound is JSON");
    assert_eq!(result::json_depth(r#"{"a":"[[[[","b":[1]}"#), 2);
}

#[test]
fn malformed_arrow_is_refused_not_panicked_on() {
    let good = {
        use base64::Engine as _;
        let b64 = data("fakesnow_select")["rowsetBase64"]
            .as_str()
            .unwrap()
            .to_string();
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap()
    };
    let decoded = arrow::decode_stream(&good, 100).unwrap();
    assert_eq!(decoded.total_rows, 2);
    assert_eq!(decoded.fields.len(), 10);
    // Every truncation and every single-byte corruption either decodes or errors; none panics.
    for cut in 0..good.len() {
        let _ = arrow::decode_stream(&good[..cut], 100);
    }
    for i in 0..good.len() {
        for x in [0x00u8, 0xFF, 0x7F, 0x80] {
            let mut bad = good.clone();
            bad[i] = x;
            let _ = arrow::decode_stream(&bad, 100);
        }
    }
    assert!(arrow::decode_stream(b"\xff\xff\xff\xff\x10\x00\x00\x00garbage", 10).is_err());
}

#[test]
fn the_target_is_mandatory_and_never_derived() {
    for (remote, url) in [("", None), ("  ", Some("")), ("", Some("  "))] {
        let err = resolve_endpoint(remote, url).unwrap_err().to_string();
        assert!(err.contains("needs a target"), "{err}");
    }
    assert_eq!(
        resolve_endpoint("127.0.0.1:8085", None).unwrap(),
        "http://127.0.0.1:8085"
    );
    assert_eq!(
        resolve_endpoint("127.0.0.1:1", Some("http://127.0.0.1:9/")).unwrap(),
        "http://127.0.0.1:9",
        "an endpoint_url is used exactly as given"
    );
    assert!(resolve_endpoint("ftp://127.0.0.1", None).is_err());
    assert!(resolve_endpoint("", Some("http://127.0.0.1:9/?x=1")).is_err());
}
