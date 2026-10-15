//! The exposition renderer, byte for byte, and every refusal it owns.
//!
//! `real_client_test.rs` proves an independent parser accepts what this renders; this file pins
//! the exact bytes and, more importantly, the refusals — each one is a body a scraper would
//! reject or mis-read, and the renderer's promise is that the model cannot produce one.

use netget::server::prometheus::exposition::{negotiate, Format, MetricFamilies};
use serde_json::json;

fn render(metrics: serde_json::Value, format: Format) -> String {
    MetricFamilies::parse(&metrics)
        .unwrap_or_else(|e| panic!("expected {metrics} to be accepted, got: {e}"))
        .render(format)
}

fn refusal(metrics: serde_json::Value) -> String {
    match MetricFamilies::parse(&metrics) {
        Ok(f) => panic!(
            "expected a refusal, but it rendered:\n{}",
            f.render(Format::Text)
        ),
        Err(e) => e,
    }
}

#[test]
fn a_counter_gains_total_on_its_type_line_in_text_and_loses_it_in_openmetrics() {
    let metrics = json!([{
        "name": "jobs", "type": "counter", "help": "Jobs run.",
        "samples": [{"labels": {"queue": "a"}, "value": 3}]
    }]);
    assert_eq!(
        render(metrics.clone(), Format::Text),
        "# HELP jobs_total Jobs run.\n# TYPE jobs_total counter\njobs_total{queue=\"a\"} 3\n"
    );
    assert_eq!(
        render(metrics, Format::OpenMetrics),
        "# HELP jobs Jobs run.\n# TYPE jobs counter\njobs_total{queue=\"a\"} 3\n# EOF\n"
    );
}

#[test]
fn a_counter_already_named_total_is_not_suffixed_twice() {
    let text = render(
        json!([{"name": "x_total", "type": "counter", "samples": [{"value": 1, "suffix": "_total"}]}]),
        Format::Text,
    );
    assert_eq!(text, "# TYPE x_total counter\nx_total 1\n");
}

#[test]
fn label_values_and_help_are_escaped() {
    let text = render(
        json!([{
            "name": "g", "type": "gauge",
            "help": "back\\slash and\nnewline \"quoted\"",
            "samples": [{"labels": {"path": "C:\\dir \"x\"\nnext"}, "value": 1.5}]
        }]),
        Format::Text,
    );
    assert_eq!(
        text,
        "# HELP g back\\\\slash and\\nnewline \"quoted\"\n# TYPE g gauge\n\
         g{path=\"C:\\\\dir \\\"x\\\"\\nnext\"} 1.5\n"
    );
    // OpenMetrics additionally escapes the double quote in help text.
    let om = render(
        json!([{"name": "g", "type": "gauge", "help": "say \"hi\"", "samples": [{"value": 1}]}]),
        Format::OpenMetrics,
    );
    assert!(om.starts_with("# HELP g say \\\"hi\\\"\n"), "{om}");
}

#[test]
fn histogram_buckets_are_sorted_and_completed_with_inf_and_count() {
    let text = render(
        json!([{
            "name": "lat_seconds", "type": "histogram",
            "samples": [
                {"suffix": "_bucket", "labels": {"le": "1"}, "value": 9},
                {"suffix": "_sum", "value": 4.5},
                {"suffix": "_bucket", "labels": {"le": 0.1}, "value": 2}
            ]
        }]),
        Format::Text,
    );
    assert_eq!(
        text,
        "# TYPE lat_seconds histogram\n\
         lat_seconds_bucket{le=\"0.1\"} 2\n\
         lat_seconds_bucket{le=\"1.0\"} 9\n\
         lat_seconds_bucket{le=\"+Inf\"} 9\n\
         lat_seconds_sum 4.5\n\
         lat_seconds_count 9\n"
    );
}

#[test]
fn a_missing_inf_bucket_is_taken_from_count_per_label_set() {
    let text = render(
        json!([{
            "name": "h", "type": "histogram",
            "samples": [
                {"suffix": "_bucket", "labels": {"svc": "b", "le": "5"}, "value": 1},
                {"suffix": "_count", "labels": {"svc": "b"}, "value": 4},
                {"suffix": "_bucket", "labels": {"svc": "a", "le": "5"}, "value": 2}
            ]
        }]),
        Format::Text,
    );
    assert!(
        text.contains("h_bucket{svc=\"b\",le=\"+Inf\"} 4\nh_count{svc=\"b\"} 4\n"),
        "{text}"
    );
    assert!(
        text.contains("h_bucket{svc=\"a\",le=\"+Inf\"} 2\n"),
        "{text}"
    );
    assert!(text.contains("h_count{svc=\"a\"} 2\n"), "{text}");
}

#[test]
fn summary_quantiles_untyped_nan_and_timestamps_render() {
    let text = render(
        json!([
            {"name": "rpc", "type": "summary", "samples": [
                {"suffix": "_count", "value": 10},
                {"labels": {"quantile": 0.99}, "value": 0.2},
                {"labels": {"quantile": "0.5"}, "value": 0.05},
                {"suffix": "_sum", "value": 1.1}
            ]},
            {"name": "u", "type": "untyped", "samples": [{"value": "NaN", "timestamp_ms": 1700000000123_i64}]}
        ]),
        Format::Text,
    );
    assert_eq!(
        text,
        "# TYPE rpc summary\nrpc{quantile=\"0.5\"} 0.05\nrpc{quantile=\"0.99\"} 0.2\n\
         rpc_sum 1.1\nrpc_count 10\n# TYPE u untyped\nu NaN 1700000000123\n"
    );
    let om = render(
        json!([{"name": "u", "type": "untyped", "samples": [{"value": 1, "timestamp_ms": 1700000000123_i64}]}]),
        Format::OpenMetrics,
    );
    assert_eq!(om, "# TYPE u unknown\nu 1 1700000000.123\n# EOF\n");
}

#[test]
fn every_malformed_answer_is_refused_with_a_reason() {
    let cases: Vec<(serde_json::Value, &str)> = vec![
        (
            json!([{"name": "9starts_with_digit", "type": "gauge"}]),
            "invalid",
        ),
        (json!([{"name": "has-dash", "type": "gauge"}]), "invalid"),
        (json!([{"name": "x", "type": "gaugeish"}]), "must be one of"),
        (
            json!([{"name": "x", "type": "gauge", "samples": [{"labels": {"__name__": "y"}, "value": 1}]}]),
            "reserves",
        ),
        (
            json!([{"name": "x", "type": "gauge", "samples": [{"labels": {"bad-label": "y"}, "value": 1}]}]),
            "label name",
        ),
        (
            json!([{"name": "x", "type": "gauge", "samples": [{"value": 1}, {"value": 2}]}]),
            "same labels",
        ),
        (
            json!([{"name": "x", "type": "gauge"}, {"name": "x", "type": "counter"}]),
            "appears twice",
        ),
        (
            json!([{"name": "x", "type": "counter", "samples": [{"value": -1}]}]),
            "not a valid count",
        ),
        (
            json!([{"name": "x", "type": "gauge", "samples": [{"value": 1, "suffix": "_bucket"}]}]),
            "does not have",
        ),
        (
            json!([{"name": "h", "type": "histogram", "samples": [{"value": 1}]}]),
            "needs a suffix",
        ),
        (
            json!([{"name": "h", "type": "histogram", "samples": [{"value": 1, "suffix": "_bucket"}]}]),
            "without an 'le'",
        ),
        (
            json!([{"name": "h", "type": "histogram", "samples": [
                {"suffix": "_bucket", "labels": {"le": "1"}, "value": 5},
                {"suffix": "_bucket", "labels": {"le": "2"}, "value": 3}
            ]}]),
            "cumulative",
        ),
        (
            json!([{"name": "h", "type": "histogram", "samples": [
                {"suffix": "_bucket", "labels": {"le": "+Inf"}, "value": 5},
                {"suffix": "_count", "value": 6}
            ]}]),
            "same number",
        ),
        (
            json!([{"name": "s", "type": "summary", "samples": [{"labels": {"quantile": 2}, "value": 1}]}]),
            "outside 0..1",
        ),
        (
            json!([{"name": "g", "type": "gauge", "samples": [{"labels": {"le": "1"}, "value": 1}]}]),
            "reserved",
        ),
        (
            json!([{"name": "h", "type": "histogram"}, {"name": "h_count", "type": "gauge"}]),
            "produced by both",
        ),
        (json!({"name": "not an array"}), "must be an array"),
        (
            json!([{"name": "x", "type": "gauge", "samples": [{"value": "many"}]}]),
            "no numeric 'value'",
        ),
    ];
    for (metrics, needle) in cases {
        let reason = refusal(metrics.clone());
        assert!(
            reason.contains(needle),
            "refusal for {metrics} should mention {needle:?}, got: {reason}"
        );
    }
}

#[test]
fn the_sample_cap_is_enforced() {
    let samples: Vec<_> = (0..=netget::server::prometheus::exposition::MAX_SAMPLES)
        .map(|i| json!({"labels": {"i": i.to_string()}, "value": i}))
        .collect();
    let reason = refusal(json!([{"name": "big", "type": "gauge", "samples": samples}]));
    assert!(reason.contains("samples in one answer"), "{reason}");
}

#[test]
fn negotiation_prefers_openmetrics_only_when_the_scraper_does() {
    // What Prometheus 3.15 sends by default, captured from a real scrape.
    let prometheus_default = "application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.7,\
        application/openmetrics-text;version=0.0.1;q=0.6,text/plain;version=1.0.0;escaping=allow-utf-8;q=0.5,\
        text/plain;version=0.0.4;q=0.4,*/*;q=0.3";
    assert_eq!(negotiate(Some(prometheus_default)), Format::OpenMetrics);
    assert_eq!(
        negotiate(Some("text/plain;version=0.0.4;q=1,*/*;q=0.1")),
        Format::Text
    );
    assert_eq!(negotiate(None), Format::Text);
    assert_eq!(negotiate(Some("*/*")), Format::Text);
    assert_eq!(
        negotiate(Some("application/openmetrics-text; version=1.0.0")),
        Format::OpenMetrics
    );
}
