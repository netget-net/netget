//! Prometheus exposition rendering: structured metric families in, text format 0.0.4 or
//! OpenMetrics 1.0.0 out.
//!
//! The model never writes a byte of the exposition. It hands over families — name, type,
//! help, samples with labels — and [`MetricFamilies::parse`] refuses anything a scraper would
//! reject or mis-read, with a message naming what is wrong. [`MetricFamilies::render`] then
//! produces the wire text. The split is what makes "the model cannot emit an invalid
//! exposition" true rather than hoped for: every check lives on the parse side, so a value
//! that reaches `render` has already been accepted.
//!
//! What is enforced, and why each one exists:
//!
//! - **Names.** Metric names match `[a-zA-Z_:][a-zA-Z0-9_:]*`, label names
//!   `[a-zA-Z_][a-zA-Z0-9_]*`, and label names beginning `__` are refused — Prometheus reserves
//!   them, and a scrape carrying one is rejected outright.
//! - **Suffixes per type.** A histogram sample is `_bucket` (with `le`), `_sum` or `_count`; a
//!   summary sample is a quantile (with `quantile`), `_sum` or `_count`; a gauge or untyped
//!   sample has no suffix. `le` and `quantile` are refused where they do not belong.
//! - **Counters end in `_total`.** Text format 0.0.4 names the family by its sample, so the
//!   `_total` goes on the `# TYPE` line too; OpenMetrics names the family without it. A counter
//!   named without `_total` has it appended, which is what the exposition guidelines require
//!   and what `promtool check metrics` lints for. Counter values may not be negative.
//! - **Histograms are well-formed.** Buckets are sorted by `le`, must be cumulative
//!   (non-decreasing), and always end in a `+Inf` bucket: one is synthesised from `_count`, or
//!   from the largest bucket when there is no `_count`. A `_count` that disagrees with the
//!   `+Inf` bucket is refused, because both formats define them as the same number.
//! - **No duplicate series.** Two samples with the same name and label set are refused — a
//!   Prometheus scrape rejects the whole target for that — and so are two families whose
//!   sample names collide (a gauge `x_count` beside a histogram `x`).
//! - **Escaping.** Label values escape `\`, `"` and line feed; help text escapes `\` and line
//!   feed (and `"` in OpenMetrics, whose grammar requires it).
//!
//! Recursion: none. Inputs are flat JSON arrays; every loop is bounded by [`MAX_SAMPLES`].

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Most samples one `send_metrics` may carry, across all families.
///
/// A real node_exporter exposes around a thousand; fifty thousand is well past any honest
/// answer and still renders in a few megabytes. The bound exists so a runaway model or script
/// cannot make one scrape allocate without limit.
pub const MAX_SAMPLES: usize = 50_000;

/// Longest metric or label name accepted.
pub const MAX_NAME_LEN: usize = 256;

/// Longest label value or help text accepted, in bytes.
pub const MAX_TEXT_LEN: usize = 16 * 1024;

/// The wire format a scrape negotiated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// `text/plain; version=0.0.4` — the classic Prometheus text format.
    Text,
    /// `application/openmetrics-text; version=1.0.0`.
    OpenMetrics,
}

impl Format {
    /// The `Content-Type` this format is served with.
    pub fn content_type(self) -> &'static str {
        match self {
            Format::Text => "text/plain; version=0.0.4; charset=utf-8",
            Format::OpenMetrics => "application/openmetrics-text; version=1.0.0; charset=utf-8",
        }
    }

    /// The name used in event data and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Text => "text",
            Format::OpenMetrics => "openmetrics",
        }
    }
}

/// Choose the format from an `Accept` header.
///
/// OpenMetrics is chosen only when the client lists `application/openmetrics-text` with a
/// strictly higher q-value than every text/plain or wildcard alternative. That is what
/// Prometheus 2.5+ and 3.x send by default; `curl` and anything that sends no `Accept`, or
/// `*/*`, gets the text format, which is what every Prometheus-compatible parser accepts.
pub fn negotiate(accept: Option<&str>) -> Format {
    let Some(accept) = accept else {
        return Format::Text;
    };
    let mut best_openmetrics: f32 = -1.0;
    let mut best_other: f32 = -1.0;
    for entry in accept.split(',') {
        let mut parts = entry.split(';');
        let media = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let mut q: f32 = 1.0;
        for param in parts {
            if let Some((k, v)) = param.split_once('=') {
                if k.trim().eq_ignore_ascii_case("q") {
                    q = v.trim().parse().unwrap_or(0.0);
                }
            }
        }
        if !q.is_finite() || q <= 0.0 {
            continue;
        }
        if media == "application/openmetrics-text" {
            best_openmetrics = best_openmetrics.max(q);
        } else if media == "text/plain" || media == "*/*" || media == "text/*" {
            best_other = best_other.max(q);
        }
    }
    if best_openmetrics > best_other {
        Format::OpenMetrics
    } else {
        Format::Text
    }
}

/// A metric type as the model names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
    Untyped,
}

impl MetricType {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "counter" => Some(Self::Counter),
            "gauge" => Some(Self::Gauge),
            "histogram" => Some(Self::Histogram),
            "summary" => Some(Self::Summary),
            "untyped" | "unknown" => Some(Self::Untyped),
            _ => None,
        }
    }

    fn type_word(self, format: Format) -> &'static str {
        match (self, format) {
            (Self::Counter, _) => "counter",
            (Self::Gauge, _) => "gauge",
            (Self::Histogram, _) => "histogram",
            (Self::Summary, _) => "summary",
            (Self::Untyped, Format::Text) => "untyped",
            (Self::Untyped, Format::OpenMetrics) => "unknown",
        }
    }
}

/// Which series of a family a sample belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Suffix {
    /// No suffix: a gauge/untyped value, a counter's `_total`, a summary quantile.
    None,
    Bucket,
    Sum,
    Count,
}

impl Suffix {
    fn text(self, mtype: MetricType) -> &'static str {
        match (self, mtype) {
            (Suffix::None, MetricType::Counter) => "_total",
            (Suffix::None, _) => "",
            (Suffix::Bucket, _) => "_bucket",
            (Suffix::Sum, _) => "_sum",
            (Suffix::Count, _) => "_count",
        }
    }
}

#[derive(Clone, Debug)]
struct Sample {
    suffix: Suffix,
    /// Labels other than `le` / `quantile`, sorted by name.
    labels: BTreeMap<String, String>,
    /// `le` for a bucket, `quantile` for a summary quantile.
    bound: Option<f64>,
    value: f64,
    timestamp_ms: Option<i64>,
}

#[derive(Clone, Debug)]
struct Family {
    /// The family name without `_total` for a counter; the name as given otherwise.
    base: String,
    mtype: MetricType,
    help: Option<String>,
    samples: Vec<Sample>,
}

/// A validated, normalised set of metric families, ready to render in either format.
#[derive(Clone, Debug)]
pub struct MetricFamilies {
    families: Vec<Family>,
}

fn valid_metric_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == ':' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

fn valid_label_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A sample value: a JSON number, or one of the strings Prometheus spells specially.
fn parse_value(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => match s.trim() {
            "NaN" | "nan" => Some(f64::NAN),
            "+Inf" | "Inf" | "inf" | "+inf" => Some(f64::INFINITY),
            "-Inf" | "-inf" => Some(f64::NEG_INFINITY),
            other => other.parse::<f64>().ok(),
        },
        _ => None,
    }
}

/// Format a sample value the way both parsers read it back exactly.
fn format_value(v: f64) -> String {
    if v.is_nan() {
        "NaN".to_string()
    } else if v == f64::INFINITY {
        "+Inf".to_string()
    } else if v == f64::NEG_INFINITY {
        "-Inf".to_string()
    } else {
        // Rust's Display for f64 is the shortest string that round-trips, and never uses
        // exponent notation — both parsers accept it.
        format!("{v}")
    }
}

/// Format an `le` / `quantile` label value. Integral bounds carry `.0` (`"1.0"`, not `"1"`),
/// which is OpenMetrics' canonical form and is equally valid in the text format.
fn format_bound(v: f64) -> String {
    if v == f64::INFINITY {
        "+Inf".to_string()
    } else if v == f64::NEG_INFINITY {
        "-Inf".to_string()
    } else if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{v:.1}")
    } else {
        format!("{v}")
    }
}

fn escape_label_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

fn escape_help(s: &str, format: Format) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '"' if format == Format::OpenMetrics => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    out
}

impl MetricFamilies {
    /// Validate the `metrics` array of a `send_metrics` action.
    ///
    /// Every refusal names the metric and what is wrong with it, because this message is what
    /// the operator (and, through the access log, the model) reads to fix the answer.
    pub fn parse(metrics: &Value) -> Result<Self, String> {
        let list = metrics
            .as_array()
            .ok_or("'metrics' must be an array of metric families")?;

        let mut families = Vec::with_capacity(list.len());
        let mut seen_bases: BTreeSet<String> = BTreeSet::new();
        let mut total_samples = 0usize;

        for (i, raw) in list.iter().enumerate() {
            let name = raw
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("metrics[{i}] is missing a string 'name'"))?;
            if name.len() > MAX_NAME_LEN {
                return Err(format!(
                    "metric name '{}…' is longer than {MAX_NAME_LEN} characters",
                    &name[..name
                        .char_indices()
                        .nth(32)
                        .map(|(b, _)| b)
                        .unwrap_or(name.len())]
                ));
            }
            if !valid_metric_name(name) {
                return Err(format!(
                    "metric name '{name}' is invalid: it must match [a-zA-Z_:][a-zA-Z0-9_:]*"
                ));
            }
            let type_str = raw.get("type").and_then(Value::as_str).unwrap_or("untyped");
            let mtype = MetricType::parse(type_str).ok_or_else(|| {
                format!(
                    "metric '{name}' has type '{type_str}'; it must be one of counter, gauge, \
                     histogram, summary, untyped"
                )
            })?;
            let help = match raw.get("help") {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) if s.len() > MAX_TEXT_LEN => {
                    return Err(format!(
                        "metric '{name}' help text is longer than {MAX_TEXT_LEN} bytes"
                    ))
                }
                Some(Value::String(s)) => Some(s.clone()),
                Some(_) => return Err(format!("metric '{name}' help must be a string")),
            };

            let base = match mtype {
                MetricType::Counter => name.strip_suffix("_total").unwrap_or(name).to_string(),
                _ => name.to_string(),
            };
            if base.is_empty() {
                return Err(format!("metric name '{name}' is only a suffix"));
            }
            if !seen_bases.insert(base.clone()) {
                return Err(format!(
                    "metric family '{name}' appears twice; put all of its samples in one entry"
                ));
            }

            let raw_samples = match raw.get("samples") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(a)) => a.clone(),
                Some(_) => return Err(format!("metric '{name}' samples must be an array")),
            };
            total_samples = total_samples.saturating_add(raw_samples.len());
            if total_samples > MAX_SAMPLES {
                return Err(format!(
                    "more than {MAX_SAMPLES} samples in one answer; send fewer series"
                ));
            }

            let mut samples = Vec::with_capacity(raw_samples.len());
            for (j, s) in raw_samples.iter().enumerate() {
                samples.push(parse_sample(name, mtype, j, s)?);
            }

            let mut family = Family {
                base,
                mtype,
                help,
                samples,
            };
            normalise(&mut family, name)?;
            families.push(family);
        }

        // Two families whose rendered sample names collide would be read as one by a scraper.
        let mut owner: BTreeMap<String, String> = BTreeMap::new();
        for f in &families {
            for series in series_names(f) {
                if let Some(other) = owner.insert(series.clone(), f.base.clone()) {
                    if other != f.base {
                        return Err(format!(
                            "sample name '{series}' is produced by both '{other}' and '{}'; \
                             rename one of them",
                            f.base
                        ));
                    }
                }
            }
        }

        Ok(Self { families })
    }

    /// How many families this answer carries.
    pub fn family_count(&self) -> usize {
        self.families.len()
    }

    /// How many samples, after any `+Inf` / `_count` synthesis.
    pub fn sample_count(&self) -> usize {
        self.families.iter().map(|f| f.samples.len()).sum()
    }

    /// Render in the negotiated format.
    pub fn render(&self, format: Format) -> String {
        let mut out = String::new();
        for f in &self.families {
            let family_name = match (f.mtype, format) {
                (MetricType::Counter, Format::Text) => format!("{}_total", f.base),
                _ => f.base.clone(),
            };
            if let Some(help) = &f.help {
                out.push_str("# HELP ");
                out.push_str(&family_name);
                out.push(' ');
                out.push_str(&escape_help(help, format));
                out.push('\n');
            }
            out.push_str("# TYPE ");
            out.push_str(&family_name);
            out.push(' ');
            out.push_str(f.mtype.type_word(format));
            out.push('\n');

            for s in &f.samples {
                out.push_str(&f.base);
                out.push_str(s.suffix.text(f.mtype));
                let mut labels: Vec<(String, String)> = s
                    .labels
                    .iter()
                    .map(|(k, v)| (k.clone(), escape_label_value(v)))
                    .collect();
                if let Some(bound) = s.bound {
                    let key = if f.mtype == MetricType::Histogram {
                        "le"
                    } else {
                        "quantile"
                    };
                    labels.push((key.to_string(), format_bound(bound)));
                }
                if !labels.is_empty() {
                    out.push('{');
                    for (idx, (k, v)) in labels.iter().enumerate() {
                        if idx > 0 {
                            out.push(',');
                        }
                        out.push_str(k);
                        out.push_str("=\"");
                        out.push_str(v);
                        out.push('"');
                    }
                    out.push('}');
                }
                out.push(' ');
                out.push_str(&format_value(s.value));
                if let Some(ts) = s.timestamp_ms {
                    out.push(' ');
                    match format {
                        Format::Text => out.push_str(&ts.to_string()),
                        // OpenMetrics timestamps are seconds.
                        Format::OpenMetrics => {
                            let secs = ts.div_euclid(1000);
                            let millis = ts.rem_euclid(1000);
                            out.push_str(&format!("{secs}.{millis:03}"));
                        }
                    }
                }
                out.push('\n');
            }
        }
        if format == Format::OpenMetrics {
            out.push_str("# EOF\n");
        }
        out
    }
}

/// Every rendered sample name a family produces.
fn series_names(f: &Family) -> Vec<String> {
    let suffixes: &[&str] = match f.mtype {
        MetricType::Counter => &["_total"],
        MetricType::Gauge | MetricType::Untyped => &[""],
        MetricType::Histogram => &["_bucket", "_sum", "_count"],
        MetricType::Summary => &["", "_sum", "_count"],
    };
    suffixes
        .iter()
        .map(|s| format!("{}{}", f.base, s))
        .collect()
}

fn parse_sample(name: &str, mtype: MetricType, j: usize, s: &Value) -> Result<Sample, String> {
    let where_ = || format!("metric '{name}' sample {j}");

    let value = s
        .get("value")
        .and_then(parse_value)
        .ok_or_else(|| format!("{} has no numeric 'value'", where_()))?;

    let suffix_str = s.get("suffix").and_then(Value::as_str).unwrap_or("");
    let suffix = match (mtype, suffix_str) {
        (MetricType::Counter, "" | "_total") => Suffix::None,
        (MetricType::Gauge | MetricType::Untyped, "") => Suffix::None,
        (MetricType::Histogram, "_bucket") => Suffix::Bucket,
        (MetricType::Histogram | MetricType::Summary, "_sum") => Suffix::Sum,
        (MetricType::Histogram | MetricType::Summary, "_count") => Suffix::Count,
        (MetricType::Summary, "") => Suffix::None,
        // A histogram sample with an `le` label can only be a bucket: `_sum` and `_count`
        // never carry one. llama3.1:8b leaves the suffix off buckets in roughly one answer in
        // five, and refusing those failed the whole scrape over a word the label already says.
        (MetricType::Histogram, "")
            if s.get("labels")
                .and_then(Value::as_object)
                .is_some_and(|labels| labels.contains_key("le")) =>
        {
            Suffix::Bucket
        }
        (MetricType::Histogram, "") => {
            return Err(format!(
                "{} needs a suffix: a histogram sample without an 'le' label is _sum or _count",
                where_()
            ))
        }
        (_, other) => {
            return Err(format!(
                "{} has suffix '{other}', which a {} does not have",
                where_(),
                mtype.type_word(Format::Text)
            ))
        }
    };

    let mut labels = BTreeMap::new();
    let mut bound: Option<f64> = None;
    match s.get("labels") {
        None | Some(Value::Null) => {}
        Some(Value::Object(map)) => {
            for (k, v) in map {
                if k.len() > MAX_NAME_LEN || !valid_label_name(k) {
                    return Err(format!(
                        "{}: label name '{k}' is invalid: it must match [a-zA-Z_][a-zA-Z0-9_]*",
                        where_()
                    ));
                }
                if k.starts_with("__") {
                    return Err(format!(
                        "{}: label name '{k}' begins with '__', which Prometheus reserves",
                        where_()
                    ));
                }
                let text = match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => {
                        return Err(format!(
                            "{}: label '{k}' must be a string, number or boolean",
                            where_()
                        ))
                    }
                };
                if text.len() > MAX_TEXT_LEN {
                    return Err(format!(
                        "{}: label '{k}' is longer than {MAX_TEXT_LEN} bytes",
                        where_()
                    ));
                }
                let is_le = k == "le" && mtype == MetricType::Histogram;
                let is_quantile = k == "quantile" && mtype == MetricType::Summary;
                if is_le || is_quantile {
                    let b = parse_value(v).filter(|b| !b.is_nan()).ok_or_else(|| {
                        format!("{}: '{k}' must be a number or \"+Inf\"", where_())
                    })?;
                    bound = Some(b);
                } else if k == "le" || k == "quantile" {
                    // Harmless on a gauge in the text format, but it collides with the reserved
                    // meaning the moment anyone aggregates across types; refuse it everywhere
                    // it is not the histogram/summary label.
                    return Err(format!(
                        "{}: '{k}' is reserved for {} samples",
                        where_(),
                        if k == "le" {
                            "histogram _bucket"
                        } else {
                            "summary quantile"
                        }
                    ));
                } else {
                    labels.insert(k.clone(), text);
                }
            }
        }
        Some(_) => return Err(format!("{}: 'labels' must be an object", where_())),
    }

    match (mtype, suffix) {
        (MetricType::Histogram, Suffix::Bucket) if bound.is_none() => {
            return Err(format!("{} is a _bucket without an 'le' label", where_()))
        }
        (MetricType::Histogram, Suffix::Sum | Suffix::Count) if bound.is_some() => {
            return Err(format!(
                "{}: 'le' belongs on _bucket samples only",
                where_()
            ))
        }
        (MetricType::Summary, Suffix::None) => match bound {
            None => {
                return Err(format!(
                    "{} is a summary quantile without a 'quantile' label",
                    where_()
                ))
            }
            Some(q) if !(0.0..=1.0).contains(&q) => {
                return Err(format!("{}: quantile {q} is outside 0..1", where_()))
            }
            _ => {}
        },
        (MetricType::Summary, Suffix::Sum | Suffix::Count) if bound.is_some() => {
            return Err(format!(
                "{}: 'quantile' belongs on quantile samples only",
                where_()
            ))
        }
        _ => {}
    }

    let counts_things = matches!(
        (mtype, suffix),
        (MetricType::Counter, _) | (_, Suffix::Bucket) | (_, Suffix::Count)
    );
    if counts_things && (value.is_nan() || value < 0.0) {
        return Err(format!(
            "{}: value {} is not a valid count; counters, buckets and _count are non-negative",
            where_(),
            format_value(value)
        ));
    }

    let timestamp_ms = match s.get("timestamp_ms") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_i64().ok_or_else(|| {
            format!(
                "{}: timestamp_ms must be an integer (milliseconds since the epoch)",
                where_()
            )
        })?),
    };

    Ok(Sample {
        suffix,
        labels,
        bound,
        value,
        timestamp_ms,
    })
}

/// Sort, deduplicate-check and complete one family.
fn normalise(f: &mut Family, name: &str) -> Result<(), String> {
    // Duplicate series: same suffix, same labels, same bound.
    let mut seen = BTreeSet::new();
    for s in &f.samples {
        let key = (s.suffix, s.labels.clone(), s.bound.map(|b| b.to_bits()));
        if !seen.insert(key) {
            return Err(format!(
                "metric '{name}' has two samples with the same labels{}; each series may \
                 appear once",
                match s.bound {
                    Some(b) => format!(" and bound {}", format_bound(b)),
                    None => String::new(),
                }
            ));
        }
    }

    if f.mtype != MetricType::Histogram && f.mtype != MetricType::Summary {
        return Ok(());
    }

    // Group by label set; within a group, order is quantiles/buckets ascending, then _sum,
    // then _count — the order every client library writes and every parser expects.
    let mut groups: BTreeMap<BTreeMap<String, String>, Vec<Sample>> = BTreeMap::new();
    let mut order: Vec<BTreeMap<String, String>> = Vec::new();
    for s in f.samples.drain(..) {
        if !groups.contains_key(&s.labels) {
            order.push(s.labels.clone());
        }
        groups.entry(s.labels.clone()).or_default().push(s);
    }

    let mut out = Vec::new();
    for labels in order {
        let mut group = groups.remove(&labels).unwrap_or_default();
        group.sort_by(|a, b| {
            a.suffix.cmp(&b.suffix).then(
                a.bound
                    .unwrap_or(0.0)
                    .partial_cmp(&b.bound.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        });

        if f.mtype == MetricType::Histogram {
            let buckets: Vec<&Sample> = group
                .iter()
                .filter(|s| s.suffix == Suffix::Bucket)
                .collect();
            let count = group.iter().find(|s| s.suffix == Suffix::Count).cloned();
            let mut previous = 0.0f64;
            for b in &buckets {
                if b.value < previous {
                    return Err(format!(
                        "histogram '{name}' bucket le={} holds {} but a smaller bucket holds \
                         {}; buckets are cumulative, so each must be at least the one before",
                        format_bound(b.bound.unwrap_or(0.0)),
                        format_value(b.value),
                        format_value(previous)
                    ));
                }
                previous = b.value;
            }
            let has_inf = buckets
                .last()
                .is_some_and(|b| b.bound == Some(f64::INFINITY));
            let inf_value = if has_inf {
                previous
            } else {
                let v = count.as_ref().map(|c| c.value).unwrap_or(previous);
                if v < previous {
                    return Err(format!(
                        "histogram '{name}' _count {} is smaller than its largest bucket {}",
                        format_value(v),
                        format_value(previous)
                    ));
                }
                let template = group.iter().find(|s| s.suffix == Suffix::Bucket).cloned();
                if let Some(mut inf) = template.or_else(|| count.clone()) {
                    inf.suffix = Suffix::Bucket;
                    inf.bound = Some(f64::INFINITY);
                    inf.value = v;
                    let insert_at = group
                        .iter()
                        .position(|s| s.suffix != Suffix::Bucket)
                        .unwrap_or(group.len());
                    group.insert(insert_at, inf);
                    v
                } else {
                    // Only a _sum: nothing to anchor a bucket to, and a histogram whose only
                    // series is a sum is not one a scraper can use.
                    return Err(format!(
                        "histogram '{name}' has a _sum but no buckets and no _count"
                    ));
                }
            };
            match count {
                Some(c) if c.value != inf_value => {
                    return Err(format!(
                        "histogram '{name}' _count is {} but its +Inf bucket is {}; they are \
                         the same number by definition",
                        format_value(c.value),
                        format_value(inf_value)
                    ))
                }
                Some(_) => {}
                None => {
                    let mut c = group
                        .iter()
                        .find(|s| s.suffix == Suffix::Bucket)
                        .cloned()
                        .expect("a +Inf bucket was just ensured");
                    c.suffix = Suffix::Count;
                    c.bound = None;
                    c.value = inf_value;
                    group.push(c);
                }
            }
        }
        out.extend(group);
    }
    f.samples = out;
    Ok(())
}
