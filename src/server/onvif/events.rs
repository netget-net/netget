//! Events (ver10/events) for the ONVIF device, pull-point mode: GetEventProperties,
//! CreatePullPointSubscription, PullMessages, Renew, Unsubscribe, SetSynchronizationPoint.
//!
//! The topics are fixed (`TOPICS`, in ONVIF's `tns1:` topic namespace) and every one is a
//! property: the device remembers each property's last value per source (`MAX_PROPERTIES`) and
//! sends those as `Initialized` when a subscription is created and on SetSynchronizationPoint,
//! as ONVIF requires. Notifications are put on every live subscription whose filter matches,
//! each queue bounded at `MAX_QUEUED` (the oldest is dropped, and counted). Subscriptions are
//! bounded in number (`MAX_SUBSCRIPTIONS`) and lifetime (`MAX_TERMINATION`); an expired one is
//! gone at the next look. All of it is in memory for the life of the server.
//!
//! Topic filters are parsed here without recursion and bounded in length, alternatives and
//! depth (`MAX_TOPIC_EXPRESSION`, `MAX_TOPIC_ALTERNATIVES`, `MAX_TOPIC_DEPTH`); the fuzz target
//! `onvif_topic_filter` drives this parser and `wire::parse_duration`.
use super::wire::{self, esc};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Live pull-point subscriptions at most.
pub const MAX_SUBSCRIPTIONS: usize = 16;
/// Notifications waiting on one subscription at most; past it the oldest is dropped.
pub const MAX_QUEUED: usize = 256;
/// A PullMessages MessageLimit is clamped to 1..=this.
pub const MAX_MESSAGE_LIMIT: usize = 100;
/// A PullMessages Timeout is clamped to this by default (startup parameter
/// `max_pull_timeout_secs`, 1..=60: ONVIF requires devices to support at least a minute).
pub const MAX_PULL_TIMEOUT: Duration = Duration::from_secs(60);
/// A subscription created without an InitialTerminationTime lives this long.
pub const DEFAULT_TERMINATION: Duration = Duration::from_secs(60);
/// A subscription's termination time is at most this far ahead.
pub const MAX_TERMINATION: Duration = Duration::from_secs(3600);
/// Property values remembered at most (one per topic and source).
pub const MAX_PROPERTIES: usize = 64;
/// A topic expression at most, in bytes.
pub const MAX_TOPIC_EXPRESSION: usize = 1024;
/// `|`-separated alternatives in one topic expression at most.
pub const MAX_TOPIC_ALTERNATIVES: usize = 16;
/// Segments in one topic path at most.
pub const MAX_TOPIC_DEPTH: usize = 8;
/// A Source or Data item's value at most, in bytes.
pub const MAX_ITEM_VALUE: usize = 256;

pub const CONCRETE_SET: &str = "http://www.onvif.org/ver10/tev/topicExpression/ConcreteSet";
pub const WSN_CONCRETE: &str = "http://docs.oasis-open.org/wsn/t-1/TopicExpression/Concrete";
pub const WSN_CONCRETE_SET: &str = "http://docs.oasis-open.org/wsn/t-1/TopicExpression/ConcreteSet";
pub const WSN_SIMPLE: &str = "http://docs.oasis-open.org/wsn/t-1/TopicExpression/Simple";
pub const WSN_FULL: &str = "http://docs.oasis-open.org/wsn/t-1/TopicExpression/Full";

/// One topic the device produces: its path below `tns1:`, the Source and Data items its
/// messages carry (name, XML Schema type).
#[derive(Debug)]
pub struct TopicDef {
    pub path: &'static str,
    pub source: &'static [(&'static str, &'static str)],
    pub data: &'static [(&'static str, &'static str)],
}

const RULE_SOURCE: &[(&str, &str)] = &[
    ("VideoSourceConfigurationToken", "tt:ReferenceToken"),
    ("VideoAnalyticsConfigurationToken", "tt:ReferenceToken"),
    ("Rule", "xs:string"),
];

pub const TOPICS: &[TopicDef] = &[
    TopicDef {
        path: "VideoSource/MotionAlarm",
        source: &[("Source", "tt:ReferenceToken")],
        data: &[("State", "xs:boolean")],
    },
    TopicDef {
        path: "RuleEngine/CellMotionDetector/Motion",
        source: RULE_SOURCE,
        data: &[("IsMotion", "xs:boolean")],
    },
    TopicDef {
        path: "RuleEngine/TamperDetector/Tamper",
        source: RULE_SOURCE,
        data: &[("IsTamper", "xs:boolean")],
    },
    TopicDef {
        path: "Device/Trigger/DigitalInput",
        source: &[("InputToken", "tt:ReferenceToken")],
        data: &[("LogicalState", "xs:boolean")],
    },
];

/// A topic by its path, with or without a namespace prefix on its root.
pub fn topic(name: &str) -> Option<&'static TopicDef> {
    let path = name.trim();
    let path = path.split_once(':').map(|(_, p)| p).unwrap_or(path);
    TOPICS.iter().find(|t| t.path == path)
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub topic: &'static TopicDef,
    pub utc: chrono::DateTime<chrono::Utc>,
    /// Initialized, Changed or Deleted.
    pub operation: &'static str,
    pub source: Vec<(String, String)>,
    pub data: Vec<(String, String)>,
}

impl Notification {
    fn property_key(&self) -> (String, Vec<(String, String)>) {
        (self.topic.path.to_string(), self.source.clone())
    }

    pub fn json(&self) -> Value {
        let map = |items: &[(String, String)]| -> Value {
            Value::Object(
                items
                    .iter()
                    .map(|(k, v)| (k.clone(), json!(v)))
                    .collect::<Map<_, _>>(),
            )
        };
        json!({"topic": format!("tns1:{}", self.topic.path), "utc_time": wire::format_datetime(self.utc),
               "property_operation": self.operation, "source": map(&self.source), "data": map(&self.data)})
    }
}

/// An item value from the model: a string, a boolean or a number, as text. Booleans are
/// written `true`/`false` whichever form they came in.
fn item_value(kind: &str, v: &Value) -> Result<String> {
    let text = match v {
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => bail!("an item value is a string, number or boolean"),
    };
    ensure!(
        !text.is_empty()
            && text.len() <= MAX_ITEM_VALUE
            && !crate::utils::sanitize::has_controls(&text),
        "an item value is 1-{MAX_ITEM_VALUE} bytes without control characters"
    );
    if kind == "xs:boolean" {
        return wire::parse_bool(&text)
            .map(|b| b.to_string())
            .context("a boolean item is true or false");
    }
    if kind == "tt:ReferenceToken" {
        ensure!(
            text.len() <= 64 && !text.chars().any(char::is_whitespace),
            "a token item is at most 64 characters without spaces"
        );
    }
    Ok(text)
}

/// The notification an `onvif_raise_event` action describes, or why it is not one.
pub fn notification_from_action(
    v: &Value,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Notification> {
    let name = v["topic"].as_str().context("topic is required")?;
    let def = topic(name).with_context(|| {
        format!(
            "topic must be one of {}",
            TOPICS
                .iter()
                .map(|t| format!("tns1:{}", t.path))
                .collect::<Vec<_>>()
                .join(", ")
        )
    })?;
    let items = |key: &str, declared: &[(&str, &str)]| -> Result<Vec<(String, String)>> {
        let obj = v[key]
            .as_object()
            .with_context(|| format!("{key} is an object of item names to values"))?;
        for k in obj.keys() {
            ensure!(
                declared.iter().any(|(n, _)| n == k),
                "{key} item {k:?} is not one {} carries (it carries {})",
                def.path,
                declared
                    .iter()
                    .map(|(n, _)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        declared
            .iter()
            .map(|(n, kind)| {
                let value = obj.get(*n).with_context(|| format!("{key} needs {n}"))?;
                Ok((n.to_string(), item_value(kind, value)?))
            })
            .collect()
    };
    let operation = match v["property_operation"].as_str() {
        None => "Changed",
        Some("Changed") => "Changed",
        Some("Initialized") => "Initialized",
        Some("Deleted") => "Deleted",
        Some(_) => bail!("property_operation is Initialized, Changed or Deleted"),
    };
    Ok(Notification {
        topic: def,
        utc: now,
        operation,
        source: items("source", def.source)?,
        data: items("data", def.data)?,
    })
}

// ---- topic filters --------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Pattern {
    /// Path segments; `*` matches any one segment.
    pub segments: Vec<String>,
    /// `//.` at the end: the topic and everything below it.
    pub descendants: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    All,
    Topics(Vec<Pattern>),
}

impl Filter {
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Filter::All => true,
            Filter::Topics(ps) => ps.iter().any(|p| p.matches(path)),
        }
    }
    pub fn json(&self) -> Value {
        match self {
            Filter::All => Value::Null,
            Filter::Topics(ps) => json!(ps
                .iter()
                .map(|p| format!(
                    "tns1:{}{}",
                    p.segments.join("/"),
                    if p.descendants { "//." } else { "" }
                ))
                .collect::<Vec<_>>()),
        }
    }
}

impl Pattern {
    pub fn matches(&self, path: &str) -> bool {
        let topic: Vec<&str> = path.split('/').collect();
        if topic.len() < self.segments.len()
            || (!self.descendants && topic.len() != self.segments.len())
        {
            return false;
        }
        self.segments
            .iter()
            .zip(&topic)
            .all(|(p, t)| p == "*" || p == t)
    }
}

/// Why a filter was refused, as the WS-BaseNotification fault it is answered with.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FilterError {
    DialectUnknown,
    InvalidExpression,
    TopicNotSupported,
}

impl FilterError {
    /// The WS-BaseNotification fault element for the Detail.
    pub fn detail(self) -> &'static str {
        match self {
            FilterError::DialectUnknown => "<wsnt:TopicExpressionDialectUnknownFault/>",
            FilterError::InvalidExpression => "<wsnt:InvalidTopicExpressionFault/>",
            FilterError::TopicNotSupported => "<wsnt:TopicNotSupportedFault/>",
        }
    }
    pub fn reason(self) -> &'static str {
        match self {
            FilterError::DialectUnknown => "Unknown topic expression dialect",
            FilterError::InvalidExpression => "Invalid topic expression",
            FilterError::TopicNotSupported => "No topic the device produces matches the filter",
        }
    }
}

fn ncname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && !s.starts_with(|c: char| c.is_ascii_digit() || c == '-' || c == '.')
}

/// A TopicExpression in one of the dialects ONVIF devices accept. An empty expression is no
/// filter at all (use-go/onvif always sends the element, empty). Matching is on paths below the
/// root's namespace prefix, whatever prefix the client bound to ONVIF's topic namespace.
pub fn parse_topic_filter(dialect: &str, expression: &str) -> Result<Filter, FilterError> {
    let expression = expression.trim();
    if expression.is_empty() {
        return Ok(Filter::All);
    }
    let dialect = dialect.trim();
    let (wildcards, descendants_ok, simple) = match dialect {
        "" | CONCRETE_SET | WSN_CONCRETE_SET => (false, true, false),
        WSN_CONCRETE => (false, false, false),
        WSN_FULL => (true, true, false),
        WSN_SIMPLE => (false, false, true),
        _ => return Err(FilterError::DialectUnknown),
    };
    if expression.len() > MAX_TOPIC_EXPRESSION {
        return Err(FilterError::InvalidExpression);
    }
    let alternatives: Vec<&str> = expression.split('|').collect();
    if alternatives.len() > MAX_TOPIC_ALTERNATIVES || (simple && alternatives.len() > 1) {
        return Err(FilterError::InvalidExpression);
    }
    let mut patterns = Vec::new();
    for alt in alternatives {
        let mut alt = alt.trim();
        let mut descendants = false;
        if let Some(rest) = alt.strip_suffix("//.") {
            if !descendants_ok {
                return Err(FilterError::InvalidExpression);
            }
            alt = rest;
            descendants = true;
        }
        // The root may carry a namespace prefix; nothing below it may.
        let alt = match alt.split_once(':') {
            Some((prefix, rest)) if ncname(prefix) => rest,
            Some(_) => return Err(FilterError::InvalidExpression),
            None => alt,
        };
        let segments: Vec<String> = alt.split('/').map(str::to_string).collect();
        if segments.len() > MAX_TOPIC_DEPTH || (simple && segments.len() != 1) {
            return Err(FilterError::InvalidExpression);
        }
        for s in &segments {
            if !(ncname(s) || (wildcards && s == "*")) {
                return Err(FilterError::InvalidExpression);
            }
        }
        // A Simple expression names a root topic, which here means everything below it.
        patterns.push(Pattern {
            segments,
            descendants: descendants || simple,
        });
    }
    let filter = Filter::Topics(patterns);
    if !TOPICS.iter().any(|t| filter.matches(t.path)) {
        return Err(FilterError::TopicNotSupported);
    }
    Ok(filter)
}

/// A subscription's filter from a CreatePullPointSubscription body.
pub fn filter_of(body: &wire::Element) -> Result<Filter, FilterError> {
    let Some(f) = body.child("Filter") else {
        return Ok(Filter::All);
    };
    if f.child("MessageContent")
        .is_some_and(|m| !m.text.trim().is_empty())
    {
        // Message content filters are not supported; refusing beats ignoring.
        return Err(FilterError::InvalidExpression);
    }
    match f.child("TopicExpression") {
        None => Ok(Filter::All),
        Some(t) => parse_topic_filter(t.attr("Dialect").unwrap_or_default(), &t.text),
    }
}

/// An AbsoluteOrRelativeTimeType: a duration from `now`, or an absolute time. use-go/onvif
/// writes it as child elements, so the first non-empty text below it counts too.
pub fn time_of(
    el: Option<&wire::Element>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    let Some(el) = el else {
        return Ok(None);
    };
    let mut text = el.text.trim().to_string();
    if text.is_empty() {
        text = el
            .children
            .iter()
            .map(|c| c.text.trim())
            .find(|t| !t.is_empty())
            .unwrap_or_default()
            .to_string();
    }
    if text.is_empty() {
        return Ok(None);
    }
    if text.starts_with('P') {
        let d = wire::parse_duration(&text)?;
        return Ok(Some(
            now + chrono::Duration::from_std(d).context("duration out of range")?,
        ));
    }
    Ok(Some(wire::parse_datetime(&text)?))
}

// ---- the broker -----------------------------------------------------------------------------

pub struct Subscription {
    pub filter: Filter,
    pub termination: chrono::DateTime<chrono::Utc>,
    queue: VecDeque<Notification>,
    /// Notifications dropped because the queue was full.
    pub dropped: u64,
    wake: Arc<tokio::sync::Notify>,
}

#[derive(Default)]
pub struct Broker {
    subs: Mutex<HashMap<String, Subscription>>,
    /// The last notification per property (topic and source).
    properties: Mutex<Vec<Notification>>,
}

#[derive(Debug, PartialEq)]
pub enum BrokerError {
    TooMany,
    Unknown,
}

fn push(sub: &mut Subscription, n: Notification) {
    if sub.queue.len() >= MAX_QUEUED {
        sub.queue.pop_front();
        sub.dropped += 1;
    }
    sub.queue.push_back(n);
    sub.wake.notify_one();
}

impl Broker {
    fn sweep(subs: &mut HashMap<String, Subscription>, now: chrono::DateTime<chrono::Utc>) {
        subs.retain(|_, s| s.termination > now);
    }

    fn initialized(
        &self,
        filter: &Filter,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<Notification> {
        self.properties
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|n| filter.matches(n.topic.path))
            .map(|n| Notification {
                operation: "Initialized",
                utc: now,
                ..n.clone()
            })
            .collect()
    }

    /// A new subscription with the current value of every property its filter matches.
    pub fn create(
        &self,
        filter: Filter,
        termination: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<String, BrokerError> {
        let initial = self.initialized(&filter, now);
        let mut subs = self.subs.lock().unwrap_or_else(|e| e.into_inner());
        Self::sweep(&mut subs, now);
        if subs.len() >= MAX_SUBSCRIPTIONS {
            return Err(BrokerError::TooMany);
        }
        let id = format!("{:032x}", rand::random::<u128>());
        let mut sub = Subscription {
            filter,
            termination,
            queue: VecDeque::new(),
            dropped: 0,
            wake: Arc::new(tokio::sync::Notify::new()),
        };
        for n in initial {
            push(&mut sub, n);
        }
        subs.insert(id.clone(), sub);
        Ok(id)
    }

    pub fn remove(&self, id: &str) -> bool {
        let removed = self
            .subs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        if let Some(s) = &removed {
            s.wake.notify_waiters();
        }
        removed.is_some()
    }

    pub fn termination(
        &self,
        id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<chrono::DateTime<chrono::Utc>, BrokerError> {
        let mut subs = self.subs.lock().unwrap_or_else(|e| e.into_inner());
        Self::sweep(&mut subs, now);
        subs.get(id)
            .map(|s| s.termination)
            .ok_or(BrokerError::Unknown)
    }

    pub fn renew(
        &self,
        id: &str,
        termination: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), BrokerError> {
        let mut subs = self.subs.lock().unwrap_or_else(|e| e.into_inner());
        Self::sweep(&mut subs, now);
        let s = subs.get_mut(id).ok_or(BrokerError::Unknown)?;
        s.termination = termination;
        Ok(())
    }

    pub fn synchronization_point(
        &self,
        id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), BrokerError> {
        let filter = self.termination(id, now).and_then(|_| {
            self.subs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(id)
                .map(|s| s.filter.clone())
                .ok_or(BrokerError::Unknown)
        })?;
        let initial = self.initialized(&filter, now);
        let mut subs = self.subs.lock().unwrap_or_else(|e| e.into_inner());
        let s = subs.get_mut(id).ok_or(BrokerError::Unknown)?;
        for n in initial {
            push(s, n);
        }
        Ok(())
    }

    /// Put a notification on every live subscription whose filter matches; returns how many.
    pub fn publish(&self, n: Notification, now: chrono::DateTime<chrono::Utc>) -> usize {
        {
            let mut props = self.properties.lock().unwrap_or_else(|e| e.into_inner());
            let key = n.property_key();
            props.retain(|p| p.property_key() != key);
            if n.operation != "Deleted" {
                if props.len() >= MAX_PROPERTIES {
                    props.remove(0);
                }
                props.push(n.clone());
            }
        }
        let mut subs = self.subs.lock().unwrap_or_else(|e| e.into_inner());
        Self::sweep(&mut subs, now);
        let mut delivered = 0;
        for s in subs.values_mut() {
            if s.filter.matches(n.topic.path) {
                push(s, n.clone());
                delivered += 1;
            }
        }
        delivered
    }

    fn take(
        &self,
        id: &str,
        limit: usize,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(Vec<Notification>, Arc<tokio::sync::Notify>), BrokerError> {
        let mut subs = self.subs.lock().unwrap_or_else(|e| e.into_inner());
        Self::sweep(&mut subs, now);
        let s = subs.get_mut(id).ok_or(BrokerError::Unknown)?;
        let n = limit.min(s.queue.len());
        Ok((s.queue.drain(..n).collect(), s.wake.clone()))
    }

    /// PullMessages: what is waiting, up to `limit`; if nothing is, wait up to `timeout` for
    /// something. An unknown or expired subscription is an error; one removed while waiting
    /// answers what it had (nothing).
    pub async fn pull(
        &self,
        id: &str,
        timeout: Duration,
        limit: usize,
        now: impl Fn() -> chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<Notification>, BrokerError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let (got, wake) = self.take(id, limit, now())?;
            if !got.is_empty() {
                return Ok(got);
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return Ok(got);
            }
            if tokio::time::timeout(left, wake.notified()).await.is_err() {
                // Timed out: one last look, then answer empty.
                return self
                    .take(id, limit, now())
                    .map(|(g, _)| g)
                    .or(Ok(Vec::new()));
            }
            if self.termination(id, now()).is_err() {
                return Ok(Vec::new());
            }
        }
    }

    pub fn count(&self) -> usize {
        self.subs.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

// ---- the wire -------------------------------------------------------------------------------

/// GetEventProperties: the fixed topic set and the dialects accepted.
pub fn event_properties() -> String {
    // The topic tree, written iteratively from the sorted paths.
    let mut paths: Vec<&TopicDef> = TOPICS.iter().collect();
    paths.sort_by_key(|t| t.path);
    let mut set = String::new();
    let mut open: Vec<&str> = Vec::new();
    for t in paths {
        let segs: Vec<&str> = t.path.split('/').collect();
        let common = open.iter().zip(&segs).take_while(|(a, b)| a == b).count();
        while open.len() > common {
            let s = open.pop().unwrap_or_default();
            set.push_str(&if open.is_empty() {
                format!("</tns1:{s}>")
            } else {
                format!("</{s}>")
            });
        }
        for (i, s) in segs.iter().enumerate().skip(common) {
            let leaf = i + 1 == segs.len();
            let tag = if i == 0 {
                format!("tns1:{s}")
            } else {
                s.to_string()
            };
            if leaf {
                let items = |list: &[(&str, &str)]| {
                    list.iter()
                        .map(|(n, k)| {
                            format!("<tt:SimpleItemDescription Name=\"{n}\" Type=\"{k}\"/>")
                        })
                        .collect::<String>()
                };
                set.push_str(&format!(
                    "<{tag} wstop:topic=\"true\"><tt:MessageDescription IsProperty=\"true\"><tt:Source>{}</tt:Source><tt:Data>{}</tt:Data></tt:MessageDescription></{tag}>",
                    items(t.source),
                    items(t.data)
                ));
            } else {
                set.push_str(&format!("<{tag}>"));
                open.push(s);
            }
        }
    }
    while let Some(s) = open.pop() {
        set.push_str(&if open.is_empty() {
            format!("</tns1:{s}>")
        } else {
            format!("</{s}>")
        });
    }
    format!(
        "<tev:GetEventPropertiesResponse><tev:TopicNamespaceLocation>http://www.onvif.org/onvif/ver10/topics/topicns.xml</tev:TopicNamespaceLocation><wsnt:FixedTopicSet>true</wsnt:FixedTopicSet><wstop:TopicSet>{set}</wstop:TopicSet><wsnt:TopicExpressionDialect>{WSN_CONCRETE}</wsnt:TopicExpressionDialect><wsnt:TopicExpressionDialect>{CONCRETE_SET}</wsnt:TopicExpressionDialect><tev:MessageContentFilterDialect>http://www.onvif.org/ver10/tev/messageContentFilter/ItemFilter</tev:MessageContentFilterDialect><tev:MessageContentSchemaLocation>http://www.onvif.org/onvif/ver10/schema/onvif.xsd</tev:MessageContentSchemaLocation></tev:GetEventPropertiesResponse>"
    )
}

pub fn create_response(
    address: &str,
    now: chrono::DateTime<chrono::Utc>,
    termination: chrono::DateTime<chrono::Utc>,
) -> String {
    format!(
        "<tev:CreatePullPointSubscriptionResponse><tev:SubscriptionReference><wsa:Address>{}</wsa:Address></tev:SubscriptionReference><wsnt:CurrentTime>{}</wsnt:CurrentTime><wsnt:TerminationTime>{}</wsnt:TerminationTime></tev:CreatePullPointSubscriptionResponse>",
        esc(address),
        wire::format_datetime(now),
        wire::format_datetime(termination)
    )
}

fn simple_items(items: &[(String, String)]) -> String {
    items
        .iter()
        .map(|(n, v)| format!("<tt:SimpleItem Name=\"{}\" Value=\"{}\"/>", esc(n), esc(v)))
        .collect()
}

pub fn notification_xml(n: &Notification, subscription: &str, producer: &str) -> String {
    format!(
        "<wsnt:NotificationMessage><wsnt:SubscriptionReference><wsa:Address>{}</wsa:Address></wsnt:SubscriptionReference><wsnt:Topic Dialect=\"{CONCRETE_SET}\">tns1:{}</wsnt:Topic><wsnt:ProducerReference><wsa:Address>{}</wsa:Address></wsnt:ProducerReference><wsnt:Message><tt:Message UtcTime=\"{}\" PropertyOperation=\"{}\"><tt:Source>{}</tt:Source><tt:Data>{}</tt:Data></tt:Message></wsnt:Message></wsnt:NotificationMessage>",
        esc(subscription),
        n.topic.path,
        esc(producer),
        wire::format_datetime(n.utc),
        n.operation,
        simple_items(&n.source),
        simple_items(&n.data)
    )
}

pub fn pull_response(
    now: chrono::DateTime<chrono::Utc>,
    termination: chrono::DateTime<chrono::Utc>,
    messages: &[Notification],
    subscription: &str,
    producer: &str,
) -> String {
    let mut out = format!(
        "<tev:PullMessagesResponse><tev:CurrentTime>{}</tev:CurrentTime><tev:TerminationTime>{}</tev:TerminationTime>",
        wire::format_datetime(now),
        wire::format_datetime(termination)
    );
    for m in messages {
        out.push_str(&notification_xml(m, subscription, producer));
    }
    out.push_str("</tev:PullMessagesResponse>");
    out
}

pub fn renew_response(
    termination: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    format!(
        "<wsnt:RenewResponse><wsnt:TerminationTime>{}</wsnt:TerminationTime><wsnt:CurrentTime>{}</wsnt:CurrentTime></wsnt:RenewResponse>",
        wire::format_datetime(termination),
        wire::format_datetime(now)
    )
}

pub fn service_capabilities() -> String {
    format!(
        "<tev:GetServiceCapabilitiesResponse><tev:Capabilities WSSubscriptionPolicySupport=\"false\" WSPullPointSupport=\"true\" WSPausableSubscriptionManagerInterfaceSupport=\"false\" MaxNotificationProducers=\"0\" MaxPullPoints=\"{MAX_SUBSCRIPTIONS}\" PersistentNotificationStorage=\"false\"/></tev:GetServiceCapabilitiesResponse>"
    )
}
