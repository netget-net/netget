//! Basic Notification (WS-BaseNotification push) for the ONVIF device: a client Subscribes
//! with a consumer EndpointReference, and the device POSTs `wsnt:Notify` to that address.
//!
//! This is the one place the device opens connections to an address a client picked, so it is
//! bounded before anything is sent:
//!
//! - **The consumer must be allowed.** Its address is an `http://` URL whose host is an IP
//!   literal (no name is ever resolved, so nothing can be rebound), without userinfo, at most
//!   `MAX_CONSUMER_URL` bytes. Its IP must fall in the startup parameter `notify_consumers` — a
//!   list of addresses or CIDR blocks, and the word `subscriber` for the subscribing client's
//!   own address — which defaults to loopback only (`DEFAULT_CONSUMERS`). Unspecified,
//!   multicast and broadcast addresses are refused whatever the list says. A refused consumer
//!   is refused before the model is asked.
//! - **https is refused** unless `notify_allow_https` is set.
//! - **Subscriptions are bounded** at `MAX_PUSH_SUBSCRIPTIONS`, apart from pull points, and live
//!   only until their termination time (the same `events::MAX_TERMINATION` cut as pull points).
//! - **Each subscription queues at most `MAX_PUSH_QUEUED`** notifications; past it the oldest is
//!   dropped and the drop is logged (`decision=notify_queue_overflow`).
//! - **One delivery at a time per subscription**, by one task, so at most
//!   `MAX_PUSH_SUBSCRIPTIONS` requests are ever in flight. A Notify carries at most
//!   `MAX_NOTIFY_BATCH` messages.
//! - **Each attempt is bounded** by `notify_timeout_secs` (connect, send and the answer
//!   together), and a batch is tried at most `1 + notify_retries` times, `RETRY_BACKOFF` apart
//!   (growing linearly). Then it is dropped, logged `decision=notify_dropped` and recorded in the
//!   access log as `onvif_notify_dropped`. Delivered batches are recorded as
//!   `onvif_notify_delivered`.
//! - **No redirect is followed** (a 3xx is a failed attempt), no proxy is used (a proxy would
//!   make the allowlist meaningless), and at most `MAX_ANSWER` bytes of the consumer's answer
//!   are read.
use super::events::{self, Notification};
use super::wire;
use super::Device;
use crate::logging::emit::Log;
use crate::protocol::SpawnContext;
use crate::state::AccessLogOwner;
use anyhow::{bail, ensure, Context, Result};
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// Live push subscriptions at most (pull points are bounded on their own).
pub const MAX_PUSH_SUBSCRIPTIONS: usize = 8;
/// Notifications waiting for delivery on one push subscription at most; past it the oldest is
/// dropped.
pub const MAX_PUSH_QUEUED: usize = 64;
/// NotificationMessages in one Notify at most.
pub const MAX_NOTIFY_BATCH: usize = 16;
/// One delivery attempt at most, by default (startup parameter `notify_timeout_secs`).
pub const NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_NOTIFY_TIMEOUT_SECS: u64 = 30;
/// Attempts after the first, by default (startup parameter `notify_retries`).
pub const NOTIFY_RETRIES: u64 = 2;
pub const MAX_NOTIFY_RETRIES: u64 = 5;
/// The wait before the first retry; the n-th retry waits n times this.
pub const RETRY_BACKOFF: Duration = Duration::from_millis(250);
/// A consumer address at most, in bytes.
pub const MAX_CONSUMER_URL: usize = 512;
/// Entries in `notify_consumers` at most.
pub const MAX_ALLOWLIST: usize = 32;
/// Bytes of a consumer's answer read at most; the rest is not read.
pub const MAX_ANSWER: usize = 64 * 1024;
/// Who may be a consumer when the operator says nothing: this host's loopback.
pub const DEFAULT_CONSUMERS: &[&str] = &["127.0.0.0/8", "::1/128"];
/// Whether https consumers are allowed when the operator says nothing (startup parameter
/// `notify_allow_https`).
pub const ALLOW_HTTPS: bool = false;
/// The allowlist entry meaning "the subscribing client's own address".
pub const SUBSCRIBER: &str = "subscriber";
/// The WS-Addressing Action of a Notify.
pub const NOTIFY_ACTION: &str = "http://docs.oasis-open.org/wsn/bw-2/NotificationConsumer/Notify";

/// The consumers a device will deliver to: networks, and whether the subscriber itself is one.
#[derive(Debug, Clone, PartialEq)]
pub struct Allowlist {
    pub nets: Vec<(IpAddr, u8)>,
    pub subscriber: bool,
}

/// An address with IPv4-mapped IPv6 read as the IPv4 it is, so `::ffff:10.0.0.1` is judged as
/// `10.0.0.1`.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn in_net(ip: IpAddr, (net, bits): (IpAddr, u8)) -> bool {
    match (canonical(ip), net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// Never a consumer, whatever the allowlist says.
pub fn forbidden(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_multicast(),
    }
}

impl Allowlist {
    /// `notify_consumers`: addresses (`192.0.2.7`), CIDR blocks (`10.0.0.0/8`, `fd00::/8`) and
    /// `subscriber`.
    pub fn parse(items: &[String]) -> Result<Allowlist> {
        ensure!(
            items.len() <= MAX_ALLOWLIST,
            "notify_consumers holds at most {MAX_ALLOWLIST} entries"
        );
        let mut out = Allowlist {
            nets: Vec::new(),
            subscriber: false,
        };
        for item in items {
            let item = item.trim();
            if item == SUBSCRIBER {
                out.subscriber = true;
                continue;
            }
            ensure!(
                !item.is_empty() && item.len() <= 64,
                "a notify_consumers entry is an address, a CIDR block or {SUBSCRIBER}"
            );
            let (addr, bits) = match item.split_once('/') {
                Some((a, b)) => (a, Some(b)),
                None => (item, None),
            };
            let ip: IpAddr = addr
                .parse()
                .with_context(|| format!("notify_consumers entry {item:?} is not an address"))?;
            let ip = canonical(ip);
            let max = if ip.is_ipv4() { 32 } else { 128 };
            let bits = match bits {
                None => max,
                Some(b) => b
                    .parse::<u8>()
                    .ok()
                    .filter(|b| *b <= max)
                    .with_context(|| {
                        format!("notify_consumers entry {item:?}: bad prefix length")
                    })?,
            };
            out.nets.push((ip, bits));
        }
        Ok(out)
    }

    pub fn default_list() -> Allowlist {
        let items: Vec<String> = DEFAULT_CONSUMERS.iter().map(|s| s.to_string()).collect();
        Allowlist::parse(&items).unwrap_or(Allowlist {
            nets: Vec::new(),
            subscriber: false,
        })
    }

    /// Whether the device may deliver to `ip` for a client at `subscriber`.
    pub fn allows(&self, ip: IpAddr, subscriber: IpAddr) -> bool {
        if forbidden(ip) {
            return false;
        }
        (self.subscriber && canonical(ip) == canonical(subscriber))
            || self.nets.iter().any(|n| in_net(ip, *n))
    }
}

/// A consumer the device will POST to.
#[derive(Debug, Clone, PartialEq)]
pub struct Consumer {
    /// The address exactly as the subscriber gave it (what Notify's wsa:To carries).
    pub url: String,
    /// Where it connects: the URL's IP literal and port.
    pub addr: SocketAddr,
    pub https: bool,
}

/// Why a consumer address was refused.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConsumerError {
    Malformed,
    NotHttp,
    HttpsRefused,
    /// A host name: the device resolves no names for a client.
    NotAnAddress,
    UserInfo,
    NotAllowed,
}

impl ConsumerError {
    pub fn reason(self) -> &'static str {
        match self {
            ConsumerError::Malformed => "malformed_address",
            ConsumerError::NotHttp => "not_http",
            ConsumerError::HttpsRefused => "https_refused",
            ConsumerError::NotAnAddress => "host_not_an_ip_address",
            ConsumerError::UserInfo => "userinfo",
            ConsumerError::NotAllowed => "not_allowlisted",
        }
    }
}

/// A ConsumerReference's Address, checked for form (the allowlist is checked by the caller,
/// which knows the subscriber).
pub fn parse_consumer(text: &str, allow_https: bool) -> Result<Consumer, ConsumerError> {
    let text = text.trim();
    if text.is_empty()
        || text.len() > MAX_CONSUMER_URL
        || text.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(ConsumerError::Malformed);
    }
    let url = url::Url::parse(text).map_err(|_| ConsumerError::Malformed)?;
    let https = match url.scheme() {
        "http" => false,
        "https" if allow_https => true,
        "https" => return Err(ConsumerError::HttpsRefused),
        _ => return Err(ConsumerError::NotHttp),
    };
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConsumerError::UserInfo);
    }
    let ip = match url.host() {
        Some(url::Host::Ipv4(a)) => IpAddr::V4(a),
        Some(url::Host::Ipv6(a)) => IpAddr::V6(a),
        Some(url::Host::Domain(_)) => return Err(ConsumerError::NotAnAddress),
        None => return Err(ConsumerError::Malformed),
    };
    let port = url
        .port_or_known_default()
        .ok_or(ConsumerError::Malformed)?;
    Ok(Consumer {
        url: text.to_string(),
        addr: SocketAddr::new(ip, port),
        https,
    })
}

/// How the device delivers: the allowlist and the per-attempt bounds, from the startup
/// parameters, and the one HTTP client every delivery uses.
pub struct Config {
    pub allowlist: Allowlist,
    pub allow_https: bool,
    pub timeout: Duration,
    pub retries: u64,
    client: reqwest::Client,
}

impl Config {
    pub fn new(
        allowlist: Allowlist,
        allow_https: bool,
        timeout: Duration,
        retries: u64,
    ) -> Result<Config> {
        let client = reqwest::Client::builder()
            // A proxy would carry the request somewhere the allowlist never saw.
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(1)
            .user_agent("netget-onvif-device")
            .build()
            .context("building the Notify client")?;
        Ok(Config {
            allowlist,
            allow_https,
            timeout,
            retries,
            client,
        })
    }
}

/// The Notify envelope for a batch.
pub fn notify_envelope(
    consumer: &str,
    messages: &[Notification],
    subscription: &str,
    producer: &str,
) -> String {
    let mut body = String::from("<wsnt:Notify>");
    for m in messages {
        body.push_str(&events::notification_xml(m, subscription, producer));
    }
    body.push_str("</wsnt:Notify>");
    wire::request_envelope_with(
        None,
        Some(&wire::addressing(consumer, NOTIFY_ACTION)),
        &body,
    )
}

/// One POST of a Notify; Ok when the consumer answered 2xx inside the timeout, which covers the
/// whole attempt (connecting, sending and reading the bounded answer).
async fn attempt(config: &Config, consumer: &Consumer, envelope: &str) -> Result<u16> {
    let send = async {
        let mut response = config
            .client
            .post(&consumer.url)
            .header("Content-Type", "application/soap+xml; charset=utf-8")
            .body(envelope.to_string())
            .send()
            .await
            .context("the consumer could not be reached")?;
        let status = response.status();
        // Read the answer, bounded, so the connection can be reused; it is not interpreted.
        let mut read = 0usize;
        while read < MAX_ANSWER {
            match response.chunk().await {
                Ok(Some(c)) => read += c.len(),
                _ => break,
            }
        }
        if status.is_redirection() {
            bail!("HTTP {} (redirects are not followed)", status.as_u16());
        }
        ensure!(status.is_success(), "HTTP {}", status.as_u16());
        Ok(status.as_u16())
    };
    match tokio::time::timeout(config.timeout, send).await {
        Ok(r) => r,
        Err(_) => bail!("no answer within {} s", config.timeout.as_secs()),
    }
}

/// The task that delivers one push subscription's notifications until it ends (Unsubscribe,
/// expiry, or the server stopping). Registered with the server, so stopping it stops this.
pub async fn deliver(ctx: SpawnContext, device: Arc<Device>, id: String, address: String) {
    let log = Log::new(Some(&ctx.status_tx));
    let producer = address
        .split(wire::SUBSCRIPTION_PREFIX)
        .next()
        .map(|base| format!("{base}{}", wire::EVENTS_PATH))
        .unwrap_or_default();
    let Some(consumer) = device.events.consumer(&id, device.now()) else {
        return;
    };
    let config = &device.notify;
    loop {
        let batch = match device.events.next_push(&id, MAX_NOTIFY_BATCH, device.now()) {
            Ok(b) => b,
            Err(_) => {
                log.info(format!(
                    "ONVIF push subscription {id} to {} ended",
                    consumer.url
                ));
                return;
            }
        };
        if batch.dropped > 0 {
            log.warn(format!(
                "ONVIF push subscription {id}: {} notification(s) dropped, more than {MAX_PUSH_QUEUED} waiting decision=notify_queue_overflow",
                batch.dropped
            ));
        }
        if batch.notifications.is_empty() {
            // Wait for a notification, or for the termination time to pass (then the next look
            // finds the subscription gone).
            let left = (batch.termination - device.now())
                .to_std()
                .unwrap_or(Duration::ZERO)
                + Duration::from_millis(50);
            let _ = tokio::time::timeout(left, batch.wake.notified()).await;
            continue;
        }
        let envelope = notify_envelope(&consumer.url, &batch.notifications, &address, &producer);
        let topics: Vec<String> = batch
            .notifications
            .iter()
            .map(|n| format!("tns1:{}", n.topic.path))
            .collect();
        let mut outcome = Err(anyhow::anyhow!("not attempted"));
        let mut attempts = 0;
        for n in 0..=config.retries {
            if n > 0 {
                if !device.events.exists(&id, device.now()) {
                    break;
                }
                tokio::time::sleep(RETRY_BACKOFF * n as u32).await;
            }
            attempts += 1;
            outcome = attempt(config, &consumer, &envelope).await;
            match &outcome {
                Ok(_) => break,
                Err(e) => log.warn(format!(
                    "ONVIF push subscription {id}: Notify to {} attempt {} of {} failed: {e:#}",
                    consumer.url,
                    n + 1,
                    config.retries + 1
                )),
            }
        }
        let (kind, extra) = match &outcome {
            Ok(status) => {
                log.info(format!(
                    "ONVIF push subscription {id}: Notify of {} message(s) delivered to {} decision=notify_delivered",
                    batch.notifications.len(),
                    consumer.url
                ));
                (
                    "onvif_notify_delivered",
                    json!({"status": status, "attempts": attempts}),
                )
            }
            Err(e) => {
                log.error(format!(
                    "ONVIF push subscription {id}: Notify of {} message(s) to {} dropped after {attempts} attempt(s): {e:#} decision=notify_dropped",
                    batch.notifications.len(),
                    consumer.url,
                ));
                (
                    "onvif_notify_dropped",
                    json!({"error": format!("{e:#}"), "attempts": attempts}),
                )
            }
        };
        let mut data = json!({"subscription": id, "consumer": consumer.url, "topics": topics,
                              "messages": batch.notifications.len()});
        if let (Some(d), Some(e)) = (data.as_object_mut(), extra.as_object()) {
            d.extend(e.clone());
        }
        ctx.state
            .record_access_log(
                AccessLogOwner::Server(ctx.server_id.as_u32()),
                "ONVIF",
                None,
                kind,
                data,
                vec![],
            )
            .await;
    }
}
