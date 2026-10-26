//! The ONVIF client's Basic Notification consumer: the HTTP endpoint a device POSTs `wsnt:Notify`
//! to once `onvif_subscribe` named it in a Subscribe.
//!
//! It is started by the first `onvif_subscribe` and lives as long as the client (its tasks are
//! registered with it). It binds `notify_bind` — loopback, `DEFAULT_BIND`, unless the operator
//! names another local address — on a port the OS picks, and accepts exactly one path, a random
//! 128-bit one, so a request that does not know the address is answered 404 and nothing else.
//! Bounded like a server: at most `MAX_CONNECTIONS` at once, headers within `HEADER_TIMEOUT`,
//! a body of at most `wire::MAX_REQUEST`, read into the same bounded tree as every other ONVIF
//! envelope, and at most `wire::MAX_ITEMS` notifications taken from one Notify. Each becomes an
//! `onvif_notification` event; the model's queue is bounded, and a notification that does not
//! fit is dropped and logged.
use super::actions;
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter};
use crate::server::onvif::wire::{self, Element};
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::Incoming, server::conn::http1, service::service_fn, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::{json, Map, Value};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::sync::mpsc;

/// Where the consumer listens unless the operator says otherwise (startup parameter
/// `notify_bind`).
pub const DEFAULT_BIND: &str = "127.0.0.1";
/// Device connections to the consumer at once, at most.
pub const MAX_CONNECTIONS: usize = 8;
/// A Notify's headers must arrive within this.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// A running consumer: the address subscriptions name.
#[derive(Debug, Clone)]
pub struct Consumer {
    pub url: String,
    pub local: SocketAddr,
}

/// The `notify_bind` startup parameter: an IP address of this host.
pub fn bind_address(text: Option<&str>) -> Result<IpAddr> {
    text.unwrap_or(DEFAULT_BIND)
        .trim()
        .parse::<IpAddr>()
        .context("notify_bind is an IP address of this host, such as 127.0.0.1")
}

fn items(e: Option<&Element>) -> Value {
    Value::Object(
        e.map(|e| {
            e.children_named("SimpleItem")
                .take(16)
                .filter_map(|i| Some((i.attr("Name")?.to_string(), json!(i.attr("Value")?))))
                .collect::<Map<_, _>>()
        })
        .unwrap_or_default(),
    )
}

/// The notifications in a Notify body, as the model reads them.
pub fn notifications(notify: &Element) -> Vec<Value> {
    notify
        .children_named("NotificationMessage")
        .take(wire::MAX_ITEMS)
        .map(|n| {
            let m = n.child("Message").and_then(|m| m.child("Message"));
            json!({
                "topic": n.text_of("Topic"),
                "subscription": n.child("SubscriptionReference").and_then(|s| s.text_of("Address")),
                "producer": n.child("ProducerReference").and_then(|s| s.text_of("Address")),
                "utc_time": m.and_then(|m| m.attr("UtcTime")),
                "property_operation": m.and_then(|m| m.attr("PropertyOperation")),
                "source": items(m.and_then(|m| m.child("Source"))),
                "data": items(m.and_then(|m| m.child("Data"))),
            })
        })
        .collect()
}

fn bare(code: StatusCode) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::new()));
    *r.status_mut() = code;
    r
}

async fn handle(
    ctx: &ConnectContext,
    path: &str,
    events: &mpsc::Sender<(Event, u32)>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let log = Log::new(Some(&ctx.status_tx));
    if req.uri().path() != path {
        return bare(StatusCode::NOT_FOUND);
    }
    if req.method() != hyper::Method::POST {
        return bare(StatusCode::METHOD_NOT_ALLOWED);
    }
    let body = match Limited::new(req.into_body(), wire::MAX_REQUEST)
        .collect()
        .await
    {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            log.warn(format!(
                "ONVIF client {}: a Notify from {peer} larger than {} bytes refused",
                ctx.client_id,
                wire::MAX_REQUEST
            ));
            return bare(StatusCode::PAYLOAD_TOO_LARGE);
        }
    };
    let request = match wire::parse_request(&body) {
        Ok(r) if r.ns == wire::WSNT && r.operation == "Notify" => r,
        Ok(r) => {
            log.warn(format!(
                "ONVIF client {}: {peer} sent {} to the notification consumer, not Notify",
                ctx.client_id, r.operation
            ));
            return bare(StatusCode::BAD_REQUEST);
        }
        Err(e) => {
            log.warn(format!(
                "ONVIF client {}: an unreadable Notify from {peer}: {e:#}",
                ctx.client_id
            ));
            return bare(StatusCode::BAD_REQUEST);
        }
    };
    let list = notifications(&request.body);
    log.info(format!(
        "ONVIF client {} received a Notify of {} notification(s) from {peer}",
        ctx.client_id,
        list.len()
    ));
    // Each one is recorded in the access log where the model is asked about it.
    for n in list {
        if events
            .try_send((Event::new(&actions::NOTIFICATION_EVENT, n), 0))
            .is_err()
        {
            log.warn(format!(
                "ONVIF client {} dropped a notification: the model is {} events behind decision=turn_queue_full",
                ctx.client_id,
                super::TURN_QUEUE
            ));
        }
    }
    bare(StatusCode::OK)
}

/// Bind the consumer and start serving it; its tasks belong to the client.
pub async fn start(
    ctx: &ConnectContext,
    bind: IpAddr,
    events: mpsc::Sender<(Event, u32)>,
) -> Result<Consumer> {
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(bind, 0))
        .await
        .with_context(|| format!("binding the notification consumer on {bind}"))?;
    let local = listener.local_addr()?;
    let path = format!("/netget/onvif/notify/{:032x}", rand::random::<u128>());
    let url = format!("http://{local}{path}");
    Log::new(Some(&ctx.status_tx)).info(format!(
        "ONVIF client {} receives notifications at {url}",
        ctx.client_id
    ));
    let accept_ctx = ctx.clone();
    let accept = tokio::spawn(async move {
        let limiter = ConnectionLimiter::new(MAX_CONNECTIONS);
        loop {
            let Ok((stream, peer, permit)) = accept_bounded(
                &listener,
                &limiter,
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "ONVIF notification consumer",
                Some(&accept_ctx.status_tx),
            )
            .await
            else {
                break;
            };
            let conn_ctx = accept_ctx.clone();
            let (path, events) = (path.clone(), events.clone());
            accept_ctx
                .state
                .spawn_client_task(accept_ctx.client_id, async move {
                    let _permit = permit;
                    let service = service_fn(move |req| {
                        let (ctx, path, events) = (conn_ctx.clone(), path.clone(), events.clone());
                        async move { Ok::<_, Infallible>(handle(&ctx, &path, &events, peer, req).await) }
                    });
                    let _ = http1::Builder::new()
                        .timer(TokioTimer::new())
                        // A device may shut its side down as soon as the Notify is written
                        // (onvif_simple_server's daemon does); half-close keeps that EOF from
                        // ending the connection before the request is answered.
                        .half_close(true)
                        .header_read_timeout(HEADER_TIMEOUT)
                        .max_buf_size(64 * 1024)
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                })
                .await;
        }
    });
    ctx.state.register_client_task(ctx.client_id, accept).await;
    Ok(Consumer { url, local })
}
