//! NIS (YP) server — ypserv, ONC RPC program 100004 version 2 — on TCP and UDP at one port,
//! optionally registered with a portmapper. Rust decodes every call, answers the RPC-level
//! errors, NULL and CLEAR, walks maps for FIRST/NEXT and writes the `ypresp_all` stream; the
//! model answers which domains are served and what every map holds, per request.
pub mod actions;
pub mod wire;

use crate::llm::action_helper::call_llm;
use crate::llm::actions::protocol_trait::ActionResult;
use crate::logging::emit::Log;
use crate::protocol::{Event, EventType, SpawnContext};
use crate::server::sunrpc::wire::{self as rpc, Accepted};
use crate::server::{
    accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS},
    connection::ConnectionId,
};
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use wire::{proc_, Request, Stat};

/// A TCP connection that sends no complete call for this long is closed.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// UDP calls answered at once; past it, datagrams wait in the socket buffer.
pub const MAX_UDP_IN_FLIGHT: usize = 64;
/// How long registering with (or removing from) the portmapper may take.
pub const PORTMAPPER_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn spawn(ctx: SpawnContext) -> Result<SocketAddr> {
    let portmapper = ctx
        .startup_params
        .as_ref()
        .map(|p| p.get_optional_string("portmapper"))
        .transpose()?
        .flatten();
    let listener = tokio::net::TcpListener::bind(ctx.legacy_listen_addr()).await?;
    let local = listener.local_addr()?;
    // UDP on the same port as TCP, as ypserv does, so one registration names both.
    let udp = Arc::new(UdpSocket::bind(local).await?);
    let registration = match portmapper {
        Some(pm) => Some(
            Registration::register(&pm, local.port())
                .await
                .with_context(|| format!("registering ypserv with the portmapper at {pm}"))?,
        ),
        None => None,
    };
    Log::new(Some(&ctx.status_tx)).info(format!(
        "NIS ypserv (program 100004 v2) listening on {local} tcp and udp{}",
        registration
            .as_ref()
            .map(|r| format!(", registered with the portmapper at {}", r.portmapper))
            .unwrap_or_default()
    ));
    let server_id = ctx.server_id;
    let state = ctx.state.clone();

    let udp_ctx = ctx.clone();
    let udp_task = tokio::spawn(async move {
        let permits = Arc::new(tokio::sync::Semaphore::new(MAX_UDP_IN_FLIGHT));
        let mut buf = vec![0u8; 65_536];
        loop {
            let Ok((n, peer)) = udp.recv_from(&mut buf).await else {
                break;
            };
            if n > wire::MAX_CALL {
                continue;
            }
            let Ok(permit) = permits.clone().acquire_owned().await else {
                break;
            };
            let msg = buf[..n].to_vec();
            let ctx = udp_ctx.clone();
            let udp = udp.clone();
            udp_ctx
                .state
                .spawn_server_task(server_id, async move {
                    let _permit = permit;
                    if let Some(reply) = handle(&ctx, None, &msg, "udp").await {
                        let _ = udp.send_to(&reply, peer).await;
                    }
                })
                .await;
        }
    });
    state.register_server_task(server_id, udp_task).await;

    let accept = tokio::spawn(async move {
        // Dropped when the server stops (this task is aborted): the registration goes too.
        let _registration = registration;
        let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
        loop {
            let (stream, peer, permit) =
                match accept_bounded(&listener, &limiter, b"", "NIS", Some(&ctx.status_tx)).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
            let child = ctx.clone();
            ctx.state
                .spawn_server_task(server_id, async move {
                    let _permit = permit;
                    connection(child, stream, peer, local).await;
                })
                .await;
        }
    });
    state.register_server_task(server_id, accept).await;
    Ok(local)
}

/// ypserv's entry in a portmapper, removed on drop.
struct Registration {
    portmapper: String,
}

impl Registration {
    /// PMAP v2 SET for program 100004 v2 on tcp and udp at `port`. A portmapper that says
    /// no (another ypserv is registered, or it refuses non-local callers) fails the start.
    async fn register(portmapper: &str, port: u16) -> Result<Self> {
        let mut s = tokio::time::timeout(PORTMAPPER_TIMEOUT, TcpStream::connect(portmapper))
            .await
            .context("the portmapper did not accept a connection in time")??;
        for prot in [rpc::IPPROTO_TCP, rpc::IPPROTO_UDP] {
            let mut args = rpc::Writer::default();
            args.u32(wire::PROGRAM)
                .u32(wire::VERSION)
                .u32(prot)
                .u32(u32::from(port));
            let body = pmap_call(&mut s, 1, &args.0).await?;
            ensure!(
                rpc::Reader::new(&body).bool()?,
                "the portmapper refused to register program 100004 version 2 ({}) — is another \
                 ypserv registered? (rpcinfo -p shows it)",
                rpc::netid_of(prot).unwrap_or("?")
            );
        }
        Ok(Self {
            portmapper: portmapper.to_string(),
        })
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // The server is stopping and its runtime may be going with it: a short blocking
        // exchange on a thread of its own. PMAP v2 UNSET removes every transport.
        let pm = self.portmapper.clone();
        std::thread::spawn(move || {
            let _ = unset_blocking(&pm);
        });
    }
}

fn unset_blocking(portmapper: &str) -> Result<()> {
    use std::io::{Read, Write};
    let addr = std::net::ToSocketAddrs::to_socket_addrs(portmapper)?
        .next()
        .context("no address")?;
    let mut s = std::net::TcpStream::connect_timeout(&addr, PORTMAPPER_TIMEOUT)?;
    s.set_read_timeout(Some(PORTMAPPER_TIMEOUT))?;
    // rpcbind's v2 UNSET ignores the protocol and removes every transport; a portmapper that
    // reads it (NetGet's own does) is told about each one that was registered.
    for prot in [rpc::IPPROTO_TCP, rpc::IPPROTO_UDP] {
        let mut args = rpc::Writer::default();
        args.u32(wire::PROGRAM).u32(wire::VERSION).u32(prot).u32(0);
        s.write_all(&rpc::record(&rpc::call_message(
            rand::random(),
            2,
            2,
            &args.0,
        )))?;
        let mut h = [0u8; 4];
        s.read_exact(&mut h)?;
        let mut body = vec![0u8; (u32::from_be_bytes(h) & 0x7fff_ffff).min(1024) as usize];
        s.read_exact(&mut body)?;
    }
    Ok(())
}

/// One PMAP v2 call over `s`; its result body.
async fn pmap_call(s: &mut TcpStream, procedure: u32, args: &[u8]) -> Result<Vec<u8>> {
    let xid: u32 = rand::random();
    tokio::time::timeout(PORTMAPPER_TIMEOUT, async {
        s.write_all(&rpc::record(&rpc::call_message(xid, 2, procedure, args)))
            .await?;
        loop {
            let msg = rpc::read_record(s)
                .await?
                .context("the portmapper closed the connection")?;
            let (got, body) = rpc::parse_reply(&msg)?;
            if got == xid {
                return body.map_err(|why| anyhow::anyhow!("the portmapper answered {why}"));
            }
        }
    })
    .await
    .context("the portmapper did not answer in time")?
}

async fn connection(ctx: SpawnContext, stream: TcpStream, remote: SocketAddr, local: SocketAddr) {
    let id = ConnectionId::new(ctx.state.get_next_unified_id().await);
    let now = crate::utils::clock::Instant::now();
    ctx.state
        .add_connection_to_server(
            ctx.server_id,
            ConnectionState {
                id,
                remote_addr: remote,
                local_addr: local,
                bytes_sent: 0,
                bytes_received: 0,
                packets_sent: 0,
                packets_received: 0,
                last_activity: now,
                status: ConnectionStatus::Active,
                status_changed_at: now,
                protocol_info: ProtocolConnectionInfo::empty(),
            },
        )
        .await;
    let (mut r, mut w) = stream.into_split();
    let reason = loop {
        let read = rpc::read_record_bounded(&mut r, wire::MAX_CALL, wire::MAX_CALL_FRAGMENTS);
        let msg = match tokio::time::timeout(IDLE_TIMEOUT, read).await {
            Err(_) => break "idle".to_string(),
            Ok(Ok(None)) => break "closed by the peer".to_string(),
            Ok(Err(e)) => break format!("refused: {e:#}"),
            Ok(Ok(Some(m))) => m,
        };
        ctx.state
            .update_connection_stats(
                ctx.server_id,
                id,
                Some(msg.len() as u64),
                None,
                Some(1),
                None,
            )
            .await;
        if let Some(reply) = handle(&ctx, Some(id), &msg, "tcp").await {
            if w.write_all(&wire::record_fragments(&reply)).await.is_err() {
                break "write failed".into();
            }
            ctx.state
                .update_connection_stats(
                    ctx.server_id,
                    id,
                    None,
                    Some(reply.len() as u64),
                    None,
                    Some(1),
                )
                .await;
        }
    };
    let _ = w.shutdown().await;
    ctx.state
        .update_connection_status(ctx.server_id, id, ConnectionStatus::Closed)
        .await;
    Log::new(Some(&ctx.status_tx)).debug(format!("NIS connection {id} ended: {reason}"));
    let _ = ctx.status_tx.send("__UPDATE_UI__".into());
}

fn outcome(ctx: &SpawnContext, request: &Request, decision: &str) {
    let (domain, map) = match request {
        Request::Domain { domain, .. } | Request::Maplist { domain } => (domain.as_str(), ""),
        Request::Match { domain, map, .. }
        | Request::First { domain, map }
        | Request::Next { domain, map, .. }
        | Request::All { domain, map }
        | Request::Master { domain, map }
        | Request::Order { domain, map } => (domain.as_str(), map.as_str()),
        _ => ("", ""),
    };
    let line = format!(
        "NIS operation={} domain={domain} map={map} decision={decision}",
        request.name()
    );
    let log = Log::new(Some(&ctx.status_tx));
    if decision.starts_with("fail_closed") || decision == "model_silent" {
        log.error(line)
    } else {
        log.info(line)
    }
}

/// Ask the model; its one answer, or None when the request must fail closed.
async fn ask(
    ctx: &SpawnContext,
    conn: Option<ConnectionId>,
    event_type: &'static EventType,
    data: Value,
    request: &Request,
) -> Option<(String, Value)> {
    let event = Event::new(event_type, data);
    let result = match call_llm(
        &ctx.llm_client,
        &ctx.state,
        ctx.server_id,
        conn,
        &event,
        &actions::NisProtocol,
    )
    .await
    {
        Ok(r) if r.failures.is_empty() => r,
        Ok(_) => {
            outcome(ctx, request, "fail_closed_invalid_reply");
            return None;
        }
        Err(_) => {
            outcome(ctx, request, "fail_closed_llm_error");
            return None;
        }
    };
    let mut answers = Vec::new();
    let mut stack = result.protocol_results;
    while let Some(r) = stack.pop() {
        match r {
            ActionResult::Custom { name, data } if name.starts_with("nis_") => {
                answers.push((name, data))
            }
            ActionResult::Multiple(items) => stack.extend(items),
            _ => {}
        }
    }
    match answers.len() {
        1 => answers.pop(),
        0 => {
            outcome(ctx, request, "model_silent");
            None
        }
        _ => {
            outcome(ctx, request, "fail_closed_invalid_reply");
            None
        }
    }
}

/// The result body a procedure fails with, in its own result type.
fn failed(procedure: u32, stat: Stat) -> Option<Vec<u8>> {
    Some(match procedure {
        proc_::DOMAIN => wire::resp_bool(false),
        // DOMAIN_NONACK answers only "yes"; anything else is silence.
        proc_::DOMAIN_NONACK => return None,
        proc_::MATCH => wire::resp_val(stat, ""),
        proc_::FIRST | proc_::NEXT => wire::resp_key_val(stat, "", ""),
        proc_::ALL => wire::resp_all(Err(stat)),
        proc_::MASTER => wire::resp_master(stat, ""),
        proc_::ORDER => wire::resp_order(stat, 0),
        proc_::MAPLIST => wire::resp_maplist(stat, &[]),
        _ => Vec::new(),
    })
}

/// Answer one RPC message; None when there is nothing to answer (a reply, no xid, or a
/// DOMAIN_NONACK for a domain not served).
pub async fn handle(
    ctx: &SpawnContext,
    conn: Option<ConnectionId>,
    msg: &[u8],
    transport: &str,
) -> Option<Vec<u8>> {
    let call = match rpc::parse_call(msg) {
        Ok(Some(c)) => c,
        Ok(None) => return None,
        Err(_) => return rpc::xid_of(msg).map(|x| rpc::accepted_reply(x, &Accepted::GarbageArgs)),
    };
    if call.rpc_version != 2 {
        return Some(rpc::rpc_mismatch_reply(call.xid));
    }
    let result = if call.program != wire::PROGRAM {
        Accepted::ProgUnavail
    } else if call.version != wire::VERSION {
        Accepted::ProgMismatch(wire::VERSION, wire::VERSION)
    } else {
        match wire::parse_request(call.procedure, call.args) {
            Err(wire::Refusal::Garbage) => Accepted::GarbageArgs,
            Err(wire::Refusal::NoProc) => Accepted::ProcUnavail,
            Err(wire::Refusal::BadArgs) => {
                Accepted::Success(failed(call.procedure, Stat::BadArgs)?)
            }
            Ok(Request::Null | Request::Clear) => Accepted::Success(Vec::new()),
            // NetGet holds no maps to transfer and pushes none.
            Ok(Request::Xfr) => Accepted::ProcUnavail,
            Ok(request) => {
                let body = answer(ctx, conn, &request, transport).await;
                let body = match body {
                    Some(b) => b,
                    None => failed(call.procedure, Stat::YpErr)?,
                };
                // A reply too large for its transport is refused whole, never cut short.
                let limit = if transport == "udp" {
                    wire::MAX_UDP_REPLY
                } else {
                    wire::MAX_REPLY
                };
                if body.len() > limit {
                    outcome(ctx, &request, "fail_closed_reply_too_large");
                    Accepted::Success(failed(call.procedure, Stat::YpErr)?)
                } else {
                    Accepted::Success(body)
                }
            }
        }
    };
    Some(rpc::accepted_reply(call.xid, &result))
}

/// The model's answer to one request, as the procedure's result body; None to fail closed
/// (YP_YPERR, or for DOMAIN false / DOMAIN_NONACK silence).
async fn answer(
    ctx: &SpawnContext,
    conn: Option<ConnectionId>,
    request: &Request,
    transport: &str,
) -> Option<Vec<u8>> {
    match request {
        Request::Domain { domain, nonack } => {
            let data =
                json!({"domain": domain, "procedure": request.name(), "transport": transport});
            let (name, v) = ask(ctx, conn, &actions::DOMAIN_EVENT, data, request).await?;
            if name != actions::DOMAIN {
                outcome(ctx, request, "fail_closed_invalid_reply");
                return None;
            }
            let served = v["served"].as_bool().unwrap_or(false);
            outcome(
                ctx,
                request,
                if served {
                    "model_answer"
                } else {
                    "model_reject"
                },
            );
            if !served && *nonack {
                return None;
            }
            Some(wire::resp_bool(served))
        }
        Request::Match { domain, map, key } => {
            let data = json!({"domain": domain, "map": map, "key": key, "transport": transport});
            let pairs = match entries(ctx, conn, &actions::MATCH_EVENT, data, request, map).await? {
                Err(stat) => return Some(wire::resp_val(stat, "")),
                Ok(p) => p,
            };
            Some(match pairs.iter().find(|(k, _)| k == key) {
                Some((_, v)) => {
                    outcome(ctx, request, "model_answer");
                    wire::resp_val(Stat::True, v)
                }
                None => {
                    outcome(ctx, request, "model_reject");
                    wire::resp_val(Stat::NoKey, "")
                }
            })
        }
        Request::First { domain, map }
        | Request::Next { domain, map, .. }
        | Request::All { domain, map } => {
            let mut data = json!({"domain": domain, "map": map, "procedure": request.name(), "transport": transport});
            if let Request::Next { key, .. } = request {
                data["key"] = json!(key);
            }
            let pairs = match entries(ctx, conn, &actions::MAP_EVENT, data, request, map).await? {
                Err(stat) => {
                    return Some(match request {
                        Request::All { .. } => wire::resp_all(Err(stat)),
                        _ => wire::resp_key_val(stat, "", ""),
                    })
                }
                Ok(p) => p,
            };
            outcome(ctx, request, "model_answer");
            Some(match request {
                Request::All { .. } => wire::resp_all(Ok(&pairs)),
                Request::First { .. } => match pairs.first() {
                    Some((k, v)) => wire::resp_key_val(Stat::True, k, v),
                    None => wire::resp_key_val(Stat::NoMore, "", ""),
                },
                Request::Next { key, .. } => match pairs.iter().position(|(k, _)| k == key) {
                    None => wire::resp_key_val(Stat::NoKey, "", ""),
                    Some(i) => match pairs.get(i + 1) {
                        Some((k, v)) => wire::resp_key_val(Stat::True, k, v),
                        None => wire::resp_key_val(Stat::NoMore, "", ""),
                    },
                },
                _ => wire::resp_key_val(Stat::BadOp, "", ""),
            })
        }
        Request::Master { domain, map } | Request::Order { domain, map } => {
            let data = json!({"domain": domain, "map": map, "procedure": request.name(), "transport": transport});
            let (name, v) = ask(ctx, conn, &actions::MAP_INFO_EVENT, data, request).await?;
            let master = matches!(request, Request::Master { .. });
            match name.as_str() {
                actions::ERROR => {
                    let stat = model_error(&v)?;
                    outcome(ctx, request, "model_reject");
                    Some(if master {
                        wire::resp_master(stat, "")
                    } else {
                        wire::resp_order(stat, 0)
                    })
                }
                actions::MAP_INFO if master && v["master"].is_string() => {
                    outcome(ctx, request, "model_answer");
                    Some(wire::resp_master(
                        Stat::True,
                        v["master"].as_str().unwrap_or_default(),
                    ))
                }
                actions::MAP_INFO if !master && v["order"].is_u64() => {
                    outcome(ctx, request, "model_answer");
                    Some(wire::resp_order(
                        Stat::True,
                        v["order"].as_u64().unwrap_or_default() as u32,
                    ))
                }
                _ => {
                    outcome(ctx, request, "fail_closed_invalid_reply");
                    None
                }
            }
        }
        Request::Maplist { domain } => {
            let data = json!({"domain": domain, "transport": transport});
            let (name, v) = ask(ctx, conn, &actions::MAPLIST_EVENT, data, request).await?;
            match name.as_str() {
                actions::ERROR => {
                    let stat = model_error(&v)?;
                    outcome(ctx, request, "model_reject");
                    Some(wire::resp_maplist(stat, &[]))
                }
                actions::MAPS => {
                    let maps: Vec<String> = v["maps"]
                        .as_array()?
                        .iter()
                        .filter_map(|m| m.as_str().map(str::to_string))
                        .collect();
                    outcome(ctx, request, "model_answer");
                    Some(wire::resp_maplist(Stat::True, &maps))
                }
                _ => {
                    outcome(ctx, request, "fail_closed_invalid_reply");
                    None
                }
            }
        }
        Request::Null | Request::Clear | Request::Xfr => None,
    }
}

fn model_error(v: &Value) -> Option<Stat> {
    Stat::from_model(v["status"].as_str().unwrap_or_default())
}

/// The model's entries for `map` rendered into (key, value) pairs; `Ok(Err(stat))` for the
/// model's refusal; None to fail closed.
async fn entries(
    ctx: &SpawnContext,
    conn: Option<ConnectionId>,
    event_type: &'static EventType,
    data: Value,
    request: &Request,
    map: &str,
) -> Option<std::result::Result<Vec<(String, String)>, Stat>> {
    let (name, v) = ask(ctx, conn, event_type, data, request).await?;
    match name.as_str() {
        actions::ERROR => {
            let stat = model_error(&v)?;
            outcome(ctx, request, "model_reject");
            Some(Err(stat))
        }
        actions::ENTRIES => match render(map, &v) {
            Ok(pairs) => Some(Ok(pairs)),
            Err(e) => {
                Log::new(Some(&ctx.status_tx)).warn(format!("NIS entries for {map}: {e:#}"));
                outcome(ctx, request, "fail_closed_invalid_reply");
                None
            }
        },
        _ => {
            outcome(ctx, request, "fail_closed_invalid_reply");
            None
        }
    }
}

fn render(map: &str, v: &Value) -> Result<Vec<(String, String)>> {
    let Some(list) = v["entries"].as_array() else {
        bail!("entries must be an array");
    };
    wire::map_pairs(map, list)
}
