//! NIS (YP) client: find ypserv (directly, or through a portmapper), bind to a domain with
//! YPPROC_DOMAIN, then one call at a time over one TCP connection, each reply matched by xid
//! and raised to the handler as `nis_reply` with its entries decoded.
pub mod actions;
use crate::client::llm_budget::call_llm_for_client;
use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::logging::emit::Log;
use crate::protocol::{ConnectContext, Event};
use crate::server::nis::wire::{self, proc_};
use crate::server::sunrpc::wire as rpc;
use crate::state::client_handles::{ClientCommand, ClientSendOutcome};
use crate::state::{AccessLogOwner, ClientStatus};
pub use actions::NisClientProtocol;
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Connect, and each call to its reply.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// A handler chain (answer → event → answer …) stops after this many follow-ups.
pub const MAX_FOLLOWUP_DEPTH: usize = 8;

async fn connect_to(addr: &str) -> Result<TcpStream> {
    tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(addr))
        .await
        .with_context(|| format!("connecting to {addr} timed out"))?
        .with_context(|| format!("connecting to {addr}"))
}

/// One call to its reply: the result body, or the RPC-level reason there is none.
async fn exchange(
    r: &mut OwnedReadHalf,
    w: &mut OwnedWriteHalf,
    xid: u32,
    program: u32,
    version: u32,
    procedure: u32,
    args: &[u8],
) -> Result<std::result::Result<Vec<u8>, String>> {
    tokio::time::timeout(IO_TIMEOUT, async {
        w.write_all(&rpc::record(&rpc::call_message_to(
            xid, program, version, procedure, args,
        )))
        .await?;
        loop {
            let msg = rpc::read_record_bounded(r, wire::MAX_REPLY, wire::MAX_REPLY_FRAGMENTS)
                .await?
                .context("the server closed the connection")?;
            let (got, body) = rpc::parse_reply(&msg)?;
            // A stale reply to an earlier, timed-out call is skipped.
            if got == xid {
                return Ok(body);
            }
        }
    })
    .await
    .context("the server did not answer within 10 s")?
}

/// ypserv's TCP address, from the portmapper at `portmapper` (PMAP v2 GETPORT).
async fn ypserv_via_portmapper(portmapper: &str) -> Result<SocketAddr> {
    let s = connect_to(portmapper).await?;
    let host = s.peer_addr()?.ip();
    let (mut r, mut w) = s.into_split();
    let mut args = rpc::Writer::default();
    args.u32(wire::PROGRAM)
        .u32(wire::VERSION)
        .u32(rpc::IPPROTO_TCP)
        .u32(0);
    let body = exchange(&mut r, &mut w, rand::random(), rpc::PROGRAM, 2, 3, &args.0)
        .await?
        .map_err(|why| anyhow::anyhow!("the portmapper answered {why}"))?;
    let port = rpc::Reader::new(&body).u32()?;
    ensure!(
        port != 0 && port <= 65535,
        "ypserv (program 100004 version 2, tcp) is not registered with the portmapper at {portmapper}"
    );
    Ok(SocketAddr::new(host, port as u16))
}

pub async fn connect(ctx: ConnectContext) -> Result<SocketAddr> {
    let params = ctx.startup_params.as_ref();
    let domain = params
        .map(|p| p.get_string("domain"))
        .transpose()?
        .context("the domain startup parameter is required")?;
    let domain = wire::model_name(&domain, wire::YPMAXDOMAIN, "domain")?;
    let use_portmapper = match params
        .map(|p| p.get_optional_bool("use_portmapper"))
        .transpose()?
        .flatten()
    {
        Some(b) => b,
        None => ctx.remote_addr.rsplit(':').next() == Some("111"),
    };
    let (ypserv, portmapper) = if use_portmapper {
        let addr = ypserv_via_portmapper(&ctx.remote_addr).await?;
        (addr.to_string(), Some(ctx.remote_addr.clone()))
    } else {
        (ctx.remote_addr.clone(), None)
    };
    let stream = connect_to(&ypserv).await?;
    let local = stream.local_addr()?;
    let remote = stream.peer_addr()?;
    let (mut r, mut w) = stream.into_split();
    let mut xid: u32 = rand::random();
    // Bind: does the server serve the domain?
    let served = match exchange(
        &mut r,
        &mut w,
        xid,
        wire::PROGRAM,
        wire::VERSION,
        proc_::DOMAIN,
        &wire::req_domain(&domain),
    )
    .await?
    {
        Ok(body) => wire::read_bool(&body)?,
        Err(why) => anyhow::bail!("{ypserv} is not a NIS v2 server: {why}"),
    };
    ctx.state
        .update_client_status(ctx.client_id, ClientStatus::Connected)
        .await;
    let external =
        crate::client::command_support::register_command_channel(&ctx.state, ctx.client_id).await;
    let (internal_tx, internal_rx) = mpsc::channel::<(Value, usize)>(32);
    let (event_tx, mut event_rx) = mpsc::channel::<(Event, usize)>(32);
    let mut connected =
        json!({"remote_addr": remote.to_string(), "domain": domain, "served": served});
    if let Some(pm) = &portmapper {
        connected["portmapper"] = json!(pm);
    }
    event_tx.try_send((Event::new(&actions::CONNECTED_EVENT, connected), 0))?;
    let events_ctx = ctx.clone();
    let dispatcher = tokio::spawn(async move {
        // call_llm_for_client records each event (with the actions it produced) in the
        // access log, whoever answers it.
        while let Some((event, depth)) = event_rx.recv().await {
            let instruction = events_ctx
                .state
                .get_instruction_for_client(events_ctx.client_id)
                .await
                .unwrap_or_default();
            let memory = events_ctx
                .state
                .get_memory_for_client(events_ctx.client_id)
                .await
                .unwrap_or_default();
            match call_llm_for_client(
                &events_ctx.llm_client,
                &events_ctx.state,
                events_ctx.client_id.to_string(),
                &instruction,
                &memory,
                Some(&event),
                &NisClientProtocol,
                &events_ctx.status_tx,
            )
            .await
            {
                Ok(result) => {
                    if let Some(memory) = result.memory_updates {
                        events_ctx
                            .state
                            .set_memory_for_client(events_ctx.client_id, memory)
                            .await;
                    }
                    for action in result.actions {
                        if internal_tx.send((action, depth + 1)).await.is_err() {
                            return;
                        }
                    }
                }
                // Fail closed: no answer, nothing sent.
                Err(e) => Log::new(Some(&events_ctx.status_tx))
                    .warn(format!("NIS client handler (nothing sent): {e}")),
            }
        }
    });
    let dispatcher_abort = dispatcher.abort_handle();
    ctx.state
        .register_client_task(ctx.client_id, dispatcher)
        .await;
    let session_ctx = ctx.clone();
    xid = xid.wrapping_add(1);
    let task = tokio::spawn(async move {
        let result = session(
            &session_ctx,
            r,
            w,
            xid,
            domain,
            external,
            internal_rx,
            event_tx,
        )
        .await;
        dispatcher_abort.abort();
        let status = match result {
            Ok(()) => ClientStatus::Disconnected,
            Err(e) => {
                Log::new(Some(&session_ctx.status_tx)).warn(format!("NIS client ended: {e}"));
                ClientStatus::Error(e.to_string())
            }
        };
        session_ctx
            .state
            .update_client_status(session_ctx.client_id, status)
            .await;
        session_ctx
            .state
            .remove_client_handle(session_ctx.client_id)
            .await;
        let _ = session_ctx.status_tx.send("__UPDATE_UI__".into());
    });
    ctx.state.register_client_task(ctx.client_id, task).await;
    Ok(local)
}

#[allow(clippy::too_many_arguments)]
async fn session(
    ctx: &ConnectContext,
    mut r: OwnedReadHalf,
    mut w: OwnedWriteHalf,
    mut xid: u32,
    bound: String,
    mut external: mpsc::Receiver<ClientCommand>,
    mut internal: mpsc::Receiver<(Value, usize)>,
    events: mpsc::Sender<(Event, usize)>,
) -> Result<()> {
    let log = Log::new(Some(&ctx.status_tx));
    loop {
        let (action, depth, mut injected) = tokio::select! {
            command = external.recv() => match command {
                Some(c) => (c.action.clone(), 0, Some(c)),
                None => return Ok(()),
            },
            action = internal.recv() => match action {
                Some((a, depth)) => (a, depth, None),
                None => return Ok(()),
            },
        };
        let reply = |injected: &mut Option<ClientCommand>, outcome: ClientSendOutcome| {
            if let Some(command) = injected.take() {
                crate::client::command_support::reply(command, Ok(outcome));
            }
        };
        match NisClientProtocol.execute_action(action.clone()) {
            Ok(ClientActionResult::Disconnect) => {
                reply(&mut injected, ClientSendOutcome::Disconnected);
                return Ok(());
            }
            Ok(_) => {}
            Err(e) => {
                log.warn(format!("NIS client action refused: {e:#}"));
                reply(
                    &mut injected,
                    ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    },
                );
                continue;
            }
        }
        if depth > MAX_FOLLOWUP_DEPTH {
            log.warn(format!(
                "NIS client: handler chain stopped after {MAX_FOLLOWUP_DEPTH} follow-ups"
            ));
            continue;
        }
        let call = match actions::call(&action, &bound) {
            Ok(c) => c,
            Err(e) => {
                log.warn(format!("NIS client action refused: {e:#}"));
                reply(
                    &mut injected,
                    ClientSendOutcome::Rejected {
                        error: e.to_string(),
                    },
                );
                continue;
            }
        };
        if injected.is_some() {
            ctx.state
                .record_access_log(
                    AccessLogOwner::Client(ctx.client_id.as_u32()),
                    "NIS",
                    None,
                    "injected_action",
                    action.clone(),
                    vec![],
                )
                .await;
        }
        xid = xid.wrapping_add(1);
        let operation = action["type"].as_str().unwrap_or_default();
        let answer = exchange(
            &mut r,
            &mut w,
            xid,
            wire::PROGRAM,
            wire::VERSION,
            call.procedure,
            &call.args,
        )
        .await;
        let mut data = json!({"operation": operation, "domain": call.domain});
        if let Some(m) = &call.map {
            data["map"] = json!(m);
        }
        match answer {
            Err(e) => {
                // The transport failed: tell the injector, end the session.
                reply(
                    &mut injected,
                    ClientSendOutcome::Rejected {
                        error: format!("{e:#}"),
                    },
                );
                return Err(e);
            }
            Ok(Err(why)) => {
                data["ok"] = json!(false);
                data["status"] = json!("RPC_ERROR");
                data["error"] = json!(why);
            }
            Ok(Ok(body)) => match actions::result(&call, &body) {
                Ok((ok, status, fields)) => {
                    data["ok"] = json!(ok);
                    data["status"] = json!(status);
                    if let Value::Object(f) = fields {
                        for (k, v) in f {
                            data[k] = v;
                        }
                    }
                }
                Err(e) => {
                    data["ok"] = json!(false);
                    data["status"] = json!("UNREADABLE");
                    data["error"] = json!(format!("unreadable result: {e:#}"));
                }
            },
        }
        reply(
            &mut injected,
            ClientSendOutcome::Executed {
                detail: data.to_string(),
            },
        );
        ensure!(
            events
                .try_send((Event::new(&actions::REPLY_EVENT, data), depth))
                .is_ok(),
            "NIS event queue full; consumer stalled"
        );
    }
}
