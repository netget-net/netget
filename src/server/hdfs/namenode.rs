//! The NameNode: one task per client connection running Hadoop IPC (the `hrpc` header, an
//! optional SASL negotiation that can only end in SIMPLE, the connection context naming the
//! effective user) and then ClientNamenodeProtocol calls, one at a time, each answered with
//! its call id. Reads are answered from the namespace; a directory nobody has described is
//! described first (the model, once); a change is planned, asked about and applied while the
//! server's decision gate is held.
use super::actions::{self, denial};
use super::namespace::{self, errno_for_class, joined, Halt, MkdirsPlan, Namespace, Step, Thrown};
use super::proto::common::{
    rpc_response_header_proto::RpcErrorCodeProto, rpc_sasl_proto::SaslAuth,
    rpc_sasl_proto::SaslState, HaServiceStateProto, IpcConnectionContextProto, RpcSaslProto,
};
use super::proto::hdfs as pb;
use super::rpc::{self, class};
use super::{Admission, Hdfs};
use crate::logging::emit::Log;
use crate::protocol::{Event, EventType};
use crate::server::accept_bounded::{accept_bounded, ConnectionLimiter, DEFAULT_MAX_CONNECTIONS};
use crate::server::connection::ConnectionId;
use crate::server::described_tree::{DirState, Kind};
use crate::state::server::{ConnectionState, ConnectionStatus, ProtocolConnectionInfo};
use crate::utils::clock::Instant;
use prost::Message;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn accept_loop(listener: tokio::net::TcpListener, hdfs: Arc<Hdfs>) {
    let limiter = ConnectionLimiter::new(DEFAULT_MAX_CONNECTIONS);
    let server_id = hdfs.ctx.server_id;
    let Ok(listening) = listener.local_addr() else {
        return;
    };
    loop {
        let (stream, peer, permit) = match accept_bounded(
            &listener,
            &limiter,
            b"",
            "HDFS NameNode",
            Some(&hdfs.ctx.status_tx),
        )
        .await
        {
            Ok(v) => v,
            Err(_) => break,
        };
        let _ = stream.set_nodelay(true);
        let local = stream.local_addr().unwrap_or(listening);
        let id = ConnectionId::new(hdfs.ctx.state.get_next_unified_id().await);
        let now = Instant::now();
        hdfs.ctx
            .state
            .add_connection_to_server(
                server_id,
                ConnectionState {
                    id,
                    remote_addr: peer,
                    local_addr: local,
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    last_activity: now,
                    status: ConnectionStatus::Active,
                    status_changed_at: now,
                    protocol_info: ProtocolConnectionInfo::new(json!({"role": "namenode"})),
                },
            )
            .await;
        let child = hdfs.clone();
        hdfs.ctx
            .state
            .spawn_server_task(server_id, async move {
                let _permit = permit;
                let mut s = Session {
                    hdfs: child.clone(),
                    id,
                    peer,
                    local,
                    stream,
                    user: String::new(),
                    calls: BTreeMap::new(),
                };
                if let Err(e) = s.run().await {
                    Log::new(Some(&child.ctx.status_tx))
                        .debug(format!("HDFS NameNode connection {id}: {e:#}"));
                }
                s.closed();
                let _ = s.stream.shutdown().await;
                child
                    .ctx
                    .state
                    .update_connection_status(server_id, id, ConnectionStatus::Closed)
                    .await;
                let _ = child.ctx.status_tx.send("__UPDATE_UI__".into());
            })
            .await;
    }
}

/// How a call failed: an exception for the client, or a method this NameNode lacks.
enum CallError {
    Thrown(Thrown),
    NoSuchMethod,
}

impl From<Thrown> for CallError {
    fn from(t: Thrown) -> Self {
        CallError::Thrown(t)
    }
}

type CallResult = Result<Vec<u8>, CallError>;

fn dec<M: Message + Default>(body: &[u8], method: &str) -> Result<M, Thrown> {
    M::decode(body).map_err(|_| {
        Thrown::new(
            class::IO,
            format!("The {method} request is not a valid protocol buffer"),
        )
    })
}

fn path_of(src: &str) -> Result<Vec<&str>, Thrown> {
    namespace::components(src)
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Dir => "dir",
        Kind::Symlink => "symlink",
        _ => "file",
    }
}

/// A step's refusal; a description still needed at apply time is a fault of this server.
fn applied<T>(s: Step<T>) -> Result<T, Thrown> {
    match s {
        Ok(v) => Ok(v),
        Err(Halt::Thrown(t)) => Err(t),
        Err(Halt::Describe(_)) => Err(Thrown::new(
            class::IO,
            "The namespace changed while the call was decided",
        )),
    }
}

struct Session {
    hdfs: Arc<Hdfs>,
    id: ConnectionId,
    peer: SocketAddr,
    local: SocketAddr,
    stream: TcpStream,
    user: String,
    calls: BTreeMap<String, u64>,
}

impl Session {
    fn who(&self) -> String {
        format!(
            "NameNode connection {} user={}",
            self.id,
            crate::utils::sanitize::token(&self.user, 64)
        )
    }

    fn outcome(&self, op: &str, path: &str, decision: &str, detail: &str) {
        self.hdfs.outcome(&self.who(), op, path, decision, detail);
    }

    /// One line per connection: which methods it called, how often.
    fn closed(&self) {
        if self.calls.is_empty() {
            return;
        }
        let total: u64 = self.calls.values().sum();
        let list: Vec<String> = self.calls.iter().map(|(m, n)| format!("{m}={n}")).collect();
        Log::new(Some(&self.hdfs.ctx.status_tx)).info(format!(
            "HDFS {} closed after {total} calls: {}",
            self.who(),
            list.join(" ")
        ));
    }

    async fn send(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        tokio::time::timeout(
            self.hdfs.settings.deadlines.frame,
            self.stream.write_all(bytes),
        )
        .await
        .map_err(|_| anyhow::anyhow!("the client did not take a response in time"))??;
        self.hdfs
            .ctx
            .state
            .update_connection_stats(
                self.hdfs.ctx.server_id,
                self.id,
                None,
                Some(bytes.len() as u64),
                None,
                Some(1),
            )
            .await;
        Ok(())
    }

    async fn fatal(&mut self, call_id: i32, class: &str, message: &str, code: RpcErrorCodeProto) {
        self.outcome(
            "connection",
            "",
            "protocol_refusal",
            &format!("{class}: {message}; closed"),
        );
        let frame = rpc::failure(call_id, &[], -1, true, class, message, code);
        let _ = self.send(&frame).await;
    }

    async fn run(&mut self) -> anyhow::Result<()> {
        let deadlines = self.hdfs.settings.deadlines;
        let mut h = [0u8; 7];
        match tokio::time::timeout(deadlines.header, self.stream.read_exact(&mut h)).await {
            Err(_) => {
                self.outcome(
                    "connection",
                    "",
                    "protocol_refusal",
                    &format!(
                        "no connection header within {} s; closed",
                        deadlines.header.as_secs()
                    ),
                );
                return Ok(());
            }
            Ok(Err(_)) => return Ok(()),
            Ok(Ok(_)) => {}
        }
        let header = match rpc::parse_connection_header(&h) {
            Ok(h) => h,
            Err(_) => {
                self.outcome(
                    "connection",
                    "",
                    "protocol_refusal",
                    "the connection does not start with hrpc; closed",
                );
                return Ok(());
            }
        };
        if header.version != rpc::IPC_VERSION {
            let v = header.version;
            self.fatal(
                rpc::INVALID_CALL_ID,
                class::VERSION_MISMATCH,
                &format!("Server IPC version 9 cannot communicate with client version {v}"),
                RpcErrorCodeProto::FatalVersionMismatch,
            )
            .await;
            return Ok(());
        }
        let auth = match header.auth_protocol {
            rpc::AUTH_NONE => "none",
            rpc::AUTH_SASL => {
                if !self.sasl().await? {
                    return Ok(());
                }
                "sasl-simple"
            }
            other => {
                self.fatal(
                    rpc::INVALID_CALL_ID,
                    class::ACCESS_CONTROL,
                    &format!("Auth protocol {other} is not supported; this NameNode accepts SIMPLE authentication only"),
                    RpcErrorCodeProto::FatalUnauthorized,
                )
                .await;
                return Ok(());
            }
        };
        // The connection context.
        let frame = match rpc::read_frame(
            &mut self.stream,
            rpc::MAX_REQUEST_FRAME,
            deadlines.header,
            deadlines.frame,
        )
        .await
        {
            Ok(f) => f,
            Err(e) => {
                self.refused_frame(&e).await;
                return Ok(());
            }
        };
        let context = rpc::decode_request(&frame).and_then(|(h, rest)| {
            anyhow::ensure!(
                h.call_id == rpc::CONNECTION_CONTEXT_CALL_ID,
                "call id {} where the connection context belongs",
                h.call_id
            );
            Ok(rpc::decode_delimited::<IpcConnectionContextProto>(rest)?.0)
        });
        let context = match context {
            Ok(c) => c,
            Err(e) => {
                self.fatal(
                    rpc::CONNECTION_CONTEXT_CALL_ID,
                    class::SERVER,
                    &format!("Invalid connection context: {e:#}"),
                    RpcErrorCodeProto::FatalInvalidRpcHeader,
                )
                .await;
                return Ok(());
            }
        };
        let info = context.user_info.unwrap_or_default();
        let user = info.effective_user.unwrap_or_default();
        if user.is_empty()
            || user.len() > namespace::MAX_PRINCIPAL_BYTES
            || crate::utils::sanitize::has_controls(&user)
        {
            self.fatal(
                rpc::CONNECTION_CONTEXT_CALL_ID,
                class::ACCESS_CONTROL,
                "The connection context names no usable effective user",
                RpcErrorCodeProto::FatalUnauthorized,
            )
            .await;
            return Ok(());
        }
        self.user = user;
        let protocol = context.protocol.unwrap_or_default();
        if let Err(t) = self.admit(info.real_user.as_deref(), &protocol, auth).await {
            self.fatal(
                rpc::CONNECTION_CONTEXT_CALL_ID,
                t.class,
                &t.message,
                RpcErrorCodeProto::FatalUnauthorized,
            )
            .await;
            return Ok(());
        }
        // Calls.
        loop {
            let frame = match rpc::read_frame(
                &mut self.stream,
                rpc::MAX_REQUEST_FRAME,
                deadlines.idle,
                deadlines.frame,
            )
            .await
            {
                Ok(f) => f,
                Err(rpc::FrameError::Closed) => return Ok(()),
                Err(e) => {
                    self.refused_frame(&e).await;
                    return Ok(());
                }
            };
            self.hdfs
                .ctx
                .state
                .update_connection_stats(
                    self.hdfs.ctx.server_id,
                    self.id,
                    Some(frame.len() as u64 + 4),
                    None,
                    Some(1),
                    None,
                )
                .await;
            let (header, rest) = match rpc::decode_request(&frame) {
                Ok(v) => v,
                Err(e) => {
                    self.fatal(
                        rpc::INVALID_CALL_ID,
                        class::SERVER,
                        &format!("Invalid RPC header: {e:#}"),
                        RpcErrorCodeProto::FatalDeserializingRequest,
                    )
                    .await;
                    return Ok(());
                }
            };
            if header.call_id == rpc::PING_CALL_ID {
                continue;
            }
            if rpc::is_close(&header) {
                return Ok(());
            }
            if header.rpc_kind != Some(super::proto::common::RpcKindProto::RpcProtocolBuffer as i32)
            {
                self.fatal(
                    header.call_id,
                    class::SERVER,
                    "Only protocol buffer calls (RPC_PROTOCOL_BUFFER) are served",
                    RpcErrorCodeProto::FatalUnsupportedSerialization,
                )
                .await;
                return Ok(());
            }
            if header.call_id < 0 {
                self.fatal(
                    header.call_id,
                    class::SERVER,
                    &format!("Call id {} is reserved", header.call_id),
                    RpcErrorCodeProto::FatalInvalidRpcHeader,
                )
                .await;
                return Ok(());
            }
            let call_id = header.call_id;
            let client_id = header.client_id.clone();
            let retry = header.retry_count.unwrap_or(-1);
            let (method, body) = match rpc::decode_call(rest) {
                Ok(v) => v,
                Err(e) => {
                    self.fatal(
                        call_id,
                        class::SERVER,
                        &format!("Cannot decode the call: {e:#}"),
                        RpcErrorCodeProto::FatalDeserializingRequest,
                    )
                    .await;
                    return Ok(());
                }
            };
            let name = crate::utils::sanitize::token(&method.method_name, 64);
            *self.calls.entry(name.clone()).or_default() += 1;
            let reply = if method.declaring_class_protocol_name != rpc::CLIENT_PROTOCOL {
                rpc::failure(
                    call_id,
                    &client_id,
                    retry,
                    false,
                    class::NO_SUCH_PROTOCOL,
                    &format!(
                        "Unknown protocol: {}",
                        crate::utils::sanitize::token(&method.declaring_class_protocol_name, 128)
                    ),
                    RpcErrorCodeProto::ErrorNoSuchProtocol,
                )
            } else {
                let deadline = tokio::time::Instant::now() + self.hdfs.settings.timeout;
                match self.call(&method.method_name, body, deadline).await {
                    Ok(bytes) => rpc::success_encoded(call_id, &client_id, retry, &bytes),
                    Err(CallError::NoSuchMethod) => {
                        self.outcome(
                            &name,
                            "",
                            "protocol_refusal",
                            "not built here; answered RpcNoSuchMethodException",
                        );
                        rpc::failure(
                            call_id,
                            &client_id,
                            retry,
                            false,
                            class::NO_SUCH_METHOD,
                            &format!(
                                "Unknown method {name} called on {} protocol.",
                                rpc::CLIENT_PROTOCOL
                            ),
                            RpcErrorCodeProto::ErrorNoSuchMethod,
                        )
                    }
                    Err(CallError::Thrown(t)) => rpc::failure(
                        call_id,
                        &client_id,
                        retry,
                        false,
                        t.class,
                        &t.message,
                        RpcErrorCodeProto::ErrorApplication,
                    ),
                }
            };
            self.send(&reply).await?;
        }
    }

    async fn refused_frame(&mut self, e: &rpc::FrameError) {
        match e {
            rpc::FrameError::TooLarge(n) => {
                self.fatal(
                    rpc::INVALID_CALL_ID,
                    class::IO,
                    &format!(
                        "Requested data length {n} is longer than maximum configured RPC length {}",
                        rpc::MAX_REQUEST_FRAME
                    ),
                    RpcErrorCodeProto::FatalInvalidRpcHeader,
                )
                .await
            }
            rpc::FrameError::Idle => self.outcome(
                "connection",
                "",
                "protocol_refusal",
                &format!(
                    "no frame began within {} s; closed",
                    if self.user.is_empty() {
                        self.hdfs.settings.deadlines.header.as_secs()
                    } else {
                        self.hdfs.settings.deadlines.idle.as_secs()
                    }
                ),
            ),
            rpc::FrameError::Timeout => self.outcome(
                "connection",
                "",
                "protocol_refusal",
                &format!(
                    "the rest of a frame did not arrive within {} s of its first byte; closed",
                    self.hdfs.settings.deadlines.frame.as_secs()
                ),
            ),
            _ => {}
        }
    }

    /// SASL negotiation that can end only in SIMPLE: NEGOTIATE is answered with the one method
    /// this NameNode has; anything else is refused. `Ok(false)`: refused and closed.
    async fn sasl(&mut self) -> anyhow::Result<bool> {
        let deadlines = self.hdfs.settings.deadlines;
        let frame = match rpc::read_frame(
            &mut self.stream,
            rpc::MAX_REQUEST_FRAME,
            deadlines.header,
            deadlines.frame,
        )
        .await
        {
            Ok(f) => f,
            Err(e) => {
                self.refused_frame(&e).await;
                return Ok(false);
            }
        };
        let message = rpc::decode_request(&frame).and_then(|(h, rest)| {
            anyhow::ensure!(
                h.call_id == rpc::SASL_CALL_ID,
                "call id {} is not SASL's",
                h.call_id
            );
            Ok(rpc::decode_delimited::<RpcSaslProto>(rest)?.0)
        });
        match message {
            Ok(m) if m.state == SaslState::Negotiate as i32 => {
                let reply = RpcSaslProto {
                    version: None,
                    state: SaslState::Negotiate as i32,
                    token: None,
                    auths: vec![SaslAuth {
                        method: "SIMPLE".into(),
                        mechanism: String::new(),
                        protocol: None,
                        server_id: None,
                        challenge: None,
                    }],
                };
                self.send(&rpc::success(rpc::SASL_CALL_ID, &[], -1, &reply))
                    .await?;
                Ok(true)
            }
            Ok(_) => {
                self.fatal(
                    rpc::SASL_CALL_ID,
                    class::ACCESS_CONTROL,
                    "Kerberos and token authentication are not built; this NameNode accepts SIMPLE only",
                    RpcErrorCodeProto::FatalUnauthorized,
                )
                .await;
                Ok(false)
            }
            Err(e) => {
                self.fatal(
                    rpc::SASL_CALL_ID,
                    class::SERVER,
                    &format!("Invalid SASL message: {e:#}"),
                    RpcErrorCodeProto::FatalDeserializingRequest,
                )
                .await;
                Ok(false)
            }
        }
    }

    /// Whether this connection's user may connect: remembered, or asked once.
    async fn admit(
        &mut self,
        real_user: Option<&str>,
        protocol: &str,
        auth: &str,
    ) -> Result<(), Thrown> {
        let key = self.user.clone();
        let remembered = self.hdfs.users().get(&key).cloned();
        match remembered {
            Some(Admission::Allowed) => return Ok(()),
            Some(Admission::Denied(c, m)) => return Err(Thrown::new(c, m)),
            None => {}
        }
        let deadline = tokio::time::Instant::now() + self.hdfs.settings.timeout;
        let _gate = self.gate(deadline).await?;
        let remembered = self.hdfs.users().get(&key).cloned();
        match remembered {
            Some(Admission::Allowed) => return Ok(()),
            Some(Admission::Denied(c, m)) => return Err(Thrown::new(c, m)),
            None => {}
        }
        let event = Event::new(
            &actions::CONNECT_EVENT,
            json!({
                "user": self.user,
                "real_user": real_user,
                "client_address": self.peer.to_string(),
                "protocol": crate::utils::sanitize::token(protocol, 128),
                "auth": auth,
            }),
        );
        let remember = |hdfs: &Hdfs, a: Admission| {
            let mut users = hdfs.users();
            if users.len() < super::MAX_REMEMBERED_USERS {
                users.insert(key.clone(), a);
            }
        };
        match self
            .hdfs
            .ask(self.id, &event, &[actions::ALLOW, actions::DENY], deadline)
            .await
        {
            Ok(a) if a["type"] == actions::ALLOW => {
                remember(&self.hdfs, Admission::Allowed);
                self.outcome("connect", "", "model_answer", "admitted");
                Ok(())
            }
            Ok(a) => {
                let (c, m) = denial(&a);
                remember(&self.hdfs, Admission::Denied(c, m.clone()));
                self.outcome("connect", "", "model_reject", &format!("answered {c}"));
                Err(Thrown::new(c, m))
            }
            Err(f) => {
                self.outcome(
                    "connect",
                    "",
                    f.decision(),
                    &format!("{}; the connection is refused", f.detail()),
                );
                Err(f.thrown())
            }
        }
    }

    async fn gate(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<tokio::sync::MutexGuard<'_, ()>, Thrown> {
        match tokio::time::timeout_at(deadline, self.hdfs.gate.lock()).await {
            Ok(g) => Ok(g),
            Err(_) => {
                self.outcome(
                    "gate",
                    "",
                    "fail_closed_deadline",
                    "the deadline passed while the call waited for another decision",
                );
                Err(Thrown::new(
                    class::IO,
                    "The NameNode could not decide in time",
                ))
            }
        }
    }

    fn base_fields(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("user".into(), json!(self.user));
        m.insert("client_address".into(), json!(self.peer.to_string()));
        m
    }

    /// Describe a pending directory; the caller holds the gate.
    async fn describe(
        &self,
        dir: u64,
        method: &str,
        deadline: tokio::time::Instant,
    ) -> Result<(), Thrown> {
        let (path, depth) = {
            let ns = self.hdfs.ns();
            match ns.tree.dir_state(dir) {
                Some(DirState::Pending(_)) => {}
                _ => return Ok(()),
            }
            (ns.tree.path(dir), ns.tree.depth(dir))
        };
        let mut fields = self.base_fields();
        fields.insert("path".into(), json!(path));
        fields.insert("depth".into(), json!(depth));
        fields.insert("method".into(), json!(method));
        let event = Event::new(&actions::DESCRIBE_EVENT, Value::Object(fields));
        let answer = self
            .hdfs
            .ask(
                self.id,
                &event,
                &[actions::DIRECTORY, actions::DENY],
                deadline,
            )
            .await;
        let failed_suffix = |failed: bool| {
            if failed {
                ", and the directory has failed for good"
            } else {
                ""
            }
        };
        match answer {
            Ok(a) if a["type"] == actions::DENY => {
                let (c, m) = denial(&a);
                self.hdfs
                    .ns()
                    .tree
                    .description_refused(dir, errno_for_class(c));
                self.outcome("describe", &path, "model_reject", &format!("answered {c}"));
                Err(Thrown::new(c, m))
            }
            Ok(a) => {
                let r = self.hdfs.ns().describe(dir, &a);
                match r {
                    Ok(n) => {
                        self.outcome("describe", &path, "model_answer", &format!("{n} entries"));
                        Ok(())
                    }
                    Err(e) => {
                        let failed = self.hdfs.ns().tree.description_failed(dir);
                        self.outcome(
                            "describe",
                            &path,
                            "fail_closed_invalid_reply",
                            &format!("{e:#}; answered IOException{}", failed_suffix(failed)),
                        );
                        Err(Thrown::new(
                            class::IO,
                            format!("The NameNode could not describe {path}"),
                        ))
                    }
                }
            }
            Err(f) => {
                let failed = self.hdfs.ns().tree.description_failed(dir);
                self.outcome(
                    "describe",
                    &path,
                    f.decision(),
                    &format!(
                        "{}; answered {}{}",
                        f.detail(),
                        f.thrown().class,
                        failed_suffix(failed)
                    ),
                );
                Err(f.thrown())
            }
        }
    }

    /// Run a check against the namespace, describing whatever directory it needs first.
    /// `held`: the caller holds the gate already.
    async fn settle<T>(
        &self,
        method: &str,
        held: bool,
        limit: usize,
        deadline: tokio::time::Instant,
        check: impl Fn(&Namespace) -> Step<T>,
    ) -> Result<T, Thrown> {
        for _ in 0..limit {
            let r = check(&self.hdfs.ns());
            match r {
                Ok(v) => return Ok(v),
                Err(Halt::Thrown(t)) => return Err(t),
                Err(Halt::Describe(dir)) => {
                    if held {
                        self.describe(dir, method, deadline).await?;
                    } else {
                        let _g = self.gate(deadline).await?;
                        self.describe(dir, method, deadline).await?;
                    }
                }
            }
        }
        Err(Thrown::new(
            class::IO,
            format!("{method} needs more than {limit} directories described"),
        ))
    }

    /// Ask whether a change may happen; the caller holds the gate.
    async fn decide(
        &self,
        op: &str,
        path: &str,
        event_type: &'static EventType,
        mut fields: Map<String, Value>,
        deadline: tokio::time::Instant,
    ) -> Result<(), Thrown> {
        if self.hdfs.settings.read_only {
            self.outcome(op, path, "read_only", "answered SafeModeException");
            return Err(Thrown::new(
                "org.apache.hadoop.hdfs.server.namenode.SafeModeException",
                format!("Cannot {op} {path}. Name node is in safe mode (read_only)."),
            ));
        }
        fields.extend(self.base_fields());
        fields.insert("path".into(), json!(path));
        let event = Event::new(event_type, Value::Object(fields));
        match self
            .hdfs
            .ask(self.id, &event, &[actions::ALLOW, actions::DENY], deadline)
            .await
        {
            Ok(a) if a["type"] == actions::ALLOW => {
                self.outcome(op, path, "model_answer", "allowed");
                Ok(())
            }
            Ok(a) => {
                let (c, m) = denial(&a);
                self.outcome(op, path, "model_reject", &format!("answered {c}"));
                Err(Thrown::new(c, m))
            }
            Err(f) => {
                self.outcome(
                    op,
                    path,
                    f.decision(),
                    &format!("{}; answered {}", f.detail(), f.thrown().class),
                );
                Err(f.thrown())
            }
        }
    }

    fn refused(&self, op: &str, path: &str, t: Thrown) -> CallError {
        self.outcome(
            op,
            path,
            "protocol_refusal",
            &format!("answered {}", t.class),
        );
        CallError::Thrown(t)
    }

    async fn call(
        &mut self,
        method: &str,
        body: &[u8],
        deadline: tokio::time::Instant,
    ) -> CallResult {
        let read = super::MAX_DESCRIBES_PER_CALL;
        match method {
            "getServerDefaults" => {
                let s = &self.hdfs.settings.namespace;
                Ok(pb::GetServerDefaultsResponseProto {
                    server_defaults: pb::FsServerDefaultsProto {
                        block_size: s.block_size,
                        bytes_per_checksum: super::transfer::BYTES_PER_CHECKSUM,
                        write_packet_size: 64 * 1024,
                        replication: s.replication as u32,
                        file_buffer_size: 4096,
                        encrypt_data_transfer: Some(false),
                        trash_interval: Some(0),
                        checksum_type: Some(pb::ChecksumTypeProto::ChecksumCrc32c as i32),
                        key_provider_uri: Some(String::new()),
                        policy_id: Some(0),
                        snapshot_trash_root_enabled: Some(false),
                    },
                }
                .encode_to_vec())
            }
            "getFileInfo" | "getFileLinkInfo" | "getLocatedFileInfo" => {
                let src = match method {
                    "getLocatedFileInfo" => {
                        dec::<pb::GetLocatedFileInfoRequestProto>(body, method)?
                            .src
                            .unwrap_or_default()
                    }
                    "getFileLinkInfo" => dec::<pb::GetFileLinkInfoRequestProto>(body, method)?.src,
                    _ => dec::<pb::GetFileInfoRequestProto>(body, method)?.src,
                };
                let comps = path_of(&src)?;
                let found = self
                    .settle(method, false, read, deadline, |ns| ns.find(&comps))
                    .await?;
                let local = self.local;
                let fs = found.and_then(|ino| {
                    let mut s = self.hdfs.ns().status(ino, b"")?;
                    if method == "getLocatedFileInfo"
                        && s.file_type == pb::hdfs_file_status_proto::FileType::IsFile as i32
                    {
                        let dn = self.hdfs.datanode_info(local);
                        s.locations = Some(self.hdfs.ns().located_blocks(ino, 0, u64::MAX, &dn));
                    }
                    Some(s)
                });
                Ok(match method {
                    "getLocatedFileInfo" => {
                        pb::GetLocatedFileInfoResponseProto { fs }.encode_to_vec()
                    }
                    "getFileLinkInfo" => pb::GetFileLinkInfoResponseProto { fs }.encode_to_vec(),
                    _ => pb::GetFileInfoResponseProto { fs }.encode_to_vec(),
                })
            }
            "getListing" => {
                let r = dec::<pb::GetListingRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let path = joined(&comps);
                let dn = self.hdfs.datanode_info(self.local);
                let listing = self
                    .settle(method, false, read, deadline, |ns| {
                        match ns.find(&comps)? {
                            None => Ok(None),
                            Some(ino) => ns
                                .listing(ino, &path, &r.start_after, r.need_location, &dn)
                                .map(Some),
                        }
                    })
                    .await?;
                Ok(pb::GetListingResponseProto { dir_list: listing }.encode_to_vec())
            }
            "getBlockLocations" => {
                let r = dec::<pb::GetBlockLocationsRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let path = joined(&comps);
                let ino = self
                    .settle(method, false, read, deadline, |ns| ns.lookup(&comps))
                    .await?;
                if self.hdfs.ns().kind(ino) != Some(Kind::File) {
                    return Err(Thrown::new(
                        class::FILE_NOT_FOUND,
                        format!("Path is not a file: {path}"),
                    )
                    .into());
                }
                let dn = self.hdfs.datanode_info(self.local);
                let locations = self.hdfs.ns().located_blocks(ino, r.offset, r.length, &dn);
                Ok(pb::GetBlockLocationsResponseProto {
                    locations: Some(locations),
                }
                .encode_to_vec())
            }
            "mkdirs" => {
                let r = dec::<pb::MkdirsRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let path = joined(&comps);
                let _g = self.gate(deadline).await?;
                let plan = self
                    .settle(method, true, read, deadline, |ns| {
                        ns.plan_mkdirs(&comps, r.create_parent)
                    })
                    .await
                    .map_err(|t| self.refused("mkdirs", &path, t))?;
                if let MkdirsPlan::Create { parent, names } = &plan {
                    let creates: Vec<String> = {
                        let ns = self.hdfs.ns();
                        let mut at = ns.tree.path(*parent);
                        names
                            .iter()
                            .map(|n| {
                                at = if at == "/" {
                                    format!("/{n}")
                                } else {
                                    format!("{at}/{n}")
                                };
                                at.clone()
                            })
                            .collect()
                    };
                    let mut f = Map::new();
                    f.insert("creates".into(), json!(creates));
                    f.insert("mode".into(), json!(r.masked.perm & 0o7777));
                    self.decide("mkdirs", &path, &actions::MKDIRS_EVENT, f, deadline)
                        .await?;
                    let owner = self.user.clone();
                    applied(self.hdfs.ns().apply_mkdirs(
                        &plan,
                        (r.masked.perm & 0o7777) as u16,
                        &owner,
                    ))?;
                }
                Ok(pb::MkdirsResponseProto { result: true }.encode_to_vec())
            }
            "create" => {
                let r = dec::<pb::CreateRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let path = joined(&comps);
                let flag = r.create_flag;
                if flag & (pb::CreateFlagProto::Append as u32) != 0 {
                    // Hadoop's create(APPEND) is append's job; its client never sends it.
                    return Err(self.refused(
                        "create",
                        &path,
                        Thrown::new(
                            class::UNSUPPORTED,
                            "create with the APPEND flag is not supported by this NameNode; call append",
                        ),
                    ));
                }
                let overwrite = flag & (pb::CreateFlagProto::Overwrite as u32) != 0;
                let block_size = namespace::check_block_size(r.block_size).map_err(|e| {
                    self.refused(
                        "create",
                        &path,
                        Thrown::new(
                            class::IO,
                            format!("Specified block size {} is invalid: {e}", r.block_size),
                        ),
                    )
                })?;
                let replication =
                    namespace::check_replication(r.replication as u64).map_err(|e| {
                        self.refused(
                            "create",
                            &path,
                            Thrown::new(
                                class::IO,
                                format!("Requested replication {} is invalid: {e}", r.replication),
                            ),
                        )
                    })?;
                let client = crate::utils::sanitize::token(&r.client_name, 256);
                let _g = self.gate(deadline).await?;
                let plan = self
                    .settle(method, true, read, deadline, |ns| {
                        ns.plan_create(&comps, overwrite, r.create_parent, &client)
                    })
                    .await
                    .map_err(|t| self.refused("create", &path, t))?;
                let parents: Vec<String> = {
                    let ns = self.hdfs.ns();
                    let mut at = ns.tree.path(plan.parent);
                    plan.missing
                        .iter()
                        .map(|n| {
                            at = if at == "/" {
                                format!("/{n}")
                            } else {
                                format!("{at}/{n}")
                            };
                            at.clone()
                        })
                        .collect()
                };
                let mut f = Map::new();
                f.insert("overwrite".into(), json!(overwrite));
                f.insert("replaces".into(), json!(plan.replaces.is_some()));
                f.insert("creates_parents".into(), json!(parents));
                f.insert("mode".into(), json!(r.masked.perm & 0o7777));
                f.insert("replication".into(), json!(replication));
                f.insert("block_size".into(), json!(block_size));
                f.insert("client_name".into(), json!(client));
                self.decide("create", &path, &actions::CREATE_EVENT, f, deadline)
                    .await?;
                let owner = self.user.clone();
                let ino = applied(self.hdfs.ns().apply_create(
                    &plan,
                    (r.masked.perm & 0o7777) as u16,
                    &owner,
                    replication,
                    block_size,
                    &client,
                ))?;
                let fs = self.hdfs.ns().status(ino, b"");
                Ok(pb::CreateResponseProto { fs }.encode_to_vec())
            }
            "addBlock" => {
                let r = dec::<pb::AddBlockRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let path = joined(&comps);
                let dn = self.hdfs.datanode_info(self.local);
                if r.exclude_nodes
                    .iter()
                    .any(|n| n.id.datanode_uuid == dn.id.datanode_uuid)
                {
                    return Err(self.refused("addBlock", &path, Thrown::new(
                        class::IO,
                        format!("File {path} could only be written to 0 of the 1 minReplication nodes. There are 1 datanode(s) running and 1 node(s) are excluded in this operation."),
                    )));
                }
                let client = crate::utils::sanitize::token(&r.client_name, 256);
                let _g = self.gate(deadline).await?;
                let block = {
                    let mut ns = self.hdfs.ns();
                    let ino = applied(ns.file_for(&comps, r.file_id))?;
                    applied(ns.add_block(ino, &path, &client, r.previous.as_ref(), &dn))
                }
                .map_err(|t| self.refused("addBlock", &path, t))?;
                Ok(pb::AddBlockResponseProto { block }.encode_to_vec())
            }
            "abandonBlock" => {
                let r = dec::<pb::AbandonBlockRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let path = joined(&comps);
                let holder = crate::utils::sanitize::token(&r.holder, 256);
                let _g = self.gate(deadline).await?;
                {
                    let mut ns = self.hdfs.ns();
                    let ino = applied(ns.file_for(&comps, r.file_id))?;
                    applied(ns.abandon_block(ino, &path, &holder, r.b.block_id))
                }
                .map_err(|t| self.refused("abandonBlock", &path, t))?;
                Ok(pb::AbandonBlockResponseProto {}.encode_to_vec())
            }
            "complete" => {
                let r = dec::<pb::CompleteRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let path = joined(&comps);
                let client = crate::utils::sanitize::token(&r.client_name, 256);
                let _g = self.gate(deadline).await?;
                let plan = {
                    let ns = self.hdfs.ns();
                    let ino = applied(ns.file_for(&comps, r.file_id))?;
                    applied(ns.plan_complete(ino, &path, &client, r.last.as_ref()))
                }
                .map_err(|t| self.refused("complete", &path, t))?;
                if plan.length > 0 {
                    let head = self.hdfs.ns().staged_preview(plan.ino, super::DATA_PREVIEW);
                    let (data, encoding, truncated) = super::preview(&head, plan.length);
                    let mut f = Map::new();
                    f.insert("length".into(), json!(plan.length));
                    f.insert("blocks".into(), json!(plan.blocks));
                    f.insert("data".into(), json!(data));
                    f.insert("encoding".into(), json!(encoding));
                    f.insert("data_truncated".into(), json!(truncated));
                    f.insert("offset".into(), json!(plan.offset));
                    f.insert("append".into(), json!(plan.append));
                    f.insert("client_name".into(), json!(client));
                    if let Err(t) = self
                        .decide("write", &path, &actions::WRITE_EVENT, f, deadline)
                        .await
                    {
                        // Refused or undecided: the bytes go, the file keeps what it had.
                        self.hdfs.ns().discard(plan.ino);
                        return Err(t.into());
                    }
                }
                let r = self.hdfs.ns().apply_complete(plan.ino, &path);
                applied(r).map_err(|t| self.refused("complete", &path, t))?;
                Ok(pb::CompleteResponseProto { result: true }.encode_to_vec())
            }
            "delete" => {
                let r = dec::<pb::DeleteRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let path = joined(&comps);
                let _g = self.gate(deadline).await?;
                let plan = self
                    .settle(method, true, read, deadline, |ns| {
                        ns.plan_delete(&comps, r.recursive)
                    })
                    .await
                    .map_err(|t| self.refused("delete", &path, t))?;
                let Some(plan) = plan else {
                    return Ok(pb::DeleteResponseProto { result: false }.encode_to_vec());
                };
                let mut f = Map::new();
                f.insert("kind".into(), json!(kind_name(plan.kind)));
                f.insert("recursive".into(), json!(r.recursive));
                self.decide("delete", &path, &actions::DELETE_EVENT, f, deadline)
                    .await?;
                applied(self.hdfs.ns().apply_delete(&plan))?;
                Ok(pb::DeleteResponseProto { result: true }.encode_to_vec())
            }
            "rename" | "rename2" => {
                let (src, dst, overwrite) = if method == "rename" {
                    let r = dec::<pb::RenameRequestProto>(body, method)?;
                    (r.src, r.dst, None)
                } else {
                    let r = dec::<pb::Rename2RequestProto>(body, method)?;
                    (r.src, r.dst, Some(r.overwrite_dest))
                };
                let s = path_of(&src)?;
                let d = path_of(&dst)?;
                let path = joined(&s);
                let _g = self.gate(deadline).await?;
                let plan = self
                    .settle(method, true, read, deadline, |ns| {
                        ns.plan_rename(&s, &d, overwrite)
                    })
                    .await
                    .map_err(|t| self.refused("rename", &path, t))?;
                let reply = |ok: bool| {
                    if method == "rename" {
                        pb::RenameResponseProto { result: ok }.encode_to_vec()
                    } else {
                        pb::Rename2ResponseProto {}.encode_to_vec()
                    }
                };
                let Some(plan) = plan else {
                    self.outcome("rename", &path, "protocol_refusal", "answered false");
                    return Ok(reply(false));
                };
                let mut f = Map::new();
                f.insert("destination".into(), json!(plan.dst_path));
                f.insert("kind".into(), json!(kind_name(plan.kind)));
                f.insert("replaces".into(), json!(plan.replaces));
                self.decide("rename", &path, &actions::RENAME_EVENT, f, deadline)
                    .await?;
                applied(self.hdfs.ns().apply_rename(&plan))?;
                Ok(reply(true))
            }
            "setPermission" => {
                let r = dec::<pb::SetPermissionRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let path = joined(&comps);
                let _g = self.gate(deadline).await?;
                let ino = self
                    .settle(method, true, read, deadline, |ns| ns.lookup(&comps))
                    .await
                    .map_err(|t| self.refused("setPermission", &path, t))?;
                let before = self.hdfs.ns().tree.attr(ino).map(|a| a.perm).unwrap_or(0);
                let mode = (r.permission.perm & 0o7777) as u16;
                let mut f = Map::new();
                f.insert("mode".into(), json!(mode));
                f.insert("mode_before".into(), json!(before));
                self.decide(
                    "setPermission",
                    &path,
                    &actions::SET_PERMISSION_EVENT,
                    f,
                    deadline,
                )
                .await?;
                applied(self.hdfs.ns().set_permission(ino, mode, &path))?;
                Ok(pb::SetPermissionResponseProto {}.encode_to_vec())
            }
            "setOwner" => {
                let r = dec::<pb::SetOwnerRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let path = joined(&comps);
                let check = |v: &Option<String>| match v {
                    Some(s)
                        if s.is_empty()
                            || s.len() > namespace::MAX_PRINCIPAL_BYTES
                            || crate::utils::sanitize::has_controls(s) =>
                    {
                        Err(Thrown::new(
                            class::IO,
                            "An owner or group is 1 to 256 bytes without controls",
                        ))
                    }
                    _ => Ok(()),
                };
                check(&r.username)?;
                check(&r.groupname)?;
                let _g = self.gate(deadline).await?;
                let ino = self
                    .settle(method, true, read, deadline, |ns| ns.lookup(&comps))
                    .await
                    .map_err(|t| self.refused("setOwner", &path, t))?;
                let (owner, group) = self.hdfs.ns().owner_of(ino);
                let mut f = Map::new();
                if let Some(u) = &r.username {
                    f.insert("owner".into(), json!(u));
                }
                if let Some(g) = &r.groupname {
                    f.insert("group".into(), json!(g));
                }
                f.insert("owner_before".into(), json!(owner));
                f.insert("group_before".into(), json!(group));
                self.decide("setOwner", &path, &actions::SET_OWNER_EVENT, f, deadline)
                    .await?;
                self.hdfs
                    .ns()
                    .set_owner(ino, r.username.as_deref(), r.groupname.as_deref());
                Ok(pb::SetOwnerResponseProto {}.encode_to_vec())
            }
            "setTimes" => {
                let r = dec::<pb::SetTimesRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let path = joined(&comps);
                // -1 (all ones as a uint64) leaves a time unchanged.
                let keep = |t: u64| (t as i64 >= 0).then_some(t);
                let (mtime, atime) = (keep(r.mtime), keep(r.atime));
                let _g = self.gate(deadline).await?;
                let ino = self
                    .settle(method, true, read, deadline, |ns| ns.lookup(&comps))
                    .await
                    .map_err(|t| self.refused("setTimes", &path, t))?;
                let mut f = Map::new();
                if let Some(m) = mtime {
                    f.insert("mtime".into(), json!(m));
                }
                if let Some(a) = atime {
                    f.insert("atime".into(), json!(a));
                }
                self.decide("setTimes", &path, &actions::SET_TIMES_EVENT, f, deadline)
                    .await?;
                applied(self.hdfs.ns().set_times(ino, mtime, atime, &path))?;
                Ok(pb::SetTimesResponseProto {}.encode_to_vec())
            }
            "setReplication" => {
                let r = dec::<pb::SetReplicationRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let path = joined(&comps);
                let replication = namespace::check_replication(r.replication as u64)
                    .map_err(|e| Thrown::new(class::IO, format!("{e}")))?;
                let _g = self.gate(deadline).await?;
                let ino = self
                    .settle(method, true, read, deadline, |ns| ns.lookup(&comps))
                    .await
                    .map_err(|t| self.refused("setReplication", &path, t))?;
                if self.hdfs.ns().kind(ino) != Some(Kind::File) {
                    return Ok(pb::SetReplicationResponseProto { result: false }.encode_to_vec());
                }
                let before = self
                    .hdfs
                    .ns()
                    .status(ino, b"")
                    .and_then(|s| s.block_replication)
                    .unwrap_or(0);
                let mut f = Map::new();
                f.insert("replication".into(), json!(replication));
                f.insert("replication_before".into(), json!(before));
                self.decide(
                    "setReplication",
                    &path,
                    &actions::SET_REPLICATION_EVENT,
                    f,
                    deadline,
                )
                .await?;
                self.hdfs.ns().set_replication(ino, replication);
                Ok(pb::SetReplicationResponseProto { result: true }.encode_to_vec())
            }
            "renewLease" => {
                dec::<pb::RenewLeaseRequestProto>(body, method)?;
                Ok(pb::RenewLeaseResponseProto {}.encode_to_vec())
            }
            "recoverLease" => {
                let r = dec::<pb::RecoverLeaseRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let _g = self.gate(deadline).await?;
                let ino = self
                    .settle(method, true, read, deadline, |ns| ns.lookup(&comps))
                    .await?;
                let closed = self.hdfs.ns().recover_lease(ino, Instant::now());
                Ok(pb::RecoverLeaseResponseProto { result: closed }.encode_to_vec())
            }
            "isFileClosed" => {
                let r = dec::<pb::IsFileClosedRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                let ino = self
                    .settle(method, false, read, deadline, |ns| ns.lookup(&comps))
                    .await?;
                let open = self.hdfs.ns().is_open(ino);
                Ok(pb::IsFileClosedResponseProto { result: !open }.encode_to_vec())
            }
            "fsync" => {
                dec::<pb::FsyncRequestProto>(body, method)?;
                Ok(pb::FsyncResponseProto {}.encode_to_vec())
            }
            "getFsStats" => {
                let ns = self.hdfs.ns();
                let capacity = ns.tree.max_overlay();
                let used = ns.tree.overlay_bytes() + ns.reserved();
                Ok(pb::GetFsStatsResponseProto {
                    capacity,
                    used,
                    remaining: capacity.saturating_sub(used),
                    under_replicated: 0,
                    corrupt_blocks: 0,
                    missing_blocks: 0,
                    missing_repl_one_blocks: Some(0),
                    blocks_in_future: Some(0),
                    pending_deletion_blocks: Some(0),
                }
                .encode_to_vec())
            }
            "getContentSummary" | "getQuotaUsage" => {
                let src = if method == "getContentSummary" {
                    dec::<pb::GetContentSummaryRequestProto>(body, method)?.path
                } else {
                    dec::<pb::GetQuotaUsageRequestProto>(body, method)?.path
                };
                let comps = path_of(&src)?;
                let path = joined(&comps);
                let summary = self
                    .settle(
                        method,
                        false,
                        super::MAX_DESCRIBES_PER_SUMMARY,
                        deadline,
                        |ns| {
                            let ino = ns.lookup(&comps)?;
                            ns.content_summary(ino, &path)
                        },
                    )
                    .await?;
                Ok(if method == "getContentSummary" {
                    pb::GetContentSummaryResponseProto { summary }.encode_to_vec()
                } else {
                    pb::GetQuotaUsageResponseProto {
                        usage: pb::QuotaUsageProto {
                            file_and_directory_count: summary.file_count + summary.directory_count,
                            quota: u64::MAX,
                            space_consumed: summary.space_consumed,
                            space_quota: u64::MAX,
                            type_quota_infos: None,
                        },
                    }
                    .encode_to_vec()
                })
            }
            "getPreferredBlockSize" => {
                let r = dec::<pb::GetPreferredBlockSizeRequestProto>(body, method)?;
                let comps = path_of(&r.filename)?;
                let ino = self
                    .settle(method, false, read, deadline, |ns| ns.lookup(&comps))
                    .await?;
                let bsize = self.hdfs.ns().block_size_of(ino);
                Ok(pb::GetPreferredBlockSizeResponseProto { bsize }.encode_to_vec())
            }
            "getLinkTarget" => {
                let r = dec::<pb::GetLinkTargetRequestProto>(body, method)?;
                let comps = path_of(&r.path)?;
                let path = joined(&comps);
                let ino = self
                    .settle(method, false, read, deadline, |ns| ns.lookup(&comps))
                    .await?;
                let target = self.hdfs.ns().tree.readlink(ino).map_err(|_| {
                    Thrown::new(class::IO, format!("Path {path} is not a symbolic link"))
                })?;
                Ok(pb::GetLinkTargetResponseProto {
                    target_path: Some(target),
                }
                .encode_to_vec())
            }
            "checkAccess" => {
                let r = dec::<pb::CheckAccessRequestProto>(body, method)?;
                let comps = path_of(&r.path)?;
                let path = joined(&comps);
                let ino = self
                    .settle(method, false, read, deadline, |ns| ns.lookup(&comps))
                    .await?;
                let mode = (r.mode & 7) as u32;
                if !self.hdfs.ns().may(ino, &self.user, mode) {
                    return Err(Thrown::new(
                        class::ACCESS_CONTROL,
                        format!(
                            "Permission denied: user={}, access={mode:03b}, inode=\"{path}\"",
                            self.user
                        ),
                    )
                    .into());
                }
                Ok(pb::CheckAccessResponseProto {}.encode_to_vec())
            }
            "getStoragePolicy" | "getStoragePolicies" => {
                let hot = pb::BlockStoragePolicyProto {
                    policy_id: 7,
                    name: "HOT".into(),
                    creation_policy: pb::StorageTypesProto {
                        storage_types: vec![pb::StorageTypeProto::Disk as i32],
                    },
                    creation_fallback_policy: Some(pb::StorageTypesProto {
                        storage_types: vec![],
                    }),
                    replication_fallback_policy: Some(pb::StorageTypesProto {
                        storage_types: vec![pb::StorageTypeProto::Archive as i32],
                    }),
                };
                if method == "getStoragePolicy" {
                    let r = dec::<pb::GetStoragePolicyRequestProto>(body, method)?;
                    let comps = path_of(&r.path)?;
                    self.settle(method, false, read, deadline, |ns| ns.lookup(&comps))
                        .await?;
                    Ok(pb::GetStoragePolicyResponseProto {
                        storage_policy: hot,
                    }
                    .encode_to_vec())
                } else {
                    Ok(pb::GetStoragePoliciesResponseProto {
                        policies: vec![hot],
                    }
                    .encode_to_vec())
                }
            }
            "getErasureCodingPolicy" => {
                let r = dec::<pb::GetErasureCodingPolicyRequestProto>(body, method)?;
                let comps = path_of(&r.src)?;
                self.settle(method, false, read, deadline, |ns| ns.lookup(&comps))
                    .await?;
                Ok(pb::GetErasureCodingPolicyResponseProto { ec_policy: None }.encode_to_vec())
            }
            "getDataEncryptionKey" => Ok(pb::GetDataEncryptionKeyResponseProto {
                data_encryption_key: None,
            }
            .encode_to_vec()),
            "getDatanodeReport" => {
                let dn = self.hdfs.datanode_info(self.local);
                Ok(pb::GetDatanodeReportResponseProto { di: vec![dn] }.encode_to_vec())
            }
            "getEnclosingRoot" => Ok(pb::GetEnclosingRootResponseProto {
                enclosing_root_path: Some("/".into()),
            }
            .encode_to_vec()),
            "getHAServiceState" => Ok(pb::HaServiceStateResponseProto {
                state: HaServiceStateProto::Active as i32,
            }
            .encode_to_vec()),
            "msync" => Ok(pb::MsyncResponseProto {}.encode_to_vec()),
            "updateBlockForPipeline" => {
                // A new generation stamp, adopted only when updatePipeline names it. Hadoop's
                // client asks before every append pipeline; colinmarc/hdfs after every block it
                // finishes, ignoring the answer.
                let r = dec::<pb::UpdateBlockForPipelineRequestProto>(body, method)?;
                let client = crate::utils::sanitize::token(&r.client_name, 256);
                let dn = self.hdfs.datanode_info(self.local);
                let block = self
                    .hdfs
                    .ns()
                    .block_for_pipeline(&r.block, &client, &dn)
                    .map_err(|t| self.refused("updateBlockForPipeline", "", t))?;
                Ok(pb::UpdateBlockForPipelineResponseProto { block }.encode_to_vec())
            }
            "updatePipeline" => {
                let r = dec::<pb::UpdatePipelineRequestProto>(body, method)?;
                let client = crate::utils::sanitize::token(&r.client_name, 256);
                let dn = self.hdfs.datanode_info(self.local);
                if r.new_nodes
                    .iter()
                    .any(|n| n.datanode_uuid != dn.id.datanode_uuid)
                {
                    return Err(self.refused(
                        "updatePipeline",
                        "",
                        Thrown::new(
                            class::IO,
                            "Pipeline recovery onto another DataNode is not supported by this NameNode",
                        ),
                    ));
                }
                let _g = self.gate(deadline).await?;
                self.hdfs
                    .ns()
                    .update_pipeline(&r.old_block, &r.new_block, &client)
                    .map_err(|t| self.refused("updatePipeline", "", t))?;
                Ok(pb::UpdatePipelineResponseProto {}.encode_to_vec())
            }
            "getAdditionalDatanode" => {
                let r = dec::<pb::GetAdditionalDatanodeRequestProto>(body, method)?;
                let client = crate::utils::sanitize::token(&r.client_name, 256);
                let dn = self.hdfs.datanode_info(self.local);
                let block = self
                    .hdfs
                    .ns()
                    .block_with_nodes(&r.blk, &client, &dn)
                    .map_err(|t| self.refused("getAdditionalDatanode", "", t))?;
                Ok(pb::GetAdditionalDatanodeResponseProto { block }.encode_to_vec())
            }
            "append" => self.append(body, deadline).await,
            "truncate" => self.truncate(body, deadline).await,
            "concat" => self.concat(body, deadline).await,
            "createSymlink" => Err(Thrown::new(
                class::UNSUPPORTED,
                format!("{method} is not supported by this NameNode"),
            )
            .into()),
            _ => Err(CallError::NoSuchMethod),
        }
    }

    /// append: Rust refuses what HDFS would (a directory, a file open elsewhere, a new block
    /// after a partial one), the model decides, and the file opens for append — its partial
    /// last block reopened and located, or none when the next block starts fresh. The bytes
    /// are decided again, with what the client wrote, at complete.
    async fn append(&mut self, body: &[u8], deadline: tokio::time::Instant) -> CallResult {
        let method = "append";
        let r = dec::<pb::AppendRequestProto>(body, method)?;
        let comps = path_of(&r.src)?;
        let path = joined(&comps);
        let client = crate::utils::sanitize::token(&r.client_name, 256);
        let flag = r.flag.unwrap_or(pb::CreateFlagProto::Append as u32);
        let new_block = flag & (pb::CreateFlagProto::NewBlock as u32) != 0;
        let _g = self.gate(deadline).await?;
        let plan = self
            .settle(
                method,
                true,
                super::MAX_DESCRIBES_PER_CALL,
                deadline,
                |ns| ns.plan_append(&comps, &client, new_block),
            )
            .await
            .map_err(|t| self.refused(method, &path, t))?;
        let mut f = Map::new();
        f.insert("length".into(), json!(plan.length));
        f.insert("block_size".into(), json!(plan.block_size));
        f.insert("last_block_partial".into(), json!(plan.partial));
        f.insert("new_block".into(), json!(new_block));
        f.insert("client_name".into(), json!(client));
        self.decide(method, &path, &actions::APPEND_EVENT, f, deadline)
            .await?;
        let dn = self.hdfs.datanode_info(self.local);
        let (block, stat) = {
            let mut ns = self.hdfs.ns();
            ns.apply_append(&plan, &client);
            (ns.append_block(plan.ino, &dn), ns.status(plan.ino, b""))
        };
        Ok(pb::AppendResponseProto { block, stat }.encode_to_vec())
    }

    /// truncate: true when done at once (a block boundary, or no change); false when the cut
    /// falls inside a block, which then goes through block recovery and the file stays open
    /// (isFileClosed false, its old length reported) until that is done, as Hadoop's NameNode
    /// reports an in-place truncate — what `hdfs dfs -truncate -w` waits for.
    async fn truncate(&mut self, body: &[u8], deadline: tokio::time::Instant) -> CallResult {
        let method = "truncate";
        let r = dec::<pb::TruncateRequestProto>(body, method)?;
        let comps = path_of(&r.src)?;
        let path = joined(&comps);
        let client = crate::utils::sanitize::token(&r.client_name, 256);
        let _g = self.gate(deadline).await?;
        let plan = self
            .settle(
                method,
                true,
                super::MAX_DESCRIBES_PER_CALL,
                deadline,
                |ns| ns.plan_truncate(&comps, r.new_length, &client),
            )
            .await
            .map_err(|t| self.refused(method, &path, t))?;
        if let namespace::TruncatePlan::Cut {
            old,
            new,
            block_size,
            boundary,
            ..
        } = &plan
        {
            let mut f = Map::new();
            f.insert("length".into(), json!(new));
            f.insert("length_before".into(), json!(old));
            f.insert("block_size".into(), json!(block_size));
            f.insert("on_block_boundary".into(), json!(boundary));
            f.insert("client_name".into(), json!(client));
            self.decide(method, &path, &actions::TRUNCATE_EVENT, f, deadline)
                .await?;
        }
        let due = Instant::now() + super::TRUNCATE_RECOVERY;
        let done = applied(self.hdfs.ns().apply_truncate(&plan, &client, &path, due))?;
        if !done {
            self.outcome(
                method,
                &path,
                "accepted",
                "the cut is inside a block: under block recovery; answered false",
            );
        }
        Ok(pb::TruncateResponseProto { result: done }.encode_to_vec())
    }

    /// concat: Hadoop's own checks and this NameNode's (one block size, whole blocks up to the
    /// last source) in Rust, then the model, then the sources' bytes move onto the target and
    /// the sources go.
    async fn concat(&mut self, body: &[u8], deadline: tokio::time::Instant) -> CallResult {
        let method = "concat";
        let r = dec::<pb::ConcatRequestProto>(body, method)?;
        let target = path_of(&r.trg)?;
        let path = joined(&target);
        if r.srcs.len() > namespace::MAX_CONCAT_SOURCES {
            return Err(self.refused(
                method,
                &path,
                Thrown::new(
                    class::HADOOP_ILLEGAL_ARGUMENT,
                    format!(
                        "concat: at most {} source files at once",
                        namespace::MAX_CONCAT_SOURCES
                    ),
                ),
            ));
        }
        let srcs = r
            .srcs
            .iter()
            .map(|s| path_of(s))
            .collect::<Result<Vec<_>, _>>()?;
        let _g = self.gate(deadline).await?;
        let plan = self
            .settle(
                method,
                true,
                super::MAX_DESCRIBES_PER_CALL,
                deadline,
                |ns| ns.plan_concat(&target, &srcs),
            )
            .await
            .map_err(|t| self.refused(method, &path, t))?;
        let mut f = Map::new();
        let sources: Vec<&str> = plan.sources.iter().map(|s| s.2.as_str()).collect();
        f.insert("sources".into(), json!(sources));
        f.insert("length_before".into(), json!(plan.length_before));
        f.insert("length".into(), json!(plan.length_after));
        f.insert("block_size".into(), json!(plan.block_size));
        self.decide(method, &path, &actions::CONCAT_EVENT, f, deadline)
            .await?;
        let r = self.hdfs.ns().apply_concat(&plan, &path);
        applied(r).map_err(|t| self.refused(method, &path, t))?;
        Ok(pb::ConcatResponseProto {}.encode_to_vec())
    }
}
