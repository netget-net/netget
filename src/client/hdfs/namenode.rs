//! A Hadoop IPC connection to a NameNode: the `hrpc` header (SIMPLE authentication, no SASL),
//! the connection context naming the user, then ClientNamenodeProtocol calls one at a time,
//! each response matched to its call id. A response for any other call id, a fatal response or
//! a transport failure ends the connection.
use crate::server::hdfs::proto::common::{
    rpc_response_header_proto::RpcStatusProto, IpcConnectionContextProto, UserInformationProto,
};
use crate::server::hdfs::rpc;
use anyhow::{bail, Context, Result};
use prost::Message;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// How long a call may take, the NameNode's own work included.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(60);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a call failed.
#[derive(Debug)]
pub enum CallError {
    /// The NameNode answered with an exception (the connection stays usable unless fatal).
    Remote {
        class: String,
        message: String,
        fatal: bool,
    },
    /// The connection or the response was broken; the connection is unusable.
    Transport(anyhow::Error),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Remote { class, message, .. } => write!(f, "{class}: {message}"),
            CallError::Transport(e) => write!(f, "{e:#}"),
        }
    }
}

pub struct NameNode {
    stream: TcpStream,
    client_id: [u8; 16],
    next_call: i32,
    pub calls: u64,
}

impl NameNode {
    pub async fn connect(addr: SocketAddr, user: &str) -> Result<Self> {
        let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .context("connecting to the NameNode timed out")?
            .with_context(|| format!("connecting to the NameNode at {addr}"))?;
        let _ = stream.set_nodelay(true);
        let client_id = *uuid::Uuid::new_v4().as_bytes();
        let mut hello = rpc::connection_header(rpc::AUTH_NONE).to_vec();
        hello.extend_from_slice(&rpc::header_frame(
            rpc::CONNECTION_CONTEXT_CALL_ID,
            &client_id,
            &IpcConnectionContextProto {
                user_info: Some(UserInformationProto {
                    effective_user: Some(user.to_string()),
                    real_user: None,
                }),
                protocol: Some(rpc::CLIENT_PROTOCOL.into()),
            },
        ));
        stream.write_all(&hello).await?;
        Ok(Self {
            stream,
            client_id,
            next_call: 0,
            calls: 0,
        })
    }

    /// One call: send it, read the response for this call id.
    pub async fn call<Req: Message, Resp: Message + Default>(
        &mut self,
        method: &str,
        request: &Req,
    ) -> std::result::Result<Resp, CallError> {
        let call_id = self.next_call;
        self.next_call = self.next_call.wrapping_add(1).max(0);
        self.calls += 1;
        let frame = rpc::call_frame(call_id, &self.client_id, method, request);
        self.stream
            .write_all(&frame)
            .await
            .map_err(|e| CallError::Transport(e.into()))?;
        let reply = rpc::read_frame(
            &mut self.stream,
            rpc::MAX_RESPONSE_FRAME,
            CALL_TIMEOUT,
            CALL_TIMEOUT,
        )
        .await
        .map_err(|e| CallError::Transport(anyhow::anyhow!("{method}: {e}")))?;
        let (header, rest) = rpc::decode_response(&reply)
            .map_err(|e| CallError::Transport(e.context("an invalid response header")))?;
        let status = header.status;
        let answered = rpc::response_call_id(&header);
        if status == RpcStatusProto::Fatal as i32 {
            return Err(CallError::Remote {
                class: header.exception_class_name.unwrap_or_default(),
                message: header.error_msg.unwrap_or_default(),
                fatal: true,
            });
        }
        if answered != call_id {
            return Err(CallError::Transport(anyhow::anyhow!(
                "the NameNode answered call {answered} while call {call_id} ({method}) was outstanding"
            )));
        }
        if status == RpcStatusProto::Error as i32 {
            return Err(CallError::Remote {
                class: header.exception_class_name.unwrap_or_default(),
                message: header.error_msg.unwrap_or_default(),
                fatal: false,
            });
        }
        if status != RpcStatusProto::Success as i32 {
            return Err(CallError::Transport(anyhow::anyhow!(
                "an unknown response status {status}"
            )));
        }
        let (body, _) = rpc::delimited(rest)
            .map_err(|e| CallError::Transport(e.context("the response has no message")))?;
        Resp::decode(body).map_err(|e| {
            CallError::Transport(anyhow::anyhow!(
                "the {method} response does not decode: {e}"
            ))
        })
    }

    /// Close politely; nothing is answered.
    pub async fn close(&mut self) {
        let _ = self.stream.shutdown().await;
    }
}

/// A NameNode's exceptions arrive as a class name and a message; this is how a client error
/// that is not one (a broken connection) is told apart.
pub fn remote(e: &CallError) -> Option<(&str, &str)> {
    match e {
        CallError::Remote { class, message, .. } => Some((class, message)),
        CallError::Transport(_) => None,
    }
}

pub fn ensure_absolute(path: &str) -> Result<()> {
    if !path.starts_with('/') {
        bail!("{path} is not an absolute path");
    }
    Ok(())
}
