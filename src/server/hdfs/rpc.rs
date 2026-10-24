//! Hadoop IPC, RPC version 9: the connection header, length-prefixed frames of varint-delimited
//! protocol buffers, call ids, and the success/error/fatal response header with the Java
//! exception class a Hadoop client turns into a `RemoteException`. Shared by the NameNode and
//! the HDFS client, and by the fuzz target, so every bound here holds in all three.
//!
//! A connection opens with `hrpc`, the version (9), the service class and the auth protocol (0
//! none, -33 SASL). Every frame after it is a four-byte big-endian length and that many bytes:
//! a varint-delimited `RpcRequestHeaderProto`, then (for a call) a delimited
//! `RequestHeaderProto` naming the method and a delimited request message. A response is a
//! frame holding a delimited `RpcResponseHeaderProto` and, on success, the delimited response.
use super::proto::common::{
    rpc_request_header_proto::OperationProto, rpc_response_header_proto::RpcErrorCodeProto,
    rpc_response_header_proto::RpcStatusProto, RequestHeaderProto, RpcKindProto,
    RpcRequestHeaderProto, RpcResponseHeaderProto,
};
use anyhow::{bail, ensure, Context, Result};
use prost::Message;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const MAGIC: &[u8; 4] = b"hrpc";
pub const IPC_VERSION: u8 = 9;
/// The connection header's auth protocol: none (SIMPLE without SASL) or SASL (-33).
pub const AUTH_NONE: u8 = 0;
pub const AUTH_SASL: u8 = 0xDF;
/// Call ids the IPC layer reserves.
pub const CONNECTION_CONTEXT_CALL_ID: i32 = -3;
pub const PING_CALL_ID: i32 = -4;
pub const SASL_CALL_ID: i32 = -33;
pub const INVALID_CALL_ID: i32 = -1;
/// The protocol every HDFS client call names.
pub const CLIENT_PROTOCOL: &str = "org.apache.hadoop.hdfs.protocol.ClientProtocol";
pub const CLIENT_PROTOCOL_VERSION: u64 = 1;
/// The largest frame the NameNode reads. Hadoop's own default (`ipc.maximum.data.length`) is
/// 64 MB; no ClientProtocol request comes near 1 MiB, so a larger one is refused from its
/// length before anything else is read.
pub const MAX_REQUEST_FRAME: usize = 1 << 20;
/// The largest frame the client reads: a listing page or the block list of a large file.
pub const MAX_RESPONSE_FRAME: usize = 16 << 20;
/// The varint in front of a delimited message is at most five bytes (a 32-bit length).
const MAX_VARINT_BYTES: usize = 5;

/// What the seven bytes opening a connection say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionHeader {
    pub version: u8,
    pub service_class: u8,
    pub auth_protocol: u8,
}

pub fn connection_header(auth_protocol: u8) -> [u8; 7] {
    [b'h', b'r', b'p', b'c', IPC_VERSION, 0, auth_protocol]
}

/// Parse the connection header; `Err` when the magic is not `hrpc`.
pub fn parse_connection_header(b: &[u8; 7]) -> Result<ConnectionHeader> {
    ensure!(&b[..4] == MAGIC, "the connection does not start with hrpc");
    Ok(ConnectionHeader {
        version: b[4],
        service_class: b[5],
        auth_protocol: b[6],
    })
}

/// Why a frame could not be read.
#[derive(Debug)]
pub enum FrameError {
    /// The peer closed the connection before a frame began.
    Closed,
    /// Nothing arrived before the idle deadline.
    Idle,
    /// The first byte of a frame arrived and the rest did not arrive in time.
    Timeout,
    /// The length prefix is larger than the bound; nothing past it was read.
    TooLarge(usize),
    Io(std::io::Error),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Closed => write!(f, "the peer closed the connection"),
            FrameError::Idle => write!(f, "no frame began before the idle deadline"),
            FrameError::Timeout => write!(f, "the rest of a frame did not arrive in time"),
            FrameError::TooLarge(n) => write!(f, "a frame of {n} bytes is over the bound"),
            FrameError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Read one frame: wait up to `idle` for its first byte, then up to `rest` for the remainder.
/// The length is checked against `max` before any of the body is read.
pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
    idle: Duration,
    rest: Duration,
) -> std::result::Result<Vec<u8>, FrameError> {
    let mut len = [0u8; 4];
    match tokio::time::timeout(idle, r.read(&mut len[..1])).await {
        Err(_) => return Err(FrameError::Idle),
        Ok(Err(e)) => return Err(FrameError::Io(e)),
        Ok(Ok(0)) => return Err(FrameError::Closed),
        Ok(Ok(_)) => {}
    }
    let body = async {
        r.read_exact(&mut len[1..]).await?;
        let n = u32::from_be_bytes(len) as usize;
        if n > max {
            return Ok(Err(n));
        }
        let mut buf = vec![0u8; n];
        r.read_exact(&mut buf).await?;
        Ok::<_, std::io::Error>(Ok(buf))
    };
    match tokio::time::timeout(rest, body).await {
        Err(_) => Err(FrameError::Timeout),
        Ok(Err(e)) => Err(FrameError::Io(e)),
        Ok(Ok(Err(n))) => Err(FrameError::TooLarge(n)),
        Ok(Ok(Ok(buf))) => Ok(buf),
    }
}

/// A varint-delimited message at the front of `buf`: its bytes and what follows.
pub fn delimited(buf: &[u8]) -> Result<(&[u8], &[u8])> {
    let mut len: u64 = 0;
    for (i, b) in buf.iter().take(MAX_VARINT_BYTES).enumerate() {
        len |= ((b & 0x7F) as u64) << (7 * i);
        if b & 0x80 == 0 {
            let start = i + 1;
            let end = start
                .checked_add(len as usize)
                .context("a delimited length overflows")?;
            ensure!(
                len <= u32::MAX as u64 && end <= buf.len(),
                "a delimited message of {len} bytes runs past its frame"
            );
            return Ok((&buf[start..end], &buf[end..]));
        }
    }
    bail!("a delimited message has no complete length")
}

/// Decode the delimited message at the front of `buf`.
pub fn decode_delimited<M: Message + Default>(buf: &[u8]) -> Result<(M, &[u8])> {
    let (bytes, rest) = delimited(buf)?;
    Ok((
        M::decode(bytes).context("a malformed protocol buffer")?,
        rest,
    ))
}

/// A frame: the four-byte length, then the parts.
pub fn frame(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut out = Vec::with_capacity(4 + total);
    out.extend_from_slice(&(total as u32).to_be_bytes());
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// A request frame's header and the rest of the frame.
pub fn decode_request(frame: &[u8]) -> Result<(RpcRequestHeaderProto, &[u8])> {
    let (header, rest) = decode_delimited::<RpcRequestHeaderProto>(frame)?;
    Ok((header, rest))
}

/// A call's method header and the request message bytes after it.
pub fn decode_call(rest: &[u8]) -> Result<(RequestHeaderProto, &[u8])> {
    let (method, rest) = decode_delimited::<RequestHeaderProto>(rest)?;
    let (body, _) = delimited(rest).context("the call has no request message")?;
    Ok((method, body))
}

pub fn request_header(call_id: i32, client_id: &[u8], retry: i32) -> RpcRequestHeaderProto {
    RpcRequestHeaderProto {
        rpc_kind: Some(RpcKindProto::RpcProtocolBuffer as i32),
        rpc_op: Some(OperationProto::RpcFinalPacket as i32),
        call_id,
        client_id: client_id.to_vec(),
        retry_count: Some(retry),
        ..Default::default()
    }
}

/// A call frame: the RPC header, the method header and the request.
pub fn call_frame(call_id: i32, client_id: &[u8], method: &str, request: &impl Message) -> Vec<u8> {
    let header = request_header(call_id, client_id, 0).encode_length_delimited_to_vec();
    let method = RequestHeaderProto {
        method_name: method.into(),
        declaring_class_protocol_name: CLIENT_PROTOCOL.into(),
        client_protocol_version: CLIENT_PROTOCOL_VERSION,
    }
    .encode_length_delimited_to_vec();
    let body = request.encode_length_delimited_to_vec();
    frame(&[&header, &method, &body])
}

/// A frame of the RPC header and one message (the connection context, a SASL message).
pub fn header_frame(call_id: i32, client_id: &[u8], message: &impl Message) -> Vec<u8> {
    let header = request_header(call_id, client_id, -1).encode_length_delimited_to_vec();
    let body = message.encode_length_delimited_to_vec();
    frame(&[&header, &body])
}

fn response_header(call_id: i32, client_id: &[u8], retry: i32) -> RpcResponseHeaderProto {
    RpcResponseHeaderProto {
        // The field is uint32 on the wire; the reserved negative ids travel as their two's
        // complement, as Hadoop's own server writes them.
        call_id: call_id as u32,
        status: RpcStatusProto::Success as i32,
        server_ipc_version_num: Some(IPC_VERSION as u32),
        client_id: Some(client_id.to_vec()),
        retry_count: Some(retry),
        ..Default::default()
    }
}

/// A successful response carrying `body`.
pub fn success(call_id: i32, client_id: &[u8], retry: i32, body: &impl Message) -> Vec<u8> {
    let header = response_header(call_id, client_id, retry).encode_length_delimited_to_vec();
    let body = body.encode_length_delimited_to_vec();
    frame(&[&header, &body])
}

/// A successful response carrying an already encoded message.
pub fn success_encoded(call_id: i32, client_id: &[u8], retry: i32, body: &[u8]) -> Vec<u8> {
    let header = response_header(call_id, client_id, retry).encode_length_delimited_to_vec();
    let mut delimited = Vec::with_capacity(body.len() + MAX_VARINT_BYTES);
    prost::encoding::encode_varint(body.len() as u64, &mut delimited);
    delimited.extend_from_slice(body);
    frame(&[&header, &delimited])
}

/// An error (the connection stays open) or fatal (it closes) response naming a Java exception.
pub fn failure(
    call_id: i32,
    client_id: &[u8],
    retry: i32,
    fatal: bool,
    class: &str,
    message: &str,
    code: RpcErrorCodeProto,
) -> Vec<u8> {
    let mut header = response_header(call_id, client_id, retry);
    let status = if fatal {
        RpcStatusProto::Fatal
    } else {
        RpcStatusProto::Error
    };
    header.status = status as i32;
    header.exception_class_name = Some(class.into());
    header.error_msg = Some(message.into());
    header.error_detail = Some(code as i32);
    frame(&[&header.encode_length_delimited_to_vec()])
}

/// A response frame's header and the rest of the frame.
pub fn decode_response(frame: &[u8]) -> Result<(RpcResponseHeaderProto, &[u8])> {
    decode_delimited::<RpcResponseHeaderProto>(frame)
}

/// The call id a response header names, back as the signed id the request carried.
pub fn response_call_id(h: &RpcResponseHeaderProto) -> i32 {
    h.call_id as i32
}

/// The exceptions a refusal may name: the short name a model uses, and the Java class a Hadoop
/// client reconstructs. Hadoop's `RemoteException.unwrapRemoteException` instantiates the class
/// by name, so these must be exact.
pub const EXCEPTIONS: &[(&str, &str)] = &[
    (
        "AccessControlException",
        "org.apache.hadoop.security.AccessControlException",
    ),
    ("FileNotFoundException", "java.io.FileNotFoundException"),
    (
        "FileAlreadyExistsException",
        "org.apache.hadoop.fs.FileAlreadyExistsException",
    ),
    (
        "ParentNotDirectoryException",
        "org.apache.hadoop.fs.ParentNotDirectoryException",
    ),
    (
        "PathIsNotEmptyDirectoryException",
        "org.apache.hadoop.fs.PathIsNotEmptyDirectoryException",
    ),
    (
        "DSQuotaExceededException",
        "org.apache.hadoop.hdfs.protocol.DSQuotaExceededException",
    ),
    (
        "NSQuotaExceededException",
        "org.apache.hadoop.hdfs.protocol.NSQuotaExceededException",
    ),
    (
        "SafeModeException",
        "org.apache.hadoop.hdfs.server.namenode.SafeModeException",
    ),
    (
        "InvalidPathException",
        "org.apache.hadoop.fs.InvalidPathException",
    ),
    ("IOException", "java.io.IOException"),
];

/// The class for a short exception name (or a full class name already in the list).
pub fn exception_class(name: &str) -> Option<&'static str> {
    EXCEPTIONS
        .iter()
        .find(|(short, full)| *short == name || *full == name)
        .map(|(_, full)| *full)
}

/// The short names, for action descriptions and refusal messages.
pub fn exception_names() -> String {
    EXCEPTIONS
        .iter()
        .map(|(s, _)| *s)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Classes NetGet's own refusals use that the model does not name.
pub mod class {
    pub const IO: &str = "java.io.IOException";
    pub const FILE_NOT_FOUND: &str = "java.io.FileNotFoundException";
    pub const ACCESS_CONTROL: &str = "org.apache.hadoop.security.AccessControlException";
    pub const ALREADY_EXISTS: &str = "org.apache.hadoop.fs.FileAlreadyExistsException";
    pub const PARENT_NOT_DIRECTORY: &str = "org.apache.hadoop.fs.ParentNotDirectoryException";
    pub const NOT_EMPTY: &str = "org.apache.hadoop.fs.PathIsNotEmptyDirectoryException";
    pub const INVALID_PATH: &str = "org.apache.hadoop.fs.InvalidPathException";
    pub const QUOTA: &str = "org.apache.hadoop.hdfs.protocol.DSQuotaExceededException";
    pub const NS_QUOTA: &str = "org.apache.hadoop.hdfs.protocol.NSQuotaExceededException";
    pub const LEASE_EXPIRED: &str = "org.apache.hadoop.hdfs.server.namenode.LeaseExpiredException";
    pub const ALREADY_BEING_CREATED: &str =
        "org.apache.hadoop.hdfs.protocol.AlreadyBeingCreatedException";
    pub const UNSUPPORTED: &str = "java.lang.UnsupportedOperationException";
    pub const NO_SUCH_METHOD: &str = "org.apache.hadoop.ipc.RpcNoSuchMethodException";
    pub const NO_SUCH_PROTOCOL: &str = "org.apache.hadoop.ipc.RpcNoSuchProtocolException";
    pub const RETRIABLE: &str = "org.apache.hadoop.ipc.RetriableException";
    pub const RECOVERY_IN_PROGRESS: &str =
        "org.apache.hadoop.hdfs.protocol.RecoveryInProgressException";
    pub const HADOOP_ILLEGAL_ARGUMENT: &str = "org.apache.hadoop.HadoopIllegalArgumentException";
    pub const ILLEGAL_ARGUMENT: &str = "java.lang.IllegalArgumentException";
    pub const VERSION_MISMATCH: &str = "org.apache.hadoop.ipc.RPC$VersionMismatch";
    pub const SERVER: &str = "org.apache.hadoop.ipc.RpcServerException";
}

/// Whether a request header asks to close the connection (RPC_CLOSE_CONNECTION).
pub fn is_close(h: &RpcRequestHeaderProto) -> bool {
    h.rpc_op == Some(OperationProto::RpcCloseConnection as i32)
}
