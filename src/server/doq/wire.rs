//! RFC 9250 framing shared by the two DoQ endpoints. This is deliberately not DoT:
//! each stream carries one transaction, IDs are zero, and FIN is part of the frame.
use anyhow::{bail, ensure, Context, Result};
use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::rdata::opt::EdnsCode;
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
use std::sync::Arc;
use std::time::Duration;

pub const MAX_MESSAGE_BYTES: usize = u16::MAX as usize;
pub const MAX_FRAME_BYTES: usize = MAX_MESSAGE_BYTES + 2;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long an answer the server has ready may wait on the peer's flow control before the
/// stream is reset with DOQ_INTERNAL_ERROR. Separate from the exchange deadline so a SERVFAIL
/// written when that deadline passes still has time to go out.
pub const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const MAX_CONNECTIONS: usize = 64;
pub const MAX_STREAMS: usize = 32;
pub const NO_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0);
pub const INTERNAL_ERROR: quinn::VarInt = quinn::VarInt::from_u32(1);
pub const PROTOCOL_ERROR: quinn::VarInt = quinn::VarInt::from_u32(2);
pub const REQUEST_CANCELLED: quinn::VarInt = quinn::VarInt::from_u32(3);
pub const EXCESSIVE_LOAD: quinn::VarInt = quinn::VarInt::from_u32(4);
pub const UNSPECIFIED_ERROR: quinn::VarInt = quinn::VarInt::from_u32(5);

pub fn encode(message: &Message) -> Result<Vec<u8>> {
    ensure!(message.id == 0, "DoQ DNS message ID must be zero");
    frame(&message.to_vec()?)
}

/// Frame an encoded DNS message for a DoQ stream: its 2-octet length, then the message
/// (RFC 9250 §4.2). Refuses a message whose id is not zero (§4.2.1) and one too long for the
/// length field, rather than putting either on the wire.
pub fn frame(message: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        message.len() >= 12,
        "a DNS message is at least its 12-byte header"
    );
    ensure!(message[..2] == [0, 0], "DoQ DNS message ID must be zero");
    let length = u16::try_from(message.len()).context("DoQ DNS message exceeds 65535 bytes")?;
    let mut frame = Vec::with_capacity(message.len() + 2);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(message);
    Ok(frame)
}

pub fn decode(frame: &[u8], expected: MessageType) -> Result<Message> {
    ensure!(
        frame.len() >= 14 && frame.len() <= MAX_FRAME_BYTES,
        "Invalid DoQ frame size"
    );
    let length = u16::from_be_bytes([frame[0], frame[1]]) as usize;
    ensure!(
        length + 2 == frame.len(),
        "DoQ stream must contain exactly one complete DNS message"
    );
    crate::utils::dns_screen::screen_dns_message(&frame[2..])
        .map_err(|reason| anyhow::anyhow!("Invalid DoQ DNS message: {reason}"))?;
    let mut decoder = BinDecoder::new(&frame[2..]);
    let message = Message::read(&mut decoder).context("Invalid DoQ DNS message")?;
    ensure!(decoder.is_empty(), "Trailing bytes after DoQ DNS message");
    ensure!(message.id == 0, "DoQ DNS message ID must be zero");
    ensure!(
        message.message_type == expected,
        "Unexpected DNS message direction"
    );
    // EDNS TCP keepalive is a connection-level error on a QUIC transport (RFC 9250 4.3.3).
    ensure!(
        message
            .edns
            .as_ref()
            .is_none_or(|edns| edns.options().get(EdnsCode::Keepalive).is_none()),
        "EDNS TCP keepalive is forbidden on DoQ"
    );
    Ok(message)
}

pub fn transport(idle: Duration, incoming_bidi: u32) -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(incoming_bidi.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport.max_idle_timeout(Some(idle.try_into().expect("bounded idle timeout")));
    transport.stream_receive_window((MAX_FRAME_BYTES as u32).into());
    transport.receive_window((MAX_FRAME_BYTES as u32 * MAX_STREAMS as u32).into());
    Arc::new(transport)
}

/// Closing on Drop matters when the owning registered task is aborted during removal.
/// Quinn's driver otherwise retains the endpoint until all connection handles disappear.
pub struct EndpointGuard(pub quinn::Endpoint);
impl Drop for EndpointGuard {
    fn drop(&mut self) {
        self.0.close(NO_ERROR, b"endpoint stopped");
    }
}
pub struct ConnectionGuard(pub quinn::Connection);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.close(NO_ERROR, b"connection stopped");
    }
}

pub fn parameter(
    name: &str,
    description: &str,
    example: serde_json::Value,
    default: Option<serde_json::Value>,
) -> crate::llm::actions::ParameterDefinition {
    crate::llm::actions::ParameterDefinition {
        name: name.into(),
        description: description.into(),
        type_hint: if example.is_number() {
            "number"
        } else {
            "string"
        }
        .into(),
        required: false,
        example,
        default,
    }
}

pub fn bounded_parameter(
    params: Option<&crate::protocol::StartupParams>,
    name: &str,
    default: u64,
    max: u64,
) -> Result<u64> {
    let value = params
        .map(|p| p.get_optional_u64(name))
        .transpose()?
        .flatten()
        .unwrap_or(default);
    if value == 0 || value > max {
        bail!("{name} must be between 1 and {max}");
    }
    Ok(value)
}
