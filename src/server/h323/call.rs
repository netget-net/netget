//! One H.225.0 call-signalling leg: the Q.931 messages of a call on its TCP connection, the
//! H.225.0 UUIE each carries, the call reference and identifiers, tunnelled H.245, and the
//! RTP/RTCP sockets this side advertises. Shared by the endpoint server (the called side) and
//! the client (the calling side).

use super::h225::{self, UserInformation};
use super::h245::{self, Codec, H245Session, Media};
use super::q931::{self, ie, msg, Q931};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::UdpSocket;

/// The Q.850 causes NetGet writes.
pub mod cause {
    pub const UNALLOCATED_NUMBER: u8 = 1;
    pub const NORMAL_CLEARING: u8 = 16;
    pub const USER_BUSY: u8 = 17;
    pub const NO_ANSWER: u8 = 19;
    pub const CALL_REJECTED: u8 = 21;
    pub const NORMAL_UNSPECIFIED: u8 = 31;
    pub const TEMPORARY_FAILURE: u8 = 41;
    pub const CONGESTION: u8 = 42;
    pub const INVALID_CALL_REFERENCE: u8 = 81;
    pub const INCOMPATIBLE_DESTINATION: u8 = 88;
    pub const PROTOCOL_ERROR: u8 = 111;
}

/// The `ReleaseCompleteReason` alternatives the model may name.
pub const RELEASE_REASONS: &[&str] = &[
    "noBandwidth",
    "gatekeeperResources",
    "unreachableDestination",
    "destinationRejection",
    "invalidRevision",
    "noPermission",
    "unreachableGatekeeper",
    "gatewayResources",
    "badFormatAddress",
    "adaptiveBusy",
    "inConf",
    "undefinedReason",
    "facilityCallDeflection",
    "securityDenied",
    "calledPartyNotRegistered",
    "callerNotRegistered",
    "newConnectionNeeded",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// This side received the Setup.
    Callee,
    /// This side sent the Setup.
    Caller,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// Setup sent or received, nothing else yet.
    Offered,
    Proceeding,
    Alerting,
    Connected,
    Released,
}

impl CallState {
    pub fn name(self) -> &'static str {
        match self {
            CallState::Offered => "offered",
            CallState::Proceeding => "proceeding",
            CallState::Alerting => "alerting",
            CallState::Connected => "connected",
            CallState::Released => "released",
        }
    }
}

/// The RTP and RTCP sockets a call advertises. NetGet sends no media; it counts the packets
/// the peer sends, which is what says whether the addresses it negotiated were used.
pub struct MediaSockets {
    pub rtp: SocketAddr,
    pub rtcp: SocketAddr,
    pub packets: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl MediaSockets {
    /// Bind an RTP/RTCP pair (an even port and the next) on `ip`.
    pub async fn bind(ip: IpAddr) -> Result<Self> {
        let mut last_err = None;
        for _ in 0..16 {
            let first = UdpSocket::bind(SocketAddr::new(ip, 0)).await?;
            let port = first.local_addr()?.port();
            let even = port & !1;
            let pair = if port == even {
                UdpSocket::bind(SocketAddr::new(ip, even.wrapping_add(1)))
                    .await
                    .map(|second| (first, second))
            } else {
                drop(first);
                match UdpSocket::bind(SocketAddr::new(ip, even)).await {
                    Ok(a) => UdpSocket::bind(SocketAddr::new(ip, even + 1))
                        .await
                        .map(|b| (a, b)),
                    Err(e) => Err(e),
                }
            };
            match pair {
                Ok((rtp, rtcp)) => {
                    let packets = Arc::new(AtomicU64::new(0));
                    let rtp_addr = rtp.local_addr()?;
                    let rtcp_addr = rtcp.local_addr()?;
                    let count = packets.clone();
                    let task = tokio::spawn(async move {
                        let mut a = [0u8; 2048];
                        let mut b = [0u8; 2048];
                        loop {
                            tokio::select! {
                                r = rtp.recv_from(&mut a) => if r.is_err() { break },
                                r = rtcp.recv_from(&mut b) => if r.is_err() { break },
                            }
                            count.fetch_add(1, Ordering::Relaxed);
                        }
                    });
                    return Ok(Self {
                        rtp: rtp_addr,
                        rtcp: rtcp_addr,
                        packets,
                        task,
                    });
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err
            .map(anyhow::Error::from)
            .unwrap_or_else(|| anyhow::anyhow!("no RTP port pair")))
        .context("binding RTP/RTCP")
    }

    pub fn received(&self) -> u64 {
        self.packets.load(Ordering::Relaxed)
    }
}

impl Drop for MediaSockets {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// What an incoming message meant for the call.
#[derive(Debug, Clone)]
pub enum Incoming {
    Proceeding,
    Alerting,
    Connected,
    Released {
        cause: Option<u8>,
        reason: Option<String>,
    },
    Forwarded {
        address: Option<SocketAddr>,
        aliases: Vec<String>,
    },
    /// A Facility, Progress, Status, Information or Notify that changes nothing NetGet tracks.
    Other(&'static str),
    /// A second Setup on a connection whose call is already up.
    UnexpectedSetup,
    /// A message for another call: its call reference value, or its call reference flag
    /// (Q.931 4.3: set by the side that did not allocate the reference), is not this call's.
    WrongCallReference {
        crv: u16,
        from_destination: bool,
    },
}

pub struct CallLeg {
    writer: OwnedWriteHalf,
    pub crv: u16,
    pub role: Role,
    pub call_id: String,
    pub conference_id: String,
    /// The peer said `h245Tunnelling: TRUE`; NetGet always does.
    pub peer_tunnelling: bool,
    pub h245: H245Session,
    pub state: CallState,
    pub media: MediaSockets,
    /// Agreed through fastStart, when it was.
    pub fast_start: Option<Media>,
    /// Codecs this side accepts, in order of preference.
    pub codecs: Vec<Codec>,
    pub bytes_sent: u64,
    /// The H.225.0 message names this side sent, in order.
    pub sent: Vec<&'static str>,
    /// fastStart proposals from the caller (callee side only).
    pub offered_fast_start: Vec<Vec<u8>>,
    /// The call reached Connect at some point (it may since have been released).
    pub ever_connected: bool,
    pending_h245: Vec<Vec<u8>>,
}

impl CallLeg {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        writer: OwnedWriteHalf,
        crv: u16,
        role: Role,
        call_id: String,
        conference_id: String,
        peer_tunnelling: bool,
        media: MediaSockets,
        codecs: Vec<Codec>,
    ) -> Self {
        let h245 = H245Session::new(codecs.clone(), media.rtp, media.rtcp);
        Self {
            writer,
            crv,
            role,
            call_id,
            conference_id,
            peer_tunnelling,
            h245,
            state: CallState::Offered,
            media,
            fast_start: None,
            codecs,
            bytes_sent: 0,
            sent: Vec::new(),
            offered_fast_start: Vec::new(),
            ever_connected: false,
            pending_h245: Vec::new(),
        }
    }

    pub fn tunnelling(&self) -> bool {
        self.peer_tunnelling
    }

    /// Queue an H.245 message to go out tunnelled with the next H.225.0 message (or
    /// [`CallLeg::flush_h245`]).
    pub fn queue_h245(&mut self, m: Vec<u8>) {
        self.pending_h245.push(m);
    }

    fn call_identifier(&self) -> Value {
        json!({"guid": self.call_id})
    }

    /// Write one Q.931 message carrying an H.225.0 UUIE (and any H.245 waiting to go).
    pub async fn send(
        &mut self,
        message_type: u8,
        kind: &str,
        body: Value,
        extra_ies: Vec<(u8, Vec<u8>)>,
    ) -> Result<()> {
        let h245 = if self.tunnelling() {
            std::mem::take(&mut self.pending_h245)
        } else {
            Vec::new()
        };
        let uu = h225::encode_user_information(kind, body, true, &h245)?;
        let mut m = Q931::new(message_type, self.crv, self.role == Role::Callee);
        for (id, contents) in extra_ies {
            m = m.with_ie(id, contents);
        }
        let bytes = q931::tpkt(&m.with_user_user(&uu).encode()?)?;
        self.writer.write_all(&bytes).await?;
        self.bytes_sent += bytes.len() as u64;
        self.sent.push(q931::message_name(message_type));
        Ok(())
    }

    /// Send whatever H.245 is waiting, in a Facility with an empty body (H.225.0 v4).
    pub async fn flush_h245(&mut self) -> Result<()> {
        if self.pending_h245.is_empty() || !self.tunnelling() {
            self.pending_h245.clear();
            return Ok(());
        }
        self.send(msg::FACILITY, "empty", Value::Null, Vec::new())
            .await
    }

    fn destination_body(&self) -> Value {
        json!({
            "protocolIdentifier": h225::PROTOCOL_ID,
            "destinationInfo": h225::endpoint_type("terminal"),
            "callIdentifier": self.call_identifier(),
            "multipleCalls": false,
            "maintainConnection": false,
        })
    }

    pub async fn call_proceeding(&mut self) -> Result<()> {
        if self.state != CallState::Offered {
            bail!("CallProceeding after {}", self.state.name());
        }
        let body = self.destination_body();
        self.send(msg::CALL_PROCEEDING, "callProceeding", body, Vec::new())
            .await?;
        self.state = CallState::Proceeding;
        Ok(())
    }

    pub async fn alerting(&mut self) -> Result<()> {
        if !matches!(self.state, CallState::Offered | CallState::Proceeding) {
            bail!("Alerting after {}", self.state.name());
        }
        let body = self.destination_body();
        self.send(msg::ALERTING, "alerting", body, Vec::new())
            .await?;
        self.state = CallState::Alerting;
        Ok(())
    }

    /// Answer the call: Connect, with a fastStart answer when the caller offered G.711, and
    /// this side's TerminalCapabilitySet and MasterSlaveDetermination tunnelled alongside.
    pub async fn connect(&mut self, prefer: &[Codec], display: Option<&str>) -> Result<()> {
        if !matches!(
            self.state,
            CallState::Offered | CallState::Proceeding | CallState::Alerting
        ) {
            bail!("Connect after {}", self.state.name());
        }
        let mut body = self.destination_body();
        body["conferenceID"] = json!(self.conference_id);
        if !self.offered_fast_start.is_empty() {
            let order: Vec<Codec> = if prefer.is_empty() {
                self.codecs.clone()
            } else {
                prefer.to_vec()
            };
            match h245::answer_fast_start(
                &self.offered_fast_start,
                &order,
                self.media.rtp,
                self.media.rtcp,
            )? {
                Some((answer, media)) => {
                    body["fastStart"] =
                        Value::Array(answer.iter().map(|a| json!(hex::encode(a))).collect());
                    self.fast_start = Some(media);
                }
                None => body["fastConnectRefused"] = Value::Null,
            }
        }
        if let Some(d) = display {
            body["displayName"] = json!([{"name": d}]);
        }
        if self.tunnelling() && !self.h245.started() {
            let opening = self.h245.start()?;
            self.pending_h245.extend(opening);
        }
        let mut ies = Vec::new();
        if let Some(d) = display {
            ies.push((ie::DISPLAY, d.as_bytes().to_vec()));
        }
        self.send(msg::CONNECT, "connect", body, ies).await?;
        self.state = CallState::Connected;
        self.ever_connected = true;
        Ok(())
    }

    /// Release Complete with a Q.850 cause and, optionally, an H.225.0 reason.
    pub async fn release(&mut self, cause: u8, reason: Option<&str>) -> Result<()> {
        if self.state == CallState::Released {
            return Ok(());
        }
        if self.h245.started() && !self.h245.ended && self.tunnelling() {
            let end = self.h245.end_session()?;
            self.pending_h245.push(end);
        }
        let mut body = json!({
            "protocolIdentifier": h225::PROTOCOL_ID,
            "callIdentifier": self.call_identifier(),
        });
        if let Some(r) = reason {
            if !RELEASE_REASONS.contains(&r) {
                bail!("release reason {r:?} is not one of {RELEASE_REASONS:?}");
            }
            body["reason"] = json!({ r: null });
        }
        self.send(
            msg::RELEASE_COMPLETE,
            "releaseComplete",
            body,
            vec![(ie::CAUSE, q931::cause_ie(cause))],
        )
        .await?;
        self.state = CallState::Released;
        let _ = self.writer.shutdown().await;
        Ok(())
    }

    /// Deflect the call: Facility (callForwarded) naming where to call instead, then Release
    /// Complete (facilityCallDeflection).
    pub async fn forward(
        &mut self,
        address: Option<SocketAddr>,
        aliases: Vec<Value>,
    ) -> Result<()> {
        if address.is_none() && aliases.is_empty() {
            bail!("forwarding needs an address or an alias");
        }
        let mut body = json!({
            "protocolIdentifier": h225::PROTOCOL_ID,
            "reason": {"callForwarded": null},
            "conferenceID": self.conference_id,
            "callIdentifier": self.call_identifier(),
            "multipleCalls": false,
            "maintainConnection": false,
        });
        if let Some(a) = address {
            body["alternativeAddress"] = h225::transport(a);
        }
        if !aliases.is_empty() {
            body["alternativeAliasAddress"] = Value::Array(aliases);
        }
        self.send(msg::FACILITY, "facility", body, Vec::new())
            .await?;
        self.release(cause::NORMAL_CLEARING, Some("facilityCallDeflection"))
            .await
    }

    /// Handle one message from the peer.
    pub async fn on_incoming(&mut self, m: &Q931) -> Result<Incoming> {
        // The peer's messages carry the flag set when the peer is the called side.
        let expected_flag = self.role == Role::Caller;
        if m.crv != self.crv || m.from_destination != expected_flag {
            return Ok(Incoming::WrongCallReference {
                crv: m.crv,
                from_destination: m.from_destination,
            });
        }
        let ui = match m.user_user()? {
            Some(raw) => Some(h225::decode_user_information(raw)?),
            None => None,
        };
        if let Some(ui) = &ui {
            if ui.h245_tunnelling() {
                self.peer_tunnelling = true;
            }
            for tunnelled in ui.h245_control() {
                match self.h245.on_message(&tunnelled) {
                    Ok(replies) => self.pending_h245.extend(replies),
                    Err(e) => {
                        tracing::debug!("H.245 message not handled: {e:#}");
                    }
                }
            }
        }
        let incoming = self.classify(m, ui.as_ref())?;
        if !matches!(incoming, Incoming::Released { .. }) && self.state != CallState::Released {
            self.flush_h245().await?;
        }
        Ok(incoming)
    }

    fn classify(&mut self, m: &Q931, ui: Option<&UserInformation>) -> Result<Incoming> {
        Ok(match m.message_type {
            msg::CALL_PROCEEDING => {
                self.take_fast_start(ui);
                if self.state == CallState::Offered {
                    self.state = CallState::Proceeding;
                }
                Incoming::Proceeding
            }
            msg::ALERTING => {
                self.take_fast_start(ui);
                if matches!(self.state, CallState::Offered | CallState::Proceeding) {
                    self.state = CallState::Alerting;
                }
                Incoming::Alerting
            }
            msg::CONNECT => {
                self.take_fast_start(ui);
                self.state = CallState::Connected;
                self.ever_connected = true;
                Incoming::Connected
            }
            msg::PROGRESS => {
                self.take_fast_start(ui);
                Incoming::Other("Progress")
            }
            msg::RELEASE_COMPLETE => {
                self.state = CallState::Released;
                Incoming::Released {
                    cause: m.cause(),
                    reason: ui.map(|u| h225::choice_name(u.body.get("reason"))),
                }
            }
            msg::FACILITY => {
                let reason = ui.map(|u| h225::choice_name(u.body.get("reason")));
                if reason.as_deref() == Some("callForwarded")
                    || reason.as_deref() == Some("routeCallToGatekeeper")
                {
                    let u = ui.expect("reason came from the UUIE");
                    Incoming::Forwarded {
                        address: u.body.get("alternativeAddress").and_then(h225::socket_addr),
                        aliases: h225::aliases_text(u.body.get("alternativeAliasAddress")),
                    }
                } else {
                    Incoming::Other("Facility")
                }
            }
            msg::SETUP => Incoming::UnexpectedSetup,
            msg::STATUS => Incoming::Other("Status"),
            msg::STATUS_ENQUIRY => Incoming::Other("StatusEnquiry"),
            msg::INFORMATION => Incoming::Other("Information"),
            msg::NOTIFY => Incoming::Other("Notify"),
            _ => Incoming::Other("Unknown"),
        })
    }

    fn take_fast_start(&mut self, ui: Option<&UserInformation>) {
        if self.role != Role::Caller || self.fast_start.is_some() {
            return;
        }
        if let Some(ui) = ui {
            let answer = ui.fast_start();
            if !answer.is_empty() {
                self.fast_start = Some(h245::read_fast_start_answer(&answer));
            }
        }
    }

    /// The call's media as it stands: fastStart's agreement, else H.245's.
    pub fn media_json(&self) -> Value {
        let m = self
            .fast_start
            .clone()
            .unwrap_or_else(|| self.h245.media.clone());
        let mut v = m.to_json();
        v["negotiated_by"] = json!(if self.fast_start.is_some() {
            "fastStart"
        } else if self.h245.started() {
            "h245"
        } else {
            "none"
        });
        v["local_rtp"] = json!(self.media.rtp.to_string());
        v["rtp_packets_received"] = json!(self.media.received());
        v
    }

    pub fn summary(&self) -> Value {
        json!({
            "crv": self.crv,
            "call_id": self.call_id,
            "conference_id": self.conference_id,
            "state": self.state.name(),
            "h245_tunnelling": self.tunnelling(),
            "h245": self.h245.summary(),
            "media": self.media_json(),
            "sent": self.sent,
        })
    }
}

/// Read Q.931 messages from a call-signalling connection into a channel, so the call's loop
/// can select over them alongside the model and the operator. Ends at EOF or the first error,
/// which it sends as `Err`.
pub async fn read_loop<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    tx: tokio::sync::mpsc::Sender<Result<Q931>>,
) {
    loop {
        match q931::read_tpkt(&mut reader).await {
            Ok(None) => break,
            Ok(Some(payload)) if payload.is_empty() => continue,
            Ok(Some(payload)) => {
                let parsed = Q931::parse(&payload);
                let stop = parsed.is_err();
                if tx.send(parsed).await.is_err() || stop {
                    break;
                }
            }
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                break;
            }
        }
    }
}

/// The model's choice of codecs: a name or a list of names, defaulting to every codec.
pub fn codecs_from(v: Option<&Value>) -> Result<Vec<Codec>> {
    match v {
        None | Some(Value::Null) => Ok(h245::ALL_CODECS.to_vec()),
        Some(Value::String(s)) => Ok(vec![Codec::parse(s)?]),
        Some(Value::Array(a)) => {
            let mut out = Vec::new();
            for c in a.iter().take(4) {
                let s = c.as_str().context("a codec is a string")?;
                let c = Codec::parse(s)?;
                if !out.contains(&c) {
                    out.push(c);
                }
            }
            if out.is_empty() {
                bail!("an empty codec list");
            }
            Ok(out)
        }
        Some(other) => bail!("codec {other} is not a name or list of names"),
    }
}
