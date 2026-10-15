//! The H.245 NetGet needs for a call to count as connected, and nothing past it.
//!
//! Two ways in, both carried inside H.225.0 call signalling (NetGet never opens a separate
//! H.245 TCP channel):
//!
//! - **Fast connect** (H.323 8.1.7): the caller's Setup carries `fastStart` — PER-encoded
//!   OpenLogicalChannel proposals. [`answer_fast_start`] picks a G.711 channel each way and
//!   returns them with this side's RTP/RTCP addresses filled in; [`offer_fast_start`] writes
//!   the proposals when NetGet calls.
//! - **Tunnelled H.245** (H.323 8.2.1): messages ride in `h245Control` of any H.225.0
//!   message. [`H245Session`] runs the procedures a peer needs before it calls the session
//!   established — capability exchange (TerminalCapabilitySet / Ack) and master-slave
//!   determination — answers OpenLogicalChannel with this side's media address, CloseLogical
//!   Channel, RoundTripDelay and EndSession, and opens one G.711 channel towards the peer.
//!
//! Only G.711 (µ-law and A-law, 64 kbit/s) is offered or accepted. NetGet binds the RTP/RTCP
//! sockets it advertises and counts what arrives on them; it sends no media.

use super::{per, schema};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// H.245 version 7.
pub const PROTOCOL_ID: &str = "0.0.8.245.0.7";
/// Most H.245 messages one call may exchange before NetGet stops answering them.
pub const MAX_H245_MESSAGES: u32 = 256;
/// The terminal type a terminal declares in master-slave determination (H.323 Table 1).
pub const TERMINAL_TYPE: u64 = 50;
/// G.711 frames per packet NetGet offers when the model does not choose: 20 ms of audio.
pub const DEFAULT_FRAMES: u64 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    G711Ulaw,
    G711Alaw,
}

impl Codec {
    pub fn asn1(self) -> &'static str {
        match self {
            Codec::G711Ulaw => "g711Ulaw64k",
            Codec::G711Alaw => "g711Alaw64k",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Codec::G711Ulaw => "g711u",
            Codec::G711Alaw => "g711a",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "g711u" | "g711ulaw" | "g711ulaw64k" | "pcmu" | "ulaw" => Ok(Codec::G711Ulaw),
            "g711a" | "g711alaw" | "g711alaw64k" | "pcma" | "alaw" => Ok(Codec::G711Alaw),
            other => bail!("codec {other:?}: NetGet speaks g711u and g711a"),
        }
    }

    /// The codec an `AudioCapability` value names, if it is one of these.
    pub fn of_audio(v: &Value) -> Option<(Codec, u64)> {
        for c in [Codec::G711Ulaw, Codec::G711Alaw] {
            if let Some(frames) = v.get(c.asn1()).and_then(|f| f.as_u64()) {
                return Some((c, frames));
            }
        }
        None
    }
}

/// Every codec NetGet will negotiate, in its default order of preference.
pub const ALL_CODECS: [Codec; 2] = [Codec::G711Ulaw, Codec::G711Alaw];

/// The audio codec an `AudioCapability` names, for the model (`g711Ulaw64k`, `g729`, ...).
pub fn audio_name(v: &Value) -> String {
    v.as_object()
        .and_then(|o| o.keys().next().cloned())
        .unwrap_or_else(|| "unknown".into())
}

pub fn decode(bytes: &[u8]) -> Result<Value> {
    per::decode(schema::H245_MULTIMEDIASYSTEMCONTROLMESSAGE, bytes).map_err(|e| anyhow!("{e}"))
}

pub fn encode(msg: &Value) -> Result<Vec<u8>> {
    per::encode(schema::H245_MULTIMEDIASYSTEMCONTROLMESSAGE, msg).map_err(|e| anyhow!("{e}"))
}

pub fn decode_olc(bytes: &[u8]) -> Result<Value> {
    per::decode(schema::H245_OPENLOGICALCHANNEL, bytes).map_err(|e| anyhow!("{e}"))
}

pub fn encode_olc(olc: &Value) -> Result<Vec<u8>> {
    per::encode(schema::H245_OPENLOGICALCHANNEL, olc).map_err(|e| anyhow!("{e}"))
}

/// An H.245 unicast `TransportAddress`.
pub fn unicast(addr: SocketAddr) -> Value {
    match addr.ip() {
        IpAddr::V4(ip) => json!({"unicastAddress": {"iPAddress": {
            "network": hex::encode(ip.octets()), "tsapIdentifier": addr.port()}}}),
        IpAddr::V6(ip) => json!({"unicastAddress": {"iP6Address": {
            "network": hex::encode(ip.octets()), "tsapIdentifier": addr.port()}}}),
    }
}

pub fn unicast_addr(v: &Value) -> Option<SocketAddr> {
    let u = v.get("unicastAddress")?;
    if let Some(a) = u.get("iPAddress") {
        let ip: [u8; 4] = hex::decode(a.get("network")?.as_str()?)
            .ok()?
            .try_into()
            .ok()?;
        let port = u16::try_from(a.get("tsapIdentifier")?.as_u64()?).ok()?;
        return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port));
    }
    if let Some(a) = u.get("iP6Address") {
        let ip: [u8; 16] = hex::decode(a.get("network")?.as_str()?)
            .ok()?
            .try_into()
            .ok()?;
        let port = u16::try_from(a.get("tsapIdentifier")?.as_u64()?).ok()?;
        return Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port));
    }
    None
}

/// Where media goes and how, once a channel each way is agreed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Media {
    pub codec: Option<&'static str>,
    pub frames: Option<u64>,
    /// Where the peer wants this side's RTP.
    pub remote_rtp: Option<SocketAddr>,
    pub remote_rtcp: Option<SocketAddr>,
}

impl Media {
    pub fn to_json(&self) -> Value {
        json!({
            "codec": self.codec,
            "frames_per_packet": self.frames,
            "remote_rtp": self.remote_rtp.map(|a| a.to_string()),
            "remote_rtcp": self.remote_rtcp.map(|a| a.to_string()),
        })
    }
}

fn h2250(session: u64, media: Option<SocketAddr>, control: Option<SocketAddr>) -> Value {
    let mut p = json!({"sessionID": session});
    if let Some(m) = media {
        p["mediaChannel"] = unicast(m);
    }
    if let Some(c) = control {
        p["mediaControlChannel"] = unicast(c);
    }
    json!({ "h2250LogicalChannelParameters": p })
}

fn audio(codec: Codec, frames: u64) -> Value {
    json!({"audioData": { codec.asn1(): frames }})
}

/// The fastStart proposals NetGet puts in a Setup: for each codec, a channel NetGet transmits
/// on (forward, RTCP given) and one it receives on (reverse, RTP and RTCP given).
pub fn offer_fast_start(
    codecs: &[Codec],
    rtp: SocketAddr,
    rtcp: SocketAddr,
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for (i, c) in codecs.iter().enumerate() {
        let lcn = 101 + i as u64;
        out.push(encode_olc(&json!({
            "forwardLogicalChannelNumber": lcn,
            "forwardLogicalChannelParameters": {
                "dataType": audio(*c, DEFAULT_FRAMES),
                "multiplexParameters": h2250(1, None, Some(rtcp)),
            },
        }))?);
        out.push(encode_olc(&json!({
            "forwardLogicalChannelNumber": lcn + 100,
            "forwardLogicalChannelParameters": {
                "dataType": {"nullData": null},
                "multiplexParameters": {"none": null},
            },
            "reverseLogicalChannelParameters": {
                "dataType": audio(*c, DEFAULT_FRAMES),
                "multiplexParameters": h2250(1, Some(rtp), Some(rtcp)),
            },
        }))?);
    }
    Ok(out)
}

/// One fastStart proposal, decoded, for the model.
pub fn describe_proposal(olc: &Value) -> Value {
    let fwd = olc.get("forwardLogicalChannelParameters");
    let rev = olc.get("reverseLogicalChannelParameters");
    let fwd_audio = fwd
        .and_then(|f| f.get("dataType"))
        .and_then(|d| d.get("audioData"));
    let rev_audio = rev
        .and_then(|r| r.get("dataType"))
        .and_then(|d| d.get("audioData"));
    match (fwd_audio, rev_audio) {
        (Some(a), _) => json!({
            "direction": "caller_sends",
            "codec": audio_name(a),
        }),
        (None, Some(a)) => {
            let media = rev
                .and_then(|r| r.get("multiplexParameters"))
                .and_then(|m| m.get("h2250LogicalChannelParameters"))
                .and_then(|p| p.get("mediaChannel"))
                .and_then(unicast_addr);
            json!({
                "direction": "caller_receives",
                "codec": audio_name(a),
                "caller_rtp": media.map(|m| m.to_string()),
            })
        }
        _ => json!({"direction": "other"}),
    }
}

/// Choose from a caller's fastStart proposals: the first channel the caller transmits on and
/// the first it receives on, in a codec from `prefer`, both in the same codec. Returns the
/// OpenLogicalChannel encodings to send back and what was agreed, or `None` when no G.711
/// pair is on offer.
pub fn answer_fast_start(
    proposals: &[Vec<u8>],
    prefer: &[Codec],
    rtp: SocketAddr,
    rtcp: SocketAddr,
) -> Result<Option<(Vec<Vec<u8>>, Media)>> {
    let decoded: Vec<Value> = proposals
        .iter()
        .filter_map(|p| decode_olc(p).ok())
        .collect();
    for codec in prefer {
        let forward = decoded.iter().find(|o| {
            o.get("reverseLogicalChannelParameters").is_none()
                && o.get("forwardLogicalChannelParameters")
                    .and_then(|f| f.get("dataType"))
                    .and_then(|d| d.get("audioData"))
                    .and_then(Codec::of_audio)
                    .is_some_and(|(c, _)| c == *codec)
        });
        let reverse = decoded.iter().find(|o| {
            o.get("reverseLogicalChannelParameters")
                .and_then(|r| r.get("dataType"))
                .and_then(|d| d.get("audioData"))
                .and_then(Codec::of_audio)
                .is_some_and(|(c, _)| c == *codec)
        });
        let (Some(forward), Some(reverse)) = (forward, reverse) else {
            continue;
        };
        // The caller's transmit channel: tell it where to send (our RTP) and our RTCP.
        let mut fwd = forward.clone();
        let params = &mut fwd["forwardLogicalChannelParameters"]["multiplexParameters"]
            ["h2250LogicalChannelParameters"];
        if !params.is_object() {
            continue;
        }
        params["mediaChannel"] = unicast(rtp);
        params["mediaControlChannel"] = unicast(rtcp);
        // The caller's receive channel: accepted as proposed, with this side's RTCP so the
        // caller's receiver reports have somewhere to go.
        let mut rev = reverse.clone();
        let rparams = &mut rev["reverseLogicalChannelParameters"]["multiplexParameters"]
            ["h2250LogicalChannelParameters"];
        let remote_rtp = rparams.get("mediaChannel").and_then(unicast_addr);
        let remote_rtcp = rparams.get("mediaControlChannel").and_then(unicast_addr);
        if rparams.is_object() {
            rparams["mediaControlChannel"] = unicast(rtcp);
        }
        let frames = reverse["reverseLogicalChannelParameters"]["dataType"]["audioData"]
            .get(codec.asn1())
            .and_then(|f| f.as_u64());
        let answer = vec![encode_olc(&fwd)?, encode_olc(&rev)?];
        return Ok(Some((
            answer,
            Media {
                codec: Some(codec.name()),
                frames,
                remote_rtp,
                remote_rtcp,
            },
        )));
    }
    Ok(None)
}

/// What a callee's fastStart answer says, for the side that offered: the agreed codec and
/// where to send media.
pub fn read_fast_start_answer(answer: &[Vec<u8>]) -> Media {
    let mut media = Media::default();
    for raw in answer {
        let Ok(olc) = decode_olc(raw) else { continue };
        if let Some(fwd) = olc.get("forwardLogicalChannelParameters") {
            if let Some((c, frames)) = fwd
                .get("dataType")
                .and_then(|d| d.get("audioData"))
                .and_then(Codec::of_audio)
            {
                let p = &fwd["multiplexParameters"]["h2250LogicalChannelParameters"];
                media.codec = Some(c.name());
                media.frames = Some(frames);
                media.remote_rtp = p.get("mediaChannel").and_then(unicast_addr);
                media.remote_rtcp = p.get("mediaControlChannel").and_then(unicast_addr);
            }
        }
    }
    media
}

fn our_capability_set(seq: u64, codecs: &[Codec]) -> Value {
    let multipoint = json!({
        "multicastCapability": false,
        "multiUniCastConference": false,
        "mediaDistributionCapability": [{
            "centralizedControl": false, "distributedControl": false,
            "centralizedAudio": false, "distributedAudio": false,
            "centralizedVideo": false, "distributedVideo": false,
        }],
    });
    let table: Vec<Value> = codecs
        .iter()
        .enumerate()
        .map(|(i, c)| {
            json!({
                "capabilityTableEntryNumber": i + 1,
                "capability": {"receiveAudioCapability": { c.asn1(): DEFAULT_FRAMES }},
            })
        })
        .collect();
    let alternatives: Vec<Value> = (1..=codecs.len()).map(|n| json!(n)).collect();
    json!({"request": {"terminalCapabilitySet": {
        "sequenceNumber": seq,
        "protocolIdentifier": PROTOCOL_ID,
        "multiplexCapability": {"h2250Capability": {
            "maximumAudioDelayJitter": 60,
            "receiveMultipointCapability": multipoint,
            "transmitMultipointCapability": multipoint,
            "receiveAndTransmitMultipointCapability": multipoint,
            "mcCapability": {"centralizedConferenceMC": false, "decentralizedConferenceMC": false},
            "rtcpVideoControlCapability": false,
            "mediaPacketizationCapability": {"h261aVideoPacketization": false},
            "logicalChannelSwitchingCapability": false,
            "t120DynamicPortCapability": false,
        }},
        "capabilityTable": table,
        "capabilityDescriptors": [{
            "capabilityDescriptorNumber": 0,
            "simultaneousCapabilities": [alternatives],
        }],
    }}})
}

/// The tunnelled H.245 procedures for one call.
pub struct H245Session {
    codecs: Vec<Codec>,
    rtp: SocketAddr,
    rtcp: SocketAddr,
    msd_number: u64,
    started: bool,
    our_tcs_acked: bool,
    peer_tcs_seen: bool,
    peer_codecs: Vec<Codec>,
    /// `Some(true)` when this side is master.
    master: Option<bool>,
    our_channel: Option<u64>,
    our_channel_acked: bool,
    peer_channels: Vec<u64>,
    messages: u32,
    pub media: Media,
    pub ended: bool,
    /// DTMF and user input the peer sent, oldest first, for the call's events.
    pub user_input: Vec<String>,
}

impl H245Session {
    pub fn new(codecs: Vec<Codec>, rtp: SocketAddr, rtcp: SocketAddr) -> Self {
        Self {
            codecs,
            rtp,
            rtcp,
            msd_number: rand::random::<u64>() & 0xFF_FFFF,
            started: false,
            our_tcs_acked: false,
            peer_tcs_seen: false,
            peer_codecs: Vec::new(),
            master: None,
            our_channel: None,
            our_channel_acked: false,
            peer_channels: Vec::new(),
            messages: 0,
            media: Media::default(),
            ended: false,
            user_input: Vec::new(),
        }
    }

    pub fn started(&self) -> bool {
        self.started
    }

    /// Capability exchange done both ways and master/slave decided.
    pub fn established(&self) -> bool {
        self.our_tcs_acked && self.peer_tcs_seen && self.master.is_some()
    }

    pub fn summary(&self) -> Value {
        json!({
            "capability_exchange": self.our_tcs_acked && self.peer_tcs_seen,
            "master": self.master,
            "peer_codecs": self.peer_codecs.iter().map(|c| c.name()).collect::<Vec<_>>(),
            "channel_to_peer": self.our_channel_acked,
            "channels_from_peer": self.peer_channels.len(),
        })
    }

    /// This side's opening: TerminalCapabilitySet and MasterSlaveDetermination.
    pub fn start(&mut self) -> Result<Vec<Vec<u8>>> {
        if self.started {
            return Ok(Vec::new());
        }
        self.started = true;
        Ok(vec![
            encode(&our_capability_set(1, &self.codecs))?,
            encode(&json!({"request": {"masterSlaveDetermination": {
                "terminalType": TERMINAL_TYPE,
                "statusDeterminationNumber": self.msd_number,
            }}}))?,
        ])
    }

    /// Handle one tunnelled message; returns the messages to send back.
    pub fn on_message(&mut self, raw: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.messages += 1;
        if self.messages > MAX_H245_MESSAGES {
            bail!("more than {MAX_H245_MESSAGES} H.245 messages on one call");
        }
        let msg = decode(raw)?;
        let mut out: Vec<Value> = Vec::new();
        let mut start_first = false;
        if let Some(req) = msg.get("request") {
            if !self.started {
                start_first = true;
            }
            if let Some(tcs) = req.get("terminalCapabilitySet") {
                let seq = tcs
                    .get("sequenceNumber")
                    .and_then(|s| s.as_u64())
                    .unwrap_or(0);
                self.peer_tcs_seen = true;
                self.peer_codecs = tcs
                    .get("capabilityTable")
                    .and_then(|t| t.as_array())
                    .map(|t| {
                        t.iter()
                            .filter_map(|e| {
                                let cap = e.get("capability")?;
                                let a = cap
                                    .get("receiveAudioCapability")
                                    .or_else(|| cap.get("receiveAndTransmitAudioCapability"))?;
                                Codec::of_audio(a).map(|(c, _)| c)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                out.push(
                    json!({"response": {"terminalCapabilitySetAck": {"sequenceNumber": seq}}}),
                );
            } else if let Some(msd) = req.get("masterSlaveDetermination") {
                let their_type = msd
                    .get("terminalType")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0);
                let their_num = msd
                    .get("statusDeterminationNumber")
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0);
                let we_are_master = if their_type != TERMINAL_TYPE {
                    TERMINAL_TYPE > their_type
                } else {
                    let diff = their_num.wrapping_sub(self.msd_number) & 0xFF_FFFF;
                    if diff == 0 || diff == 0x80_0000 {
                        out.push(json!({"response": {"masterSlaveDeterminationReject": {
                            "cause": {"identicalNumbers": null}}}}));
                        return self.finish(out, false);
                    }
                    diff < 0x80_0000
                };
                self.master = Some(we_are_master);
                // The Ack tells the *receiver* what it is.
                let decision = if we_are_master { "slave" } else { "master" };
                out.push(json!({"response": {"masterSlaveDeterminationAck": {
                    "decision": { decision: null }}}}));
            } else if let Some(olc) = req.get("openLogicalChannel") {
                let lcn = olc
                    .get("forwardLogicalChannelNumber")
                    .and_then(|n| n.as_u64())
                    .unwrap_or(1);
                let codec = olc
                    .get("forwardLogicalChannelParameters")
                    .and_then(|f| f.get("dataType"))
                    .and_then(|d| d.get("audioData"))
                    .and_then(Codec::of_audio);
                match codec {
                    Some((c, frames)) if self.codecs.contains(&c) => {
                        if self.peer_channels.len() < 8 {
                            self.peer_channels.push(lcn);
                        }
                        if self.media.codec.is_none() {
                            self.media.codec = Some(c.name());
                            self.media.frames = Some(frames);
                        }
                        out.push(json!({"response": {"openLogicalChannelAck": {
                            "forwardLogicalChannelNumber": lcn,
                            "forwardMultiplexAckParameters": {"h2250LogicalChannelAckParameters": {
                                "sessionID": 1,
                                "mediaChannel": unicast(self.rtp),
                                "mediaControlChannel": unicast(self.rtcp),
                                "flowControlToZero": false,
                            }},
                        }}}));
                    }
                    _ => out.push(json!({"response": {"openLogicalChannelReject": {
                        "forwardLogicalChannelNumber": lcn,
                        "cause": {"dataTypeNotSupported": null},
                    }}})),
                }
            } else if let Some(clc) = req.get("closeLogicalChannel") {
                let lcn = clc
                    .get("forwardLogicalChannelNumber")
                    .and_then(|n| n.as_u64())
                    .unwrap_or(1);
                self.peer_channels.retain(|c| *c != lcn);
                out.push(json!({"response": {"closeLogicalChannelAck": {
                    "forwardLogicalChannelNumber": lcn}}}));
            } else if let Some(rtd) = req.get("roundTripDelayRequest") {
                let seq = rtd
                    .get("sequenceNumber")
                    .and_then(|s| s.as_u64())
                    .unwrap_or(0);
                out.push(json!({"response": {"roundTripDelayResponse": {"sequenceNumber": seq}}}));
            } else if let Some(rcc) = req.get("requestChannelClose") {
                let lcn = rcc
                    .get("forwardLogicalChannelNumber")
                    .and_then(|n| n.as_u64())
                    .unwrap_or(1);
                out.push(json!({"response": {"requestChannelCloseAck": {
                    "forwardLogicalChannelNumber": lcn}}}));
            }
        } else if let Some(resp) = msg.get("response") {
            if resp.get("terminalCapabilitySetAck").is_some() {
                self.our_tcs_acked = true;
            } else if let Some(ack) = resp.get("masterSlaveDeterminationAck") {
                // The peer tells this side what it is.
                if let Some(d) = ack.get("decision").and_then(|d| d.as_object()) {
                    let we_are_master = d.contains_key("master");
                    if self.master.is_none() {
                        self.master = Some(we_are_master);
                        let theirs = if we_are_master { "slave" } else { "master" };
                        out.push(json!({"response": {"masterSlaveDeterminationAck": {
                            "decision": { theirs: null }}}}));
                    }
                }
            } else if let Some(ack) = resp.get("openLogicalChannelAck") {
                let p = ack
                    .get("forwardMultiplexAckParameters")
                    .and_then(|m| m.get("h2250LogicalChannelAckParameters"));
                if let Some(p) = p {
                    self.media.remote_rtp = p.get("mediaChannel").and_then(unicast_addr);
                    self.media.remote_rtcp = p.get("mediaControlChannel").and_then(unicast_addr);
                }
                self.our_channel_acked = true;
            }
        } else if let Some(cmd) = msg.get("command") {
            if cmd.get("endSessionCommand").is_some() {
                self.ended = true;
                out.push(json!({"command": {"endSessionCommand": {"disconnect": null}}}));
            }
        } else if let Some(ind) = msg.get("indication") {
            if let Some(ui) = ind.get("userInput") {
                let text = ui
                    .get("signal")
                    .and_then(|s| s.get("signalType"))
                    .or_else(|| ui.get("alphanumeric"))
                    .and_then(|s| s.as_str())
                    .map(crate::utils::sanitize::strip_controls);
                if let Some(t) = text {
                    if self.user_input.len() < 64 {
                        self.user_input.push(t);
                    }
                }
            }
        }
        self.finish(out, start_first)
    }

    fn finish(&mut self, out: Vec<Value>, start_first: bool) -> Result<Vec<Vec<u8>>> {
        let mut encoded = if start_first {
            self.start()?
        } else {
            Vec::new()
        };
        for m in &out {
            encoded.push(encode(m)?);
        }
        // Once both capability sets are known and roles decided, open a G.711 channel to the
        // peer in the first codec both sides have.
        if self.established() && self.our_channel.is_none() {
            if let Some(codec) = self
                .codecs
                .iter()
                .find(|c| self.peer_codecs.contains(c))
                .copied()
            {
                self.our_channel = Some(1);
                encoded.push(encode(&json!({"request": {"openLogicalChannel": {
                    "forwardLogicalChannelNumber": 1,
                    "forwardLogicalChannelParameters": {
                        "dataType": audio(codec, DEFAULT_FRAMES),
                        "multiplexParameters": h2250(1, None, Some(self.rtcp)),
                    },
                }}}))?);
                if self.media.codec.is_none() {
                    self.media.codec = Some(codec.name());
                    self.media.frames = Some(DEFAULT_FRAMES);
                }
            }
        }
        Ok(encoded)
    }

    /// EndSessionCommand, for hanging up a call that has H.245 running.
    pub fn end_session(&mut self) -> Result<Vec<u8>> {
        self.ended = true;
        encode(&json!({"command": {"endSessionCommand": {"disconnect": null}}}))
    }
}
