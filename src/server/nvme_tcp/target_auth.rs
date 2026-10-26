//! The target's side of DH-HMAC-CHAP, on an admin queue whose Connect the model admitted with
//! `require_authentication`: the Connect completes with AUTHREQ.ATR, and nothing but
//! Authentication Send and Receive runs on the queue (AUTHENTICATION REQUIRED otherwise) until
//! the host's response checks out against `dhchap_secret`. A host that asks the controller to
//! prove itself gets R2 from `dhchap_ctrl_secret`, or AUTH_Failure1 when none is configured.
//!
//! As in nvmet, a message that fails (a wrong response, an unusable hash or group, a payload
//! or step out of order) completes its Authentication Send successfully and the failure is the
//! next Authentication Receive's answer, AUTH_Failure1 with the reason; the queue stays
//! unauthenticated and may negotiate again, at most [`MAX_AUTH_ATTEMPTS`] times, within
//! [`super::AUTH_DEADLINE`] of the Connect. Nothing about a secret, a challenge or a response
//! reaches the model or the log.
use super::auth::{self, DhGroup, DhKey, Hash, Message, Role};
use super::nvme::{fctype, Sqe, Status};
use super::MAX_AUTH_ATTEMPTS;
use super::{err, incoming, ok, outcome, outgoing, shown, Conn, Done, Incoming, PendingKind};
use anyhow::Result;

/// Where a queue's exchange stands: what it expects next.
pub(super) enum AuthState {
    /// The queue was not asked to authenticate.
    None,
    /// AUTH_Negotiate.
    Negotiate,
    /// Negotiated: an Authentication Receive, answered with the challenge.
    Challenge {
        tid: u16,
        hash: Hash,
        group: DhGroup,
    },
    /// The challenge went out: the Reply.
    Reply {
        tid: u16,
        hash: Hash,
        c1: Vec<u8>,
        s1: u32,
        key: Option<DhKey>,
    },
    /// The host proved itself: an Authentication Receive, answered with Success1 (carrying R2
    /// when the host asked for it).
    Success1 {
        tid: u16,
        hash: Hash,
        r2: Option<Vec<u8>>,
    },
    /// R2 went out: Success2 (or Failure2 when the host did not accept it).
    Success2 { tid: u16 },
    /// Something failed: an Authentication Receive, answered with AUTH_Failure1.
    Failure1 { tid: u16, explanation: u8 },
    /// Authenticated.
    Done,
}

impl AuthState {
    fn expecting(&self) -> &'static str {
        match self {
            AuthState::None => "nothing",
            AuthState::Negotiate => "AUTH_Negotiate",
            AuthState::Challenge { .. } => "an Authentication Receive for the challenge",
            AuthState::Reply { .. } => "DH-HMAC-CHAP_Reply",
            AuthState::Success1 { .. } => "an Authentication Receive for Success1",
            AuthState::Success2 { .. } => "DH-HMAC-CHAP_Success2",
            AuthState::Failure1 { .. } => "an Authentication Receive for AUTH_Failure1",
            AuthState::Done => "nothing (authenticated)",
        }
    }
}

impl Conn<'_> {
    /// An Authentication Send or Receive on the admin queue.
    pub(super) async fn auth_command(&mut self, sqe: &Sqe, data: Vec<u8>) -> Result<Done> {
        let (secp, spsp0, spsp1, len) = auth::command_fields(sqe);
        if secp != auth::SECP || spsp0 != auth::SPSP0 || spsp1 != auth::SPSP1 {
            return Ok(err(Status::INVALID_FIELD));
        }
        if matches!(self.auth, AuthState::None) {
            outcome(
                self.ctx,
                self.id,
                "authenticate",
                "protocol_refusal",
                "Authentication Send/Receive on a queue that was not asked to authenticate",
            );
            return Ok(err(Status::COMMAND_SEQUENCE_ERROR));
        }
        let len = len as usize;
        if sqe.fctype() == fctype::AUTH_SEND {
            if len == 0 || len > auth::MAX_MESSAGE {
                return Ok(err(Status::INVALID_FIELD));
            }
            return match incoming(sqe, data, len) {
                Ok(Incoming::InCapsule(d)) => Ok(self.auth_send(sqe, &d)),
                Ok(Incoming::Solicited) => {
                    self.solicit(sqe.clone(), PendingKind::AuthSend, len).await
                }
                Err(s) => Ok(err(s)),
            };
        }
        if len == 0 || len > 2 * auth::MAX_MESSAGE {
            return Ok(err(Status::INVALID_FIELD));
        }
        if let Err(s) = outgoing(sqe, &data, len) {
            return Ok(err(s));
        }
        Ok(self.auth_receive(len))
    }

    /// The NQNs the responses are computed over: (host, subsystem).
    fn nqns(&self) -> (String, String) {
        self.queue.as_ref().map_or_else(Default::default, |q| {
            (q.ctrl.hostnqn.clone(), q.ctrl.subnqn.clone())
        })
    }

    /// Fail the exchange: the next Authentication Receive answers AUTH_Failure1.
    fn auth_fail(&mut self, tid: u16, explanation: u8, why: &str) {
        self.authenticated = false;
        self.auth = AuthState::Failure1 { tid, explanation };
        let (host, _) = self.nqns();
        outcome(
            self.ctx,
            self.id,
            "authenticate",
            "protocol_refusal",
            &format!(
                "{}: {why}; AUTH_Failure1 ({})",
                shown(&host),
                auth::reason::name(explanation)
            ),
        );
    }

    /// An Authentication Send's message, all of it here.
    pub(super) fn auth_send(&mut self, _sqe: &Sqe, data: &[u8]) -> Done {
        let current_tid = match &self.auth {
            AuthState::Challenge { tid, .. }
            | AuthState::Reply { tid, .. }
            | AuthState::Success1 { tid, .. }
            | AuthState::Success2 { tid }
            | AuthState::Failure1 { tid, .. } => Some(*tid),
            _ => None,
        };
        let message = match Message::decode(data) {
            Ok(m) => m,
            Err(r) => {
                let tid = current_tid.unwrap_or_else(|| {
                    data.get(4..6)
                        .map_or(0, |t| u16::from_le_bytes([t[0], t[1]]))
                });
                self.auth_fail(tid, r, "a message that does not decode");
                return ok();
            }
        };
        let Some(cfg) = self.target.config.auth.clone() else {
            // Only a description the configuration can check is admitted, so this is a defect;
            // refuse rather than let the queue through.
            self.auth_fail(
                message.tid(),
                auth::reason::FAILED,
                "no secret is configured",
            );
            return ok();
        };
        let state = std::mem::replace(&mut self.auth, AuthState::Negotiate);
        match (message, state) {
            (Message::Negotiate(n), _) => {
                self.auth_attempts = self.auth_attempts.saturating_add(1);
                if self.auth_attempts > MAX_AUTH_ATTEMPTS {
                    self.auth_fail(
                        n.tid,
                        auth::reason::FAILED,
                        &format!("more than {MAX_AUTH_ATTEMPTS} negotiations on one queue"),
                    );
                    return ok();
                }
                let refusal = if n.sc_c != 0 {
                    Some((
                        auth::reason::CONCAT_MISMATCH,
                        "secure channel concatenation, which needs TLS",
                    ))
                } else if n.napd != 1 {
                    Some((
                        auth::reason::HASH_UNUSABLE,
                        "not exactly one protocol descriptor",
                    ))
                } else if n.authid != auth::AUTHID_DHCHAP {
                    Some((
                        auth::reason::INCORRECT_PAYLOAD,
                        "a protocol other than DH-HMAC-CHAP",
                    ))
                } else if n.halen as usize > auth::MAX_IDS || n.dhlen as usize > auth::MAX_IDS {
                    Some((
                        auth::reason::INCORRECT_PAYLOAD,
                        "more identifiers than a descriptor holds",
                    ))
                } else {
                    None
                };
                if let Some((r, why)) = refusal {
                    self.auth_fail(n.tid, r, &format!("AUTH_Negotiate asks for {why}"));
                    return ok();
                }
                let Some(hash) = cfg
                    .hashes
                    .iter()
                    .copied()
                    .find(|h| n.hashes.contains(&h.id()))
                else {
                    self.auth_fail(
                        n.tid,
                        auth::reason::HASH_UNUSABLE,
                        "the host offers none of this target's hashes",
                    );
                    return ok();
                };
                let Some(group) = cfg
                    .groups
                    .iter()
                    .copied()
                    .find(|g| n.groups.contains(&g.id()))
                else {
                    self.auth_fail(
                        n.tid,
                        auth::reason::DHGROUP_UNUSABLE,
                        "the host offers none of this target's DH groups",
                    );
                    return ok();
                };
                outcome(
                    self.ctx,
                    self.id,
                    "authenticate",
                    "protocol_accept",
                    &format!(
                        "AUTH_Negotiate (transaction {}): hash {}, DH group {}",
                        n.tid,
                        hash.name(),
                        group.name()
                    ),
                );
                self.auth = AuthState::Challenge {
                    tid: n.tid,
                    hash,
                    group,
                };
            }
            (
                Message::Reply(r),
                AuthState::Reply {
                    tid,
                    hash,
                    c1,
                    s1,
                    key,
                },
            ) => {
                if r.tid != tid {
                    self.auth_fail(
                        tid,
                        auth::reason::INCORRECT_PAYLOAD,
                        &format!("a Reply for transaction {} in transaction {tid}", r.tid),
                    );
                    return ok();
                }
                if r.hl as usize != hash.len() {
                    self.auth_fail(
                        tid,
                        auth::reason::INCORRECT_PAYLOAD,
                        &format!(
                            "a Reply with HL {} where {} gives {}",
                            r.hl,
                            hash.name(),
                            hash.len()
                        ),
                    );
                    return ok();
                }
                let session = match (&key, r.dhv.is_empty()) {
                    (None, true) => None,
                    (Some(k), false) => match k.session_key(hash, &r.dhv) {
                        Ok(s) => Some(s),
                        Err(why) => {
                            self.auth_fail(tid, why, "the host's DH value is not usable");
                            return ok();
                        }
                    },
                    _ => {
                        self.auth_fail(
                            tid,
                            auth::reason::INCORRECT_PAYLOAD,
                            "a DH value that does not match the negotiated group",
                        );
                        return ok();
                    }
                };
                let (host, subsystem) = self.nqns();
                let expected = auth::response(
                    Role::Host,
                    &auth::ResponseInput {
                        hash,
                        key: &cfg.host_secret.transformed(&host),
                        challenge: &c1,
                        session_key: session.as_deref(),
                        seqnum: s1,
                        tid,
                        sc_c: 0,
                        host_nqn: &host,
                        subsystem_nqn: &subsystem,
                    },
                );
                if !auth::ct_eq(&r.rval, &expected) {
                    self.auth_fail(
                        tid,
                        auth::reason::FAILED,
                        "the host's response does not match the configured secret",
                    );
                    return ok();
                }
                // SEQNUM 0 with a challenge is a PSK request for secure channel concatenation,
                // not bidirectional authentication.
                let r2 = if r.cvalid && r.seqnum != 0 {
                    let Some(ctrl_secret) = cfg.ctrl_secret.as_ref() else {
                        self.auth_fail(
                            tid,
                            auth::reason::FAILED,
                            "the host asks the controller to authenticate and no \
                             dhchap_ctrl_secret is configured",
                        );
                        return ok();
                    };
                    Some(auth::response(
                        Role::Controller,
                        &auth::ResponseInput {
                            hash,
                            key: &ctrl_secret.transformed(&subsystem),
                            challenge: &r.cval,
                            session_key: session.as_deref(),
                            seqnum: r.seqnum,
                            tid,
                            sc_c: 0,
                            host_nqn: &host,
                            subsystem_nqn: &subsystem,
                        },
                    ))
                } else {
                    None
                };
                outcome(
                    self.ctx,
                    self.id,
                    "authenticate",
                    "protocol_accept",
                    &format!(
                        "{}'s response checks out ({}, {}){}",
                        shown(&host),
                        hash.name(),
                        key.as_ref().map_or("null", |k| k.group().name()),
                        if r2.is_some() {
                            "; it asks the controller to prove itself"
                        } else {
                            ""
                        }
                    ),
                );
                self.auth = AuthState::Success1 { tid, hash, r2 };
            }
            (Message::Success2 { tid: t }, AuthState::Success2 { tid }) if t == tid => {
                self.authenticated = true;
                self.auth_by = None;
                self.auth = AuthState::Done;
                let (host, _) = self.nqns();
                outcome(
                    self.ctx,
                    self.id,
                    "authenticate",
                    "protocol_accept",
                    &format!(
                        "{} accepted the controller's response: authenticated both ways",
                        shown(&host)
                    ),
                );
            }
            (Message::Failure(f), state) if f.second => {
                self.authenticated = false;
                let (host, _) = self.nqns();
                outcome(
                    self.ctx,
                    self.id,
                    "authenticate",
                    "protocol_refusal",
                    &format!(
                        "{} ended authentication with AUTH_Failure2 ({}) while this target \
                         expected {}",
                        shown(&host),
                        auth::reason::name(f.explanation),
                        state.expecting()
                    ),
                );
                self.auth = AuthState::Negotiate;
            }
            (m, state) => {
                let why = format!("{} while expecting {}", m.name(), state.expecting());
                self.auth_fail(
                    current_tid.unwrap_or(m.tid()),
                    auth::reason::INCORRECT_MESSAGE,
                    &why,
                );
            }
        }
        ok()
    }

    /// An Authentication Receive of `al` bytes: the message the exchange owes the host.
    fn auth_receive(&mut self, al: usize) -> Done {
        // Too small to carry the message: refused, and the exchange stays where it was.
        let needed = match &self.auth {
            AuthState::Challenge { hash, group, .. } => 16 + hash.len() + group.value_len(),
            AuthState::Success1 { r2, .. } => 16 + r2.as_ref().map_or(0, Vec::len),
            _ => 8,
        };
        if al < needed {
            return err(Status::INVALID_FIELD);
        }
        let state = std::mem::replace(&mut self.auth, AuthState::Negotiate);
        let (message, next, done) = match state {
            AuthState::Challenge { tid, hash, group } => {
                let c1 = auth::random(hash.len());
                let s1 = auth::seqnum();
                let key = DhKey::generate(group);
                let message = Message::Challenge(auth::Challenge {
                    tid,
                    hl: hash.len() as u8,
                    hash_id: hash.id(),
                    dhgid: group.id(),
                    seqnum: s1,
                    cval: c1.clone(),
                    dhv: key
                        .as_ref()
                        .map(|k| k.public().to_vec())
                        .unwrap_or_default(),
                });
                (
                    message,
                    AuthState::Reply {
                        tid,
                        hash,
                        c1,
                        s1,
                        key,
                    },
                    false,
                )
            }
            AuthState::Success1 { tid, hash, r2 } => {
                let bidirectional = r2.is_some();
                let message = Message::Success1(auth::Success1 {
                    tid,
                    hl: hash.len() as u8,
                    rvalid: bidirectional,
                    rval: r2.unwrap_or_default(),
                });
                if bidirectional {
                    (message, AuthState::Success2 { tid }, false)
                } else {
                    (message, AuthState::Done, true)
                }
            }
            AuthState::Failure1 { tid, explanation } => (
                Message::Failure(auth::Failure {
                    second: false,
                    tid,
                    rescode: auth::RESCODE_FAILED,
                    explanation,
                }),
                AuthState::Negotiate,
                false,
            ),
            other => {
                let (host, _) = self.nqns();
                outcome(
                    self.ctx,
                    self.id,
                    "authenticate",
                    "protocol_refusal",
                    &format!(
                        "{}: an Authentication Receive while expecting {}; AUTH_Failure1 ({})",
                        shown(&host),
                        other.expecting(),
                        auth::reason::name(auth::reason::INCORRECT_MESSAGE)
                    ),
                );
                self.authenticated = false;
                (
                    Message::Failure(auth::Failure {
                        second: false,
                        tid: 0,
                        rescode: auth::RESCODE_FAILED,
                        explanation: auth::reason::INCORRECT_MESSAGE,
                    }),
                    AuthState::Negotiate,
                    false,
                )
            }
        };
        let mut bytes = message.encode();
        self.auth = next;
        if done {
            self.authenticated = true;
            self.auth_by = None;
            let (host, _) = self.nqns();
            outcome(
                self.ctx,
                self.id,
                "authenticate",
                "protocol_accept",
                &format!("{} authenticated (unidirectional)", shown(&host)),
            );
        }
        bytes.resize(al, 0);
        Done::Data(bytes, 0)
    }
}
