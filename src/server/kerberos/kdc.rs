//! The KDC engine: everything between a request's bytes and the model's decision, and
//! everything between the decision and the reply's bytes. No I/O.
//!
//! [`Kdc::analyze`] reads a request and either answers it mechanically — a malformed message,
//! a wrong realm, an unsupported option or enctype, a pre-authentication that does not decrypt,
//! a stale or replayed timestamp, a TGT or authenticator that fails its integrity check — or
//! returns a [`Pending`] request for the model: a question of policy, asked only once every
//! cryptographic fact in it has been established.
//!
//! [`Kdc::issue`], [`Kdc::preauth_required`] and [`Kdc::refuse`] build the three answers the
//! model can choose. `issue` still enforces what is not policy: no ticket for a principal
//! without a configured key, none without pre-authentication when the principal requires it,
//! no lifetime past the configured ceiling, the TGT's end time or the client's own `till`, and
//! no flag the client did not ask for or its TGT does not carry.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag10,
    ExplicitContextTag11, ExplicitContextTag12, ExplicitContextTag2, ExplicitContextTag3,
    ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag6, ExplicitContextTag7,
    ExplicitContextTag8, ExplicitContextTag9, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_krb::data_types::{
    Authenticator, EncTicketPart, EncTicketPartInner, EncryptedData, HostAddresses, LastReqInner,
    PaData, PaEncTsEnc, Ticket, TicketInner, TransitedEncoding,
};
use picky_krb::messages::{
    ApReq, AsRep, AsReq, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KdcRep, KdcReq, KrbError,
    KrbErrorInner, TgsRep, TgsReq,
};
use serde_json::{json, Value};

use super::codec::{
    self, decode, encode, etype_name, flag_names, flags, flags_u32, int, int_i64, kdc_options,
    kstring, kstring_text, now_secs, rfc3339, ticket_flags, unix, Key, Principal, ETYPE_AES256,
    KDC_ERR_BADOPTION, KDC_ERR_C_PRINCIPAL_UNKNOWN, KDC_ERR_ETYPE_NOSUPP, KDC_ERR_NEVER_VALID,
    KDC_ERR_PADATA_TYPE_NOSUPP, KDC_ERR_PREAUTH_FAILED, KDC_ERR_PREAUTH_REQUIRED,
    KDC_ERR_S_PRINCIPAL_UNKNOWN, KDC_ERR_WRONG_REALM, KRB_AP_ERR_BADMATCH,
    KRB_AP_ERR_BAD_INTEGRITY, KRB_AP_ERR_INAPP_CKSUM, KRB_AP_ERR_MODIFIED, KRB_AP_ERR_MSG_TYPE,
    KRB_AP_ERR_REPEAT, KRB_AP_ERR_SKEW, KRB_AP_ERR_TKT_EXPIRED, KRB_AP_ERR_TKT_NYV,
    KRB_ERR_GENERIC, PA_ENC_TIMESTAMP, PA_ETYPE_INFO2, PA_TGS_REQ, SUPPORTED_ETYPES,
};

/// Remembered pre-authentication timestamps and TGS authenticators. Only requests that already
/// decrypted correctly are recorded, so a peer without a key cannot fill it.
pub const MAX_REPLAY_ENTRIES: usize = 65_536;

/// Most principals the operator may configure.
pub const MAX_PRINCIPALS: usize = 1024;

/// Most enctypes listed in an event; a request may list more, and they are still considered.
const MAX_ETYPES_SHOWN: usize = 16;

/// Key version number of every key this KDC holds. Keys come from configuration each start, so
/// there is only ever one version.
pub const KVNO: i64 = 1;

/// The ticket-granting service's keys are random for the life of the server: a TGT does not
/// survive a restart, and no key the operator typed protects every ticket.
const KRBTGT: &str = "krbtgt";

/// A configured principal: its keys (one per supported enctype) and how they were salted.
pub struct PrincipalEntry {
    pub principal: Principal,
    keys: Vec<Key>,
    pub salt: String,
    pub require_preauth: bool,
}

impl PrincipalEntry {
    fn key(&self, etype: i32) -> Option<&Key> {
        self.keys.iter().find(|k| k.etype() == etype)
    }

    /// The strongest key, which encrypts tickets for this principal.
    fn best_key(&self) -> &Key {
        self.key(ETYPE_AES256).unwrap_or(&self.keys[0])
    }
}

/// Operator configuration, with every key already derived. Not `Debug`.
pub struct KdcConfig {
    pub realm: String,
    principals: HashMap<Vec<String>, PrincipalEntry>,
    pub max_ticket_lifetime: i64,
    pub max_renewable_lifetime: i64,
    pub max_skew: i64,
}

impl KdcConfig {
    /// Derive every key. `passwords` maps a principal name (`alice`, `host/web.example.com`,
    /// optionally with `@REALM`) to its password; `no_preauth` lists principals that may be
    /// issued a ticket without pre-authentication.
    pub fn new(
        realm: &str,
        passwords: &[(String, String)],
        no_preauth: &[String],
        max_ticket_lifetime: i64,
        max_renewable_lifetime: i64,
        max_skew: i64,
    ) -> Result<Self> {
        codec::check_realm(realm)?;
        if passwords.is_empty() {
            return Err(anyhow!(
                "principal_passwords names no principal; a KDC with no principals can issue \
                 nothing"
            ));
        }
        if passwords.len() > MAX_PRINCIPALS {
            return Err(anyhow!(
                "at most {MAX_PRINCIPALS} principals may be configured"
            ));
        }
        let mut principals = HashMap::new();
        for (name, password) in passwords {
            let (principal, named_realm) =
                Principal::parse(name).with_context(|| format!("principal '{name}'"))?;
            if let Some(r) = named_realm {
                if r != realm {
                    return Err(anyhow!(
                        "principal '{name}' names realm {r}, but this KDC serves {realm}"
                    ));
                }
            }
            if principal.components.first().map(String::as_str) == Some(KRBTGT) {
                return Err(anyhow!(
                    "'{name}' is reserved: the ticket-granting service's key is generated at \
                     startup and never configured"
                ));
            }
            if password.is_empty() {
                return Err(anyhow!("principal '{name}' has an empty password"));
            }
            let salt = principal.default_salt(realm);
            let keys = SUPPORTED_ETYPES
                .iter()
                .map(|e| Key::from_password(*e, password, &salt))
                .collect::<Result<Vec<_>>>()?;
            let require_preauth = !no_preauth.iter().any(|n| {
                Principal::parse(n)
                    .map(|(p, _)| p.same_name(&principal))
                    .unwrap_or(false)
            });
            if principals
                .insert(
                    principal.components.clone(),
                    PrincipalEntry {
                        principal,
                        keys,
                        salt,
                        require_preauth,
                    },
                )
                .is_some()
            {
                return Err(anyhow!("principal '{name}' is configured twice"));
            }
        }
        for n in no_preauth {
            let (p, _) =
                Principal::parse(n).with_context(|| format!("no_preauth principal '{n}'"))?;
            if !principals.contains_key(&p.components) {
                return Err(anyhow!(
                    "no_preauth_principals names '{n}', which principal_passwords does not"
                ));
            }
        }
        let tgs = Principal::krbtgt(realm);
        let keys = SUPPORTED_ETYPES
            .iter()
            .map(|e| Key::random(*e))
            .collect::<Result<Vec<_>>>()?;
        principals.insert(
            tgs.components.clone(),
            PrincipalEntry {
                salt: tgs.default_salt(realm),
                principal: tgs,
                keys,
                require_preauth: true,
            },
        );
        Ok(Self {
            realm: realm.to_string(),
            principals,
            max_ticket_lifetime,
            max_renewable_lifetime,
            max_skew,
        })
    }

    fn entry(&self, p: &Principal) -> Option<&PrincipalEntry> {
        self.principals.get(&p.components)
    }

    /// Every configured principal's name, for the startup log. Names only.
    pub fn principal_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .principals
            .values()
            .map(|e| e.principal.to_string())
            .collect();
        v.sort();
        v
    }
}

/// Which exchange a pending request belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exchange {
    As,
    Tgs,
}

/// What the TGT presented with a TGS-REQ established.
#[derive(Clone)]
pub struct TgtFacts {
    pub flags: u32,
    pub authtime: i64,
    pub endtime: i64,
    pub renew_till: Option<i64>,
}

/// A request whose cryptography checked out, waiting for the model's policy decision.
/// Holds the key the reply will be encrypted in, so it is not `Debug`.
pub struct Pending {
    pub exchange: Exchange,
    pub client: Principal,
    pub client_realm: String,
    pub client_known: bool,
    pub service: Principal,
    pub service_known: bool,
    pub options: u32,
    /// The client's requested end time; `None` means "as long as allowed" (RFC 4120's zero).
    pub till: Option<i64>,
    pub rtime: Option<i64>,
    pub nonce: IntegerAsn1,
    /// The client's enctypes, in its order.
    pub etypes: Vec<i32>,
    pub addresses: Option<HostAddresses>,
    /// The enctype a verified PA-ENC-TIMESTAMP was made with.
    pub preauth_etype: Option<i32>,
    /// TGS only: the key and usage the reply's encrypted part uses (subkey or session key).
    reply_key: Option<(Key, i32)>,
    pub tgt: Option<TgtFacts>,
    pub source: SocketAddr,
    pub transport: &'static str,
}

impl Pending {
    pub fn preauth_verified(&self) -> bool {
        self.preauth_etype.is_some()
    }

    /// The first enctype the client listed that this KDC supports.
    fn session_etype(&self) -> Option<i32> {
        self.etypes
            .iter()
            .copied()
            .find(|e| SUPPORTED_ETYPES.contains(e))
    }
}

/// A reply produced without asking the model.
pub struct Mechanical {
    pub reply: Vec<u8>,
    /// Stable `decision=` token for the log.
    pub decision: &'static str,
    pub detail: String,
}

/// What [`Kdc::analyze`] concluded.
pub enum Analysis {
    /// Answered by Rust; the model is not asked.
    Answer(Mechanical),
    /// A policy question for the model.
    Ask(Box<Pending>),
    /// Not a request; a KDC does not answer replies.
    Ignore(String),
}

/// What the model granted with `kerberos_issue_ticket`. Every field narrows; none widens past
/// what the request asked for and the configuration allows.
#[derive(Debug, Clone, Default)]
pub struct Grant {
    pub lifetime_secs: Option<i64>,
    pub renewable_lifetime_secs: Option<i64>,
    pub renewable: bool,
    pub forwardable: bool,
    pub proxiable: bool,
    pub ok_as_delegate: bool,
}

/// The outcome of [`Kdc::issue`].
pub enum Issued {
    /// A ticket, and what it carries (for the log and the access record).
    Ticket {
        reply: Vec<u8>,
        summary: Value,
        clamped: bool,
    },
    /// Rust refused although the model said issue: what is missing is not policy.
    Enforced {
        reply: Vec<u8>,
        decision: &'static str,
        detail: String,
    },
}

#[derive(Default)]
struct ReplayCache {
    seen: HashMap<(String, i64, i64), i64>,
}

impl ReplayCache {
    /// Record `key`, expiring at `expiry`. `false` when it was already there (a replay) or the
    /// cache is full of live entries.
    fn insert(&mut self, key: (String, i64, i64), expiry: i64, now: i64) -> bool {
        if self.seen.contains_key(&key) {
            return false;
        }
        if self.seen.len() >= MAX_REPLAY_ENTRIES {
            self.seen.retain(|_, exp| *exp > now);
            if self.seen.len() >= MAX_REPLAY_ENTRIES {
                return false;
            }
        }
        self.seen.insert(key, expiry);
        true
    }
}

/// The KDC: configuration plus the replay cache.
pub struct Kdc {
    pub config: KdcConfig,
    replay: Mutex<ReplayCache>,
}

/// Build a mechanical answer.
fn mech(reply: Vec<u8>, decision: &'static str, detail: impl Into<String>) -> Analysis {
    Analysis::Answer(Mechanical {
        reply,
        decision,
        detail: detail.into(),
    })
}

fn opt_time(t: &picky_krb::data_types::KerberosTime) -> Option<i64> {
    // RFC 4120 §5.4.1: a `till` of 19700101000000Z means "as late as allowed".
    unix(t).filter(|s| *s > 0)
}

impl Kdc {
    pub fn new(config: KdcConfig) -> Self {
        Self {
            config,
            replay: Mutex::new(ReplayCache::default()),
        }
    }

    // -----------------------------------------------------------------------------------------
    // KRB-ERROR
    // -----------------------------------------------------------------------------------------

    /// A KRB-ERROR. `sname` defaults to the TGS; `client` adds crealm/cname.
    pub fn error(
        &self,
        code: i32,
        sname: Option<&Principal>,
        client: Option<(&Principal, &str)>,
        e_text: Option<&str>,
        e_data: Option<Vec<u8>>,
    ) -> Vec<u8> {
        match self.try_error(code, sname, client, e_text, e_data) {
            Ok(v) => v,
            // Only a name that is not IA5 could make this fail, and every name reaching here
            // was validated. If it ever did, answer the bare error rather than nothing.
            Err(_) => self
                .try_error(code, None, None, None, None)
                .unwrap_or_default(),
        }
    }

    fn try_error(
        &self,
        code: i32,
        sname: Option<&Principal>,
        client: Option<(&Principal, &str)>,
        e_text: Option<&str>,
        e_data: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let realm = &self.config.realm;
        let sname = match sname {
            Some(s) => s.clone(),
            None => Principal::krbtgt(realm),
        };
        let (crealm, cname) = match client {
            Some((p, r)) => (
                Optional(Some(ExplicitContextTag7(kstring(r)?))),
                Optional(Some(ExplicitContextTag8(p.to_asn1()?))),
            ),
            None => (Optional(None), Optional(None)),
        };
        let e_text = match e_text {
            Some(t) => Optional(Some(ExplicitContextTag11(kstring(t)?))),
            None => Optional(None),
        };
        let error = KrbError::from(KrbErrorInner {
            pvno: ExplicitContextTag0(int(5)),
            msg_type: ExplicitContextTag1(int(30)),
            ctime: Optional(None),
            cusec: Optional(None),
            stime: ExplicitContextTag4(codec::ktime(now_secs())),
            susec: ExplicitContextTag5(int(0)),
            error_code: ExplicitContextTag6(code as u32),
            crealm,
            cname,
            realm: ExplicitContextTag9(kstring(realm)?),
            sname: ExplicitContextTag10(sname.to_asn1()?),
            e_text,
            e_data: Optional(e_data.map(|d| ExplicitContextTag12(OctetStringAsn1(d)))),
        });
        encode(&error)
    }

    fn salt_for(&self, client: &Principal) -> String {
        match self.config.entry(client) {
            Some(e) => e.salt.clone(),
            None => client.default_salt(&self.config.realm),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Analysis
    // -----------------------------------------------------------------------------------------

    /// Read one request. See the module docs.
    pub fn analyze(&self, message: &[u8], source: SocketAddr, transport: &'static str) -> Analysis {
        let now = now_secs();
        match message.first() {
            Some(&codec::TAG_AS_REQ) => self.analyze_as(message, source, transport, now),
            Some(&codec::TAG_TGS_REQ) => self.analyze_tgs(message, source, transport, now),
            Some(&tag)
                if matches!(
                    tag,
                    codec::TAG_AS_REP
                        | codec::TAG_TGS_REP
                        | codec::TAG_KRB_ERROR
                        | codec::TAG_AP_REQ
                ) =>
            {
                Analysis::Ignore(format!("message tag 0x{tag:02x} is not a KDC request"))
            }
            _ => mech(
                self.error(KRB_AP_ERR_MSG_TYPE, None, None, None, None),
                "malformed",
                "not an AS-REQ or TGS-REQ",
            ),
        }
    }

    /// The checks every KDC-REQ shares: version, realm, options, enctypes, times.
    fn common(&self, req: &KdcReq, msg_type: i64) -> std::result::Result<Common, Analysis> {
        let malformed = |detail: &str| {
            mech(
                self.error(KRB_ERR_GENERIC, None, None, Some("malformed request"), None),
                "malformed",
                detail.to_string(),
            )
        };
        if int_i64(&req.pvno.0) != Some(5) {
            return Err(mech(
                self.error(3, None, None, None, None),
                "malformed",
                "protocol version is not 5",
            ));
        }
        if int_i64(&req.msg_type.0) != Some(msg_type) {
            return Err(malformed("msg-type does not match the application tag"));
        }
        let body = &req.req_body.0;
        let realm = kstring_text(&body.realm.0);
        if codec::check_realm(&realm).is_err() {
            return Err(malformed("realm is not a printable name"));
        }
        let sname = match &body.sname.0 {
            Some(s) => match Principal::from_asn1(&s.0) {
                Ok(p) => p,
                Err(e) => {
                    return Err(mech(
                        self.error(
                            KDC_ERR_S_PRINCIPAL_UNKNOWN,
                            None,
                            None,
                            Some("malformed service name"),
                            None,
                        ),
                        "malformed",
                        format!("service name: {e}"),
                    ))
                }
            },
            None => {
                return Err(mech(
                    self.error(KDC_ERR_S_PRINCIPAL_UNKNOWN, None, None, None, None),
                    "malformed",
                    "no service name",
                ))
            }
        };
        if realm != self.config.realm {
            return Err(mech(
                self.error(KDC_ERR_WRONG_REALM, Some(&sname), None, None, None),
                "wrong_realm",
                format!(
                    "request is for realm '{}'",
                    crate::utils::sanitize::line_field(&realm)
                ),
            ));
        }
        let options = flags_u32(&body.kdc_options.0);
        if options & kdc_options::UNSUPPORTED != 0 {
            return Err(mech(
                self.error(
                    KDC_ERR_BADOPTION,
                    Some(&sname),
                    None,
                    Some("this KDC does not implement the requested options"),
                    None,
                ),
                "unsupported_option",
                format!(
                    "options {:?}",
                    flag_names(options & kdc_options::UNSUPPORTED, kdc_options::NAMES)
                ),
            ));
        }
        let etypes: Vec<i32> = body
            .etype
            .0
             .0
            .iter()
            .filter_map(|e| int_i64(e).and_then(|v| i32::try_from(v).ok()))
            .collect();
        if !etypes.iter().any(|e| SUPPORTED_ETYPES.contains(e)) {
            return Err(mech(
                self.error(KDC_ERR_ETYPE_NOSUPP, Some(&sname), None, None, None),
                "etype_nosupp",
                format!(
                    "client offered {:?}; this KDC speaks aes256/aes128-cts-hmac-sha1-96 only",
                    etypes.iter().map(|e| etype_name(*e)).collect::<Vec<_>>()
                ),
            ));
        }
        let till = opt_time(&body.till.0);
        let rtime = body.rtime.0.as_ref().and_then(|t| opt_time(&t.0));
        Ok(Common {
            sname,
            options,
            etypes,
            till,
            rtime,
        })
    }

    fn analyze_as(
        &self,
        message: &[u8],
        source: SocketAddr,
        transport: &'static str,
        now: i64,
    ) -> Analysis {
        let req: AsReq = match decode(message) {
            Ok(r) => r,
            Err(e) => {
                return mech(
                    self.error(KRB_ERR_GENERIC, None, None, Some("malformed request"), None),
                    "malformed",
                    format!("AS-REQ: {e}"),
                )
            }
        };
        let req = req.0;
        let common = match self.common(&req, 10) {
            Ok(c) => c,
            Err(a) => return a,
        };
        let body = &req.req_body.0;
        let client = match body.cname.0.as_ref().map(|c| Principal::from_asn1(&c.0)) {
            Some(Ok(p)) => p,
            Some(Err(e)) => {
                return mech(
                    self.error(
                        KDC_ERR_C_PRINCIPAL_UNKNOWN,
                        Some(&common.sname),
                        None,
                        Some("malformed client name"),
                        None,
                    ),
                    "malformed",
                    format!("client name: {e}"),
                )
            }
            None => {
                return mech(
                    self.error(
                        KDC_ERR_C_PRINCIPAL_UNKNOWN,
                        Some(&common.sname),
                        None,
                        None,
                        None,
                    ),
                    "malformed",
                    "AS-REQ without a client name",
                )
            }
        };
        let realm = self.config.realm.clone();
        let client_entry = self.config.entry(&client);
        let service_known = self.config.entry(&common.sname).is_some();

        // Pre-authentication, verified here and nowhere else.
        let padata: &[PaData] = req
            .padata
            .0
            .as_ref()
            .map(|p| p.0 .0.as_slice())
            .unwrap_or(&[]);
        let mut preauth_etype = None;
        if let Some(pa) = padata
            .iter()
            .find(|p| codec::padata_type(p) == PA_ENC_TIMESTAMP as i64)
        {
            let refuse = |code: i32, decision: &'static str, detail: String| {
                mech(
                    self.error(
                        code,
                        Some(&common.sname),
                        Some((&client, &realm)),
                        None,
                        None,
                    ),
                    decision,
                    detail,
                )
            };
            let Some(entry) = client_entry else {
                // No key to check it with. Answered as a failed pre-authentication so that a
                // model that hides which principals exist (by requiring pre-authentication of
                // everyone) is not undone here.
                return refuse(
                    KDC_ERR_PREAUTH_FAILED,
                    "preauth_failed",
                    format!("{client}: no such principal, so its timestamp cannot verify"),
                );
            };
            let enc: EncryptedData = match decode(&pa.padata_data.0 .0) {
                Ok(e) => e,
                Err(e) => {
                    return refuse(
                        KDC_ERR_PREAUTH_FAILED,
                        "preauth_failed",
                        format!("{client}: PA-ENC-TIMESTAMP is not an EncryptedData: {e}"),
                    )
                }
            };
            let etype = int_i64(&enc.etype.0)
                .and_then(|v| i32::try_from(v).ok())
                .unwrap_or(-1);
            let Some(key) = entry.key(etype) else {
                return refuse(
                    KDC_ERR_ETYPE_NOSUPP,
                    "etype_nosupp",
                    format!("{client}: timestamp encrypted with {}", etype_name(etype)),
                );
            };
            let plain = match key.decrypt_data(codec::KU_PA_ENC_TIMESTAMP, &enc) {
                Ok(p) => p,
                Err(e) => {
                    return refuse(
                        KDC_ERR_PREAUTH_FAILED,
                        "preauth_failed",
                        format!("{client}: encrypted timestamp did not verify ({e})"),
                    )
                }
            };
            let ts: PaEncTsEnc = match decode(&plain) {
                Ok(t) => t,
                Err(e) => {
                    return refuse(
                        KDC_ERR_PREAUTH_FAILED,
                        "preauth_failed",
                        format!("{client}: decrypted timestamp is malformed: {e}"),
                    )
                }
            };
            let Some(stamp) = unix(&ts.patimestamp.0) else {
                return refuse(
                    KDC_ERR_PREAUTH_FAILED,
                    "preauth_failed",
                    format!("{client}: timestamp is not a date"),
                );
            };
            if (stamp - now).abs() > self.config.max_skew {
                return refuse(
                    KRB_AP_ERR_SKEW,
                    "preauth_skew",
                    format!(
                        "{client}: timestamp is {}s from this KDC's clock",
                        stamp - now
                    ),
                );
            }
            let usec = ts
                .pausec
                .0
                .as_ref()
                .and_then(|u| int_i64(&u.0))
                .unwrap_or(0);
            let fresh = self
                .replay
                .lock()
                .map(|mut c| {
                    c.insert(
                        (format!("as:{client}"), stamp, usec),
                        now + 2 * self.config.max_skew,
                        now,
                    )
                })
                .unwrap_or(false);
            if !fresh {
                return refuse(
                    KRB_AP_ERR_REPEAT,
                    "preauth_replay",
                    format!("{client}: this pre-authentication timestamp was already used"),
                );
            }
            preauth_etype = Some(etype);
        }

        Analysis::Ask(Box::new(Pending {
            exchange: Exchange::As,
            client_known: client_entry.is_some(),
            client,
            client_realm: realm,
            service: common.sname,
            service_known,
            options: common.options,
            till: common.till,
            rtime: common.rtime,
            nonce: body.nonce.0.clone(),
            etypes: common.etypes,
            addresses: body.addresses.0.as_ref().map(|a| a.0.clone()),
            preauth_etype,
            reply_key: None,
            tgt: None,
            source,
            transport,
        }))
    }

    fn analyze_tgs(
        &self,
        message: &[u8],
        source: SocketAddr,
        transport: &'static str,
        now: i64,
    ) -> Analysis {
        let req: TgsReq = match decode(message) {
            Ok(r) => r,
            Err(e) => {
                return mech(
                    self.error(KRB_ERR_GENERIC, None, None, Some("malformed request"), None),
                    "malformed",
                    format!("TGS-REQ: {e}"),
                )
            }
        };
        let req = req.0;
        let common = match self.common(&req, 12) {
            Ok(c) => c,
            Err(a) => return a,
        };
        let sname = common.sname.clone();
        let fail = |code: i32, decision: &'static str, detail: String| {
            mech(
                self.error(code, Some(&sname), None, None, None),
                decision,
                detail,
            )
        };
        let padata: &[PaData] = req
            .padata
            .0
            .as_ref()
            .map(|p| p.0 .0.as_slice())
            .unwrap_or(&[]);
        let Some(pa) = padata
            .iter()
            .find(|p| codec::padata_type(p) == PA_TGS_REQ as i64)
        else {
            return fail(
                KDC_ERR_PADATA_TYPE_NOSUPP,
                "malformed",
                "TGS-REQ without PA-TGS-REQ".into(),
            );
        };
        let ap_bytes = &pa.padata_data.0 .0;
        if ap_bytes.first() != Some(&codec::TAG_AP_REQ) {
            return fail(
                KRB_AP_ERR_MSG_TYPE,
                "malformed",
                "PA-TGS-REQ is not an AP-REQ".into(),
            );
        }
        let ap: ApReq = match decode(ap_bytes) {
            Ok(a) => a,
            Err(e) => return fail(KRB_AP_ERR_MSG_TYPE, "malformed", format!("AP-REQ: {e}")),
        };
        let ap = ap.0;
        let ticket = &ap.ticket.0 .0;
        let tkt_sname = match Principal::from_asn1(&ticket.sname.0) {
            Ok(p) => p,
            Err(e) => {
                return fail(
                    KRB_AP_ERR_BAD_INTEGRITY,
                    "tgt_invalid",
                    format!("TGT sname: {e}"),
                )
            }
        };
        if kstring_text(&ticket.realm.0) != self.config.realm
            || !tkt_sname.is_krbtgt(&self.config.realm)
        {
            return fail(
                35,
                "tgt_not_ours",
                format!("presented ticket is for {tkt_sname}, not this realm's TGS"),
            );
        }
        let tgs = self
            .config
            .entry(&Principal::krbtgt(&self.config.realm))
            .expect("the TGS entry is created with the configuration");
        let tkt_etype = int_i64(&ticket.enc_part.0.etype.0)
            .and_then(|v| i32::try_from(v).ok())
            .unwrap_or(-1);
        let Some(tgs_key) = tgs.key(tkt_etype) else {
            return fail(
                KRB_AP_ERR_BAD_INTEGRITY,
                "tgt_invalid",
                format!("TGT encrypted with {}", etype_name(tkt_etype)),
            );
        };
        let enc_ticket: EncTicketPart = match tgs_key
            .decrypt_data(codec::KU_TICKET, &ticket.enc_part.0)
            .map_err(|e| anyhow!(e))
            .and_then(|p| decode(&p))
        {
            Ok(t) => t,
            Err(e) => {
                return fail(
                    KRB_AP_ERR_BAD_INTEGRITY,
                    "tgt_integrity",
                    format!("TGT did not decrypt with this KDC's key: {e}"),
                )
            }
        };
        let et = enc_ticket.0;
        let client = match Principal::from_asn1(&et.cname.0) {
            Ok(p) => p,
            Err(e) => {
                return fail(
                    KRB_AP_ERR_BAD_INTEGRITY,
                    "tgt_invalid",
                    format!("TGT cname: {e}"),
                )
            }
        };
        let crealm = kstring_text(&et.crealm.0);
        let fail_c = |code: i32, decision: &'static str, detail: String| {
            mech(
                self.error(code, Some(&sname), Some((&client, &crealm)), None, None),
                decision,
                detail,
            )
        };
        let tgt_flags = flags_u32(&et.flags.0);
        let (Some(authtime), Some(endtime)) = (unix(&et.auth_time.0), unix(&et.endtime.0)) else {
            return fail_c(
                KRB_AP_ERR_BAD_INTEGRITY,
                "tgt_invalid",
                "TGT times are not dates".into(),
            );
        };
        if endtime + self.config.max_skew < now {
            return fail_c(
                KRB_AP_ERR_TKT_EXPIRED,
                "tgt_expired",
                format!("{client}: TGT expired"),
            );
        }
        let start = et
            .starttime
            .0
            .as_ref()
            .and_then(|t| unix(&t.0))
            .unwrap_or(authtime);
        if start - self.config.max_skew > now || tgt_flags & ticket_flags::INVALID != 0 {
            return fail_c(
                KRB_AP_ERR_TKT_NYV,
                "tgt_not_yet_valid",
                format!("{client}: TGT not yet valid"),
            );
        }
        let renew_till = et.renew_till.0.as_ref().and_then(|t| unix(&t.0));
        let session = match Key::from_asn1(&et.key.0) {
            Ok(k) => k,
            Err(e) => {
                return fail_c(
                    KRB_AP_ERR_BAD_INTEGRITY,
                    "tgt_invalid",
                    format!("TGT key: {e}"),
                )
            }
        };
        let authenticator: Authenticator = match session
            .decrypt_data(codec::KU_TGS_REQ_AUTHENTICATOR, &ap.authenticator.0)
            .map_err(|e| anyhow!(e))
            .and_then(|p| decode(&p))
        {
            Ok(a) => a,
            Err(e) => {
                return fail_c(
                    KRB_AP_ERR_BAD_INTEGRITY,
                    "authenticator_integrity",
                    format!(
                        "{client}: authenticator did not decrypt with the TGT session key: {e}"
                    ),
                )
            }
        };
        let auth = authenticator.0;
        let auth_client = Principal::from_asn1(&auth.cname.0).ok();
        if auth_client.as_ref().map(|p| p.same_name(&client)) != Some(true)
            || kstring_text(&auth.crealm.0) != crealm
        {
            return fail_c(
                KRB_AP_ERR_BADMATCH,
                "authenticator_mismatch",
                format!("{client}: authenticator names a different client"),
            );
        }
        let Some(ctime) = unix(&auth.ctime.0) else {
            return fail_c(
                KRB_AP_ERR_SKEW,
                "authenticator_skew",
                "authenticator time is not a date".into(),
            );
        };
        if (ctime - now).abs() > self.config.max_skew {
            return fail_c(
                KRB_AP_ERR_SKEW,
                "authenticator_skew",
                format!(
                    "{client}: authenticator is {}s from this KDC's clock",
                    ctime - now
                ),
            );
        }
        // The checksum binds the authenticator to this request body. Without it a captured
        // authenticator could be stapled to a different request within the skew window.
        let Some(cksum) = auth.cksum.0.as_ref() else {
            return fail_c(
                KRB_AP_ERR_INAPP_CKSUM,
                "checksum_missing",
                format!("{client}: authenticator carries no checksum over the request body"),
            );
        };
        let Some(body_bytes) = codec::req_body_bytes(message) else {
            return fail_c(
                KRB_ERR_GENERIC,
                "malformed",
                "request body could not be located".into(),
            );
        };
        let cksumtype = int_i64(&cksum.0.cksumtype.0)
            .and_then(|v| i32::try_from(v).ok())
            .unwrap_or(-1);
        if cksumtype != session.checksum_type() {
            return fail_c(
                KRB_AP_ERR_INAPP_CKSUM,
                "checksum_type",
                format!("{client}: checksum type {cksumtype} is not keyed with the session key"),
            );
        }
        if !session.verify_checksum(
            cksumtype,
            codec::KU_TGS_REQ_AUTH_CKSUM,
            body_bytes,
            &cksum.0.checksum.0 .0,
        ) {
            return fail_c(
                KRB_AP_ERR_MODIFIED,
                "checksum_mismatch",
                format!("{client}: request body does not match the authenticator's checksum"),
            );
        }
        let cusec = int_i64(&auth.cusec.0).unwrap_or(0);
        let fresh = self
            .replay
            .lock()
            .map(|mut c| {
                c.insert(
                    (format!("tgs:{client}@{crealm}"), ctime, cusec),
                    now + 2 * self.config.max_skew,
                    now,
                )
            })
            .unwrap_or(false);
        if !fresh {
            return fail_c(
                KRB_AP_ERR_REPEAT,
                "authenticator_replay",
                format!("{client}: authenticator already used"),
            );
        }
        let reply_key = match auth.subkey.0.as_ref() {
            Some(sk) => match Key::from_asn1(&sk.0) {
                Ok(k) => (k, codec::KU_TGS_REP_ENC_SUBKEY),
                Err(e) => {
                    return fail_c(
                        KDC_ERR_ETYPE_NOSUPP,
                        "etype_nosupp",
                        format!("{client}: authenticator subkey: {e}"),
                    )
                }
            },
            None => (session.clone(), codec::KU_TGS_REP_ENC_SESSION_KEY),
        };
        let body = &req.req_body.0;
        Analysis::Ask(Box::new(Pending {
            exchange: Exchange::Tgs,
            client_known: crealm == self.config.realm && self.config.entry(&client).is_some(),
            client,
            client_realm: crealm,
            service_known: self.config.entry(&common.sname).is_some(),
            service: common.sname,
            options: common.options,
            till: common.till,
            rtime: common.rtime,
            nonce: body.nonce.0.clone(),
            etypes: common.etypes,
            addresses: body.addresses.0.as_ref().map(|a| a.0.clone()),
            preauth_etype: None,
            reply_key: Some(reply_key),
            tgt: Some(TgtFacts {
                flags: tgt_flags,
                authtime,
                endtime,
                renew_till,
            }),
            source,
            transport,
        }))
    }

    // -----------------------------------------------------------------------------------------
    // What the model is shown
    // -----------------------------------------------------------------------------------------

    /// The event payload for a pending request. Names, times, options and facts; never a key.
    pub fn event_data(&self, p: &Pending) -> Value {
        let now = now_secs();
        let span = |t: Option<i64>| t.map(|t| t - now);
        let mut data = json!({
            "client": p.client.to_string(),
            "client_realm": p.client_realm,
            "client_known": p.client_known,
            "service": p.service.to_string(),
            "service_known": p.service_known,
            "service_is_tgs": p.service.is_krbtgt(&self.config.realm),
            "requested_lifetime_secs": span(p.till),
            "requested_renewable_lifetime_secs": span(p.rtime),
            "options": flag_names(p.options, kdc_options::NAMES),
            "etypes": p.etypes.iter().take(MAX_ETYPES_SHOWN).map(|e| etype_name(*e)).collect::<Vec<_>>(),
            "addresses": p.addresses.as_ref().map(addresses_json).unwrap_or_default(),
            "source_addr": p.source.to_string(),
            "transport": p.transport,
            "max_ticket_lifetime_secs": self.config.max_ticket_lifetime,
            "max_renewable_lifetime_secs": self.config.max_renewable_lifetime,
        });
        match p.exchange {
            Exchange::As => {
                data["preauth"] = json!(if p.preauth_verified() {
                    "verified"
                } else {
                    "none"
                });
                let required = self
                    .config
                    .entry(&p.client)
                    .map(|e| e.require_preauth)
                    .unwrap_or(true);
                data["preauth_required_by_config"] = json!(required);
            }
            Exchange::Tgs => {
                if let Some(t) = &p.tgt {
                    data["tgt_flags"] = json!(flag_names(t.flags, ticket_flags::NAMES));
                    data["tgt_expires_in_secs"] = json!(t.endtime - now);
                    data["tgt_authtime"] = json!(rfc3339(t.authtime));
                    data["tgt_renew_till"] = json!(t.renew_till.map(rfc3339));
                }
            }
        }
        data
    }

    // -----------------------------------------------------------------------------------------
    // The three answers
    // -----------------------------------------------------------------------------------------

    /// KDC_ERR_PREAUTH_REQUIRED with METHOD-DATA naming PA-ENC-TIMESTAMP and an ETYPE-INFO2
    /// entry, with salt, for each enctype the client offered that this KDC speaks. Answered for
    /// an unknown principal too, if that is what the model chose, with the salt it would have.
    pub fn preauth_required(&self, p: &Pending) -> Result<Vec<u8>> {
        if p.exchange != Exchange::As {
            return Err(anyhow!(
                "pre-authentication applies to the AS exchange only"
            ));
        }
        let salt = self.salt_for(&p.client);
        let entries: Vec<(i32, String)> = p
            .etypes
            .iter()
            .copied()
            .filter(|e| SUPPORTED_ETYPES.contains(e))
            .map(|e| (e, salt.clone()))
            .collect();
        let method_data = Asn1SequenceOf(vec![
            codec::padata(PA_ENC_TIMESTAMP, Vec::new()),
            codec::padata(PA_ETYPE_INFO2, codec::etype_info2(&entries)?),
        ]);
        Ok(self.error(
            KDC_ERR_PREAUTH_REQUIRED,
            Some(&p.service),
            Some((&p.client, &p.client_realm)),
            None,
            Some(encode(&method_data)?),
        ))
    }

    /// The KRB-ERROR the model chose. `code` has been checked against the model's vocabulary.
    pub fn refuse(&self, p: &Pending, code: i32, text: Option<&str>) -> Vec<u8> {
        let text = text.map(crate::utils::sanitize::line_field);
        self.error(
            code,
            Some(&p.service),
            Some((&p.client, &p.client_realm)),
            text.as_deref(),
            None,
        )
    }

    /// The answer when no decision was produced. Never a ticket.
    pub fn fail_closed(&self, p: &Pending, code: i32, text: &str) -> Vec<u8> {
        self.error(
            code,
            Some(&p.service),
            Some((&p.client, &p.client_realm)),
            Some(text),
            None,
        )
    }

    /// Issue the ticket the model granted, within every bound that is not the model's to move.
    pub fn issue(&self, p: &Pending, grant: &Grant) -> Result<Issued> {
        let enforced = |code: i32, decision: &'static str, detail: String| -> Result<Issued> {
            Ok(Issued::Enforced {
                reply: self.error(
                    code,
                    Some(&p.service),
                    Some((&p.client, &p.client_realm)),
                    None,
                    None,
                ),
                decision,
                detail,
            })
        };
        let now = now_secs();
        let config = &self.config;

        // Who: both ends need a key, and the AS exchange needs pre-authentication where the
        // principal requires it.
        let client_entry = config.entry(&p.client);
        if p.exchange == Exchange::As {
            let Some(entry) = client_entry else {
                return enforced(
                    KDC_ERR_C_PRINCIPAL_UNKNOWN,
                    "enforced_unknown_client",
                    format!(
                        "{}: no key is configured, so no ticket can be issued",
                        p.client
                    ),
                );
            };
            if entry.require_preauth && !p.preauth_verified() {
                return Ok(Issued::Enforced {
                    reply: self.preauth_required(p)?,
                    decision: "enforced_preauth_required",
                    detail: format!("{}: pre-authentication is required", p.client),
                });
            }
        }
        let Some(service_entry) = config.entry(&p.service) else {
            return enforced(
                KDC_ERR_S_PRINCIPAL_UNKNOWN,
                "enforced_unknown_service",
                format!("{}: no key is configured for this service", p.service),
            );
        };
        let Some(session_etype) = p.session_etype() else {
            return enforced(
                KDC_ERR_ETYPE_NOSUPP,
                "etype_nosupp",
                "no common enctype".into(),
            );
        };

        // When: the shortest of the model's lifetime, the ceiling, the client's till and (TGS)
        // the TGT's own end.
        let mut clamped = false;
        let ceiling = config.max_ticket_lifetime;
        let model_life = match grant.lifetime_secs {
            Some(l) if l > ceiling => {
                clamped = true;
                ceiling
            }
            Some(l) => l,
            None => ceiling,
        };
        let mut end = now.saturating_add(model_life);
        if let Some(till) = p.till {
            end = end.min(till);
        }
        if let Some(tgt) = &p.tgt {
            end = end.min(tgt.endtime);
        }
        if end <= now {
            return enforced(
                KDC_ERR_NEVER_VALID,
                "enforced_never_valid",
                format!("{}: the ticket would end before it starts", p.client),
            );
        }

        // Flags: what the model grants, intersected with what the client asked for and, in
        // the TGS exchange, what the TGT itself carries.
        let tgt_flags = p.tgt.as_ref().map(|t| t.flags);
        let tgt_allows = |f: u32| tgt_flags.map(|t| t & f != 0).unwrap_or(true);
        let mut tflags = 0u32;
        match p.exchange {
            Exchange::As => {
                tflags |= ticket_flags::INITIAL;
                if p.preauth_verified() {
                    tflags |= ticket_flags::PRE_AUTHENT;
                }
            }
            Exchange::Tgs => {
                if tgt_flags.unwrap_or(0) & ticket_flags::PRE_AUTHENT != 0 {
                    tflags |= ticket_flags::PRE_AUTHENT;
                }
            }
        }
        if grant.forwardable
            && p.options & kdc_options::FORWARDABLE != 0
            && tgt_allows(ticket_flags::FORWARDABLE)
        {
            tflags |= ticket_flags::FORWARDABLE;
        }
        if grant.proxiable
            && p.options & kdc_options::PROXIABLE != 0
            && tgt_allows(ticket_flags::PROXIABLE)
        {
            tflags |= ticket_flags::PROXIABLE;
        }
        if grant.ok_as_delegate && !p.service.is_krbtgt(&config.realm) {
            tflags |= ticket_flags::OK_AS_DELEGATE;
        }
        let mut renew_till = None;
        let wants_renewable = p.options & kdc_options::RENEWABLE != 0
            || (p.options & kdc_options::RENEWABLE_OK != 0
                && p.till.map(|t| t > end).unwrap_or(true));
        if grant.renewable && wants_renewable && tgt_allows(ticket_flags::RENEWABLE) {
            let rceiling = config.max_renewable_lifetime;
            let rlife = match grant.renewable_lifetime_secs {
                Some(l) if l > rceiling => {
                    clamped = true;
                    rceiling
                }
                Some(l) => l,
                None => rceiling,
            };
            let mut rtill = now.saturating_add(rlife);
            if p.options & kdc_options::RENEWABLE != 0 {
                if let Some(r) = p.rtime {
                    rtill = rtill.min(r);
                }
            } else if let Some(t) = p.till {
                rtill = rtill.min(t);
            }
            if let Some(t) = p.tgt.as_ref().and_then(|t| t.renew_till) {
                rtill = rtill.min(t);
            }
            if rtill > end {
                tflags |= ticket_flags::RENEWABLE;
                renew_till = Some(rtill);
            }
        }

        let authtime = p.tgt.as_ref().map(|t| t.authtime).unwrap_or(now);
        let session = Key::random(session_etype)?;
        let realm = &config.realm;
        let cname = p.client.to_asn1()?;
        let crealm = kstring(&p.client_realm)?;
        let sname = p.service.to_asn1()?;

        let enc_ticket = EncTicketPart::from(EncTicketPartInner {
            flags: ExplicitContextTag0(flags(tflags)),
            key: ExplicitContextTag1(session.to_asn1()),
            crealm: ExplicitContextTag2(crealm.clone()),
            cname: ExplicitContextTag3(cname.clone()),
            transited: ExplicitContextTag4(TransitedEncoding {
                tr_type: ExplicitContextTag0(int(1)),
                contents: ExplicitContextTag1(OctetStringAsn1(Vec::new())),
            }),
            auth_time: ExplicitContextTag5(codec::ktime(authtime)),
            starttime: Optional(Some(ExplicitContextTag6(codec::ktime(now)))),
            endtime: ExplicitContextTag7(codec::ktime(end)),
            renew_till: Optional(renew_till.map(|t| ExplicitContextTag8(codec::ktime(t)))),
            caddr: Optional(p.addresses.clone().map(ExplicitContextTag9)),
            authorization_data: Optional(None),
        });
        let ticket_key = service_entry.best_key();
        let ticket = Ticket::from(TicketInner {
            tkt_vno: ExplicitContextTag0(int(5)),
            realm: ExplicitContextTag1(kstring(realm)?),
            sname: ExplicitContextTag2(sname.clone()),
            enc_part: ExplicitContextTag3(ticket_key.encrypted_data(
                codec::KU_TICKET,
                &encode(&enc_ticket)?,
                Some(KVNO),
            )?),
        });

        let rep_part = EncKdcRepPart {
            key: ExplicitContextTag0(session.to_asn1()),
            last_req: ExplicitContextTag1(Asn1SequenceOf(vec![LastReqInner {
                lr_type: ExplicitContextTag0(int(0)),
                lr_value: ExplicitContextTag1(codec::ktime(now)),
            }])),
            nonce: ExplicitContextTag2(p.nonce.clone()),
            key_expiration: Optional(None),
            flags: ExplicitContextTag4(flags(tflags)),
            auth_time: ExplicitContextTag5(codec::ktime(authtime)),
            start_time: Optional(Some(ExplicitContextTag6(codec::ktime(now)))),
            end_time: ExplicitContextTag7(codec::ktime(end)),
            renew_till: Optional(renew_till.map(|t| ExplicitContextTag8(codec::ktime(t)))),
            srealm: ExplicitContextTag9(kstring(realm)?),
            sname: ExplicitContextTag10(sname),
            caddr: Optional(p.addresses.clone().map(ExplicitContextTag11)),
            encrypted_pa_data: Optional(None),
        };

        let (msg_type, padata, enc_part) = match p.exchange {
            Exchange::As => {
                let entry = client_entry.expect("checked above");
                // The reply key: the enctype the client pre-authenticated with, or else the
                // first of its enctypes this principal has a key for.
                let etype = p
                    .preauth_etype
                    .or_else(|| p.etypes.iter().copied().find(|e| entry.key(*e).is_some()));
                let Some(key) = etype.and_then(|e| entry.key(e)) else {
                    return enforced(KDC_ERR_ETYPE_NOSUPP, "etype_nosupp", "no client key".into());
                };
                let info = codec::etype_info2(&[(key.etype(), entry.salt.clone())])?;
                let enc = key.encrypted_data(
                    codec::KU_AS_REP_ENC_PART,
                    &encode(&EncAsRepPart::from(rep_part))?,
                    Some(KVNO),
                )?;
                (
                    11,
                    Optional(Some(ExplicitContextTag2(Asn1SequenceOf(vec![
                        codec::padata(PA_ETYPE_INFO2, info),
                    ])))),
                    enc,
                )
            }
            Exchange::Tgs => {
                let (key, usage) = p
                    .reply_key
                    .as_ref()
                    .context("a TGS request carries its reply key")?;
                let enc =
                    key.encrypted_data(*usage, &encode(&EncTgsRepPart::from(rep_part))?, None)?;
                (13, Optional(None), enc)
            }
        };
        let rep = KdcRep {
            pvno: ExplicitContextTag0(int(5)),
            msg_type: ExplicitContextTag1(int(msg_type)),
            padata,
            crealm: ExplicitContextTag3(crealm),
            cname: ExplicitContextTag4(cname),
            ticket: ExplicitContextTag5(ticket),
            enc_part: ExplicitContextTag6(enc_part),
        };
        let reply = match p.exchange {
            Exchange::As => encode(&AsRep::from(rep))?,
            Exchange::Tgs => encode(&TgsRep::from(rep))?,
        };
        let summary = json!({
            "client": format!("{}@{}", p.client, p.client_realm),
            "service": format!("{}@{}", p.service, realm),
            "starttime": rfc3339(now),
            "endtime": rfc3339(end),
            "lifetime_secs": end - now,
            "renew_till": renew_till.map(rfc3339),
            "flags": flag_names(tflags, ticket_flags::NAMES),
            "session_etype": etype_name(session_etype),
            "ticket_etype": etype_name(ticket_key.etype()),
        });
        Ok(Issued::Ticket {
            reply,
            summary,
            clamped,
        })
    }
}

/// The checks shared by AS-REQ and TGS-REQ.
struct Common {
    sname: Principal,
    options: u32,
    etypes: Vec<i32>,
    till: Option<i64>,
    rtime: Option<i64>,
}

/// Host addresses as text: dotted quads and IPv6 where the type says so, hex otherwise.
pub fn addresses_json(addrs: &HostAddresses) -> Vec<Value> {
    addrs
        .0
        .iter()
        .take(16)
        .map(|a| {
            let kind = int_i64(&a.addr_type.0).unwrap_or(-1);
            let bytes = &a.address.0 .0;
            match (kind, bytes.len()) {
                (2, 4) => json!(
                    std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
                ),
                (24, 16) => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(bytes);
                    json!(std::net::Ipv6Addr::from(b).to_string())
                }
                _ => json!({"type": kind, "hex": hex::encode(bytes)}),
            }
        })
        .collect()
}
