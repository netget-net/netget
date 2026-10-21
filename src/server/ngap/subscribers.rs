//! The AMF's subscriber credentials and SUCI keys — the part of a 5G core that would be the
//! UDM/ARPF and the SIDF, held in memory for the life of the server.
//!
//! Everything here comes from startup parameters whose names `src/utils/redact.rs` masks
//! (`subscriber_key`, `subscriber_opc`/`subscriber_op`, `home_network_private_key`), and nothing
//! here is ever put in an event, a log line or the model's prompt. The model decides *who* may
//! register; it never sees a key.
//!
//! The SQN is the only state that changes: each vector advances it by 32 (one step of SEQ with a
//! 5-bit IND, as Open5GS's UDM does), and a UE's AUTS resynchronises it.

use super::nas;
use super::security::{self, AkaVector, Milenage, MAX_SQN};
use super::suci;
use serde_json::Value;
use std::collections::BTreeMap;

/// Subscribers one AMF holds.
pub const MAX_SUBSCRIBERS: usize = 1024;
/// SUCI deconcealment keys one AMF holds.
pub const MAX_SUCI_KEYS: usize = 16;
/// How far one vector advances the SQN: SEQ + 1 with a 5-bit IND (TS 33.102 Annex C.3.2).
pub const SQN_STEP: u64 = 32;
/// The AMF field's default: the separation bit set, nothing else (TS 33.102 Annex H).
pub const DEFAULT_AMF_FIELD: &str = "8000";

struct Subscriber {
    milenage: Milenage,
    amf_field: [u8; 2],
    /// The last SQN the home network used (or the configured starting value).
    sqn: u64,
}

struct SuciKey {
    profile: u8,
    private_key: [u8; 32],
}

/// The credential store. Construct with [`Credentials::from_params`]; share behind a mutex.
#[derive(Default)]
pub struct Credentials {
    subscribers: BTreeMap<String, Subscriber>,
    suci_keys: BTreeMap<u8, SuciKey>,
}

/// How a 5GS mobile identity resolves.
pub enum Identity {
    /// A SUPI this AMF holds credentials for.
    Known { supi: String, protection_scheme: u8 },
    /// A SUPI recovered from the SUCI, with no credentials for it.
    Unknown { supi: String },
    /// A SUCI this AMF cannot read (an ECIES profile with no key for its key id), or a
    /// non-SUCI identity.
    Unreadable(String),
}

fn hex_field<const N: usize>(v: &Value, field: &str) -> Result<Option<[u8; N]>, String> {
    match v.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => security::hex_key::<N>(field, s).map(Some),
        Some(_) => Err(format!("{field} must be a hex string")),
    }
}

/// `"imsi-001010000000001"` or `"001010000000001"` → the IMSI digits.
pub fn supi_digits(s: &str) -> Result<String, String> {
    let d = s.trim().trim_start_matches("imsi-");
    if !(6..=15).contains(&d.len()) || !d.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("supi {s:?} must be imsi- followed by 6..15 digits"));
    }
    Ok(d.to_string())
}

impl Credentials {
    /// Read `subscribers` and `suci_keys`. Every error names the field, never its value.
    pub fn from_params(
        subscribers: Option<&[Value]>,
        suci_keys: Option<&[Value]>,
    ) -> Result<Self, String> {
        let mut c = Credentials::default();
        for (i, s) in subscribers.unwrap_or(&[]).iter().enumerate() {
            if c.subscribers.len() >= MAX_SUBSCRIBERS {
                return Err(format!("more than {MAX_SUBSCRIBERS} subscribers"));
            }
            let at = |e: String| format!("subscribers[{i}]: {e}");
            let supi = supi_digits(
                s.get("supi")
                    .and_then(Value::as_str)
                    .ok_or_else(|| at("supi is required, e.g. \"imsi-001010000000001\"".into()))?,
            )
            .map_err(at)?;
            let k = hex_field::<16>(s, "subscriber_key")
                .map_err(at)?
                .ok_or_else(|| at("subscriber_key (K, 32 hex digits) is required".into()))?;
            let milenage = match (
                hex_field::<16>(s, "subscriber_opc").map_err(at)?,
                hex_field::<16>(s, "subscriber_op").map_err(at)?,
            ) {
                (Some(opc), None) => Milenage::with_opc(k, opc),
                (None, Some(op)) => Milenage::with_op(k, op),
                (Some(_), Some(_)) => {
                    return Err(at("give subscriber_opc or subscriber_op, not both".into()))
                }
                (None, None) => {
                    return Err(at("subscriber_opc or subscriber_op is required".into()))
                }
            };
            let amf_field = match s.get("amf_field") {
                None | Some(Value::Null) => security::hex_key::<2>("amf_field", DEFAULT_AMF_FIELD)?,
                Some(Value::String(a)) => security::hex_key::<2>("amf_field", a).map_err(at)?,
                Some(_) => return Err(at("amf_field must be four hex digits".into())),
            };
            let sqn = match s.get("sqn") {
                None | Some(Value::Null) => 0,
                Some(Value::Number(n)) => n
                    .as_u64()
                    .ok_or_else(|| at("sqn must be 0..2^48-1".into()))?,
                Some(Value::String(x)) => {
                    let b = security::hex_key::<6>("sqn", x).map_err(at)?;
                    security::sqn_value(&b)
                }
                Some(_) => return Err(at("sqn must be a number or twelve hex digits".into())),
            };
            if sqn > MAX_SQN {
                return Err(at("sqn must be below 2^48".into()));
            }
            if c.subscribers.contains_key(&supi) {
                return Err(at(format!("supi {supi} is listed twice")));
            }
            c.subscribers.insert(
                supi,
                Subscriber {
                    milenage,
                    amf_field,
                    sqn,
                },
            );
        }
        for (i, k) in suci_keys.unwrap_or(&[]).iter().enumerate() {
            if c.suci_keys.len() >= MAX_SUCI_KEYS {
                return Err(format!("more than {MAX_SUCI_KEYS} suci_keys"));
            }
            let at = |e: String| format!("suci_keys[{i}]: {e}");
            let id =
                k.get("key_id")
                    .and_then(Value::as_u64)
                    .filter(|x| *x <= 255)
                    .ok_or_else(|| at("key_id (0..255) is required".into()))? as u8;
            let profile = match k.get("scheme").and_then(Value::as_str) {
                Some("profile_a") | Some("a") => suci::PROFILE_A,
                Some("profile_b") | Some("b") => suci::PROFILE_B,
                _ => return Err(at("scheme must be \"profile_a\" or \"profile_b\"".into())),
            };
            let private_key = hex_field::<32>(k, "home_network_private_key")
                .map_err(at)?
                .ok_or_else(|| at("home_network_private_key (64 hex digits) is required".into()))?;
            if c.suci_keys
                .insert(
                    id,
                    SuciKey {
                        profile,
                        private_key,
                    },
                )
                .is_some()
            {
                return Err(at(format!("key_id {id} is listed twice")));
            }
        }
        Ok(c)
    }

    pub fn is_empty(&self) -> bool {
        self.subscribers.is_empty()
    }

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Resolve a 5GS mobile identity to a SUPI.
    pub fn resolve(&self, mobile_identity: &[u8]) -> Identity {
        let Some(s) = nas::parse_suci(mobile_identity) else {
            return Identity::Unreadable("not an IMSI-format SUCI".into());
        };
        let msin = match s.protection_scheme {
            0 => nas::msin_from_bcd(&s.scheme_output),
            p @ (suci::PROFILE_A | suci::PROFILE_B) => {
                let Some(key) = self
                    .suci_keys
                    .get(&s.home_network_public_key_id)
                    .filter(|k| k.profile == p)
                else {
                    return Identity::Unreadable(format!(
                        "SUCI protection scheme {p} with home network public key id {} has no \
                         configured private key",
                        s.home_network_public_key_id
                    ));
                };
                match suci::deconceal(p, &key.private_key, &s.scheme_output) {
                    Ok(plain) => nas::msin_from_bcd(&plain),
                    Err(e) => return Identity::Unreadable(e),
                }
            }
            other => return Identity::Unreadable(format!("SUCI protection scheme {other}")),
        };
        let Some(msin) = msin else {
            return Identity::Unreadable("the SUCI's MSIN is not BCD digits".into());
        };
        let supi = format!("{}{}{}", s.plmn.mcc, s.plmn.mnc, msin);
        if self.subscribers.contains_key(&supi) {
            Identity::Known {
                supi,
                protection_scheme: s.protection_scheme,
            }
        } else {
            Identity::Unknown { supi }
        }
    }

    /// A fresh vector for `supi`, advancing its SQN.
    pub fn next_vector(&mut self, supi: &str, snn: &str) -> Option<AkaVector> {
        let sub = self.subscribers.get_mut(supi)?;
        sub.sqn = (sub.sqn + SQN_STEP) & MAX_SQN;
        let rand: [u8; 16] = rand::random();
        Some(security::generate_vector(
            &sub.milenage,
            rand,
            sub.sqn,
            sub.amf_field,
            snn,
        ))
    }

    /// Resynchronise from a UE's AUTS. `false` when MAC-S does not verify.
    pub fn resync(&mut self, supi: &str, rand: &[u8; 16], auts: &[u8]) -> bool {
        let Some(sub) = self.subscribers.get_mut(supi) else {
            return false;
        };
        match security::resync_sqn(&sub.milenage, rand, auts) {
            Some(sqn_ms) => {
                sub.sqn = sqn_ms;
                true
            }
            None => false,
        }
    }
}
