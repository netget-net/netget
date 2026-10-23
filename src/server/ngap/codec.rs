//! NGAP (3GPP TS 38.413) PDU structure, the IEs of the procedures NetGet speaks, and message
//! builders — shared by the AMF (server) and the gNB (client).
//!
//! # What is decoded and what is skipped
//!
//! An NGAP PDU is a CHOICE of initiating / successful / unsuccessful message, each carrying a
//! procedure code, a criticality and an open type holding a `ProtocolIE-Container`: a list of
//! `(id, criticality, open type)` fields. [`decode_pdu`] walks that outer structure for every
//! procedure, so any NGAP message can be framed, named and have its IE ids reported. The IE
//! *values* are decoded only for the procedures listed in [`procedure_name`]'s implemented set:
//! NG Setup, Initial UE Message, Downlink/Uplink NAS Transport, Error Indication, NG Reset and UE
//! Context Release. An IE NetGet does not decode stays as its raw octets and is surfaced by id —
//! the open-type framing is exactly what lets a receiver do that honestly.
//!
//! Every value is checked against its ASN.1 constraint on the way in *and* on the way out, so an
//! action cannot put a 33-bit gNB ID or an eleven-digit MCC on the wire.
//!
//! # Bounds
//!
//! [`MAX_PDU_LEN`] bounds the PDU, [`MAX_IES`] the IE count per container, [`MAX_NAS_PDU_LEN`] the
//! NAS-PDU, and every `SEQUENCE OF` is bounded by its own 38.413 constraint *and* by
//! [`MAX_LIST_ITEMS`] in total per decode, so the structure handed to the model is bounded however
//! the peer nests its lists. No decoder here recurses.

use super::aper::{self, AperError, Reader, Writer};
use serde_json::{json, Map, Value};

/// SCTP Payload Protocol Identifier for NGAP (TS 38.412 section 7).
pub const PPID: u32 = 60;
/// SCTP port the AMF listens on (TS 38.412 section 7, IANA).
pub const SCTP_PORT: u16 = 38412;
/// Largest NGAP PDU accepted or written. NGAP itself has no length field; this is the bound on
/// one SCTP message (or one lab-transport frame).
pub const MAX_PDU_LEN: usize = 65_535;
/// IEs accepted in one `ProtocolIE-Container`. The constraint allows 65535; the largest message in
/// NetGet's subset carries about ten.
pub const MAX_IES: usize = 64;
/// Largest NAS-PDU accepted or written. A 5GMM message NetGet handles is under a hundred octets;
/// 8 KiB leaves room for any capability container a UE might add without approaching the APER
/// fragmentation threshold.
pub const MAX_NAS_PDU_LEN: usize = 8_192;
/// `SEQUENCE OF` elements decoded per PDU, summed across every list in it.
pub const MAX_LIST_ITEMS: usize = 1_024;

// Procedure codes (TS 38.413 section 9.4.7).
pub const PROC_AMF_CONFIGURATION_UPDATE: u8 = 0;
pub const PROC_DOWNLINK_NAS_TRANSPORT: u8 = 4;
pub const PROC_ERROR_INDICATION: u8 = 9;
pub const PROC_INITIAL_UE_MESSAGE: u8 = 15;
pub const PROC_NG_RESET: u8 = 20;
pub const PROC_NG_SETUP: u8 = 21;
pub const PROC_RAN_CONFIGURATION_UPDATE: u8 = 35;
pub const PROC_UE_CONTEXT_RELEASE: u8 = 41;
pub const PROC_UPLINK_NAS_TRANSPORT: u8 = 46;

// IE ids (TS 38.413 section 9.4.7).
pub const IE_AMF_NAME: u16 = 1;
pub const IE_AMF_SET_ID: u16 = 3;
pub const IE_AMF_UE_NGAP_ID: u16 = 10;
pub const IE_CAUSE: u16 = 15;
pub const IE_CRITICALITY_DIAGNOSTICS: u16 = 19;
pub const IE_DEFAULT_PAGING_DRX: u16 = 21;
pub const IE_FIVE_G_S_TMSI: u16 = 26;
pub const IE_GLOBAL_RAN_NODE_ID: u16 = 27;
pub const IE_NAS_PDU: u16 = 38;
pub const IE_PLMN_SUPPORT_LIST: u16 = 80;
pub const IE_RAN_NODE_NAME: u16 = 82;
pub const IE_RAN_UE_NGAP_ID: u16 = 85;
pub const IE_RELATIVE_AMF_CAPACITY: u16 = 86;
pub const IE_RESET_TYPE: u16 = 88;
pub const IE_RRC_ESTABLISHMENT_CAUSE: u16 = 90;
pub const IE_SERVED_GUAMI_LIST: u16 = 96;
pub const IE_SUPPORTED_TA_LIST: u16 = 102;
pub const IE_TIME_TO_WAIT: u16 = 107;
pub const IE_UE_ASSOCIATED_LOGICAL_NG_CONNECTION_LIST: u16 = 111;
pub const IE_UE_CONTEXT_REQUEST: u16 = 112;
pub const IE_UE_NGAP_IDS: u16 = 114;
pub const IE_USER_LOCATION_INFORMATION: u16 = 121;

pub const MAX_AMF_UE_NGAP_ID: u64 = (1 << 40) - 1;
pub const MAX_RAN_UE_NGAP_ID: u64 = u32::MAX as u64;

/// Name of a procedure code, for logs and events. `None` for a code NetGet has no name for.
pub fn procedure_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "AMFConfigurationUpdate",
        1 => "AMFStatusIndication",
        4 => "DownlinkNASTransport",
        9 => "ErrorIndication",
        12 => "HandoverPreparation",
        14 => "InitialContextSetup",
        15 => "InitialUEMessage",
        20 => "NGReset",
        21 => "NGSetup",
        24 => "Paging",
        25 => "PathSwitchRequest",
        26 => "PDUSessionResourceModify",
        28 => "PDUSessionResourceRelease",
        29 => "PDUSessionResourceSetup",
        30 => "PDUSessionResourceNotify",
        35 => "RANConfigurationUpdate",
        40 => "UEContextModification",
        41 => "UEContextRelease",
        42 => "UEContextReleaseRequest",
        44 => "UERadioCapabilityInfoIndication",
        46 => "UplinkNASTransport",
        _ => return None,
    })
}

/// Name of an IE id NetGet decodes, for events. Others are reported by number.
pub fn ie_name(id: u16) -> Option<&'static str> {
    Some(match id {
        IE_AMF_NAME => "AMFName",
        IE_AMF_SET_ID => "AMFSetID",
        IE_AMF_UE_NGAP_ID => "AMF-UE-NGAP-ID",
        IE_CAUSE => "Cause",
        IE_CRITICALITY_DIAGNOSTICS => "CriticalityDiagnostics",
        IE_DEFAULT_PAGING_DRX => "DefaultPagingDRX",
        IE_FIVE_G_S_TMSI => "FiveG-S-TMSI",
        IE_GLOBAL_RAN_NODE_ID => "GlobalRANNodeID",
        IE_NAS_PDU => "NAS-PDU",
        IE_PLMN_SUPPORT_LIST => "PLMNSupportList",
        IE_RAN_NODE_NAME => "RANNodeName",
        IE_RAN_UE_NGAP_ID => "RAN-UE-NGAP-ID",
        IE_RELATIVE_AMF_CAPACITY => "RelativeAMFCapacity",
        IE_RESET_TYPE => "ResetType",
        IE_RRC_ESTABLISHMENT_CAUSE => "RRCEstablishmentCause",
        IE_SERVED_GUAMI_LIST => "ServedGUAMIList",
        IE_SUPPORTED_TA_LIST => "SupportedTAList",
        IE_TIME_TO_WAIT => "TimeToWait",
        IE_UE_ASSOCIATED_LOGICAL_NG_CONNECTION_LIST => "UE-associatedLogicalNG-connectionList",
        IE_UE_CONTEXT_REQUEST => "UEContextRequest",
        IE_UE_NGAP_IDS => "UE-NGAP-IDs",
        IE_USER_LOCATION_INFORMATION => "UserLocationInformation",
        IE_ALLOWED_NSSAI => "AllowedNSSAI",
        IE_GUAMI => "GUAMI",
        IE_MASKED_IMEISV => "MaskedIMEISV",
        IE_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_CXT_RES => {
            "PDUSessionResourceFailedToSetupListCxtRes"
        }
        IE_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_SU_RES => {
            "PDUSessionResourceFailedToSetupListSURes"
        }
        IE_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_REQ => "PDUSessionResourceSetupListCxtReq",
        IE_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_RES => "PDUSessionResourceSetupListCxtRes",
        IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ => "PDUSessionResourceSetupListSUReq",
        IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES => "PDUSessionResourceSetupListSURes",
        IE_SECURITY_KEY => "SecurityKey",
        IE_UE_AGGREGATE_MAXIMUM_BIT_RATE => "UEAggregateMaximumBitRate",
        IE_UE_SECURITY_CAPABILITIES => "UESecurityCapabilities",
        IE_PDU_SESSION_RESOURCE_LIST_CXT_REL_REQ => "PDUSessionResourceListCxtRelReq",
        _ => return None,
    })
}

// ============================================================================
// Errors carry the Cause the peer is answered with
// ============================================================================

/// A PDU NetGet refuses, with the NGAP Cause that tells the peer why. The detail is for the log
/// only; nothing in it is put on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    pub cause: Cause,
    pub detail: String,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.detail, self.cause.label())
    }
}

impl std::error::Error for ProtocolError {}

impl From<AperError> for ProtocolError {
    fn from(e: AperError) -> Self {
        ProtocolError {
            cause: Cause::protocol(PROTOCOL_TRANSFER_SYNTAX_ERROR),
            detail: e.0,
        }
    }
}

fn abstract_reject(detail: impl Into<String>) -> ProtocolError {
    ProtocolError {
        cause: Cause::protocol(PROTOCOL_ABSTRACT_SYNTAX_ERROR_REJECT),
        detail: detail.into(),
    }
}

fn semantic(detail: impl Into<String>) -> ProtocolError {
    ProtocolError {
        cause: Cause::protocol(PROTOCOL_SEMANTIC_ERROR),
        detail: detail.into(),
    }
}

pub type CodecResult<T> = Result<T, ProtocolError>;

/// An encode refusal: what the action asked for cannot be put on the wire.
#[derive(Debug, Clone)]
pub struct EncodeError(pub String);

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EncodeError {}

impl From<AperError> for EncodeError {
    fn from(e: AperError) -> Self {
        EncodeError(e.0)
    }
}

pub type EncodeResult<T> = Result<T, EncodeError>;

fn enc_err<T>(msg: impl Into<String>) -> EncodeResult<T> {
    Err(EncodeError(msg.into()))
}

// ============================================================================
// Cause (TS 38.413 section 9.3.1.2)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CauseGroup {
    RadioNetwork,
    Transport,
    Nas,
    Protocol,
    Misc,
}

const RADIO_NETWORK_ROOT: &[&str] = &[
    "unspecified",
    "txnrelocoverall-expiry",
    "successful-handover",
    "release-due-to-ngran-generated-reason",
    "release-due-to-5gc-generated-reason",
    "handover-cancelled",
    "partial-handover",
    "ho-failure-in-target-5GC-ngran-node-or-target-system",
    "ho-target-not-allowed",
    "tngrelocoverall-expiry",
    "tngrelocprep-expiry",
    "cell-not-available",
    "unknown-targetID",
    "no-radio-resources-available-in-target-cell",
    "unknown-local-UE-NGAP-ID",
    "inconsistent-remote-UE-NGAP-ID",
    "handover-desirable-for-radio-reason",
    "time-critical-handover",
    "resource-optimisation-handover",
    "reduce-load-in-serving-cell",
    "user-inactivity",
    "radio-connection-with-ue-lost",
    "radio-resources-not-available",
    "invalid-qos-combination",
    "failure-in-radio-interface-procedure",
    "interaction-with-other-procedure",
    "unknown-PDU-session-ID",
    "unkown-qos-flow-ID",
    "multiple-PDU-session-ID-instances",
    "multiple-qos-flow-ID-instances",
    "encryption-and-or-integrity-protection-algorithms-not-supported",
    "ng-intra-system-handover-triggered",
    "ng-inter-system-handover-triggered",
    "xn-handover-triggered",
    "not-supported-5QI-value",
    "ue-context-transfer",
    "ims-voice-eps-fallback-or-rat-fallback-triggered",
    "up-integrity-protection-not-possible",
    "up-confidentiality-protection-not-possible",
    "slice-not-supported",
    "ue-in-rrc-inactive-state-not-reachable",
    "redirection",
    "resources-not-available-for-the-slice",
    "ue-max-integrity-protected-data-rate-reason",
    "release-due-to-cn-detected-mobility",
];
const RADIO_NETWORK_EXT: &[&str] = &[
    "n26-interface-not-available",
    "release-due-to-pre-emption",
    "multiple-location-reporting-reference-ID-instances",
    "rsn-not-available-for-the-up",
    "npn-access-denied",
    "cag-only-access-denied",
    "insufficient-ue-capabilities",
    "redcap-ue-not-supported",
    "unknown-MBS-Session-ID",
    "indicated-MBS-session-area-information-not-served-by-the-gNB",
    "inconsistent-slice-info-for-the-session",
    "misaligned-association-for-multicast-unicast",
    "eredcap-ue-not-supported",
    "two-rx-xr-ue-not-supported",
    "aerial-ue-flight-information-reporting-initiation-failure",
    "unknown-RAN-AIoT-Device-NGAP-ID",
    "requested-AIoT-service-area-information-not-served-by-the-gNB",
    "unknown-AIoT-session",
    "aiot-device-not-reachable",
    "multiple-AIoT-session-ID-instances",
];
const TRANSPORT_ROOT: &[&str] = &["transport-resource-unavailable", "unspecified"];
const NAS_ROOT: &[&str] = &[
    "normal-release",
    "authentication-failure",
    "deregister",
    "unspecified",
];
const NAS_EXT: &[&str] = &[
    "uE-not-in-PLMN-serving-area",
    "mobile-IAB-not-authorized",
    "iAB-not-authorized",
    "no-aiot-NAS-response",
];
const PROTOCOL_ROOT: &[&str] = &[
    "transfer-syntax-error",
    "abstract-syntax-error-reject",
    "abstract-syntax-error-ignore-and-notify",
    "message-not-compatible-with-receiver-state",
    "semantic-error",
    "abstract-syntax-error-falsely-constructed-message",
    "unspecified",
];
const MISC_ROOT: &[&str] = &[
    "control-processing-overload",
    "not-enough-user-plane-processing-resources",
    "hardware-failure",
    "om-intervention",
    "unknown-PLMN-or-SNPN",
    "unspecified",
];

pub const RADIO_UNKNOWN_LOCAL_UE_NGAP_ID: u8 = 14;
pub const RADIO_INCONSISTENT_REMOTE_UE_NGAP_ID: u8 = 15;
pub const NAS_NORMAL_RELEASE: u8 = 0;
pub const NAS_UNSPECIFIED: u8 = 3;
pub const PROTOCOL_TRANSFER_SYNTAX_ERROR: u8 = 0;
pub const PROTOCOL_ABSTRACT_SYNTAX_ERROR_REJECT: u8 = 1;
pub const PROTOCOL_MESSAGE_NOT_COMPATIBLE_WITH_RECEIVER_STATE: u8 = 3;
pub const PROTOCOL_SEMANTIC_ERROR: u8 = 4;
pub const PROTOCOL_UNSPECIFIED: u8 = 6;
pub const MISC_CONTROL_PROCESSING_OVERLOAD: u8 = 0;
pub const MISC_HARDWARE_FAILURE: u8 = 2;
pub const MISC_OM_INTERVENTION: u8 = 3;
pub const MISC_UNKNOWN_PLMN: u8 = 4;
pub const MISC_UNSPECIFIED: u8 = 5;

impl CauseGroup {
    const ALL: [CauseGroup; 5] = [
        CauseGroup::RadioNetwork,
        CauseGroup::Transport,
        CauseGroup::Nas,
        CauseGroup::Protocol,
        CauseGroup::Misc,
    ];

    pub fn name(self) -> &'static str {
        match self {
            CauseGroup::RadioNetwork => "radioNetwork",
            CauseGroup::Transport => "transport",
            CauseGroup::Nas => "nas",
            CauseGroup::Protocol => "protocol",
            CauseGroup::Misc => "misc",
        }
    }

    fn tables(self) -> (&'static [&'static str], &'static [&'static str]) {
        match self {
            CauseGroup::RadioNetwork => (RADIO_NETWORK_ROOT, RADIO_NETWORK_EXT),
            CauseGroup::Transport => (TRANSPORT_ROOT, &[]),
            CauseGroup::Nas => (NAS_ROOT, NAS_EXT),
            CauseGroup::Protocol => (PROTOCOL_ROOT, &[]),
            CauseGroup::Misc => (MISC_ROOT, &[]),
        }
    }
}

/// An NGAP Cause: a group and an index in that group's root (or, when `extended`, its extension
/// list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cause {
    pub group: CauseGroup,
    pub extended: bool,
    pub index: u8,
}

fn normalize(s: &str) -> String {
    s.trim().to_ascii_lowercase().replace('_', "-")
}

impl Cause {
    pub fn protocol(index: u8) -> Self {
        Cause {
            group: CauseGroup::Protocol,
            extended: false,
            index,
        }
    }
    pub fn misc(index: u8) -> Self {
        Cause {
            group: CauseGroup::Misc,
            extended: false,
            index,
        }
    }
    pub fn radio(index: u8) -> Self {
        Cause {
            group: CauseGroup::RadioNetwork,
            extended: false,
            index,
        }
    }
    pub fn nas(index: u8) -> Self {
        Cause {
            group: CauseGroup::Nas,
            extended: false,
            index,
        }
    }

    pub fn value_name(&self) -> String {
        let (root, ext) = self.group.tables();
        let table = if self.extended { ext } else { root };
        table
            .get(self.index as usize)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}{}", if self.extended { "ext-" } else { "" }, self.index))
    }

    /// `group/value`, the form logs and errors use.
    pub fn label(&self) -> String {
        format!("{}/{}", self.group.name(), self.value_name())
    }

    pub fn to_json(&self) -> Value {
        json!({"group": self.group.name(), "value": self.value_name()})
    }

    /// Accepts `{"group": "misc", "value": "unknown-PLMN-or-SNPN"}` or `"misc/unknown-PLMN-or-SNPN"`.
    /// Names match case-insensitively and with `_` for `-`. A bare value name is accepted when it
    /// is unambiguous across the groups.
    pub fn from_json(v: &Value) -> EncodeResult<Cause> {
        let (group, value) = match v {
            Value::String(s) => match s.split_once('/') {
                Some((g, val)) => (Some(g.to_string()), val.to_string()),
                None => (None, s.clone()),
            },
            Value::Object(m) => (
                m.get("group").and_then(Value::as_str).map(str::to_string),
                m.get("value")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| EncodeError("cause.value must be a string".into()))?,
            ),
            _ => return enc_err("cause must be \"group/value\" or {\"group\", \"value\"}"),
        };
        let wanted = normalize(&value);
        let groups: Vec<CauseGroup> = match &group {
            Some(g) => {
                let g = normalize(g).replace('-', "");
                let found = CauseGroup::ALL
                    .iter()
                    .copied()
                    .find(|c| c.name().to_ascii_lowercase() == g);
                match found {
                    Some(c) => vec![c],
                    None => {
                        return enc_err(format!(
                        "cause group {g:?} is not one of radioNetwork, transport, nas, protocol, misc"
                    ))
                    }
                }
            }
            None => CauseGroup::ALL.to_vec(),
        };
        let mut hits = Vec::new();
        for g in groups {
            let (root, ext) = g.tables();
            for (i, name) in root.iter().enumerate() {
                if normalize(name) == wanted {
                    hits.push(Cause {
                        group: g,
                        extended: false,
                        index: i as u8,
                    });
                }
            }
            for (i, name) in ext.iter().enumerate() {
                if normalize(name) == wanted {
                    hits.push(Cause {
                        group: g,
                        extended: true,
                        index: i as u8,
                    });
                }
            }
        }
        match hits.len() {
            1 => Ok(hits[0]),
            0 => enc_err(format!(
                "cause value {value:?} is not defined{}; e.g. misc/unknown-PLMN-or-SNPN, \
                 misc/control-processing-overload, nas/normal-release, \
                 radioNetwork/unspecified, protocol/semantic-error",
                group.map(|g| format!(" in group {g}")).unwrap_or_default()
            )),
            _ => enc_err(format!(
                "cause value {value:?} exists in more than one group; write it as group/value"
            )),
        }
    }

    fn encode(&self, w: &mut Writer) -> EncodeResult<()> {
        let gi = CauseGroup::ALL
            .iter()
            .position(|g| *g == self.group)
            .unwrap_or(0) as u64;
        // Cause ::= CHOICE { radioNetwork, transport, nas, protocol, misc, choice-Extensions }:
        // six root alternatives and no extension marker.
        put_choice(w, gi, 6, "Cause")?;
        let (root, ext) = self.group.tables();
        let limit = if self.extended { ext.len() } else { root.len() };
        if self.index as usize >= limit {
            return enc_err(format!("cause index {} out of range", self.index));
        }
        // Every group's ENUMERATED is extensible.
        w.enumerated(
            self.index as u64,
            self.extended,
            root.len() as u64,
            true,
            "Cause",
        )?;
        Ok(())
    }

    fn decode(r: &mut Reader) -> CodecResult<Cause> {
        let gi = choice(r, 6, "Cause")? as usize;
        let group = CauseGroup::ALL[gi];
        let (root, _) = group.tables();
        let (extended, index) = r.enumerated(root.len() as u64, true, "Cause value")?;
        Ok(Cause {
            group,
            extended,
            index: index as u8,
        })
    }
}

// ============================================================================
// PDU framing
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduKind {
    Initiating,
    Successful,
    Unsuccessful,
}

impl PduKind {
    pub fn name(self) -> &'static str {
        match self {
            PduKind::Initiating => "initiatingMessage",
            PduKind::Successful => "successfulOutcome",
            PduKind::Unsuccessful => "unsuccessfulOutcome",
        }
    }
    fn index(self) -> u64 {
        match self {
            PduKind::Initiating => 0,
            PduKind::Successful => 1,
            PduKind::Unsuccessful => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Criticality {
    Reject,
    Ignore,
    Notify,
}

impl Criticality {
    fn from_index(i: u64) -> Criticality {
        match i {
            0 => Criticality::Reject,
            1 => Criticality::Ignore,
            _ => Criticality::Notify,
        }
    }
    fn index(self) -> u64 {
        match self {
            Criticality::Reject => 0,
            Criticality::Ignore => 1,
            Criticality::Notify => 2,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Criticality::Reject => "reject",
            Criticality::Ignore => "ignore",
            Criticality::Notify => "notify",
        }
    }
}

/// One `ProtocolIE-Field`, its value still an encoded open type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ie {
    pub id: u16,
    pub criticality: Criticality,
    pub value: Vec<u8>,
}

impl Ie {
    pub fn new(id: u16, criticality: Criticality, value: Vec<u8>) -> Self {
        Ie {
            id,
            criticality,
            value,
        }
    }
}

/// One NGAP PDU with its IEs framed but not interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    pub kind: PduKind,
    pub procedure_code: u8,
    pub criticality: Criticality,
    pub ies: Vec<Ie>,
}

impl Pdu {
    pub fn new(kind: PduKind, procedure_code: u8, criticality: Criticality, ies: Vec<Ie>) -> Self {
        Pdu {
            kind,
            procedure_code,
            criticality,
            ies,
        }
    }

    pub fn ie(&self, id: u16) -> Option<&Ie> {
        self.ies.iter().find(|ie| ie.id == id)
    }

    /// `"NGSetup initiatingMessage"`, or the code when NetGet has no name for it.
    pub fn label(&self) -> String {
        match procedure_name(self.procedure_code) {
            Some(n) => format!("{n} {}", self.kind.name()),
            None => format!("procedure {} {}", self.procedure_code, self.kind.name()),
        }
    }

    /// The ids of IEs NetGet did not interpret for this message, for events.
    pub fn uninterpreted_ies(&self, interpreted: &[u16]) -> Vec<Value> {
        self.ies
            .iter()
            .filter(|ie| !interpreted.contains(&ie.id))
            .map(|ie| {
                json!({
                    "id": ie.id,
                    "name": ie_name(ie.id),
                    "criticality": ie.criticality.name(),
                    "length": ie.value.len(),
                })
            })
            .collect()
    }

    /// The mandatory IE `id`, or the abstract-syntax refusal 38.413 section 10.3.5 prescribes.
    pub fn require(&self, id: u16) -> CodecResult<&Ie> {
        self.ie(id).ok_or_else(|| {
            abstract_reject(format!(
                "{} is missing mandatory IE {} ({})",
                self.label(),
                id,
                ie_name(id).unwrap_or("?")
            ))
        })
    }
}

/// Decode the outer structure of one NGAP PDU.
pub fn decode_pdu(bytes: &[u8]) -> CodecResult<Pdu> {
    if bytes.is_empty() {
        return Err(AperError("empty PDU".into()).into());
    }
    if bytes.len() > MAX_PDU_LEN {
        return Err(AperError(format!(
            "PDU of {} octets exceeds {MAX_PDU_LEN}",
            bytes.len()
        ))
        .into());
    }
    let mut r = Reader::new(bytes);
    if r.extension_bit("NGAP-PDU")? {
        return Err(AperError("NGAP-PDU choice extension".into()).into());
    }
    let kind = match r.constrained(0, 2, "NGAP-PDU")? {
        0 => PduKind::Initiating,
        1 => PduKind::Successful,
        _ => PduKind::Unsuccessful,
    };
    let procedure_code = r.constrained(0, 255, "procedureCode")? as u8;
    let criticality = Criticality::from_index(r.constrained(0, 2, "criticality")?);
    let content = r.open_type("message value")?;
    if !r.at_end() {
        return Err(AperError("octets after the PDU".into()).into());
    }

    let mut c = Reader::new(content);
    let extended = c.extension_bit("message")?;
    let count = c.size(0, 65_535, "ProtocolIE-Container")?;
    if count > MAX_IES {
        return Err(AperError(format!(
            "{count} IEs in one message exceeds the bound of {MAX_IES}"
        ))
        .into());
    }
    let mut ies = Vec::with_capacity(count);
    for _ in 0..count {
        let id = c.constrained(0, 65_535, "ProtocolIE-ID")? as u16;
        let crit = Criticality::from_index(c.constrained(0, 2, "IE criticality")?);
        let value = c.open_type("IE value")?.to_vec();
        if ies.iter().any(|ie: &Ie| ie.id == id) {
            // 38.413 section 10.3.6: an IE appearing more than once is a falsely constructed
            // message.
            return Err(ProtocolError {
                cause: Cause::protocol(5),
                detail: format!("IE {id} appears more than once"),
            });
        }
        ies.push(Ie::new(id, crit, value));
    }
    if extended {
        c.skip_extension_additions("message extension additions")?;
    }
    Ok(Pdu {
        kind,
        procedure_code,
        criticality,
        ies,
    })
}

/// Encode one NGAP PDU.
pub fn encode_pdu(pdu: &Pdu) -> EncodeResult<Vec<u8>> {
    if pdu.ies.len() > MAX_IES {
        return enc_err(format!("{} IEs exceeds {MAX_IES}", pdu.ies.len()));
    }
    let mut c = Writer::new();
    c.bit(false);
    c.size(pdu.ies.len(), 0, 65_535, "ProtocolIE-Container")?;
    for ie in &pdu.ies {
        c.constrained(ie.id as u64, 0, 65_535, "ProtocolIE-ID")?;
        c.constrained(ie.criticality.index(), 0, 2, "IE criticality")?;
        c.open_type(&ie.value, "IE value")?;
    }
    let content = c.finish();

    let mut w = Writer::new();
    w.bit(false);
    w.constrained(pdu.kind.index(), 0, 2, "NGAP-PDU")?;
    w.constrained(pdu.procedure_code as u64, 0, 255, "procedureCode")?;
    w.constrained(pdu.criticality.index(), 0, 2, "criticality")?;
    w.open_type(&content, "message value")?;
    let out = w.finish();
    if out.len() > MAX_PDU_LEN {
        return enc_err(format!("PDU of {} octets exceeds {MAX_PDU_LEN}", out.len()));
    }
    Ok(out)
}

/// The procedure code and kind of an encoded PDU, read without decoding the rest.
pub fn peek(bytes: &[u8]) -> Option<(PduKind, u8)> {
    let mut r = Reader::new(bytes);
    if r.extension_bit("NGAP-PDU").ok()? {
        return None;
    }
    let kind = match r.constrained(0, 2, "NGAP-PDU").ok()? {
        0 => PduKind::Initiating,
        1 => PduKind::Successful,
        _ => PduKind::Unsuccessful,
    };
    let code = r.constrained(0, 255, "procedureCode").ok()? as u8;
    Some((kind, code))
}

/// True when the PDU is UE-associated signalling — it carries an AMF or RAN UE NGAP ID — which
/// TS 38.412 section 7 sends on a non-zero SCTP stream. Non-UE-associated signalling (NG Setup,
/// NG Reset, a UE-less Error Indication) uses stream 0.
pub fn is_ue_associated(bytes: &[u8]) -> bool {
    match decode_pdu(bytes) {
        Ok(p) => p.ies.iter().any(|ie| {
            matches!(
                ie.id,
                IE_AMF_UE_NGAP_ID | IE_RAN_UE_NGAP_ID | IE_UE_NGAP_IDS
            )
        }),
        Err(_) => false,
    }
}

// ============================================================================
// A per-decode budget on SEQUENCE OF elements
// ============================================================================

/// Counts list elements across one PDU so nested lists cannot multiply into an unbounded event.
pub struct Budget(usize);

impl Default for Budget {
    fn default() -> Self {
        Budget(MAX_LIST_ITEMS)
    }
}

impl Budget {
    fn take(&mut self, n: usize, what: &str) -> CodecResult<()> {
        if n > self.0 {
            return Err(AperError(format!(
                "{what}: list elements in one PDU exceed the bound of {MAX_LIST_ITEMS}"
            ))
            .into());
        }
        self.0 -= n;
        Ok(())
    }
}

// ============================================================================
// Primitive IEs
// ============================================================================

/// A PLMN identity, three TBCD octets (TS 38.413 section 9.3.3.5, TS 24.008 figure 10.5.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plmn {
    pub mcc: String,
    pub mnc: String,
}

impl Plmn {
    pub fn decode_octets(b: &[u8]) -> CodecResult<Plmn> {
        if b.len() != 3 {
            return Err(semantic("PLMN identity is not three octets"));
        }
        let d = [
            b[0] & 0x0F,
            b[0] >> 4,
            b[1] & 0x0F,
            b[1] >> 4,
            b[2] & 0x0F,
            b[2] >> 4,
        ];
        let digit = |x: u8| -> CodecResult<char> {
            if x > 9 {
                Err(semantic("PLMN identity has a non-decimal digit"))
            } else {
                Ok((b'0' + x) as char)
            }
        };
        let mcc: String = [digit(d[0])?, digit(d[1])?, digit(d[2])?].iter().collect();
        let mnc: String = if d[3] == 0xF {
            [digit(d[4])?, digit(d[5])?].iter().collect()
        } else {
            [digit(d[4])?, digit(d[5])?, digit(d[3])?].iter().collect()
        };
        Ok(Plmn { mcc, mnc })
    }

    pub fn octets(&self) -> [u8; 3] {
        let m: Vec<u8> = self.mcc.bytes().map(|c| c - b'0').collect();
        let n: Vec<u8> = self.mnc.bytes().map(|c| c - b'0').collect();
        let mnc3 = if n.len() == 3 { n[2] } else { 0xF };
        [m[1] << 4 | m[0], mnc3 << 4 | m[2], n[1] << 4 | n[0]]
    }

    pub fn to_json(&self) -> Value {
        json!({"mcc": self.mcc, "mnc": self.mnc})
    }

    /// `{"mcc": "001", "mnc": "01"}`, or a string `"001-01"` / `"00101"` (five digits is a
    /// two-digit MNC, six a three-digit one).
    pub fn from_json(v: &Value) -> EncodeResult<Plmn> {
        let (mcc, mnc) = match v {
            Value::Object(m) => (
                json_digits(m.get("mcc"), "plmn.mcc")?,
                json_digits(m.get("mnc"), "plmn.mnc")?,
            ),
            Value::String(s) => {
                let s = s.trim();
                if let Some((a, b)) = s.split_once(['-', '/']) {
                    (a.to_string(), b.to_string())
                } else if s.len() == 5 || s.len() == 6 {
                    (s[..3].to_string(), s[3..].to_string())
                } else {
                    return enc_err(format!(
                        "plmn {s:?} must be \"MCC-MNC\" or {{\"mcc\", \"mnc\"}}"
                    ));
                }
            }
            _ => return enc_err("plmn must be {\"mcc\": \"001\", \"mnc\": \"01\"}"),
        };
        if mcc.len() != 3 || !mcc.bytes().all(|c| c.is_ascii_digit()) {
            return enc_err(format!("mcc {mcc:?} must be three decimal digits"));
        }
        if !(2..=3).contains(&mnc.len()) || !mnc.bytes().all(|c| c.is_ascii_digit()) {
            return enc_err(format!("mnc {mnc:?} must be two or three decimal digits"));
        }
        Ok(Plmn { mcc, mnc })
    }

    fn decode(r: &mut Reader) -> CodecResult<Plmn> {
        let b = r.fixed_octets(3, "PLMNIdentity")?;
        Plmn::decode_octets(&b)
    }

    fn encode(&self, w: &mut Writer) {
        w.fixed_octets(&self.octets());
    }
}

fn json_digits(v: Option<&Value>, what: &str) -> EncodeResult<String> {
    match v {
        Some(Value::String(s)) => Ok(s.trim().to_string()),
        Some(Value::Number(n)) => enc_err(format!(
            "{what} must be a string so leading zeros survive (got {n})"
        )),
        _ => enc_err(format!("{what} is required")),
    }
}

pub fn json_u64(v: &Value, field: &str, max: u64) -> EncodeResult<u64> {
    let n = match v.get(field) {
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| EncodeError(format!("{field} must be a non-negative integer")))?,
        Some(Value::String(s)) => {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x") {
                u64::from_str_radix(hex, 16)
                    .map_err(|_| EncodeError(format!("{field} {s:?} is not a number")))?
            } else {
                s.parse()
                    .map_err(|_| EncodeError(format!("{field} {s:?} is not a number")))?
            }
        }
        None | Some(Value::Null) => return enc_err(format!("{field} is required")),
        _ => return enc_err(format!("{field} must be a number")),
    };
    if n > max {
        return enc_err(format!("{field} {n} is above its maximum {max}"));
    }
    Ok(n)
}

pub fn json_opt_u64(v: &Value, field: &str, max: u64) -> EncodeResult<Option<u64>> {
    match v.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => json_u64(v, field, max).map(Some),
    }
}

fn opt_extension_container(r: &mut Reader, present: bool, budget: &mut Budget) -> CodecResult<()> {
    if present {
        let n = r.size(1, 65_535, "ProtocolExtensionContainer")?;
        budget.take(n, "ProtocolExtensionContainer")?;
        for _ in 0..n {
            r.constrained(0, 65_535, "ProtocolExtensionID")?;
            r.constrained(0, 2, "extension criticality")?;
            r.open_type("extension value")?;
        }
    }
    Ok(())
}

fn finish_sequence(r: &mut Reader, extended: bool) -> CodecResult<()> {
    if extended {
        r.skip_extension_additions("extension additions")?;
    }
    Ok(())
}

/// An NGAP CHOICE. 38.413 writes its CHOICEs with a final `choice-Extensions` *root*
/// alternative (a ProtocolIE-SingleContainer) instead of an extension marker, so there is no
/// extension bit: the index is a constrained whole number over every alternative including that
/// one. `alternatives` counts `choice-Extensions`. Selecting it is refused here; callers that can
/// carry on without it check for [`CHOICE_EXTENSIONS`] first.
fn choice(r: &mut Reader, alternatives: u64, what: &str) -> CodecResult<u64> {
    let i = r.constrained(0, alternatives - 1, what)?;
    if i == alternatives - 1 {
        return Err(semantic(format!(
            "{what} selects its choice-Extensions alternative, which NetGet does not decode"
        )));
    }
    Ok(i)
}

/// Marker for the `choice-Extensions` index of a CHOICE with `alternatives` alternatives.
pub const CHOICE_EXTENSIONS: &str = "choice-Extensions";

fn put_choice(w: &mut Writer, index: u64, alternatives: u64, what: &str) -> EncodeResult<()> {
    Ok(w.constrained(index, 0, alternatives - 1, what)?)
}

/// Decode an IE value with `f`, requiring it to consume the whole open type.
fn decode_ie<T>(ie: &Ie, f: impl FnOnce(&mut Reader) -> CodecResult<T>) -> CodecResult<T> {
    let mut r = Reader::new(&ie.value);
    let v = f(&mut r)?;
    if !r.at_end() {
        return Err(AperError(format!(
            "IE {} ({}) has octets after its value",
            ie.id,
            ie_name(ie.id).unwrap_or("?")
        ))
        .into());
    }
    Ok(v)
}

fn encode_ie(
    id: u16,
    crit: Criticality,
    f: impl FnOnce(&mut Writer) -> EncodeResult<()>,
) -> EncodeResult<Ie> {
    let mut w = Writer::new();
    f(&mut w)?;
    Ok(Ie::new(id, crit, w.finish()))
}

pub fn decode_amf_ue_ngap_id(ie: &Ie) -> CodecResult<u64> {
    decode_ie(ie, |r| {
        Ok(r.constrained(0, MAX_AMF_UE_NGAP_ID, "AMF-UE-NGAP-ID")?)
    })
}

pub fn decode_ran_ue_ngap_id(ie: &Ie) -> CodecResult<u64> {
    decode_ie(ie, |r| {
        Ok(r.constrained(0, MAX_RAN_UE_NGAP_ID, "RAN-UE-NGAP-ID")?)
    })
}

pub fn amf_ue_ngap_id_ie(id: u64, crit: Criticality) -> EncodeResult<Ie> {
    encode_ie(IE_AMF_UE_NGAP_ID, crit, |w| {
        Ok(w.constrained(id, 0, MAX_AMF_UE_NGAP_ID, "AMF-UE-NGAP-ID")?)
    })
}

pub fn ran_ue_ngap_id_ie(id: u64, crit: Criticality) -> EncodeResult<Ie> {
    encode_ie(IE_RAN_UE_NGAP_ID, crit, |w| {
        Ok(w.constrained(id, 0, MAX_RAN_UE_NGAP_ID, "RAN-UE-NGAP-ID")?)
    })
}

pub fn decode_nas_pdu(ie: &Ie) -> CodecResult<Vec<u8>> {
    decode_ie(ie, |r| {
        Ok(r.octet_string(MAX_NAS_PDU_LEN, "NAS-PDU")?.to_vec())
    })
}

pub fn nas_pdu_ie(nas: &[u8]) -> EncodeResult<Ie> {
    if nas.is_empty() || nas.len() > MAX_NAS_PDU_LEN {
        return enc_err(format!(
            "NAS-PDU of {} octets is outside 1..{MAX_NAS_PDU_LEN}",
            nas.len()
        ));
    }
    encode_ie(IE_NAS_PDU, Criticality::Reject, |w| {
        Ok(w.octet_string(nas, "NAS-PDU")?)
    })
}

pub fn decode_cause(ie: &Ie) -> CodecResult<Cause> {
    decode_ie(ie, Cause::decode)
}

pub fn cause_ie(cause: &Cause, crit: Criticality) -> EncodeResult<Ie> {
    encode_ie(IE_CAUSE, crit, |w| cause.encode(w))
}

const TIME_TO_WAIT: &[&str] = &["v1s", "v2s", "v5s", "v10s", "v20s", "v60s"];
const PAGING_DRX: &[&str] = &["v32", "v64", "v128", "v256"];
const RRC_CAUSE_ROOT: &[&str] = &[
    "emergency",
    "highPriorityAccess",
    "mt-Access",
    "mo-Signalling",
    "mo-Data",
    "mo-VoiceCall",
    "mo-VideoCall",
    "mo-SMS",
    "mps-PriorityAccess",
    "mcs-PriorityAccess",
];
const RRC_CAUSE_EXT: &[&str] = &["notAvailable", "mo-ExceptionData"];

fn enum_index(table: &[&str], v: &str, what: &str) -> EncodeResult<u64> {
    let want = normalize(v);
    table
        .iter()
        .position(|n| normalize(n) == want)
        .map(|i| i as u64)
        .ok_or_else(|| EncodeError(format!("{what} {v:?} is not one of {}", table.join(", "))))
}

pub fn time_to_wait_ie(v: &str) -> EncodeResult<Ie> {
    // Seconds are accepted as well as the ASN.1 names: "10" or "10s" mean v10s.
    let name = if v.starts_with('v') {
        v.to_string()
    } else {
        format!("v{}s", v.trim_end_matches('s'))
    };
    let i = enum_index(TIME_TO_WAIT, &name, "time_to_wait")?;
    encode_ie(IE_TIME_TO_WAIT, Criticality::Ignore, |w| {
        Ok(w.enumerated(i, false, 6, true, "TimeToWait")?)
    })
}

pub fn decode_time_to_wait(ie: &Ie) -> CodecResult<String> {
    decode_ie(ie, |r| {
        let (ext, i) = r.enumerated(6, true, "TimeToWait")?;
        Ok(if ext {
            format!("ext-{i}")
        } else {
            TIME_TO_WAIT[i as usize].to_string()
        })
    })
}

fn decode_paging_drx(ie: &Ie) -> CodecResult<String> {
    decode_ie(ie, |r| {
        let (ext, i) = r.enumerated(4, true, "PagingDRX")?;
        Ok(if ext {
            format!("ext-{i}")
        } else {
            PAGING_DRX[i as usize].to_string()
        })
    })
}

fn decode_rrc_cause(ie: &Ie) -> CodecResult<String> {
    decode_ie(ie, |r| {
        let (ext, i) = r.enumerated(10, true, "RRCEstablishmentCause")?;
        let table = if ext { RRC_CAUSE_EXT } else { RRC_CAUSE_ROOT };
        Ok(table
            .get(i as usize)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("ext-{i}")))
    })
}

fn rrc_cause_ie(v: &str) -> EncodeResult<Ie> {
    let (ext, i) = match enum_index(RRC_CAUSE_ROOT, v, "rrc_establishment_cause") {
        Ok(i) => (false, i),
        Err(_) => (
            true,
            enum_index(RRC_CAUSE_EXT, v, "rrc_establishment_cause").map_err(|_| {
                EncodeError(format!(
                    "rrc_establishment_cause {v:?} is not one of {}, {}",
                    RRC_CAUSE_ROOT.join(", "),
                    RRC_CAUSE_EXT.join(", ")
                ))
            })?,
        ),
    };
    encode_ie(IE_RRC_ESTABLISHMENT_CAUSE, Criticality::Ignore, |w| {
        Ok(w.enumerated(i, ext, 10, true, "RRCEstablishmentCause")?)
    })
}

fn tac_octets(tac: u64) -> [u8; 3] {
    [(tac >> 16) as u8, (tac >> 8) as u8, tac as u8]
}

fn decode_tac(r: &mut Reader) -> CodecResult<u64> {
    let b = r.fixed_octets(3, "TAC")?;
    Ok(((b[0] as u64) << 16) | ((b[1] as u64) << 8) | b[2] as u64)
}

// ============================================================================
// S-NSSAI and slice lists
// ============================================================================

fn decode_snssai(r: &mut Reader, budget: &mut Budget) -> CodecResult<Value> {
    let ext = r.extension_bit("S-NSSAI")?;
    let has_sd = r.bit("S-NSSAI")?;
    let has_ext = r.bit("S-NSSAI")?;
    let sst = r.fixed_octets(1, "SST")?[0];
    let mut v = json!({"sst": sst});
    if has_sd {
        let sd = r.fixed_octets(3, "SD")?;
        v["sd"] = json!(hex::encode(sd));
    }
    opt_extension_container(r, has_ext, budget)?;
    finish_sequence(r, ext)?;
    Ok(v)
}

/// `{"sst": 1, "sd": "010203"}`; `sd` may also be a number.
fn encode_snssai(w: &mut Writer, v: &Value) -> EncodeResult<()> {
    let sst = json_u64(v, "sst", 255)?;
    let sd = match v.get("sd") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => {
            let s = s.trim().trim_start_matches("0x");
            if s.len() != 6 {
                return enc_err(format!("sd {s:?} must be six hex digits"));
            }
            Some(
                u32::from_str_radix(s, 16)
                    .map_err(|_| EncodeError(format!("sd {s:?} is not hex")))?,
            )
        }
        Some(Value::Number(_)) => Some(json_u64(v, "sd", 0xFF_FFFF)? as u32),
        Some(_) => return enc_err("sd must be six hex digits"),
    };
    w.bit(false);
    w.bit(sd.is_some());
    w.bit(false);
    w.fixed_octets(&[sst as u8]);
    if let Some(sd) = sd {
        w.fixed_octets(&[(sd >> 16) as u8, (sd >> 8) as u8, sd as u8]);
    }
    Ok(())
}

fn decode_slice_list(r: &mut Reader, budget: &mut Budget) -> CodecResult<Vec<Value>> {
    let n = r.size(1, 1024, "SliceSupportList")?;
    budget.take(n, "SliceSupportList")?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let ext = r.extension_bit("SliceSupportItem")?;
        let has_ext = r.bit("SliceSupportItem")?;
        out.push(decode_snssai(r, budget)?);
        opt_extension_container(r, has_ext, budget)?;
        finish_sequence(r, ext)?;
    }
    Ok(out)
}

fn json_list<'a>(v: &'a Value, field: &str) -> EncodeResult<&'a Vec<Value>> {
    v.get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| EncodeError(format!("{field} must be a list")))
}

fn encode_slice_list(w: &mut Writer, slices: &[Value]) -> EncodeResult<()> {
    w.size(slices.len(), 1, 1024, "slices")?;
    for s in slices {
        w.bit(false);
        w.bit(false);
        encode_snssai(w, s)?;
    }
    Ok(())
}

// ============================================================================
// NG Setup IEs
// ============================================================================

/// GlobalRANNodeID — gNB form decoded; ng-eNB and N3IWF forms named only.
pub fn decode_global_ran_node_id(ie: &Ie, budget: &mut Budget) -> CodecResult<Value> {
    decode_ie(ie, |r| match choice(r, 4, "GlobalRANNodeID")? {
        0 => {
            let ext = r.extension_bit("GlobalGNB-ID")?;
            let has_ext = r.bit("GlobalGNB-ID")?;
            let plmn = Plmn::decode(r)?;
            choice(r, 2, "GNB-ID")?;
            let (id, bits) = r.varying_bits(22, 32, "gNB-ID")?;
            opt_extension_container(r, has_ext, budget)?;
            finish_sequence(r, ext)?;
            Ok(json!({"type": "gnb", "plmn": plmn.to_json(), "gnb_id": id, "gnb_id_bits": bits}))
        }
        1 => Err(semantic(
            "an ng-eNB GlobalRANNodeID; NetGet's AMF serves gNBs",
        )),
        _ => Err(semantic(
            "an N3IWF GlobalRANNodeID; NetGet's AMF serves gNBs",
        )),
    })
}

pub fn global_gnb_id_ie(plmn: &Plmn, gnb_id: u64, bits: u32) -> EncodeResult<Ie> {
    encode_ie(IE_GLOBAL_RAN_NODE_ID, Criticality::Reject, |w| {
        put_choice(w, 0, 4, "GlobalRANNodeID")?;
        w.bit(false);
        w.bit(false);
        plmn.encode(w);
        put_choice(w, 0, 2, "GNB-ID")?;
        w.varying_bits(gnb_id, bits, 22, 32, "gnb_id")?;
        Ok(())
    })
}

pub fn decode_name(ie: &Ie) -> CodecResult<String> {
    decode_ie(ie, |r| Ok(r.printable_string(1, 150, "name")?))
}

pub fn name_ie(id: u16, crit: Criticality, name: &str) -> EncodeResult<Ie> {
    encode_ie(id, crit, |w| Ok(w.printable_string(name, 1, 150, "name")?))
}

pub fn decode_supported_ta_list(ie: &Ie, budget: &mut Budget) -> CodecResult<Vec<Value>> {
    decode_ie(ie, |r| {
        let n = r.size(1, 256, "SupportedTAList")?;
        budget.take(n, "SupportedTAList")?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let ext = r.extension_bit("SupportedTAItem")?;
            let has_ext = r.bit("SupportedTAItem")?;
            let tac = decode_tac(r)?;
            let m = r.size(1, 12, "BroadcastPLMNList")?;
            budget.take(m, "BroadcastPLMNList")?;
            let mut plmns = Vec::with_capacity(m);
            for _ in 0..m {
                let bext = r.extension_bit("BroadcastPLMNItem")?;
                let bhas = r.bit("BroadcastPLMNItem")?;
                let plmn = Plmn::decode(r)?;
                let slices = decode_slice_list(r, budget)?;
                opt_extension_container(r, bhas, budget)?;
                finish_sequence(r, bext)?;
                plmns.push(json!({"plmn": plmn.to_json(), "slices": slices}));
            }
            opt_extension_container(r, has_ext, budget)?;
            finish_sequence(r, ext)?;
            out.push(json!({"tac": tac, "broadcast_plmns": plmns}));
        }
        Ok(out)
    })
}

/// `[{"tac": 1, "broadcast_plmns": [{"plmn": {...}, "slices": [{"sst": 1}]}]}]`
pub fn supported_ta_list_ie(list: &[Value]) -> EncodeResult<Ie> {
    encode_ie(IE_SUPPORTED_TA_LIST, Criticality::Reject, |w| {
        w.size(list.len(), 1, 256, "supported_ta_list")?;
        for ta in list {
            let tac = json_u64(ta, "tac", 0xFF_FFFF)?;
            let plmns = json_list(ta, "broadcast_plmns")?;
            w.bit(false);
            w.bit(false);
            w.fixed_octets(&tac_octets(tac));
            w.size(plmns.len(), 1, 12, "broadcast_plmns")?;
            for p in plmns {
                let plmn = Plmn::from_json(p.get("plmn").unwrap_or(&Value::Null))?;
                w.bit(false);
                w.bit(false);
                plmn.encode(w);
                encode_slice_list(w, json_list(p, "slices")?)?;
            }
        }
        Ok(())
    })
}

pub fn paging_drx_ie(v: &str) -> EncodeResult<Ie> {
    let i = enum_index(PAGING_DRX, v, "default_paging_drx")?;
    encode_ie(IE_DEFAULT_PAGING_DRX, Criticality::Ignore, |w| {
        Ok(w.enumerated(i, false, 4, true, "PagingDRX")?)
    })
}

pub fn decode_served_guami_list(ie: &Ie, budget: &mut Budget) -> CodecResult<Vec<Value>> {
    decode_ie(ie, |r| {
        let n = r.size(1, 256, "ServedGUAMIList")?;
        budget.take(n, "ServedGUAMIList")?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let ext = r.extension_bit("ServedGUAMIItem")?;
            let has_backup = r.bit("ServedGUAMIItem")?;
            let has_ext = r.bit("ServedGUAMIItem")?;
            let mut g = decode_guami(r, budget)?;
            if has_backup {
                g["backup_amf_name"] = json!(r.printable_string(1, 150, "backupAMFName")?);
            }
            opt_extension_container(r, has_ext, budget)?;
            finish_sequence(r, ext)?;
            out.push(g);
        }
        Ok(out)
    })
}

fn decode_guami(r: &mut Reader, budget: &mut Budget) -> CodecResult<Value> {
    let ext = r.extension_bit("GUAMI")?;
    let has_ext = r.bit("GUAMI")?;
    let plmn = Plmn::decode(r)?;
    let region = r.fixed_bits(8, "AMFRegionID")?;
    let set = r.fixed_bits(10, "AMFSetID")?;
    let pointer = r.fixed_bits(6, "AMFPointer")?;
    opt_extension_container(r, has_ext, budget)?;
    finish_sequence(r, ext)?;
    Ok(
        json!({"plmn": plmn.to_json(), "amf_region_id": region, "amf_set_id": set, "amf_pointer": pointer}),
    )
}

/// `[{"plmn": {...}, "amf_region_id": 2, "amf_set_id": 1, "amf_pointer": 0}]`
pub fn served_guami_list_ie(list: &[Value]) -> EncodeResult<Ie> {
    encode_ie(IE_SERVED_GUAMI_LIST, Criticality::Reject, |w| {
        w.size(list.len(), 1, 256, "served_guami")?;
        for g in list {
            let plmn = Plmn::from_json(g.get("plmn").unwrap_or(&Value::Null))?;
            let region = json_u64(g, "amf_region_id", 0xFF)?;
            let set = json_u64(g, "amf_set_id", 0x3FF)?;
            let pointer = json_u64(g, "amf_pointer", 0x3F)?;
            let backup = g.get("backup_amf_name").and_then(Value::as_str);
            w.bit(false);
            w.bit(backup.is_some());
            w.bit(false);
            w.bit(false);
            w.bit(false);
            plmn.encode(w);
            w.fixed_bits(region, 8);
            w.fixed_bits(set, 10);
            w.fixed_bits(pointer, 6);
            if let Some(b) = backup {
                w.printable_string(b, 1, 150, "backup_amf_name")?;
            }
        }
        Ok(())
    })
}

pub fn relative_amf_capacity_ie(c: u64) -> EncodeResult<Ie> {
    encode_ie(IE_RELATIVE_AMF_CAPACITY, Criticality::Ignore, |w| {
        Ok(w.constrained(c, 0, 255, "relative_amf_capacity")?)
    })
}

pub fn decode_relative_amf_capacity(ie: &Ie) -> CodecResult<u64> {
    decode_ie(ie, |r| Ok(r.constrained(0, 255, "RelativeAMFCapacity")?))
}

pub fn decode_plmn_support_list(ie: &Ie, budget: &mut Budget) -> CodecResult<Vec<Value>> {
    decode_ie(ie, |r| {
        let n = r.size(1, 12, "PLMNSupportList")?;
        budget.take(n, "PLMNSupportList")?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let ext = r.extension_bit("PLMNSupportItem")?;
            let has_ext = r.bit("PLMNSupportItem")?;
            let plmn = Plmn::decode(r)?;
            let slices = decode_slice_list(r, budget)?;
            opt_extension_container(r, has_ext, budget)?;
            finish_sequence(r, ext)?;
            out.push(json!({"plmn": plmn.to_json(), "slices": slices}));
        }
        Ok(out)
    })
}

/// `[{"plmn": {...}, "slices": [{"sst": 1, "sd": "010203"}]}]`
pub fn plmn_support_list_ie(list: &[Value]) -> EncodeResult<Ie> {
    encode_ie(IE_PLMN_SUPPORT_LIST, Criticality::Reject, |w| {
        w.size(list.len(), 1, 12, "plmn_support")?;
        for p in list {
            let plmn = Plmn::from_json(p.get("plmn").unwrap_or(&Value::Null))?;
            w.bit(false);
            w.bit(false);
            plmn.encode(w);
            encode_slice_list(w, json_list(p, "slices")?)?;
        }
        Ok(())
    })
}

// ============================================================================
// UE-associated IEs
// ============================================================================

/// UserLocationInformation: NR decoded fully, E-UTRA decoded, N3IWF named.
pub fn decode_user_location(ie: &Ie, budget: &mut Budget) -> CodecResult<Value> {
    decode_ie(ie, |r| {
        // EUTRA, NR, N3IWF, choice-Extensions (TNGF / TWIF / W-AGF).
        match r.constrained(0, 3, "UserLocationInformation")? {
            choice @ (0 | 1) => {
                let ext = r.extension_bit("UserLocationInformation")?;
                let has_ts = r.bit("UserLocationInformation")?;
                let has_ext = r.bit("UserLocationInformation")?;
                // E-UTRA-CGI / NR-CGI
                let cext = r.extension_bit("CGI")?;
                let chas = r.bit("CGI")?;
                let cplmn = Plmn::decode(r)?;
                let cell = if choice == 1 {
                    r.fixed_bits(36, "NRCellIdentity")?
                } else {
                    r.fixed_bits(28, "EUTRACellIdentity")?
                };
                opt_extension_container(r, chas, budget)?;
                finish_sequence(r, cext)?;
                // TAI
                let text = r.extension_bit("TAI")?;
                let thas = r.bit("TAI")?;
                let tplmn = Plmn::decode(r)?;
                let tac = decode_tac(r)?;
                opt_extension_container(r, thas, budget)?;
                finish_sequence(r, text)?;
                let mut v = json!({
                    "type": if choice == 1 { "nr" } else { "eutra" },
                    "cgi": {"plmn": cplmn.to_json(), "cell_id": cell},
                    "tai": {"plmn": tplmn.to_json(), "tac": tac},
                });
                if has_ts {
                    let ts = r.fixed_octets(4, "TimeStamp")?;
                    v["time_stamp"] = json!(u32::from_be_bytes([ts[0], ts[1], ts[2], ts[3]]));
                }
                opt_extension_container(r, has_ext, budget)?;
                finish_sequence(r, ext)?;
                Ok(v)
            }
            other => {
                // N3IWF or a choice extension: not interpreted. The open type already bounded it
                // and this value is the whole IE, so the rest is consumed unread.
                while !r.at_end() {
                    r.bits(8, "UserLocationInformation")?;
                }
                Ok(json!({"type": if other == 2 { "n3iwf" } else { CHOICE_EXTENSIONS }}))
            }
        }
    })
}

/// NR user location: `{"cgi": {"plmn", "cell_id"}, "tai": {"plmn", "tac"}}`.
pub fn user_location_nr_ie(v: &Value, crit: Criticality) -> EncodeResult<Ie> {
    let cgi = v
        .get("cgi")
        .ok_or_else(|| EncodeError("user_location.cgi is required".into()))?;
    let tai = v
        .get("tai")
        .ok_or_else(|| EncodeError("user_location.tai is required".into()))?;
    let cplmn = Plmn::from_json(cgi.get("plmn").unwrap_or(&Value::Null))?;
    let cell = json_u64(cgi, "cell_id", (1 << 36) - 1)?;
    let tplmn = Plmn::from_json(tai.get("plmn").unwrap_or(&Value::Null))?;
    let tac = json_u64(tai, "tac", 0xFF_FFFF)?;
    encode_ie(IE_USER_LOCATION_INFORMATION, crit, |w| {
        put_choice(w, 1, 4, "UserLocationInformation")?;
        w.bit(false);
        w.bit(false);
        w.bit(false);
        w.bit(false);
        w.bit(false);
        cplmn.encode(w);
        w.fixed_bits(cell, 36);
        w.bit(false);
        w.bit(false);
        tplmn.encode(w);
        w.fixed_octets(&tac_octets(tac));
        Ok(())
    })
}

fn decode_five_g_s_tmsi(ie: &Ie, budget: &mut Budget) -> CodecResult<Value> {
    decode_ie(ie, |r| {
        let ext = r.extension_bit("FiveG-S-TMSI")?;
        let has_ext = r.bit("FiveG-S-TMSI")?;
        let set = r.fixed_bits(10, "AMFSetID")?;
        let pointer = r.fixed_bits(6, "AMFPointer")?;
        let t = r.fixed_octets(4, "FiveG-TMSI")?;
        opt_extension_container(r, has_ext, budget)?;
        finish_sequence(r, ext)?;
        Ok(json!({"amf_set_id": set, "amf_pointer": pointer,
                  "tmsi": u32::from_be_bytes([t[0], t[1], t[2], t[3]])}))
    })
}

/// UE-NGAP-IDs: `(amf_ue_ngap_id, Some(ran_ue_ngap_id))` for the pair form.
pub fn decode_ue_ngap_ids(ie: &Ie, budget: &mut Budget) -> CodecResult<(u64, Option<u64>)> {
    decode_ie(ie, |r| {
        if choice(r, 3, "UE-NGAP-IDs")? == 0 {
            let ext = r.extension_bit("UE-NGAP-ID-pair")?;
            let has_ext = r.bit("UE-NGAP-ID-pair")?;
            let amf = r.constrained(0, MAX_AMF_UE_NGAP_ID, "AMF-UE-NGAP-ID")?;
            let ran = r.constrained(0, MAX_RAN_UE_NGAP_ID, "RAN-UE-NGAP-ID")?;
            opt_extension_container(r, has_ext, budget)?;
            finish_sequence(r, ext)?;
            Ok((amf, Some(ran)))
        } else {
            Ok((
                r.constrained(0, MAX_AMF_UE_NGAP_ID, "AMF-UE-NGAP-ID")?,
                None,
            ))
        }
    })
}

pub fn ue_ngap_ids_ie(amf: u64, ran: Option<u64>) -> EncodeResult<Ie> {
    encode_ie(IE_UE_NGAP_IDS, Criticality::Reject, |w| {
        match ran {
            Some(ran) => {
                put_choice(w, 0, 3, "UE-NGAP-IDs")?;
                w.bit(false);
                w.bit(false);
                w.constrained(amf, 0, MAX_AMF_UE_NGAP_ID, "AMF-UE-NGAP-ID")?;
                w.constrained(ran, 0, MAX_RAN_UE_NGAP_ID, "RAN-UE-NGAP-ID")?;
            }
            None => {
                put_choice(w, 1, 3, "UE-NGAP-IDs")?;
                w.constrained(amf, 0, MAX_AMF_UE_NGAP_ID, "AMF-UE-NGAP-ID")?;
            }
        }
        Ok(())
    })
}

/// One `UE-associatedLogicalNG-connectionItem`: either id may be absent.
pub type ConnectionItem = (Option<u64>, Option<u64>);

fn decode_connection_list(r: &mut Reader, budget: &mut Budget) -> CodecResult<Vec<ConnectionItem>> {
    let n = r.size(1, 65_536, "UE-associatedLogicalNG-connectionList")?;
    budget.take(n, "UE-associatedLogicalNG-connectionList")?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let ext = r.extension_bit("UE-associatedLogicalNG-connectionItem")?;
        let has_amf = r.bit("item")?;
        let has_ran = r.bit("item")?;
        let has_ext = r.bit("item")?;
        let amf = if has_amf {
            Some(r.constrained(0, MAX_AMF_UE_NGAP_ID, "AMF-UE-NGAP-ID")?)
        } else {
            None
        };
        let ran = if has_ran {
            Some(r.constrained(0, MAX_RAN_UE_NGAP_ID, "RAN-UE-NGAP-ID")?)
        } else {
            None
        };
        opt_extension_container(r, has_ext, budget)?;
        finish_sequence(r, ext)?;
        out.push((amf, ran));
    }
    Ok(out)
}

fn encode_connection_list(w: &mut Writer, items: &[ConnectionItem]) -> EncodeResult<()> {
    w.size(items.len(), 1, 65_536, "connection list")?;
    for (amf, ran) in items {
        w.bit(false);
        w.bit(amf.is_some());
        w.bit(ran.is_some());
        w.bit(false);
        if let Some(a) = amf {
            w.constrained(*a, 0, MAX_AMF_UE_NGAP_ID, "AMF-UE-NGAP-ID")?;
        }
        if let Some(r) = ran {
            w.constrained(*r, 0, MAX_RAN_UE_NGAP_ID, "RAN-UE-NGAP-ID")?;
        }
    }
    Ok(())
}

/// ResetType: `None` is reset-all, `Some(items)` the partial form.
pub fn decode_reset_type(ie: &Ie, budget: &mut Budget) -> CodecResult<Option<Vec<ConnectionItem>>> {
    decode_ie(ie, |r| {
        if choice(r, 3, "ResetType")? == 0 {
            r.enumerated(1, true, "ResetAll")?;
            Ok(None)
        } else {
            Ok(Some(decode_connection_list(r, budget)?))
        }
    })
}

pub fn reset_type_ie(partial: Option<&[ConnectionItem]>) -> EncodeResult<Ie> {
    encode_ie(IE_RESET_TYPE, Criticality::Reject, |w| {
        match partial {
            None => {
                put_choice(w, 0, 3, "ResetType")?;
                w.enumerated(0, false, 1, true, "ResetAll")?;
            }
            Some(items) => {
                put_choice(w, 1, 3, "ResetType")?;
                encode_connection_list(w, items)?;
            }
        }
        Ok(())
    })
}

pub fn decode_connection_list_ie(ie: &Ie, budget: &mut Budget) -> CodecResult<Vec<ConnectionItem>> {
    decode_ie(ie, |r| decode_connection_list(r, budget))
}

pub fn connection_list_ie(items: &[ConnectionItem]) -> EncodeResult<Ie> {
    encode_ie(
        IE_UE_ASSOCIATED_LOGICAL_NG_CONNECTION_LIST,
        Criticality::Ignore,
        |w| encode_connection_list(w, items),
    )
}

// ============================================================================
// Decoded messages
// ============================================================================

/// NG Setup Request, decoded for the model (TS 38.413 section 9.2.6.1).
pub fn parse_ng_setup_request(pdu: &Pdu) -> CodecResult<Value> {
    let mut budget = Budget::default();
    let node = decode_global_ran_node_id(pdu.require(IE_GLOBAL_RAN_NODE_ID)?, &mut budget)?;
    let tas = decode_supported_ta_list(pdu.require(IE_SUPPORTED_TA_LIST)?, &mut budget)?;
    let drx = decode_paging_drx(pdu.require(IE_DEFAULT_PAGING_DRX)?)?;
    let name = match pdu.ie(IE_RAN_NODE_NAME) {
        Some(ie) => Some(decode_name(ie)?),
        None => None,
    };
    Ok(json!({
        "global_ran_node_id": node,
        "ran_node_name": name,
        "supported_ta_list": tas,
        "default_paging_drx": drx,
        "uninterpreted_ies": pdu.uninterpreted_ies(&[
            IE_GLOBAL_RAN_NODE_ID, IE_SUPPORTED_TA_LIST, IE_DEFAULT_PAGING_DRX, IE_RAN_NODE_NAME
        ]),
    }))
}

/// NG Setup Response, decoded for the gNB's model (TS 38.413 section 9.2.6.2).
pub fn parse_ng_setup_response(pdu: &Pdu) -> CodecResult<Value> {
    let mut budget = Budget::default();
    let name = decode_name(pdu.require(IE_AMF_NAME)?)?;
    let guamis = decode_served_guami_list(pdu.require(IE_SERVED_GUAMI_LIST)?, &mut budget)?;
    let capacity = decode_relative_amf_capacity(pdu.require(IE_RELATIVE_AMF_CAPACITY)?)?;
    let plmns = decode_plmn_support_list(pdu.require(IE_PLMN_SUPPORT_LIST)?, &mut budget)?;
    Ok(json!({
        "amf_name": name,
        "served_guami": guamis,
        "relative_amf_capacity": capacity,
        "plmn_support": plmns,
        "uninterpreted_ies": pdu.uninterpreted_ies(&[
            IE_AMF_NAME, IE_SERVED_GUAMI_LIST, IE_RELATIVE_AMF_CAPACITY, IE_PLMN_SUPPORT_LIST
        ]),
    }))
}

/// NG Setup Failure, or any message carrying an optional Cause and Time to Wait.
pub fn parse_cause_message(pdu: &Pdu) -> CodecResult<Value> {
    let mut v = Map::new();
    if let Some(ie) = pdu.ie(IE_CAUSE) {
        v.insert("cause".into(), decode_cause(ie)?.to_json());
    }
    if let Some(ie) = pdu.ie(IE_TIME_TO_WAIT) {
        v.insert("time_to_wait".into(), json!(decode_time_to_wait(ie)?));
    }
    if let Some(ie) = pdu.ie(IE_AMF_UE_NGAP_ID) {
        v.insert("amf_ue_ngap_id".into(), json!(decode_amf_ue_ngap_id(ie)?));
    }
    if let Some(ie) = pdu.ie(IE_RAN_UE_NGAP_ID) {
        v.insert("ran_ue_ngap_id".into(), json!(decode_ran_ue_ngap_id(ie)?));
    }
    v.insert(
        "uninterpreted_ies".into(),
        json!(pdu.uninterpreted_ies(&[
            IE_CAUSE,
            IE_TIME_TO_WAIT,
            IE_AMF_UE_NGAP_ID,
            IE_RAN_UE_NGAP_ID
        ])),
    );
    Ok(Value::Object(v))
}

/// The UE-associated fields of an Initial UE Message.
pub struct InitialUe {
    pub ran_ue_ngap_id: u64,
    pub nas: Vec<u8>,
    pub user_location: Value,
    pub rrc_establishment_cause: String,
    pub five_g_s_tmsi: Option<Value>,
    pub uninterpreted: Vec<Value>,
}

/// Initial UE Message (TS 38.413 section 9.2.5.1).
pub fn parse_initial_ue_message(pdu: &Pdu) -> CodecResult<InitialUe> {
    let mut budget = Budget::default();
    let ran = decode_ran_ue_ngap_id(pdu.require(IE_RAN_UE_NGAP_ID)?)?;
    let nas = decode_nas_pdu(pdu.require(IE_NAS_PDU)?)?;
    if nas.is_empty() {
        return Err(semantic("empty NAS-PDU"));
    }
    let uli = decode_user_location(pdu.require(IE_USER_LOCATION_INFORMATION)?, &mut budget)?;
    let cause = decode_rrc_cause(pdu.require(IE_RRC_ESTABLISHMENT_CAUSE)?)?;
    let tmsi = match pdu.ie(IE_FIVE_G_S_TMSI) {
        Some(ie) => Some(decode_five_g_s_tmsi(ie, &mut budget)?),
        None => None,
    };
    Ok(InitialUe {
        ran_ue_ngap_id: ran,
        nas,
        user_location: uli,
        rrc_establishment_cause: cause,
        five_g_s_tmsi: tmsi,
        uninterpreted: pdu.uninterpreted_ies(&[
            IE_RAN_UE_NGAP_ID,
            IE_NAS_PDU,
            IE_USER_LOCATION_INFORMATION,
            IE_RRC_ESTABLISHMENT_CAUSE,
            IE_FIVE_G_S_TMSI,
        ]),
    })
}

/// The fields of a Downlink or Uplink NAS Transport.
pub struct NasTransport {
    pub amf_ue_ngap_id: u64,
    pub ran_ue_ngap_id: u64,
    pub nas: Vec<u8>,
    pub user_location: Option<Value>,
    pub uninterpreted: Vec<Value>,
}

/// Downlink (9.2.5.2) or Uplink (9.2.5.3) NAS Transport.
pub fn parse_nas_transport(pdu: &Pdu) -> CodecResult<NasTransport> {
    let mut budget = Budget::default();
    let amf = decode_amf_ue_ngap_id(pdu.require(IE_AMF_UE_NGAP_ID)?)?;
    let ran = decode_ran_ue_ngap_id(pdu.require(IE_RAN_UE_NGAP_ID)?)?;
    let nas = decode_nas_pdu(pdu.require(IE_NAS_PDU)?)?;
    if nas.is_empty() {
        return Err(semantic("empty NAS-PDU"));
    }
    let uli = match pdu.ie(IE_USER_LOCATION_INFORMATION) {
        Some(ie) => Some(decode_user_location(ie, &mut budget)?),
        None if pdu.procedure_code == PROC_UPLINK_NAS_TRANSPORT => {
            return Err(abstract_reject(
                "UplinkNASTransport is missing mandatory IE 121 (UserLocationInformation)",
            ))
        }
        None => None,
    };
    Ok(NasTransport {
        amf_ue_ngap_id: amf,
        ran_ue_ngap_id: ran,
        nas,
        user_location: uli,
        uninterpreted: pdu.uninterpreted_ies(&[
            IE_AMF_UE_NGAP_ID,
            IE_RAN_UE_NGAP_ID,
            IE_NAS_PDU,
            IE_USER_LOCATION_INFORMATION,
        ]),
    })
}

// ============================================================================
// Builders
// ============================================================================

fn build(kind: PduKind, code: u8, crit: Criticality, ies: Vec<Ie>) -> EncodeResult<Vec<u8>> {
    encode_pdu(&Pdu::new(kind, code, crit, ies))
}

/// NG Setup Response from the model's fields.
pub fn ng_setup_response(
    amf_name: &str,
    served_guami: &[Value],
    relative_amf_capacity: u64,
    plmn_support: &[Value],
) -> EncodeResult<Vec<u8>> {
    build(
        PduKind::Successful,
        PROC_NG_SETUP,
        Criticality::Reject,
        vec![
            name_ie(IE_AMF_NAME, Criticality::Reject, amf_name)?,
            served_guami_list_ie(served_guami)?,
            relative_amf_capacity_ie(relative_amf_capacity)?,
            plmn_support_list_ie(plmn_support)?,
        ],
    )
}

pub fn ng_setup_failure(cause: &Cause, time_to_wait: Option<&str>) -> EncodeResult<Vec<u8>> {
    let mut ies = vec![cause_ie(cause, Criticality::Ignore)?];
    if let Some(t) = time_to_wait {
        ies.push(time_to_wait_ie(t)?);
    }
    build(
        PduKind::Unsuccessful,
        PROC_NG_SETUP,
        Criticality::Reject,
        ies,
    )
}

pub fn ng_setup_request(
    plmn: &Plmn,
    gnb_id: u64,
    gnb_id_bits: u32,
    ran_node_name: Option<&str>,
    supported_ta_list: &[Value],
    paging_drx: &str,
) -> EncodeResult<Vec<u8>> {
    let mut ies = vec![global_gnb_id_ie(plmn, gnb_id, gnb_id_bits)?];
    if let Some(n) = ran_node_name {
        ies.push(name_ie(IE_RAN_NODE_NAME, Criticality::Ignore, n)?);
    }
    ies.push(supported_ta_list_ie(supported_ta_list)?);
    ies.push(paging_drx_ie(paging_drx)?);
    build(PduKind::Initiating, PROC_NG_SETUP, Criticality::Reject, ies)
}

pub fn downlink_nas_transport(amf: u64, ran: u64, nas: &[u8]) -> EncodeResult<Vec<u8>> {
    build(
        PduKind::Initiating,
        PROC_DOWNLINK_NAS_TRANSPORT,
        Criticality::Ignore,
        vec![
            amf_ue_ngap_id_ie(amf, Criticality::Reject)?,
            ran_ue_ngap_id_ie(ran, Criticality::Reject)?,
            nas_pdu_ie(nas)?,
        ],
    )
}

pub fn uplink_nas_transport(
    amf: u64,
    ran: u64,
    nas: &[u8],
    user_location: &Value,
) -> EncodeResult<Vec<u8>> {
    build(
        PduKind::Initiating,
        PROC_UPLINK_NAS_TRANSPORT,
        Criticality::Ignore,
        vec![
            amf_ue_ngap_id_ie(amf, Criticality::Reject)?,
            ran_ue_ngap_id_ie(ran, Criticality::Reject)?,
            nas_pdu_ie(nas)?,
            user_location_nr_ie(user_location, Criticality::Ignore)?,
        ],
    )
}

pub fn initial_ue_message(
    ran: u64,
    nas: &[u8],
    user_location: &Value,
    rrc_establishment_cause: &str,
) -> EncodeResult<Vec<u8>> {
    build(
        PduKind::Initiating,
        PROC_INITIAL_UE_MESSAGE,
        Criticality::Ignore,
        vec![
            ran_ue_ngap_id_ie(ran, Criticality::Reject)?,
            nas_pdu_ie(nas)?,
            user_location_nr_ie(user_location, Criticality::Reject)?,
            rrc_cause_ie(rrc_establishment_cause)?,
        ],
    )
}

pub fn error_indication(
    amf: Option<u64>,
    ran: Option<u64>,
    cause: Option<&Cause>,
) -> EncodeResult<Vec<u8>> {
    let mut ies = Vec::new();
    if let Some(a) = amf {
        ies.push(amf_ue_ngap_id_ie(a, Criticality::Ignore)?);
    }
    if let Some(r) = ran {
        ies.push(ran_ue_ngap_id_ie(r, Criticality::Ignore)?);
    }
    if let Some(c) = cause {
        ies.push(cause_ie(c, Criticality::Ignore)?);
    }
    build(
        PduKind::Initiating,
        PROC_ERROR_INDICATION,
        Criticality::Ignore,
        ies,
    )
}

pub fn ng_reset(cause: &Cause, partial: Option<&[ConnectionItem]>) -> EncodeResult<Vec<u8>> {
    build(
        PduKind::Initiating,
        PROC_NG_RESET,
        Criticality::Reject,
        vec![
            cause_ie(cause, Criticality::Ignore)?,
            reset_type_ie(partial)?,
        ],
    )
}

/// NG Reset Acknowledge; for a partial reset the list of connections reset is echoed (38.413
/// section 8.7.4.2.1).
pub fn ng_reset_acknowledge(partial: Option<&[ConnectionItem]>) -> EncodeResult<Vec<u8>> {
    let mut ies = Vec::new();
    if let Some(items) = partial {
        ies.push(connection_list_ie(items)?);
    }
    build(PduKind::Successful, PROC_NG_RESET, Criticality::Reject, ies)
}

pub fn ue_context_release_command(
    amf: u64,
    ran: Option<u64>,
    cause: &Cause,
) -> EncodeResult<Vec<u8>> {
    build(
        PduKind::Initiating,
        PROC_UE_CONTEXT_RELEASE,
        Criticality::Reject,
        vec![
            ue_ngap_ids_ie(amf, ran)?,
            cause_ie(cause, Criticality::Ignore)?,
        ],
    )
}

pub fn ue_context_release_complete(amf: u64, ran: u64) -> EncodeResult<Vec<u8>> {
    build(
        PduKind::Successful,
        PROC_UE_CONTEXT_RELEASE,
        Criticality::Reject,
        vec![
            amf_ue_ngap_id_ie(amf, Criticality::Ignore)?,
            ran_ue_ngap_id_ie(ran, Criticality::Ignore)?,
        ],
    )
}

/// Every IE id of an encoded PDU, for logs; `None` when it does not decode.
pub fn summarize(bytes: &[u8]) -> Option<String> {
    let p = decode_pdu(bytes).ok()?;
    Some(p.label())
}

/// Re-export so callers name one error type for "the peer sent garbage".
pub use aper::AperError as WireError;

// ============================================================================
// UE context and PDU session resources (TS 38.413 sections 9.2.1, 9.2.2, 9.3)
// ============================================================================

pub const IE_ALLOWED_NSSAI: u16 = 0;
pub const IE_GUAMI: u16 = 28;
pub const IE_MASKED_IMEISV: u16 = 34;
pub const IE_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_CXT_RES: u16 = 55;
pub const IE_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_SU_RES: u16 = 58;
pub const IE_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_REQ: u16 = 71;
pub const IE_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_RES: u16 = 72;
pub const IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ: u16 = 74;
pub const IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES: u16 = 75;
pub const IE_SECURITY_KEY: u16 = 94;
pub const IE_UE_AGGREGATE_MAXIMUM_BIT_RATE: u16 = 110;
pub const IE_UE_SECURITY_CAPABILITIES: u16 = 119;
pub const IE_PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE: u16 = 130;
pub const IE_PDU_SESSION_RESOURCE_LIST_CXT_REL_REQ: u16 = 133;
pub const IE_PDU_SESSION_TYPE: u16 = 134;
pub const IE_QOS_FLOW_SETUP_REQUEST_LIST: u16 = 136;
pub const IE_UL_NGU_UP_TNL_INFORMATION: u16 = 139;

pub const PROC_INITIAL_CONTEXT_SETUP: u8 = 14;
pub const PROC_PDU_SESSION_RESOURCE_RELEASE: u8 = 28;
pub const PROC_PDU_SESSION_RESOURCE_SETUP: u8 = 29;
pub const PROC_UE_CONTEXT_RELEASE_REQUEST: u8 = 42;

/// BitRate ::= INTEGER (0..4000000000000, ...), in bits per second.
pub const MAX_BIT_RATE: u64 = 4_000_000_000_000;
/// PDU sessions in one setup list NetGet writes or reads (the constraint allows 256).
pub const MAX_PDU_SESSIONS: usize = 16;
/// QoS flows per PDU session NetGet writes or reads (the constraint allows 64).
pub const MAX_QOS_FLOWS: usize = 8;

fn encode_container(ies: &[Ie]) -> EncodeResult<Vec<u8>> {
    if ies.len() > MAX_IES {
        return enc_err(format!("{} IEs exceeds {MAX_IES}", ies.len()));
    }
    let mut c = Writer::new();
    c.bit(false);
    c.size(ies.len(), 0, 65_535, "ProtocolIE-Container")?;
    for ie in ies {
        c.constrained(ie.id as u64, 0, 65_535, "ProtocolIE-ID")?;
        c.constrained(ie.criticality.index(), 0, 2, "IE criticality")?;
        c.open_type(&ie.value, "IE value")?;
    }
    Ok(c.finish())
}

/// A `SEQUENCE { protocolIEs ProtocolIE-Container, ... }` that is not a whole PDU — the
/// PDU Session Resource Setup Request Transfer is one.
fn decode_container(bytes: &[u8]) -> CodecResult<Vec<Ie>> {
    let mut c = Reader::new(bytes);
    let extended = c.extension_bit("container")?;
    let count = c.size(0, 65_535, "ProtocolIE-Container")?;
    if count > MAX_IES {
        return Err(AperError(format!("{count} IEs exceeds the bound of {MAX_IES}")).into());
    }
    let mut ies: Vec<Ie> = Vec::with_capacity(count);
    for _ in 0..count {
        let id = c.constrained(0, 65_535, "ProtocolIE-ID")? as u16;
        let crit = Criticality::from_index(c.constrained(0, 2, "IE criticality")?);
        let value = c.open_type("IE value")?.to_vec();
        if ies.iter().any(|ie| ie.id == id) {
            return Err(ProtocolError {
                cause: Cause::protocol(5),
                detail: format!("IE {id} appears more than once"),
            });
        }
        ies.push(Ie::new(id, crit, value));
    }
    if extended {
        c.skip_extension_additions("container extension additions")?;
    }
    Ok(ies)
}

fn require_in(ies: &[Ie], id: u16, what: &str) -> CodecResult<Ie> {
    ies.iter()
        .find(|ie| ie.id == id)
        .cloned()
        .ok_or_else(|| abstract_reject(format!("{what} is missing mandatory IE {id}")))
}

fn put_bit_rate(w: &mut Writer, bps: u64) -> EncodeResult<()> {
    w.bit(false);
    Ok(w.constrained(bps, 0, MAX_BIT_RATE, "BitRate")?)
}

fn get_bit_rate(r: &mut Reader) -> CodecResult<u64> {
    if r.extension_bit("BitRate")? {
        return Err(semantic("a BitRate beyond its root range"));
    }
    Ok(r.constrained(0, MAX_BIT_RATE, "BitRate")?)
}

/// `{"uplink_bps", "downlink_bps"}` for UEAggregateMaximumBitRate and
/// PDUSessionAggregateMaximumBitRate, which share a shape.
fn encode_ambr(w: &mut Writer, dl: u64, ul: u64) -> EncodeResult<()> {
    w.bit(false);
    w.bit(false);
    put_bit_rate(w, dl)?;
    put_bit_rate(w, ul)
}

fn decode_ambr(r: &mut Reader, budget: &mut Budget) -> CodecResult<(u64, u64)> {
    let ext = r.extension_bit("AMBR")?;
    let has_ext = r.bit("AMBR")?;
    let dl = get_bit_rate(r)?;
    let ul = get_bit_rate(r)?;
    opt_extension_container(r, has_ext, budget)?;
    finish_sequence(r, ext)?;
    Ok((dl, ul))
}

pub fn ue_ambr_ie(dl: u64, ul: u64) -> EncodeResult<Ie> {
    encode_ie(IE_UE_AGGREGATE_MAXIMUM_BIT_RATE, Criticality::Reject, |w| {
        encode_ambr(w, dl, ul)
    })
}

fn encode_guami(w: &mut Writer, g: &Value) -> EncodeResult<()> {
    let plmn = Plmn::from_json(g.get("plmn").unwrap_or(&Value::Null))?;
    let region = json_u64(g, "amf_region_id", 0xFF)?;
    let set = json_u64(g, "amf_set_id", 0x3FF)?;
    let pointer = json_u64(g, "amf_pointer", 0x3F)?;
    w.bit(false);
    w.bit(false);
    plmn.encode(w);
    w.fixed_bits(region, 8);
    w.fixed_bits(set, 10);
    w.fixed_bits(pointer, 6);
    Ok(())
}

pub fn guami_ie(g: &Value) -> EncodeResult<Ie> {
    encode_ie(IE_GUAMI, Criticality::Reject, |w| encode_guami(w, g))
}

pub fn decode_guami_ie(ie: &Ie) -> CodecResult<Value> {
    let mut budget = Budget::default();
    decode_ie(ie, |r| decode_guami(r, &mut budget))
}

/// AllowedNSSAI ::= SEQUENCE (SIZE(1..8)) OF AllowedNSSAI-Item.
pub fn allowed_nssai_ie(slices: &[Value]) -> EncodeResult<Ie> {
    encode_ie(IE_ALLOWED_NSSAI, Criticality::Reject, |w| {
        w.size(slices.len(), 1, 8, "allowed_nssai")?;
        for s in slices {
            w.bit(false);
            w.bit(false);
            encode_snssai(w, s)?;
        }
        Ok(())
    })
}

pub fn decode_allowed_nssai(ie: &Ie) -> CodecResult<Vec<Value>> {
    let mut budget = Budget::default();
    decode_ie(ie, |r| {
        let n = r.size(1, 8, "AllowedNSSAI")?;
        budget.take(n, "AllowedNSSAI")?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let ext = r.extension_bit("AllowedNSSAI-Item")?;
            let has_ext = r.bit("AllowedNSSAI-Item")?;
            out.push(decode_snssai(r, &mut budget)?);
            opt_extension_container(r, has_ext, &mut budget)?;
            finish_sequence(r, ext)?;
        }
        Ok(out)
    })
}

/// UESecurityCapabilities: four `BIT STRING (SIZE(16, ...))` (NR encryption, NR integrity,
/// E-UTRA encryption, E-UTRA integrity).
pub fn ue_security_capabilities_ie(caps: [u16; 4]) -> EncodeResult<Ie> {
    encode_ie(IE_UE_SECURITY_CAPABILITIES, Criticality::Reject, |w| {
        w.bit(false);
        w.bit(false);
        for c in caps {
            w.bit(false);
            w.fixed_bits(c as u64, 16);
        }
        Ok(())
    })
}

pub fn decode_ue_security_capabilities(ie: &Ie) -> CodecResult<[u16; 4]> {
    let mut budget = Budget::default();
    decode_ie(ie, |r| {
        let ext = r.extension_bit("UESecurityCapabilities")?;
        let has_ext = r.bit("UESecurityCapabilities")?;
        let mut out = [0u16; 4];
        for o in out.iter_mut() {
            if r.extension_bit("algorithms")? {
                return Err(semantic("an algorithm bitmap beyond 16 bits"));
            }
            *o = r.fixed_bits(16, "algorithms")? as u16;
        }
        opt_extension_container(r, has_ext, &mut budget)?;
        finish_sequence(r, ext)?;
        Ok(out)
    })
}

/// SecurityKey ::= BIT STRING (SIZE(256)) — K_gNB.
pub fn security_key_ie(key: &[u8; 32]) -> EncodeResult<Ie> {
    encode_ie(IE_SECURITY_KEY, Criticality::Reject, |w| {
        w.align();
        w.octets_aligned(key);
        Ok(())
    })
}

pub fn decode_security_key(ie: &Ie) -> CodecResult<[u8; 32]> {
    decode_ie(ie, |r| {
        let b = r.octets_aligned(32, "SecurityKey")?;
        let mut k = [0u8; 32];
        k.copy_from_slice(b);
        Ok(k)
    })
}

pub fn nas_pdu_ie_with(nas: &[u8], crit: Criticality) -> EncodeResult<Ie> {
    let mut ie = nas_pdu_ie(nas)?;
    ie.criticality = crit;
    Ok(ie)
}

/// A GTP tunnel endpoint: UPTransportLayerInformation's gTPTunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtpTunnel {
    pub address: std::net::IpAddr,
    pub teid: u32,
}

impl GtpTunnel {
    pub fn to_json(&self) -> Value {
        json!({"address": self.address.to_string(), "teid": self.teid})
    }
}

fn encode_tunnel(w: &mut Writer, t: &GtpTunnel) -> EncodeResult<()> {
    put_choice(w, 0, 2, "UPTransportLayerInformation")?;
    w.bit(false);
    w.bit(false);
    let addr = match t.address {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };
    // TransportLayerAddress ::= BIT STRING (SIZE(1..160, ...))
    w.bit(false);
    w.size(addr.len() * 8, 1, 160, "TransportLayerAddress")?;
    w.align();
    w.octets_aligned(&addr);
    // GTP-TEID ::= OCTET STRING (SIZE(4))
    w.fixed_octets(&t.teid.to_be_bytes());
    Ok(())
}

fn decode_tunnel(r: &mut Reader, budget: &mut Budget) -> CodecResult<GtpTunnel> {
    choice(r, 2, "UPTransportLayerInformation")?;
    let ext = r.extension_bit("GTPTunnel")?;
    let has_ext = r.bit("GTPTunnel")?;
    if r.extension_bit("TransportLayerAddress")? {
        return Err(semantic("a TransportLayerAddress beyond 160 bits"));
    }
    let bits = r.size(1, 160, "TransportLayerAddress")?;
    r.align();
    let address = match bits {
        32 => {
            let b = r.octets_aligned(4, "IPv4 address")?;
            std::net::IpAddr::from([b[0], b[1], b[2], b[3]])
        }
        128 | 160 => {
            // 160 bits is IPv4 then IPv6 (TS 38.414); the IPv4 part is used.
            let b = r.octets_aligned(bits / 8, "transport address")?;
            if bits == 160 {
                std::net::IpAddr::from([b[0], b[1], b[2], b[3]])
            } else {
                let mut a = [0u8; 16];
                a.copy_from_slice(b);
                std::net::IpAddr::from(a)
            }
        }
        n => {
            return Err(semantic(format!(
                "a {n}-bit transport layer address is neither IPv4 nor IPv6"
            )))
        }
    };
    let teid = r.fixed_octets(4, "GTP-TEID")?;
    opt_extension_container(r, has_ext, budget)?;
    finish_sequence(r, ext)?;
    Ok(GtpTunnel {
        address,
        teid: u32::from_be_bytes([teid[0], teid[1], teid[2], teid[3]]),
    })
}

/// One QoS flow of a PDU session: QFI, a standardised 5QI and an ARP priority level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QosFlow {
    pub qfi: u8,
    pub five_qi: u8,
    pub arp_priority: u8,
}

fn encode_qos_flow(w: &mut Writer, f: &QosFlow) -> EncodeResult<()> {
    // QosFlowSetupRequestItem: ext, e-RAB-ID absent, iE-Extensions absent.
    w.bit(false);
    w.bit(false);
    w.bit(false);
    w.bit(false);
    w.constrained(f.qfi as u64, 0, 63, "qosFlowIdentifier")?;
    // QosFlowLevelQosParameters: ext, four optionals absent.
    w.bit(false);
    for _ in 0..4 {
        w.bit(false);
    }
    // QosCharacteristics: nonDynamic5QI.
    put_choice(w, 0, 3, "QosCharacteristics")?;
    w.bit(false);
    for _ in 0..4 {
        w.bit(false);
    }
    w.bit(false);
    w.constrained(f.five_qi as u64, 0, 255, "fiveQI")?;
    // AllocationAndRetentionPriority: ext, iE-Extensions absent, level, not-pre-empting.
    w.bit(false);
    w.bit(false);
    w.constrained(f.arp_priority as u64, 1, 15, "priorityLevelARP")?;
    w.enumerated(0, false, 2, true, "pre-emptionCapability")?;
    w.enumerated(0, false, 2, true, "pre-emptionVulnerability")?;
    Ok(())
}

fn decode_qos_flow(r: &mut Reader, budget: &mut Budget) -> CodecResult<QosFlow> {
    let ext = r.extension_bit("QosFlowSetupRequestItem")?;
    let has_erab = r.bit("QosFlowSetupRequestItem")?;
    let has_ext = r.bit("QosFlowSetupRequestItem")?;
    if r.extension_bit("qosFlowIdentifier")? {
        return Err(semantic("a QFI beyond 63"));
    }
    let qfi = r.constrained(0, 63, "qosFlowIdentifier")? as u8;
    let pext = r.extension_bit("QosFlowLevelQosParameters")?;
    let opts: Vec<bool> = (0..4)
        .map(|_| r.bit("QosFlowLevelQosParameters"))
        .collect::<Result<_, _>>()?;
    if opts[0] || opts[2] {
        return Err(semantic(
            "GBR or additional QoS flow information, which NetGet does not decode",
        ));
    }
    let five_qi = match choice(r, 3, "QosCharacteristics")? {
        0 => {
            let dext = r.extension_bit("NonDynamic5QIDescriptor")?;
            let dopts: Vec<bool> = (0..4)
                .map(|_| r.bit("NonDynamic5QIDescriptor"))
                .collect::<Result<_, _>>()?;
            if r.extension_bit("fiveQI")? {
                return Err(semantic("a 5QI beyond 255"));
            }
            let q = r.constrained(0, 255, "fiveQI")? as u8;
            if dopts[0] {
                r.bit("priorityLevelQos ext")?;
                r.constrained(1, 127, "priorityLevelQos")?;
            }
            if dopts[1] {
                r.bit("averagingWindow ext")?;
                r.constrained(0, 4095, "averagingWindow")?;
            }
            if dopts[2] {
                r.bit("maximumDataBurstVolume ext")?;
                r.constrained(0, 4095, "maximumDataBurstVolume")?;
            }
            opt_extension_container(r, dopts[3], budget)?;
            finish_sequence(r, dext)?;
            q
        }
        _ => {
            return Err(semantic(
                "a dynamic 5QI descriptor, which NetGet does not decode",
            ))
        }
    };
    let aext = r.extension_bit("AllocationAndRetentionPriority")?;
    let ahas = r.bit("AllocationAndRetentionPriority")?;
    let arp_priority = r.constrained(1, 15, "priorityLevelARP")? as u8;
    r.enumerated(2, true, "pre-emptionCapability")?;
    r.enumerated(2, true, "pre-emptionVulnerability")?;
    opt_extension_container(r, ahas, budget)?;
    finish_sequence(r, aext)?;
    if opts[1] {
        r.enumerated(1, true, "reflectiveQosAttribute")?;
    }
    opt_extension_container(r, opts[3], budget)?;
    finish_sequence(r, pext)?;
    if has_erab {
        r.bit("E-RAB-ID ext")?;
        r.constrained(0, 15, "E-RAB-ID")?;
    }
    opt_extension_container(r, has_ext, budget)?;
    finish_sequence(r, ext)?;
    Ok(QosFlow {
        qfi,
        five_qi,
        arp_priority,
    })
}

const PDU_SESSION_TYPES_NGAP: &[&str] = &["ipv4", "ipv6", "ipv4v6", "ethernet", "unstructured"];

/// The PDU Session Resource Setup Request Transfer the SMF would build (TS 38.413 9.3.4.1).
#[derive(Debug, Clone)]
pub struct SetupRequestTransfer {
    pub ambr_dl_bps: u64,
    pub ambr_ul_bps: u64,
    pub ul_tunnel: GtpTunnel,
    pub pdu_session_type: String,
    pub qos_flows: Vec<QosFlow>,
}

pub fn encode_setup_request_transfer(t: &SetupRequestTransfer) -> EncodeResult<Vec<u8>> {
    if t.qos_flows.is_empty() || t.qos_flows.len() > MAX_QOS_FLOWS {
        return enc_err(format!("1..{MAX_QOS_FLOWS} QoS flows"));
    }
    let ty = enum_index(
        PDU_SESSION_TYPES_NGAP,
        &t.pdu_session_type,
        "pdu_session_type",
    )?;
    let ies = vec![
        encode_ie(
            IE_PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE,
            Criticality::Reject,
            |w| encode_ambr(w, t.ambr_dl_bps, t.ambr_ul_bps),
        )?,
        encode_ie(IE_UL_NGU_UP_TNL_INFORMATION, Criticality::Reject, |w| {
            encode_tunnel(w, &t.ul_tunnel)
        })?,
        encode_ie(IE_PDU_SESSION_TYPE, Criticality::Reject, |w| {
            Ok(w.enumerated(ty, false, 5, true, "PDUSessionType")?)
        })?,
        encode_ie(IE_QOS_FLOW_SETUP_REQUEST_LIST, Criticality::Reject, |w| {
            w.size(t.qos_flows.len(), 1, 64, "QosFlowSetupRequestList")?;
            for f in &t.qos_flows {
                encode_qos_flow(w, f)?;
            }
            Ok(())
        })?,
    ];
    encode_container(&ies)
}

pub fn decode_setup_request_transfer(bytes: &[u8]) -> CodecResult<SetupRequestTransfer> {
    let ies = decode_container(bytes)?;
    let mut budget = Budget::default();
    let (dl, ul) = match ies
        .iter()
        .find(|i| i.id == IE_PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE)
    {
        Some(ie) => decode_ie(ie, |r| decode_ambr(r, &mut budget))?,
        None => (0, 0),
    };
    let tunnel_ie = require_in(
        &ies,
        IE_UL_NGU_UP_TNL_INFORMATION,
        "the setup request transfer",
    )?;
    let ul_tunnel = decode_ie(&tunnel_ie, |r| decode_tunnel(r, &mut budget))?;
    let type_ie = require_in(&ies, IE_PDU_SESSION_TYPE, "the setup request transfer")?;
    let (ext, ty) = decode_ie(&type_ie, |r| Ok(r.enumerated(5, true, "PDUSessionType")?))?;
    let flows_ie = require_in(
        &ies,
        IE_QOS_FLOW_SETUP_REQUEST_LIST,
        "the setup request transfer",
    )?;
    let qos_flows = decode_ie(&flows_ie, |r| {
        let n = r.size(1, 64, "QosFlowSetupRequestList")?;
        if n > MAX_QOS_FLOWS {
            return Err(AperError(format!("{n} QoS flows exceeds {MAX_QOS_FLOWS}")).into());
        }
        budget.take(n, "QosFlowSetupRequestList")?;
        (0..n).map(|_| decode_qos_flow(r, &mut budget)).collect()
    })?;
    Ok(SetupRequestTransfer {
        ambr_dl_bps: dl,
        ambr_ul_bps: ul,
        ul_tunnel,
        pdu_session_type: if ext {
            format!("ext-{ty}")
        } else {
            PDU_SESSION_TYPES_NGAP[ty as usize].to_string()
        },
        qos_flows,
    })
}

/// The gNB's answer for one PDU session (TS 38.413 9.3.4.2): its downlink tunnel and the QoS
/// flows it set up.
#[derive(Debug, Clone)]
pub struct SetupResponseTransfer {
    pub dl_tunnel: GtpTunnel,
    pub qfis: Vec<u8>,
}

pub fn encode_setup_response_transfer(t: &SetupResponseTransfer) -> EncodeResult<Vec<u8>> {
    if t.qfis.is_empty() || t.qfis.len() > MAX_QOS_FLOWS {
        return enc_err(format!("1..{MAX_QOS_FLOWS} associated QoS flows"));
    }
    let mut w = Writer::new();
    // PDUSessionResourceSetupResponseTransfer: ext, four optionals absent.
    w.bit(false);
    for _ in 0..4 {
        w.bit(false);
    }
    // QosFlowPerTNLInformation: ext, iE-Extensions absent.
    w.bit(false);
    w.bit(false);
    encode_tunnel(&mut w, &t.dl_tunnel)?;
    w.size(t.qfis.len(), 1, 64, "AssociatedQosFlowList")?;
    for q in &t.qfis {
        w.bit(false);
        w.bit(false);
        w.bit(false);
        w.bit(false);
        w.constrained(*q as u64, 0, 63, "qosFlowIdentifier")?;
    }
    Ok(w.finish())
}

/// The downlink tunnel and QoS flows of a response transfer. What follows the first
/// QosFlowPerTNLInformation (additional tunnels, security result, failed flows) is bounded by
/// the octet string and not interpreted.
pub fn decode_setup_response_transfer(bytes: &[u8]) -> CodecResult<SetupResponseTransfer> {
    let mut r = Reader::new(bytes);
    let mut budget = Budget::default();
    r.extension_bit("PDUSessionResourceSetupResponseTransfer")?;
    for _ in 0..4 {
        r.bit("PDUSessionResourceSetupResponseTransfer")?;
    }
    r.extension_bit("QosFlowPerTNLInformation")?;
    r.bit("QosFlowPerTNLInformation")?;
    let dl_tunnel = decode_tunnel(&mut r, &mut budget)?;
    let n = r.size(1, 64, "AssociatedQosFlowList")?;
    if n > MAX_QOS_FLOWS {
        return Err(AperError(format!("{n} associated QoS flows exceeds {MAX_QOS_FLOWS}")).into());
    }
    let mut qfis = Vec::with_capacity(n);
    for _ in 0..n {
        let ext = r.extension_bit("AssociatedQosFlowItem")?;
        let has_mapping = r.bit("AssociatedQosFlowItem")?;
        let has_ext = r.bit("AssociatedQosFlowItem")?;
        r.extension_bit("qosFlowIdentifier")?;
        qfis.push(r.constrained(0, 63, "qosFlowIdentifier")? as u8);
        if has_mapping {
            r.enumerated(2, true, "qosFlowMappingIndication")?;
        }
        opt_extension_container(&mut r, has_ext, &mut budget)?;
        finish_sequence(&mut r, ext)?;
    }
    Ok(SetupResponseTransfer { dl_tunnel, qfis })
}

/// One item of a PDU Session Resource Setup Request (SUReq) list.
#[derive(Debug, Clone)]
pub struct SetupItem {
    pub pdu_session_id: u8,
    pub nas: Option<Vec<u8>>,
    pub s_nssai: Value,
    pub transfer: Vec<u8>,
}

/// PDU Session Resource Setup Request (TS 38.413 9.2.1.1).
pub fn pdu_session_resource_setup_request(
    amf: u64,
    ran: u64,
    items: &[SetupItem],
    ue_ambr: Option<(u64, u64)>,
) -> EncodeResult<Vec<u8>> {
    if items.is_empty() || items.len() > MAX_PDU_SESSIONS {
        return enc_err(format!("1..{MAX_PDU_SESSIONS} PDU sessions"));
    }
    let list = encode_setup_items(IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ, items)?;
    let mut ies = vec![
        amf_ue_ngap_id_ie(amf, Criticality::Reject)?,
        ran_ue_ngap_id_ie(ran, Criticality::Reject)?,
        list,
    ];
    if let Some((dl, ul)) = ue_ambr {
        let mut ie = ue_ambr_ie(dl, ul)?;
        ie.criticality = Criticality::Ignore;
        ies.push(ie);
    }
    build(
        PduKind::Initiating,
        PROC_PDU_SESSION_RESOURCE_SETUP,
        Criticality::Reject,
        ies,
    )
}

/// A PDU Session Resource Setup item list: `PDUSessionResourceSetupListSUReq` and
/// `PDUSessionResourceSetupListCxtReq` items share one shape.
fn decode_setup_items(ie: &Ie, what: &str) -> CodecResult<Vec<SetupItem>> {
    let mut budget = Budget::default();
    decode_ie(ie, |r| {
        let n = r.size(1, 256, what)?;
        if n > MAX_PDU_SESSIONS {
            return Err(AperError(format!("{n} PDU sessions exceeds {MAX_PDU_SESSIONS}")).into());
        }
        budget.take(n, what)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let ext = r.extension_bit("PDUSessionResourceSetupItem")?;
            let has_nas = r.bit("item")?;
            let has_ext = r.bit("item")?;
            let psi = r.constrained(0, 255, "pDUSessionID")? as u8;
            let nas = if has_nas {
                Some(r.octet_string(MAX_NAS_PDU_LEN, "NAS-PDU")?.to_vec())
            } else {
                None
            };
            let s_nssai = decode_snssai(r, &mut budget)?;
            let transfer = r
                .octet_string(MAX_PDU_LEN, "pDUSessionResourceSetupRequestTransfer")?
                .to_vec();
            opt_extension_container(r, has_ext, &mut budget)?;
            finish_sequence(r, ext)?;
            out.push(SetupItem {
                pdu_session_id: psi,
                nas,
                s_nssai,
                transfer,
            });
        }
        Ok(out)
    })
}

fn encode_setup_items(id: u16, items: &[SetupItem]) -> EncodeResult<Ie> {
    if items.is_empty() || items.len() > MAX_PDU_SESSIONS {
        return enc_err(format!("1..{MAX_PDU_SESSIONS} PDU sessions"));
    }
    encode_ie(id, Criticality::Reject, |w| {
        w.size(items.len(), 1, 256, "PDU session setup list")?;
        for it in items {
            w.bit(false);
            w.bit(it.nas.is_some());
            w.bit(false);
            w.constrained(it.pdu_session_id as u64, 0, 255, "pDUSessionID")?;
            if let Some(n) = &it.nas {
                if n.is_empty() || n.len() > MAX_NAS_PDU_LEN {
                    return enc_err("NAS-PDU size");
                }
                w.octet_string(n, "NAS-PDU")?;
            }
            encode_snssai(w, &it.s_nssai)?;
            w.octet_string(&it.transfer, "pDUSessionResourceSetupRequestTransfer")?;
        }
        Ok(())
    })
}

pub fn parse_pdu_session_resource_setup_request(
    pdu: &Pdu,
) -> CodecResult<(u64, u64, Vec<SetupItem>)> {
    let amf = decode_amf_ue_ngap_id(pdu.require(IE_AMF_UE_NGAP_ID)?)?;
    let ran = decode_ran_ue_ngap_id(pdu.require(IE_RAN_UE_NGAP_ID)?)?;
    let items = decode_setup_items(
        pdu.require(IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ)?,
        "PDUSessionResourceSetupListSUReq",
    )?;
    Ok((amf, ran, items))
}

/// A setup outcome list: `(PDU session ID, transfer octets)` per item. Used for the SURes and
/// CxtRes lists (response transfers) and the failed-to-setup lists (unsuccessful transfers),
/// which share this shape.
fn encode_outcome_list(id: u16, items: &[(u8, Vec<u8>)]) -> EncodeResult<Ie> {
    encode_ie(id, Criticality::Ignore, |w| {
        w.size(items.len(), 1, 256, "PDU session outcome list")?;
        for (psi, transfer) in items {
            w.bit(false);
            w.bit(false);
            w.constrained(*psi as u64, 0, 255, "pDUSessionID")?;
            w.octet_string(transfer, "transfer")?;
        }
        Ok(())
    })
}

fn decode_outcome_list(ie: &Ie, budget: &mut Budget) -> CodecResult<Vec<(u8, Vec<u8>)>> {
    decode_ie(ie, |r| {
        let n = r.size(1, 256, "PDU session outcome list")?;
        if n > MAX_PDU_SESSIONS {
            return Err(AperError(format!("{n} PDU sessions exceeds {MAX_PDU_SESSIONS}")).into());
        }
        budget.take(n, "PDU session outcome list")?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let ext = r.extension_bit("outcome item")?;
            let has_ext = r.bit("outcome item")?;
            let psi = r.constrained(0, 255, "pDUSessionID")? as u8;
            let t = r.octet_string(MAX_PDU_LEN, "transfer")?.to_vec();
            opt_extension_container(r, has_ext, budget)?;
            finish_sequence(r, ext)?;
            out.push((psi, t));
        }
        Ok(out)
    })
}

/// `PDUSessionResourceSetupUnsuccessfulTransfer ::= SEQUENCE { cause, criticalityDiagnostics
/// OPTIONAL, iE-Extensions OPTIONAL, ... }` with only the cause.
pub fn encode_unsuccessful_transfer(cause: &Cause) -> EncodeResult<Vec<u8>> {
    let mut w = Writer::new();
    w.bit(false);
    w.bit(false);
    w.bit(false);
    cause.encode(&mut w)?;
    Ok(w.finish())
}

pub fn decode_unsuccessful_transfer(bytes: &[u8]) -> CodecResult<Cause> {
    let mut r = Reader::new(bytes);
    r.extension_bit("PDUSessionResourceSetupUnsuccessfulTransfer")?;
    r.bit("criticalityDiagnostics")?;
    r.bit("iE-Extensions")?;
    Cause::decode(&mut r)
}

/// What a gNB answered to PDU session setup: the established sessions with their downlink
/// tunnels, and the failed ones with their causes.
#[derive(Debug, Clone, Default)]
pub struct SetupOutcome {
    pub amf_ue_ngap_id: u64,
    pub ran_ue_ngap_id: u64,
    pub established: Vec<(u8, SetupResponseTransfer)>,
    pub failed: Vec<(u8, Cause)>,
}

fn parse_setup_outcome(pdu: &Pdu, ok_id: u16, failed_id: u16) -> CodecResult<SetupOutcome> {
    let mut budget = Budget::default();
    let mut out = SetupOutcome {
        amf_ue_ngap_id: decode_amf_ue_ngap_id(pdu.require(IE_AMF_UE_NGAP_ID)?)?,
        ran_ue_ngap_id: decode_ran_ue_ngap_id(pdu.require(IE_RAN_UE_NGAP_ID)?)?,
        ..Default::default()
    };
    if let Some(ie) = pdu.ie(ok_id) {
        for (psi, t) in decode_outcome_list(ie, &mut budget)? {
            out.established
                .push((psi, decode_setup_response_transfer(&t)?));
        }
    }
    if let Some(ie) = pdu.ie(failed_id) {
        for (psi, t) in decode_outcome_list(ie, &mut budget)? {
            out.failed.push((psi, decode_unsuccessful_transfer(&t)?));
        }
    }
    Ok(out)
}

pub fn parse_pdu_session_resource_setup_response(pdu: &Pdu) -> CodecResult<SetupOutcome> {
    parse_setup_outcome(
        pdu,
        IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES,
        IE_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_SU_RES,
    )
}

pub fn parse_initial_context_setup_response(pdu: &Pdu) -> CodecResult<SetupOutcome> {
    parse_setup_outcome(
        pdu,
        IE_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_RES,
        IE_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_CXT_RES,
    )
}

/// PDU Session Resource Setup Response (gNB side).
pub fn pdu_session_resource_setup_response(
    amf: u64,
    ran: u64,
    established: &[(u8, SetupResponseTransfer)],
    failed: &[(u8, Cause)],
) -> EncodeResult<Vec<u8>> {
    let mut ies = vec![
        amf_ue_ngap_id_ie(amf, Criticality::Ignore)?,
        ran_ue_ngap_id_ie(ran, Criticality::Ignore)?,
    ];
    if !established.is_empty() {
        let items = established
            .iter()
            .map(|(p, t)| Ok((*p, encode_setup_response_transfer(t)?)))
            .collect::<EncodeResult<Vec<_>>>()?;
        ies.push(encode_outcome_list(
            IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES,
            &items,
        )?);
    }
    if !failed.is_empty() {
        let items = failed
            .iter()
            .map(|(p, c)| Ok((*p, encode_unsuccessful_transfer(c)?)))
            .collect::<EncodeResult<Vec<_>>>()?;
        ies.push(encode_outcome_list(
            IE_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_SU_RES,
            &items,
        )?);
    }
    build(
        PduKind::Successful,
        PROC_PDU_SESSION_RESOURCE_SETUP,
        Criticality::Reject,
        ies,
    )
}

/// What an Initial Context Setup Request carries that NetGet builds or a gNB reads.
#[derive(Debug, Clone)]
pub struct InitialContext {
    pub amf_ue_ngap_id: u64,
    pub ran_ue_ngap_id: u64,
    pub guami: Value,
    pub allowed_nssai: Vec<Value>,
    pub ue_security_capabilities: [u16; 4],
    pub security_key: [u8; 32],
    pub ue_ambr: Option<(u64, u64)>,
    pub nas: Option<Vec<u8>>,
    /// PDU sessions set up with the context (`PDUSessionResourceSetupListCxtReq`): an AMF that
    /// sent the Registration Accept in a Downlink NAS Transport sets the first session up here.
    pub pdu_sessions: Vec<SetupItem>,
}

/// Initial Context Setup Request (TS 38.413 9.2.2.1), IEs in the order the ASN.1 lists them.
pub fn initial_context_setup_request(c: &InitialContext) -> EncodeResult<Vec<u8>> {
    let mut ies = vec![
        amf_ue_ngap_id_ie(c.amf_ue_ngap_id, Criticality::Reject)?,
        ran_ue_ngap_id_ie(c.ran_ue_ngap_id, Criticality::Reject)?,
    ];
    if let Some((dl, ul)) = c.ue_ambr {
        ies.push(ue_ambr_ie(dl, ul)?);
    }
    ies.push(guami_ie(&c.guami)?);
    if !c.pdu_sessions.is_empty() {
        ies.push(encode_setup_items(
            IE_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_REQ,
            &c.pdu_sessions,
        )?);
    }
    ies.push(allowed_nssai_ie(&c.allowed_nssai)?);
    ies.push(ue_security_capabilities_ie(c.ue_security_capabilities)?);
    ies.push(security_key_ie(&c.security_key)?);
    if let Some(n) = &c.nas {
        ies.push(nas_pdu_ie_with(n, Criticality::Ignore)?);
    }
    build(
        PduKind::Initiating,
        PROC_INITIAL_CONTEXT_SETUP,
        Criticality::Reject,
        ies,
    )
}

pub fn parse_initial_context_setup_request(pdu: &Pdu) -> CodecResult<InitialContext> {
    let mut budget = Budget::default();
    Ok(InitialContext {
        amf_ue_ngap_id: decode_amf_ue_ngap_id(pdu.require(IE_AMF_UE_NGAP_ID)?)?,
        ran_ue_ngap_id: decode_ran_ue_ngap_id(pdu.require(IE_RAN_UE_NGAP_ID)?)?,
        guami: decode_guami_ie(pdu.require(IE_GUAMI)?)?,
        allowed_nssai: decode_allowed_nssai(pdu.require(IE_ALLOWED_NSSAI)?)?,
        ue_security_capabilities: decode_ue_security_capabilities(
            pdu.require(IE_UE_SECURITY_CAPABILITIES)?,
        )?,
        security_key: decode_security_key(pdu.require(IE_SECURITY_KEY)?)?,
        ue_ambr: match pdu.ie(IE_UE_AGGREGATE_MAXIMUM_BIT_RATE) {
            Some(ie) => Some(decode_ie(ie, |r| decode_ambr(r, &mut budget))?),
            None => None,
        },
        nas: match pdu.ie(IE_NAS_PDU) {
            Some(ie) => Some(decode_nas_pdu(ie)?),
            None => None,
        },
        pdu_sessions: match pdu.ie(IE_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_REQ) {
            Some(ie) => decode_setup_items(ie, "PDUSessionResourceSetupListCxtReq")?,
            None => Vec::new(),
        },
    })
}

/// Initial Context Setup Response (gNB side), with the outcome of any PDU sessions the request
/// set up.
pub fn initial_context_setup_response(
    amf: u64,
    ran: u64,
    established: &[(u8, SetupResponseTransfer)],
    failed: &[(u8, Cause)],
) -> EncodeResult<Vec<u8>> {
    let mut ies = vec![
        amf_ue_ngap_id_ie(amf, Criticality::Ignore)?,
        ran_ue_ngap_id_ie(ran, Criticality::Ignore)?,
    ];
    if !established.is_empty() {
        let items = established
            .iter()
            .map(|(p, t)| Ok((*p, encode_setup_response_transfer(t)?)))
            .collect::<EncodeResult<Vec<_>>>()?;
        ies.push(encode_outcome_list(
            IE_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_RES,
            &items,
        )?);
    }
    if !failed.is_empty() {
        let items = failed
            .iter()
            .map(|(p, c)| Ok((*p, encode_unsuccessful_transfer(c)?)))
            .collect::<EncodeResult<Vec<_>>>()?;
        ies.push(encode_outcome_list(
            IE_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_CXT_RES,
            &items,
        )?);
    }
    build(
        PduKind::Successful,
        PROC_INITIAL_CONTEXT_SETUP,
        Criticality::Reject,
        ies,
    )
}

/// UE Context Release Request from a gNB (TS 38.413 9.2.2.4): the UE's ids and the cause.
pub fn parse_ue_context_release_request(pdu: &Pdu) -> CodecResult<(u64, u64, Option<Cause>)> {
    Ok((
        decode_amf_ue_ngap_id(pdu.require(IE_AMF_UE_NGAP_ID)?)?,
        decode_ran_ue_ngap_id(pdu.require(IE_RAN_UE_NGAP_ID)?)?,
        match pdu.ie(IE_CAUSE) {
            Some(ie) => Some(decode_cause(ie)?),
            None => None,
        },
    ))
}

pub fn ue_context_release_request(amf: u64, ran: u64, cause: &Cause) -> EncodeResult<Vec<u8>> {
    build(
        PduKind::Initiating,
        PROC_UE_CONTEXT_RELEASE_REQUEST,
        Criticality::Ignore,
        vec![
            amf_ue_ngap_id_ie(amf, Criticality::Reject)?,
            ran_ue_ngap_id_ie(ran, Criticality::Reject)?,
            cause_ie(cause, Criticality::Ignore)?,
        ],
    )
}
