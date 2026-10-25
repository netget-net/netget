//! 5G NAS security, shared by the AMF and the gNB's UE: Milenage (TS 35.206), the 5G-AKA key
//! hierarchy (TS 33.501 Annex A), the NAS integrity and ciphering algorithms NIA2/NEA2 (TS 33.501
//! Annex D, which reuses 128-EIA2/128-EEA2 of TS 33.401 Annex B) and NIA0/NEA0, and the
//! security-protected NAS message framing with its COUNT handling (TS 24.501 sections 4.4.3 and
//! 9.1.1).
//!
//! Nothing here sees the model. Keys are inputs and outputs of functions; they are never
//! formatted, logged or put in an event. The vectors these functions are checked against are in
//! `tests/server/ngap/security_test.rs`: Milenage against TS 35.208 test sets, NIA2/NEA2 against
//! TS 33.401 Annex C, the KDF's HMAC-SHA-256 against RFC 4231, and the 5G derivations against the
//! two independent implementations the pair tests talk to (UERANSIM's UE verifies every MAC this
//! module computes and the AUTN; Open5GS's AMF hands the gNB a K_gNB the UE side recomputes).
//!
//! NIA1/NEA1 (SNOW 3G, [`super::snow3g`]) and NIA3/NEA3 (ZUC, [`super::zuc`]) live in their own
//! modules, checked against every published SAGE and TS 33.401 test set in
//! `tests/server/ngap/cipher_vectors_test.rs`; a [`NasContext`] protects and verifies with
//! whichever algorithms it names. Which ones an AMF selects is its policy, in `amf.rs`.

use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use aes::Aes128;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub type Key128 = [u8; 16];
pub type Key256 = [u8; 32];

fn aes(key: &Key128, block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(&(*key).into());
    let mut b = (*block).into();
    cipher.encrypt_block(&mut b);
    b.into()
}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Rotate a 128-bit value left by `bytes` octets (Milenage's `rot`, whose r values are all
/// multiples of eight).
fn rot(x: &[u8; 16], bytes: usize) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = x[(i + bytes) % 16];
    }
    out
}

/// Milenage (TS 35.206) for one subscriber: K and OPc.
#[derive(Clone)]
pub struct Milenage {
    k: Key128,
    opc: Key128,
}

/// What f2-f5 produce for one RAND.
pub struct MilenageOut {
    pub res: [u8; 8],
    pub ck: Key128,
    pub ik: Key128,
    pub ak: [u8; 6],
}

impl Milenage {
    pub fn with_opc(k: Key128, opc: Key128) -> Self {
        Milenage { k, opc }
    }

    /// OPc = E_K(OP) xor OP (TS 35.206 section 4.1).
    pub fn with_op(k: Key128, op: Key128) -> Self {
        let opc = xor16(&aes(&k, &op), &op);
        Milenage { k, opc }
    }

    pub fn opc(&self) -> Key128 {
        self.opc
    }

    fn temp(&self, rand: &[u8; 16]) -> [u8; 16] {
        aes(&self.k, &xor16(rand, &self.opc))
    }

    /// f1 and f1*: `(MAC-A, MAC-S)`.
    pub fn f1(&self, rand: &[u8; 16], sqn: &[u8; 6], amf: &[u8; 2]) -> ([u8; 8], [u8; 8]) {
        let temp = self.temp(rand);
        let mut in1 = [0u8; 16];
        in1[0..6].copy_from_slice(sqn);
        in1[6..8].copy_from_slice(amf);
        in1[8..14].copy_from_slice(sqn);
        in1[14..16].copy_from_slice(amf);
        // OUT1 = E_K(TEMP xor rot(IN1 xor OPc, r1) xor c1) xor OPc, r1 = 64, c1 = 0.
        let x = xor16(&temp, &rot(&xor16(&in1, &self.opc), 8));
        let out1 = xor16(&aes(&self.k, &x), &self.opc);
        let mut mac_a = [0u8; 8];
        let mut mac_s = [0u8; 8];
        mac_a.copy_from_slice(&out1[0..8]);
        mac_s.copy_from_slice(&out1[8..16]);
        (mac_a, mac_s)
    }

    /// OUTn = E_K(rot(TEMP xor OPc, rn) xor cn) xor OPc.
    fn out(&self, temp: &[u8; 16], rot_bytes: usize, c: u8) -> [u8; 16] {
        let mut x = rot(&xor16(temp, &self.opc), rot_bytes);
        x[15] ^= c;
        xor16(&aes(&self.k, &x), &self.opc)
    }

    /// f2 (RES), f3 (CK), f4 (IK) and f5 (AK).
    pub fn f2345(&self, rand: &[u8; 16]) -> MilenageOut {
        let temp = self.temp(rand);
        let out2 = self.out(&temp, 0, 1);
        let out3 = self.out(&temp, 4, 2);
        let out4 = self.out(&temp, 8, 4);
        let mut res = [0u8; 8];
        res.copy_from_slice(&out2[8..16]);
        let mut ak = [0u8; 6];
        ak.copy_from_slice(&out2[0..6]);
        MilenageOut {
            res,
            ck: out3,
            ik: out4,
            ak,
        }
    }

    /// f5*: the anonymity key that conceals SQN_MS in AUTS.
    pub fn f5_star(&self, rand: &[u8; 16]) -> [u8; 6] {
        let temp = self.temp(rand);
        let out5 = self.out(&temp, 12, 8);
        let mut ak = [0u8; 6];
        ak.copy_from_slice(&out5[0..6]);
        ak
    }
}

/// The generic KDF of TS 33.220 Annex B.2: HMAC-SHA-256 over FC || P0 || L0 || P1 || L1 ….
pub fn kdf(key: &[u8], fc: u8, params: &[&[u8]]) -> Key256 {
    let mut s = vec![fc];
    for p in params {
        s.extend_from_slice(p);
        s.extend_from_slice(&(p.len() as u16).to_be_bytes());
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(&s);
    mac.finalize().into_bytes().into()
}

/// The serving network name (TS 24.501 section 9.12.1): `5G:mncXXX.mccYYY.3gppnetwork.org`, the
/// MNC padded to three digits.
pub fn serving_network_name(mcc: &str, mnc: &str) -> String {
    format!("5G:mnc{mnc:0>3}.mcc{mcc}.3gppnetwork.org")
}

pub fn sqn_bytes(sqn: u64) -> [u8; 6] {
    let b = sqn.to_be_bytes();
    [b[2], b[3], b[4], b[5], b[6], b[7]]
}

pub fn sqn_value(b: &[u8; 6]) -> u64 {
    b.iter().fold(0u64, |acc, x| (acc << 8) | *x as u64)
}

pub const MAX_SQN: u64 = (1 << 48) - 1;

/// One 5G-AKA authentication vector as the home network holds it (TS 33.501 section 6.1.3.2).
#[derive(Clone)]
pub struct AkaVector {
    pub rand: [u8; 16],
    pub autn: [u8; 16],
    pub xres_star: [u8; 16],
    pub hxres_star: [u8; 16],
    pub k_ausf: Key256,
    pub sqn: u64,
}

fn res_star(ck: &Key128, ik: &Key128, snn: &str, rand: &[u8; 16], res: &[u8]) -> [u8; 16] {
    let key = [&ck[..], &ik[..]].concat();
    // Annex A.4: the 128 least significant bits of the KDF output.
    let out = kdf(&key, 0x6B, &[snn.as_bytes(), rand, res]);
    let mut r = [0u8; 16];
    r.copy_from_slice(&out[16..32]);
    r
}

fn k_ausf(ck: &Key128, ik: &Key128, snn: &str, sqn_xor_ak: &[u8; 6]) -> Key256 {
    let key = [&ck[..], &ik[..]].concat();
    kdf(&key, 0x6A, &[snn.as_bytes(), sqn_xor_ak])
}

/// HXRES* / HRES* (Annex A.5): the 128 least significant bits of SHA-256(RAND || XRES*).
pub fn hres_star(rand: &[u8; 16], res_star: &[u8; 16]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(rand);
    h.update(res_star);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[16..32]);
    out
}

/// Build a vector for `sqn` (TS 33.501 section 6.1.3.2 and Annex A.2, A.4, A.5).
pub fn generate_vector(
    m: &Milenage,
    rand: [u8; 16],
    sqn: u64,
    amf: [u8; 2],
    snn: &str,
) -> AkaVector {
    let sqn_b = sqn_bytes(sqn);
    let (mac_a, _) = m.f1(&rand, &sqn_b, &amf);
    let o = m.f2345(&rand);
    let mut conc = [0u8; 6];
    for i in 0..6 {
        conc[i] = sqn_b[i] ^ o.ak[i];
    }
    let mut autn = [0u8; 16];
    autn[0..6].copy_from_slice(&conc);
    autn[6..8].copy_from_slice(&amf);
    autn[8..16].copy_from_slice(&mac_a);
    let xres_star = res_star(&o.ck, &o.ik, snn, &rand, &o.res);
    AkaVector {
        rand,
        autn,
        xres_star,
        hxres_star: hres_star(&rand, &xres_star),
        k_ausf: k_ausf(&o.ck, &o.ik, snn, &conc),
        sqn,
    }
}

/// SQN_MS recovered from an AUTS (TS 33.102 section 6.3.5), or `None` when MAC-S does not verify.
/// The resynchronisation MAC is computed with the dummy AMF 0x0000.
pub fn resync_sqn(m: &Milenage, rand: &[u8; 16], auts: &[u8]) -> Option<u64> {
    if auts.len() != 14 {
        return None;
    }
    let ak_star = m.f5_star(rand);
    let mut sqn_ms = [0u8; 6];
    for i in 0..6 {
        sqn_ms[i] = auts[i] ^ ak_star[i];
    }
    let (_, mac_s) = m.f1(rand, &sqn_ms, &[0, 0]);
    if !constant_time_eq(&mac_s, &auts[6..14]) {
        return None;
    }
    Some(sqn_value(&sqn_ms))
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// What a UE concludes about an AUTN (TS 33.102 section 6.3.3, TS 33.501 section 6.1.3.2.1).
pub enum AutnOutcome {
    /// Accepted: RES*, K_AUSF and the SQN now held by the USIM.
    Ok {
        res_star: [u8; 16],
        k_ausf: Key256,
        sqn: u64,
    },
    MacFailure,
    /// The SQN is not fresh; AUTS for the network to resynchronise from.
    SynchFailure {
        auts: [u8; 14],
    },
    /// The AMF field's separation bit is 0: not a 5G authentication.
    SeparationBit,
}

/// The UE side of 5G-AKA. `sqn_ms` is the highest SQN the USIM has accepted; a fresh SQN must be
/// above it and within `delta` of it.
pub fn ue_check_autn(
    m: &Milenage,
    rand: &[u8; 16],
    autn: &[u8; 16],
    snn: &str,
    sqn_ms: u64,
    delta: u64,
) -> AutnOutcome {
    let amf = [autn[6], autn[7]];
    if amf[0] & 0x80 == 0 {
        return AutnOutcome::SeparationBit;
    }
    let o = m.f2345(rand);
    let mut sqn_b = [0u8; 6];
    for i in 0..6 {
        sqn_b[i] = autn[i] ^ o.ak[i];
    }
    let (mac_a, _) = m.f1(rand, &sqn_b, &amf);
    if !constant_time_eq(&mac_a, &autn[8..16]) {
        return AutnOutcome::MacFailure;
    }
    let sqn = sqn_value(&sqn_b);
    if sqn <= sqn_ms || sqn - sqn_ms > delta {
        let ak_star = m.f5_star(rand);
        let ms = sqn_bytes(sqn_ms);
        let (_, mac_s) = m.f1(rand, &ms, &[0, 0]);
        let mut auts = [0u8; 14];
        for i in 0..6 {
            auts[i] = ms[i] ^ ak_star[i];
        }
        auts[6..14].copy_from_slice(&mac_s);
        return AutnOutcome::SynchFailure { auts };
    }
    let mut conc = [0u8; 6];
    conc.copy_from_slice(&autn[0..6]);
    AutnOutcome::Ok {
        res_star: res_star(&o.ck, &o.ik, snn, rand, &o.res),
        k_ausf: k_ausf(&o.ck, &o.ik, snn, &conc),
        sqn,
    }
}

/// K_SEAF (Annex A.6).
pub fn k_seaf(k_ausf: &Key256, snn: &str) -> Key256 {
    kdf(k_ausf, 0x6C, &[snn.as_bytes()])
}

/// K_AMF (Annex A.7). `supi` is the IMSI's digits.
pub fn k_amf(k_seaf: &Key256, supi: &str, abba: &[u8]) -> Key256 {
    kdf(k_seaf, 0x6D, &[supi.as_bytes(), abba])
}

/// K_NASenc and K_NASint (Annex A.8): the 128 least significant bits of each KDF output.
pub fn nas_keys(k_amf: &Key256, ea: u8, ia: u8) -> (Key128, Key128) {
    let enc = kdf(k_amf, 0x69, &[&[0x01], &[ea]]);
    let int = kdf(k_amf, 0x69, &[&[0x02], &[ia]]);
    let mut e = [0u8; 16];
    let mut i = [0u8; 16];
    e.copy_from_slice(&enc[16..32]);
    i.copy_from_slice(&int[16..32]);
    (e, i)
}

/// Access type distinguisher for 3GPP access (Annex A.9, Table A.9-1).
pub const ACCESS_3GPP: u8 = 0x01;

/// K_gNB (Annex A.9) from K_AMF and an uplink NAS COUNT.
pub fn k_gnb(k_amf: &Key256, uplink_count: u32, access: u8) -> Key256 {
    kdf(k_amf, 0x6E, &[&uplink_count.to_be_bytes(), &[access]])
}

// ============================================================================
// NIA2 / NEA2
// ============================================================================

/// The NAS BEARER for 3GPP access. TS 33.501 section 6.4.3 makes it the NAS connection
/// identifier; UERANSIM, Open5GS and free5GC all put 1 here for 3GPP access (2 for non-3GPP),
/// and a MAC that disagrees with them is a MAC no UE accepts.
pub const BEARER_3GPP: u8 = 1;
pub const UPLINK: u8 = 0;
pub const DOWNLINK: u8 = 1;

fn iv_prefix(count: u32, bearer: u8, direction: u8) -> [u8; 8] {
    let c = count.to_be_bytes();
    [
        c[0],
        c[1],
        c[2],
        c[3],
        (bearer << 3) | (direction << 2),
        0,
        0,
        0,
    ]
}

/// 128-NIA2 (TS 33.401 Annex B.2.3): AES-CMAC over COUNT || BEARER || DIRECTION || 0^26 ||
/// MESSAGE, truncated to 32 bits.
pub fn nia2(key: &Key128, count: u32, bearer: u8, direction: u8, message: &[u8]) -> [u8; 4] {
    let mut m = iv_prefix(count, bearer, direction).to_vec();
    m.extend_from_slice(message);
    let full = crate::server::lorawan::mac::aes_cmac(key, &m);
    [full[0], full[1], full[2], full[3]]
}

/// 128-NEA2 (TS 33.401 Annex B.1.3): AES-128 in counter mode from COUNT || BEARER || DIRECTION ||
/// 0^90. Its own inverse.
pub fn nea2(key: &Key128, count: u32, bearer: u8, direction: u8, data: &mut [u8]) {
    let mut iv = [0u8; 16];
    iv[0..8].copy_from_slice(&iv_prefix(count, bearer, direction));
    let mut c = ctr::Ctr128BE::<Aes128>::new(&(*key).into(), &iv.into());
    c.apply_keystream(data);
}

/// NAS integrity algorithms NetGet implements, by their 4-bit codes (TS 24.501 9.11.3.34).
pub const NIA0: u8 = 0;
pub const NIA1: u8 = 1;
pub const NIA2: u8 = 2;
pub const NIA3: u8 = 3;
/// NAS ciphering algorithms NetGet implements.
pub const NEA0: u8 = 0;
pub const NEA1: u8 = 1;
pub const NEA2: u8 = 2;
pub const NEA3: u8 = 3;

pub fn integrity_name(ia: u8) -> &'static str {
    match ia {
        0 => "NIA0",
        1 => "NIA1",
        2 => "NIA2",
        3 => "NIA3",
        _ => "NIA-reserved",
    }
}

pub fn ciphering_name(ea: u8) -> &'static str {
    match ea {
        0 => "NEA0",
        1 => "NEA1",
        2 => "NEA2",
        3 => "NEA3",
        _ => "NEA-reserved",
    }
}

fn mac(ia: u8, key: &Key128, count: u32, direction: u8, data: &[u8]) -> [u8; 4] {
    match ia {
        NIA1 => super::snow3g::nia1(key, count, BEARER_3GPP, direction, data),
        NIA2 => nia2(key, count, BEARER_3GPP, direction, data),
        NIA3 => super::zuc::nia3(key, count, BEARER_3GPP, direction, data),
        _ => [0; 4],
    }
}

fn cipher(ea: u8, key: &Key128, count: u32, direction: u8, data: &mut [u8]) {
    match ea {
        NEA1 => super::snow3g::nea1(key, count, BEARER_3GPP, direction, data),
        NEA2 => nea2(key, count, BEARER_3GPP, direction, data),
        NEA3 => super::zuc::nea3(key, count, BEARER_3GPP, direction, data),
        _ => {}
    }
}

// ============================================================================
// Security-protected NAS messages (TS 24.501 section 9.1.1, 4.4.3)
// ============================================================================

pub const SHT_PLAIN: u8 = 0;
pub const SHT_INTEGRITY: u8 = 1;
pub const SHT_INTEGRITY_CIPHERED: u8 = 2;
pub const SHT_INTEGRITY_NEW_CONTEXT: u8 = 3;
pub const SHT_INTEGRITY_CIPHERED_NEW_CONTEXT: u8 = 4;

/// Why a protected NAS message was not accepted. The tag is the log's `decision=` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnprotectError {
    Malformed(&'static str),
    /// The MAC did not verify against the estimated COUNT.
    Mac {
        count: u32,
    },
    /// The COUNT this message would carry was already accepted once.
    Replay {
        count: u32,
    },
    /// A header type this direction may not use, or no security context to check it with.
    HeaderType(u8),
}

impl UnprotectError {
    pub fn decision(&self) -> &'static str {
        match self {
            UnprotectError::Malformed(_) => "nas_malformed",
            UnprotectError::Mac { .. } => "nas_integrity_failure",
            UnprotectError::Replay { .. } => "nas_count_replay",
            UnprotectError::HeaderType(_) => "nas_header_refused",
        }
    }
}

impl std::fmt::Display for UnprotectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnprotectError::Malformed(w) => write!(f, "malformed protected NAS message: {w}"),
            UnprotectError::Mac { count } => write!(f, "NAS MAC does not verify at COUNT {count}"),
            UnprotectError::Replay { count } => {
                write!(f, "NAS COUNT {count} was already accepted (replay)")
            }
            UnprotectError::HeaderType(t) => write!(f, "security header type {t} refused here"),
        }
    }
}

/// One direction's NAS COUNT (TS 24.501 section 4.4.3.1): 16 bits of overflow and the 8-bit
/// sequence number that crosses the wire.
#[derive(Debug, Clone, Default)]
pub struct Counts {
    /// The next COUNT this side sends.
    pub tx: u32,
    /// The highest COUNT this side has accepted, if any.
    pub rx_last: Option<u32>,
}

/// The 24-bit NAS COUNT space.
const COUNT_MASK: u32 = 0x00FF_FFFF;

/// Estimate the full COUNT of a received sequence number, given the last accepted one.
pub fn estimate_count(last: Option<u32>, sqn: u8) -> u32 {
    match last {
        None => sqn as u32,
        Some(l) => {
            let mut overflow = l >> 8;
            if (sqn as u32) < (l & 0xFF) {
                overflow += 1;
            }
            ((overflow << 8) | sqn as u32) & COUNT_MASK
        }
    }
}

/// A current 5G NAS security context (TS 33.501 section 6.3).
#[derive(Clone)]
pub struct NasContext {
    pub ngksi: u8,
    pub k_amf: Key256,
    pub ia: u8,
    pub ea: u8,
    k_int: Key128,
    k_enc: Key128,
    pub counts: Counts,
    /// Which direction this side sends in: [`DOWNLINK`] for the AMF, [`UPLINK`] for a UE.
    pub tx_direction: u8,
}

impl NasContext {
    pub fn new(ngksi: u8, k_amf: Key256, ia: u8, ea: u8, tx_direction: u8) -> Self {
        let (k_enc, k_int) = nas_keys(&k_amf, ea, ia);
        NasContext {
            ngksi,
            k_amf,
            ia,
            ea,
            k_int,
            k_enc,
            counts: Counts::default(),
            tx_direction,
        }
    }

    fn rx_direction(&self) -> u8 {
        1 - self.tx_direction
    }

    /// Protect a plain 5GMM message with header type `sht` at the next COUNT.
    pub fn protect(&mut self, plain: &[u8], sht: u8) -> Vec<u8> {
        let count = self.counts.tx;
        let mut body = plain.to_vec();
        if sht == SHT_INTEGRITY_CIPHERED || sht == SHT_INTEGRITY_CIPHERED_NEW_CONTEXT {
            cipher(self.ea, &self.k_enc, count, self.tx_direction, &mut body);
        }
        let sqn = (count & 0xFF) as u8;
        let mut covered = vec![sqn];
        covered.extend_from_slice(&body);
        let m = mac(self.ia, &self.k_int, count, self.tx_direction, &covered);
        let mut out = vec![0x7e, sht];
        out.extend_from_slice(&m);
        out.extend_from_slice(&covered);
        self.counts.tx = (count + 1) & COUNT_MASK;
        out
    }

    /// Verify and, when ciphered, decipher a protected message. Accepts header types 1-4; the
    /// caller decides which it allows where. On success the COUNT is recorded as accepted.
    pub fn unprotect(&mut self, msg: &[u8]) -> Result<(Vec<u8>, u32, u8), UnprotectError> {
        if msg.len() < 8 {
            return Err(UnprotectError::Malformed("shorter than a security header"));
        }
        if msg[0] != 0x7e {
            return Err(UnprotectError::Malformed("not 5GMM"));
        }
        let sht = msg[1] & 0x0F;
        if !(SHT_INTEGRITY..=SHT_INTEGRITY_CIPHERED_NEW_CONTEXT).contains(&sht) {
            return Err(UnprotectError::HeaderType(sht));
        }
        let received_mac = [msg[2], msg[3], msg[4], msg[5]];
        let sqn = msg[6];
        let count = estimate_count(self.counts.rx_last, sqn);
        if let Some(last) = self.counts.rx_last {
            if count <= last {
                return Err(UnprotectError::Replay { count });
            }
        }
        let expected = mac(self.ia, &self.k_int, count, self.rx_direction(), &msg[6..]);
        if self.ia != NIA0 && !constant_time_eq(&expected, &received_mac) {
            return Err(UnprotectError::Mac { count });
        }
        let mut body = msg[7..].to_vec();
        if sht == SHT_INTEGRITY_CIPHERED || sht == SHT_INTEGRITY_CIPHERED_NEW_CONTEXT {
            cipher(self.ea, &self.k_enc, count, self.rx_direction(), &mut body);
        }
        if body.is_empty() {
            return Err(UnprotectError::Malformed("no message inside the header"));
        }
        self.counts.rx_last = Some(count);
        Ok((body, count, sht))
    }

    /// Cipher or decipher `data` with this context's algorithm at an explicit COUNT and
    /// direction — the NAS message container of an initial NAS message, which TS 24.501 4.4.6
    /// ciphers at the COUNT of the integrity-protected message that carries it.
    pub fn cipher_at(&self, count: u32, direction: u8, data: &mut [u8]) {
        cipher(self.ea, &self.k_enc, count, direction, data);
    }

    /// The uplink NAS COUNT of the latest accepted uplink message (the AMF's view), used for
    /// K_gNB.
    pub fn last_uplink_count(&self) -> u32 {
        if self.tx_direction == DOWNLINK {
            self.counts.rx_last.unwrap_or(0)
        } else {
            self.counts.tx.saturating_sub(1)
        }
    }

    pub fn k_gnb(&self) -> Key256 {
        k_gnb(&self.k_amf, self.last_uplink_count(), ACCESS_3GPP)
    }
}

/// Parse a hex key of exactly `N` octets, naming the field (never the value) when it is wrong.
pub fn hex_key<const N: usize>(field: &str, s: &str) -> Result<[u8; N], String> {
    let raw = hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|_| format!("{field} must be hex"))?;
    raw.try_into()
        .map_err(|_| format!("{field} must be {N} octets ({} hex digits)", N * 2))
}
