//! SNOW 3G and the 3GPP algorithms built on it: UEA2/UIA2 and their LTE/5G forms 128-EEA1/128-EIA1,
//! which TS 33.501 Annex D.2/D.3 reuses as 128-NEA1/128-NIA1.
//!
//! Written here from the ETSI/SAGE specifications rather than taken from a crate. On crates.io in
//! October 2026 SNOW 3G exists only inside `oxirush-security` 0.3 (Apache-2.0, weeks old, a single
//! maintainer, `SECURITY.md` saying it has had no security audit, SIMD back-ends) and the
//! catch-all `cryptography-rs`; neither is audited, and this module is small enough to check
//! line by line against the documents it follows:
//!
//! - "Specification of the 3GPP Confidentiality and Integrity Algorithms UEA2 & UIA2",
//!   Document 2: SNOW 3G Specification, v1.1 — the cipher ([`Snow3g`]); the S-boxes `SR` and `SQ`
//!   are Tables 1 and 2 of its section 5, and `MULα`/`DIVα` are computed from their definitions in
//!   sections 3.4.2/3.4.3 (`MULxPOW` with `0xA9`) rather than copied as tables.
//! - Document 1: UEA2 and UIA2 Specification, v2.1 — the IVs (sections 3.4 and 4.4) and UIA2's
//!   polynomial evaluation in GF(2^64) (section 4.5).
//! - TS 33.401 Annex B.1.2 (128-EEA1 is UEA2 with BEARER and DIRECTION as given) and B.2.2
//!   (128-EIA1 is UIA2 with FRESH replaced by BEARER || 0^27).
//!
//! The vectors are in `tests/server/ngap/cipher_vectors_test.rs`: SAGE Document 3 (implementors'
//! test data) and Document 4 (design conformance), and TS 33.401 Annex C.4.
//!
//! The S-box lookups index by secret-dependent bytes, as every table implementation of SNOW 3G
//! does; nothing here is hardened against cache-timing observers on the same machine.
//!
//! Bit lengths: every function has a `_bits` form taking LENGTH in bits, as the specifications
//! do. A LENGTH longer than the buffer is clamped to the buffer, so no input can index outside
//! it. For ciphering, the bits of the last octet beyond LENGTH are left as they were: the
//! keystream is defined for LENGTH bits only (Document 3 prints the keystream of a partial last
//! octet with those bits zero).

/// The Rijndael S-box SR, SNOW 3G specification (Document 2) section 5.1, Table 1.
const SR: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

/// The S-box SQ, SNOW 3G specification (Document 2) section 5.2, Table 2.
const SQ: [u8; 256] = [
    0x25, 0x24, 0x73, 0x67, 0xD7, 0xAE, 0x5C, 0x30, 0xA4, 0xEE, 0x6E, 0xCB, 0x7D, 0xB5, 0x82, 0xDB,
    0xE4, 0x8E, 0x48, 0x49, 0x4F, 0x5D, 0x6A, 0x78, 0x70, 0x88, 0xE8, 0x5F, 0x5E, 0x84, 0x65, 0xE2,
    0xD8, 0xE9, 0xCC, 0xED, 0x40, 0x2F, 0x11, 0x28, 0x57, 0xD2, 0xAC, 0xE3, 0x4A, 0x15, 0x1B, 0xB9,
    0xB2, 0x80, 0x85, 0xA6, 0x2E, 0x02, 0x47, 0x29, 0x07, 0x4B, 0x0E, 0xC1, 0x51, 0xAA, 0x89, 0xD4,
    0xCA, 0x01, 0x46, 0xB3, 0xEF, 0xDD, 0x44, 0x7B, 0xC2, 0x7F, 0xBE, 0xC3, 0x9F, 0x20, 0x4C, 0x64,
    0x83, 0xA2, 0x68, 0x42, 0x13, 0xB4, 0x41, 0xCD, 0xBA, 0xC6, 0xBB, 0x6D, 0x4D, 0x71, 0x21, 0xF4,
    0x8D, 0xB0, 0xE5, 0x93, 0xFE, 0x8F, 0xE6, 0xCF, 0x43, 0x45, 0x31, 0x22, 0x37, 0x36, 0x96, 0xFA,
    0xBC, 0x0F, 0x08, 0x52, 0x1D, 0x55, 0x1A, 0xC5, 0x4E, 0x23, 0x69, 0x7A, 0x92, 0xFF, 0x5B, 0x5A,
    0xEB, 0x9A, 0x1C, 0xA9, 0xD1, 0x7E, 0x0D, 0xFC, 0x50, 0x8A, 0xB6, 0x62, 0xF5, 0x0A, 0xF8, 0xDC,
    0x03, 0x3C, 0x0C, 0x39, 0xF1, 0xB8, 0xF3, 0x3D, 0xF2, 0xD5, 0x97, 0x66, 0x81, 0x32, 0xA0, 0x00,
    0x06, 0xCE, 0xF6, 0xEA, 0xB7, 0x17, 0xF7, 0x8C, 0x79, 0xD6, 0xA7, 0xBF, 0x8B, 0x3F, 0x1F, 0x53,
    0x63, 0x75, 0x35, 0x2C, 0x60, 0xFD, 0x27, 0xD3, 0x94, 0xA5, 0x7C, 0xA1, 0x05, 0x58, 0x2D, 0xBD,
    0xD9, 0xC7, 0xAF, 0x6B, 0x54, 0x0B, 0xE0, 0x38, 0x04, 0xC8, 0x9D, 0xE7, 0x14, 0xB1, 0x87, 0x9C,
    0xDF, 0x6F, 0xF9, 0xDA, 0x2A, 0xC4, 0x59, 0x16, 0x74, 0x91, 0xAB, 0x26, 0x61, 0x76, 0x34, 0x2B,
    0xAD, 0x99, 0xFB, 0x72, 0xEC, 0x33, 0x12, 0xDE, 0x98, 0x3B, 0xC0, 0x9B, 0x3E, 0x18, 0x10, 0x3A,
    0x56, 0xE1, 0x77, 0xC9, 0x1E, 0x9E, 0x95, 0xA3, 0x90, 0x19, 0xA8, 0x6C, 0x09, 0xD0, 0xF0, 0x86,
];

/// `MULx(V, c)` of Document 2 section 3.1.1.
const fn mulx(v: u8, c: u8) -> u8 {
    if v & 0x80 != 0 {
        (v << 1) ^ c
    } else {
        v << 1
    }
}

/// `MULxPOW(V, i, c)` of Document 2 section 3.1.2.
const fn mulx_pow(v: u8, i: u32, c: u8) -> u8 {
    let mut r = v;
    let mut n = 0;
    while n < i {
        r = mulx(r, c);
        n += 1;
    }
    r
}

const fn be4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | d as u32
}

/// `MULα(c)` (section 3.4.2) for every byte.
const MUL_ALPHA: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut c = 0;
    while c < 256 {
        let b = c as u8;
        t[c] = be4(
            mulx_pow(b, 23, 0xA9),
            mulx_pow(b, 245, 0xA9),
            mulx_pow(b, 48, 0xA9),
            mulx_pow(b, 239, 0xA9),
        );
        c += 1;
    }
    t
};

/// `DIVα(c)` (section 3.4.3) for every byte.
const DIV_ALPHA: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut c = 0;
    while c < 256 {
        let b = c as u8;
        t[c] = be4(
            mulx_pow(b, 16, 0xA9),
            mulx_pow(b, 39, 0xA9),
            mulx_pow(b, 6, 0xA9),
            mulx_pow(b, 64, 0xA9),
        );
        c += 1;
    }
    t
};

/// The 32x32 S-boxes S1 (over `SR`, `c = 0x1B`) and S2 (over `SQ`, `c = 0x69`) of sections 3.3.1
/// and 3.3.2: the byte S-box followed by a MixColumn-style mix.
fn s_box(w: u32, sbox: &[u8; 256], c: u8) -> u32 {
    let [w0, w1, w2, w3] = w.to_be_bytes();
    let (s0, s1, s2, s3) = (
        sbox[w0 as usize],
        sbox[w1 as usize],
        sbox[w2 as usize],
        sbox[w3 as usize],
    );
    let r0 = mulx(s0, c) ^ s1 ^ s2 ^ mulx(s3, c) ^ s3;
    let r1 = mulx(s0, c) ^ s0 ^ mulx(s1, c) ^ s2 ^ s3;
    let r2 = s0 ^ mulx(s1, c) ^ s1 ^ mulx(s2, c) ^ s3;
    let r3 = s0 ^ s1 ^ mulx(s2, c) ^ s2 ^ mulx(s3, c);
    be4(r0, r1, r2, r3)
}

/// The SNOW 3G keystream generator (Document 2).
pub struct Snow3g {
    s: [u32; 16],
    r1: u32,
    r2: u32,
    r3: u32,
}

impl Snow3g {
    /// Initialise from the key words `k[0..4]` = k0..k3 and IV words `iv[0..4]` = IV0..IV3
    /// (section 4.1), and move to the first keystream word (section 4.2).
    pub fn new(k: [u32; 4], iv: [u32; 4]) -> Self {
        let one = 0xFFFF_FFFF;
        let s = [
            k[0] ^ one,
            k[1] ^ one,
            k[2] ^ one,
            k[3] ^ one,
            k[0],
            k[1],
            k[2],
            k[3],
            k[0] ^ one,
            k[1] ^ one ^ iv[3],
            k[2] ^ one ^ iv[2],
            k[3] ^ one,
            k[0] ^ iv[1],
            k[1],
            k[2],
            k[3] ^ iv[0],
        ];
        let mut g = Snow3g {
            s,
            r1: 0,
            r2: 0,
            r3: 0,
        };
        for _ in 0..32 {
            let f = g.clock_fsm();
            g.clock_lfsr(f);
        }
        g.clock_fsm();
        g.clock_lfsr(0);
        g
    }

    /// The key and IV as Document 3 section 3 prints them: k0 is the first four octets of `key`,
    /// IV0 the first four of `iv`.
    pub fn from_bytes(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Snow3g::new(words(key), words(iv))
    }

    /// Section 3.4.6.
    fn clock_fsm(&mut self) -> u32 {
        let f = self.s[15].wrapping_add(self.r1) ^ self.r2;
        let r = self.r2.wrapping_add(self.r3 ^ self.s[5]);
        self.r3 = s_box(self.r2, &SQ, 0x69);
        self.r2 = s_box(self.r1, &SR, 0x1B);
        self.r1 = r;
        f
    }

    /// Sections 3.4.4 (`f` is the FSM output) and 3.4.5 (`f` = 0).
    fn clock_lfsr(&mut self, f: u32) {
        let s0 = self.s[0];
        let s11 = self.s[11];
        let v = (s0 << 8)
            ^ MUL_ALPHA[(s0 >> 24) as usize]
            ^ self.s[2]
            ^ (s11 >> 8)
            ^ DIV_ALPHA[(s11 & 0xFF) as usize]
            ^ f;
        self.s.copy_within(1..16, 0);
        self.s[15] = v;
    }

    /// The next keystream word z_t (section 4.2).
    pub fn next_word(&mut self) -> u32 {
        let z = self.clock_fsm() ^ self.s[0];
        self.clock_lfsr(0);
        z
    }
}

fn words(b: &[u8; 16]) -> [u32; 4] {
    [
        be4(b[0], b[1], b[2], b[3]),
        be4(b[4], b[5], b[6], b[7]),
        be4(b[8], b[9], b[10], b[11]),
        be4(b[12], b[13], b[14], b[15]),
    ]
}

/// K0..K3 from a 128-bit CK or IK (Document 1 sections 3.4 and 4.4): K3 holds bits 0-31 of the
/// key, so the words run in the opposite order to the octets.
fn key_words(key: &[u8; 16]) -> [u32; 4] {
    let w = words(key);
    [w[3], w[2], w[1], w[0]]
}

/// The number of message bits actually processed: LENGTH, clamped to the buffer.
fn clamp_bits(length_bits: u64, len_bytes: usize) -> u64 {
    length_bits.min((len_bytes as u64).saturating_mul(8))
}

/// XOR `n` bits of keystream into `data`, leaving any bits of the last octet beyond `n` as they
/// were.
fn apply_keystream(data: &mut [u8], n: u64, mut next_word: impl FnMut() -> u32) {
    let full = (n / 8) as usize;
    let rem = (n % 8) as u32;
    let mut ks = [0u8; 4];
    for (i, byte) in data
        .iter_mut()
        .take(full + usize::from(rem != 0))
        .enumerate()
    {
        if i % 4 == 0 {
            ks = next_word().to_be_bytes();
        }
        let k = ks[i % 4];
        *byte ^= if i < full { k } else { k & (0xFF << (8 - rem)) };
    }
}

/// UEA2 / 128-EEA1 over the first `length_bits` bits of `data`, in place (Document 1 section 3;
/// TS 33.401 Annex B.1.2). Its own inverse.
pub fn eea1_bits(
    key: &[u8; 16],
    count: u32,
    bearer: u8,
    direction: u8,
    data: &mut [u8],
    length_bits: u64,
) {
    let n = clamp_bits(length_bits, data.len());
    let bd = (((bearer & 0x1F) as u32) << 27) | (((direction & 1) as u32) << 26);
    let mut g = Snow3g::new(key_words(key), [bd, count, bd, count]);
    apply_keystream(data, n, || g.next_word());
}

/// `MUL(V, P, c)` of Document 1 section 4.3.4: V·P in GF(2^64) with reduction constant `c`.
fn mul64(mut v: u64, p: u64, c: u64) -> u64 {
    let mut r = 0u64;
    for i in 0..64 {
        if (p >> i) & 1 == 1 {
            r ^= v;
        }
        v = if v >> 63 == 1 { (v << 1) ^ c } else { v << 1 };
    }
    r
}

/// Message bits `64i .. 64i+63` as one word, bits at or beyond `n` zero.
fn block64(msg: &[u8], i: u64, n: u64) -> u64 {
    let start = i * 64;
    let mut b = [0u8; 8];
    for (j, o) in b.iter_mut().enumerate() {
        let idx = (start / 8) as usize + j;
        *o = msg.get(idx).copied().unwrap_or(0);
    }
    let w = u64::from_be_bytes(b);
    let valid = n.saturating_sub(start).min(64);
    if valid == 64 {
        w
    } else if valid == 0 {
        0
    } else {
        w & !(u64::MAX >> valid)
    }
}

/// UIA2 (Document 1 section 4): the 32-bit MAC-I over the first `length_bits` bits of `message`.
pub fn uia2_bits(
    key: &[u8; 16],
    count: u32,
    fresh: u32,
    direction: u8,
    message: &[u8],
    length_bits: u64,
) -> [u8; 4] {
    let n = clamp_bits(length_bits, message.len());
    let dir = (direction & 1) as u32;
    let iv = [fresh ^ (dir << 15), count ^ (dir << 31), fresh, count];
    let mut g = Snow3g::new(key_words(key), iv);
    let z1 = g.next_word() as u64;
    let z2 = g.next_word() as u64;
    let z3 = g.next_word() as u64;
    let z4 = g.next_word() as u64;
    let z5 = g.next_word();
    let p = (z1 << 32) | z2;
    let q = (z3 << 32) | z4;
    const C: u64 = 0x1b;
    // D = ceil(LENGTH / 64) + 1; M_0 .. M_{D-2} carry the message, M_{D-1} its length.
    let blocks = n.div_ceil(64);
    let mut eval = 0u64;
    for i in 0..blocks {
        eval = mul64(eval ^ block64(message, i, n), p, C);
    }
    eval ^= n;
    eval = mul64(eval, q, C);
    (((eval >> 32) as u32) ^ z5).to_be_bytes()
}

/// 128-EIA1 (TS 33.401 Annex B.2.2): UIA2 with FRESH = BEARER || 0^27.
pub fn eia1_bits(
    key: &[u8; 16],
    count: u32,
    bearer: u8,
    direction: u8,
    message: &[u8],
    length_bits: u64,
) -> [u8; 4] {
    let fresh = ((bearer & 0x1F) as u32) << 27;
    uia2_bits(key, count, fresh, direction, message, length_bits)
}

/// 128-NIA1 over a whole octet string.
pub fn nia1(key: &[u8; 16], count: u32, bearer: u8, direction: u8, message: &[u8]) -> [u8; 4] {
    let bits = (message.len() as u64).saturating_mul(8);
    eia1_bits(key, count, bearer, direction, message, bits)
}

/// 128-NEA1 over a whole octet string, in place. Its own inverse.
pub fn nea1(key: &[u8; 16], count: u32, bearer: u8, direction: u8, data: &mut [u8]) {
    let bits = (data.len() as u64).saturating_mul(8);
    eea1_bits(key, count, bearer, direction, data, bits);
}
