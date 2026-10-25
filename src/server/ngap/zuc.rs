//! ZUC and the 3GPP algorithms built on it, 128-EEA3 and 128-EIA3, which TS 33.501 Annex D.2/D.3
//! reuses as 128-NEA3/128-NIA3.
//!
//! Written here from the ETSI/SAGE specifications rather than taken from a crate. crates.io has
//! `zuc` 0.4 (MIT, one maintainer) and `gm-zuc`, and `oxirush-security` 0.3 (Apache-2.0, weeks
//! old, stating it has had no security audit); none is audited, and this module is short enough
//! to check line by line against the documents it follows:
//!
//! - "Specification of the 3GPP Confidentiality and Integrity Algorithms 128-EEA3 & 128-EIA3",
//!   Document 2: ZUC Specification, **v1.6** — the cipher ([`Zuc`]), including the v1.5 change
//!   to the initialisation (the LFSR takes `W >> 1`, section 3.6.1). The S-boxes `S0` and `S1` are
//!   its Tables 3.1 and 3.2 and the constants `D` its section 3.5.
//! - Document 1: 128-EEA3 and 128-EIA3 Specification, v1.8 — the IVs (sections 3.3 and 4.3) and
//!   the MAC as revised in v1.5: L = ceil(LENGTH/32) + 2 keystream words, and the final word
//!   XORed into T is the word-aligned z[32(L-1)] (section 4.5).
//!
//! The vectors are in `tests/server/ngap/cipher_vectors_test.rs`: Document 3 (implementor's test
//! data) v1.1, the version matching the v1.5 algorithms.
//!
//! The S-box lookups index by secret-dependent bytes, as every table implementation of ZUC does;
//! nothing here is hardened against cache-timing observers on the same machine.
//!
//! Bit lengths: every function has a `_bits` form taking LENGTH in bits, as the specification
//! does. A LENGTH longer than the buffer is clamped to the buffer, so no input can index outside
//! it. For ciphering, the bits of the last octet beyond LENGTH are left as they were: the
//! keystream is defined for LENGTH bits only.

/// The S-box S0, ZUC specification (Document 2) v1.6 section 3.4.1, Table 3.1.
const S0: [u8; 256] = [
    0x3E, 0x72, 0x5B, 0x47, 0xCA, 0xE0, 0x00, 0x33, 0x04, 0xD1, 0x54, 0x98, 0x09, 0xB9, 0x6D, 0xCB,
    0x7B, 0x1B, 0xF9, 0x32, 0xAF, 0x9D, 0x6A, 0xA5, 0xB8, 0x2D, 0xFC, 0x1D, 0x08, 0x53, 0x03, 0x90,
    0x4D, 0x4E, 0x84, 0x99, 0xE4, 0xCE, 0xD9, 0x91, 0xDD, 0xB6, 0x85, 0x48, 0x8B, 0x29, 0x6E, 0xAC,
    0xCD, 0xC1, 0xF8, 0x1E, 0x73, 0x43, 0x69, 0xC6, 0xB5, 0xBD, 0xFD, 0x39, 0x63, 0x20, 0xD4, 0x38,
    0x76, 0x7D, 0xB2, 0xA7, 0xCF, 0xED, 0x57, 0xC5, 0xF3, 0x2C, 0xBB, 0x14, 0x21, 0x06, 0x55, 0x9B,
    0xE3, 0xEF, 0x5E, 0x31, 0x4F, 0x7F, 0x5A, 0xA4, 0x0D, 0x82, 0x51, 0x49, 0x5F, 0xBA, 0x58, 0x1C,
    0x4A, 0x16, 0xD5, 0x17, 0xA8, 0x92, 0x24, 0x1F, 0x8C, 0xFF, 0xD8, 0xAE, 0x2E, 0x01, 0xD3, 0xAD,
    0x3B, 0x4B, 0xDA, 0x46, 0xEB, 0xC9, 0xDE, 0x9A, 0x8F, 0x87, 0xD7, 0x3A, 0x80, 0x6F, 0x2F, 0xC8,
    0xB1, 0xB4, 0x37, 0xF7, 0x0A, 0x22, 0x13, 0x28, 0x7C, 0xCC, 0x3C, 0x89, 0xC7, 0xC3, 0x96, 0x56,
    0x07, 0xBF, 0x7E, 0xF0, 0x0B, 0x2B, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xA6, 0x4C, 0x10, 0xFE,
    0xBC, 0x26, 0x95, 0x88, 0x8A, 0xB0, 0xA3, 0xFB, 0xC0, 0x18, 0x94, 0xF2, 0xE1, 0xE5, 0xE9, 0x5D,
    0xD0, 0xDC, 0x11, 0x66, 0x64, 0x5C, 0xEC, 0x59, 0x42, 0x75, 0x12, 0xF5, 0x74, 0x9C, 0xAA, 0x23,
    0x0E, 0x86, 0xAB, 0xBE, 0x2A, 0x02, 0xE7, 0x67, 0xE6, 0x44, 0xA2, 0x6C, 0xC2, 0x93, 0x9F, 0xF1,
    0xF6, 0xFA, 0x36, 0xD2, 0x50, 0x68, 0x9E, 0x62, 0x71, 0x15, 0x3D, 0xD6, 0x40, 0xC4, 0xE2, 0x0F,
    0x8E, 0x83, 0x77, 0x6B, 0x25, 0x05, 0x3F, 0x0C, 0x30, 0xEA, 0x70, 0xB7, 0xA1, 0xE8, 0xA9, 0x65,
    0x8D, 0x27, 0x1A, 0xDB, 0x81, 0xB3, 0xA0, 0xF4, 0x45, 0x7A, 0x19, 0xDF, 0xEE, 0x78, 0x34, 0x60,
];

/// The S-box S1, ZUC specification (Document 2) v1.6 section 3.4.1, Table 3.2.
const S1: [u8; 256] = [
    0x55, 0xC2, 0x63, 0x71, 0x3B, 0xC8, 0x47, 0x86, 0x9F, 0x3C, 0xDA, 0x5B, 0x29, 0xAA, 0xFD, 0x77,
    0x8C, 0xC5, 0x94, 0x0C, 0xA6, 0x1A, 0x13, 0x00, 0xE3, 0xA8, 0x16, 0x72, 0x40, 0xF9, 0xF8, 0x42,
    0x44, 0x26, 0x68, 0x96, 0x81, 0xD9, 0x45, 0x3E, 0x10, 0x76, 0xC6, 0xA7, 0x8B, 0x39, 0x43, 0xE1,
    0x3A, 0xB5, 0x56, 0x2A, 0xC0, 0x6D, 0xB3, 0x05, 0x22, 0x66, 0xBF, 0xDC, 0x0B, 0xFA, 0x62, 0x48,
    0xDD, 0x20, 0x11, 0x06, 0x36, 0xC9, 0xC1, 0xCF, 0xF6, 0x27, 0x52, 0xBB, 0x69, 0xF5, 0xD4, 0x87,
    0x7F, 0x84, 0x4C, 0xD2, 0x9C, 0x57, 0xA4, 0xBC, 0x4F, 0x9A, 0xDF, 0xFE, 0xD6, 0x8D, 0x7A, 0xEB,
    0x2B, 0x53, 0xD8, 0x5C, 0xA1, 0x14, 0x17, 0xFB, 0x23, 0xD5, 0x7D, 0x30, 0x67, 0x73, 0x08, 0x09,
    0xEE, 0xB7, 0x70, 0x3F, 0x61, 0xB2, 0x19, 0x8E, 0x4E, 0xE5, 0x4B, 0x93, 0x8F, 0x5D, 0xDB, 0xA9,
    0xAD, 0xF1, 0xAE, 0x2E, 0xCB, 0x0D, 0xFC, 0xF4, 0x2D, 0x46, 0x6E, 0x1D, 0x97, 0xE8, 0xD1, 0xE9,
    0x4D, 0x37, 0xA5, 0x75, 0x5E, 0x83, 0x9E, 0xAB, 0x82, 0x9D, 0xB9, 0x1C, 0xE0, 0xCD, 0x49, 0x89,
    0x01, 0xB6, 0xBD, 0x58, 0x24, 0xA2, 0x5F, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xB8, 0x95, 0xE4,
    0xD0, 0x91, 0xC7, 0xCE, 0xED, 0x0F, 0xB4, 0x6F, 0xA0, 0xCC, 0xF0, 0x02, 0x4A, 0x79, 0xC3, 0xDE,
    0xA3, 0xEF, 0xEA, 0x51, 0xE6, 0x6B, 0x18, 0xEC, 0x1B, 0x2C, 0x80, 0xF7, 0x74, 0xE7, 0xFF, 0x21,
    0x5A, 0x6A, 0x54, 0x1E, 0x41, 0x31, 0x92, 0x35, 0xC4, 0x33, 0x07, 0x0A, 0xBA, 0x7E, 0x0E, 0x34,
    0x88, 0xB1, 0x98, 0x7C, 0xF3, 0x3D, 0x60, 0x6C, 0x7B, 0xCA, 0xD3, 0x1F, 0x32, 0x65, 0x04, 0x28,
    0x64, 0xBE, 0x85, 0x9B, 0x2F, 0x59, 0x8A, 0xD7, 0xB0, 0x25, 0xAC, 0xAF, 0x12, 0x03, 0xE2, 0xF2,
];

/// The 15-bit constants d0..d15 of section 3.5 (given there in binary).
const D: [u32; 16] = [
    0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF, 0x4D78, 0x2F13, 0x6BC4, 0x1AF1,
    0x5E26, 0x3C4D, 0x789A, 0x47AC,
];

const M31: u32 = 0x7FFF_FFFF;

/// a + b mod 2^31 - 1 for 31-bit a and b (section 3.2's informative note).
fn add31(a: u32, b: u32) -> u32 {
    let c = a + b;
    (c & M31) + (c >> 31)
}

/// a · 2^k mod 2^31 - 1: a 31-bit left rotation.
fn rot31(a: u32, k: u32) -> u32 {
    ((a << k) | (a >> (31 - k))) & M31
}

fn l1(x: u32) -> u32 {
    x ^ x.rotate_left(2) ^ x.rotate_left(10) ^ x.rotate_left(18) ^ x.rotate_left(24)
}

fn l2(x: u32) -> u32 {
    x ^ x.rotate_left(8) ^ x.rotate_left(14) ^ x.rotate_left(22) ^ x.rotate_left(30)
}

/// The 32x32 S-box S = (S0, S1, S0, S1) of section 3.4.1.
fn s_box(x: u32) -> u32 {
    let [a, b, c, d] = x.to_be_bytes();
    u32::from_be_bytes([
        S0[a as usize],
        S1[b as usize],
        S0[c as usize],
        S1[d as usize],
    ])
}

/// The ZUC keystream generator (Document 2).
pub struct Zuc {
    s: [u32; 16],
    r1: u32,
    r2: u32,
}

impl Zuc {
    /// Key loading (section 3.5) and the initialisation stage (3.6.1), then the first working-
    /// stage step whose output is discarded (3.6.2).
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let mut s = [0u32; 16];
        for (i, cell) in s.iter_mut().enumerate() {
            *cell = ((key[i] as u32) << 23) | (D[i] << 8) | iv[i] as u32;
        }
        let mut z = Zuc { s, r1: 0, r2: 0 };
        for _ in 0..32 {
            let [x0, x1, x2, _] = z.bit_reorganization();
            let w = z.f(x0, x1, x2);
            z.lfsr(Some(w >> 1));
        }
        let [x0, x1, x2, _] = z.bit_reorganization();
        z.f(x0, x1, x2);
        z.lfsr(None);
        z
    }

    /// Section 3.3: X0..X3 from the high (bits 30..15) and low (bits 15..0) halves of the cells.
    fn bit_reorganization(&self) -> [u32; 4] {
        let s = &self.s;
        let h = |i: usize| s[i] >> 15;
        let l = |i: usize| s[i] & 0xFFFF;
        [
            (h(15) << 16) | l(14),
            (l(11) << 16) | h(9),
            (l(7) << 16) | h(5),
            (l(2) << 16) | h(0),
        ]
    }

    /// The nonlinear function F (section 3.4).
    fn f(&mut self, x0: u32, x1: u32, x2: u32) -> u32 {
        let w = (x0 ^ self.r1).wrapping_add(self.r2);
        let w1 = self.r1.wrapping_add(x1);
        let w2 = self.r2 ^ x2;
        self.r1 = s_box(l1((w1 << 16) | (w2 >> 16)));
        self.r2 = s_box(l2((w2 << 16) | (w1 >> 16)));
        w
    }

    /// LFSRWithInitialisationMode(u) with `Some(u)`, LFSRWithWorkMode() with `None` (section 3.2).
    fn lfsr(&mut self, u: Option<u32>) {
        let s = &self.s;
        let mut v = s[0];
        v = add31(v, rot31(s[0], 8));
        v = add31(v, rot31(s[4], 20));
        v = add31(v, rot31(s[10], 21));
        v = add31(v, rot31(s[13], 17));
        v = add31(v, rot31(s[15], 15));
        if let Some(u) = u {
            v = add31(v, u);
        }
        if v == 0 {
            v = M31;
        }
        self.s.copy_within(1..16, 0);
        self.s[15] = v;
    }

    /// The next keystream word Z (section 3.6.2).
    pub fn next_word(&mut self) -> u32 {
        let [x0, x1, x2, x3] = self.bit_reorganization();
        let z = self.f(x0, x1, x2) ^ x3;
        self.lfsr(None);
        z
    }
}

/// The number of message bits actually processed: LENGTH, clamped to the buffer.
fn clamp_bits(length_bits: u64, len_bytes: usize) -> u64 {
    length_bits.min((len_bytes as u64).saturating_mul(8))
}

/// 128-EEA3 over the first `length_bits` bits of `data`, in place (Document 1 section 3). Bits of
/// the last octet beyond `length_bits` are left as they were. Its own inverse.
pub fn eea3_bits(
    key: &[u8; 16],
    count: u32,
    bearer: u8,
    direction: u8,
    data: &mut [u8],
    length_bits: u64,
) {
    let n = clamp_bits(length_bits, data.len());
    let c = count.to_be_bytes();
    let b = ((bearer & 0x1F) << 3) | ((direction & 1) << 2);
    let iv = [
        c[0], c[1], c[2], c[3], b, 0, 0, 0, c[0], c[1], c[2], c[3], b, 0, 0, 0,
    ];
    let mut g = Zuc::new(key, &iv);
    let full = (n / 8) as usize;
    let rem = (n % 8) as u32;
    let mut ks = [0u8; 4];
    for (i, byte) in data
        .iter_mut()
        .take(full + usize::from(rem != 0))
        .enumerate()
    {
        if i % 4 == 0 {
            ks = g.next_word().to_be_bytes();
        }
        let k = ks[i % 4];
        *byte ^= if i < full { k } else { k & (0xFF << (8 - rem)) };
    }
}

/// A sliding 64-bit view of the keystream: `cur` is word `index`, `next` word `index + 1`.
struct Window {
    g: Zuc,
    index: u64,
    cur: u32,
    next: u32,
}

impl Window {
    fn new(mut g: Zuc) -> Self {
        let cur = g.next_word();
        let next = g.next_word();
        Window {
            g,
            index: 0,
            cur,
            next,
        }
    }

    /// Advance until `cur` is keystream word `word`. Never moves backwards.
    fn seek(&mut self, word: u64) {
        while self.index < word {
            self.cur = self.next;
            self.next = self.g.next_word();
            self.index += 1;
        }
    }

    /// z_i = z[i] || … || z[i+31] (Document 1 section 4.4).
    fn bits_at(&mut self, i: u64) -> u32 {
        self.seek(i / 32);
        let t = (i % 32) as u32;
        if t == 0 {
            self.cur
        } else {
            (self.cur << t) | (self.next >> (32 - t))
        }
    }
}

/// 128-EIA3 (Document 1 section 4): the 32-bit MAC over the first `length_bits` bits of
/// `message`.
pub fn eia3_bits(
    key: &[u8; 16],
    count: u32,
    bearer: u8,
    direction: u8,
    message: &[u8],
    length_bits: u64,
) -> [u8; 4] {
    let n = clamp_bits(length_bits, message.len());
    let c = count.to_be_bytes();
    let b = (bearer & 0x1F) << 3;
    let d = (direction & 1) << 7;
    let iv = [
        c[0],
        c[1],
        c[2],
        c[3],
        b,
        0,
        0,
        0,
        c[0] ^ d,
        c[1],
        c[2],
        c[3],
        b,
        0,
        d,
        0,
    ];
    let mut z = Window::new(Zuc::new(key, &iv));
    let mut t = 0u32;
    for i in 0..n {
        let octet = message.get((i / 8) as usize).copied().unwrap_or(0);
        if (octet >> (7 - i % 8)) & 1 == 1 {
            t ^= z.bits_at(i);
        }
    }
    t ^= z.bits_at(n);
    // L = ceil(LENGTH / 32) + 2 words; the last one, z[32(L-1)], is word-aligned. The window now
    // sits at word floor(n/32), and L - 1 is one or two words beyond it.
    let last = n.div_ceil(32) + 1;
    z.seek(last - 1);
    (t ^ z.next).to_be_bytes()
}

/// 128-NIA3 over a whole octet string.
pub fn nia3(key: &[u8; 16], count: u32, bearer: u8, direction: u8, message: &[u8]) -> [u8; 4] {
    let bits = (message.len() as u64).saturating_mul(8);
    eia3_bits(key, count, bearer, direction, message, bits)
}

/// 128-NEA3 over a whole octet string, in place. Its own inverse.
pub fn nea3(key: &[u8; 16], count: u32, bearer: u8, direction: u8, data: &mut [u8]) {
    let bits = (data.len() as u64).saturating_mul(8);
    eea3_bits(key, count, bearer, direction, data, bits);
}
