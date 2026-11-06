//! `netget::server::mysql::stmt_params::parse_execute` — the MySQL server's decoder for the
//! parameter block of `COM_STMT_EXECUTE`, written because `opensrv-mysql`'s own `ParamParser`
//! panics on five malformed shapes (`params.rs` lines 81, 86, 90, 103 and 127). Reachable from
//! any connection that has prepared a statement, which needs no credentials at all.
//!
//! Input layout, so the fuzzer can vary what the server knows as well as the packet:
//!
//! ```text
//! byte 0      parameter count the PREPARE reply declared (0..=255)
//! byte 1      bit 0: an earlier execute bound types (they follow, 2 × count bytes)
//! byte 2      bitmap of which of the first eight parameters received long data
//! …           the previous types, when bit 0 is set
//! rest        the COM_STMT_EXECUTE payload after the 0x17 command byte
//! ```
//!
//! Properties asserted:
//!
//! 1. It never panics, whatever the bytes and whatever the declared count.
//! 2. It is deterministic.
//! 3. **What it accepts, it accepts canonically**: re-encoding the decoded request in the
//!    canonical wire form and decoding that again gives back the same parameters. A decoder
//!    that misread a length or a type width would decode its own re-encoding differently.
//! 4. Accepted input renders: one entry per declared parameter, no string value longer than
//!    `MAX_RENDERED_VALUE_BYTES`, and a rendered query with exactly one closing mark per
//!    placeholder — a value can never close its own bracket.
//!
//! There is no depth bomb in this corpus because the format has no nesting: every field is
//! at a fixed position or follows a length, and the decoder is a single loop.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::mysql::placeholder_offsets;
use netget::server::mysql::stmt_params::{
    params_json, parse_execute, render_query, ExecuteRequest, LongData, ParamType, ParamValue,
    MAX_RENDERED_VALUE_BYTES, RENDER_CLOSE,
};
use std::collections::HashMap;

fn lenenc(out: &mut Vec<u8>, n: u64) {
    if n < 0xFB {
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(0xFC);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFF_FFFF {
        out.push(0xFD);
        out.extend_from_slice(&(n as u32).to_le_bytes()[..3]);
    } else {
        out.push(0xFE);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

/// The canonical encoding of `req`: minimal length prefixes, unsigned flag only, and types
/// always rebound so the re-encoding does not depend on what the server remembered.
fn encode(req: &ExecuteRequest<'_>, types: &[ParamType]) -> Vec<u8> {
    let mut out = req.stmt_id.to_le_bytes().to_vec();
    out.push(req.flags);
    out.extend_from_slice(&req.iteration_count.to_le_bytes());
    let n = req.params.len();
    if n == 0 {
        return out;
    }
    let mut bitmap = vec![0u8; n.div_ceil(8)];
    for (i, p) in req.params.iter().enumerate() {
        if p.null_bit {
            bitmap[i / 8] |= 1 << (i % 8);
        }
    }
    out.extend_from_slice(&bitmap);
    out.push(1);
    for t in types {
        out.push(t.code);
        out.push(if t.unsigned { 0x80 } else { 0 });
    }
    for p in &req.params {
        match &p.value {
            ParamValue::Null | ParamValue::LongData(_) => {}
            ParamValue::Int(v) => {
                let b = v.to_le_bytes();
                out.extend_from_slice(&b[..width(p.ty.code)]);
            }
            ParamValue::UInt(v) => {
                let b = v.to_le_bytes();
                out.extend_from_slice(&b[..width(p.ty.code)]);
            }
            ParamValue::Float(f) => out.extend_from_slice(&f.to_le_bytes()),
            ParamValue::Double(f) => out.extend_from_slice(&f.to_le_bytes()),
            ParamValue::Bytes(b) => {
                lenenc(&mut out, b.len() as u64);
                out.extend_from_slice(b);
            }
            ParamValue::DateTime {
                len,
                year,
                month,
                day,
                hour,
                minute,
                second,
                micros,
            } => {
                out.push(*len);
                if *len >= 4 {
                    out.extend_from_slice(&year.to_le_bytes());
                    out.extend_from_slice(&[*month, *day]);
                }
                if *len >= 7 {
                    out.extend_from_slice(&[*hour, *minute, *second]);
                }
                if *len >= 11 {
                    out.extend_from_slice(&micros.to_le_bytes());
                }
            }
            ParamValue::Time {
                len,
                negative,
                days,
                hour,
                minute,
                second,
                micros,
            } => {
                out.push(*len);
                if *len >= 8 {
                    out.push(u8::from(*negative));
                    out.extend_from_slice(&days.to_le_bytes());
                    out.extend_from_slice(&[*hour, *minute, *second]);
                }
                if *len >= 12 {
                    out.extend_from_slice(&micros.to_le_bytes());
                }
            }
        }
    }
    out
}

fn width(code: u8) -> usize {
    match code {
        0x01 => 1,
        0x02 | 0x0D => 2,
        0x03 | 0x09 => 4,
        _ => 8,
    }
}

/// Values compared bit-for-bit, so a NaN decodes equal to itself.
fn same(a: &ParamValue<'_>, b: &ParamValue<'_>) -> bool {
    match (a, b) {
        (ParamValue::Float(x), ParamValue::Float(y)) => x.to_bits() == y.to_bits(),
        (ParamValue::Double(x), ParamValue::Double(y)) => x.to_bits() == y.to_bits(),
        _ => a == b,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let count = usize::from(data[0]);
    let has_previous = data[1] & 1 != 0;
    let long_mask = data[2];
    let mut rest = &data[3..];

    let previous: Option<Vec<ParamType>> = if has_previous {
        if rest.len() < 2 * count {
            return;
        }
        let (t, r) = rest.split_at(2 * count);
        rest = r;
        Some(
            t.chunks_exact(2)
                .map(|p| ParamType {
                    code: p[0],
                    unsigned: p[1] & 0x80 != 0,
                })
                .collect(),
        )
    } else {
        None
    };

    let mut long_data = HashMap::new();
    for bit in 0..8u16 {
        if long_mask & (1 << bit) != 0 && usize::from(bit) < count {
            let mut ld = LongData::default();
            let chunk = vec![b'L'; 600 + usize::from(bit)];
            ld.append(&chunk, chunk.len() as u64);
            long_data.insert(bit, ld);
        }
    }

    let first = parse_execute(rest, count, previous.as_deref(), &long_data);
    let second = parse_execute(rest, count, previous.as_deref(), &long_data);
    // Through `Debug`, because a decoded NaN is not `==` to itself.
    assert_eq!(
        format!("{first:?}"),
        format!("{second:?}"),
        "parse_execute disagreed with itself"
    );

    let req = match first {
        Ok(req) => req,
        Err(e) => {
            let _ = e.to_string();
            return;
        }
    };

    assert_eq!(
        req.params.len(),
        count,
        "one decoded value per declared parameter"
    );

    let types: Vec<ParamType> = req.params.iter().map(|p| p.ty).collect();
    let canonical = encode(&req, &types);
    let again = parse_execute(&canonical, count, None, &long_data)
        .expect("the canonical re-encoding of an accepted execute must be accepted");
    assert_eq!(again.params.len(), req.params.len());
    for (a, b) in req.params.iter().zip(again.params.iter()) {
        assert_eq!(a.ty, b.ty);
        assert_eq!(a.null_bit, b.null_bit);
        assert!(
            same(&a.value, &b.value),
            "re-encoding changed a value: {:?} -> {:?}",
            a.value,
            b.value
        );
    }

    let json = params_json(&req);
    let arr = json.as_array().expect("params is an array");
    assert_eq!(arr.len(), count);
    for v in arr {
        if let Some(s) = v["value"].as_str() {
            assert!(
                s.len() <= MAX_RENDERED_VALUE_BYTES,
                "a value was not bounded"
            );
        }
    }

    let sql = format!("SELECT {}", vec!["?"; count].join(", "));
    let offsets = placeholder_offsets(&sql);
    let rendered = render_query(&sql, &offsets, &req);
    assert_eq!(
        rendered.matches(RENDER_CLOSE).count(),
        count,
        "a rendered value closed its own bracket"
    );
});
