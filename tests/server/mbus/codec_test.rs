//! The M-Bus codec alone: link-layer frames against bytes worked out from EN 13757-2, records
//! against bytes worked out from the EN 13757-3 tables, and every bound.
use netget::server::mbus::frame::{self, Frame, Parsed, SecondaryAddress};
use netget::server::mbus::records::{self, Header};
use serde_json::{json, Value};

fn rec(v: Value) -> Vec<u8> {
    records::encode_record(&v).unwrap_or_else(|e| panic!("{v}: {e:#}"))
}

#[test]
fn short_and_long_frames_carry_the_sum_checksum_and_the_stop_byte() {
    let req = Frame::Short {
        c: frame::c::REQ_UD2 | frame::c::FCB,
        a: 1,
    };
    assert_eq!(req.encode().unwrap(), [0x10, 0x7B, 0x01, 0x7C, 0x16]);
    let sel = Frame::Long {
        c: 0x73,
        a: 0xFD,
        ci: 0x52,
        data: vec![0x78, 0x56, 0x34, 0x12, 0xFF, 0xFF, 0xFF, 0xFF],
    };
    let bytes = sel.encode().unwrap();
    assert_eq!(
        bytes,
        [
            0x68, 0x0B, 0x0B, 0x68, 0x73, 0xFD, 0x52, 0x78, 0x56, 0x34, 0x12, 0xFF, 0xFF, 0xFF,
            0xFF, 0xD2, 0x16
        ]
    );
    assert_eq!(frame::parse(&bytes), Parsed::Frame(sel, bytes.len()));
    let control = Frame::long(0x53, 5, 0x50, vec![]);
    assert_eq!(
        control.encode().unwrap(),
        [0x68, 0x03, 0x03, 0x68, 0x53, 0x05, 0x50, 0xA8, 0x16]
    );
    assert_eq!(frame::parse(&[0xE5]), Parsed::Frame(Frame::Ack, 1));
}

#[test]
fn a_broken_telegram_is_discarded_whole_and_never_parsed_from_its_middle() {
    let mut bytes = Frame::Short { c: 0x5B, a: 1 }.encode().unwrap();
    bytes[3] ^= 1;
    assert!(matches!(
        frame::parse(&bytes),
        Parsed::Invalid { skip: 5, .. }
    ));
    // A long frame with a bad checksum whose data happens to contain a short frame.
    let inner = Frame::Short { c: 0x40, a: 7 }.encode().unwrap();
    let mut long = Frame::long(0x53, 1, 0x51, inner.clone()).encode().unwrap();
    let cs = long.len() - 2;
    long[cs] ^= 0xFF;
    match frame::parse(&long) {
        Parsed::Invalid { skip, reason } => {
            assert_eq!(skip, long.len());
            assert!(reason.contains("checksum"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    let (frames, errors) = frame::parse_all(&long);
    assert!(
        frames.is_empty(),
        "a frame was read out of a broken one: {frames:?}"
    );
    assert_eq!(errors.len(), 1);
    // Disagreeing length bytes and a missing stop byte.
    assert!(matches!(
        frame::parse(&[0x68, 0x05, 0x06, 0x68]),
        Parsed::Invalid { skip: 1, .. }
    ));
    let mut no_stop = Frame::Short { c: 0x40, a: 1 }.encode().unwrap();
    no_stop[4] = 0x17;
    assert!(matches!(frame::parse(&no_stop), Parsed::Invalid { .. }));
    assert!(matches!(
        frame::parse(&[0x42]),
        Parsed::Invalid { skip: 1, .. }
    ));
    assert_eq!(frame::parse(&[0x68, 0x10]), Parsed::Incomplete(2));
}

#[test]
fn the_l_field_bounds_a_telegram_at_252_bytes_of_user_data() {
    assert_eq!(frame::MAX_FRAME_LEN, 261);
    let full = Frame::long(0x08, 1, 0x72, vec![0x2F; frame::MAX_USER_DATA]);
    let bytes = full.encode().unwrap();
    assert_eq!(bytes.len(), frame::MAX_FRAME_LEN);
    assert_eq!(bytes[1], 0xFF);
    assert_eq!(
        frame::parse(&bytes),
        Parsed::Frame(full, frame::MAX_FRAME_LEN)
    );
    let over = Frame::long(0x08, 1, 0x72, vec![0x2F; frame::MAX_USER_DATA + 1]);
    assert!(over.encode().is_err());
}

#[test]
fn manufacturer_codes_ids_and_secondary_addresses() {
    assert_eq!(frame::manufacturer_code("KAM").unwrap(), 0x2C2D);
    assert_eq!(frame::manufacturer_code("ELS").unwrap(), 0x1593);
    assert_eq!(frame::manufacturer_letters(0x2C2D), "KAM");
    assert!(frame::manufacturer_code("kam").is_err());
    assert!(frame::manufacturer_code("KAMS").is_err());
    assert_eq!(
        frame::id_to_bcd(12345678).unwrap(),
        [0x78, 0x56, 0x34, 0x12]
    );
    assert!(frame::id_to_bcd(100_000_000).is_err());
    let heat = SecondaryAddress {
        id: frame::id_to_bcd(12345678).unwrap(),
        manufacturer: 0x2C2D,
        version: 1,
        medium: 4,
    };
    assert_eq!(heat.to_hex(), "123456782D2C0104");
    assert_eq!(frame::mask_from_hex(&heat.to_hex()).unwrap(), heat.bytes());
    for (mask, hit) in [
        ("FFFFFFFFFFFFFFFF", true),
        ("1234567FFFFFFFFF", true),
        ("1234567FFFFFFFF4", true),
        ("1234567FFFFFFFF7", false),
        ("123456782D2CFFFF", true),
        ("123456782D2D0104", false),
        ("F2345678FFFF01FF", true),
        ("02345678FFFFFFFF", false),
    ] {
        let m = frame::mask_from_hex(mask).unwrap();
        assert_eq!(heat.matches(&m), hit, "{mask}");
        assert_eq!(frame::mask_to_hex(&m), mask);
    }
    assert!(frame::mask_from_hex("A234567FFFFFFFFF").is_err());
    assert!(frame::mask_from_hex("1234").is_err());
    assert_eq!(frame::medium_from_name("Cold water").unwrap(), 0x16);
    assert_eq!(frame::medium_name(0x07), "water");
}

#[test]
fn records_pick_the_coarsest_exact_vif_and_the_smallest_coding() {
    // 12345 kWh = 12345 * 10^3 Wh: VIF 0x06 (kWh), 16-bit integer.
    assert_eq!(
        rec(json!({"quantity": "energy", "unit": "kWh", "value": 12345})),
        [0x02, 0x06, 0x39, 0x30]
    );
    // 12000 Wh travels as 12 * 10^3 Wh in one byte.
    assert_eq!(
        rec(json!({"quantity": "energy", "unit": "Wh", "value": 12000})),
        [0x01, 0x06, 0x0C]
    );
    // 456.789 m3 in BCD: 456789 * 10^-3 m3, VIF 0x13, six digits.
    assert_eq!(
        rec(json!({"quantity": "volume", "unit": "m3", "value": 456.789, "encoding": "bcd"})),
        [0x0B, 0x13, 0x89, 0x67, 0x45]
    );
    // 65.4 °C: 654 * 10^-1, VIF 0x5A.
    assert_eq!(
        rec(json!({"quantity": "flow_temperature", "unit": "°C", "value": 65.4})),
        [0x02, 0x5A, 0x8E, 0x02]
    );
    // A resolution fixes the step: 1.5 m3 counted in litres.
    assert_eq!(
        rec(json!({"quantity": "volume", "unit": "m3", "value": 1.5, "resolution": 0.001})),
        [0x02, 0x13, 0xDC, 0x05]
    );
    // Volume flow in l/h, temperature difference in K, voltage and current through 0xFD.
    // 250 l/h = 25 * 10^-2 m3/h: VIF 0x3C.
    assert_eq!(
        rec(json!({"quantity": "volume_flow", "unit": "l/h", "value": 250})),
        [0x01, 0x3C, 0x19]
    );
    // 230 V = 23 * 10^1 V: 0xFD, then 0x40 | (1 + 9).
    assert_eq!(
        rec(json!({"quantity": "voltage", "unit": "V", "value": 230})),
        [0x01, 0xFD, 0x4A, 0x17]
    );
    // 1500 mA = 15 * 10^-1 A: 0xFD, then 0x50 | (-1 + 12).
    assert_eq!(
        rec(json!({"quantity": "current", "unit": "mA", "value": 1500})),
        [0x01, 0xFD, 0x5B, 0x0F]
    );
    assert_eq!(
        rec(json!({"quantity": "operating_time", "unit": "h", "value": 8760})),
        [0x02, 0x26, 0x38, 0x22]
    );
    assert_eq!(
        rec(json!({"quantity": "fabrication_number", "value": 4711})),
        [0x0A, 0x78, 0x11, 0x47]
    );
    // An explicit width is honoured, and refused when the value does not fit it.
    assert_eq!(
        rec(json!({"quantity": "energy", "unit": "Wh", "value": 7, "encoding": "int32"})),
        [0x04, 0x03, 0x07, 0, 0, 0]
    );
    assert!(records::encode_record(
        &json!({"quantity": "energy", "unit": "Wh", "value": 70001, "encoding": "int16"})
    )
    .is_err());
    assert!(records::encode_record(
        &json!({"quantity": "energy", "unit": "Wh", "value": 70001, "encoding": "bcd4"})
    )
    .is_err());
}

#[test]
fn storage_tariff_subunit_function_and_signs_are_encoded_in_the_dib() {
    // Storage 1 is the DIF's own bit; tariff 1 needs a DIFE.
    assert_eq!(
        rec(
            json!({"quantity": "energy", "unit": "kWh", "value": 11000, "storage": 1, "tariff": 1})
        ),
        [0xC2, 0x10, 0x07, 0x4C, 0x04]
    );
    // Storage 5 = 1 in the DIF + 2 in the first DIFE; subunit 1 sets bit 6 of the DIFE.
    assert_eq!(
        rec(json!({"quantity": "energy", "unit": "Wh", "value": 1, "storage": 5, "subunit": 1})),
        [0xC1, 0x42, 0x03, 0x01]
    );
    // Storage 40 needs two DIFEs: 0 in the DIF, then 20 in four-bit steps (4, then 1).
    assert_eq!(
        rec(json!({"quantity": "energy", "unit": "Wh", "value": 1, "storage": 40})),
        [0x81, 0x84, 0x01, 0x03, 0x01]
    );
    // Maximum value, and a negative BCD with the sign nibble F.
    assert_eq!(
        rec(json!({"quantity": "power", "unit": "W", "value": 5, "function": "maximum"})),
        [0x11, 0x2B, 0x05]
    );
    assert_eq!(
        rec(
            json!({"quantity": "volume", "unit": "l", "value": -42, "encoding": "bcd", "function": "error"})
        ),
        [0x3A, 0x13, 0x42, 0xF0]
    );
    // A negative integer is two's complement.
    assert_eq!(
        rec(json!({"quantity": "external_temperature", "unit": "°C", "value": -5.5})),
        [0x01, 0x66, 0xC9]
    );
    // Type G date and type F date-time.
    assert_eq!(
        rec(json!({"quantity": "date", "value": "2026-09-30", "storage": 1})),
        [0x42, 0x6C, 0x5E, 0x39]
    );
    assert_eq!(
        rec(json!({"quantity": "datetime", "value": "2026-10-16T12:30"})),
        [0x04, 0x6D, 0x1E, 0x0C, 0x50, 0x3A]
    );
}

#[test]
fn values_m_bus_cannot_carry_are_refused_not_rounded() {
    for bad in [
        json!({"quantity": "energy", "unit": "Wh", "value": 0.0001}),
        json!({"quantity": "energy", "unit": "furlongs", "value": 1}),
        json!({"quantity": "warp_factor", "unit": "W", "value": 1}),
        json!({"quantity": "volume", "unit": "m3", "value": 1.2345, "resolution": 0.01}),
        json!({"quantity": "energy", "unit": "Wh", "value": 1, "function": "average"}),
        json!({"quantity": "energy", "unit": "Wh", "value": 1, "storage": 1u64 << 41}),
        json!({"quantity": "on_time", "unit": "fortnights", "value": 1}),
        json!({"quantity": "date", "value": "1999-01-01"}),
        json!({"quantity": "energy", "unit": "Wh"}),
    ] {
        assert!(records::encode_record(&bad).is_err(), "{bad} was accepted");
    }
}

#[test]
fn decoding_reads_back_what_encoding_wrote() {
    let mut data = Vec::new();
    for r in [
        json!({"quantity": "energy", "unit": "kWh", "value": 12345}),
        json!({"quantity": "volume", "unit": "m3", "value": 456.789, "encoding": "bcd"}),
        json!({"quantity": "flow_temperature", "unit": "°C", "value": 65.4}),
        json!({"quantity": "energy", "unit": "kWh", "value": 11000, "storage": 1, "tariff": 1}),
        json!({"quantity": "date", "value": "2026-09-30", "storage": 1}),
        json!({"quantity": "volume", "unit": "l", "value": 1234.5, "encoding": "real"}),
        json!({"quantity": "volume", "unit": "l", "value": -42, "encoding": "bcd", "function": "error"}),
        json!({"quantity": "energy", "unit": "Wh", "value": 1, "storage": 40, "subunit": 3}),
        json!({"quantity": "voltage", "unit": "V", "value": 230.5}),
    ] {
        data.extend(rec(r));
    }
    let d = records::decode_records(&data).unwrap();
    let r = &d.records;
    assert_eq!(r.len(), 9);
    assert_eq!(r[0]["quantity"], "energy");
    assert_eq!(r[0]["unit"], "Wh");
    assert_eq!(r[0]["value"], json!(12345000));
    assert_eq!(r[0]["raw_value"], json!(12345));
    assert_eq!(r[0]["exponent"], json!(3));
    assert_eq!(r[1]["value"], json!(456.789));
    assert_eq!(r[1]["encoding"], "bcd6");
    assert_eq!(r[2]["value"], json!(65.4));
    assert_eq!(r[3]["value"], json!(11000000));
    assert_eq!(r[3]["storage"], json!(1));
    assert_eq!(r[3]["tariff"], json!(1));
    assert_eq!(r[4]["value"], "2026-09-30");
    assert_eq!(r[5]["value"], json!(1.2345));
    assert_eq!(r[5]["unit"], "m3");
    assert_eq!(r[6]["value"], json!(-0.042));
    assert_eq!(r[6]["function"], "error");
    assert_eq!(r[7]["storage"], json!(40));
    assert_eq!(r[7]["subunit"], json!(3));
    assert_eq!(r[8]["value"], json!(230.5));
    assert_eq!(r[8]["vif"], "0xfd 0x48");
    assert!(!d.more_records_follow);
}

#[test]
fn decoding_handles_text_manufacturer_data_fillers_and_more_records() {
    // LVAR text is sent last character first; 0x2F is an idle filler; 0x1F ends the telegram
    // with manufacturer data and announces more records.
    let data = [
        0x0D, 0xFD, 0x0C, 0x03, b'C', b'B', b'A', 0x2F, 0x2F, 0x01, 0x03, 0x09, 0x1F, 0xAA, 0xBB,
    ];
    let d = records::decode_records(&data).unwrap();
    assert_eq!(d.records.len(), 2);
    assert_eq!(d.records[0]["quantity"], "model_version");
    assert_eq!(d.records[0]["value"], "ABC");
    assert_eq!(d.records[1]["value"], json!(9));
    assert!(d.more_records_follow);
    assert_eq!(d.manufacturer_specific_bytes, 2);
    // An unknown VIF is reported with its code, its value decoded per the DIF.
    let d = records::decode_records(&[0x01, 0x6F, 0x05]).unwrap();
    assert_eq!(d.records[0]["quantity"], "unknown");
    assert_eq!(d.records[0]["vif"], "0x6f");
    // A BCD digit above 9 is no number: the value is null and the digits are reported, as
    // meters use A-F nibbles to mark a value unavailable.
    let d = records::decode_records(&[0x3A, 0x13, 0xDD, 0xEB]).unwrap();
    assert_eq!(d.records[0]["value"], Value::Null);
    assert_eq!(d.records[0]["bcd_digits"], "EBDD");
    assert_eq!(d.records[0]["function"], "error");
    // Type I date-time (six bytes): 2016-07-22 08:00:00.
    let d = records::decode_records(&[0x06, 0x6D, 0x00, 0x00, 0x08, 0x16, 0x27, 0x00]).unwrap();
    assert_eq!(d.records[0]["value"], "2016-07-22T08:00:00");
    // A record cut short is refused.
    assert!(records::decode_records(&[0x04, 0x13, 0x01]).is_err());
}

#[test]
fn dife_and_vife_chains_stop_at_ten() {
    let mut ten = vec![0x81];
    ten.extend([0x80; 9]);
    ten.push(0x00);
    ten.extend([0x03, 0x05]);
    assert!(records::decode_records(&ten).is_ok());
    let mut eleven = vec![0x81];
    eleven.extend([0x80; 10]);
    eleven.push(0x00);
    eleven.extend([0x03, 0x05]);
    let e = records::decode_records(&eleven).unwrap_err().to_string();
    assert!(e.contains("10 DIFEs"), "{e}");
    let mut vifes = vec![0x01, 0x83];
    vifes.extend([0x80; 9]);
    vifes.push(0x00);
    vifes.push(0x05);
    assert!(records::decode_records(&vifes).is_ok());
    let mut too_many = vec![0x01, 0x83];
    too_many.extend([0x80; 10]);
    too_many.push(0x00);
    too_many.push(0x05);
    let e = records::decode_records(&too_many).unwrap_err().to_string();
    assert!(e.contains("10 VIFEs"), "{e}");
}

#[test]
fn a_telegram_holds_at_most_64_records() {
    let one = [0x01u8, 0x03, 0x00];
    let sixty_four: Vec<u8> = one.iter().copied().cycle().take(3 * 64).collect();
    assert_eq!(
        records::decode_records(&sixty_four).unwrap().records.len(),
        64
    );
    let sixty_five: Vec<u8> = one.iter().copied().cycle().take(3 * 65).collect();
    let e = records::decode_records(&sixty_five)
        .unwrap_err()
        .to_string();
    assert!(e.contains("more than 64 records"), "{e}");
}

#[test]
fn a_readout_splits_into_telegrams_closed_with_0x1f_and_stops_at_sixteen() {
    let address = SecondaryAddress {
        id: frame::id_to_bcd(1).unwrap(),
        manufacturer: 0x2C2D,
        version: 1,
        medium: 4,
    };
    let recs: Vec<Vec<u8>> = (0..120)
        .map(|n| {
            rec(json!({"quantity": "energy", "unit": "Wh", "value": 1000 + n, "storage": n, "encoding": "int32"}))
        })
        .collect();
    let telegrams = records::pack_telegrams(address, 10, 0, &recs).unwrap();
    assert!(telegrams.len() > 1);
    let mut seen = 0usize;
    for (i, t) in telegrams.iter().enumerate() {
        assert!(
            t.len() <= frame::MAX_USER_DATA,
            "telegram {i} is {} bytes",
            t.len()
        );
        let h = Header::decode(t).unwrap();
        assert_eq!(h.access_number, 10 + i as u8);
        let d = records::decode_records(&t[records::HEADER_LEN..]).unwrap();
        assert_eq!(d.more_records_follow, i + 1 < telegrams.len());
        assert!(d.records.len() <= records::MAX_RECORDS_PER_TELEGRAM);
        for r in &d.records {
            assert_eq!(r["storage"], json!(seen));
            seen += 1;
        }
    }
    assert_eq!(seen, 120);
    // Seventeen telegrams' worth is one readout too many.
    let huge: Vec<Vec<u8>> = vec![vec![0x2F; 200]; records::MAX_TELEGRAMS + 1];
    let e = records::pack_telegrams(address, 0, 0, &huge)
        .unwrap_err()
        .to_string();
    assert!(e.contains("at most 16"), "{e}");
    // A readout with no records is the identity alone.
    let empty = records::pack_telegrams(address, 0, 0x02, &[]).unwrap();
    assert_eq!(empty.len(), 1);
    assert_eq!(empty[0].len(), records::HEADER_LEN);
    assert_eq!(empty[0][9], 0x02);
}

#[test]
fn status_flags_are_named_both_ways() {
    assert_eq!(
        records::status_from_json(Some(&json!(["power_low", "application_busy"]))).unwrap(),
        0x05
    );
    assert!(
        records::status_from_json(Some(&json!(["application_busy", "application_error"]))).is_err()
    );
    assert!(records::status_from_json(Some(&json!(["on_fire"]))).is_err());
    assert_eq!(
        records::status::names(0x0A),
        vec!["application_error", "permanent_error"]
    );
}

/// The fuzz target's invariants (`fuzz/fuzz_targets/mbus_frame.rs`) as properties, so they run
/// with the suite: whatever arrives, the parser never claims more than it was given, a parsed
/// frame re-encodes to its own bytes, and the record walk never exceeds its bounds or panics.
fn check_stream(data: &[u8]) -> Result<(), TestCaseError> {
    let mut rest = data;
    while !rest.is_empty() {
        match frame::parse(rest) {
            Parsed::Incomplete(n) => {
                prop_assert!(n > 0 && rest.len() + n <= frame::MAX_FRAME_LEN);
                break;
            }
            Parsed::Invalid { skip, .. } => {
                prop_assert!(skip > 0 && skip <= frame::MAX_FRAME_LEN);
                rest = &rest[skip.min(rest.len())..];
            }
            Parsed::Frame(f, used) => {
                prop_assert!(used > 0 && used <= rest.len());
                prop_assert_eq!(f.encode().unwrap(), rest[..used].to_vec());
                if let (Some(ci), data) = (f.ci(), f.data()) {
                    if let Ok((_, d)) = records::decode_response(ci, data) {
                        prop_assert!(d.records.len() <= records::MAX_RECORDS_PER_TELEGRAM);
                    }
                }
                rest = &rest[used..];
            }
        }
    }
    if let Ok(d) = records::decode_records(data) {
        prop_assert!(d.records.len() <= records::MAX_RECORDS_PER_TELEGRAM);
    }
    Ok(())
}

fn heat_telegram() -> Vec<u8> {
    let mut data = vec![
        0x78, 0x56, 0x34, 0x12, 0x2D, 0x2C, 0x01, 0x04, 0x05, 0x00, 0x00, 0x00,
    ];
    for r in [
        json!({"quantity": "energy", "unit": "kWh", "value": 12345}),
        json!({"quantity": "volume", "unit": "m3", "value": 456.789, "encoding": "bcd"}),
        json!({"quantity": "datetime", "value": "2026-10-16T12:30", "storage": 3, "tariff": 2}),
        json!({"quantity": "voltage", "unit": "V", "value": 230.5, "encoding": "real"}),
    ] {
        data.extend(rec(r));
    }
    Frame::long(0x08, 1, 0x72, data).encode().unwrap()
}

use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn any_bytes_parse_without_overreach(data in proptest::collection::vec(any::<u8>(), 0..600)) {
        check_stream(&data)?;
    }

    /// A real telegram with bytes changed: either it still parses and re-encodes, or it is
    /// discarded; the record walk over its body never panics.
    #[test]
    fn a_damaged_telegram_is_parsed_or_discarded(
        edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..6),
        cut in any::<usize>(),
    ) {
        let mut t = heat_telegram();
        for (i, b) in edits {
            let i = i % t.len();
            t[i] = b;
        }
        let keep = 1 + cut % t.len();
        check_stream(&t[..keep])?;
        check_stream(&t)?;
        let _ = records::decode_records(&t[7.min(t.len())..]);
    }

    /// Any record the encoder accepts decodes back to the same storage, tariff and value.
    #[test]
    fn an_encoded_integer_record_decodes_to_itself(
        value in -9_999_999i64..=9_999_999,
        storage in 0u64..5000,
        tariff in 0u64..64,
        bcd in any::<bool>(),
    ) {
        let r = json!({
            "quantity": "energy", "unit": "Wh", "value": value, "storage": storage,
            "tariff": tariff, "encoding": if bcd { "bcd" } else { "int" }
        });
        let bytes = records::encode_record(&r).unwrap();
        let d = records::decode_records(&bytes).unwrap();
        prop_assert_eq!(d.records.len(), 1);
        let got = &d.records[0];
        prop_assert_eq!(got["storage"].as_u64(), Some(storage));
        prop_assert_eq!(got["tariff"].as_u64().unwrap_or(0), tariff);
        prop_assert_eq!(got["value"].as_f64(), Some(value as f64));
    }
}
