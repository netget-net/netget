//! The Db2 client's DRDA codec on its own: framing, the bounds on every length a server
//! declares, and the decoders run over bytes Apache Derby 10.17.1.0 actually sent.
//!
//! The fixtures marked "captured" are the reply bytes Derby's network server sent its own
//! JDBC client (`ij`) for `select * from t` and `select nosuch from t`, taken off the loopback
//! interface with tshark — so they are a third party's encoding, not ours.
//!
//! No LLM calls, no network.

use netget::client::db2::wire::{self, Endian, Field, Repr, RowItem};
use serde_json::json;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Captured: Derby's QRYDSC for `t (id int, s smallint, b bigint, v varchar(20), c char(5),
/// d decimal(10,2), dt date, tm time, ts timestamp, dbl double)`.
const QRYDSC: &str = "2176d00300040500021700083300143f00050f0a0221000a23000825001d0b00080971e0540001d000010671f0e00000";
/// Captured: the QRYDTA with both rows and the end-of-data SQLCA.
const QRYDTA: &str = "ff0000000000010000020000000000b2d05e0000000568656c6c6f00000561622020200000000012345c00323032362d31302d31340031323a33343a353600323032362d31302d31342d31322e33342e35362e313233343536303030003ff8000000000000ff000000000002ffffffffffffffffff000000006430323030304353533130313730000000000000000002000000000000000000000000000000002020202020202020202020000000000000ffff";
/// Captured: the SQLCARD (data only) answering `select nosuch from t`.
const SQLCARD_ERROR: &str = "00ffffb1df343258303443535331303137300000000000000000000000000000000000000000000000000020202020202020202020200000000c4e4f535543481434325830340000ff";

#[test]
fn captured_answer_set_decodes_to_typed_rows() {
    let fields = wire::parse_qrydsc(&hex(QRYDSC)).unwrap();
    let types: Vec<u8> = fields.iter().map(|f| f.drda_type).collect();
    assert_eq!(
        types,
        [0x03, 0x05, 0x17, 0x33, 0x3F, 0x0F, 0x21, 0x23, 0x25, 0x0B]
    );
    assert_eq!(
        fields[5].length, 0x0A02,
        "DECIMAL(10,2) packs precision and scale"
    );

    let repr = Repr::default();
    let data = hex(QRYDTA);
    let (first, used) = wire::decode_row(&data, &fields, &repr).unwrap().unwrap();
    assert_eq!(
        first,
        RowItem::Row(
            vec![
                json!(1),
                json!(2),
                json!(3000000000i64),
                json!("hello"),
                json!("ab   "),
                json!("123.45"),
                json!("2026-10-14"),
                json!("12:34:56"),
                json!("2026-10-14-12.34.56.123456000"),
                json!(1.5)
            ],
            None
        )
    );
    let (second, used2) = wire::decode_row(&data[used..], &fields, &repr)
        .unwrap()
        .unwrap();
    let mut nulls = vec![json!(null); 10];
    nulls[0] = json!(2);
    assert_eq!(second, RowItem::Row(nulls, None));
    let (end, used3) = wire::decode_row(&data[used + used2..], &fields, &repr)
        .unwrap()
        .unwrap();
    match end {
        RowItem::End(ca) => assert_eq!((ca.sqlcode, ca.sqlstate.as_str()), (100, "02000")),
        other => panic!("expected end of data, got {other:?}"),
    }
    assert_eq!(used + used2 + used3, data.len());
}

#[test]
fn a_row_cut_by_the_end_of_a_query_block_waits_for_the_next() {
    let fields = wire::parse_qrydsc(&hex(QRYDSC)).unwrap();
    let data = hex(QRYDTA);
    for cut in 1..40 {
        assert_eq!(
            wire::decode_row(&data[..cut], &fields, &Repr::default()).unwrap(),
            None,
            "a row cut after {cut} bytes is incomplete, not malformed"
        );
    }
}

#[test]
fn captured_error_sqlca_carries_code_state_and_tokens() {
    let ca = wire::parse_sqlcard(&hex(SQLCARD_ERROR), &Repr::default())
        .unwrap()
        .unwrap();
    assert_eq!(ca.sqlcode, -20001);
    assert_eq!(ca.sqlstate, "42X04");
    assert_eq!(ca.errproc, "CSS10170");
    assert_eq!(ca.tokens, ["NOSUCH", "42X04"]);
    // The null SQLCAGRP is success with no SQLCA at all.
    assert_eq!(
        wire::parse_sqlcard(&[0xFF], &Repr::default()).unwrap(),
        None
    );
}

#[test]
fn little_endian_servers_are_read_in_their_own_byte_order() {
    let fields = [Field {
        drda_type: 0x02,
        length: 4,
        ccsid: None,
    }];
    let mut x86 = Repr::named("QTDSQLX86");
    assert_eq!(x86.endian, Endian::Little);
    let row = [0xFF, 0x00, 0x01, 0x00, 0x00, 0x00];
    let (item, _) = wire::decode_row(&row, &fields, &x86).unwrap().unwrap();
    assert_eq!(item, RowItem::Row(vec![json!(1)], None));
    x86.set_name(&wire::ebcdic("QTDSQLASC", "t").unwrap())
        .unwrap();
    let (item, _) = wire::decode_row(&row, &fields, &x86).unwrap().unwrap();
    assert_eq!(item, RowItem::Row(vec![json!(16777216)], None));
}

#[test]
fn packed_decimals_keep_every_digit_and_their_sign() {
    let decimal = |precision: u16, scale: u16, bytes: &[u8]| {
        let fields = [Field {
            drda_type: 0x0E,
            length: (precision << 8) | scale,
            ccsid: None,
        }];
        let mut row = vec![0xFF, 0x00];
        row.extend_from_slice(bytes);
        match wire::decode_row(&row, &fields, &Repr::default())
            .unwrap()
            .unwrap()
            .0
        {
            RowItem::Row(v, _) => v[0].clone(),
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(decimal(5, 3, &[0x00, 0x50, 0x0D]), json!("-0.500"));
    assert_eq!(
        decimal(10, 2, &[0x00, 0x00, 0x00, 0x12, 0x34, 0x5C]),
        json!("123.45")
    );
    assert_eq!(
        decimal(
            31,
            0,
            &[0x99; 15].iter().copied().chain([0x9C]).collect::<Vec<_>>()
        ),
        json!("9".repeat(31))
    );
    assert_eq!(
        decimal(3, 0, &[0x00, 0x0D]),
        json!("0"),
        "negative zero is zero"
    );
}

// ---------------------------------------------------------------------------------------------
// Bounds: every length a server declares
// ---------------------------------------------------------------------------------------------

#[test]
fn a_value_longer_than_its_column_is_refused() {
    let fields = [Field {
        drda_type: 0x33,
        length: 4,
        ccsid: None,
    }];
    let row = [0xFF, 0x00, 0x00, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];
    let err = wire::decode_row(&row, &fields, &Repr::default()).unwrap_err();
    assert!(err.to_string().contains("at most 4"), "{err}");
}

#[test]
fn an_impossible_packed_decimal_is_refused() {
    for length in [0x2800u16, 0x0000, 0x0506] {
        let fields = [Field {
            drda_type: 0x0E,
            length,
            ccsid: None,
        }];
        let row = [0xFF, 0x00, 0x12, 0x34, 0x5C];
        assert!(
            wire::decode_row(&row, &fields, &Repr::default()).is_err(),
            "DECIMAL length 0x{length:04X}"
        );
    }
    let fields = [Field {
        drda_type: 0x0E,
        length: 0x0300,
        ccsid: None,
    }];
    assert!(wire::decode_row(&[0xFF, 0x00, 0xA1, 0x0C], &fields, &Repr::default()).is_err());
}

#[test]
fn a_row_layout_past_max_columns_is_refused() {
    let mut dsc = Vec::new();
    let mut entries = 0;
    let mut first = true;
    while entries <= wire::MAX_COLUMNS {
        let n = 84.min(wire::MAX_COLUMNS + 1 - entries);
        dsc.push((3 + n * 3) as u8);
        dsc.push(if first { 0x76 } else { 0x7F });
        dsc.push(if first { 0xD0 } else { 0x00 });
        for _ in 0..n {
            dsc.extend_from_slice(&[0x03, 0x00, 0x04]);
        }
        entries += n;
        first = false;
    }
    let err = wire::parse_qrydsc(&dsc).unwrap_err();
    assert!(err.to_string().contains("more than"), "{err}");
    // Exactly the bound is accepted.
    let mut ok = Vec::new();
    let mut left = wire::MAX_COLUMNS;
    let mut first = true;
    while left > 0 {
        let n = 84.min(left);
        ok.push((3 + n * 3) as u8);
        ok.push(if first { 0x76 } else { 0x7F });
        ok.push(if first { 0xD0 } else { 0x00 });
        for _ in 0..n {
            ok.extend_from_slice(&[0x03, 0x00, 0x04]);
        }
        left -= n;
        first = false;
    }
    assert_eq!(wire::parse_qrydsc(&ok).unwrap().len(), wire::MAX_COLUMNS);
}

#[test]
fn an_sqlda_past_max_columns_is_refused() {
    let mut dard = vec![0xFF, 0xFF];
    dard.extend_from_slice(&((wire::MAX_COLUMNS + 1) as i16).to_be_bytes());
    let err = wire::parse_sqldard(&dard, &Repr::default()).unwrap_err();
    assert!(err.to_string().contains("at most"), "{err}");
}

#[test]
fn a_qrydsc_triplet_running_past_its_object_is_refused() {
    assert!(wire::parse_qrydsc(&[0x21, 0x76, 0xD0, 0x03, 0x00]).is_err());
    assert!(wire::parse_qrydsc(&[0x02, 0x76, 0xD0]).is_err());
    assert!(wire::parse_qrydsc(&[0x06, 0x99, 0x00, 0, 0, 0]).is_err());
}

#[test]
fn dss_continuation_reassembles_and_is_bounded() {
    // A 100 KiB object is split into continuation segments and joined back unchanged.
    let payload = wire::object(0x241B, &vec![0xAB; 100 * 1024]);
    let mut stream = wire::dss(wire::DSS_OBJDSS, 1, false, false, &payload);
    assert!(
        stream.len() > payload.len() + 6,
        "it must have been segmented"
    );
    let cut = stream.len() - 1;
    let mut partial = stream[..cut].to_vec();
    assert_eq!(wire::take_dss(&mut partial).unwrap(), None);
    let dss = wire::take_dss(&mut stream).unwrap().unwrap();
    assert!(stream.is_empty());
    assert_eq!(dss.payload, payload);
    let objects = wire::objects(&dss.payload).unwrap();
    assert_eq!(objects.len(), 1);
    assert_eq!(
        objects[0].data.len(),
        100 * 1024,
        "the extended length is honoured"
    );

    // Continuations that add up past MAX_DSS_BYTES are refused.
    let segments = wire::MAX_DSS_BYTES / 0x7FFD + 2;
    let mut big = vec![0xFF, 0xFF, 0xD0, 0x03, 0x00, 0x01];
    big.resize(0x7FFF, 0);
    for _ in 0..segments {
        big.extend_from_slice(&[0xFF, 0xFF]);
        big.resize(big.len() + 0x7FFD, 0);
    }
    let err = wire::take_dss(&mut big).unwrap_err();
    assert!(err.to_string().contains("refused"), "{err}");
}

#[test]
fn malformed_framing_is_refused() {
    let mut bad_magic = vec![0x00, 0x0A, 0xD1, 0x02, 0x00, 0x01, 0x00, 0x04, 0x24, 0x08];
    assert!(wire::take_dss(&mut bad_magic).is_err());
    let mut too_short = vec![0x00, 0x05, 0xD0, 0x02, 0x00, 0x01];
    assert!(wire::take_dss(&mut too_short).is_err());
    // An object declaring more than its DSS holds.
    assert!(wire::objects(&[0x00, 0x40, 0x24, 0x08, 0x00]).is_err());
    // An extended length declaring more than remains.
    assert!(wire::objects(&[0x80, 0x08, 0x24, 0x1B, 0x00, 0x10, 0x00, 0x00]).is_err());
    // Too many objects in one DSS.
    let many: Vec<u8> = (0..=wire::MAX_OBJECTS_PER_DSS)
        .flat_map(|_| [0x00, 0x04, 0x24, 0x08])
        .collect();
    assert!(wire::objects(&many).is_err());
}

#[test]
fn requests_are_well_formed_drda() {
    // EXCSQLIMM chained to its SQLSTT under one correlator, as Derby's own client sends it.
    let pkg = wire::Package::new("refdb;create=true").unwrap();
    let parts = wire::excsqlimm(&pkg, "create table t (id int)").unwrap();
    let mut bytes = wire::command(1, &parts);
    let first = wire::take_dss(&mut bytes).unwrap().unwrap();
    assert_eq!(
        (first.dss_type, first.chained, first.correlator),
        (1, true, 1)
    );
    let second = wire::take_dss(&mut bytes).unwrap().unwrap();
    assert_eq!(
        (second.dss_type, second.chained, second.correlator),
        (3, false, 1)
    );
    let sqlstt = &wire::objects(&second.payload).unwrap()[0];
    assert_eq!(sqlstt.codepoint, 0x2414);
    assert_eq!(&sqlstt.data[..5], &[0x00, 0x00, 0x00, 0x00, 23]);
    assert_eq!(*sqlstt.data.last().unwrap(), 0xFF);

    // PKGNAMCSN: fixed 68-byte form for an 18-byte name, extended form past it.
    let short = wire::Package::new("netget").unwrap().encode();
    assert_eq!(short.len(), 4 + 18 * 3 + 8 + 2);
    let long = wire::Package::new("netget_session_evidence;create=true")
        .unwrap()
        .encode();
    assert_eq!(long.len(), 4 + 2 + 35 + 2 + 18 + 2 + 18 + 8 + 2);

    // DDM strings are CCSID 37, and a credential that cannot be carried is refused, not
    // substituted.
    assert_eq!(wire::ebcdic("App1", "u").unwrap(), [0xC1, 0x97, 0x97, 0xF1]);
    assert!(wire::secchk(3, "db", "app", Some("pässword")).is_err());
    assert!(wire::secchk(3, "db", "app", Some(&"x".repeat(256))).is_err());
    assert!(wire::sqlstt(&"x".repeat(wire::MAX_SQL_BYTES + 1)).is_err());
}

#[test]
fn rows_with_repeated_or_missing_names_keep_every_value() {
    let col = |name: &str| wire::Column {
        name: name.into(),
        sql_type: 497,
        nullable: true,
        precision: 10,
        scale: 0,
        length: 4,
        ccsid: 0,
    };
    let row = wire::row_object(
        &[col("1"), col("1"), col("")],
        vec![json!(1), json!(2), json!(3)],
    );
    assert_eq!(row, json!({"1": 1, "1#2": 2, "COL3": 3}));
}
