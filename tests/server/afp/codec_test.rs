//! The DSI and AFP codecs on their own: literal bytes from the spec and from netatalk, round
//! trips of every request NetGet's client sends and every reply its server builds, the bounds
//! on everything a peer declares, and tshark's `dsi`/`afp` dissectors over a synthetic session.
use crate::helpers::pcap_oracle::PcapOracle;
use netget::server::afp::dsi;
use netget::server::afp::wire::{
    self, err, AfpPath, EnumerateKind, NodeParams, PathElement, Request, UnixPrivs,
};

fn file(name: &str, id: u32, size: u64) -> NodeParams {
    let mode = 0o100644;
    NodeParams {
        is_dir: false,
        parent_id: 2,
        created: wire::date_from_unix(1_790_000_000),
        modified: wire::date_from_unix(1_790_000_100),
        backup: wire::DATE_NEVER,
        name: name.into(),
        node_id: id,
        data_len: size,
        unix: UnixPrivs {
            uid: 1000,
            gid: 1000,
            mode,
            access: wire::access_rights(mode, true),
        },
        ..Default::default()
    }
}

fn dir(name: &str, id: u32) -> NodeParams {
    let mode = 0o040755;
    NodeParams {
        is_dir: true,
        parent_id: 2,
        name: name.into(),
        node_id: id,
        offspring: 3,
        access: wire::access_rights(mode, true),
        unix: UnixPrivs {
            uid: 1000,
            gid: 1000,
            mode,
            access: wire::access_rights(mode, true),
        },
        ..Default::default()
    }
}

#[test]
fn the_dsi_header_is_sixteen_big_endian_bytes() {
    let m = dsi::message(
        dsi::FLAG_REPLY,
        dsi::command::COMMAND,
        0x1234,
        -5000i32 as u32,
        b"xy",
    );
    assert_eq!(
        m,
        vec![1, 2, 0x12, 0x34, 0xff, 0xff, 0xec, 0x78, 0, 0, 0, 2, 0, 0, 0, 0, b'x', b'y']
    );
    let mut h = [0u8; 16];
    h.copy_from_slice(&m[..16]);
    let h = dsi::Header::parse(&h);
    assert_eq!(h.result(), err::ACCESS_DENIED);
    assert_eq!(h.length, 2);
}

#[test]
fn a_dsi_length_past_the_bound_is_refused_before_any_payload_is_read() {
    let mut h = dsi::Header {
        flags: 0,
        command: dsi::command::WRITE,
        request_id: 1,
        code: 0,
        length: dsi::MAX_PAYLOAD_LEN as u32,
        reserved: 0,
    };
    assert_eq!(h.check_length().unwrap(), dsi::MAX_PAYLOAD_LEN);
    h.length += 1;
    assert!(h.check_length().is_err());
    h.length = u32::MAX;
    assert!(h.check_length().is_err());
}

#[test]
fn a_dsi_write_cannot_claim_more_command_than_it_carries() {
    let h = dsi::Header {
        flags: 0,
        command: dsi::command::WRITE,
        request_id: 1,
        code: 40,
        length: 30,
        reserved: 0,
    };
    assert!(dsi::split_write(&h, &[0u8; 30]).is_err());
    let h = dsi::Header { code: 20, ..h };
    assert_eq!(dsi::split_write(&h, &[0u8; 30]).unwrap(), (20, 10));
}

#[test]
fn open_session_options_parse_and_reject_overruns() {
    let opts = dsi::parse_options(&[0x01, 4, 0, 0, 4, 0, 0x00, 4, 0, 2, 0, 0]).unwrap();
    assert_eq!(
        dsi::quantum_option(&opts, dsi::option::ATTENTION_QUANTUM),
        Some(1024)
    );
    assert_eq!(
        dsi::quantum_option(&opts, dsi::option::SERVER_REQUEST_QUANTUM),
        Some(0x20000)
    );
    assert!(dsi::parse_options(&[0x01, 9, 0, 0]).is_err());
    assert!(dsi::parse_options(&[0x01]).is_err());
    // Seventeen empty options: more than the bound.
    assert!(dsi::parse_options(&[0u8; 34]).is_err());
}

#[test]
fn afp_dates_count_from_2000() {
    assert_eq!(wire::date_from_unix(946_684_800), 0);
    assert_eq!(wire::date_from_text("2000-01-01T00:00:00Z").unwrap(), 0);
    assert_eq!(wire::date_from_text("2000-01-02").unwrap(), 86_400);
    assert_eq!(wire::date_to_text(86_400).unwrap(), "2000-01-02T00:00:00Z");
    assert_eq!(wire::date_to_text(wire::DATE_NEVER), None);
    assert!(wire::date_from_text("yesterday").is_err());
}

#[test]
fn long_names_are_mac_roman_and_cut_at_31_bytes() {
    assert_eq!(
        wire::mac_roman_encode("café", 31),
        vec![b'c', b'a', b'f', 0x8e]
    );
    assert_eq!(wire::mac_roman_decode(&[b'c', b'a', b'f', 0x8e]), "café");
    // A character MacRoman lacks is '?', and a long name stops at the limit.
    assert_eq!(wire::mac_roman_encode("a€b", 31), b"a\xdbb".to_vec());
    assert_eq!(wire::mac_roman_encode("日本", 31), b"??".to_vec());
    assert_eq!(wire::mac_roman_encode(&"x".repeat(40), 31).len(), 31);
    // UTF-8 names go out decomposed and are compared composed.
    assert_eq!(wire::to_wire_utf8("café").as_bytes(), b"cafe\xcc\x81");
    assert_eq!(wire::normalize("cafe\u{301}"), "café");
}

#[test]
fn paths_split_on_nul_and_extra_nuls_ascend() {
    let p = AfpPath::from_wire(3, b"a\0b").unwrap();
    assert_eq!(
        p.elements,
        vec![PathElement::Name("a".into()), PathElement::Name("b".into())]
    );
    let p = AfpPath::from_wire(2, b"\0a\0\0b\0").unwrap();
    assert_eq!(
        p.elements,
        vec![
            PathElement::Name("a".into()),
            PathElement::Parent,
            PathElement::Name("b".into())
        ]
    );
    // What the client encodes is what the server reads back.
    for path in [
        AfpPath::names(&["x", "y z", "café"]),
        AfpPath {
            kind: 3,
            elements: vec![
                PathElement::Name("a".into()),
                PathElement::Parent,
                PathElement::Parent,
                PathElement::Name("b".into()),
            ],
        },
        AfpPath::here(),
    ] {
        let wire_bytes = path.encode();
        let mut r = wire::Reader::new(&wire_bytes);
        assert_eq!(r.path().unwrap(), path);
    }
}

#[test]
fn path_bounds_hold() {
    let many = vec![b'a', 0].repeat(wire::MAX_PATH_ELEMENTS + 1);
    let e = AfpPath::from_wire(3, &many).unwrap_err();
    assert_eq!(e.code, err::PARAM_ERR);
    assert!(AfpPath::from_wire(3, &vec![b'a', 0].repeat(wire::MAX_PATH_ELEMENTS)).is_ok());
    // A run of NULs is ascents, and ascents count against the same bound.
    assert!(AfpPath::from_wire(3, &[0u8; 200]).is_err());
    let long = vec![b'n'; wire::MAX_NAME_BYTES + 1];
    assert!(AfpPath::from_wire(3, &long).is_err());
    assert!(AfpPath::from_wire(3, &long[1..]).is_ok());
    // A declared length past the end is a parameter error, not a panic.
    let mut r = wire::Reader::new(&[3, 0, 0, 0, 0, 0xff, 0xff, b'a']);
    assert_eq!(r.path().unwrap_err().code, err::PARAM_ERR);
}

#[test]
fn every_request_the_client_sends_parses_back_to_itself() {
    let path = AfpPath::names(&["docs", "notes.txt"]);
    let requests = vec![
        Request::GetSrvrParms,
        Request::Logout,
        Request::OpenVol {
            bitmap: wire::vol_bit::VOLUME_ID | wire::vol_bit::NAME,
            name: "Share".into(),
            has_password: false,
        },
        Request::CloseVol { vol: 1 },
        Request::GetVolParms {
            vol: 1,
            bitmap: 0x0fff,
        },
        Request::GetFileDirParms {
            vol: 1,
            dir: 2,
            file_bitmap: 0x2fff,
            dir_bitmap: 0x3fff,
            path: path.clone(),
        },
        Request::Enumerate {
            kind: EnumerateKind::Ext2,
            vol: 1,
            dir: 2,
            file_bitmap: 1,
            dir_bitmap: 1,
            req_count: 100,
            start_index: 70_000,
            max_reply: 1 << 20,
            path: path.clone(),
        },
        Request::Enumerate {
            kind: EnumerateKind::Classic,
            vol: 1,
            dir: 17,
            file_bitmap: 1,
            dir_bitmap: 0,
            req_count: 150,
            start_index: 3,
            max_reply: 8000,
            path: AfpPath::here(),
        },
        Request::OpenFork {
            resource: true,
            vol: 1,
            dir: 2,
            bitmap: 0x0800,
            mode: 3,
            path: path.clone(),
        },
        Request::Read {
            ext: true,
            fork: 9,
            offset: 1 << 33,
            count: 4096,
        },
        Request::Read {
            ext: false,
            fork: 9,
            offset: 10,
            count: 20,
        },
        Request::Write {
            ext: true,
            from_end: false,
            fork: 9,
            offset: 5,
            count: 3,
        },
        Request::GetForkParms {
            fork: 9,
            bitmap: 0x0200,
        },
        Request::SetForkParms {
            fork: 9,
            bitmap: wire::file_bit::EXT_DATA_FORK_LEN,
            length: 1 << 40,
        },
        Request::SetForkParms {
            fork: 9,
            bitmap: wire::file_bit::DATA_FORK_LEN,
            length: 7,
        },
        Request::CloseFork { fork: 9 },
        Request::FlushFork { fork: 9 },
        Request::Flush { vol: 1 },
        Request::CreateFile {
            hard: true,
            vol: 1,
            dir: 2,
            path: path.clone(),
        },
        Request::CreateDir {
            vol: 1,
            dir: 2,
            path: path.clone(),
        },
        Request::Delete {
            vol: 1,
            dir: 2,
            path: path.clone(),
        },
        Request::ResolveId {
            vol: 1,
            id: 42,
            bitmap: 0x0140,
        },
        Request::GetUserInfo {
            this_user: true,
            user_id: 0,
            bitmap: 3,
        },
    ];
    for req in requests {
        let bytes = wire::encode_request(&req);
        assert_eq!(wire::parse_request(&bytes).unwrap(), req, "{bytes:02x?}");
    }
}

#[test]
fn cleartext_logins_carry_the_user_and_an_eight_byte_password_on_an_even_boundary() {
    let login = wire::Login {
        ext: false,
        version: "AFP3.1".into(),
        uam: wire::uam::CLEARTXT_PASSWRD.into(),
        user: Some("bob".into()),
        password: Some(b"hunter2".to_vec()),
    };
    let bytes = wire::encode_request(&Request::Login(login.clone()));
    // cmd, "AFP3.1", "Cleartxt Passwrd", "bob" = 1+7+17+4 = 29 bytes, one pad, eight bytes.
    assert_eq!(bytes.len(), 29 + 1 + 8);
    assert_eq!(&bytes[30..], b"hunter2\0");
    assert_eq!(wire::parse_request(&bytes).unwrap(), Request::Login(login));

    // netatalk's test client's FPLoginExt: user type 3, an empty type-3 directory name, pad.
    let ext = wire::Login {
        ext: true,
        version: "AFP3.4".into(),
        uam: wire::uam::CLEARTXT_PASSWRD.into(),
        user: Some("bob".into()),
        password: Some(b"pw".to_vec()),
    };
    let bytes = wire::encode_request(&Request::Login(ext.clone()));
    assert_eq!(bytes.len() % 2, 0);
    assert_eq!(wire::parse_request(&bytes).unwrap(), Request::Login(ext));

    // A guest login carries nothing after the UAM.
    let guest = wire::Login {
        ext: false,
        version: "AFP3.4".into(),
        uam: wire::uam::NO_USER_AUTHENT.into(),
        user: None,
        password: None,
    };
    let bytes = wire::encode_request(&Request::Login(guest.clone()));
    assert_eq!(bytes.len(), 1 + 7 + 16);
    assert_eq!(wire::parse_request(&bytes).unwrap(), Request::Login(guest));

    // A cleartext login cut short is a parameter error.
    let mut short = wire::encode_request(&Request::Login(wire::Login {
        ext: false,
        version: "AFP3.1".into(),
        uam: wire::uam::CLEARTXT_PASSWRD.into(),
        user: Some("bob".into()),
        password: Some(b"x".to_vec()),
    }));
    short.truncate(short.len() - 3);
    assert_eq!(
        wire::parse_request(&short).unwrap_err().code,
        err::PARAM_ERR
    );
}

#[test]
fn an_unknown_command_is_unsupported_and_a_truncated_one_is_a_parameter_error() {
    assert_eq!(
        wire::parse_request(&[wire::cmd::RENAME, 0, 0, 1]).unwrap(),
        Request::Unsupported {
            code: wire::cmd::RENAME
        }
    );
    for code in [
        wire::cmd::OPEN_FORK,
        wire::cmd::ENUMERATE_EXT2,
        wire::cmd::READ_EXT,
        wire::cmd::GET_FILE_DIR_PARMS,
    ] {
        assert_eq!(
            wire::parse_request(&[code, 0, 0]).unwrap_err().code,
            err::PARAM_ERR,
            "{}",
            wire::command_name(code)
        );
    }
    assert!(wire::parse_request(&[]).is_err());
    // A negative FPRead offset is refused rather than wrapped.
    let mut read = vec![wire::cmd::READ, 0, 0, 1];
    read.extend_from_slice(&(-1i32).to_be_bytes());
    read.extend_from_slice(&10u32.to_be_bytes());
    read.extend_from_slice(&[0, 0]);
    assert_eq!(wire::parse_request(&read).unwrap_err().code, err::PARAM_ERR);
}

#[test]
fn server_info_round_trips_and_has_the_afp3_offsets() {
    let info = wire::ServerInfo {
        machine_type: "NetGet".into(),
        versions: vec!["AFP3.3".into(), "AFP3.4".into()],
        uams: vec!["No User Authent".into(), "Cleartxt Passwrd".into()],
        flags: wire::srvr_flag::SERVER_SIGNATURE
            | wire::srvr_flag::TCP_IP
            | wire::srvr_flag::UTF8_SERVER_NAME,
        server_name: "Studio".into(),
        signature: Some([7; 16]),
        addresses: vec![(2, vec![127, 0, 0, 1, 0x12, 0x34])],
        utf8_server_name: Some("Studio".into()),
    };
    let b = wire::encode_server_info(&info);
    // Server name at 10, padded to even ("Studio" + length = 7 -> 8), then four offsets.
    assert_eq!(&b[10..17], b"\x06Studio");
    let machine = u16::from_be_bytes([b[0], b[1]]) as usize;
    assert_eq!(
        machine,
        18 + 8,
        "machine type right after the AFP 3 offsets"
    );
    let back = wire::decode_server_info(&b).unwrap();
    assert_eq!(back, info);
    assert_eq!(back.address_strings(), vec!["127.0.0.1:4660".to_string()]);
}

#[test]
fn volume_parameters_put_the_name_after_the_fixed_part() {
    let v = wire::VolumeParams {
        attributes: wire::vol_attr::SUPPORTS_UTF8_NAMES,
        signature: 2,
        created: 1,
        modified: 2,
        backup: wire::DATE_NEVER,
        id: 1,
        bytes_free: 1 << 35,
        bytes_total: 1 << 36,
        name: "Share".into(),
        block_size: 4096,
    };
    let b = wire::encode_vol_params(wire::vol_bit::VOLUME_ID | wire::vol_bit::NAME, &v).unwrap();
    assert_eq!(b, vec![0, 1, 0, 4, 5, b'S', b'h', b'a', b'r', b'e']);
    let all = wire::encode_vol_params(wire::vol_bit::ALL, &v).unwrap();
    let back = wire::decode_vol_params(wire::vol_bit::ALL, &all).unwrap();
    assert_eq!(back, v);
    // 32-bit byte counts saturate.
    let small = wire::encode_vol_params(wire::vol_bit::BYTES_FREE, &v).unwrap();
    assert_eq!(small, vec![0xff; 4]);
    assert_eq!(
        wire::encode_vol_params(1 << 12, &v).unwrap_err(),
        err::BITMAP_ERR
    );
}

#[test]
fn file_parameters_lay_out_names_after_the_fixed_part_in_netatalks_order() {
    let f = file("notes.txt", 23, 12);
    let bitmap = wire::file_bit::LONG_NAME | wire::file_bit::NODE_ID | wire::file_bit::UTF8_NAME;
    let b = wire::encode_node_params(bitmap, &f).unwrap();
    // long-name offset(2) node(4) utf8-offset(2)+pad(4) = 12, then the long name, then UTF-8.
    assert_eq!(&b[..2], &[0, 12]);
    assert_eq!(&b[2..6], &23u32.to_be_bytes());
    assert_eq!(&b[6..8], &[0, 22]);
    assert_eq!(&b[8..12], &[0, 0, 0, 0]);
    assert_eq!(&b[12..22], b"\x09notes.txt");
    assert_eq!(&b[22..26], &wire::UTF8_HINT.to_be_bytes());
    assert_eq!(&b[26..28], &[0, 9]);
    assert_eq!(&b[28..], b"notes.txt");
    let back = wire::decode_node_params(bitmap, false, &b).unwrap();
    assert_eq!(back.name, "notes.txt");
    assert_eq!(back.node_id, 23);

    let all_file = wire::file_bit::SUPPORTED;
    let b = wire::encode_node_params(all_file, &f).unwrap();
    let back = wire::decode_node_params(all_file, false, &b).unwrap();
    assert_eq!(back, f);
    let d = dir("photos", 30);
    let all_dir = wire::dir_bit::SUPPORTED;
    let b = wire::encode_node_params(all_dir, &d).unwrap();
    assert_eq!(wire::decode_node_params(all_dir, true, &b).unwrap(), d);

    // Bits AFP does not define for the kind, and the obsolete launch limit, are refused.
    assert_eq!(
        wire::encode_node_params(wire::file_bit::LAUNCH_LIMIT, &f).unwrap_err(),
        err::BITMAP_ERR
    );
    assert_eq!(
        wire::encode_node_params(1 << 14, &d).unwrap_err(),
        err::BITMAP_ERR
    );
}

#[test]
fn unix_access_rights_are_user_world_group_owner() {
    assert_eq!(
        wire::access_rights(0o100644, true).to_be_bytes(),
        [0x80 | 0x02 | 0x04, 0x02, 0x02, 0x02 | 0x04]
    );
    assert_eq!(
        wire::access_rights(0o040755, false).to_be_bytes(),
        [0x80 | 0x03, 0x03, 0x03, 0x03]
    );
}

#[test]
fn enumerate_replies_pad_entries_and_stop_at_both_bounds() {
    let nodes = vec![file("a.txt", 20, 1), dir("bb", 21), file("ccc", 22, 3)];
    let fb = wire::file_bit::NODE_ID | wire::file_bit::LONG_NAME;
    let db = wire::dir_bit::NODE_ID | wire::dir_bit::LONG_NAME;
    for kind in [
        EnumerateKind::Classic,
        EnumerateKind::Ext,
        EnumerateKind::Ext2,
    ] {
        let (b, n) = wire::encode_enumerate_reply(kind, fb, db, &nodes, 100, 10_000).unwrap();
        assert_eq!(n, 3);
        let back = wire::decode_enumerate_reply(kind, &b).unwrap();
        assert_eq!(
            back.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
            ["a.txt", "bb", "ccc"]
        );
        assert!(back[1].is_dir);
        // Each entry is padded to even length.
        let first_len = match kind {
            EnumerateKind::Classic => b[6] as usize,
            _ => u16::from_be_bytes([b[6], b[7]]) as usize,
        };
        assert_eq!(first_len % 2, 0);
        // The entry count bound.
        let (_, n) = wire::encode_enumerate_reply(kind, fb, db, &nodes, 2, 10_000).unwrap();
        assert_eq!(n, 2);
        // The size bound: room for the header and one entry only.
        let (b1, n) =
            wire::encode_enumerate_reply(kind, fb, db, &nodes, 100, 6 + first_len).unwrap();
        assert_eq!((n, b1.len()), (1, 6 + first_len));
        // Not even one entry fits: a parameter error, as netatalk answers.
        assert_eq!(
            wire::encode_enumerate_reply(kind, fb, db, &nodes, 100, 8).unwrap_err(),
            err::PARAM_ERR
        );
    }
    // An entry too long for FPEnumerate's one-byte length is refused, not truncated.
    let long = file(&"n".repeat(240), 40, 1);
    assert_eq!(
        wire::encode_enumerate_reply(
            EnumerateKind::Classic,
            wire::file_bit::LONG_NAME | wire::file_bit::UTF8_NAME,
            0,
            &[long],
            10,
            10_000
        )
        .unwrap_err(),
        err::PARAM_ERR
    );
}

#[test]
fn decoders_refuse_lengths_past_the_end() {
    assert!(wire::decode_server_info(&[0, 200, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    assert!(wire::decode_srvr_parms(&[0, 0, 0, 0, 3, 0, 5, b'a']).is_err());
    assert!(
        wire::decode_enumerate_reply(EnumerateKind::Ext2, &[0, 1, 0, 0, 0, 1, 0, 200, 0, 0])
            .is_err()
    );
    assert!(wire::decode_node_params(wire::file_bit::LONG_NAME, false, &[0, 50]).is_err());
    assert!(wire::decode_open_fork_reply(&[0, 0, 0, 0]).is_err());
}

/// A whole synthetic session through tshark's `dsi` and `afp` dissectors: every reply builder
/// NetGet's server uses, in the order a client sees them.
#[test]
fn tshark_reads_a_synthetic_session_without_complaint() {
    let next = std::cell::Cell::new(0u16);
    let req = |command: u8, code: u32, payload: &[u8]| {
        let id = next.get() + 1;
        next.set(id);
        (
            id,
            dsi::message(dsi::FLAG_REQUEST, command, id, code, payload),
        )
    };
    let reply = |command: u8, id: u16, code: i32, payload: &[u8]| {
        dsi::message(dsi::FLAG_REPLY, command, id, code as u32, payload)
    };
    let mut o = PcapOracle::tcp("afp").also_named("afp").port(548);
    let info = wire::ServerInfo {
        machine_type: "NetGet".into(),
        versions: vec!["AFP3.4".into()],
        uams: vec!["Cleartxt Passwrd".into()],
        flags: wire::srvr_flag::SERVER_SIGNATURE | wire::srvr_flag::UTF8_SERVER_NAME,
        server_name: "Studio".into(),
        signature: Some([1; 16]),
        addresses: vec![],
        utf8_server_name: Some("Studio".into()),
    };
    let (i, m) = req(dsi::command::OPEN_SESSION, 0, &[1, 4, 0, 0, 4, 0]);
    o = o.to_server(&m).from_server(&reply(
        dsi::command::OPEN_SESSION,
        i,
        0,
        &dsi::encode_options(&[(0, dsi::REQUEST_QUANTUM.to_be_bytes().to_vec())]),
    ));
    let afp = |r: &Request| wire::encode_request(r);
    let cmd = |o: PcapOracle, r: Request, code: i32, body: Vec<u8>| -> PcapOracle {
        let (i, m) = req(dsi::command::COMMAND, 0, &afp(&r));
        o.to_server(&m)
            .from_server(&reply(dsi::command::COMMAND, i, code, &body))
    };
    o = cmd(o, Request::GetSrvrInfo, 0, wire::encode_server_info(&info));
    o = cmd(
        o,
        Request::Login(wire::Login {
            ext: false,
            version: "AFP3.4".into(),
            uam: wire::uam::CLEARTXT_PASSWRD.into(),
            user: Some("bob".into()),
            password: Some(b"pw".to_vec()),
        }),
        0,
        vec![],
    );
    o = cmd(
        o,
        Request::GetSrvrParms,
        0,
        wire::encode_srvr_parms(
            5,
            &[wire::VolumeListing {
                name: "Share".into(),
                has_password: false,
            }],
        ),
    );
    let vp = wire::VolumeParams {
        attributes: 0x00e4,
        signature: 2,
        id: 1,
        name: "Share".into(),
        ..Default::default()
    };
    let bitmap = wire::vol_bit::ALL;
    let mut body = bitmap.to_be_bytes().to_vec();
    body.extend(wire::encode_vol_params(bitmap, &vp).unwrap());
    o = cmd(
        o,
        Request::OpenVol {
            bitmap,
            name: "Share".into(),
            has_password: false,
        },
        0,
        body,
    );
    let fb = wire::file_bit::SUPPORTED;
    let db = wire::dir_bit::SUPPORTED;
    let nodes = vec![file("README.txt", 17, 18), dir("docs", 18)];
    let (body, _) =
        wire::encode_enumerate_reply(EnumerateKind::Ext2, fb, db, &nodes, 100, 60_000).unwrap();
    o = cmd(
        o,
        Request::Enumerate {
            kind: EnumerateKind::Ext2,
            vol: 1,
            dir: 2,
            file_bitmap: fb,
            dir_bitmap: db,
            req_count: 100,
            start_index: 1,
            max_reply: 60_000,
            path: AfpPath::here(),
        },
        0,
        body,
    );
    let body = wire::encode_file_dir_reply(fb, db, &nodes[1]).unwrap();
    o = cmd(
        o,
        Request::GetFileDirParms {
            vol: 1,
            dir: 2,
            file_bitmap: fb,
            dir_bitmap: db,
            path: AfpPath::names(&["docs"]),
        },
        0,
        body,
    );
    let mut body = fb.to_be_bytes().to_vec();
    body.extend_from_slice(&7u16.to_be_bytes());
    body.extend(wire::encode_node_params(fb, &nodes[0]).unwrap());
    o = cmd(
        o,
        Request::OpenFork {
            resource: false,
            vol: 1,
            dir: 2,
            bitmap: fb,
            mode: 1,
            path: AfpPath::names(&["README.txt"]),
        },
        0,
        body,
    );
    o = cmd(
        o,
        Request::Read {
            ext: true,
            fork: 7,
            offset: 0,
            count: 100,
        },
        err::EOF_ERR,
        b"Hello from NetGet\n".to_vec(),
    );
    // A write travels as DSIWrite: the command, then the data.
    let block = afp(&Request::Write {
        ext: true,
        from_end: false,
        fork: 7,
        offset: 0,
        count: 3,
    });
    let mut payload = block.clone();
    payload.extend_from_slice(b"abc");
    let (i, m) = req(dsi::command::WRITE, block.len() as u32, &payload);
    o = o
        .to_server(&m)
        .from_server(&reply(dsi::command::WRITE, i, 0, &3u64.to_be_bytes()));
    o = cmd(o, Request::CloseFork { fork: 7 }, 0, vec![]);
    o = cmd(o, Request::Logout, 0, vec![]);
    o.assert_clean();
}
