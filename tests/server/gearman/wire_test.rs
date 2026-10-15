//! The Gearman wire formats in isolation: packet framing, argument splitting, request parsing,
//! the rendered answers and the admin protocol, as properties and tables.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features gearman --test server -- gearman::wire --test-threads=100


use netget::server::gearman::actions::Work;
use netget::server::gearman::wire::{self, *};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Any arguments whose leading ones hold no NUL frame and split back to themselves; the
    /// last one keeps its NULs.
    #[test]
    fn a_packet_round_trips(
        head in proptest::collection::vec(proptest::collection::vec(1u8..=255, 0..40), 0..4),
        last in proptest::collection::vec(any::<u8>(), 0..200),
        packet_type in any::<u32>(),
        request in any::<bool>(),
    ) {
        let mut args: Vec<&[u8]> = head.iter().map(|a| a.as_slice()).collect();
        args.push(&last);
        let packet = encode(request, packet_type, &args);
        let header = parse_header(&packet).unwrap();
        prop_assert_eq!(header.request, request);
        prop_assert_eq!(header.packet_type, packet_type);
        prop_assert_eq!(header.size as usize, packet.len() - HEADER_LEN);
        let split = split_args(&packet[HEADER_LEN..], args.len()).unwrap();
        prop_assert_eq!(split, args);
    }

    /// Any declared size past the bound is refused from the header alone.
    #[test]
    fn a_declared_size_past_the_bound_is_refused(size in (MAX_PACKET_BYTES as u32 + 1)..=u32::MAX) {
        let mut header = MAGIC_REQ.to_vec();
        header.extend_from_slice(&SUBMIT_JOB.to_be_bytes());
        header.extend_from_slice(&size.to_be_bytes());
        prop_assert_eq!(parse_header(&header), Err(HeaderError::TooLarge(size)));
    }

    /// Every answer the model can give reads back as the packet it meant, for any handle and
    /// payload.
    #[test]
    fn every_answer_renders_and_reads_back(
        handle in "H:[a-z]{1,8}:[0-9]{1,6}",
        payload in proptest::collection::vec(any::<u8>(), 0..200),
        n in 0u64..1000,
        d in 0u64..1000,
    ) {
        let h = handle.as_bytes();
        let cases = [
            (Work::Status(n, d), WORK_STATUS, vec![h.to_vec(), n.to_string().into_bytes(), d.to_string().into_bytes()]),
            (Work::Data(payload.clone()), WORK_DATA, vec![h.to_vec(), payload.clone()]),
            (Work::Complete(payload.clone()), WORK_COMPLETE, vec![h.to_vec(), payload.clone()]),
            (Work::Fail, WORK_FAIL, vec![h.to_vec()]),
            (Work::Exception(payload.clone()), WORK_EXCEPTION, vec![h.to_vec(), payload.clone()]),
        ];
        for (work, t, args) in cases {
            prop_assert_eq!(read_response(&work.render(h)), Some((t, args)));
        }
    }

    /// No input panics the parsers.
    #[test]
    fn the_parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = read_response(&data);
        if let Ok(header) = parse_header(&data) {
            let body = &data[HEADER_LEN..];
            let _ = parse_request(&header, &body[..body.len().min(header.size as usize)]);
        }
        let _ = parse_admin(&String::from_utf8_lossy(&data));
    }
}

fn header(packet_type: u32, size: u32) -> Header {
    Header {
        request: true,
        packet_type,
        size,
    }
}

#[test]
fn submit_variants_carry_priority_and_background() {
    for (t, priority, background) in [
        (SUBMIT_JOB, Priority::Normal, false),
        (SUBMIT_JOB_BG, Priority::Normal, true),
        (SUBMIT_JOB_HIGH, Priority::High, false),
        (SUBMIT_JOB_HIGH_BG, Priority::High, true),
        (SUBMIT_JOB_LOW, Priority::Low, false),
        (SUBMIT_JOB_LOW_BG, Priority::Low, true),
    ] {
        let data = b"reverse\0u-1\0a\0b";
        match parse_request(&header(t, data.len() as u32), data).unwrap() {
            Request::Submit {
                function,
                unique,
                workload,
                priority: p,
                background: bg,
            } => {
                assert_eq!(function, "reverse");
                assert_eq!(unique, "u-1");
                assert_eq!(workload, b"a\0b", "the workload keeps its NUL");
                assert_eq!((p, bg), (priority, background), "type {t}");
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn requests_are_classified() {
    assert_eq!(
        parse_request(&header(SUBMIT_JOB, 3), b"f\0u"),
        Err(ArgError::WrongArgCount)
    );
    assert_eq!(
        parse_request(&header(SUBMIT_JOB, 4), b"\0u\0w"),
        Err(ArgError::BadName),
        "an empty function name"
    );
    let long_unique = format!("f\0{}\0w", "u".repeat(MAX_UNIQUE + 1));
    assert_eq!(
        parse_request(&header(SUBMIT_JOB, 0), long_unique.as_bytes()),
        Err(ArgError::BadName)
    );
    for t in [CAN_DO, GRAB_JOB, GRAB_JOB_ALL, PRE_SLEEP, WORK_COMPLETE] {
        assert_eq!(parse_request(&header(t, 0), b""), Ok(Request::Worker(t)));
    }
    assert_eq!(
        parse_request(&header(35, 0), b""),
        Ok(Request::Unsupported(35))
    );
    assert_eq!(
        parse_request(&header(9999, 0), b""),
        Ok(Request::Unsupported(9999))
    );
    let res = Header {
        request: false,
        packet_type: SUBMIT_JOB,
        size: 0,
    };
    assert_eq!(
        parse_request(&res, b""),
        Ok(Request::Unsupported(SUBMIT_JOB)),
        "a \\0RES packet is not a request"
    );
    assert_eq!(
        parse_request(&header(ECHO_REQ, 3), b"a\0b"),
        Ok(Request::Echo(b"a\0b".to_vec()))
    );
    assert_eq!(parse_header(b"\0REQ\0\0"), Err(HeaderError::BadMagic));
    assert_eq!(
        parse_header(b"XREQ\0\0\0\x07\0\0\0\0"),
        Err(HeaderError::BadMagic)
    );
}

#[test]
fn errors_cannot_forge_an_argument() {
    assert!(wire::error("queue_full", "try later").is_ok());
    assert!(
        wire::error("queue full", "x").is_err(),
        "a space in the code"
    );
    assert!(wire::error("", "x").is_err());
    assert!(wire::error("code", "a\0b").is_err(), "a NUL in the text");
}

#[test]
fn the_admin_protocol() {
    assert_eq!(parse_admin("status"), AdminCommand::Status);
    assert_eq!(parse_admin("workers"), AdminCommand::Workers);
    assert_eq!(parse_admin("version"), AdminCommand::Version);
    assert_eq!(parse_admin("maxqueue f 10"), AdminCommand::MaxQueue);
    assert_eq!(parse_admin("shutdown graceful"), AdminCommand::Shutdown);
    assert_eq!(parse_admin("show jobs"), AdminCommand::Unknown);
    assert_eq!(
        admin_status(&[("reverse".into(), 2, 1, 0), ("bad\tname".into(), 1, 1, 0)]),
        "reverse\t2\t1\t0\nbad name\t1\t1\t0\n.\n",
        "a tab in a function name cannot add a column"
    );
    assert_eq!(admin_error("X", "a b"), "ERR X a+b\n");
}
