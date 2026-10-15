//! The beanstalkd wire format in isolation: command parsing, the byte-counted job replies, the
//! YAML reports and the reply-fits-command check, each as a property or a table.
//!
//! These run no server. They pin the guarantee the protocol's safety rests on — **whatever the
//! model writes, a client reads exactly one reply, and reads the body as body** — against every
//! string proptest can think of.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features beanstalkd --test server -- beanstalkd::wire --test-threads=100

use netget::server::beanstalkd::wire::{
    parse_command, render_inserted, render_job, render_stats, render_status, render_tube_list,
    reply_fits, valid_tube_name, Command, JobReply, MAX_JOB_BYTES, MAX_TUBE_NAME,
};
use proptest::prelude::*;

/// Read one reply the way greenstalk does: a CRLF line, and for `RESERVED`/`FOUND`/`OK` exactly
/// `<bytes>` more plus CRLF. Returns (line, payload, what is left over).
fn read_reply(wire: &[u8]) -> (String, Option<Vec<u8>>, Vec<u8>) {
    let end = wire
        .windows(2)
        .position(|w| w == b"\r\n")
        .expect("reply line ends in CRLF");
    let line = String::from_utf8(wire[..end].to_vec()).expect("reply line is ASCII");
    let rest = &wire[end + 2..];
    let words: Vec<&str> = line.split(' ').collect();
    let size = match words.as_slice() {
        ["RESERVED" | "FOUND", _, n] | ["OK", n] => Some(n.parse::<usize>().unwrap()),
        _ => None,
    };
    match size {
        Some(n) => {
            assert_eq!(&rest[n..n + 2], b"\r\n", "payload not followed by CRLF");
            (line, Some(rest[..n].to_vec()), rest[n + 2..].to_vec())
        }
        None => (line, None, rest.to_vec()),
    }
}

fn tube_name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9+/;.$_()][A-Za-z0-9+/;.$_()-]{0,199}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Any body, however many CRLFs and reply-shaped lines it holds, is read back whole and
    /// leaves nothing behind for the client to take as a second reply.
    #[test]
    fn a_job_body_round_trips_through_its_byte_count(
        body in "(\\PC|[\r\n])(\\PC|[\r\n]){0,400}",
        id in 1u64..,
        found in any::<bool>(),
    ) {
        let kind = if found { JobReply::Found } else { JobReply::Reserved };
        let wire = render_job(kind, id, &body).unwrap();
        let (line, payload, rest) = read_reply(wire.as_bytes());
        let word = if found { "FOUND" } else { "RESERVED" };
        prop_assert_eq!(line, format!("{word} {id} {}", body.len()));
        prop_assert_eq!(payload.unwrap(), body.as_bytes().to_vec());
        prop_assert!(rest.is_empty(), "bytes after the reply");
    }

    /// A stats report of valid names and printable values parses back, key for key, with
    /// greenstalk's reader (`key: value` lines after `---`).
    #[test]
    fn a_stats_report_parses_back(
        entries in proptest::collection::btree_map("[a-z][a-z0-9_-]{0,30}", "[ -~]{1,40}", 0..20)
    ) {
        let map: serde_json::Map<String, serde_json::Value> = entries
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        let wire = render_stats(&map).unwrap();
        let (line, payload, rest) = read_reply(wire.as_bytes());
        prop_assert!(line.starts_with("OK "));
        prop_assert!(rest.is_empty());
        let text = String::from_utf8(payload.unwrap()).unwrap();
        let body = text.strip_prefix("---\n").unwrap();
        let parsed: Vec<(String, String)> = body
            .lines()
            .map(|l| {
                let (k, v) = l.split_once(": ").unwrap();
                (k.to_string(), v.to_string())
            })
            .collect();
        let expected: Vec<(String, String)> = entries.into_iter().collect();
        prop_assert_eq!(parsed, expected);
    }

    /// Every generated tube name is valid, parses as one argument, and lists back.
    #[test]
    fn a_tube_name_parses_and_lists(name in tube_name()) {
        prop_assert!(valid_tube_name(&name));
        prop_assert_eq!(parse_command(&format!("use {name}")), Command::Use(name.clone()));
        let wire = render_tube_list(std::slice::from_ref(&name)).unwrap();
        let (_, payload, _) = read_reply(wire.as_bytes());
        prop_assert_eq!(payload.unwrap(), format!("---\n- {name}\n").into_bytes());
    }

    /// No line parses to a command the server would act on unless it is well-formed, and no
    /// input panics the parser.
    #[test]
    fn the_parser_never_panics(line in "\\PC{0,240}") {
        let _ = parse_command(&line);
    }
}

#[test]
fn commands_parse_as_upstream_spells_them() {
    assert_eq!(
        parse_command("put 1 2 3 4"),
        Command::Put {
            priority: 1,
            delay: 2,
            ttr: 3,
            bytes: Some(4)
        }
    );
    assert_eq!(
        parse_command("put 1 2 3 99999999999999999999"),
        Command::Put {
            priority: 1,
            delay: 2,
            ttr: 3,
            bytes: None
        },
        "a declared size past u64 is too big, not malformed"
    );
    assert_eq!(parse_command("put 4294967296 0 0 1"), Command::BadFormat);
    assert_eq!(parse_command("reserve"), Command::Reserve);
    assert_eq!(
        parse_command("reserve-with-timeout 5"),
        Command::ReserveWithTimeout(5)
    );
    assert_eq!(
        parse_command("release 3 7 0"),
        Command::Release {
            id: 3,
            priority: 7,
            delay: 0
        }
    );
    assert_eq!(parse_command("kick 10"), Command::Kick(10));
    assert_eq!(
        parse_command("stats-tube default"),
        Command::StatsTube("default".into())
    );
    assert_eq!(
        parse_command("list-tubes-watched"),
        Command::ListTubesWatched
    );
    assert_eq!(parse_command("quit"), Command::Quit);
    assert_eq!(parse_command("QUIT"), Command::Unknown);
    assert_eq!(parse_command("delete +1"), Command::BadFormat);
    assert_eq!(parse_command("use -x"), Command::BadFormat);
    assert_eq!(parse_command("use a\u{e9}"), Command::BadFormat);
    assert!(valid_tube_name(&"a".repeat(MAX_TUBE_NAME)));
    assert!(!valid_tube_name(&"a".repeat(MAX_TUBE_NAME + 1)));
}

#[test]
fn a_reply_fits_only_the_command_it_answers() {
    let inserted = render_inserted(9, false).unwrap();
    let buried_put = render_inserted(9, true).unwrap();
    let reserved = render_job(JobReply::Reserved, 9, "b").unwrap();
    let found = render_job(JobReply::Found, 9, "b").unwrap();
    let deleted = render_status("DELETED", None).unwrap();
    let buried = render_status("BURIED", None).unwrap();
    let kicked = render_status("KICKED", None).unwrap();
    let kicked_n = render_status("KICKED", Some(3)).unwrap();
    let timed_out = render_status("TIMED_OUT", None).unwrap();
    let not_found = render_status("NOT_FOUND", None).unwrap();
    let internal = render_status("INTERNAL_ERROR", None).unwrap();
    let mut one = serde_json::Map::new();
    one.insert("a".into(), 1.into());
    let stats = render_stats(&one).unwrap();
    let list = render_tube_list(&["default"]).unwrap();

    let put = Command::Put {
        priority: 0,
        delay: 0,
        ttr: 1,
        bytes: Some(1),
    };
    let cases: &[(&Command, &str, bool)] = &[
        (&put, &inserted, true),
        (&put, &buried_put, true),
        (&put, &buried, false),
        (&put, &reserved, false),
        (&Command::Reserve, &reserved, true),
        (&Command::Reserve, &timed_out, false),
        (&Command::ReserveWithTimeout(1), &timed_out, true),
        (&Command::ReserveWithTimeout(1), &found, false),
        (&Command::Delete(9), &deleted, true),
        (&Command::Delete(9), &not_found, true),
        (&Command::Delete(9), &reserved, false),
        (&Command::Bury { id: 9, priority: 1 }, &buried, true),
        (&Command::Bury { id: 9, priority: 1 }, &buried_put, false),
        (&Command::Kick(5), &kicked_n, true),
        (&Command::Kick(5), &kicked, false),
        (&Command::KickJob(9), &kicked, true),
        (&Command::KickJob(9), &kicked_n, false),
        (&Command::Peek(9), &found, true),
        (&Command::PeekReady, &reserved, false),
        (&Command::Stats, &stats, true),
        (&Command::Stats, &list, false),
        (&Command::ListTubes, &list, true),
        (&Command::ListTubes, &stats, false),
        (&Command::StatsTube("t".into()), &not_found, true),
        (&Command::Stats, &internal, true),
    ];
    for (command, reply, fits) in cases {
        assert_eq!(
            reply_fits(command, reply.as_bytes()),
            *fits,
            "{command:?} answered with {reply:?}"
        );
    }
}

#[test]
fn the_renderers_refuse_what_a_client_would_misread() {
    assert!(
        render_job(JobReply::Reserved, 0, "x").is_err(),
        "job ids start at 1"
    );
    assert!(render_job(JobReply::Reserved, 1, &"x".repeat(MAX_JOB_BYTES + 1)).is_err());
    assert!(
        render_status("INSERTED", None).is_err(),
        "INSERTED carries an id"
    );
    assert!(
        render_status("USING", None).is_err(),
        "USING is NetGet's own"
    );
    assert!(render_status("DELETED", Some(1)).is_err());
    assert_eq!(render_status("deleted", None).unwrap(), "DELETED\r\n");
    let mut bad = serde_json::Map::new();
    bad.insert("host".into(), "a\nb: c".into());
    assert!(render_stats(&bad).is_err(), "a newline would forge a stat");
    let mut bad = serde_json::Map::new();
    bad.insert("host".into(), "caf\u{e9}".into());
    assert!(
        render_stats(&bad).is_err(),
        "greenstalk decodes stats as ASCII"
    );
    let mut bad = serde_json::Map::new();
    bad.insert("a b".into(), 1.into());
    assert!(render_stats(&bad).is_err());
    assert!(render_tube_list(&["ok", "not ok"]).is_err());
}
