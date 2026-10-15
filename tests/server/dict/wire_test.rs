//! The DICT wire format in isolation: parameter quoting, dot-stuffing, line wrapping and the
//! OPTION MIME preface, each as a property over arbitrary model text.
//!
//! These run no server. They pin the one guarantee the protocol's safety rests on — **the
//! model cannot end a text block early or forge a status line** — against every string proptest
//! can think of, rather than against the handful the socket tests happen to send.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features dict --test server -- dict::wire --test-threads=100


use netget::server::dict::wire::{
    apply_mime, atom, quoted, render_definitions, split_args, text_block, text_lines, ArgError,
    Definition, MAX_LINE_BYTES, MIME_HEADER,
};
use netget::server::dict::{parse_command, Command};
use proptest::prelude::*;

/// Read a dot-terminated block the way RFC 2229 §2.4.1 says a client must: lines up to a lone
/// `.`, with one leading dot removed from any line that has two.
fn read_block(wire: &str) -> (Vec<String>, &str) {
    let mut lines = Vec::new();
    let mut rest = wire;
    loop {
        let end = rest.find("\r\n").expect("block is CRLF-terminated");
        let line = &rest[..end];
        rest = &rest[end + 2..];
        if line == "." {
            return (lines, rest);
        }
        lines.push(line.strip_prefix('.').unwrap_or(line).to_string());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Whatever the model writes, a client reading the block recovers exactly the lines NetGet
    /// meant to send, the block ends where NetGet ended it, and every line fits the RFC's 1024.
    #[test]
    fn a_text_block_round_trips_and_never_ends_early(text in "(\\PC|[\r\n.\t]){0,3000}") {
        let lines = text_lines(&text);
        let wire = text_block("112 database information follows", &lines);
        let body = wire.strip_prefix("112 database information follows\r\n").unwrap();
        let (read, rest) = read_block(body);
        prop_assert_eq!(&read, &lines);
        prop_assert_eq!(rest, "", "bytes after the terminator: the block ended early");
        for line in wire.split_inclusive("\r\n") {
            prop_assert!(line.len() <= MAX_LINE_BYTES, "a {}-byte line", line.len());
            prop_assert!(!line.trim_end_matches("\r\n").contains(['\r', '\n']));
        }
    }

    /// A quoted value comes back as itself through the RFC's own parameter rules — the same
    /// parser the server applies to what `dict(1)` sends.
    #[test]
    fn a_quoted_parameter_parses_back_to_itself(word in "[^\\p{Cc}]{0,200}") {
        let line = format!("DEFINE * {}", quoted(&word));
        prop_assert_eq!(
            split_args(&line).unwrap(),
            vec!["DEFINE".to_string(), "*".to_string(), word]
        );
    }

    /// An atom is one parameter whatever the name, so a listing line cannot grow a column.
    #[test]
    fn an_atom_is_always_one_parameter(name in "[^\\p{Cc}]{1,80}") {
        let args = split_args(&format!("{} {}", atom(&name), quoted("desc"))).unwrap();
        prop_assert_eq!(args.len(), 2);
        prop_assert_eq!(&args[0], &name);
    }

    /// The MIME preface lands once per text block — here, once per definition — and never
    /// inside one, even when the definition text itself begins with `151 `.
    #[test]
    fn mime_preface_is_inserted_once_per_block(n in 1usize..5, body in "(151 |\\PC|[\n.]){0,200}") {
        let defs: Vec<Definition> = (0..n).map(|i| Definition {
            word: "w".into(),
            database: format!("db{i}"),
            database_description: "D".into(),
            text: body.clone(),
        }).collect();
        let plain = render_definitions(&defs);
        let mime = String::from_utf8(apply_mime(plain.as_bytes())).unwrap();
        prop_assert_eq!(mime.matches(MIME_HEADER).count(), n);
        prop_assert_eq!(mime.replace(MIME_HEADER, ""), plain);
    }
}

#[test]
fn split_args_follows_the_rfc_quoting_rules() {
    assert_eq!(
        split_args(r#"define * "hello world""#).unwrap(),
        ["define", "*", "hello world"]
    );
    assert_eq!(
        split_args("MATCH wn . 'it''s'").unwrap(),
        ["MATCH", "wn", ".", "its"]
    );
    assert_eq!(
        split_args(r"DEFINE wn a\ b").unwrap(),
        ["DEFINE", "wn", "a b"]
    );
    assert_eq!(split_args(r#"DEFINE wn """#).unwrap(), ["DEFINE", "wn", ""]);
    assert_eq!(split_args("  SHOW   DB  ").unwrap(), ["SHOW", "DB"]);
    assert_eq!(
        split_args(r#"DEFINE wn "open"#),
        Err(ArgError::UnterminatedQuote)
    );
    assert_eq!(
        split_args("DEFINE wn trailing\\"),
        Err(ArgError::DanglingEscape)
    );
}

#[test]
fn commands_parse_case_insensitively_and_check_their_arity() {
    assert_eq!(
        parse_command(r#"define * "hello""#),
        Command::Define {
            database: "*".into(),
            word: "hello".into()
        }
    );
    assert_eq!(
        parse_command(r#"match * prefix "hel""#),
        Command::Match {
            database: "*".into(),
            strategy: "prefix".into(),
            word: "hel".into()
        }
    );
    assert_eq!(parse_command("show db"), Command::ShowDatabases);
    assert_eq!(parse_command("SHOW DATABASES"), Command::ShowDatabases);
    assert_eq!(parse_command("show strat"), Command::ShowStrategies);
    assert_eq!(
        parse_command("SHOW INFO wn"),
        Command::ShowInfo {
            database: "wn".into()
        }
    );
    assert_eq!(parse_command("show server"), Command::ShowServer);
    assert_eq!(parse_command("option mime"), Command::OptionMime);
    assert_eq!(parse_command("OPTION GZIP"), Command::OptionOther);
    assert_eq!(parse_command(r#"client "dict 1.13""#), Command::Client);
    assert_eq!(parse_command("AUTH user digest"), Command::NotImplemented);
    assert_eq!(parse_command("DEFINE onlyone"), Command::BadParameters);
    assert_eq!(parse_command("MATCH a b"), Command::BadParameters);
    assert_eq!(parse_command("SHOW INFO"), Command::BadParameters);
    assert_eq!(parse_command("SHOW NONSENSE"), Command::BadParameters);
    assert_eq!(parse_command(r#"DEFINE wn "open"#), Command::BadParameters);
    assert_eq!(parse_command("XYZZY"), Command::Unknown);
    assert_eq!(parse_command("quit"), Command::Quit);
}

#[test]
fn a_definition_renders_as_rfc_2229_describes_it() {
    let wire = render_definitions(&[Definition {
        word: "say \"hi\"".into(),
        database: "wn".into(),
        database_description: "WordNet".into(),
        text: "line one\r\n.\n..two dots\n\n".into(),
    }]);
    assert_eq!(
        wire,
        "150 1 definitions retrieved - definitions follow\r\n\
         151 \"say \\\"hi\\\"\" wn \"WordNet\" - text follows\r\n\
         line one\r\n\
         ..\r\n\
         ...two dots\r\n\
         .\r\n\
         250 ok\r\n"
    );
    assert_eq!(render_definitions(&[]), "552 no match\r\n");
}
