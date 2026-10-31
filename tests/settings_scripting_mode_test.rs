//! The saved scripting mode and `-e`/`--env` are read by one parser.
//!
//! They used to be two: the CLI accepted `on`/`auto`/`off`/`llm`/`python`/`py`/`javascript`/
//! `js`/`node`/`go`/`golang`/`perl`, while the settings file knew only `llm`/`python`/
//! `javascript`/`go`. A saved `"scripting_mode": "on"` — the shipped default mode — was warned
//! "Invalid scripting mode in settings: 'on', ignoring" on every start and never applied.

use clap::Parser;
use netget::cli::Args;
use netget::settings::Settings;
use netget::state::app_state::ScriptingMode;

/// Every spelling the `-e` help text and error message name, written out literally so this
/// test does not merely agree with whatever table the parser happens to use.
const CLI_SPELLINGS: &[(&str, ScriptingMode)] = &[
    ("on", ScriptingMode::On),
    ("auto", ScriptingMode::On),
    ("off", ScriptingMode::Off),
    ("llm", ScriptingMode::Off),
    ("python", ScriptingMode::Python),
    ("py", ScriptingMode::Python),
    ("javascript", ScriptingMode::JavaScript),
    ("js", ScriptingMode::JavaScript),
    ("node", ScriptingMode::JavaScript),
    ("go", ScriptingMode::Go),
    ("golang", ScriptingMode::Go),
    ("perl", ScriptingMode::Perl),
];

fn settings_with(value: &str) -> Settings {
    let mut settings = Settings::default();
    settings.scripting_mode = Some(value.to_string());
    settings
}

fn cli_mode(value: &str) -> anyhow::Result<Option<ScriptingMode>> {
    Args::parse_from(["netget", "-e", value]).parse_scripting_mode()
}

#[test]
fn every_value_the_cli_accepts_is_accepted_by_settings() {
    for &(spelling, expected) in CLI_SPELLINGS {
        for written in [spelling.to_string(), spelling.to_uppercase()] {
            assert_eq!(
                cli_mode(&written).expect("CLI accepts it"),
                Some(expected),
                "-e {written}"
            );
            assert_eq!(
                settings_with(&written).parse_scripting_mode(),
                Some(expected),
                "settings scripting_mode {written:?} must read as the CLI reads it"
            );
        }
    }
    // The parser's own table is the same set, so neither surface can grow a spelling alone.
    let mut table: Vec<_> = ScriptingMode::SPELLINGS.to_vec();
    let mut literal: Vec<_> = CLI_SPELLINGS.to_vec();
    table.sort_by_key(|(name, _)| *name);
    literal.sort_by_key(|(name, _)| *name);
    assert_eq!(table, literal);
}

#[test]
fn the_saved_default_on_is_applied() {
    assert_eq!(
        settings_with("on").parse_scripting_mode(),
        Some(ScriptingMode::On)
    );
}

#[test]
fn every_value_settings_writes_parses_back_through_both_surfaces() {
    let home = tempfile::tempdir().expect("temp home");
    for mode in ScriptingMode::ALL {
        let mut settings = Settings::default();
        settings.record_scripting_mode(mode);
        settings.save_at(home.path()).expect("save settings");

        let loaded = Settings::load_at(home.path()).expect("load settings");
        assert_eq!(loaded.parse_scripting_mode(), Some(mode), "{mode:?}");

        let written = loaded.scripting_mode.clone().expect("written");
        assert_eq!(cli_mode(&written).expect("CLI accepts it"), Some(mode));
    }
}

#[test]
fn an_unknown_value_is_refused_by_both_and_named() {
    let err = cli_mode("ruby").expect_err("CLI refuses ruby");
    assert!(err.to_string().contains("'ruby'"), "{err}");
    assert_eq!(settings_with("ruby").parse_scripting_mode(), None);
    assert_eq!(Settings::default().parse_scripting_mode(), None);
}
