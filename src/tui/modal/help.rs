//! Keybinding reference. Doubles as the discovery surface for everything the
//! dashboard can do, which is why it enumerates the old slash commands too.

/// Lines of the help modal: `(key, description)`; a `None` key marks a
/// section heading.
pub fn help_lines() -> Vec<(Option<&'static str>, &'static str)> {
    vec![
        (None, "Moving around"),
        (Some("↑ / ↓"), "walk every row of every server and client"),
        (
            Some("← / →"),
            "along a row's buttons; on a section, fold / unfold it",
        ),
        (Some("Enter / Space"), "press the button, or act on the row"),
        (Some("Tab"), "between the instances and the chat (or click)"),
        (Some("Esc"), "back to the chat"),
        (Some("Ctrl-T"), "free the mouse for native text selection"),
        (Some("F1"), "this help"),
        (Some("Ctrl-C"), "quit"),
        (None, "Instances — each card has buttons and sections"),
        (
            Some("a"),
            "start a server or a client — one picker lists both",
        ),
        (Some("+ new server or client"), "the last row does the same"),
        (Some("x"), "stop a server / remove a client — immediate"),
        (
            Some("e"),
            "edit config (port, host, instruction, parameters)",
        ),
        (Some("r"), "rules: who answers each event"),
        (
            Some("m"),
            "cycle the driver: MANUAL → LLM → SILENT (keeps specific rules)",
        ),
        (
            Some("c"),
            "on a server: connect a client of its protocol to it",
        ),
        (Some("n"), "on a client: compose and send one of its verbs"),
        (Some("w"), "Wireshark / tshark capture recipe"),
        (
            Some("d"),
            "protocol description and maturity, into the stream",
        ),
        (None, "Rows — Enter acts, buttons sit on the row"),
        (
            Some("  a peer"),
            "unfold its requests; message / disconnect beside it",
        ),
        (Some("  a request"), "open its full request and response"),
        (
            Some("  a rule"),
            "edit it; delete / ↑ / ↓ beside it, + add rule below",
        ),
        (Some("  a config row"), "open the edit form"),
        (
            Some("  a verb (send)"),
            "compose it with its parameters as fields",
        ),
        (
            Some("  ⚠ waiting"),
            "answer a request a MANUAL rule parked for you",
        ),
        (None, "The stream (right column, above the chat box)"),
        (
            Some("PageUp / wheel"),
            "scroll back from the chat box; the stream takes the keys",
        ),
        (
            Some("↑ / ↓"),
            "then walk its lines; Enter opens what a line points at",
        ),
        (Some("f"), "only the lines of the card under the cursor"),
        (
            Some("Esc / End"),
            "back to the newest line and the chat box",
        ),
        (
            Some("Ctrl-L"),
            "cycle the log level the stream shows (retroactive)",
        ),
        (None, "The chat box (bottom right)"),
        (Some("Enter"), "send to the model, or run a slash command"),
        (Some("Alt-Enter / Ctrl-N"), "newline"),
        (Some("↑ / ↓"), "command history (at the first / last line)"),
        (
            Some("Ctrl-A / E / K / U / W"),
            "start / end of line · kill to end · kill line · delete word (while typing)",
        ),
        (
            Some("Alt-← / →  Alt-b / f"),
            "move by word · Alt-d deletes the next word",
        ),
        (None, "Who answers an event — the driver, and rules"),
        (
            Some("MANUAL"),
            "you: each event parks until you compose the answer",
        ),
        (
            Some("LLM"),
            "the model, from the instance instruction (needs a model)",
        ),
        (Some("SILENT"), "nobody: acknowledged, never answered"),
        (Some("STATIC"), "a rule with fixed actions, no model call"),
        (
            Some("SCRIPT"),
            "a rule running your python / js / perl / go per event",
        ),
        (None, "Global toggles"),
        (Some("Ctrl-W"), "web search: on / ask / off"),
        (Some("Ctrl-H"), "handler mode: any / script / static / llm"),
        (Some("Ctrl-E"), "scripting mode"),
        (None, "Slash commands still work in chat"),
        (
            Some("/model /backend"),
            "pick the model (click llm: on the status bar)",
        ),
        (Some("/log /web /handler"), "also Ctrl-L / Ctrl-W / Ctrl-H"),
        (Some("/docs /env /usage"), "also d on an instance"),
        (Some("/save /load"), "persist and restore instances"),
        (Some("/stop [id]"), "also x on an instance"),
        (Some("/quit"), "also Ctrl-C"),
    ]
}
