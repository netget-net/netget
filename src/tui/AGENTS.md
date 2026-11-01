# The dashboard (`src/tui/`) — NetGet Console

The interactive UI. A full-screen ratatui frame, repainted whole into the alternate screen.
(The rolling-terminal TUI that used to sit behind `--legacy-tui` was removed in September
2026; `src/cli/tasks.rs` keeps the scheduled-task tick it owned.)

## The shape of the screen

```
┌ SERVERS 2 · CLIENTS 1 ───────────────────────┐┌ ACTIVITY & CHAT ─────────────────────────┐
│ ● #1  http     :8080      1⇄ ▁▂▅█▅▂ ⚠1 MANUAL││ 02:13:01 http#1  ◆ listening on 127.0.0…  │
│   ⚠ YOUR answer needed · http_request from …  ││ 02:13:04 http#1  ⇄ ⇐ 127.0.0.1:53121 conn…│
│   Running · up 2m13s · ↓1.2K ↑45K · 3 req     ││ 02:13:04 http#1  → :53121 http_request → …│
│   driver MANUAL — you answer each event here  ││ 02:13:09 http#1  ⚠ http_request from :531…│
│   [ stop     ] [ edit     ] [ rules    ]      ││ ▶ start an http server on 8080            │
│   [ driver → LLM ] [ + http client ] [ wire… ]││   Started server #1 (http)                │
│ ▾ peers  1 live · 0 recent                    ││                                           │
│   ● 127.0.0.1:53121 ↓1.2K ↑45K · 3 req ⚠      ││                                           │
│     17:13:23 http_request → send_http_response││                                           │
│ ▸ rules  1 rule · driver MANUAL               ││                                           │
│ ▸ config  2 settings                          ││                                           │
│ ✗ #2  dns      :53 bind 0.0.0.0:53: permissi… ││                                           │
│ ● #3  telnet   →127.0.0.1:2323           LLM  ││                                           │
│   …                                           │├───────────────────────────────────────────┤
│   + new server or client                      ││ > _                                       │
└───────────────────────────────────────────────┘└───────────────────────────────────────────┘
 2 servers · 1 client │ ⚠ 1 waiting for you │ llm: qwen3 │ log:INFO │ F1 keys
```

**Left column = every instance, always visible.** One scrollable canvas of **cards**. A
card is its summary line (status glyph, id, protocol, address, live peers, a 30-second
sparkline, a **driver badge**), the requests parked for you, a facts line (status, uptime,
traffic, rate), the driver, then its **buttons as an aligned grid** — every cell as wide
as the widest label, as many per row as fit — and its **sections**: `peers` (each peer
with `[ disconnect ]` on its row and, beneath it, **the conversation on that connection**:
one row per message in `←` and per message out `→`, oldest first, the latest few with an
"… N earlier" row that lifts the cap, each row opening the full entry, then
`[ send message ]`; `[ + <proto> client ]` at the foot), `rules` (each rule with delete /
↑ / ↓ beside it and `+ add rule` below), `config` (each setting opens the form); a client
has `send` (its verbs) and `connections` (each attempt with its conversation and
`[ send message ]`) instead of `peers`. `cards::payload_summary` turns a request or an
action into the text that crossed the wire (`data`, `text`, `command`, `GET /path`, …)
rather than the JSON around it; an injected send is logged as `injected_action` with the
action as its request and renders as one outgoing row. Nothing is selected and nothing
is drilled into: ↑/↓ walk every row, ←/→ walk a row's buttons (and fold / unfold a
section), Enter presses the button or acts on the row, and the letters (`x e r m c n w d`)
act on the card under the cursor. `+ new server or client` at the foot opens one picker
listing both kinds. Rules and config start folded; everything else is open.

**Right column = one stream.** Machine events (instances starting, peers connecting and
closing, every request with the action that answered it, questions parked for you, the
`[LEVEL]` log lines filtered by level) and the conversation (what you typed, the model's
reasoning and replies, command output) are one timeline, newest at the bottom, with the
input box under it. Event lines are one row each; conversation entries wrap. PageUp or
the wheel scrolls back, ↑/↓ then walk lines and Enter opens what one points at.

Tab hops between the two columns. That is the only thing Tab does.

**Live model work has a spinner.** Each in-progress generation appears below the owning
server peer or client connection, after its messages and before `[ send message ]`, with
elapsed time and the triggering event. Connectionless work gets a bucket even before its
first request completes. Folded peers/sections and the card header still animate. Chat
replies animate beside the input; global tasks appear above it in the stream. The footer
puts the active count first so it survives narrow layouts. All use the same 100ms animation.
`state/llm_activity.rs` tracks generation lifetimes with weak handles: success, errors and
cancellation all clear the indicator, and scripts/recently completed conversations do not
count. The UI tick polls only this small registry; full snapshots keep their 1s cadence.

**Narrower than 80 columns the two columns stack** (`render::TWO_COLUMN_WIDTH`): the canvas
on top (55% of the height, leaving the stream at least six rows), the stream and the input box
under it, each the full width, and a modal takes the whole width. Below 40×24
(`render::MIN_WIDTH` / `MIN_HEIGHT`) it says the terminal is too small. The stacked layout is
what a phone gets in the browser demo: `site/js/demo.js` sizes that terminal to about 48
columns of ~10.5px text on a 390px screen, where 80 columns meant 6px.
`tests/dashboard_frame_test.rs` renders it at 40, 48, 60 and 79 columns.

## Manual first, model optional

The dashboard is built around driving instances yourself. Three mechanisms carry that:

- **Driver** (`driver.rs`): a one-word summary of an instance's `*` handler rule —
  `MANUAL` (every unmatched event parks for you), `LLM` (no wildcard rule; the instance
  instruction answers), `SILENT` (`*` → static with no actions: acknowledge, never reply),
  or `RULES` (a wildcard script/static/LLM rule — something custom). The `[ driver → … ]`
  button, and `m` on a card, cycle MANUAL → LLM → SILENT; the non-wildcard rules are kept
  untouched. It applies through `management::update_*` with only `event_handlers` set,
  which is a hot swap — no restart, no dropped connections.
- **Rules section**: the handler table inline. Enter on a rule edits it in the routing
  modal (`modal/routing.rs`); its delete / ↑ / ↓ buttons rebuild the table headlessly
  through `RoutingModel` and apply the same way; `+ add rule` opens the modal on a fresh one.
- **Send section / message a peer**: a client's own verbs as rows (Enter opens the composer
  on that verb's parameters); a server's live peer carries `[ message ]` and
  `[ disconnect ]` on its own row where the protocol registered a peer handle
  (`server/peer_support.rs`). Without a handle the buttons stay, disabled, and say why:
  a protocol declaring `ProtocolMetadataV2::request_only` (HTTP and the protocols on plain
  HTTP request/response) gives its own reason — it can only answer a request, so there is no
  "yet" — and every other protocol says messaging a peer is not implemented here yet
  (`cards::NO_PEER_HANDLE_REASON`). `tests/request_only_declaration_test.rs` keeps the
  declaration off any protocol that registers a handle.

`[ + client ]` inherits the OpenAPI server's inline spec, uses local OAuth2 endpoints, and
sets explicit HTTP URLs for local npm/PyPI/Maven and OIDC servers. Unknown client IDs and
optional secrets stay editable in the normal focused form. The browser page API opens that
same form when it needs input. OpenAPI forms require an inline spec or (clients only) a
spec file; either one satisfies the requirement. OIDC's initial discovery, like other
client connect events, is acknowledged with no actions so Apply can finish before a send.

Instances created here default to `*` → manual (see `modal/form.rs`), so the first thing you
see after starting a server and poking it with `curl` is `⚠ … waiting for YOUR answer`, in
the list badge, the inspector overview, the feed, and the status bar.

## Modules

| file | what |
|---|---|
| `mod.rs` | `run_dashboard` entry, model resolution, channel wiring |
| `app.rs` | `DashboardApp`: focus, the canvas cursor, fold state, snapshot, modal stack |
| `event_loop.rs` | terminal lifecycle; the select loop; status-line routing; snapshot absorption |
| `projection.rs` | `AppState` → owned `RailSnapshot` (`ServerRow` / `ClientRow`) under short locks |
| `rail.rs` | the one-line instance summary a card's header renders |
| `cards.rs` | the canvas model: every card's rows, buttons, sections, fold state |
| `driver.rs` | `Driver` detection from a handler table and rebuilding the table for a new driver |
| `activity.rs` | the stream ring (events and conversation), and `Tracker::diff`, which turns two snapshots into events |
| `metrics.rs` | per-instance throughput samples, rates, sparklines, byte formatting |
| `chat.rs` | `route_status_line`: a status line becomes a log entry or a conversation entry |
| `actions.rs` | every instance action (`InstanceAction`) executed in one place |
| `keymap.rs` | global keys, focus cycling, per-pane keys, mouse |
| `modal_keys.rs` | input handling for every modal |
| `hit.rs` | per-frame hit-test registry for the mouse |
| `render/` | one file per pane plus `overlay.rs` for modals |
| `modal/` | forms, composer, routing editor, intercept answer, picker, help, wireshark |
| `wireshark.rs` | protocol → dissector/capture-filter table; leads with `wireshark -r <file>` when NetGet is writing the instance's own pcap (`ServerRow::capture` / `ClientRow::capture`, from `src/capture/`) and otherwise says how to turn that on |

The rule that keeps keyboard and mouse from drifting: an action is an `InstanceAction`, run
by `actions::run`, whatever produced it — a letter, a menu entry, Enter on an item, a click.

## Things that must not run on the event loop

Creating a server, connecting a client, sending through one, applying a routing change: all
network I/O, all spawned, all reporting back through `uimsg::UiMsg`. Awaiting one inline
froze the whole dashboard for the kernel's SYN-retry window once. `handle_ui_msg` closes the
originating modal on success and leaves it open showing the error on failure.

## Peer text is made terminal-safe at ingestion, not per renderer

ratatui's `Paragraph` writes every grapheme of width > 0 into the buffer verbatim and
`CrosstermBackend` prints each cell as is; unicode-width gives ESC, C1 and BEL a width of
one, and only `Buffer::set_string` filters controls. Every pane here is a `Paragraph`, so
until September 2026 a telnet line of `\x1b]52;c;QUJD\x07` was painted on the operator's
real terminal as the OSC 52 clipboard write it is — from the request row on a card, from a
`[LEVEL]` line quoting it, from the model's reply echoing it — and a DSR query would have
had its answer typed into the chat box as keystrokes. Three choke points now strip them
with `utils::sanitize`: `ActivityFeed::push` (every stream entry: logs, replies, reasoning,
command output, error strings), `cards::payload_summary` (the one row a request gets) and
`logging::emit::Log::emit` (the status channel and `netget.log`, which `tail -f` paints
too); `cli::non_interactive::emit_status_line` does the same for headless stdout. The
sanitizer removes a whole escape sequence (CSI, OSC and the other control strings, in 7-bit
and 8-bit form) rather than only its ESC, so neither a peer's sequence nor NetGet's own dim
styling from `llm::format_indented_dimmed_lines` is left behind as a literal `[2m`.

Pretty-printed JSON is the other way peer text reaches a pane: `serde_json` escapes
U+0000–U+001F inside a string but writes DEL and C1 (U+009B is an 8-bit CSI) raw. The request
detail modal (`modal::request_detail::detail_lines`), the intercept overlay's payload and the
band detail's `startup_params` and routing pass it through `sanitize::json_text`, which writes
each of those as its `\uXXXX` escape; the intercept's description and the band detail's
instruction lines go through `sanitize::line_field`.
`tests/dashboard_frame_test.rs::peer_escape_sequences_are_not_painted_as_terminal_cells`
renders a hostile payload through all three TUI paths and requires no control character in
any cell, and `intercept_payload_controls_are_not_painted_as_terminal_cells` does the same for
the intercept overlay; `tests/terminal_escape_injection_test.rs` covers the channel, the row,
the request detail lines and whole-sequence removal. Still
unfiltered: a protocol's own `tracing::info!("{}", peer_text)`, which the headless fmt layer
writes to stderr with ANSI on — route peer text through `Log` rather than `tracing` directly.

## Tests

- `tests/dashboard_frame_test.rs` — whole frames rendered into ratatui's `TestBackend`:
  the empty dashboard at 80×24, a populated one (peers, traffic, a parked request, an
  errored server, a client with verbs), every tab for both kinds at the minimum size, and
  what the selection does when its instance vanishes. **Start here for any layout change**;
  `--nocapture` prints the frames.
- `tests/dashboard_rail_test.rs` — the summary line, driver detection/rebuild, and the
  card rows: the button grid, sections, peers with their requests, rules, config, verbs.
- `tests/dashboard_activity_test.rs` — `Tracker::diff` emits each lifecycle/peer/request/
  waiting event exactly once; status-line routing.
- `tests/dashboard_routing_test.rs`, `dashboard_create_flow_test.rs`,
  `dashboard_wireshark_test.rs` — the modals and the create path.
- `tests/terminal_snapshot/` — the real binary in a pty: an 80×24 snapshot of the first
  frame, and `test_dashboard_starts_and_stops_a_server_from_the_keyboard`, which drives
  Tab → `a` → `tcp` → Enter → Enter → `x` with no model configured and waits on what each
  key must paint. `assert_snapshot` creates a missing snapshot and passes, so review a new
  one before trusting it.

## Progress log

- 2026-09-12: layout swapped (management left, activity + chat right); instance list +
  tabbed inspector replace the single tree; activity feed derived from snapshot diffs;
  driver badge/cycle; throughput sparklines; status bar reworked.
- 2026-09-12 (second pass): a new instance becomes the selection; the chat hard-wraps its
  rows so the newest line is always visible; `F2` cycles the right column (balanced → chat
  only → feed only); the readline chords (Ctrl-A/E/K/U/W, Alt-word keys) the legacy footer
  had are back in the chat input, taking precedence over the Ctrl-E/Ctrl-W toggles while a
  line is being typed; the pty harness gained `PtyScreen` and renders unpainted cells as
  spaces, and all six snapshots were re-recorded as real screens.

- 2026-09-13: the conversation on each connection (in / out rows, send button beneath,
  `+ client` under the peers); the legacy rolling TUI, `--legacy-tui` and its ten pty tests
  removed.
- 2026-09-12 (third pass, from operator feedback): the list + inspector split and the
  popup menu are gone. Every instance is a card that is always open with its buttons (an
  aligned grid) and sections; ↑/↓ walk every row, ←/→ the buttons; Tab only changes column.
  One picker for both kinds. Activity and chat are one stream with the input beneath it.

## Next steps

- Prefer `tests/dashboard_frame_test.rs` (ratatui `TestBackend`, deterministic, populated
  states) for layout assertions. The pty snapshots in `tests/terminal_snapshot/` need
  re-recording after any layout change (delete the `.snap.md`, run, review the new file —
  `assert_snapshot` creates a missing one and passes). Every dashboard pty test waits on
  the text its last key must paint through one `PtyScreen`; never add a fixed sleep.
- Candidates not done: fold-all / unfold-all keys once many cards are open; per-peer
  throughput; an `[ answer all ]` shortcut when several requests are parked.
