# DICT Protocol Implementation

DICT (RFC 2229) dictionary server. The model is the dictionary: it supplies definitions,
matches, the database and strategy lists and the informational texts; NetGet writes every byte
of framing.

**State**: Beta (see Maturity). **Privilege**: `None` — the well-known port is 2628.
**Stack**: `ETH>IP>TCP>DICT`. **Feature**: `dict` (no dependencies).

## Library choice

None. DICT is a line protocol with one framing rule (dot-terminated, dot-stuffed text blocks),
and no maintained Rust crate implements the server side. `wire.rs` is ~300 lines of pure
functions; `mod.rs` is the session loop.

## Files

| File | What it holds |
|---|---|
| `mod.rs` | accept loop, session loop, `LineReader`, `parse_command`, the commands NetGet answers itself |
| `wire.rs` | pure rendering and parsing: `split_args`, `quoted`/`atom`, `text_lines`/`stuff`/`text_block`, `render_*`, `apply_mime`, `leading_code` |
| `actions.rs` | the `Protocol`/`Server` impls, the seven actions, the three events |

## Spec subset

| Command | Answered by | Reply |
|---|---|---|
| `DEFINE db word` | model → `dict_define {database, word}` | `150` + `151` blocks + `250`, or a 5xx |
| `MATCH db strat word` | model → `dict_match {database, strategy, word}` | `152` block + `250`, or a 5xx |
| `SHOW DB` / `SHOW DATABASES` | model → `dict_show {what: "databases"}` | `110` block + `250`, or `554` |
| `SHOW STRAT` / `SHOW STRATEGIES` | model → `dict_show {what: "strategies"}` | `111` block + `250`, or `555` |
| `SHOW INFO db` | model → `dict_show {what: "info", database}` | `112` block + `250`, or a 5xx (`550`) |
| `SHOW SERVER` | model → `dict_show {what: "server"}` | `114` block + `250` |
| `CLIENT text` | NetGet | `250 ok` |
| `STATUS` | NetGet | `210 status [netget]` |
| `HELP` | NetGet | `113` block listing the commands above + `250` |
| `OPTION MIME` | NetGet | `250 ok`, and MIME mode on for the connection |
| `OPTION <other>` | NetGet | `503 Command parameter not implemented` |
| `AUTH`, `SASLAUTH`, `SASLRESP` | NetGet | `502 Command not implemented` |
| `QUIT` | NetGet | `221 Closing Connection`, then close |
| wrong arity, unterminated quote | NetGet | `501 Syntax error, illegal parameters` |
| anything else | NetGet | `500 Syntax error, command not recognized` |

The commands NetGet answers are answered **without consulting the model**, so a stranger
typing garbage costs no model call. `tests/server/dict/e2e_test.rs` pins that through the mock's
call counts.

The banner is `220 netget DICT server <mime> <conn.pid.unixtime@netget>` — RFC 2229's
`220 text capabilities msg-id`. `<mime>` is advertised because OPTION MIME is implemented; no
AUTH capability is advertised because AUTH is not.

`!` and `*` (first-match / all databases) are passed to the model as given; there are no real
databases to search. Parameters are parsed with the RFC's quoting rules (atoms, `"…"`, `'…'`,
backslash escapes) — `dict(1)` quotes every word it sends (`define * "hello"`) and lower-cases
every command.

## What the model sees and controls

| Action | Renders |
|---|---|
| `send_dict_definitions {word, definitions:[{database, database_description, text, word?}]}` | `150 n definitions retrieved` + one `151 "word" db "description"` block each + `250 ok`; `552 no match` when empty |
| `send_dict_matches {matches:[{database, word}]}` | `152 n matches found` + `db "word"` lines + `250 ok`; `552` when empty |
| `send_dict_databases {databases:[{name, description}]}` | `110` listing + `250`; `554` when empty |
| `send_dict_strategies {strategies:[{name, description}]}` | `111` listing + `250`; `555` when empty |
| `send_dict_text {code, text}` | `112`/`113`/`114` block + `250`; any other code is refused |
| `send_dict_error {code, message?}` | one 5xx line; only 500–503, 530–532, 550–552, 554, 555; empty message → the RFC's own wording |
| `close_connection` | close after the reply |

The `dict_define` event says that a word the instructions give no definition for is no match,
answered `send_dict_error` 552. Without that sentence, told "you only know words that begin with
q" and asked `DEFINE * zebra`, llama3.1:8b answered 550 (unknown database — the error action's
example code) or 551 on 40 replayed seeds in 40; with it, 552 on 38
(`eval-results/2026-11-08-weak-cases-replay/`; `e2e_test.rs` pins the sentence).

`send_dict_definitions` takes a **top-level `word`** that the per-definition entries default
to. The executor has no view of the event, and a `151` line must name its headword, so the
model supplies it (normally copying the event's `word`). A missing word is refused by the
executor rather than rendered as `""`.

### NetGet does the framing; the model cannot

* **Dot-stuffing.** Every text line beginning with `.` gets a second one (`wire::stuff`). A
  model line that *is* `.` goes out as `..`, so the only lone `.` on the wire is the terminator
  NetGet writes. Removing the stuffing makes the real `dict(1)` fail with `Unexpected status code
  600 (line), wanted 151` — measured, see the tests CLAUDE.md.
* **Line length.** RFC 2229 caps a text line at 1024 bytes including the stuffing dot and CRLF.
  Lines longer than 1000 bytes are wrapped on a char boundary.
* **Control characters.** Text blocks keep tab and newline and lose every other control
  (`sanitize::multiline`); quoted single-line fields map controls to spaces
  (`sanitize::line_field`) so a CR cannot forge a status line, and escape `\` and `"`.
  Database/strategy names are written bare when they are atoms and quoted otherwise, so a name
  with a space cannot add a column to a listing.
* **The reply must fit the command.** After the model answers, the loop reads the reply's
  leading code: it must be the command's success code (`150` for DEFINE, `152` MATCH, `110`
  SHOW DB, `111` SHOW STRAT, `112` SHOW INFO, `114` SHOW SERVER) or a 5xx. Anything else — a
  `152` match list sent to a DEFINE — is refused with `420` and logged
  `decision=fail_closed_mismatched_reply`. Only the first reply is sent if the model produced
  several.

### OPTION MIME

RFC 2229 §3.10.1: once MIME is on, every text response is prefaced by a MIME header and a
blank line. The executor is stateless, so the **session loop** applies `wire::apply_mime` to the
rendered reply, inserting `Content-type: text/plain; charset=utf-8` /
`Content-transfer-encoding: 8bit` / blank line after each status line that opens a block. That is
unambiguous because every reply it sees was rendered by `wire.rs`: inside a block it consumes
lines until the lone `.`, and stuffing guarantees no content line is one.

Replies **injected from the dashboard** (`[ message ]`, `peer_support`) go straight from the
executor to the socket and do not get the MIME preface. That is a known limitation, not a
design choice.

Note on the real client: `dict -M` sends OPTION MIME without checking capabilities and then
prints each text block as received, header included — it does not parse MIME.

## Failure behaviour

`FailureMode::Answers`. Three outcomes put `420 Server temporarily unavailable` on the wire
and then close the connection:

| Cause | Log token |
|---|---|
| the backend failed | `decision=fail_closed_llm_error category=unavailable\|overloaded` (overloaded appends `, backend at capacity` to the 420 text) |
| the handler/model answered nothing | `decision=model_silent` |
| the reply does not answer the command | `decision=fail_closed_mismatched_reply` |

`420` because DICT has no "could not decide" code, and every 5xx NetGet could invent instead
(`552 no match`, `550 invalid database`) is a claim about the dictionary nothing made. A model
5xx is sent as-is and logged `decision=model_reject`; a success reply is
`decision=model_answer`. Both texts are byte literals, so nothing from the error reaches the
peer.

## Bounds

| Bound | Value | Override | Why |
|---|---|---|---|
| `MAX_LINE_BYTES` (= `max_inbound_bytes`) | 1024 incl. CRLF | — | RFC 2229 §2.2's MUST. Over it: `500 Syntax error, command line too long`, close, `decision=fail_closed_line_too_long`, before any handler runs. Also applied to a line with no newline once 1024 bytes are buffered. |
| `FIRST_COMMAND_TIMEOUT` | 300 s | `first_byte_timeout_secs` | Real clients answer the banner at once; 300 s is the `manual` window, for a NetGet TCP client whose banner event is parked for a human. Lower it for a public listener. |
| `IDLE_TIMEOUT` | 300 s | `idle_timeout_secs` | Between commands of a hand-driven session. `dict(1)` QUITs immediately. |
| `MAX_CONNECTIONS` | 256 (house default) | — | Each connection holds a 1 KiB buffer and a task for up to 300 s. The peer past the cap gets `420 Server temporarily unavailable` instead of `220` (RFC 2229 §3.1 allows exactly that greeting) and the socket closes. |

**Every close lingers.** After the last reply the server half-closes and then reads and
discards whatever the peer already sent, for at most 2 s / 64 KiB (`linger`). Closing a socket
with unread input makes the kernel send RST, and an RST can destroy a reply the peer has not
read yet — a `500` for an oversize line, or a `420` with pipelined commands behind it, arrived as
"connection reset" about one run in three before this. Removing `linger` makes
`connection_bounds_test`'s oversize case fail with `ConnectionReset` every time.

The deadlines wrap the `read()` only, so a command parked for a human under a `manual` rule is
never closed by either. Pipelined commands (RFC 2229 allows them) are kept in the line buffer and
answered in order.

## Peer handle

Registered before the banner, so `[ message ]`/`[ disconnect ]` work from the first moment.
Injected actions are rendered by the same executor as the model's (see the MIME caveat above).

## Wireshark

No DICT dissector in this Wireshark build (`tshark -G protocols` lists none;
`-d tcp.port==2628,dict` is rejected), so `src/tui/wireshark.rs` maps `dict` to plain TCP and
there is no pcap-oracle test.

## Maturity

Beta. Evidence: `tests/server/dict/real_client_test.rs` drives the real `dict(1)` 1.13
(dictd project; C, not linked, not written by us, and sharing no code with the server, which
uses no DICT library at all) for a lookup, `-m -s prefix`, `-D`, `-S`, `-i`, `-I`, `-M` and a
no-match lookup, and asserts on what it parsed and printed. It is not `#[ignore]`d and fails,
never skips, when the binary is absent; CI's `registry-audit` installs Ubuntu's `dict` and runs
it. Promoted after the whole suite passed three consecutive runs at `--test-threads=100` and
`scripts/beta_evidence_table.py --check` stayed green with `dict` ✓ as the peer.

What Beta does **not** cover, and what Stable would need: one client only (a second
independent DICT client — e.g. Python's `dictionary-client`, or GNU `dico` — is condition 1 of
the Stable bar); no pcap oracle (no dissector exists); no fuzz target (the parser is a flat line
splitter with no recursion, but condition 3 asks for one regardless).
