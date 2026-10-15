# SPICE server tests

No LLM calls except `a_mocked_model_admits_and_draws` (one `open_server` and one
`spice_connection_request`, mocked). Everything else is answered by the python policy in
`support.rs` or a static rule: admit, draw a `#1e293b` background with a `#38bdf8` panel at
(80,120) 300×160 and a text line; `x` turns the panel `#16a34a`, a left click `#f97316`, other
keys `spice_no_change`. The server runs in-process with the model unreachable at `127.0.0.1:1`,
so any event the routing does not answer is a backend failure.

| File | What |
|---|---|
| `e2e_test.rs` | In-process: the screen pixel for pixel through NetGet's client, keys (shift decoded) and clicks reaching the model and its redraw reaching the client, wrong password refused before the model, admission failing closed (backend down, reject, render-without-accept, silence), the placeholder, the unanswered-input NOTIFY with the frame kept, unknown session / unoffered channel, bad link headers, an oversized message, the display stream decoded by hand, the mocked model through the binary |
| `real_client_test.rs` | spice-gtk's `spicy-screenshot` (PPM read back pixel by pixel; tshark over every channel through `recording_relay`; wrong password refused), `spicy` on Xvfb driven by `xdotool` (XTEST, not `--window`: GTK ignores synthetic events) with `xwd` reading the model's redraw off the X server, spice-html5 in headless Chrome through websockify (`html5.mjs`) |

Peers, all failing rather than skipping: `spice-client-gtk` (0.42 on Ubuntu 24.04), `xvfb`,
`xdotool`, `x11-apps` (xwd), `spice-html5` (0.2.2) + `websockify` (0.10) + node 22 + Chrome
(`NETGET_CHROME`), `tshark`. Linux only for spice-gtk and X; the spice-html5 test also runs on
macOS with `NETGET_SPICE_HTML5_DIR` pointing at a spice-html5 checkout and `websockify` on
`PATH`.

Things that cost a run each:

- spice-html5 links its inputs channel after the display: `html5.mjs` waits for
  `sc.inputs.state === "ready"` before typing, and needs `Emulation.setFocusEmulationEnabled`
  for a headless page to receive key events at all.
- A frame split into several DRAW_COPYs was captured by `spicy-screenshot` one strip in; the
  server sends one message per frame.

Mutation-checked (each made the named tests fail): ticket check removed; admission on a failed
model call; the unanswered-input NOTIFY removed; the message size bound removed; the model's
render dropped.
