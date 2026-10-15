# SPICE client tests

No LLM calls: a python script or static rules play the model.

| File | What |
|---|---|
| `real_server_test.rs` | QEMU 8.2 (`qemu-system-x86`, `qemu-system-modules-spice` — the `-spice` option is in the module) with no disk and no NIC, password from a `secret` object, started with `-S`: the paused 640×480 surface, then `cont` over QMP and SeaBIOS's 720×400 text screen (checksum changes, `exact`, bitmaps only — the client's preferred-compression request honoured). The model, seeing that screen, types `a1`, presses Escape and clicks; QEMU's own trace events (`input_event_key_qcode`, `input_event_btn`) show each arriving. tshark over every channel through `recording_relay`. A wrong password is refused by spice-server |
| `bounds_test.rs` | A server written in the file links anything, then breaks one bound each: a surface past 4096 a side or past the pixel limit, a message header past `MAX_SERVER_MESSAGE_BYTES`, a bitmap claiming more bytes than its message carries, an image past the side limit, one clip rectangle more than `MAX_CLIP_RECTS` (all bytes present, so only the count refuses it), a main channel that never sends INIT; and the model's follow-up chain stopping at `MAX_FOLLOWUP_DEPTH` |
| `display_test.rs` | The display decoder against hand-built messages: fills through clip rectangles, bottom-up 24-bit bitmaps, a cached image stretched from the cache, COPY_BITS, and LZ_RGB / XOR fills counted as undecoded |

QEMU traces keys as qcodes, not key numbers: spice-server hands it scancodes. Its input layer
drops events while the VM is paused, so the model only types once SeaBIOS is on screen.

Mutation-checked (each made tests fail): keys never written to the inputs channel (the QEMU
test, and the server suite's keys test through NetGet's client); the model's actions dropped
(the QEMU test and the follow-up test); the size bound, the clip-rectangle bound and the message
bound removed (the matching bounds tests).
