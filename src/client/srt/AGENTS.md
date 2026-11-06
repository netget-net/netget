# SRT caller — Beta

srt-tokio caller with `stream_id`, `latency_ms` and an optional `passphrase`, and the listener's
`announce_mss` (see `src/server/srt/AGENTS.md`). Actions: `srt_receive` (for `seconds`: messages,
bytes, MPEG-TS packets, PIDs and PMT stream types — h264, hevc, aac, mp3 — text messages, and SRT
statistics), `srt_send_file` (an operator-supplied MPEG-TS file of at most 64 MiB, 1316-byte
messages paced at `bitrate_kbps`, then a second for acknowledgements), `srt_send_text`,
`disconnect`. Each operation ends with one `srt_report`; data arriving between operations is
read and discarded. Every event carries its depth in the handler chain; an answer to an event
at depth `MAX_FOLLOWUPS` (4) is logged and not carried out, so a model that answers every
report with another send stops there.

## Local files come from `media_root` only

`srt_send_file` reads a file on this machine and streams it to the peer — the peer whose
responses the model reads — so until October 2026 its `path` was a file-exfiltration
primitive one prompt injection away (`"/home/op/.ssh/id_ed25519"`; the content gate was
format sniffing, not confinement). `client::media_root::MediaRoot`, shared with the
other media client, is the boundary: the `media_root` startup parameter, defaulting to
NetGet's own `media` directory under the platform's local-data dir (neither `$HOME`
nor the working directory, for the Git client's reasons). A path is canonicalised and
must be a regular file under the root; a relative path is resolved against the root.
Refused by name, not relocated. `tests/client/srt/media_root_test.rs` covers the
boundary for both clients.

## Maturity: Beta

All four conditions of the client bar hold, on the real-server tests in `tests/client/srt/`:

1. the peer is libsrt's srt-live-transmit — third-party, and not a library this client is built on;
2. a missing peer fails the test, never skips it;
3. a real session, completed against that server;
4. the client acts on the model's answer, asserted from the server's side: libsrt writes the mocked model's text exactly `MAX_FOLLOWUPS` times — none without the model's answers, no more than the bound. Emptying the loop over the model's actions fails it.

Verified 1 November 2026 by running the suite against the installed peer and by that mutation. The CI job that installs the peer is in `.github/workflows/protocol-pairs.yml`.
