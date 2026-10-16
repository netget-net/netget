# AFP server tests

- `codec_test.rs` — DSI and AFP codecs alone: literal bytes, round trips of every request the
  client sends and every reply the server builds, bounds, and tshark's `dsi`/`afp` dissectors
  over a synthetic session.
- `e2e_test.rs` — the in-process server from a raw DSI client (`support.rs`), with the python
  policy in `support.rs` playing the model: a guest session, writes/creates/deletes as model
  decisions, the cleartext password check, fail-closed answers (no model, wrong action, unusable
  answer, no answer), and every bound. tshark reads each recorded session.
- `real_peer_test.rs` — independent clients through a recording relay: netatalk's `afparg` and
  `asip-status`, and Nmap's `afp-serverinfo`, `afp-showmount` and `afp-ls`. They fail rather
  than skip when a peer is missing (`brew install netatalk nmap`; on Ubuntu
  `sh scripts/test-peers/build-netatalk.sh <dir>` plus `apt-get install nmap`).

No LLM calls anywhere: policies, static rules, or a model at `127.0.0.1:1` that never answers.
Nmap runs its AFP scripts only on port 548 or a port its services file names `afp`, so the test
hands it a one-line `--servicedb`.
