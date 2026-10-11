# rsync client

Uses the daemon's protocol-29 codec (`src/server/rsync/wire.rs`; read that AGENTS.md first).
Each action is one TCP connection, as rsync itself makes one per transfer:

- **`rsync_list_modules`**: the module line is empty. Lines with a TAB are modules, the rest
  is MOTD. The answer arrives as `rsync_modules`.
- **`rsync_list{path, recursive}`**: arguments `--server --sender -ld|-lr . <path>`. No file
  requests are made, then the end-of-run exchange. The answer arrives as `rsync_listing`.
- **`rsync_fetch{path, recursive}`**: the same, then one whole-file request (no basis) for
  each regular file while `max_fetch_bytes` lasts; the rest are listed as `skipped`. Each
  file is checked against MD4(seed ‖ data). Contents arrive in `rsync_fetched`, as utf8, or
  as hex when not text.
- **`rsync_push{path, files}`**: arguments `--server -lr . <path>/`, as `rsync -rl` sends
  them. The client builds the file list itself, from the model's files plus the directories
  they imply and the `"."` root, and writes it raw: at protocol 29 nothing the client sends is
  multiplexed.
  - The daemon's generator then asks for files, multiplexed. Each transfer request is
    answered whole: the request's header echoed, literal tokens of at most 32 KiB, and
    MD4(le32(seed) ‖ data).
  - Items it only touches (directories) are echoed with their flags.
  - Up to three `DONE`s are echoed, then the final one is read.
  - The result arrives as `rsync_pushed`: `sent`, `not_requested`, and the daemon's `errors`.
  - A push that the daemon refuses outright (for example a read-only module) is an error
    carrying the daemon's message.
  - Nothing is ever deleted on the daemon.
- `@RSYNCD: AUTHREQD` is answered with `username` and base64 (no padding) of
  MD4(0000 ‖ password ‖ challenge). Without credentials the operation reports that the module
  requires authentication.

A stock daemon sends its file list in readdir order; it is sorted into rsync's order before
indexes are assigned.

Requests are written concurrently with reading the replies (`tokio::join!` of a writer and a
reader), because rsync's sender stops reading while it is blocked writing file data.

Failures (a refusal, a missing path, a checksum mismatch, a timeout of 120 s per operation)
arrive as `rsync_error`. Injected actions return the event's data as the `Executed` detail.

Chains are bounded at `MAX_FOLLOWUP_DEPTH` (8). Nothing is written to local disk.
