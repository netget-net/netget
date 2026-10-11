# rsync daemon

An rsync daemon (`rsync://`, TCP 873) at **protocol 29**, hand-rolled in `wire.rs`
(shared with the client). The exact wire format, with captured bytes, was derived from rsync
3.2.7's source and checked against the stock binary in both roles; the summary below is what
to keep in mind when changing it.

## Why protocol 29

- It is the smallest version rsync 3.2.7 still speaks in full. There are no compat flags, no
  checksum or compression negotiation, and no incremental recursion.
- File indexes are plain int32, file-list fields are fixed width, and the client→daemon
  direction is never multiplexed.
- Everything is MD4.
- Advertise exactly `@RSYNCD: 29.0`: a non-zero sub-version makes a 3.2.7 client drop to 28.

## A connection

1. Greeting (and MOTD), the client's greeting, then the module line. An empty line (or
   `#list`) is a listing: the model answers `rsync_list_modules` with `rsync_modules`, and
   the daemon writes `name<TAB>comment` lines and `@RSYNCD: EXIT`.
2. `@RSYNCD: OK`, then newline-terminated arguments up to a blank line, parsed by
   `wire::parse_args`. Without `--sender` the client is uploading (see Uploads below). `-z`,
   `-U`, `-N`, `-R`, `-s` and `--files-from` are refused.
3. A raw int32 checksum seed (or `--checksum-seed=N`). From here on output is multiplexed.
   A refusal is one MSG_ERROR_XFER sent immediately; the daemon then drains the client's
   bytes so the message is not lost to a reset. An uploading client sends its file list
   here, not a filter list.
4. The filter list (raw, bounded at 64 KiB, read and ignored), then **`rsync_request`** to
   the model per path: `{module, path, recursive, list_only}`. The answer is
   `rsync_send_entries` (the module's tree at and under that path, paths relative to the
   module root, contents included) or `rsync_refuse`.
   - Directories the entries imply are added.
   - `select()` builds what rsync's sender would list for each path: `"."` plus contents for
     a trailing slash, the basename for a named file, and a named directory plus its subtree
     with `-r`.
   - The list is sorted in rsync's order (`wire::sort_key`).
   - A missing path is a `link_stat … failed` MSG_ERROR_XFER, and `io_error` is set (the
     client exits 23).
5. The file list (with `-o`/`-g`: ids, plus empty name lists), then requests. A transfer is
   echoed with its checksum header, the whole file as literal tokens in ≤ 32 KiB pieces, and
   MD4(le32(seed) ‖ data).
   - Block checksums the client offers are read and ignored: sending whole is correct, just
     not minimal.
   - A dry run's requests carry no checksum header.
6. NDX_DONE: echo the first two; the third ends the loop. Then NDX_DONE, five longint stats
   (real byte counts: zeros make rsync print a nonsense speedup), the client's goodbye, and
   close. An empty list closes right after the list, as rsync's own sender does.

## Uploads

A client without `--sender` is pushing. At protocol 29 the client→daemon direction is not
multiplexed, so its file list is read with `wire::MuxReader::raw`. It sends no filter list
unless `--delete` (or `-m`) is given, and `--delete` is refused: a daemon that stores nothing
has nothing to delete.

1. The list is sorted into rsync's order, so that indexes match the client's numbering. Then
   **`rsync_upload_request`** goes to the model: `{module, path, files (no contents),
   file_count, total_bytes}`.
2. The model answers `rsync_accept_upload` (optionally `paths`, to take only some) or
   `rsync_refuse`. No decision, or a backend failure, refuses the upload (fail closed).
   Decisions are logged `decision=model_accepted|model_refused|fail_closed_*`.
3. Each file not taken gets its own MSG_ERROR_XFER, `rsync: [receiver] <path>: <reason>`,
   which the client prints and turns into exit 23.
4. Taken files are requested one at a time, whole:
   - The request is ndx, iflags `ITEM_TRANSFER|ITEM_IS_NEW` and an all-zero checksum header.
   - The client replies with ndx, iflags, the header echoed, literal tokens, 0, and
     MD4(le32(seed) ‖ data).
   - A mismatched sum discards the file with an error.
5. The end of the run: daemon `DONE`, client `DONE`, daemon `DONE DONE`, client `DONE DONE`,
   a final `DONE`, then close. A receiver sends no stats.
6. **`rsync_upload_complete`** carries the files taken (contents as utf8 or hex) and those
   refused. It declares no actions. Nothing is written to disk; the model keeps what matters
   in memory.

An upload names one destination path, and `-H` is refused for it (the list would carry
device and inode numbers). Bounds: 1 MiB per file (checked against the declared size, and
again while the tokens arrive), 8 MiB and 1000 files per upload.

**Answers on failure:** a model that does not answer a module listing gives an empty listing.
A backend failure is `@ERROR: <category>` there, and an MSG_ERROR_XFER carrying the category
for a request. Nothing internal reaches the wire.

## Bounds

- Lines are at most 4096 bytes; at most 64 arguments and 16 paths.
- Filter rules total at most 64 KiB; one request carries at most 2^20 block sums.
- A file list holds at most 100 000 entries, and names are at most 4096 bytes.
- `idle_timeout_secs` (default 120) applies to every read.

## Not implemented

- Authentication: every module is open.
- Deleting on upload (`--delete`).
- Compression.
- Block matching (delta transfer).
- Devices and specials: the model cannot describe them.
- Hard links.
- Protocol 30+.
