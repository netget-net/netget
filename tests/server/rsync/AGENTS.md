# rsync server tests

No LLM calls; a python policy plays the model. The policy offers modules `pub` and `mirror`.
`pub` holds:

- a text file with a set mtime;
- a binary file (hex content, mode 600);
- a 100 KiB file;
- a nested tree;
- a symlink;
- an empty file.

Any other module is refused.

`real_client_test.rs` drives the **stock rsync 3.2.7 client**, which speaks protocol 29 to
the daemon (`apt-get install rsync`). It fails rather than skips without it.

- The module list, with the MOTD.
- `--list-only`: one level, sizes. With `-l`, the symlink's target appears.
- `-a pub/`: every file compared byte for byte, the symlink, the mtime and both modes.
- One named file with no options.
- A second `-a --checksum` run onto a changed tree. The client offers block checksums, which
  are ignored, and the result is still identical.
- A dry run, which writes nothing.
- Refusals:
  - an unknown module (the model's `rsync_refuse`);
  - a missing path (exit 23, `link_stat`);
  - an upload (the policy refuses it with `module pub is read only`);
  - `-z` (refused).

`upload_test.rs` drives stock rsync pushing to NetGet. Its policy accepts `inbox`, except
`deny.txt`, refuses `ro`, and records each `rsync_upload_complete`.

- A tree with text, binary, empty and multi-chunk files, a symlink and a nested directory.
  `deny.txt` is refused per file (exit 23). Every other file's content in the event is
  compared byte for byte with the client's disk.
- One file with `-a`.
- Refusals: the `ro` module (the model's refusal), `--delete`, `-H`, and a file at the 1 MiB
  bound, which is taken, next to one a byte over it, which is not.

Mutation-checked: skipping the sort (indexes then name the wrong files) and a wrong MD4 seed
both fail.

`upload_bounds_test.rs` uses a hand-written protocol-29 uploading client (no rsync binary)
so the client can break the rules, with static handlers as the model:

- A file listed at 3 bytes that sends 11 is refused per file and none of its data reaches the
  model; its neighbour, which keeps to its size, is taken.
- Ten files listed at size 0 that each send 1 MiB: the ninth crosses `MAX_UPLOAD_BYTES`, the
  client is told `over this daemon's upload limit`, and no `rsync_upload_complete` is raised.
- A refused upload finishes the end-of-run exchange and raises no `rsync_upload_complete`.
- A refusal naming a path whose two-byte character straddles byte 4000 of the message is cut
  on a character boundary (the old byte `truncate` panicked the connection task);
  `message_text` is also checked directly for 2-, 3- and 4-byte characters.
- `file_list_bounded` with `FlistLimits::UPLOAD`: 2000 device entries pass (and are skipped),
  2001 fail; 1 MiB of names fails; the same lists pass the download bounds. End to end, an
  oversized list is refused before `rsync_upload_request` is raised.

`wire_test.rs` covers the codec alone:

- The whole-file MD4 against bytes captured from a stock exchange.
- The 12-byte longint.
- rsync's sort order.
- A file list round trip through demultiplexing, with frames split mid-field, a keep-alive and
  an info message.
- Unsafe names refused.
