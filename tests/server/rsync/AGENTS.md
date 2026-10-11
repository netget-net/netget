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

`wire_test.rs` covers the codec alone:

- The whole-file MD4 against bytes captured from a stock exchange.
- The 12-byte longint.
- rsync's sort order.
- A file list round trip through demultiplexing, with frames split mid-field, a keep-alive and
  an info message.
- Unsafe names refused.
