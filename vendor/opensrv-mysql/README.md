# opensrv-mysql 0.7.0, patched: no reads from freed memory, no OK for a malformed command

This is opensrv-mysql **0.7.0** exactly as published on crates.io (the `.crate` whose sha256,
`4148ab944991b0a33be74d2636a815268974578812a9e4cf7dc785325e858154`, is the checksum Cargo.lock
recorded for it), with the changes below. Kept: `Cargo.toml`, `src/`, and the `examples/` the
published manifest declares as targets. This README replaces the published one; the crate ships
no licence file (its manifest says `Apache-2.0`). The root `Cargo.toml` and `fuzz/Cargo.toml`
point `[patch.crates-io] opensrv-mysql` here.

The unmodified tree is its own commit (`chore(vendor): add opensrv-mysql 0.7.0 exactly as
published on crates.io`), so the patch is `git diff <that commit> -- vendor/opensrv-mysql`.
Every changed site carries a `NetGet patch (vendor/opensrv-mysql/README.md)` comment.

**The public API is upstream's, unchanged**, on purpose: a `[patch]` does not reach the crate
as published to crates.io, so `cargo install netget-tool` builds upstream 0.7.0, and NetGet's
MySQL server has to compile and stay safe against both. What the patch cannot reach is
defended in NetGet itself (below).

## Why

| | upstream 0.7.0 | the peer sends |
|---|---|---|
| `packet_reader.rs:132-141` | `next_async` builds the packet it returns from a raw-pointer slice of `self.bytes`, then runs `self.bytes = rest.to_vec()` before returning it whenever the read held more than one packet. The returned packet points into freed memory. | any two commands in one read. Measured: two pipelined `COM_STMT_SEND_LONG_DATA` chunks each drew a stray OK (the freed bytes no longer parsed), and every reply after was one behind. `mysql_async`'s long data, and a statement close followed by the next command, both pipeline this way. |
| `lib.rs:730` | every packet `commands::parse` rejects is answered OK | a `COM_STMT_EXECUTE` too short to name its statement: the client is told its write succeeded. A short `COM_STMT_SEND_LONG_DATA` or `COM_STMT_CLOSE`, which have no reply, get one, and the session is out of step. |
| `commands.rs` | `COM_STMT_RESET` is not parsed; it reaches the OK above and the long data stays | a reset between long data and an execute: the execute uses the data the client discarded instead of the value it sent. |

The sync `PacketReader::next` (`:44-61`) has the same raw-pointer slice but is sound: it
neither replaces nor resizes the buffer before returning, and the next call, which does, needs
the `&mut self` the returned packet borrows. It is unchanged (and unused).

## The change

- `packet_reader.rs`: `next_async` keeps the unparsed bytes as `bytes[start..start + remaining]`
  and steps `start` past a returned packet instead of replacing the buffer; the next call drains
  it. The `AsyncRead` impl (which hands buffered bytes to TLS) hands over exactly those bytes,
  not the zeroed tail of the buffer after them.
- `lib.rs`, the parse-failure arm: an empty packet or a `COM_STMT_EXECUTE` is answered ERR
  **1835 `ER_MALFORMED_PACKET`**, `Malformed communication packet.` (mysqld's text); a
  `COM_STMT_SEND_LONG_DATA` or `COM_STMT_CLOSE` gets no reply, like a well-formed one. Any other
  command the crate does not implement keeps upstream's OK, which is what its comment says the
  OK was for.
- `commands.rs` / `lib.rs`: `COM_STMT_RESET` is parsed; it discards the statement's long data and
  is answered OK.

## What stays in NetGet, and why

- **`ParamParser`'s iterator still panics** on five malformed parameter blocks (`params.rs:81`,
  `:86`, `:90-91`, `:103`, `:127`). NetGet never iterates it. Its fields are `pub(crate)`, so
  `src/server/mysql/command_tap.rs` copies each execute from beneath the crate and
  `stmt_params.rs` decodes it. An accessor here would remove that copy, but it would be an API
  upstream lacks, and the crates.io build of NetGet would stop compiling.
- **Long data is still appended without limit here** (`lib.rs:663-678`).
  `command_tap::LongDataGate` withholds chunks past 64 MiB a statement / 128 MiB a connection
  before the crate sees them, and NetGet's shim answers the next execute 1105. A bound inside the
  crate would have to answer that execute without calling the shim, which would leave the tap's
  copy of it unpaired; and it would not reach the crates.io build either.
- **The tap still hands the crate one packet per read.** With this patch the reader no longer
  needs it; the crates.io build, which runs upstream's reader, does.

## A path patch reaches only this repository's builds

`[patch.crates-io]` is not part of a published crate. `cargo install netget-tool` builds
upstream opensrv-mysql 0.7.0, where the defects above are still there and NetGet's tap is what
stands between them and the wire: one packet per read means no read ever leaves a remainder for
the freed-buffer branch, and a short execute is never captured, so the shim is not involved in
the OK upstream sends for it (that OK, and the stray one for a short long-data or close, remain
in the crates.io build). Publishing this tree as a `netget-opensrv-mysql` crate, the way
`netget-tonic` and the other forks are, is what would carry the fix there.

## Re-applying it on an upgrade

`tests/vendored_opensrv_patch_test.rs` fails when Cargo.lock's opensrv-mysql is not this copy
at this version (including `[[patch.unused]]`) or `fuzz/Cargo.toml` stops patching it, and runs
the bare crate over an in-memory pipe with every shape in the table above.
`tests/server/mysql/prepared_params_test.rs` covers the server built on it.

1. Fetch the new source and copy `Cargo.toml`, `src/` and `examples/` over this directory
   (delete `src/` first). Check the `.crate`'s sha256 against Cargo.lock.
2. Commit that tree unmodified, on its own.
3. Re-apply the change above: `grep -rn 'NetGet patch' src` in this commit lists every site.
4. `cargo test --test vendored_opensrv_patch_test` and the MySQL server suite.

If upstream fixes the reader, answers malformed commands and parses `COM_STMT_RESET`, delete
this directory and both `[patch.crates-io]` entries instead.
