# pgwire 0.35.0, patched to refuse malformed frontend messages

This is pgwire **0.35.0** exactly as published on crates.io (the `.crate` whose sha256,
`8af67f4c689d97c91fb95132942f1e05eadc765448e9ffcc16e792783286d99d`, is the checksum Cargo.lock
recorded for it), with the changes below. Kept: `Cargo.toml`, both licences, `src/`, and the
`examples/` the published manifest declares as targets. The root `Cargo.toml` points
`[patch.crates-io] pgwire` here. This README is the only added file.

The unmodified tree is its own commit (`chore(vendor): add pgwire 0.35.0 exactly as published
on crates.io`), so the patch is `git log --follow -p vendor/pgwire/src` from there, or
`git diff <that commit> -- vendor/pgwire`. Every changed line carries a
`NetGet patch (vendor/pgwire/README.md)` comment.

## Why

`messages::codec::decode_packet` checks a message's declared length only from above, then hands
the body decoder **the whole remaining receive buffer** rather than the message. The frontend
decoders read with `Buf::get_*` and `BytesMut::split_to`, which panic when the bytes are not
there, and `codec::get_cstring` calls `split_to(i + 1)` one past the end when no NUL is found.
So, after a valid startup handshake:

| bytes | message | upstream 0.35.0 |
|---|---|---|
| `51 00 00 00 05 78` | Query, no NUL | panic in `get_cstring` (`bytes_mut.rs`, `split_to out of bounds`) |
| `43 00 00 00 04` | Close, no body | panic in `get_u8` |
| `44 00 00 00 04` | Describe, no body | panic in `get_u8` |
| `42 00 00 00 0f 00 00 00 00 00 01 00 00 00 64 35` | Bind, parameter declares 100 bytes, has 1 | panic in `split_to` |
| `42 00 00 00 0c 00 00 00 00 00 00 ff ff` | Bind, result-format count -1 | panic in `Vec::with_capacity` (`capacity overflow`): the count is read as `i16` |
| `51 00 00 00 05 78` `53 00 00 00 04` | Query with no NUL, then a Sync | the Query reads `xS` out of the Sync; the stream desynchronises |

The panic kills that connection's task and the peer gets no reply. NetGet contains it
(`src/server/postgresql/mod.rs` runs `process_socket` in a task of its own and logs
`decision=connection_aborted_decoder_panic`), but a malformed message should be a protocol
error, which is what PostgreSQL answers: `FATAL 08P01`.

**Upgrading does not fix it.** pgwire 0.42.1 (the newest at the time of writing) fixes
`get_cstring` the same way as here, but `decode_packet` still passes the whole buffer and
`Bind`, `Close`, `Describe`, `Execute` and `Parse` still use the panicking getters, so most of the
table above still panics; and 0.42 is edition 2024 with `rust-version = 1.89`, seven minor
versions of handler-API changes away from what `src/server/postgresql/` implements.

## The change

- `messages/codec.rs`
  - `get_cstring` returns `None` and consumes nothing when no NUL is found (as upstream 0.42
    does).
  - `decode_packet` refuses a declared length under 4, and splits off exactly the declared
    message before calling the body decoder, so no decoder can read past its own message.
  - `decode_frontend_packet`: `decode_packet` plus PostgreSQL's own end-of-message check — a
    frontend message with bytes left over is refused. That is also what refuses an
    unterminated string, which `get_cstring` leaves unconsumed.
  - `split_declared`: `split_to` for a peer-declared length, refused rather than panicking.
- `messages/mod.rs`: `PgWireFrontendMessage::decode` decodes Startup and every post-startup
  message through `decode_frontend` (the SSL/GSS negotiation and CancelRequest paths are
  unchanged). Backend decoding, which pgwire's client uses, is unchanged apart from the framing
  fix.
- `messages/extendedquery.rs` (Parse, Close, Bind, Describe, Execute) and
  `messages/startup.rs` (SASLInitialResponse): `try_get_*` and `split_declared` instead of the
  panicking reads, and Bind's result-format count read as `u16` (as upstream 0.42 does).
- `error.rs`: `PgWireError::InvalidMessageFormat(&'static str)`, mapped to `FATAL 08P01`, and
  `From<bytes::TryGetError>` into it.
- `tokio/server.rs`: `process_socket` answers a decode error other than an I/O error with that
  `ErrorResponse`, closes, and returns `Err(io::ErrorKind::InvalidData)` carrying the reason.
  Upstream ended the session silently and returned `Ok(())`. NetGet logs it as
  `decision=refused_malformed_message`.
- `Cargo.toml`: `bytes` 1.10 (the `try_get_*` methods).

What it does not do: a required string that is missing its NUL, followed by bytes that happen to
decode as the fields after it, still decodes as garbage values rather than being refused at the
string. It no longer panics or reads into the next message; making every required string
strict would touch every decoder.

## A path patch reaches only this repository's builds

`[patch.crates-io]` is not part of a published crate. `cargo install netget-tool` builds
upstream pgwire 0.35.0, where the panic is still contained per connection by
`src/server/postgresql/mod.rs`. Publishing this tree as a `netget-pgwire` crate, the way
`netget-tonic` and the other forks are, is what would carry it there.

## Re-applying it on a pgwire upgrade

`tests/vendored_pgwire_patch_test.rs` fails when Cargo.lock's pgwire is not this copy at this
version (including `[[patch.unused]]`), and drives `PgWireFrontendMessage::decode` with every
shape in the table above plus the well-formed messages, each under `catch_unwind`.
`tests/server/postgresql/decoder_panic_test.rs` asserts the `FATAL 08P01` on the wire.

1. Fetch the new source and copy `Cargo.toml`, the licences, `src/` and `examples/` over this
   directory (delete `src/` first). Check the `.crate`'s sha256 against Cargo.lock.
2. Commit that tree unmodified, on its own.
3. Re-apply the change above; `grep -n 'get_\(u\|i\)[0-9]*()\|split_to' src/messages/*.rs` for
   new frontend reads.
4. `cargo test --test vendored_pgwire_patch_test` and the PostgreSQL server suite.

If upstream bounds each message and stops panicking on short input, delete this directory and
the `[patch.crates-io]` entry instead.
