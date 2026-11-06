# Panic audit: decoding crates and the code that calls them

IMPROVEMENTS item 48. A panic inside a socket task is silent — the task dies, the server keeps
reporting `Running`, and the operator sees a protocol that stopped answering for no stated
reason. Eleven such crashes were found and fixed in one session; every one was **a length or
size field taken from the wire, or a string taken from model output, used without a bound**.
The dhcproto `chaddr()` panic was found in the DHCP *server* and then existed unfixed in the
DHCP *client*, which is the point of this document: the hazard belongs to the crate, so it
recurs in every consumer of that crate.

**Where this file should live.** It is written under `src/server/tcp/` only because that is the
ownership boundary of the pass that produced it; nothing in it is TCP-specific. Each finding's
permanent home is the *Known limitations* section of the owning protocol's
`src/server/<proto>/CLAUDE.md` or `src/client/<proto>/CLAUDE.md`, and the unassigned remainder
belongs in `IMPROVEMENTS.md` under item 48. Delete this file once both have happened.

**Method.** Crate sources read from the vendored registry
(`~/.cargo/registry/src/index.crates.io-*/<crate>-<version>/`); every crate line number below
was read, not inferred. Call sites verified in the working tree. Anything not confirmed is
marked as such rather than guessed. Two verdicts were **revised** on a second pass after a
deeper sweep — kafka-protocol from "safe" (it rejects negative counts, which is not the same as
bounding them) and pgwire from "unverified" to the worst finding here. Treat a "SAFE" verdict as
"safe against the shapes listed", not as a proof.

## Ranking

| Crate | Verdict | Worst finding | Reachable in NetGet today? |
|---|---|---|---|
| pgwire 0.35 | **RISKY** | `codec.rs:26` `split_to(i+1)` on an unterminated cstring | **Yes** — six bytes on the simple-query path |
| opensrv-mysql 0.7 | **RISKY** | `params.rs:90` explicit `panic!` on a client column-type byte | **Yes** — any prepared statement |
| kafka-protocol 0.14 | **RISKY** | `types.rs:988` unbounded reserve from a wire count | **Yes** — inner counts are unbounded |
| dhcproto 0.12 | **RISKY** | `v4/mod.rs:285` `chaddr()` slices by an unvalidated `hlen` | No — all five call sites guarded |
| cassandra-protocol 3.3 | **RISKY** | `types.rs:485` unchecked slice behind every protocol string | No — server frames by hand |
| bson 3.0 | Mixed | `raw/iter.rs:325` lossy-regex offset overrun | No — strict path only |
| rasn 0.18 | Minor | `ber/enc.rs:269` OID arc overflow (debug builds) | Yes, from model output |
| hickory-proto 0.24 | SAFE | — | — |
| bitcoin 0.32 | SAFE | — | — |

---

## Part 1 — the decoding crates

### dhcproto 0.12.0 — RISKY (the reference case)

| Crate site | API | Trigger |
|---|---|---|
| `src/v4/mod.rs:285-287` | `Message::chaddr()` | `&self.chaddr[..(self.hlen as usize)]` on a `[u8; 16]`. `hlen` is decoded straight off the wire and never validated, so **one datagram declaring `hlen > 16` panics any caller**. |
| `src/v4/mod.rs:290-300` | `Message::set_chaddr()` | Truncates the address to 16 bytes but sets `self.hlen = chaddr.len() as u8` from the *untruncated* length. Handing it 20 bytes builds a `Message` whose own `chaddr()` panics, and puts `hlen = 20` on the wire for the peer to choke on. |

Call sites, all currently guarded — keep them that way:

- `src/server/dhcp/mod.rs:294`, `src/server/bootp/mod.rs:274`, `src/client/dhcp/mod.rs:618` —
  explicit `hlen > 16` rejection before any `chaddr()` call.
- `src/server/dhcp/actions.rs:243`, `src/server/bootp/actions.rs:257` — `set_chaddr` fed by
  `parse_mac`, which caps at 32 hex characters (`dhcp/actions.rs:465`,
  `bootp/actions.rs:371`). The cap is what keeps `hlen ≤ 16`; it is load-bearing, not cosmetic.
- `src/client/dhcp/mod.rs:474, 528, 574` — `set_chaddr` fed by `parse_mac_address`
  (`client/dhcp/mod.rs:586`), which demands exactly six colon-separated bytes.

Side finding while checking that last one: `parse_mac_address` **pads the MAC to 16 bytes**
(`src/client/dhcp/mod.rs:598-600`) before `set_chaddr`, so every DISCOVER/REQUEST NetGet's DHCP
client sends declares `hlen = 16` with ten bytes of zero padding instead of `hlen = 6`. Not a
panic — a wire-correctness bug, and one a real DHCP server may key leases off.

### rasn 0.18.0 / rasn-snmp 0.18.0 — SAFE on decode, one overflow on encode

- Decoding is entirely `Result`-based; the only `panic!` sites in the crate are inside test
  macros (`rasn-0.18.0/src/lib.rs:18,32,48,64`). `ber::decode::<v2c::Message<_>>` cannot be
  made to panic by a malformed datagram, which is why `src/server/snmp/mod.rs:262,277` can call
  it inside `if let Ok(...)` and stop worrying.
- `ObjectIdentifier::new_unchecked` (`src/types/oid.rs:191`) does not panic itself but defers
  the problem: the BER encoder rejects an OID with fewer than two arcs
  (`src/ber/enc.rs:258-260`) and then computes `first * 40 + second` at `src/ber/enc.rs:269`
  with **no upper bound on `second`** — an arc near `u32::MAX` overflows, which panics in debug
  builds (the default for development, see IMPROVEMENTS item 33). Reached from
  `src/client/snmp/mod.rs:87-97`, whose `parse_oid` accepts any dotted-decimal string the model
  emits and feeds it to `new_unchecked`.
- NetGet's hand-written SNMP encoder has the identical overflow at
  `src/server/snmp/mod.rs:714` (`parts[0] * 40 + parts[1]`). Everything else there is properly
  validated — first arc ≤ 2, second < 40 unless the first is 2, at least two components — so
  the fix is one `checked_mul`/`checked_add` pair, not a rewrite.

### hickory-proto 0.24.4 — SAFE

`BinDecoder::read_slice` (`src/serialize/binary/decoder.rs:180-187`) length-checks before
`split_at`, `read_vec` goes through it, and every read returns `Restrict<T>`, a newtype that
forces the caller to state a bound before it can see the value. `Message::from_vec` is
`Result`. The `panic!`s in `src/rr/domain/name.rs:1788,1898` and `src/rr/domain/label.rs:408,413`
are all inside `#[cfg(test)]` modules. Consumers (`src/server/dns/mod.rs:92`,
`src/server/dot/mod.rs`, `src/server/doh/mod.rs`) use `queries().first()` rather than `[0]`.

Two caller-facing hazards that are *not* reachable from message parsing, recorded so nobody has
to re-derive them: `BinDecoder::clone(index_at)` (`decoder.rs:134-138`) slices
`&self.buffer[index_at as usize..]` unchecked, but its only in-crate caller
(`src/rr/domain/name.rs:1202`) first passes the compression pointer through
`verify_unwrap(|ptr| (*ptr as usize) < name_start)` at `:1193-1195`; and
`impl From<&Record> for Edns` (`src/op/edns.rs:129,146`) asserts the record type is OPT, which
holds for anything `Record::read` produced. Both bite only a caller who hand-builds the input.
Section vectors are `Vec::with_capacity(count)` from `u16` header counts
(`src/op/message.rs:640,658`), so the amplification ceiling is 65 535 elements — a few MB from a
12-byte packet, not an abort. No action.

### kafka-protocol 0.14.1 — RISKY (allocation), safe against negatives

Sign is checked everywhere; **magnitude is not checked anywhere**. Every collection in the codec
is sized directly from a wire length and allocated *before* a single element is read, so the
declared size never has to be backed by bytes actually sent.

| Crate site | API | Trigger |
|---|---|---|
| `src/protocol/types.rs:988` | `Array<E>::decode` | `Vec::with_capacity(n as usize)` with `n: i32` checked only for `>= 0`. `n = 0x7FFFFFFF` reserves 2³¹ × `size_of::<T>()` from four bytes. |
| `src/protocol/types.rs:1096` | `CompactArray<E>::decode` | `Vec::with_capacity((n - 1) as usize)`, `n` an unsigned varint — ~4×10⁹ elements from five bytes. |
| `src/protocol/types.rs:514` | `CompactString::decode` | `vec![0; (n - 1) as usize]` zeroed before `try_copy_to_slice` checks what remains — up to 4 GiB from five bytes. |
| `src/protocol/types.rs:807`, `:658` | `CompactBytes::decode`, `Bytes::decode` | same shape. |
| `src/records.rs:561`, `:1100` | `RecordBatchDecoder::decode_new_records`, `Record::decode_new` | `reserve(record_count)` / `IndexMap::with_capacity(num_headers)` from `i32`s checked only for `< 0`. |
| `src/records.rs:1063`, `:1067` | `Record::decode_new` | unchecked `i64 + i64` on two wire values (`min_timestamp + timestamp_delta`, `min_offset + offset_delta`) — overflow panic in debug builds. |

**This is reachable in NetGet.** `src/server/kafka/mod.rs:310-336` correctly bounds the *outer*
`i32` size prefix — that fix is what stopped a sign-extended prefix from shrinking the read
buffer — but nothing bounds the array counts *inside* an accepted request, and the request is
decoded at `:364` via `Decodable::decode`. A ~20-byte request declaring a 2-billion-element
array is enough. Whoever owns `kafka` should decide whether to cap counts against the message
size or wrap decode in `catch_unwind`; the crate will not do it.

I confirmed the value reaching the allocator is attacker-chosen and uncapped. Whether a given
input aborts or merely allocates depends on element size and host allocator, so this is stated
as a hazard, not as a specific reproducer.

### bson 3.0.0 — strict path safe, lossy path panics

The strict decode path is careful: `read_len` (`src/raw.rs:254-280`) validates the declared end
against the buffer, `usize_try_from_i32` (`:304`) rejects negatives, `checked_add` (`:308`)
rejects overflow, and `RawIter::verify_enough_bytes` (`src/raw/iter.rs:80`) gates every element.
Two gaps:

| Crate site | API | Trigger |
|---|---|---|
| `src/raw/iter.rs:325` | `RawElement::value_utf8_lossy_inner`, `RegularExpression` arm | The offset for the options string is `self.start_at + pattern_len + 1` where `pattern_len` is the length of the **lossy-converted** pattern. Each invalid UTF-8 byte becomes a 3-byte U+FFFD, so the offset can exceed the document, and `cstring_bytes_at` slices `&self.as_bytes()[start_at..]` (`src/raw/document.rs:483`) → panic. A 3-byte invalid-UTF-8 pattern with empty options suffices. The sibling `JavaScriptCodeWithScope` arm guards exactly this at `:302`; the regex arm was missed. |
| `src/raw.rs:322` | `reader_to_vec` | `Vec::with_capacity(length as usize)` from the 4-byte document header, checked only against a *lower* bound. A 4-byte header claiming `0x7FFFFFFF` reserves 2 GB. No 16 MB MongoDB cap is applied. |

NetGet's only ingress call is `src/server/mongodb/mod.rs:466`,
`Document::from_reader(&body[5..])` — the **strict** path, preceded by an explicit
`body.len() < 5` rejection at `:450`. So neither gap is currently reachable here. They become
reachable the moment someone uses `Utf8Lossy<Document>` or `deserialize_from_reader` to be
"tolerant of malformed input", which is the natural thing to reach for. The MongoDB
message-length handling at `:257-275` validates `16..=MAX` before subtracting, which was the
earlier `(message_length - 16) as usize` abort.

### pgwire 0.35.0 — RISKY, and NetGet's PostgreSQL server is crashable in six bytes

**Status:** NetGet builds `vendor/pgwire`, which fixes the frontend half of this (each message
isolated before its body decoder runs, checked reads, `FATAL 08P01` instead of a panic;
`vendor/pgwire/README.md`, `tests/vendored_pgwire_patch_test.rs`). The backend-message sites
below are pgwire's *client* path, which NetGet does not use, and are unchanged apart from the
framing fix. The finding stands for upstream and for `cargo install` builds.

**This is the most severe finding in the audit.** The framing layer never restricts the body
slice to the declared message length and never *lower*-bounds it. `decode_packet`
(`src/messages/codec.rs:62-83`) checks only `msg_len > max_size`, then advances past the header
and hands `decode_fn` the **entire remaining buffer** rather than a slice limited to `msg_len`.
Every `Buf::get_*` and `split_to` in every `decode_body` is therefore unguarded.

The reachable one:

- `src/messages/codec.rs:20-26` — `get_cstring` — scans `while i < buf.remaining() && buf[i] != 0`,
  then does `buf.split_to(i + 1)`. When no NUL is found the loop exits with
  `i == buf.remaining()`, so this is `split_to(remaining + 1)` — **panic**.
- Reached from `Query::decode_body` (`src/messages/simplequery.rs:36`), which is dispatched for
  the `'Q'` message type at `src/messages/mod.rs:287-288`, i.e. the ordinary simple-query path
  that `pgwire::tokio::process_socket` runs — the entry point NetGet uses at
  `src/server/postgresql/mod.rs:25`.
- Trigger, traced by hand through the code: `51 00 00 00 05 78` — `'Q'`, length 5, one byte `x`
  and no terminator. `get_length` returns 5, `remaining (6) >= 5 + 1`, `advance(5)` leaves one
  byte, no NUL, `split_to(2)` on a 1-byte buffer panics. Six bytes, no authentication, no TLS
  needed. **Verified by reading, not by execution** — someone should confirm it against a
  running server before it is written up as a CVE-shaped claim, but the code path is not
  ambiguous.

Also present, same missing-lower-bound cause: `src/messages/extendedquery.rs:276-278`
(`Vec::with_capacity(get_i16() as usize)` — a *signed* count, so `-1` becomes `usize::MAX`),
`:270` (`split_to(data_len as usize)`), `src/messages/data.rs:182` (`split_to(msg_len - 4 - 2)`,
underflow below 6), `src/messages/data.rs:73-74` and `src/messages/copy.rs:130,176,222` (signed
`i16` capacities), `src/messages/startup.rs:280` (`split_to(full_len - 4)` — the
**pre-authentication** password message), `:685` (`SASLInitialResponse`, only `-1` special-cased),
`:719`, `:209-210` (`split_to(msg_len - 8)`).

The `unreachable!()`s at `src/messages/startup.rs:560,625` and `src/messages/response.rs:273,328`
are backend-message `decode_body`s and remain the *least* of pgwire's problems; I still could not
prove them unreachable by reading alone, but they are moot next to the above.

### opensrv-mysql 0.7.0 — RISKY, already defended once

| Crate site | API | Trigger |
|---|---|---|
| `src/params.rs:90-92` | `Params::next` | `ColumnType::try_from(typmap[2 * i]).unwrap_or_else(\|e\| panic!("bad column type 0x{:x}"))` — an **explicit panic on a client-chosen byte** in `COM_STMT_EXECUTE`. |
| `src/params.rs:81` | `Params::next` | `self.input.split_at(nullmap_len)` where the NULL-bitmap length comes from the *statement* and `input` is the client's blob — panics when the blob is shorter. |
| `src/params.rs:86` | `Params::next` | `rest[1..].split_at(2 * self.params)` — panics when the new-params-bound flag is set without a full type map. |
| `src/params.rs:103` | `Params::next` | `&self.bound_types[self.col as usize]` — empty when the client clears the new-params-bound byte on the first execution → index out of bounds. |
| `src/params.rs:127` | `Params::next` | `Value::parse_from(...).unwrap()` — `parse_from` correctly returns `Err` on a truncated value and this converts it back into a panic. |
| `src/packet_reader.rs:252`, `:266` | `packet` | `assert_eq!(nseq, seq + 1)` — non-consecutive sequence bytes on a >16 MB payload; `seq + 1` is also a `u8` addition that overflows at 255 in debug builds. |
| `src/errorcodes.rs:2807` | `impl From<u16> for ErrorKind` | `_ => panic!("Unknown error type {}", x)` — anything outside its ~886-code table. |
| `src/value/decode.rs:190,212,214` | `impl From<Value> for {ints, floats, &str}` | `panic!("invalid type conversion …")`, and `from_utf8(v).unwrap()` on non-UTF-8 client bytes. |
| `src/value/decode.rs:223,229,237` | `From<Value> for NaiveDate` / `NaiveDateTime` | `assert_eq!(v.len(), 4)` on a client DATE payload, then `from_ymd_opt(...).unwrap()` — `None` for month 0 or day 0. |
| `src/value/decode.rs:322,330,345` | `From<Value> for Duration` | length assert, `unimplemented!()` on any **negative** TIME (an ordinary MySQL value), and `micros * 1_000` overflowing `u32`. |

`ErrorKind::from` is fed straight from model output in principle; `src/server/mysql/mod.rs:486`
already wraps it in `mysql_error_kind`, which allow-lists the codes a model realistically emits
and falls back to `ER_UNKNOWN_ERROR`. That is the only `ErrorKind::from` call site in the tree —
verified — and it must stay that way.

The `params.rs` cluster is the more urgent half and is **not** currently defended: it is entered
whenever a client issues a prepared statement, and five distinct malformed `COM_STMT_EXECUTE`
shapes panic inside the crate before NetGet's shim sees anything. The `value/decode.rs`
conversions fire on top of that whenever a shim reads a parameter as a typed value rather than
via `Value::to_string()`. The handshake parser (`src/commands.rs`) is nom-based and safe by
comparison.

### cassandra-protocol 3.3.0 — the most panic-prone crate of the nine, currently bypassed

`src/server/cassandra/mod.rs` imports only `Direction`, `Envelope`, `Flags`, `Opcode`, `Version`
and `Compression` (`:24-25`); request bytes are framed and parsed by hand, and that hand-written
parsing checks its lengths (`:218-223`, `:644`, `:1183`, `:1213-1234`). That accident is the only
thing keeping the following out of reach:

| Crate site | API | Trigger |
|---|---|---|
| `src/types.rs:485` | `cursor_next_value_ref` | `&cursor.get_ref()[start..start + len]` with **no** bounds check. The `if result.len() != len` guard on `:488` is dead code — the slice has already panicked. `start + len` can also overflow `usize`. |
| `src/types.rs:234`, `:244` | `from_cursor_str`, `from_cursor_str_long` | Pass a `[short]`/`[long string]` length straight into the above. **Any** protocol string whose declared length exceeds the remaining body panics; a negative length sign-extends to ~1.8×10¹⁹. |
| `src/frame.rs:157-158`, `:171` | `Envelope::from_buffer` | `try_i32_from_bytes(&data[5..9]).unwrap() as usize` then `ENVELOPE_HEADER_LEN + body_len`. `body_len = -9` wraps; version and opcode are validated *after* the length is computed, so a valid header byte plus a negative length reaches the slice on `:171`. |
| `src/frame.rs:187` | `Envelope::from_buffer` | `read_exact(...).unwrap()` — a response with the TRACING flag and fewer than 16 body bytes. |
| `src/compression.rs:155,159` | `Compression::decode_lz4` | `bytes[..4]` before any length check; then `uncompressed_size as i32` (negative sign-extends) passed as the decompression output capacity. |
| `src/types/data_serialization_types.rs:139`, `:174`, `:194` | `decode_list`, `decode_map`, `decode_tinyint` | `Vec::with_capacity(l as usize)` on signed counts; `bytes[0]` on an empty column value. |
| `src/frame/message_startup.rs:53`, `message_supported.rs:34-35`, `message_batch.rs:87,225`, `message_result.rs:485,747,784` | various `from_cursor` | `with_capacity` sized by signed `i16`/`i32` wire counts. |

**Do not switch the server to `Envelope::from_buffer`** without a `catch_unwind` boundary or an
upstream fix — a single malformed envelope header panics deterministically. Worth a note in
`src/server/cassandra/CLAUDE.md` so the hand-rolled parser is not "cleaned up" into the crate.

### bitcoin 0.32.7 — SAFE

Consensus decoding caps allocation at `MAX_VEC_SIZE = 4_000_000`
(`src/consensus/encode.rs:309`, applied at `:372` and `:667`), so a hostile `VarInt` count
cannot drive an OOM. The `panic!`s at `src/consensus/mod.rs:52-57` are internal invariant
checks on the crate's own serde bridge, and `src/p2p/message.rs:797,843` is `#[cfg(test)]`.
NetGet's own framing at `src/server/bitcoin/mod.rs:648-670` bounds the payload length. No
action.

---

## Part 2 — NetGet's own decoding paths

Same audit, applied to the code around the crates. All verified in the working tree; none are in
`tcp`, `tls` or `ssh_agent` (audited and clean — see below). Ordered by reachability.

### Unauthenticated network input

| Site | Pattern | Trigger |
|---|---|---|
| `src/client/turn/mod.rs:734-735` | wire length used as a loop bound before bounds-checking | `message_length` is read from the STUN header and never compared with `data.len()`; the `pos + 4 + attr_length > data.len()` guard at `:740` is *inside* the matching-attribute branch, so `data[pos]` at `:734` is read first. A 20-byte reply declaring `message_length = 0xFFFF` panics. Three more copies at `:813-815`, `:845-847`, `:872-874`. |
| `src/client/tftp/mod.rs:250` | inverted range on a wire length | `&data[4..n - 1]` in the ERROR arm, guarded only by `data.len() < 4` at `:155`. A 4-byte ERROR datagram yields `data[4..3]` — panic. |
| `src/server/sip/mod.rs:87` | `&str` slice off a char boundary | `&text[..200]` on a UTF-8 decode of one UDP datagram. Any multi-byte character straddling byte 200 panics the receive loop. No handshake needed. |
| `src/server/dc/mod.rs:147` | `&str` slice off a char boundary | `&command[..100]`, `command` from `String::from_utf8` of socket bytes. |
| `src/server/nntp/mod.rs:168` | `&str` slice off a char boundary | `&line[..100]` from `read_line`, pre-auth. |
| `src/client/dc/mod.rs:1618` | subtraction underflow on peer input | `lock_bytes[len - 2]` guarded only for `len == 0`. A hub sending a one-character `$Lock` challenge underflows. |
| `src/server/smb/mod.rs:639` | uncapped allocation from a wire length | `vec![0u8; length as usize]` with a `u32` taken from the SMB2 WRITE body at `:637` — up to 4 GiB per request, pre-auth, and then `read_exact` into it. (The READ path reads the same uncapped `u32` at `:579` but only reports it to the model, so it is not an allocation.) `src/server/vnc/mod.rs:435` (`MAX_CUT_TEXT_LEN`) and `src/server/amqp/mod.rs:228` (`MAX_FRAME_SIZE`) show the cap that is missing. |

The three `&str`-slice rows are the same defect the repo has already fixed twice —
`truncate_on_char_boundary` exists at `src/server/proxy/mod.rs:1448` and the history is recorded
at `src/server/irc/mod.rs:91`. Note that the `&data_str[..100]` previews in `server/udp`,
`server/http3` and `server/socket_file` are *not* in this list: they are gated on an
`is_ascii_graphic() || is_ascii_whitespace()` test, so they cannot hit a multi-byte boundary.

### Model output

| Site | Pattern | Trigger |
|---|---|---|
| `src/server/nntp/mod.rs:119`, `:239` | `&str` slice off a char boundary | `&response[..100]` on the LLM's own reply. `String::from_utf8_lossy` inserts three-byte U+FFFD, so even a lossy conversion can land mid-character. |
| `src/server/tls_cert_manager.rs:86` | `.unwrap()` on a fallible conversion | `SanType::DnsName(name.to_string().try_into().unwrap())` — rcgen rejects non-ASCII and over-length names. Safe while the SAN list is operator-supplied; a panic the moment a cert spec comes from a model or an observed SNI value. |
| `src/client/usb/mod.rs:321-324, 432, 462-463, 531-532, 600` | `.unwrap()` on `serde_json` accessors | Currently defended by validation in `src/client/usb/actions.rs:462+`, but the coupling is convention only: renaming a field or adding a `Custom` variant makes these panic on model output. |

### Overflow that defeats an existing bounds check

`src/server/usb/msc/disk.rs:101` checks `lba + count > self.total_sectors` and then slices
`self.mmap[offset..offset + length]` at `:121`, with `lba`, `count` and the products all `u32`.
In debug builds the addition panics; in release it wraps, the check passes, and the mmap slice
goes out of bounds. Same shape at `:133-155` (`write_sectors`) and `:172-184` (`zero_sectors`).
Input is the SCSI CDB carried over USB/IP.

### Uncapped allocations from wire fields (client side, DoS rather than panic)

`src/client/vnc/mod.rs:471` (`width * height * 4` from two `u16`s — ~17 TB is expressible),
`:348` (`u32` desktop-name length), `:575` (`u32` cut-text length — the *server* caps this at
`src/server/vnc/mod.rs:435`, the client does not), `:276`, `:322`.

---

## Already clean — do not re-audit

`tcp`, `tls` and `ssh_agent` were audited as part of this pass. `ssh_agent` is the only one of
the three that parses a length-prefixed wire format, and it validates: `take_framed_message`
(`src/server/ssh_agent/mod.rs:57-79`) rejects zero-length and over-cap frames before slicing and
caps at `MAX_AGENT_MESSAGE_LEN` (256 KiB, `:46`); `read_string` (`:668`) and `read_uint32`
(`:684`) check the remaining buffer before every read; `parse_message` (`:553`) rejects anything
shorter than five bytes before touching `data[4]`. Hex from the handler is decoded with
`hex::decode` and an empty result is refused rather than put on the wire. The one panic found in
the three was `tcp`'s `unwrap()` on the connection map, fixed in `99f6d073` — a lifetime bug, not
a decoding bug.

Verified-and-bounded elsewhere, so the next pass can skip them: `server/kafka` `:310-320`,
`server/zookeeper` `:234-248`, `server/mongodb` `:257-275`, `server/bgp` `:215-230`, `:699-760`,
`server/cassandra` `:644`, `:1183-1245`, `server/tor_relay` `:572-582`, `server/grpc` `:645-655`,
`server/ipsec` `:285-292`, `server/rip` `:121`, `server/isis` `:201-215`, `:591-599`,
`server/ospf` `:189`, `:503`, `:620`, `:691`, `server/bitcoin` `:648-670`, `server/torrent_peer`
`:241`, `:419`, `server/mqtt` `:730-798`, `server/amqp` `:228`, `server/git/pktline.rs:60-81`,
`server/socks5` `:764-826`, `:963`, `server/tftp` `:1049-1061`, `server/mssql` `:211-219`,
`server/ldap` `:836-847`, `client/rip` `:87`, `client/ntp` `:209`.

## What to grep for next time

```
rg 'as usize' src/ | rg 'i8|i16|i32|i64|from_be_bytes|from_le_bytes'
rg '\[\.\.[a-z_]+\]|\[[a-z_]+\.\.|split_at\(' src/
rg '\[\.\.(100|200|\d+)\]' src/          # &str previews — char boundaries
rg 'vec!\[0u8; |with_capacity\(' src/    # allocation sized by the wire
rg '\.unwrap\(\)' src/server src/client  # then filter to socket tasks
```

The recurring shapes, in the order they have actually bitten: a length field used before it is
compared with the remaining buffer; a `&str` byte-slice used as a log preview; an `i32` cast to
`usize` before its sign is checked; a subtraction on a length that can be smaller than the
constant; a fixed-width array filled from a model-supplied string.
