# AFP server

AFP 3.x (Apple Filing Protocol) over DSI/TCP. NetGet is the file server; the model is its disk.

**Port**: 548 (well known, privileged: without the right to bind it the server starts on an
OS-assigned port and says so). **Status**: Experimental — see "Maturity" below.

## Code layout

- `dsi.rs` — the DSI header (16 bytes), message and reply builders, the DSIWrite command/data
  split, DSIOpenSession options, and the bounds: `REQUEST_QUANTUM` (128 KiB, advertised in
  DSIOpenSession), `MAX_COMMAND_LEN` (8 KiB, netatalk's `DSI_CMDSIZ`), `MAX_PAYLOAD_LEN` and
  `MAX_MESSAGE_LEN`. A header declaring more than `MAX_PAYLOAD_LEN` closes the connection before
  a byte of its payload is read (`decision=protocol_error`).
- `wire.rs` — every AFP byte both ways: command and error codes, request parsing
  (`parse_request`) and encoding (`encode_request`, used by the client), FPGetSrvrInfo,
  FPGetSrvrParms, volume, file and directory parameter blocks, the three enumerate reply
  flavours, AFP paths, MacRoman long names, decomposed UTF-8 names, AFP dates. Pure functions;
  fuzzed by `fuzz/fuzz_targets/afp_dsi.rs`. Layouts were checked against netatalk 4.6's
  afpd sources (status, volume, file, directory, enumerate, fork and auth) and against tshark's
  `dsi` and `afp` dissectors.
- `actions.rs` — the six events, five actions, startup parameters and metadata.
- `mod.rs` — the connection loop, the session (login, open volumes, remembered listings, open
  forks), CNIDs and every command handler.

## What the model decides, and what it does not

| Event | Raised by | Answer |
|---|---|---|
| `afp_list_volumes` | FPGetSrvrParms or FPOpenVol, once per session, only when `volumes` is not configured | `afp_volumes` |
| `afp_list_directory` | the first time a session needs a directory's entries (enumerate, parameters of an entry, a path through it) | `afp_directory_listing` |
| `afp_read_file` | FPOpenFork with read access (not for a file created empty this session) | `afp_file_content` (`encoding` utf8 or hex) |
| `afp_write_file` | each FPWrite/FPWriteExt (`operation: write`, the data as text or hex) and each FPSetForkParms length change (`operation: set_length`) | `afp_allow` |
| `afp_create` | FPCreateFile (`replace: true` for a hard create over a file) and FPCreateDir | `afp_allow` |
| `afp_delete` | FPDelete of a file or an empty directory | `afp_allow` |

`afp_deny` answers any of them with the AFP error it names (`access_denied` → kFPAccessDenied,
`not_found`, `exists`, `disk_full`, `locked`, `busy`, `misc`).

Rust decides without asking: the login, volume IDs, CNIDs, fork reference numbers, bitmaps,
paging through a remembered listing, reads from an open fork's content, kFPObjectExists for a
soft create over an existing name, kFPDirNotEmpty, kFPFileBusy (a delete of an open file),
kFPVolLocked (any change on a `read_only` volume), kFPObjectLocked (a delete of a `read_only`
entry), and kFPAccessDenied for a write through a fork not opened for writing.

An accepted create, write or delete changes the listing NetGet remembers for the session, so the
client sees the effect of what the model approved. Protocols must not implement storage: this is
a per-session memory of the model's own answers, bounded by `MAX_CACHED_LISTINGS` (cleared when
full) and gone when the session ends. A new session asks again.

## Login

`No User Authent` (when `guest_access`, the default) and `Cleartxt Passwrd` (when `username` and
`password` are configured), through FPLogin or FPLoginExt, at AFPX03, AFP3.1–3.4. The password
is compared in Rust, in constant time, on its first eight bytes — the field AFP carries — and is
never put in an event or a log line. `MAX_LOGIN_FAILURES` (5) wrong passwords close the
connection. DHX, DHX2, DHCAST128 and Kerberos are kFPBadUAM: no peer used here insists on them
(netatalk's `afparg` uses cleartext, Nmap logs in as a guest without a user name).

## CNIDs

Assigned per server from 17 (`FIRST_CNID`) keyed by volume and path, so an item keeps its ID
across sessions while the server runs; the root is 2, its parent 1. `MAX_CNIDS` (65 536) bounds
the table; past it new items get kFPMiscErr (`decision=fail_closed_cnid_exhausted`).

## Bounds

| Bound | Value | Where |
|---|---|---|
| DSI payload | `MAX_PAYLOAD_LEN` = 8 KiB + 128 KiB | `dsi.rs`, refused from the header |
| AFP command block | `MAX_COMMAND_LEN` 8 KiB | kFPParamErr |
| Write data / read reply | `REQUEST_QUANTUM` 128 KiB | advertised, enforced |
| DSIOpenSession options | 16 | kFPParamErr |
| Path elements | `MAX_PATH_ELEMENTS` 64 (ascents count) | kFPParamErr |
| Name | `MAX_NAME_BYTES` 255 | kFPParamErr |
| Enumerate reply | `MAX_ENUMERATE_ENTRIES` 1024, and the client's max reply size | |
| Listing from the model | `MAX_DIR_ENTRIES` 4096 | kFPMiscErr, `fail_closed_bad_action` |
| File content / size | `MAX_FILE_BYTES` 16 MiB | kFPMiscErr / kFPDiskFull |
| Volumes | `MAX_VOLUMES` 64 | |
| Open forks | `MAX_OPEN_FORKS` 64 | kFPTooManyFilesOpen |
| Connections | `DEFAULT_MAX_CONNECTIONS` 256 | `accept_bounded` |
| First byte, rest of a message, idle | 60 s, 30 s, `idle_timeout_secs` (300) | close, `decision=protocol_timeout` |

NetGet sends a DSITickle after `TICKLE_INTERVAL` (30 s) of sending nothing. It does not tickle
while a model call is in progress.

## Failing closed

A model call that fails, answers with an action that does not answer the question, answers
something NetGet cannot use, or answers nothing is kFPMiscErr — for every event — and never an
invented listing, invented content or a success. Decision tags: `model_answer`, `model_reject`,
`model_silent`, `fail_closed_bad_action`, `fail_closed_llm_error`, `fail_closed_llm_overloaded`,
plus `login_accepted` / `login_refused` and `protocol_error` / `protocol_timeout`.

## Not implemented

kFPCallNotSupported: FPLoginCont (no multi-step UAM), byte-range locks, FPRename,
FPMoveAndRename, FPCopyFile, FPExchangeFiles, FPCatSearch, FPSetFileDirParms and the other
setters, the desktop database, extended attributes, ACLs, Spotlight, FPMapID/FPMapName,
FPGetSessionToken/FPDisconnectOldSession (reconnect), FPZzzzz, FPOpenDir. Resource forks open
empty and refuse writes. No DSIAttention. Names in replies are decomposed UTF-8; incoming names
are compared after NFC normalisation, falling back to a case-insensitive match.

## Maturity

Experimental. Two independent clients drive it in `tests/server/afp/real_peer_test.rs` —
netatalk's `afparg` and `asip-status`, and Nmap's AFP library — and tshark's `dsi`/`afp`
dissectors read both directions; but the fuzz target has not run at length and the pair job
(`protocol-pairs.yml`, job `afp`) had not run in CI when it landed.
