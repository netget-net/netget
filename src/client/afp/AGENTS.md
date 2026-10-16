# AFP client

Logs in to an AFP 3.x file server over DSI/TCP and does what the model asks. Shares every byte
with the server: `src/server/afp/wire.rs` and `src/server/afp/dsi.rs`.

## Connect

1. DSIGetStatus on a connection of its own (servers end the session it arrives on): the
   server's name, machine type, AFP versions and UAMs.
2. A second connection: DSIOpenSession (the server's request quantum caps each read and write,
   at most `MAX_CHUNK` 128 KiB), then FPLogin at the highest AFP 3 version both sides speak —
   `Cleartxt Passwrd` with the configured `username`/`password`, or `No User Authent`. FPLogin
   rather than FPLoginExt for cleartext: netatalk's own test client does the same because
   cleartext over FPLoginExt has long been unreliable there.
3. A refused login fails the connect. The password never reaches the model.

Then `afp_connected` goes to the model.

## Tasks

`transport` (one request on the wire at a time; DSITickle every 30 s while idle; server
tickles and attentions are skipped while waiting for a reply, at most 64 of them), `turns`
(the model, with `MAX_FOLLOWUP_DEPTH` 8) and `commands` (injected actions), all registered with
the client — the shape of `src/client/mbus/mod.rs`.

## Actions and events

| Action | AFP | Event |
|---|---|---|
| `afp_list_volumes` | FPGetSrvrParms | `afp_volumes` |
| `afp_list_directory` | FPOpenVol, FPEnumerateExt2 paged until kFPObjectNotFound (at most `MAX_LIST_ENTRIES`) | `afp_directory` |
| `afp_read_file` | FPOpenFork, FPReadExt in quantum chunks to `max_bytes`, FPCloseFork | `afp_file` (utf8 or hex) |
| `afp_write_file` | FPCreateFile (soft), FPOpenFork, FPSetForkParms to 0, FPWriteExt chunks, FPCloseFork | `afp_done` |
| `afp_create_directory` | FPCreateDir | `afp_done` |
| `afp_delete` | FPDelete | `afp_done` |
| `afp_get_info` | FPGetFileDirParms | `afp_info` |
| `disconnect` | FPLogout, DSICloseSession | — |

Every AFP error comes back as `afp_error` with the code and its name; a broken connection ends
the client with `ClientStatus::Error`. Replies are bounded by `dsi::MAX_PAYLOAD_LEN` from the
header, before the payload is read.

## Evidence

`tests/client/afp/real_server_test.rs` against netatalk 4.6's `afpd`, unprivileged, guest
volume, effects asserted on disk, tshark over the relay. `tests/client/afp/e2e_test.rs` against
NetGet's own server is a regression suite only (cleartext login, refusals, timeouts, depth).
