# RDP client

Feature `rdp-client` (implies the `rdp` server feature, and `rustls` for the TLS upgrade).
One persistent RDP session per client, driven by **IronRDP**:

- `ironrdp-connector` 0.10 runs the connection sequence: X.224 negotiation, the TLS upgrade,
  CredSSP for NLA, MCS/GCC, licensing, capabilities and finalization.
- `ironrdp-tokio` / `ironrdp-tls` (rustls, ring) carry it.
- `ironrdp-session` 0.11 decodes fast-path and slow-path graphics into a `DecodedImage`
  (RGBA).
- `ironrdp-input` turns operations into fast-path input events.

The connection sequence runs inside `connect()`, bounded by `CONNECT_TIMEOUT` (30 s), so a
refused logon or an unreachable server fails client creation instead of reporting Connected.

## Settings (startup parameters)

- `username`, `password`, `domain`.
  - A username turns on autologon.
  - Without one, a server such as xrdp shows its own login screen, which the model can fill
    in by typing.
- `security`: `any` (offer TLS and NLA; the server picks), `tls` or `nla`.
- `width`, `height`: 200–4096; the width is rounded down to even.

The server's certificate is **not verified**: RDP servers almost always present self-signed
certificates, and IronRDP's upgrade accepts any. CredSSP is NTLM only. `NoKerberos` refuses
the KDC requests sspi would otherwise make.

## What the model does

| Action | Effect |
|---|---|
| `rdp_type{text}` | Keystrokes. US-layout scancodes where the character has a key (shift held for shifted ones); Unicode key events otherwise. `\n` is Enter. |
| `rdp_keys{keys}` | Named keys and combos (`ctrl+alt+delete`, `enter`, `f5`, `up`), pressed in order and released in reverse (`keys.rs`). |
| `rdp_mouse{x, y, action, button}` | A move, then click, double_click, press, release, scroll_up or scroll_down. A point outside the desktop is an error. |
| `rdp_read_screen{grid, settle_ms}` | Waits until no graphics update has arrived for `settle_ms` (default 500), or 10 s more at most (`settled: false`). Then answers `rdp_screen`. |
| `disconnect` | Sends the shutdown request and closes. |

`rdp_screen` describes the screen by colour (`screen.rs`):

- the size;
- the most common colour and its share of the screen;
- a grid of each cell's most common colour.

A cell's most common colour, not its average, so a background reads exactly and an edge does
not blur two colours into a third. Pixels never reach the model.

Input is sent in fast-path PDUs of at most 32 operations. Events: `rdp_connected` (security
selected, granted size), `rdp_screen`, `rdp_error` (an action that failed), `rdp_disconnected`.

## Session loop

`Session::run` selects over:

- the framed reader (`read_pdu` is cancel-safe: bytes stay in its buffer);
- injected commands;
- the model's follow-up actions;
- the pending screen read's wake-up.

Server frames go through `ActiveStage::process`; response frames are written back.

- **DeactivateAll** runs the deactivation-reactivation sequence through the connection's
  activation factory. The framebuffer is rebuilt at the new size and the share id updated.
- **Terminate** ends the session with the server's reason.
- **Turn bounds:** model turns chain up to `MAX_FOLLOWUP_DEPTH` (8); the turn queue holds 64.

## Not implemented

- Virtual channels: clipboard, audio, drives, RemoteApp, display control.
- Standard RDP security (RC4).
- Kerberos.
- Certificate verification or pinning.
- Reading text off the screen.
- Bulk compression is not negotiated.
