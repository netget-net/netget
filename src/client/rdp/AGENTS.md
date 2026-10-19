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
- `security` (`security_offer`):
  - `nla`, the **default** (`actions::DEFAULT_SECURITY`): only HYBRID/HYBRID_EX is offered,
    and IronRDP refuses a server that selects anything else. The password is proven through
    CredSSP/NTLM, which a party in the middle cannot complete without knowing it.
  - `tls`: only SSL is offered. With autologon the password is sent **itself**, in the Client
    Info PDU inside TLS, and the certificate is not verified (below), so anyone who can
    intercept the connection and present any certificate receives it. Use it on a trusted
    network, or with no password to reach the server's own login screen (as against xrdp).
  - `any`: both are offered. While a password is set, a server that selects TLS-only is
    refused before the TLS upgrade (`check_selected_security`), so the password goes over
    TLS-only security only when the operator asked for `tls` by name.
- `width`, `height`: 200–4096; the width is rounded down to even.

The server's certificate is **not verified**: RDP servers almost always present self-signed
certificates, and IronRDP's upgrade accepts any. That is why `nla` is the default. CredSSP is
NTLM only. `NoKerberos` refuses the KDC requests sspi would otherwise make.

The desktop size is the **server's** choice (it may grant other than what was asked, and may
change it at reactivation), and the framebuffer is width × height × 4 bytes. A granted size
outside 1–`MAX_SIDE` (4096) a side is refused by `check_granted_size` before any framebuffer is
allocated: after the connection sequence it fails client creation, and at reactivation it ends
the session with the error as its reason.

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
  activation factory. The new size goes through `check_granted_size`, then the framebuffer is
  rebuilt at it and the share id updated.
- **Terminate** ends the session with the server's reason.
- **Turn bounds:** model turns chain up to `MAX_FOLLOWUP_DEPTH` (8); the turn queue holds 64.

**Batching: unsupported.** Nothing the server sends becomes an event by itself: a screen
reading answers the model's own `rdp_read_screen`, an error its own input action, and the only
server-caused event, `rdp_disconnected`, ends the session.

## Not implemented

- Virtual channels: clipboard, audio, drives, RemoteApp, display control.
- Standard RDP security (RC4).
- Kerberos.
- Certificate verification or pinning (hence the `nla` default).
- Reading text off the screen.
- Bulk compression is not negotiated.
