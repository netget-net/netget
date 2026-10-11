# RDP client tests

No LLM calls; a python script handler plays the model. `real_server_test.rs` drives two
independent RDP servers and fails rather than skips when they are absent. Install them with:

```
apt-get install xrdp freerdp3-shadow-x11 xvfb x11-utils x11-xserver-utils
```

## FreeRDP's shadow server, with NLA

`freerdp-shadow-cli3` shares an Xvfb display.

- **Xvfb** runs with `-displayfd`, so it picks a free display, and `-noreset`, without which
  the root colour is wiped when `xsetroot` disconnects.
- **Credentials:** NLA is CredSSP/NTLM against a SAM file holding alice's NT hash. The hash is
  a constant; the test's doc comment gives the openssl command that derives it.
- **Input:** the model's turn on `rdp_connected` clicks at (300, 250), inside an `xev` window
  at 100,100, then types `Hi!` and presses Enter. xev prints what the X server received:
  - a ButtonPress at `root:(300,250)`;
  - KeyPress keysyms in order: `Shift_L H i Shift_L exclam Return`.

  That is the model's answer asserted on the far side of the wire.
- **Screen:** `rdp_read_screen` (grid 8) finds the root colour dominant and in the
  bottom-right cell, and the xev window white.
  - The shadow server's codec rounds a channel by one unit (`#20a040` arrives as `#209f40`),
    so colours compare within 2 per channel.
- **Disconnect:** a disconnect returns `Disconnected`.
- **Wrong password:** a second test checks that a wrong password fails client creation in the
  connection sequence.

## xrdp, with TLS

xrdp 0.9 runs from a temp-dir `xrdp.ini`: a loopback port, `security_layer=tls`, and a
certificate made by `openssl req` in a setup command. It runs unprivileged, so it also runs on
a CI runner.

- Without a username, xrdp draws its own login screen.
- The background colour (`ls_top_window_bg_color=3060c0`) must be the dominant colour and the
  corner cells, exactly.
- The middle cells must be the login box's `#dedede`.

Both real-server tests name `security` explicitly (`nla` for the shadow server, `tls` without
a username for xrdp), so they do not depend on the default.

## Without a server

`security_test.rs` pins the decisions a hostile server would aim at, through the public
functions the connection uses:

- `security_offer`: the default offers NLA alone, and the declared parameter default is
  `actions::DEFAULT_SECURITY`.
- `check_selected_security`: a server selecting TLS-only is refused while a password is set
  unless `tls` was asked for by name; with no password it is allowed.
- `check_granted_size`: 1–4096 a side passes; 4097, 65535×65535 and 0 are refused.

What they cannot show is the refusal on the wire (a server granting 65535×65535, or selecting
TLS under `any`): neither real server can be made to, and a fake one would have to complete the
whole IronRDP connection sequence first.

## Mutation-checked

Discarding the model's actions in `run_turns` fails the shadow test at the click.
