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

## Mutation-checked

Discarding the model's actions in `run_turns` fails the shadow test at the click.
