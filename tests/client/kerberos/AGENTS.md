# Kerberos client tests

No LLM calls: a python chain is the model.

| File | What it proves |
|---|---|
| `real_server_test.rs` | NetGet against **MIT krb5kdc** (temp realm via `kdb5_util create` and `kadmin.local`, through a UDP relay into tshark) and **Heimdal's kdc** (temp realm via `kadmin -l`). TGT with the model's lifetime and flags, a service ticket, an unknown service refused. MIT `klist` / Heimdal `klist` read NetGet's ccache; MIT `kvno -k` decrypts the service ticket with the keytab the KDC's own database exported; MIT `kvno` / Heimdal `kgetcred` use NetGet's TGT and session key for a ticket NetGet never requested; krb5kdc's log shows the AS_REQ and TGS_REQ it issued. Wrong passwords: refused by the KDC (pre-auth required), or by NetGet when the AS-REP does not decrypt (no pre-auth). The password is in no event and nothing printed. |
| `bounds_test.rs` | Canned KDCs: an oversized declared reply, a DER depth bomb, a replayed AS-REP (wrong nonce, `integrity`), a service ticket before any TGT (`no_tgt`), and a model that asks for TGTs forever — exactly `MAX_FOLLOWUP_DEPTH` AS-REQs reach the KDC. |

## Peers (required)

- MIT: `brew install krb5`; Ubuntu `krb5-kdc krb5-admin-server krb5-user`.
- Heimdal KDC: macOS ships `/System/Library/PrivateFrameworks/Heimdal.framework/Helpers/kdc`
  (needs `--no-sandbox` to bind a test port; the test adds it only there) and `/usr/sbin/kadmin`;
  Ubuntu `heimdal-clients` (`kadmin.heimdal`) and `heimdal-kdc`'s `kdc`. **`heimdal-kdc`
  declares `Conflicts: krb5-kdc, krb5-admin-server`**, so CI installs its libraries normally,
  unpacks the package itself with `dpkg -x` into a private prefix and appends
  `<prefix>/usr/lib/heimdal-servers` to `PATH`. Heimdal 7.8 logs "KDC started master process
  pid=…" (kdc/connect.c), which the readiness regex `KDC started` matches.
  `tests/helpers/real_server.rs` searches both directories, and Homebrew's keg-only krb5 first
  (macOS's `/usr/sbin/kadmin.local` is Apple's, not MIT's).

Heimdal 7.8's `kadmin -l` writes an iprop log, by default under `/var/lib/heimdal-kdc`, which an
unprivileged test cannot open ("Failed iprop log initialization"), and then every `add` fails;
the realm's config sets `log_file` to its own directory. Heimdal 7's klist is `heimtools klist`.
Both were found and confirmed in an ubuntu:24.04 container running the CI job's packages as an
unprivileged user: NetGet's client got a TGT (forwardable, renewable, pre-authenticated) and a
service ticket from Heimdal 7.8's kdc, `heimtools klist` read the ccache, `kgetcred` used it,
MIT 1.20 `kvno -k` validated the service ticket, and a wrong password was refused with
PREAUTH_FAILED (7.8; Apple's 1.5 answers PREAUTH_REQUIRED again).

Apple's Heimdal KDC answers a timestamp that does not decrypt with PREAUTH_REQUIRED again rather
than PREAUTH_FAILED (it logs "Failed to decrypt PA-DATA"); the test accepts either and asserts
the log line and the absence of a TGT.

## Mutation-checked

Removing the nonce check, removing the follow-up depth bound, discarding the model's actions,
and putting the password into the ready event each fail a test here.
