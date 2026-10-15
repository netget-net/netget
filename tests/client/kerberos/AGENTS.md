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
  Ubuntu `heimdal-kdc heimdal-clients` (`/usr/lib/heimdal-servers/kdc`, `kadmin.heimdal`).
  `tests/helpers/real_server.rs` searches both directories, and Homebrew's keg-only krb5 first
  (macOS's `/usr/sbin/kadmin.local` is Apple's, not MIT's).

Apple's Heimdal KDC answers a timestamp that does not decrypt with PREAUTH_REQUIRED again rather
than PREAUTH_FAILED (it logs "Failed to decrypt PA-DATA"); the test accepts either and asserts
the log line and the absence of a TGT.

## Mutation-checked

Removing the nonce check, removing the follow-up depth bound, discarding the model's actions,
and putting the password into the ready event each fail a test here.
