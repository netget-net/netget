# Kerberos KDC tests

No LLM calls except one mocked test. The "model" is a python script handler (`support::POLICY`)
or a static rule that admits everything (so every refusal observed is Rust's).

| File | What it proves |
|---|---|
| `real_client_test.rs` | MIT kinit/klist/kvno/ktutil (UDP, via a recording relay) and Heimdal kinit/klist/kgetcred (TCP, via a relay) against NetGet: TGT with the policy's 2 h lifetime and F/R/I/A flags, a service ticket MIT `kvno -k` decrypts with a keytab `ktutil` derived from the service's password, unknown service / unknown and revoked principals / wrong password refused, no password in events or logs; tshark's `kerberos` dissector over every captured datagram and stream. With the model unreachable, both kinits fail for a principal exempt from pre-authentication. |
| `e2e_test.rs` | Pre-authentication (required, wrong key, skew, MAC-only tamper, unknown principal, replay), lifetime/renewable ceilings and flag intersection, TGS integrity (flipped TGT, wrong session key, body modified after the checksum, unknown service), the lookaside cache, the four fail-closed rows, every bound (DER depth bomb, garbage, indefinite length, FIELD_TOOLONG, RESPONSE_TOO_BIG vs TCP, rate limit, silent TCP peer), and a mocked LLM admitting a real MIT kinit against the binary. |
| `codec_test.rs` | `check_der` at its exact limits, the model's refusal vocabulary excluding the fail-closed codes, decryption/checksum refusals, and 6000 mutated AS-/TGS-REQs through `Kdc::analyze` without a panic. |
| `support.rs` | In-process KDC, tool discovery (version-checked), `krb5.conf` per implementation (`Via`). |

## Peers (required — the tests fail, not skip)

- MIT krb5: macOS `brew install krb5` (keg-only, found under `/opt/homebrew/opt/krb5/bin`);
  Ubuntu `krb5-user` (`kinit.mit`, `klist.mit`, `ktutil.mit`, `kvno`).
- Heimdal: macOS ships it in `/usr/bin` (Heimdal 1.5.1apple1); Ubuntu `heimdal-clients`
  (`kinit.heimdal`, `kgetcred`, and `heimtools`), installable beside MIT. Heimdal 7's `klist` is
  a command of the multi-call `heimtools`, chosen from `argv[0]` only when that is exactly
  `klist`, so Ubuntu's `klist.heimdal` symlink prints a usage message; the suite runs
  `heimtools klist` (`Tools::heimdal_klist_args`).
- `tshark`. Overrides: `NETGET_KRB5_MIT_DIR`, `NETGET_KRB5_HEIMDAL_DIR`.

Every tool runs with `LC_ALL=C`. MIT `klist` formats times by trying `%c`, `%d %b %Y %T` and
then `%x %X` in a 20-byte buffer (krb5 `str_conv.c`); in the C locale only `%x %X` fits, giving
`10/15/26 04:43:52` on macOS and Ubuntu alike. Heimdal's `klist -v` prints `ctime(3)` from the
month on, which no locale changes.

MIT `krb5.conf` syntax does not accept `kdc = tcp/host:port`; TCP is forced with
`udp_preference_limit = 1`. Heimdal takes the `tcp/` prefix. Hence `Via::{MitTcp, HeimdalTcp}`.

tshark reports "Missing keytype … usage 8 or 9" at Warn when it tries to decrypt a TGS-REP with
no keytab; the oracle allows exactly that note and nothing else.

## Checked on Ubuntu 24.04 (Heimdal 7.8.0, MIT 1.20)

The first CI run failed two tests that macOS could not: `klist.heimdal` (above), and Heimdal
7.8's `kinit` spinning forever on KDC_ERR_SVC_UNAVAILABLE, which the KDC then sent for an
unreachable model (see `src/server/kerberos/AGENTS.md`; it now sends KRB_ERR_GENERIC). Both
were reproduced and their fixes confirmed in an ubuntu:24.04 container with the CI job's
packages, as an unprivileged user, driving NetGet's KDC on the host: kinit/heimtools
klist -v/kgetcred, the wrong password ("Password incorrect"), MIT kinit -f -r 1d and klist -f -e
(`10/15/26 09:38:14`, Flags FRIA), and both kinits against an unreachable model, which now exit
at once with NetGet's e-text.

## Mutation-checked (October 2026)

Each made its tests fail: accepting a request without pre-authentication as verified; skipping
the HMAC comparison on decryption; removing the lifetime ceiling; removing the DER depth bound;
issuing a ticket on the no-action path and on the LLM-error path; logging the configured
passwords. The first two fail-open mutations survived until the tests used a principal exempt
from pre-authentication, and the integrity mutation survived until a MAC-only tamper was added.

## Run

```bash
./cargo-isolated.sh test --no-default-features --features kerberos --test server -- kerberos:: --test-threads=8
```

About 30 s, most of it the LLM-unreachable path's retries.
