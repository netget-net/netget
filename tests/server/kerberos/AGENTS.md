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
  (`kinit.heimdal`, `klist.heimdal`, `kgetcred`), installable beside MIT.
- `tshark`. Overrides: `NETGET_KRB5_MIT_DIR`, `NETGET_KRB5_HEIMDAL_DIR`.

Every tool runs with `LC_ALL=C`. MIT `klist` formats times by trying `%c`, `%d %b %Y %T` and
then `%x %X` in a 20-byte buffer (krb5 `str_conv.c`); in the C locale only `%x %X` fits, giving
`10/15/26 04:43:52` on macOS and Ubuntu alike. Heimdal's `klist -v` prints `ctime(3)` from the
month on, which no locale changes.

MIT `krb5.conf` syntax does not accept `kdc = tcp/host:port`; TCP is forced with
`udp_preference_limit = 1`. Heimdal takes the `tcp/` prefix. Hence `Via::{MitTcp, HeimdalTcp}`.

tshark reports "Missing keytype … usage 8 or 9" at Warn when it tries to decrypt a TGS-REP with
no keytab; the oracle allows exactly that note and nothing else.

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
