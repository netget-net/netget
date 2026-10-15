# Kerberos KDC (RFC 4120)

A Kerberos V5 Key Distribution Center: the AS exchange (initial tickets, usually a TGT) and the
TGS exchange (service tickets), on UDP and TCP on one port. **The model decides policy; Rust
owns everything else** — the ASN.1, every key, nonce and salt, all cryptography, and every check
whose answer is a fact rather than a choice.

Files: `codec.rs` (bounded DER walk, keys, times, flags, names, error vocabulary — shared with
the client), `kdc.rs` (request analysis and reply construction, no I/O), `actions.rs` (the
model's vocabulary and the per-request executor), `mod.rs` (sockets, rate limit, lookaside
cache, the fail-closed rule).

## What the model decides, and what it never sees

Two events, raised only once a request's cryptography has checked out:

| Event | Raised when | Actions |
|---|---|---|
| `kerberos_as_request` | an AS-REQ whose pre-authentication verified, or that carried none | `kerberos_issue_ticket`, `kerberos_require_preauth`, `kerberos_refuse` |
| `kerberos_tgs_request` | a TGS-REQ whose TGT, authenticator and body checksum verified | `kerberos_issue_ticket`, `kerberos_refuse` |

The payload is names, times, options, enctypes, whether a key is configured for the client and
the service (`client_known`, `service_known`), `preauth` (`verified`/`none`), the TGT's flags and
expiry for TGS, and the configured ceilings. **No key, password, salt or nonce is ever in an
event**, and no action parameter can carry one.

- `kerberos_issue_ticket {lifetime_secs?, renewable?, renewable_lifetime_secs?, forwardable?,
  proxiable?, ok_as_delegate?}` — every field narrows. Flags you do not set are not granted.
- `kerberos_require_preauth` — KDC_ERR_PREAUTH_REQUIRED with PA-ETYPE-INFO2 (salt per enctype).
  Usable for a principal that does not exist, so a model can hide which principals exist; such
  a principal's timestamp then fails as PREAUTH_FAILED, consistently.
- `kerberos_refuse {error, text?}` — a code from `codec::MODEL_REFUSALS` (C/S_PRINCIPAL_UNKNOWN,
  POLICY, CLIENT_REVOKED, KEY_EXPIRED, PREAUTH_FAILED, …), by name or number. **SVC_UNAVAILABLE
  and KRB_ERR_GENERIC are not in it**: they are the fail-closed codes, so a refusal the model
  chose and one nobody chose differ on the wire.

Replies do not travel as executor output. Each action builds its reply and records it with its
decision (`actions::Record`); `mod.rs` sends the first record's reply. One request, one reply.

## What Rust enforces whatever the model says

Answered in `Kdc::analyze`, without asking the model (`decision=` tag in parentheses):

- malformed DER, wrong `pvno`/`msg-type`, a name with `/`, `@`, `\` or a control character
  (`malformed`); a realm other than ours (`wrong_realm`, KDC_ERR_WRONG_REALM); an option this KDC
  does not implement — FORWARDED, PROXY, POSTDATE, RENEW, VALIDATE, ENC-TKT-IN-SKEY
  (`unsupported_option`, BADOPTION); no common enctype (`etype_nosupp`);
- **PA-ENC-TIMESTAMP**: decrypted with the principal's key and its HMAC compared in constant time
  (`preauth_failed`), within `max_clock_skew_secs` (`preauth_skew`, KRB_AP_ERR_SKEW), and not
  seen before (`preauth_replay`, KRB_AP_ERR_REPEAT). A failed pre-authentication never reaches
  the model;
- **TGS**: the TGT must be this realm's TGS ticket and decrypt with the TGS key
  (`tgt_integrity`, BAD_INTEGRITY), be current (`tgt_expired`, `tgt_not_yet_valid`); the
  authenticator must decrypt with its session key (`authenticator_integrity`), name the TGT's
  client (`authenticator_mismatch`), be within skew and fresh; its **keyed checksum over the raw
  request body** must be present, of the session key's own type, and match
  (`checksum_missing`/`checksum_type`/`checksum_mismatch`, KRB_AP_ERR_MODIFIED). The reply is
  encrypted in the authenticator's subkey when it carries one (usage 9), else the session key.

Enforced in `Kdc::issue` even when the model says issue (`enforced_*`):

- no ticket for a client (AS) or service without a configured key (C/S_PRINCIPAL_UNKNOWN);
- no ticket without pre-authentication for a principal that requires it — answered with
  PREAUTH_REQUIRED, which is what the client needs next;
- end time = the shortest of the model's lifetime, `max_ticket_lifetime_secs`, the client's
  `till` and (TGS) the TGT's end; renew-till likewise against `max_renewable_lifetime_secs`, the
  client's `rtime` and the TGT's (`model_issue_clamped` when the model asked past a ceiling);
- a flag only when the model grants it **and** the client asked for it **and** (TGS) the TGT
  carries it. INITIAL and PRE-AUTHENT are set by Rust from what happened.

## The fail-closed rule (`mod.rs::decide`)

| Situation | Wire | Log |
|---|---|---|
| model chose an action | its reply | `decision=model_issue` / `model_require_preauth` / `model_reject` / `enforced_*` |
| LLM call failed | KDC_ERR_SVC_UNAVAILABLE | `decision=fail_closed_llm_error category=…` |
| model answered nothing | KRB_ERR_GENERIC | `decision=fail_closed_no_action` |
| model's actions all failed | KRB_ERR_GENERIC | `decision=fail_closed_action_error` |

Nothing on any of these paths can issue a ticket. `.answers_on_failure()` is declared.

## Keys

`principal_passwords` (an object: principal → password) is the only source of keys. At startup
each password becomes an aes256 and an aes128 key (PBKDF2-HMAC-SHA1, 4096 iterations, default
salt REALM+components). The TGS key (`krbtgt/REALM`) is random per start and cannot be
configured: TGTs do not survive a restart. `Key` is not `Debug`; the parameter name contains
`password`, so `src/utils/redact.rs` masks it wherever startup parameters are printed; the real
client test asserts no password reaches an event or the log.

Encryption is `picky-krb`'s AES-CTS. Decryption recomputes HMAC-SHA1-96 with Ki and compares in
constant time (picky's own `decrypt` compares with `!=`). **Keyed checksums use Kc
(usage | 0x99), not Ki** — NetGet's client and KDC agreed with each other on Ki until Heimdal's
`kgetcred` was refused with "Message stream modified"; `Key::checksum` documents it.

## Bounds

| Bound | Value | Where |
|---|---|---|
| message size (UDP datagram, TCP declared length) | 64 KiB (`MAX_MESSAGE_LEN`) | `codec.rs`, `mod.rs` |
| DER nesting / elements | 24 / 4096 | `codec::check_der`, iterative, before every decode |
| TCP length with the reserved high bit, or past 64 KiB | KRB_ERR_FIELD_TOOLONG, then close | `handle_stream` |
| UDP reply size | 1400 → KRB_ERR_RESPONSE_TOO_BIG | `udp_loop` |
| TCP first byte / idle / body / write | 10 s / 30 s / 10 s / 10 s | `mod.rs` constants |
| TCP connections | 256 (`accept_bounded`) | `tcp_loop` |
| UDP requests in flight | 256 | `udp_loop` |
| requests per source per minute | `max_requests_per_minute_per_source` (600) | token bucket, 16384 sources |
| replay cache | 65536, only entries that decrypted | `kdc.rs` |
| lookaside cache | 4096 entries, 120 s | `serve` |
| principals | 1024 | `KdcConfig::new` |

The lookaside cache answers a retransmission (same source, same bytes) with the cached answer,
or waits for the one in flight; it never reaches the model twice, and is why a UDP retry while
the model thinks does not trip the replay cache.

## Ports

88 on UDP and TCP; `PrivilegedPort(88)`. Unprivileged, the default-port logic falls back to an
OS-assigned port. For port 0 the UDP port the system picks is bound on TCP too (retried on a
fresh pair if TCP has it).

## Not implemented

DES, RC4, DES3, RFC 8009 (aes-sha2), FAST, PKINIT, SPAKE, PAC, cross-realm, renewal and
validation (BADOPTION), postdating, S4U, user-to-user, kpasswd, and any database: principals
exist only in the startup parameter.

## Maturity: Experimental (both roles)

The evidence is two independent clients completing real sessions — MIT krb5 1.22 (kinit over
UDP, kvno) and Heimdal 1.5.1 (Apple; kinit over TCP, kgetcred) — with MIT `kvno -k` decrypting
the service ticket with a keytab `ktutil` derived from the password, and tshark's dissector
reading both directions. Not Beta because nobody has reviewed it beyond the tests and the pair
job (`kerberos` in protocol-pairs.yml) has not yet run on Ubuntu's MIT 1.20 / Heimdal 7.8.
