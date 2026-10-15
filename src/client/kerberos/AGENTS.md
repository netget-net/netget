# Kerberos client

NetGet gets TGTs and service tickets from a KDC; the model decides which, with what lifetime
and flags. The password is a startup parameter used only to derive keys.

## Files

- `wire.rs` — AS-REQ, PA-ENC-TIMESTAMP, TGS-REQ (AP-REQ with an authenticator carrying a keyed
  checksum over the encoded body and a fresh subkey), `parse_reply`, and `verify_rep`. The KDC's
  `src/server/kerberos/codec.rs` supplies the DER walk, keys and vocabulary — shared, not copied.
- `ccache.rs` — MIT `FILE:` ccache v4 writer (mode 0600, temp file + rename).
- `actions.rs` — vocabulary, events, `exchange_from_action` (every refusal before the wire).
- `mod.rs` — the session task (owns password, TGT, tickets; performs every exchange) and the
  turns task (asks the model); both registered, plus the command channel.

## Exchanges

- **AS**, as MIT kinit does it: an unauthenticated AS-REQ; on KDC_ERR_PREAUTH_REQUIRED the key is
  derived with the salt and enctype the KDC's ETYPE-INFO2 names, and a second AS-REQ carries
  PA-ENC-TIMESTAMP. An AS-REP to the first request (no pre-authentication required) is decrypted
  with the salt in its own ETYPE-INFO2, or the default salt.
- **TGS** with the current TGT; refused before the wire without one (`kind: no_tgt`).
- Each exchange is a fresh UDP socket (retransmitted `retries` times, `timeout_ms` each) or TCP
  connection (4-byte prefix). A UDP KRB_ERR_RESPONSE_TOO_BIG is retried over TCP.

## Every reply is verified before it is believed

Bounded first (64 KiB declared or received, DER depth 24 — `oversize`/`malformed`), then
`verify_rep`: the encrypted part must decrypt under the password-derived key (AS, usage 3) or the
request's subkey (TGS, usage 9) with its HMAC checked in constant time, echo this request's
nonce, and name the client and service asked for (encrypted part and ticket). Anything else is
`kerberos_request_failed {kind: integrity}` — a wrong password against a KDC that does not
require pre-authentication lands here, as does a replayed reply.

## Events

`kerberos_client_ready {kdc, principal, transport}`, `kerberos_tgt_obtained` and
`kerberos_service_ticket_obtained {client, service, authtime, starttime, endtime, lifetime_secs,
expires_in_secs, renew_till, flags, session_etype, ticket_etype}`, `kerberos_request_failed
{stage, service, kind, error?, code?, text?, message?}`. No key or password, ever.

## Actions

`kerberos_request_tgt {lifetime_secs?, renewable_lifetime_secs?, forwardable?, proxiable?}`,
`kerberos_request_service_ticket {service, …same}` (no realm: no cross-realm), `disconnect`.

## Chains

The model is asked about each result with the depth of the action that produced it; an event at
`MAX_FOLLOWUP_DEPTH` (6) is not asked about (`decision=followup_depth`), so a model that asks for
a TGT forever makes exactly six requests (`bounds_test.rs` counts them at the KDC).

## The password

Required startup parameter `password`, redacted by name wherever parameters are printed, kept
only in the session (`Session` is not `Debug`). The real-server test asserts it reaches no event
and nothing NetGet printed. The ccache, when `ccache_path` is set, holds session keys as any
ccache does.

## Maturity: Experimental

Against MIT krb5kdc and Heimdal's kdc (see `tests/client/kerberos/AGENTS.md`): real sessions,
tickets accepted by the peers' own tools, the model's choices visible in the KDC's log. Not Beta
until the pair job has run in CI and someone has reviewed it.

## Not implemented

FAST, PKINIT, SPAKE, renewal, validation, cross-realm referrals, AP exchange to a service,
kpasswd, RFC 8009 enctypes, keytab-based authentication.
