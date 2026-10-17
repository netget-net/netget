# LMTP server (RFC 2033)

Hand-written over Tokio TCP; there is no LMTP server crate worth depending on, and the
protocol is SMTP's command set with two differences that matter: LHLO replaces HELO/EHLO
(both are refused, as RFC 2033 requires), and after DATA the server answers **once per
accepted recipient, in RCPT order**.

## What the handler decides

- `lmtp_recipient` → `lmtp_recipient_reply {accept, temporary?, reason?}`: 250, 450 or 550.
- `lmtp_message` → `lmtp_delivery {results?, deliver_all?}`: one outcome per recipient. A
  recipient the answer does not mention takes `deliver_all`; with no `deliver_all` it gets
  `451 4.3.0`, so an incomplete answer can never become a false delivery.

The event carries headers as fields (lowercase names, first occurrence, 100 at most) and the
body as text capped at 64 KiB with `body_truncated`. Nothing is stored here.

## Failure modes

Every handler outcome is logged with `decision=`: `model_answer`, `model_reject`,
`model_silent`, `fail_closed_llm_error`, `fail_closed_invalid_reply` and
`fail_closed_incomplete_reply`. A failure on RCPT answers `451 4.3.0` (the recipient is not
accepted); a failure on DATA answers `451 4.3.0` for every recipient.

## Batching (on by default)

RFC 2033 requires PIPELINING, and a client delivering to several mailboxes sends its RCPT lines
together. A run of well-formed `RCPT TO:` lines already buffered behind the one being read is
decided in one model call (`recipient_batch`), up to `MAX_BATCH_EVENTS` and the recipient cap;
anything else ends the run and is read normally, so MAIL, DATA, the message body and the
`lmtp_message` decision are never batched. The answer is used only when every action executed
and it holds exactly one `lmtp_recipient_reply` per recipient, applied in RCPT order; otherwise
every recipient in the run gets `451 4.3.0` (`decision=fail_closed_batch_mismatch`) and none is
accepted. `tests/server/lmtp/batching_test.rs` holds the control, the claim and the fail-closed
short answer.

## Bounds

`wire.rs` holds them: 1000-byte lines (refused without buffering the excess), 100 recipients,
`max_message_bytes` (default 10 MiB, at most 64 MiB; an oversized body is drained and refused
per recipient), 30 s writes, `idle_timeout_secs` per command (default 300), 20 consecutive
refused commands close with 421, and the shared accept-loop connection cap.

## Not implemented

STARTTLS, AUTH, BDAT/CHUNKING, SMTPUTF8, DSN and Unix-socket listening. The well-known port
24 is privileged; without that privilege the server starts on an OS-assigned port.
