# M-Bus master

NetGet is the master behind an M-Bus/IP gateway: it dials the gateway's TCP port and writes
wired M-Bus telegrams to it. The codec is the slave's (`src/server/mbus/frame.rs`,
`records.rs`); this directory is the bus discipline and the model's vocabulary.

## Actions

`mbus_read` (address or secondary_address; follows DIF 0x1F with the FCB toggled, up to
`max_telegrams`), `mbus_scan_primary` (SND_NKE over a range), `mbus_scan_secondary` (wildcard
search), `mbus_write` (records encoded like the slave's), `mbus_set_primary_address`,
`mbus_application_reset`, `mbus_ping`, `disconnect`. Each is one operation; its result is one
event: `mbus_data`, `mbus_scan_result`, `mbus_ack` (acknowledged true/false) or `mbus_error`
(kind `timeout`, `collision`, `bad_frame`, `unexpected_reply`, `not_selected`).

## Tasks

The transport owns the socket and runs one operation at a time — M-Bus is half duplex, and a
telegram sent while a meter is still answering garbles both. The turn task asks the model about
each result in order; a result of an action the model gave in answer to a result is one turn
deeper, and at `MAX_FOLLOWUP_DEPTH` (8) the chain stops with `decision=followup_depth`. The
command task runs injected actions down the same queue (`MAX_QUEUED` 16; the next is refused).

## Link discipline

- **FCB.** A meter's link is initialised with SND_NKE once per session (for a whole secondary
  address: select, SND_NKE at 253, select again — SND_NKE at 253 also ends the selection), so the
  first REQ_UD2 carries FCB 1 whatever an earlier master left the meter at. The FCB toggles
  after every whole answer. A REQ_UD2 that times out is retried once with the **same** FCB,
  which asks the meter to repeat what it may already have sent.
- **Collisions.** After every answer the transport keeps reading for `COLLISION_WINDOW`
  (100 ms, or the response timeout if shorter); anything more, or a garbled answer, is a
  collision.
- **Secondary search.** Select with the mask; if nobody answers, nothing is there; if one meter
  answers, read it for its whole address; if several answer, fix the first wildcard nibble to
  each value in turn (0-9 in the BCD identification digits; 0-F, then leave it wildcard, in the
  manufacturer/version/medium nibbles, where a meter may hold a real F) and look again. At most
  `MAX_SECONDARY_PROBES` (2048) telegrams and `MAX_FOUND` (250) meters.

## Startup parameter

`response_timeout_ms` (default 2000, 20-60000). At 2400 baud a whole 261-byte telegram takes
1.1 s on the wire, so a real gateway needs well over a second; every silent address in a scan
costs one timeout.

## Failure

No answer from the model sends nothing (`decision=llm_error`); an action the codec refuses is
rejected before it reaches the bus. The connection's end is reported as the client's status.

## Not implemented

Serial ports, wireless M-Bus, fixed-data (CI 0x73) responses (reported as `bad_frame`),
encryption, extended selection by fabrication number.

## Maturity

Experimental. Independent slaves: pyMbusSlave (Python) and Addiva's mbus-device (C) serving
libmbus's captured real-meter telegrams, whose decoding is checked against libmbus's own
normalised XML; neither does multi-telegram readouts or collisions, which run only against
NetGet's own slave (a regression, not evidence). See `tests/client/mbus/AGENTS.md`.
