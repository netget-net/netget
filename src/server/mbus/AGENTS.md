# M-Bus slave (M-Bus/IP gateway)

NetGet plays an M-Bus/IP gateway and every meter behind it. A master connects over TCP and
writes wired M-Bus (EN 13757-2) telegrams; the meters answer through the same socket, byte for
byte, as a transparent serial-to-TCP gateway forwards them. There is no TCP framing of its own:
the stream is the bus.

| File | What it owns |
|---|---|
| `frame.rs` | Link layer: E5, short, control and long frames, the sum checksum and stop byte, the streaming parser (`parse`, which skips garbage and never parses a frame out of a broken one), C field bits (FCB/FCV), CI values, primary addresses, the 16-character secondary address and its nibble-wildcard matching, manufacturer codes, medium names, BCD identification numbers. Shared with the master. |
| `records.rs` | Application layer: the 12-byte CI 0x72 header, status flags, record encoding from the model's `{quantity, unit, value}`, record decoding, splitting a readout into telegrams. Shared with the master. |
| `actions.rs` | Events (`mbus_request_data`, `mbus_write_data`, `mbus_application_reset`), actions (`mbus_respond_data`, `mbus_acknowledge`, `mbus_no_response`), the `meters` startup parameter, metadata. |
| `mod.rs` | The gateway: one telegram at a time per connection, addressing, selection, FCB, readouts, writes, the fail-closed paths. |

## Library choice

None. The Rust M-Bus crates on crates.io decode wireless telegrams or a subset of records, and
none encodes a RSP_UD; the slave needs the encoder and the master the decoder, so both are
hand-written from EN 13757-2/-3 and checked against two independent implementations
(libmbus in C, pyMeterBus in Python) rather than against each other.

## What Rust does and what the model does

- **Rust:** SND_NKE (E5, resets the meter's FCB and any readout in progress; at 253 also ends
  the selection), REQ_UD1 (E5: no meter here raises alarms), selection (CI 0x52 at 253: every
  meter whose secondary address the mask matches is selected and answers E5, every other one
  is deselected), baud-rate SND_UDs (E5; the TCP side has no baud rate), the FCB repeat rule,
  the telegrams after the first of a multi-telegram readout, the access number.
- **The model:** each fresh REQ_UD2 (`mbus_request_data` -> `mbus_respond_data` with records,
  or `mbus_no_response`), each data write (`mbus_write_data`) and each application reset
  (`mbus_application_reset`) -> `mbus_acknowledge` or `mbus_no_response`. An acknowledged write
  carrying a `bus_address` record moves the meter to that primary address.

The model writes records as `{"quantity": "energy", "unit": "kWh", "value": 12.345}` with
optional `storage`, `tariff`, `subunit`, `function`, `encoding` (int — smallest that fits — bcd,
real, or an explicit width) and `resolution`. `encode_record` picks the VIF whose power of ten
carries the value exactly: the coarsest step at which it is still a whole number (12000 Wh
travels as 12 at 10^3 Wh), or the step `resolution` names. A value finer than the finest step
the VIF table has is refused, not rounded. Supported quantities: energy (Wh and J families),
volume, mass, power (W and J/h), volume flow (per hour, minute, second), mass flow, flow /
return / external temperature, temperature difference, pressure, voltage and current (0xFD
table), on/operating time and the two durations, date (type G) and date-time (type F),
fabrication number, enhanced identification, bus address, HCA units.

## Per-connection link state

FCB state, the readout in progress and the selection belong to each master **connection**: a
new TCP connection starts as though the master had sent SND_NKE. That is a deliberate choice.
Within one connection the FCB rule is exact (the same FCB again resends the last telegram;
toggled continues a multi-telegram readout or starts a fresh one). Across connections a real
meter would remember, and libmbus's one-shot tools — which send REQ_UD2 with FCB 0 every time
and never SND_NKE first — would then get the previous readout repeated forever. Meter identity
(including a primary address moved by a write) and the access number are shared by every
connection.

## Collisions

Several meters can answer one telegram (two at one primary address, a selection mask matching
two, anything at 254). Their answers are written back to back. A real bus would garble them;
masters detect a collision by reading more than one clean answer (libmbus's purge, NetGet's own
master's collision window), and that is what they see here. No line noise is fabricated.

## Failure modes

| Situation | Wire | Log |
|---|---|---|
| LLM error on REQ_UD2 | RSP_UD: identity, no records, status `application_error` | `decision=fail_closed_llm_error` |
| LLM overloaded on REQ_UD2 | as above with status `application_busy` | `decision=fail_closed_llm_overloaded` |
| The model's records cannot be encoded | as LLM error | `decision=fail_closed_bad_action` |
| `mbus_no_response` / no action | silence (the master times out) | `decision=model_reject` / `model_silent` |
| LLM error on a write or reset | silence — E5 would accept a change nobody approved | `decision=fail_closed_llm_error` |
| Garbled telegram (checksum, length, stop byte) | silence, bytes discarded | `decision=protocol_error` |
| Undecodable SND_UD data | silence | `decision=protocol_error` |
| Master silent past `idle_timeout_secs` | connection closed | `decision=protocol_timeout` |

## Bounds

- Frame: the L field is one byte, so at most 252 bytes of user data, 261 on the wire
  (`MAX_FRAME_LEN`, declared as `max_inbound_bytes`). The receive buffer never holds more than
  one telegram plus one read.
- Records per telegram: 64 (`MAX_RECORDS_PER_TELEGRAM`), decode and encode.
- DIFE and VIFE chains: 10 each.
- Telegrams per readout: 16 (`MAX_TELEGRAMS`); records the model may give: 256.
- Meters per gateway: 250. Connections: `accept_bounded`'s default cap.

## Not implemented

Serial ports, wireless M-Bus (EN 13757-4: different link layer, AES), encryption and the
signature field, fixed-data responses (CI 0x73), extended selection by fabrication number
(CI 0x52 with 12 bytes), mode-2 selection (CI 0x56), alarm data (REQ_UD1 is always E5), the
CI 0x70 application-error telegram, manufacturer-specific record data from the model.

## Maturity

Experimental. Two independent masters read it (libmbus 0.10.3 and pyMeterBus 0.8.5, see
`tests/server/mbus/AGENTS.md`), which meets condition 1 of the Stable bar, but there is no
pcap oracle (tshark 4.6.8 has no wired M-Bus dissector — checked with `tshark -G protocols`),
the fuzz target (`fuzz/fuzz_targets/mbus_frame.rs`) has not been run at length, and the pair
job had not run in CI when it landed.
