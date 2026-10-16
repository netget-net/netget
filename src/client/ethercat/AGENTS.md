# EtherCAT master (client)

NetGet as the MainDevice of a segment: scan, SII, state walk, cyclic process data, CoE. It
shares the codec in `src/server/ethercat/` (`frame`, `sii`, `coe`, `device`, `link`) — read that
directory's `AGENTS.md` for the wire details and transports.

**State**: `Experimental`. **Privilege**: `PacketCapture` for the raw transport (opening the
packet socket fails with a message naming CAP_NET_RAW and the UDP transport).

## Targeting

`remote_addr` is the segment's **Ethernet interface** with `transport: "raw"` (frames go to the
broadcast address from the interface's MAC), and the **HOST[:PORT]** of an EtherCAT-in-UDP
endpoint with `transport: "udp"` (port 34980 by default).

## Tasks

The link reader and the bus dispatcher match each returned frame to the request waiting on its
first datagram's index (100 ms, three attempts). The session runs one action at a time. Once a
slave is configured for SAFE-OP the cyclic task sends one LRW over the logical image every
`cycle_ms` and compares the working counter with the expected one (2 per slave with outputs, 1
per slave with inputs); inputs are reported only from frames with the expected counter. The
dispatcher asks the model one event at a time (`MAX_FOLLOWUP_DEPTH` 8).

## What each step does

- **Scan** (on start and on `ethercat_scan`): BWR AL control INIT+ack; BRD of the type register,
  whose working counter is the slave count; BWR resets of alias use, FMMUs, SyncManagers and
  EEPROM ownership; APWR station addresses 0x1001…; each SII read through the EEPROM registers
  (4- or 8-octet chunks, as the slave says) until its END category; identity, name, mailbox and
  the PDO layout from it → `ethercat_segment_scanned`.
- **PRE-OP**: the mailbox SyncManagers from the SII's standard mailbox words and SyncM types.
- **SAFE-OP**: the PDO layout over CoE (0x1C12/0x1C13 and each mapping object, names and types
  from the SII where it names the same entry) when the slave has CoE, else the SII's assigned
  PDOs; process data SyncManagers with the computed lengths; FMMUs (from the SII's FMMU usage)
  placing the slave's outputs then inputs, byte-aligned, after everything placed before.
- **OP**: refused until every slave with outputs has had them set.
- Each request writes AL control (with the acknowledge bit) and polls AL status until the state,
  an error (its AL status code is reported), or `state_timeout_ms` → `ethercat_state_result`.
- **SDO**: the receive mailbox written when empty, the send mailbox polled through its
  SyncManager status, expedited / normal / segmented both ways, aborts decoded →
  `ethercat_sdo_result`.

## Fail closed

Outputs are zero until set and OP is refused until they are; on an LLM failure nothing is sent
and the log says `decision=fail_closed_llm_error`.

## Not implemented

Distributed clocks, topology beyond a line, redundancy, ENI files, FoE/EoE/SoE/AoE, SDO
information, complete access, PDO remapping, EEPROM writes, the mailbox status through an FMMU.

## Maturity

`Experimental`: one independent slave implementation, KickCAT's `network_simulator` (an
emulated ESC with KickCAT's slave stack and a CiA 402 drive), in
`tests/client/ethercat/real_server_test.rs`, run only in the `ethercat` pair job. No other
software EtherCAT slave exists that runs without an ESC chip (SOES needs one), so a second
independent slave is not available.
