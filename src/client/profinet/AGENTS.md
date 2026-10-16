# PROFINET IO controller (client)

NetGet as the PLC side: DCP Identify and Set, Connect with a layout the model describes,
parameter writes, PrmEnd, the device's ApplicationReady, cyclic RT_CLASS_1 data, records,
Release. It shares the codec in `src/server/profinet/` (`dcp`, `rpc`, `blocks`, `rt`, `values`,
`l2`) — read that directory's `AGENTS.md` for the wire details, transports and bounds.

**State**: `Experimental`. **Privilege**: `PacketCapture` for the raw transport (the client
startup path checks no privilege; opening the packet socket fails with a message naming
CAP_NET_RAW and the lab transport).

## Targeting

`remote_addr` is the **Ethernet interface** with `transport: "raw"` (the `datalink`/`arp`
precedent), and the **device's lab link** `HOST:PORT` with `transport: "udp"`. The controller's
own RPC endpoint — where a device sends ApplicationReady — is the interface's IPv4 address on
UDP 34964 (raw), or an OS-assigned port in the lab, where the device answers the Connect's source
address. Devices are reached at the IP their DCP answer reported, on `rpc_port` (34964).

## Three tasks

The session owns the link, the RPC socket, the AR and every timer; the dispatcher asks the model
one event at a time and hands its actions back (`MAX_FOLLOWUP_DEPTH` 8); each AR's output
provider sends the output image every cycle. A slow model never delays a frame or an RPC answer.

One RPC call is outstanding at a time (retransmitted every second, four attempts, the same
sequence number); a second action needing one is refused with a reason. One AR at a time.

## Events and actions

On start the controller sends an Identify and, after `identify_ms`, raises
`profinet_devices_discovered`. Actions: `profinet_identify`, `profinet_dcp_set` (name, IP,
signal; per-option results in `profinet_dcp_set_result`), `profinet_connect` (layout, cycle,
watchdog, parameters → `profinet_ar_established` or `profinet_connect_failed` naming the stage),
`profinet_set_outputs`, `profinet_read_record` (through the AR, or implicit by
`name_of_station` → `profinet_record_read` with I&M0-3 decoded), `profinet_write_record`
(→ `profinet_record_written`), `profinet_release` (→ `profinet_ar_closed`), `disconnect`.
`profinet_inputs_changed` carries the latest decoded inputs at most every 200 ms; the input
watchdog closes the AR when frames stop.

## Fail closed

Outputs are IOPS BAD with zero data until the model (or an operator through `send_to_client`)
sets them; on an LLM failure nothing is sent and the log says `decision=fail_closed_llm_error`.

## Not implemented

Alarms (the AlarmCR is requested; alarm notifications from a device are not acknowledged, so a
device that raises one will eventually drop the AR), RT_CLASS_2/3, multicast CRs, fragmented RPC,
WriteMultiple, a GSDML importer (the model supplies the layout), more than one AR.

## Maturity

`Experimental`: one independent device implementation (rt-labs' p-net, in
`tests/client/profinet/real_server_test.rs`, observed from p-net's side), run only in the
`profinet` pair job.
