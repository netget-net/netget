# M-Bus slave tests

| File | What it proves |
|---|---|
| `codec_test.rs` | The codec alone: frames against bytes worked out from EN 13757-2 (checksums, the 261-byte bound, a broken frame discarded whole), manufacturer codes, secondary addresses and wildcard masks, every record coding against bytes worked out from the EN 13757-3 tables (the coarsest exact VIF, BCD with the sign nibble, two's complement, real, storage/tariff/subunit DIFEs, type F and G dates, the 0xFD table), refusals, decoding round trips, LVAR text, both ten-extension bounds, the 64-record bound and the 16-telegram bound. |
| `e2e_test.rs` | The gateway from a raw master socket: a readout's records and identity, the FCB repeat rule (per connection, FCV respected), a 120-record multi-telegram readout fetched by toggling the FCB (with a repeat mid-way and SND_NKE abandoning it), selection with wildcards and a two-meter collision, meters sharing an address, broadcasts, REQ_UD1, writes accepted and refused, a bus-address write moving a meter, application reset, the fail-closed paths (no model: error status and no records; unencodable answer; silence; refusal), garbled input and resynchronisation, the idle timeout, startup validation, and a mocked model through the binary (2 LLM calls). |
| `real_peer_test.rs` | **libmbus 0.10.3** (rSCADA, C): `mbus-tcp-request-data` prints the model's readings as XML with libmbus's own units and values, by primary and by secondary address, and reports the collision for a mask matching both meters; `mbus-tcp-scan -d` finds the meters at 1 and 2 (stopped once past them: it waits 4 s on each of 251 addresses); `mbus-tcp-scan-secondary` finds both by wildcard search; `mbus-tcp-request-data-multi-reply` reads all 120 records across telegrams with the FCB toggled, the model asked once; `mbus-tcp-application-reset` and `mbus-tcp-raw-send` are acknowledged or refused by the model. **pyMeterBus 0.8.5** (Python): its own frame builders, receive loop and record decoder read the same meters, see the FCB repeat, and select by secondary address. |

A python policy (`support::POLICY`) plays the model everywhere except the mocked test.

Peers fail rather than skip:

```bash
sh scripts/test-peers/build-libmbus.sh /abs/dir        # LIBMBUS_BIN=/abs/dir/bin
python3 -m venv /abs/venv && /abs/venv/bin/pip install pyMeterBus==0.8.5   # MBUS_PYTHON=/abs/venv/bin/python
LIBMBUS_BIN=... MBUS_PYTHON=... ./cargo-isolated.sh test --test server -- server::mbus:: --test-threads=8
```

pyMeterBus 0.8.5's console scripts import a `meterbus.tools` module the package does not ship,
so `pymeterbus_master.py` drives the library's own functions instead. libmbus waits four
seconds after every answer (its "purge" for a colliding second answer) and on every silent
address, so `real_peer_test` takes a couple of minutes; that is libmbus's timing.

There is no pcap oracle: tshark 4.6.8 has no wired M-Bus dissector.
