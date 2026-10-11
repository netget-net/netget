# CoAP client tests

```bash
./cargo-isolated.sh test --no-default-features --features coap --test client -- coap --test-threads=100
```

| file | peer | LLM calls | proves |
|---|---|---|---|
| `real_server_test.rs` | libcoap `coap-server`, read back with `coap-client` | 7+ | the client bar (below) |
| `transport_test.rs` | hand-written UDP servers built on the shared codec | 3-4 each | retransmission bound, Block2 cap and order, oversize drop, notification dedup and RST, exchange cap |
| `request_test.rs` | none | 0 | `request_from_action`: options, content formats, refusals |
| `blockwise_upload_test.rs` | libcoap `coap-server` + `coap-client`; aiocoap; a coap-lite server | 0 (script handler) | Block1 uploads: libcoap stores 3000 bytes sent in twelve 256-byte blocks and `coap-client` reads them back; aiocoap reassembles three 1024-byte blocks; the client continues at the smaller size a server asks for in its 2.31, from the right offset; a 4.13 part way reaches the model with `blocks_sent` |

## real_server_test.rs — the evidence the rating rests on

`coap-server -A 127.0.0.1 -p {port} -v 7`, ready when it logs `created UDP  endpoint`. It is
libcoap's example server: `/`, an observable `/time`, and a writable, observable
`/example_data`. A missing `coap-server` or `coap-client` **fails** the test.

`coap_client_reassembles_puts_and_observes_against_libcoap`:

1. `coap-client -m put -b 1024 -f big.txt` stores 3000 bytes (`0123456789` × 300) at
   `/example_data`; `coap-client -m get` confirms it.
2. On `coap_connected` the model GETs `/example_data`. libcoap answers in three 1024-byte Block2
   blocks; the model is shown one `coap_response` with `blocks: 3` and `payload_size: 3000`.
3. The model PUTs `the model read 3000 bytes ending in 0123456789` — or, if the body it was
   shown differs from what coap-client stored by a single byte, `REASSEMBLY MISMATCH …`.
4. On the PUT's 2.0x it observes `/time`: `coap_response {observing: true}`, then
   `coap_notification`s; the first is answered with `coap_observe_cancel`, and the
   cancellation's response arrives with `observing: false`. A notification that lands while the
   cancellation is in flight produces `coap_error {kind: not_observing}` (allowed, at most 10).

Then `coap-client -m get /example_data` must read the model's sentence. Condition 4 is asserted
from the server's side; emptying the loop over `result.actions` fails this test.

`injected_coap_put_reaches_libcoap` drives the command channel in-process (no model): a PUT that
`coap-client` reads back, a payload one byte over `MAX_REPRESENTATION_LEN` (64 KiB) refused
before the wire, and `disconnect`. Until Block1 existed the refusal was at 1025 bytes.

## blockwise_upload_test.rs — Block1

A script handler on `coap_connected` answers with `coap_put` of 3000 LCG letters — the answer a
model would give — so the upload is the client acting on its handler's answer, asserted at each
server. aiocoap is `tests/server/coap/peer/aiocoap_peer.py server` and needs
`NETGET_AIOCOAP_PYTHON`; like libcoap, missing, the test fails.

The coap-lite server answers block 0 (1024 bytes) with a 2.31 whose Block1 says SZX 4 (256
bytes). RFC 7959 §2.3 makes the client continue at the smaller size from the bytes already
acknowledged, so the next block is number **4**; the test asserts the whole sequence
`[0, 4, 5, …, 11]` and the body byte for byte. Making the client ignore the server's SZX fails it.

**Version note.** Homebrew ships libcoap 4.3.5; Ubuntu 22.04, where CI's registry-audit runs,
ships `libcoap2-bin` 4.2.1. The test was run against 4.3.5.

## Verified by mutation

Each removed on its own, with its test failing: the loop over `result.actions`
(`real_server_test`), the retransmission bound, `MAX_BODY`, the oversize drop, message-id
deduplication, RST for an unknown token, `MAX_EXCHANGES`, the block-order check
(`transport_test`), the payload refusal (`request_test`, now at `MAX_REPRESENTATION_LEN`), the
smaller block size a server asks for (`blockwise_upload_test`).
