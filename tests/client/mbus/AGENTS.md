# M-Bus master tests

| File | What it proves |
|---|---|
| `real_server_test.rs` | **pyMbusSlave** (Python, its own encoder, listening on TCP): the master's primary scan finds it at address 3, its secondary search finds its whole address, and both reads decode its voltage and volume records; its own log shows the SND_NKE, REQ_UD2 and selection the model's actions put on the wire. **mbus-device** (Addiva Elektronik, C, on Addiva's libmbus fork) behind `serial_gateway.py`, a pty-to-TCP bridge that is what an M-Bus/IP gateway is, answering with telegrams libmbus captured from real meters (Kamstrup Multical 601, Landis+Gyr UH T230, Eastron SDM630, Itron Cyble): the master's read over TCP decodes exactly what the codec decodes from the file, and that agrees with libmbus's normalised XML. The codec over **every** libmbus capture with a `.norm.xml`: identification, record count, storage, tariff and every value both read as the same quantity, against libmbus. |
| `e2e_test.rs` | Against **NetGet's own gateway — a regression, not evidence**: the wildcard search narrowing collisions, multi-telegram readouts and `max_telegrams`, writes acknowledged and refused, a new primary address, application reset, a timeout, a collision on a shared address, the follow-up depth (exactly 8 reads), and the fail-closed path with no model. |

Neither independent slave implements multi-telegram readouts or collisions, so those paths have
no independent peer. A python policy plays the model in every test.

Peers fail rather than skip:

```bash
sh scripts/test-peers/fetch-pymbusslave.sh /abs/dir   # PYMBUSSLAVE=/abs/dir/pyMbusSlave/slave.py
sh scripts/test-peers/build-mbus-device.sh /abs/dir   # MBUS_DEVICE=/abs/dir/bin/mbus-device
sh scripts/test-peers/build-libmbus.sh /abs/dir       # LIBMBUS_BIN=/abs/dir/bin (frames beside it)
python3 -m venv /abs/venv && /abs/venv/bin/pip install pyserial   # MBUS_PYTHON=/abs/venv/bin/python
./cargo-isolated.sh test --test client -- client::mbus:: --test-threads=8
```
