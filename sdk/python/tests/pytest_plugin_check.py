"""The pytest plugin's ``netget`` fixture, against a real netget binary ($NETGET_BIN).

Run from ``sdk/python``:
    python3 -m pytest -p netget_fixture.pytest_plugin tests/pytest_plugin_check.py

Named so ``unittest discover`` (which needs no pytest) does not pick it up.
"""

import socket

ECHO = {
    "type": "open_server",
    "protocol": "tcp",
    "port": 0,
    "instruction": "echo",
    "event_handlers": [
        {
            "event_pattern": "tcp_data_received",
            "handler": {
                "type": "static",
                "actions": [{"type": "send_tcp_data", "data": "{{event.data}}"}],
            },
        }
    ],
}

_seen = {}


def test_fixture_starts_two_instances(netget):
    first = netget(actions=[ECHO], no_model=True, max_lifetime=120)
    second = netget(actions=[ECHO], no_model=True, max_lifetime=120)
    assert first.address("tcp") != second.address("tcp")
    for instance in (first, second):
        with socket.create_connection(instance.address("tcp"), timeout=10) as conn:
            conn.sendall(b"pytest\n")
            assert conn.recv(64) == b"pytest\n"
    _seen["addresses"] = [first.address("tcp"), second.address("tcp")]
    _seen["dirs"] = [first.work_dir, second.work_dir]


def test_previous_instances_were_stopped():
    import os

    assert _seen, "runs after test_fixture_starts_two_instances"
    for directory in _seen["dirs"]:
        assert not os.path.exists(directory)
    for address in _seen["addresses"]:
        try:
            socket.create_connection(address, timeout=2).close()
        except OSError:
            continue
        raise AssertionError(f"{address} still accepts after teardown")
