#!/usr/bin/env python3
"""Install the MQTT 5 peers the v5 tests drive, into a directory of the caller's choosing.

    python3 tests/server/mqtt/install_v5_peers.py <dir>

Creates <dir>/venv with Eclipse Paho's Python client (paho-mqtt 2) and prints the variable
the tests read:

    NETGET_MQTT_PYTHON=<dir>/venv/bin/python

The Mosquitto clients and broker come from the system package manager
(apt-get install mosquitto mosquitto-clients / brew install mosquitto). The tests fail rather
than skip when any of these is missing.
"""
import os
import subprocess
import sys

PAHO = "paho-mqtt==2.1.0"


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = os.path.abspath(sys.argv[1])
    venv = os.path.join(root, "venv")
    python = os.path.join(venv, "bin", "python")
    if not os.path.exists(python):
        subprocess.run([sys.executable, "-m", "venv", venv], check=True)
    subprocess.run(
        [python, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", PAHO],
        check=True,
    )
    print(f"NETGET_MQTT_PYTHON={python}")


if __name__ == "__main__":
    main()
