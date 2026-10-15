"""Build the GTP client's go-gtp peer (wmnsk/go-gtp v0.8.12, go.sum-pinned) into an owned ROOT.
Needs Go 1.24 or newer on PATH.

osmo-ggsn, the second peer, is a distribution package (`apt-get install osmo-ggsn` on
Ubuntu/Debian) and is not built here; tests/client/gtp/AGENTS.md says how it is run.

Usage: python3 install_peers.py /absolute/owned/root
Prints the NETGET_GTP_GO_PEER export tests/client/gtp/real_server_test.rs reads.
"""
import os, pathlib, subprocess, sys

root = pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
here = pathlib.Path(__file__).resolve().parent / "peer"
peer = root / "gtp-peer"
env = dict(os.environ, GOFLAGS="-mod=readonly", CGO_ENABLED="0")
subprocess.run(["go", "build", "-trimpath", "-o", str(peer), "."], cwd=here, env=env, check=True, timeout=900)
subprocess.run(["go", "mod", "verify"], cwd=here, env=env, check=True, timeout=300)
print("export NETGET_GTP_GO_PEER=" + str(peer))
