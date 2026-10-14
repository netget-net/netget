"""Install the ONVIF tests' third-party peers into an owned ROOT:

- python onvif-zeep-async 4.3.0 (Home Assistant's ONVIF library, zeep over ONVIF's WSDL) in a
  venv: the first client the device tests are driven by (`peer/zeep_client.py`).
- github.com/use-go/onvif v0.0.9 (Go), built from `peer/go` against its pinned go.sum: the
  second client.
- RPOS (BreeeZe/rpos, the Node.js ONVIF camera) at a pinned commit, SHA-256 checked, its
  TypeScript compiled with tsc: the device the client tests talk to. It verifies WS-Security
  PasswordDigest tokens itself.

Needs python 3.10+, go 1.21+, node 18+ with npm, and git (one of RPOS's dependencies is a git
URL).

Usage: python3 install_peers.py /absolute/owned/root
Prints NETGET_ONVIF_PYTHON, NETGET_ONVIF_GO_CLIENT and NETGET_RPOS.
"""
import hashlib, io, pathlib, subprocess, sys, tarfile, urllib.request

RPOS_COMMIT = "22ea0df47fb920dc8b0e9a630d0523ac984d7623"
RPOS_URL = f"https://codeload.github.com/BreeeZe/rpos/tar.gz/{RPOS_COMMIT}"
RPOS_SHA256 = "0e46aaf5fa89295db8a89ce90b6354c9fa5c05abced839cece95e62d716963e4"
ZEEP = "onvif-zeep-async==4.3.0"

root = pathlib.Path(sys.argv[1]).resolve()
here = pathlib.Path(__file__).resolve().parent
root.mkdir(parents=True, exist_ok=True)


def run(*args, cwd=None):
    subprocess.run([str(a) for a in args], check=True, timeout=1800, cwd=cwd,
                   stdout=sys.stderr)


venv = root / "venv"
if not (venv / "bin" / "python").exists():
    run(sys.executable, "-m", "venv", venv)
python = venv / "bin" / "python"
run(python, "-m", "pip", "install", "--quiet", ZEEP)
run(python, "-I", "-c", "import onvif, zeep")

go_client = root / "bin" / "onvif-go-client"
go_client.parent.mkdir(parents=True, exist_ok=True)
run("go", "build", "-mod=readonly", "-o", go_client, ".", cwd=here / "peer" / "go")

rpos = root / f"rpos-{RPOS_COMMIT}"
if not (rpos / "rpos.js").exists():
    for attempt in range(4):
        try:
            with urllib.request.urlopen(RPOS_URL, timeout=600) as r:
                data = r.read()
            break
        except Exception as e:  # a cut-off transfer: try again
            if attempt == 3:
                raise
            print(f"retrying the RPOS download: {e}", file=sys.stderr)
    got = hashlib.sha256(data).hexdigest()
    if got != RPOS_SHA256:
        sys.exit(f"{RPOS_URL}: sha256 {got}, expected {RPOS_SHA256}")
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        t.extractall(root, filter="data")
    # RPOS's install scripts build serial-port and Raspberry Pi modules the tests never load.
    run("npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--silent", cwd=rpos)
    run("npx", "--no-install", "tsc", "-p", "tsconfig.json", cwd=rpos)
print("export NETGET_ONVIF_PYTHON=" + str(python))
print("export NETGET_ONVIF_GO_CLIENT=" + str(go_client))
print("export NETGET_RPOS=" + str(rpos))
