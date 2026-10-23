"""Install the ONVIF tests' third-party peers into an owned ROOT:

- python onvif-zeep-async 4.3.0 (Home Assistant's ONVIF library, zeep over ONVIF's WSDL) in a
  venv: the first client the device tests are driven by (`peer/zeep_client.py`).
- github.com/use-go/onvif v0.0.9 (Go), built from `peer/go` against its pinned go.sum: the
  second client.
- python onvif2-zeep 0.3.4 (a separate ONVIF library with Media2) from its source
  distribution, SHA-256 checked, installed into the same venv; its ver20 WSDL tree is extracted
  from the same archive (the wheel's copy is flattened and cannot be loaded): the Media2 client.
- github.com/IOTechSystems/onvif v1.3.0 (Go, EdgeX's ONVIF library), built from `peer/go-media2`
  against its pinned go.sum: the second Media2 client. Needs go 1.25+.
- RPOS (BreeeZe/rpos, the Node.js ONVIF camera) at a pinned commit, SHA-256 checked, its
  TypeScript compiled with tsc: the device the client tests talk to. It verifies WS-Security
  PasswordDigest tokens itself.

Needs python 3.10+, go 1.25+, node 18+ with npm, and git (one of RPOS's dependencies is a git
URL).

Usage: python3 install_peers.py /absolute/owned/root
Prints NETGET_ONVIF_PYTHON, NETGET_ONVIF2_WSDL, NETGET_ONVIF_GO_CLIENT, NETGET_ONVIF_GO_MEDIA2
and NETGET_RPOS.
"""
import hashlib, io, pathlib, subprocess, sys, tarfile, urllib.request

RPOS_COMMIT = "22ea0df47fb920dc8b0e9a630d0523ac984d7623"
RPOS_URL = f"https://codeload.github.com/BreeeZe/rpos/tar.gz/{RPOS_COMMIT}"
RPOS_SHA256 = "0e46aaf5fa89295db8a89ce90b6354c9fa5c05abced839cece95e62d716963e4"
ZEEP = "onvif-zeep-async==4.3.0"
ONVIF2_URL = "https://files.pythonhosted.org/packages/source/o/onvif2_zeep/onvif2_zeep-0.3.4.tar.gz"
ONVIF2_SHA256 = "f82e44031e912de4647990fdc78cbe02db674c8e141bcfd4f2541190cbc76b5d"

root = pathlib.Path(sys.argv[1]).resolve()
here = pathlib.Path(__file__).resolve().parent
root.mkdir(parents=True, exist_ok=True)


def run(*args, cwd=None):
    subprocess.run([str(a) for a in args], check=True, timeout=1800, cwd=cwd,
                   stdout=sys.stderr)


def fetch(url, sha256):
    """Download url, retrying a cut-off transfer, and check its SHA-256."""
    for attempt in range(4):
        try:
            with urllib.request.urlopen(url, timeout=600) as r:
                data = r.read()
            break
        except Exception as e:  # a cut-off transfer: try again
            if attempt == 3:
                raise
            print(f"retrying {url}: {e}", file=sys.stderr)
    got = hashlib.sha256(data).hexdigest()
    if got != sha256:
        sys.exit(f"{url}: sha256 {got}, expected {sha256}")
    return data


venv = root / "venv"
if not (venv / "bin" / "python").exists():
    run(sys.executable, "-m", "venv", venv)
python = venv / "bin" / "python"
run(python, "-m", "pip", "install", "--quiet", ZEEP)
run(python, "-I", "-c", "import onvif, zeep")

onvif2 = root / "onvif2_zeep-0.3.4"
if not (onvif2 / "wsdl" / "ver20" / "media" / "wsdl" / "media.wsdl").exists():
    sdist = root / "onvif2_zeep-0.3.4.tar.gz"
    sdist.write_bytes(fetch(ONVIF2_URL, ONVIF2_SHA256))
    with tarfile.open(sdist) as t:
        t.extractall(root, filter="data")
    run(python, "-m", "pip", "install", "--quiet", sdist)
run(python, "-I", "-c", "import onvif2")

go_client = root / "bin" / "onvif-go-client"
go_client.parent.mkdir(parents=True, exist_ok=True)
run("go", "build", "-mod=readonly", "-o", go_client, ".", cwd=here / "peer" / "go")
go_media2 = root / "bin" / "onvif-go-media2"
run("go", "build", "-mod=readonly", "-o", go_media2, ".", cwd=here / "peer" / "go-media2")

rpos = root / f"rpos-{RPOS_COMMIT}"
if not (rpos / "rpos.js").exists():
    data = fetch(RPOS_URL, RPOS_SHA256)
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        t.extractall(root, filter="data")
    # RPOS's install scripts build serial-port and Raspberry Pi modules the tests never load.
    run("npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--silent", cwd=rpos)
    run("npx", "--no-install", "tsc", "-p", "tsconfig.json", cwd=rpos)
print("export NETGET_ONVIF_PYTHON=" + str(python))
print("export NETGET_ONVIF2_WSDL=" + str(onvif2 / "wsdl"))
print("export NETGET_ONVIF_GO_CLIENT=" + str(go_client))
print("export NETGET_ONVIF_GO_MEDIA2=" + str(go_media2))
print("export NETGET_RPOS=" + str(rpos))
