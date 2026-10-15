"""Install the devp2p suites' third-party peers into an owned ROOT:

- go-ethereum 1.17.8's geth: the official geth-alltools tarball for linux amd64/arm64 from
  gethstore.blob.core.windows.net, sha256 pinned below. On macOS use `brew install ethereum`
  (1.17.8 at the time of writing), which also provides `devp2p`.
- go-ethereum 1.17.8's devp2p tool: the alltools tarball no longer carries it, so it is built
  with `go install github.com/ethereum/go-ethereum/cmd/devp2p@v1.17.8` (module checksums
  verified against sum.golang.org). Needs Go 1.24 or newer on PATH. Linux only; brew on macOS.
- reth 2.7.0: the official release tarball from github.com/paradigmxyz/reth, sha256 pinned
  below, for linux x86_64/aarch64 and macOS arm64.

Usage: python3 install_peers.py /absolute/owned/root
Prints the NETGET_GETH, NETGET_DEVP2P and NETGET_RETH exports the tests read
(tests/helpers/ethereum.rs); on macOS only NETGET_RETH.
"""
import hashlib, io, os, pathlib, platform, shutil, subprocess, sys, tarfile, urllib.request

root = pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
bindir = root / "bin"
bindir.mkdir(exist_ok=True)
system, machine = platform.system(), platform.machine()


def fetch(url, sha):
    with urllib.request.urlopen(url, timeout=600) as r:
        data = r.read()
    got = hashlib.sha256(data).hexdigest()
    assert got == sha, f"{url}: sha256 {got}, expected {sha}"
    return data


def extract(data, member, dest):
    with tarfile.open(fileobj=io.BytesIO(data)) as t, t.extractfile(member) as src, open(dest, "wb") as dst:
        shutil.copyfileobj(src, dst)
    dest.chmod(0o755)


GETH = "1.17.8"
GETH_COMMIT = "a5790770"
GETH_SHA256 = {
    ("Linux", "x86_64"): ("linux-amd64", "3bcf870a525c815e20713aea238982db6c18ac53d4e8bdcb79109c11b430f911"),
    ("Linux", "aarch64"): ("linux-arm64", "b07ee3638008f7035e610b0e4d80bcd62f6f8d452b2d7a7577d846264817cf5b"),
}
RETH = "2.7.0"
RETH_SHA256 = {
    ("Linux", "x86_64"): ("x86_64-unknown-linux-gnu", "c91ef845f97c28e9fdb60de04eee871f957738548d474c9b6379debbf3f1064a"),
    ("Linux", "aarch64"): ("aarch64-unknown-linux-gnu", "5a5ae8a380c9bf09969b39e092c09edcbbdbab61244ee51707c0529713d07d87"),
    ("Darwin", "arm64"): ("aarch64-apple-darwin", "d551806bb7735e668f46d28ef66abd021c864aa6b382b4cf5d9c6f20161750ec"),
}

exports = {}
if system == "Linux":
    assert (system, machine) in GETH_SHA256, f"no pinned geth {GETH} build for {(system, machine)}"
    target, sha = GETH_SHA256[(system, machine)]
    geth = bindir / "geth"
    if not geth.exists():
        name = f"geth-alltools-{target}-{GETH}-{GETH_COMMIT}"
        data = fetch(f"https://gethstore.blob.core.windows.net/builds/{name}.tar.gz", sha)
        extract(data, f"{name}/geth", geth)
    exports["NETGET_GETH"] = geth
    devp2p = bindir / "devp2p"
    if not devp2p.exists():
        env = dict(os.environ, GOBIN=str(bindir), CGO_ENABLED="0", GOFLAGS="-mod=mod")
        subprocess.run(
            ["go", "install", f"github.com/ethereum/go-ethereum/cmd/devp2p@v{GETH}"],
            env=env, check=True, timeout=1800,
        )
    exports["NETGET_DEVP2P"] = devp2p

assert (system, machine) in RETH_SHA256, f"no pinned reth {RETH} build for {(system, machine)}"
target, sha = RETH_SHA256[(system, machine)]
reth = bindir / "reth"
if not reth.exists():
    data = fetch(f"https://github.com/paradigmxyz/reth/releases/download/v{RETH}/reth-v{RETH}-{target}.tar.gz", sha)
    extract(data, "reth", reth)
exports["NETGET_RETH"] = reth

for name, path in exports.items():
    out = subprocess.run([str(path), "--version"] if name != "NETGET_DEVP2P" else [str(path), "--help"],
                         check=True, timeout=60, capture_output=True, text=True).stdout
    if name == "NETGET_GETH":
        assert GETH in out, out
    if name == "NETGET_RETH":
        assert RETH in out, out
for name, path in exports.items():
    print(f"export {name}={path}")
