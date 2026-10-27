"""Install the libp2p peers into an owned ROOT:
- the go-libp2p peer (go-libp2p v0.41.1, go.sum-pinned), built from peer/. Needs Go 1.24 or
  newer on PATH;
- Kubo 0.43.1 (go-ipfs), the official release tarball from github.com/ipfs/kubo, sha256
  pinned below (the release's own .sha512 files were checked when the pins were taken).
  macOS arm64 and Linux amd64 only;
- Helia (JavaScript IPFS: js-libp2p, @helia/unixfs, ipfs-unixfs-importer), pinned by
  helia/package-lock.json and installed with npm ci. Needs Node 22 or newer.

Usage: python3 install_peers.py /absolute/owned/root
Prints the NETGET_LIBP2P_GO_PEER, NETGET_KUBO and NETGET_HELIA exports the server and client
tests read.
"""
import hashlib, io, os, pathlib, platform, shutil, subprocess, sys, tarfile, urllib.request

root = pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
here = pathlib.Path(__file__).resolve().parent / "peer"
peer = root / "libp2p-peer"
env = dict(os.environ, GOFLAGS="-mod=readonly", CGO_ENABLED="0")
subprocess.run(["go", "build", "-trimpath", "-o", str(peer), "."], cwd=here, env=env, check=True, timeout=1800)
subprocess.run(["go", "mod", "verify"], cwd=here, env=env, check=True, timeout=300)

KUBO = "0.43.1"
SHA256 = {
    ("Darwin", "arm64"): ("darwin-arm64", "63ab05f578190a39aaba1e80b697644a9b717f5dc6a5485ec7a2bded68f9374f"),
    ("Linux", "x86_64"): ("linux-amd64", "3f2bf974ab2a3ec6d997fac7d8cb46f59983a7cddd0b55ef998e6ce379155fb2"),
}
key = (platform.system(), platform.machine())
assert key in SHA256, f"no pinned Kubo {KUBO} build for {key}"
target, sha = SHA256[key]
kubo = root / "kubo" / "ipfs"
if not kubo.exists():
    url = f"https://github.com/ipfs/kubo/releases/download/v{KUBO}/kubo_v{KUBO}_{target}.tar.gz"
    with urllib.request.urlopen(url, timeout=600) as r:
        data = r.read()
    got = hashlib.sha256(data).hexdigest()
    assert got == sha, f"{url}: sha256 {got}, expected {sha}"
    kubo.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as t, t.extractfile("kubo/ipfs") as src, open(kubo, "wb") as dst:
        shutil.copyfileobj(src, dst)
    kubo.chmod(0o755)
version = subprocess.run([str(kubo), "version"], check=True, timeout=60, capture_output=True, text=True).stdout
assert KUBO in version, version

# Helia 7.1.16 (@helia/unixfs 8.0.9, ipfs-unixfs-importer 17.1.1, js-libp2p 3.5.1): every
# module pinned with its integrity hash by helia/package-lock.json, installed with `npm ci`.
node = subprocess.run(["node", "--version"], check=True, timeout=60, capture_output=True, text=True).stdout.strip()
assert int(node.lstrip("v").split(".")[0]) >= 22, f"Helia needs Node 22 or newer, not {node}"
helia_src = pathlib.Path(__file__).resolve().parent / "helia"
helia = root / "helia"
helia.mkdir(parents=True, exist_ok=True)
for name in ("package.json", "package-lock.json", "helia_peer.mjs"):
    shutil.copyfile(helia_src / name, helia / name)
subprocess.run(["npm", "ci", "--no-audit", "--no-fund"], cwd=helia, check=True, timeout=1800)

print("export NETGET_LIBP2P_GO_PEER=" + str(peer))
print("export NETGET_KUBO=" + str(kubo))
print("export NETGET_HELIA=" + str(helia / "helia_peer.mjs"))
