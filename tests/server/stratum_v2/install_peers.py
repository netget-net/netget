"""Install the Stratum V2 tests' peers into an owned ROOT, each pinned:

- SRI's sv2-apps at v0.8.0 (commit 7f49074357e5): `pool_sv2`, the pool the client tests mine
  against (its embedded Job Declaration Server is the JDS NetGet's Job Declarator Client
  declares to, and it takes templates from NetGet's Template Provider over network TDP),
  `mining_device`, the CPU miner the server tests point at NetGet's pool, and
  `jd_client_sv2`, the Job Declarator Client that declares jobs to NetGet's JDS. All three are
  built from source with cargo; they frame, encrypt and hash with SRI's own crates
  (noise_sv2, codec_sv2, binary_sv2, channels_sv2, job_declaration_sv2,
  template_distribution_sv2), none of which NetGet links.
- Bitcoin Core 31.0 (SHA-256 pinned): `bitcoin-node`, whose IPC socket `pool_sv2` takes its
  templates from, and `bitcoin-cli`.

Building sv2-apps needs a Rust toolchain and the Cap'n Proto compiler with its standard schemas
(Ubuntu: capnproto and libcapnp-dev — the Bitcoin Core IPC schemas import /capnp/c++.capnp, which
only libcapnp-dev installs; macOS: brew install capnp, which ships both). Only the two binaries
are kept (ROOT/bin), so ROOT is small enough to cache.

Usage: python3 install_peers.py /absolute/owned/root
Prints the NETGET_SV2_POOL, NETGET_SV2_MINING_DEVICE, NETGET_SV2_JD_CLIENT,
NETGET_SV2_BITCOIN_NODE and NETGET_SV2_BITCOIN_CLI exports the tests read.
"""
import hashlib, os, pathlib, platform, shutil, subprocess, sys, tarfile, urllib.request

SV2_APPS = ("https://github.com/stratum-mining/sv2-apps", "v0.8.0",
            "7f49074357e54da4f5b13acfcc29dc3cbb9e541f")
BITCOIN = {
    ("Linux", "x86_64"): ("bitcoin-31.0-x86_64-linux-gnu.tar.gz",
                          "d3e4c58a35b1d0a97a457462c94f55501ad167c660c245cb1ffa565641c65074"),
    ("Linux", "aarch64"): ("bitcoin-31.0-aarch64-linux-gnu.tar.gz",
                           "4de1d568dedd48604f75132421bc0abeca432639589b49a3909c81db3a813112"),
    ("Darwin", "arm64"):("bitcoin-31.0-arm64-apple-darwin.tar.gz",
                          "a2d7a13b4da53d4a3e4c517f3a0269e2429813417bb320d3b268993cfdc545d0"),
}

root = pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)


def run(cmd, cwd, env=None):
    """Run quietly (stdout carries only the exports), but show everything when it fails."""
    done = subprocess.run(cmd, cwd=cwd, timeout=3600, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if done.returncode != 0:
        sys.stderr.write(done.stdout[-20000:])
        sys.exit(f"{' '.join(cmd)} exited {done.returncode} in {cwd}")


def sv2_apps():
    """Build the three binaries into ROOT/bin, then drop the sources and the cargo target."""
    bin_dir = root / "bin"
    pool, device = bin_dir / "pool_sv2", bin_dir / "mining_device"
    jdc = bin_dir / "jd_client_sv2"
    if pool.exists() and device.exists() and jdc.exists():
        return pool, device, jdc
    src = root / "sv2-apps"
    url, tag, commit = SV2_APPS
    if not src.exists():
        tmp = root / "sv2-apps.tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        run(["git", "clone", "--quiet", "--depth", "1", "--branch", tag, url, str(tmp)], root)
        tmp.rename(src)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=src, check=True,
                          capture_output=True, text=True).stdout.strip()
    if head != commit:
        sys.exit(f"sv2-apps {tag} is {head}, expected {commit}")
    target = root / "target"
    # sv2-apps pins its toolchain in rust-toolchain.toml; stable builds it too, and wherever
    # rustup is in charge this avoids a second toolchain download.
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    env.setdefault("RUSTUP_TOOLCHAIN", "stable")
    run(["cargo", "build", "--release", "--locked", "--manifest-path",
         "pool-apps/Cargo.toml", "-p", "pool_sv2", "--bin", "pool_sv2"], src, env)
    run(["cargo", "build", "--release", "--locked", "--manifest-path",
         "integration-tests/Cargo.toml", "--bin", "mining_device"], src, env)
    run(["cargo", "build", "--release", "--locked", "--manifest-path",
         "miner-apps/Cargo.toml", "-p", "jd_client_sv2", "--bin", "jd_client_sv2"], src, env)
    bin_dir.mkdir(exist_ok=True)
    for name, dest in [("pool_sv2", pool), ("mining_device", device), ("jd_client_sv2", jdc)]:
        shutil.copy2(target / "release" / name, dest)
    shutil.rmtree(target, ignore_errors=True)
    shutil.rmtree(src, ignore_errors=True)
    return pool, device, jdc


def bitcoin():
    key = (platform.system(), platform.machine())
    if key not in BITCOIN:
        sys.exit(f"no pinned Bitcoin Core 31.0 build for {key}")
    name, digest = BITCOIN[key]
    home = root / "bitcoin-31.0"
    if not home.exists():
        url = f"https://bitcoincore.org/bin/bitcoin-core-31.0/{name}"
        with urllib.request.urlopen(url, timeout=600) as r:
            data = r.read()
        got = hashlib.sha256(data).hexdigest()
        if got != digest:
            sys.exit(f"{url}: sha256 {got}, expected {digest}")
        archive = root / name
        archive.write_bytes(data)
        with tarfile.open(archive) as t:
            t.extractall(root, filter="data")
        archive.unlink()
    return home / "libexec" / "bitcoin-node", home / "bin" / "bitcoin-cli"


pool, device, jdc = sv2_apps()
node, cli = bitcoin()
for exe in [pool, device, jdc, node, cli]:
    if not exe.exists():
        sys.exit(f"{exe} was not built")
print("export NETGET_SV2_POOL=" + str(pool))
print("export NETGET_SV2_MINING_DEVICE=" + str(device))
print("export NETGET_SV2_JD_CLIENT=" + str(jdc))
print("export NETGET_SV2_BITCOIN_NODE=" + str(node))
print("export NETGET_SV2_BITCOIN_CLI=" + str(cli))
