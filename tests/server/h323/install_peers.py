"""Build the H323Plus peers of the H.323 suites into an owned ROOT: GNU Gatekeeper (`gnugk`) and
H323Plus's sample endpoint (`simph323`), with the PTLib they need, from the projects' own
GitHub release tags. Neither is packaged for Ubuntu 24.04 or Homebrew.

    PTLib     willamowius/ptlib     v2_10_9_6
    H323Plus  willamowius/h323plus  v1_28_0   (and samples/simple, built as simph323)
    GnuGk     willamowius/gnugk     v5_16

Needs a C++ toolchain, autoconf, flex, bison, pkg-config and the OpenSSL and expat headers
(Ubuntu: build-essential autoconf flex bison pkg-config libssl-dev libexpat1-dev). Everything
is linked statically against PTLib and H323Plus, so the binaries need nothing from ROOT at run
time but themselves. The other peer family, Asterisk's chan_ooh323 (ooh323c), is a distribution
package: `sudo apt-get install asterisk asterisk-ooh323`.

Usage: python3 install_peers.py /absolute/owned/root
Prints ROOT/bin, where `gnugk` and `simph323` are; put it on PATH.
"""
import glob, os, pathlib, shutil, subprocess, sys, urllib.request

PINS = [("ptlib", "v2_10_9_6"), ("h323plus", "v1_28_0"), ("gnugk", "v5_16")]

root = pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
src = root / "src"
src.mkdir(exist_ok=True)
bin_dir = root / "bin"
bin_dir.mkdir(exist_ok=True)
jobs = str(os.cpu_count() or 2)


def run(args, cwd, env, log):
    with open(root / log, "w") as out:
        done = subprocess.run(args, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT, timeout=3600)
    if done.returncode != 0:
        sys.stderr.write((root / log).read_text()[-20000:])
        sys.exit(f"{' '.join(args)} exited {done.returncode} in {cwd}")


def fetch(name, tag):
    dest = src / name
    if dest.exists():
        return dest
    url = f"https://github.com/willamowius/{name}/archive/refs/tags/{tag}.tar.gz"
    archive = src / f"{name}.tar.gz"
    urllib.request.urlretrieve(url, archive)
    subprocess.run(["tar", "-xzf", str(archive), "-C", str(src)], check=True)
    unpacked = next(p for p in src.iterdir() if p.is_dir() and p.name.startswith(f"{name}-"))
    unpacked.rename(dest)
    archive.unlink()
    return dest


def built(pattern):
    found = glob.glob(pattern)
    return pathlib.Path(found[0]) if found else None


gnugk_bin = built(str(src / "gnugk/obj_*/gnugk"))
simple_bin = built(str(src / "h323plus/samples/simple/obj_*/simph323"))
if not (gnugk_bin and simple_bin):
    env = dict(os.environ, PTLIBDIR=str(src / "ptlib"), OPENH323DIR=str(src / "h323plus"))
    for name, tag in PINS:
        fetch(name, tag)
    run(["./configure", "--disable-sdl", "--disable-video", "--disable-odbc", "--disable-ldap",
         "--disable-sasl", "--disable-lua", "--enable-ipv6"], src / "ptlib", env, "ptlib-configure.log")
    run(["make", f"-j{jobs}", "optnoshared"], src / "ptlib", env, "ptlib-make.log")
    run(["./configure", "--disable-video"], src / "h323plus", env, "h323plus-configure.log")
    run(["make", f"-j{jobs}", "optnoshared"], src / "h323plus", env, "h323plus-make.log")
    run(["make", "optnoshared"], src / "h323plus/samples/simple", env, "simple-make.log")
    run(["./configure", "--with-large-fdset=1024"], src / "gnugk", env, "gnugk-configure.log")
    run(["make", f"-j{jobs}", "optnoshared"], src / "gnugk", env, "gnugk-make.log")
    gnugk_bin = built(str(src / "gnugk/obj_*/gnugk"))
    simple_bin = built(str(src / "h323plus/samples/simple/obj_*/simph323"))
    if not (gnugk_bin and simple_bin):
        sys.exit("the build finished without gnugk or simph323")

for binary in (gnugk_bin, simple_bin):
    shutil.copy2(binary, bin_dir / binary.name)
print(bin_dir)
