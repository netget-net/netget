"""Build the NGAP server tests' peer into an owned ROOT, pinned: UERANSIM v3.2.7 (`nr-gnb`, `nr-cli`,
`nr-ue`), from its release tarball with the SHA-256 below. UERANSIM is Linux-only C++; building
it needs cmake, g++ and the lksctp headers (Ubuntu: cmake g++ libsctp-dev lksctp-tools). Only the
two binaries are kept (ROOT/ueransim/build), so ROOT is small enough to cache.

The client tests' peer, Open5GS's AMF, is a distribution package rather than something this
script builds: on Ubuntu, `sudo add-apt-repository ppa:open5gs/latest` then
`sudo apt-get install open5gs-amf` puts `open5gs-amfd` on PATH. Both suites fail, rather than
skip, without their peer — and both need a kernel with SCTP (`sudo modprobe sctp`) and a dumpcap
allowed to capture on loopback (`sudo setcap cap_net_raw,cap_net_admin=eip $(command -v dumpcap)`).

Usage: python3 install_peers.py /absolute/owned/root
Prints the NETGET_UERANSIM_DIR export the server tests read.
"""
import hashlib, os, pathlib, shutil, subprocess, sys, tarfile, urllib.request

UERANSIM = ("https://codeload.github.com/aligungr/UERANSIM/tar.gz/refs/tags/v3.2.7",
            "e99a783d4b95cecf4c65a159ded7e7071ce46cb52d98e18f313eb5a3d220646b")

root = pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
build = root / "ueransim" / "build"


def run(cmd, cwd):
    """Run quietly (stdout carries only the export), but show everything when it fails."""
    done = subprocess.run(cmd, cwd=cwd, timeout=3600,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if done.returncode != 0:
        sys.stderr.write(done.stdout[-20000:])
        sys.exit(f"{' '.join(cmd)} exited {done.returncode} in {cwd}")


if not all((build / b).exists() for b in ("nr-gnb", "nr-ue", "nr-cli")):
    url, digest = UERANSIM
    archive = root / "ueransim.tar.gz"
    with urllib.request.urlopen(url, timeout=300) as response:
        data = response.read()
    actual = hashlib.sha256(data).hexdigest()
    if actual != digest:
        sys.exit(f"UERANSIM tarball SHA-256 is {actual}, expected {digest}")
    archive.write_bytes(data)
    src = root / "ueransim-src"
    shutil.rmtree(src, ignore_errors=True)
    src.mkdir()
    with tarfile.open(archive) as tar:
        members = []
        for m in tar.getmembers():
            parts = pathlib.PurePosixPath(m.name).parts[1:]
            if not parts or ".." in parts or m.issym() or m.islnk():
                continue
            m.name = str(pathlib.PurePosixPath(*parts))
            members.append(m)
        tar.extractall(src, members=members)
    cmake_dir = src / "cmake-build-release"
    cmake_dir.mkdir()
    run(["cmake", "-DCMAKE_BUILD_TYPE=Release", ".."], cmake_dir)
    run(["make", f"-j{max(2, os.cpu_count() or 2)}", "nr-gnb", "nr-ue", "nr-cli"], cmake_dir)
    build.mkdir(parents=True, exist_ok=True)
    for binary in ("nr-gnb", "nr-ue", "nr-cli"):
        shutil.copy2(cmake_dir / binary, build / binary)
    shutil.rmtree(src)
    archive.unlink()

print("export NETGET_UERANSIM_DIR=" + str(build))
