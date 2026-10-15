"""Build the SS7 tests' peer into an owned ROOT: the jSS7 driver in jss7_peer/ (Ss7Peer.java over
Restcomm jSS7 8.0.112 from Maven Central and the JBoss repository), with Maven. Needs a JDK (11+)
and Maven on PATH (Ubuntu: openjdk-17-jdk-headless maven). Maven checks every artifact against the
repository's checksum; the versions are pinned in jss7_peer/pom.xml.

The other peer, osmo-stp (libosmo-sigtran's STP), is a distribution package: on Ubuntu
`sudo apt-get install osmo-stp`. Both suites fail, rather than skip, without their peers — and
need a kernel with SCTP (`sudo modprobe sctp`) and a dumpcap allowed to capture on loopback.

Usage: python3 install_peers.py /absolute/owned/root
Prints the NETGET_JSS7_PEER export (the runnable jar) the tests read.
"""
import os, pathlib, shutil, subprocess, sys

here = pathlib.Path(__file__).resolve().parent
root = pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
build = root / "jss7_peer"
jar = build / "target" / "jss7-peer.jar"

if not jar.exists():
    shutil.rmtree(build, ignore_errors=True)
    shutil.copytree(here / "jss7_peer", build)
    done = subprocess.run(
        ["mvn", "-q", "-B", "-s", "settings.xml", f"-Dmaven.repo.local={root / 'm2'}", "package"],
        cwd=build, timeout=3600, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if done.returncode != 0 or not jar.exists():
        sys.stderr.write(done.stdout[-20000:])
        sys.exit(f"mvn package exited {done.returncode} in {build}")

print("export NETGET_JSS7_PEER=" + str(jar))
