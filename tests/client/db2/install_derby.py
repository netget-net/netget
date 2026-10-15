"""Fetch Apache Derby 10.17.1.0 -- the DRDA server the Db2 client is tested against, and
Derby's own ij client that reads the results back -- into an owned ROOT.

The five jars come from Maven Central and each is checked against the SHA-256 pinned below
before it is kept. Derby 10.17 needs Java 21 or newer to run.

Usage: python3 install_derby.py /absolute/owned/root
Prints the NETGET_DERBY_LIB export tests/client/db2/derby.rs reads.
"""
import hashlib, pathlib, sys, urllib.request

VERSION = "10.17.1.0"
PINS = {
    "derby": "764e4c133f860a8876e835ef2306efecad27a742d27f05bc4bce669432c6b397",
    "derbynet": "c2f8e2d9a12208121b614c4abe97a2486d8dfa7b79799e3ffa735ac0852c6ba3",
    "derbyshared": "fb68bab30785375c1f8cb5e9583b349750f8904d6f7ee15ce8e1c30b6be30ef4",
    "derbytools": "c1e24e47d944a7c4c6fa88ad1a0989d7cf37e4108dc2fbde8cb07e758087996e",
    "derbyclient": "8f3e7a1f2eec23faf8c1c0fb21767b37c4d60d32223362a1f82a740b39b3726a",
}

root = pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
for artifact, pin in PINS.items():
    name = f"{artifact}-{VERSION}.jar"
    target = root / name
    if not (target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == pin):
        url = f"https://repo1.maven.org/maven2/org/apache/derby/{artifact}/{VERSION}/{name}"
        data = urllib.request.urlopen(url, timeout=120).read()
        got = hashlib.sha256(data).hexdigest()
        if got != pin:
            sys.exit(f"{name}: sha256 {got} is not the pinned {pin}")
        target.write_bytes(data)
print("export NETGET_DERBY_LIB=" + str(root))
