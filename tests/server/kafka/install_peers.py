"""Install the Kafka peers the flexible-version tests need, into one directory of their own.

- Apache Kafka's Java client, kafka-clients 3.9.1, and slf4j-api 1.7.36 (Maven Central),
  run by tests/server/kafka/peer/JavaPeer.java as a single-file source program.
- franz-go 1.18.1, built from tests/server/kafka/peer/franz/ with its go.sum pinned.
- Apache Kafka 3.9.1 itself (the official release), the real broker the client tests use.

Every download is checked against a pinned digest. Usage:
  python3 tests/server/kafka/install_peers.py <dir>
then export what it prints. Needs java (17+) and go on PATH.
"""
import hashlib, os, pathlib, shlex, shutil, subprocess, sys, tarfile, time, urllib.request

root = pathlib.Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
here = pathlib.Path(__file__).resolve().parent

DOWNLOADS = [
    ('https://repo1.maven.org/maven2/org/apache/kafka/kafka-clients/3.9.1/kafka-clients-3.9.1.jar',
     'sha256', '7568b998572d256f0b7bc0afdc1b7a2588b8b08415c62ce314c864a6851ae9d9'),
    ('https://repo1.maven.org/maven2/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar',
     'sha256', 'd3ef575e3e4979678dc01bf1dcce51021493b4d11fb7f1be8ad982877c16a1c0'),
    # The digest Apache publishes beside the release (kafka_2.13-3.9.1.tgz.sha512).
    ('https://archive.apache.org/dist/kafka/3.9.1/kafka_2.13-3.9.1.tgz',
     'sha512', '1ea204ba73411737a275429ca976d440f007ff0957b90b19be41dc5a4bae52617267769be9f0b5791714d0b3c4c760605bd426faea39edd90763585523fa2cfe'),
]

def fetch(url):
    # Maven Central answers 429 to bursts; back off and retry rather than fail the install.
    for attempt in range(6):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'curl/8.5'}), timeout=300).read()
        except urllib.error.HTTPError as e:
            if e.code != 429 or attempt == 5:
                raise
            time.sleep(2 ** attempt)

for url, algo, digest in DOWNLOADS:
    name = url.rsplit('/', 1)[1]
    target = root / name
    if name.endswith('.tgz') and (root / 'kafka_2.13-3.9.1').is_dir():
        continue
    data = target.read_bytes() if target.exists() else fetch(url)
    actual = hashlib.new(algo, data).hexdigest()
    assert actual == digest, f'{name}: {algo} {actual} is not the pinned {digest}'
    if name.endswith('.tgz'):
        with tarfile.open(fileobj=__import__('io').BytesIO(data), mode='r:gz') as archive:
            archive.extractall(root, filter='data')
    else:
        target.write_bytes(data)

franz = root / 'franz-src'
franz.mkdir(exist_ok=True)
for source, dest in [('main.go.txt', 'main.go'), ('go.mod.txt', 'go.mod'), ('go.sum.txt', 'go.sum')]:
    shutil.copyfile(here / 'peer' / 'franz' / source, franz / dest)
env = dict(os.environ, GOTOOLCHAIN='local', GOFLAGS='-mod=readonly', GOCACHE=str(root / 'go-cache'), GOMODCACHE=str(root / 'go-modcache'))
subprocess.run(['go', 'build', '-o', str(root / 'franz-peer'), '.'], cwd=franz, env=env, check=True)

print('export NETGET_KAFKA_PEERS=' + shlex.quote(str(root)))
