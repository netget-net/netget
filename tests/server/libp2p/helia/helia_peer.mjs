// Helia (js-libp2p, @helia/unixfs, ipfs-unixfs-importer): the second independent IPFS
// implementation the libp2p suites run against. Versions are pinned by package-lock.json and
// installed by ../install_peers.py. Loopback only: one TCP listener on 127.0.0.1, no
// bootstrap, no DHT, no delegated or HTTP routing, no gateways; a peer is dialled only when a
// test names it.
//
//   node helia_peer.mjs cid  <path> [opts]         the root CID ipfs-unixfs-importer builds
//   node helia_peer.mjs cat  <multiaddr> <cid>      fetch a file over Bitswap
//   node helia_peer.mjs get  <multiaddr> <cid>      fetch a directory tree over Bitswap
//   node helia_peer.mjs serve <path> [opts]         add a file or tree and serve it until stdin closes
//
// opts: --cid-version=0|1 --raw-leaves=true|false --chunk=N --max-links=N
// Every result is one JSON line on stdout.
import { createHeliaLight } from 'helia'
import { withBitswap } from '@helia/bitswap'
import { withLibp2pLight } from '@helia/libp2p'
import { unixfs } from '@helia/unixfs'
import { tcp } from '@libp2p/tcp'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { identify } from '@libp2p/identify'
import { ping } from '@libp2p/ping'
import { multiaddr } from '@multiformats/multiaddr'
import { CID } from 'multiformats/cid'
import { importer } from 'ipfs-unixfs-importer'
import { fixedSize } from 'ipfs-unixfs-importer/chunker'
import { balanced } from 'ipfs-unixfs-importer/layout'
import { MemoryBlockstore } from 'blockstore-core/memory'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const out = (o) => process.stdout.write(JSON.stringify(o) + '\n')
const sha256 = (b) => createHash('sha256').update(b).digest('hex')

function options (args) {
  const o = { cidVersion: 0, rawLeaves: undefined, chunk: 262144, maxLinks: 174 }
  for (const a of args) {
    const [k, v] = a.replace(/^--/, '').split('=')
    if (k === 'cid-version') o.cidVersion = Number(v)
    else if (k === 'raw-leaves') o.rawLeaves = v !== 'false'
    else if (k === 'chunk') o.chunk = Number(v)
    else if (k === 'max-links') o.maxLinks = Number(v)
  }
  // As Kubo: CIDv1 means raw leaves unless told otherwise (raw leaves under a CIDv0 root are
  // what Kubo's --raw-leaves alone makes).
  if (o.rawLeaves === undefined) o.rawLeaves = o.cidVersion === 1
  return {
    cidVersion: o.cidVersion,
    rawLeaves: o.rawLeaves,
    reduceSingleLeafToSelf: true,
    chunker: fixedSize({ chunkSize: o.chunk }),
    layout: balanced({ maxChildrenPerNode: o.maxLinks }),
    wrapWithDirectory: false
  }
}

// A file, or a tree (files and directories; symlinks are not something the importer takes),
// as importer candidates rooted at the path's own name.
function candidates (root) {
  const base = path.dirname(root)
  const list = []
  const walk = (p) => {
    const st = fs.lstatSync(p)
    const rel = path.relative(base, p)
    if (st.isDirectory()) {
      list.push({ path: rel })
      for (const name of fs.readdirSync(p).sort()) walk(path.join(p, name))
    } else if (st.isFile()) {
      list.push({ path: rel, content: fs.readFileSync(p) })
    }
  }
  walk(root)
  return list
}

async function importerCid (root, args) {
  const bs = new MemoryBlockstore()
  let last
  let blocks = 0
  for await (const entry of importer(candidates(root), bs, options(args))) last = entry
  for await (const _ of bs.getAll()) blocks++
  out({ step: 'cid', cid: last.cid.toString(), blocks })
}

async function node () {
  const helia = withBitswap(withLibp2pLight(createHeliaLight({}), {
    addresses: { listen: ['/ip4/127.0.0.1/tcp/0'] },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    peerDiscovery: [],
    services: { identify: identify(), ping: ping() }
  }))
  await helia.start()
  return helia
}

async function dialled (addr) {
  const helia = await node()
  const conn = await helia.libp2p.dial(multiaddr(addr), { signal: AbortSignal.timeout(20000) })
  out({ step: 'connected', peer: conn.remotePeer.toString(), agent: helia.libp2p.peerId.toString() })
  return helia
}

async function readAll (fsys, cid) {
  const chunks = []
  for await (const c of fsys.cat(cid, { signal: AbortSignal.timeout(60000) })) chunks.push(c)
  return Buffer.concat(chunks)
}

async function cat (addr, cid) {
  const helia = await dialled(addr)
  const fsys = unixfs(helia)
  const bytes = await readAll(fsys, CID.parse(cid))
  out({ step: 'cat', cid, size: bytes.length, sha256: sha256(bytes), head: bytes.subarray(0, 64).toString('utf8') })
  await helia.stop()
}

// Every path in the tree under a directory: its kind, size and, for a file, its hash.
async function get (addr, cid) {
  const helia = await dialled(addr)
  const fsys = unixfs(helia)
  const entries = []
  const visit = async (c, prefix) => {
    for await (const e of fsys.ls(c, { signal: AbortSignal.timeout(60000) })) {
      const p = prefix + e.name
      // A listing names entries; what each is, Helia reads from the entry's own root.
      const st = await fsys.stat(e.cid, { signal: AbortSignal.timeout(60000) })
      const type = st.unixfs?.type ?? st.type
      if (type === 'directory') {
        entries.push({ path: p, type: 'directory', cid: e.cid.toString() })
        await visit(e.cid, p + '/')
      } else if (type === 'file' || type === 'raw') {
        const bytes = await readAll(fsys, e.cid)
        entries.push({ path: p, type: 'file', cid: e.cid.toString(), size: bytes.length, sha256: sha256(bytes) })
      } else {
        entries.push({ path: p, type, cid: e.cid.toString() })
      }
    }
  }
  await visit(CID.parse(cid), '')
  out({ step: 'get', cid, entries })
  await helia.stop()
}

async function serve (root, args) {
  const helia = await node()
  const fsys = unixfs(helia)
  let last
  for await (const entry of fsys.addAll(candidates(root), options(args))) last = entry
  const addr = helia.libp2p.getMultiaddrs().map(String).find((a) => a.startsWith('/ip4/127.0.0.1/tcp/'))
  out({ step: 'serving', cid: last.cid.toString(), addr })
  helia.libp2p.addEventListener('peer:connect', (e) => out({ step: 'peer_connected', peer: e.detail.toString() }))
  await new Promise((resolve) => {
    process.stdin.on('end', resolve)
    process.stdin.on('close', resolve)
    process.stdin.resume()
  })
  await helia.stop()
}

const [mode, a, b, ...rest] = process.argv.slice(2)
try {
  if (mode === 'cid') await importerCid(a, [b, ...rest].filter(Boolean))
  else if (mode === 'cat') await cat(a, b)
  else if (mode === 'get') await get(a, b)
  else if (mode === 'serve') await serve(a, [b, ...rest].filter(Boolean))
  else throw new Error(`unknown mode ${mode}`)
  process.exit(0)
} catch (err) {
  out({ step: 'error', mode, error: String(err?.stack ?? err) })
  process.exit(1)
}
