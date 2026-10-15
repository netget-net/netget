#!/usr/bin/env node
'use strict';

// Launcher for the platform-native netget binary.
//
// Resolution order:
//   1. NETGET_BINARY env override
//   2. The @smotana/netget-<platform> optional dependency
//   3. Cached download in the user cache dir
//   4. Download from GitHub Releases (base overridable via NETGET_DOWNLOAD_BASE)
//
// This script must NEVER write to stdout: in `--mcp` mode stdout carries
// JSON-RPC framing for the MCP client. All diagnostics go to stderr.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const { Readable, Transform } = require('stream');
const crypto = require('crypto');
const { pipeline } = require('stream/promises');

const pkg = require('../package.json');
const VERSION = pkg.version;
const DOWNLOAD_BASE =
  process.env.NETGET_DOWNLOAD_BASE ||
  'https://github.com/netget-net/netget/releases/download';

const PLATFORMS = {
  'darwin-arm64': { triple: 'aarch64-apple-darwin', ext: 'tar.gz' },
  'darwin-x64': { triple: 'x86_64-apple-darwin', ext: 'tar.gz' },
  'linux-x64': { triple: 'x86_64-unknown-linux-gnu', ext: 'tar.gz' },
  'linux-arm64': { triple: 'aarch64-unknown-linux-gnu', ext: 'tar.gz' },
  'linux-x64-musl': { triple: 'x86_64-unknown-linux-musl', ext: 'tar.gz' },
  'win32-x64': { triple: 'x86_64-pc-windows-msvc', ext: 'zip' },
};

function isMusl() {
  // glibcVersionRuntime is absent on musl-based systems (e.g. Alpine).
  try {
    const report = process.report.getReport();
    return !report.header.glibcVersionRuntime;
  } catch {
    return false;
  }
}

function platformKey() {
  const { platform, arch } = process;
  if (platform === 'darwin' && arch === 'arm64') return 'darwin-arm64';
  if (platform === 'darwin' && arch === 'x64') return 'darwin-x64';
  if (platform === 'linux' && arch === 'x64')
    return isMusl() ? 'linux-x64-musl' : 'linux-x64';
  if (platform === 'linux' && arch === 'arm64') {
    if (isMusl()) fail(`no prebuilt netget binary for linux-arm64 (musl)`);
    return 'linux-arm64';
  }
  if (platform === 'win32' && arch === 'x64') return 'win32-x64';
  return null;
}

function fail(message) {
  process.stderr.write(`netget: ${message}\n`);
  process.exit(1);
}

function binName() {
  return process.platform === 'win32' ? 'netget.exe' : 'netget';
}

function resolveOptionalDep(key) {
  try {
    return require.resolve(`@smotana/netget-${key}/bin/${binName()}`);
  } catch {
    return null;
  }
}

function cacheDir(key) {
  if (process.platform === 'win32' && process.env.LOCALAPPDATA) {
    return path.join(process.env.LOCALAPPDATA, 'netget', 'bin', VERSION, key);
  }
  const base =
    process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');
  return path.join(base, 'netget', VERSION, key);
}

async function download(url, dest, { timeoutMs = 120_000, maxBytes = 512 * 1024 * 1024, fetchImpl = fetch } = {}) {
  const signal = AbortSignal.timeout(timeoutMs);
  const res = await fetchImpl(url, { redirect: 'follow', signal });
  if (!res.ok) throw new Error(`download failed: ${res.status} ${res.statusText} (${url})`);
  if (!res.body) throw new Error(`download had no body (${url})`);
  const hash = crypto.createHash('sha256');
  let received = 0;
  const digest = new Transform({
    transform(chunk, encoding, callback) {
      received += chunk.length;
      if (received > maxBytes) return callback(new Error(`download exceeds ${maxBytes} bytes`));
      hash.update(chunk);
      callback(null, chunk);
    },
  });
  await pipeline(Readable.fromWeb(res.body), digest, fs.createWriteStream(dest, { flags: 'wx' }), { signal });
  return hash.digest('hex');
}

function expectedChecksum(manifest, archiveName) {
  const matches = manifest.split(/\r?\n/).flatMap(line => {
    const match = /^([a-fA-F0-9]{64}) [ *](.+)$/.exec(line);
    return match && match[2] === archiveName ? [match[1].toLowerCase()] : [];
  });
  if (matches.length !== 1) throw new Error(`SHA256SUMS must contain exactly one checksum for ${archiveName}; install the platform package or use a release with a checksum manifest`);
  return matches[0];
}

async function fetchBinary(key, { base = DOWNLOAD_BASE, timeoutMs = 120_000, cache = cacheDir(key), temporaryRoot = os.tmpdir(), fetchImpl = fetch } = {}) {
  const { triple, ext } = PLATFORMS[key];
  const dir = cache;
  const cached = path.join(dir, binName());
  if (fs.existsSync(cached)) {
    if (!fs.lstatSync(cached).isFile()) throw new Error(`cached binary is not a regular file: ${cached}`);
    return cached;
  }

  const archiveName = `netget-${triple}.${ext}`;
  const url = `${base}/v${VERSION}/${archiveName}`;
  process.stderr.write(`netget: downloading ${url}\n`);

  fs.mkdirSync(dir, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(temporaryRoot, 'netget-'));
  const staging = path.join(dir, `.${binName()}.tmp-${crypto.randomUUID()}`);
  try {
    const archive = path.join(tmp, archiveName);
    const manifestPath = path.join(tmp, 'SHA256SUMS');
    try {
      await download(`${base}/v${VERSION}/SHA256SUMS`, manifestPath, { timeoutMs, maxBytes: 128 * 1024, fetchImpl });
    } catch (error) {
      throw new Error(`release checksum manifest unavailable (${error.message}); install the platform package or use a release with SHA256SUMS`);
    }
    const expected = expectedChecksum(fs.readFileSync(manifestPath, 'utf8'), archiveName);
    const actual = await download(url, archive, { timeoutMs, fetchImpl });
    if (actual !== expected) throw new Error(`SHA-256 mismatch for ${archiveName}; refusing to extract or execute it`);
    // System tar handles .tar.gz everywhere and .zip on Windows (bsdtar).
    const tar = spawnSync('tar', ['-xf', archive, '-C', tmp, '--', binName()], {
      stdio: ['ignore', 'ignore', 'inherit'],
      timeout: timeoutMs,
      killSignal: 'SIGKILL',
    });
    if (tar.status !== 0) throw new Error('failed to extract archive');
    const extracted = path.join(tmp, binName());
    if (!fs.existsSync(extracted) || !fs.lstatSync(extracted).isFile()) {
      throw new Error(`archive did not contain a regular ${binName()} file`);
    }
    if (process.platform !== 'win32') fs.chmodSync(extracted, 0o755);
    // Atomic within the same filesystem is not guaranteed across tmp -> cache,
    // so copy to a temp name inside the cache dir, then rename.
    fs.copyFileSync(extracted, staging);
    if (process.platform !== 'win32') fs.chmodSync(staging, 0o755);
    fs.renameSync(staging, cached);
    return cached;
  } finally {
    try { fs.rmSync(staging, { force: true }); }
    finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  }
}

async function resolveBinary() {
  if (process.env.NETGET_BINARY) return process.env.NETGET_BINARY;

  const key = platformKey();
  if (!key) {
    fail(
      `unsupported platform ${process.platform}-${process.arch}; ` +
        `build from source: https://github.com/netget-net/netget`
    );
  }
  const fromDep = resolveOptionalDep(key);
  if (fromDep) return fromDep;

  try {
    return await fetchBinary(key);
  } catch (err) {
    fail(
      `could not locate the @smotana/netget-${key} package or download the ` +
        `binary (${err.message}). Try reinstalling without --ignore-scripts/` +
        `--omit=optional, or set NETGET_BINARY to a netget binary.`
    );
  }
}

async function main() {
  const bin = await resolveBinary();
  const child = spawn(bin, process.argv.slice(2), { stdio: 'inherit' });

  // Forward termination signals; let the child drive shutdown so MCP servers
  // exit cleanly when the client (e.g. Claude Code) stops them.
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(sig, () => {
      if (child.exitCode === null && child.signalCode === null) child.kill(sig);
    });
  }

  child.on('error', (err) => fail(`failed to run ${bin}: ${err.message}`));
  child.on('exit', (code, signal) => {
    if (signal) {
      // Re-raise so our own exit status reflects the child's signal death.
      process.removeAllListeners(signal);
      process.kill(process.pid, signal);
    } else {
      process.exit(code == null ? 1 : code);
    }
  });
}

if (require.main === module) main().catch((err) => fail(err.message));
module.exports = { download, fetchBinary, expectedChecksum, platformKey };
