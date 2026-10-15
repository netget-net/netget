#!/usr/bin/env node
// Generates publishable npm packages under dist/npm/ from prebuilt binaries.
//
// Usage:
//   node scripts/npm/prepare-packages.mjs <version> --binaries <dir>
//       <dir> layout: <platform-key>/netget[.exe] for each platform key,
//       e.g. binaries/darwin-arm64/netget, binaries/win32-x64/netget.exe
//   node scripts/npm/prepare-packages.mjs <version> --local <path-to-netget-binary>
//       Dev mode: packages only the current host platform using the given binary.
//
// Output:
//   dist/npm/netget/            main @smotana/netget package (shim)
//   dist/npm/netget-<key>/      @smotana/netget-<key> platform packages
//
// The main package's optionalDependencies are pinned to the exact version and
// include ONLY the platform packages generated in this run (all six in CI).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..');

const PLATFORMS = {
  'darwin-arm64': { os: 'darwin', cpu: 'arm64' },
  'darwin-x64': { os: 'darwin', cpu: 'x64' },
  'linux-x64': { os: 'linux', cpu: 'x64', libc: ['glibc'] },
  'linux-arm64': { os: 'linux', cpu: 'arm64', libc: ['glibc'] },
  'linux-x64-musl': { os: 'linux', cpu: 'x64', libc: ['musl'] },
  'win32-x64': { os: 'win32', cpu: 'x64' },
};

function usage(msg) {
  if (msg) console.error(`error: ${msg}`);
  console.error(
    'usage: prepare-packages.mjs <version> (--binaries <dir> | --local <binary>)'
  );
  process.exit(2);
}

const [version, mode, modeArg] = process.argv.slice(2);
if (!version || !/^\d+\.\d+\.\d+(-[\w.]+)?$/.test(version)) {
  usage(`invalid or missing version: ${version ?? '(none)'}`);
}
if (!['--binaries', '--local'].includes(mode) || !modeArg) usage();

function hostPlatformKey() {
  const { platform, arch } = process;
  const key = `${platform === 'win32' ? 'win32' : platform}-${arch}`;
  if (!PLATFORMS[key]) usage(`unsupported host platform: ${key}`);
  return key;
}

// Map of platform key -> path to binary
const binaries = {};
if (mode === '--local') {
  const bin = path.resolve(modeArg);
  if (!fs.existsSync(bin)) usage(`binary not found: ${bin}`);
  binaries[hostPlatformKey()] = bin;
} else {
  const dir = path.resolve(modeArg);
  for (const key of Object.keys(PLATFORMS)) {
    const name = key.startsWith('win32') ? 'netget.exe' : 'netget';
    const candidate = path.join(dir, key, name);
    if (fs.existsSync(candidate)) binaries[key] = candidate;
  }
  if (Object.keys(binaries).length === 0) {
    usage(`no binaries found under ${dir} (expected <platform-key>/netget)`);
  }
}

const outRoot = path.join(repoRoot, 'dist', 'npm');
fs.rmSync(outRoot, { recursive: true, force: true });
fs.mkdirSync(outRoot, { recursive: true });

function writeJson(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2) + '\n');
}

// --- Platform packages ---
for (const [key, binPath] of Object.entries(binaries)) {
  const meta = PLATFORMS[key];
  const pkgDir = path.join(outRoot, `netget-${key}`);
  const binDir = path.join(pkgDir, 'bin');
  fs.mkdirSync(binDir, { recursive: true });

  const binName = key.startsWith('win32') ? 'netget.exe' : 'netget';
  fs.copyFileSync(binPath, path.join(binDir, binName));
  if (!key.startsWith('win32')) {
    fs.chmodSync(path.join(binDir, binName), 0o755);
  }

  const pkgJson = {
    name: `@smotana/netget-${key}`,
    version,
    description: `netget prebuilt binary for ${key}`,
    license: 'AGPL-3.0-or-later',
    repository: {
      type: 'git',
      url: 'git+https://github.com/netget-net/netget.git',
    },
    os: [meta.os],
    cpu: [meta.cpu],
    ...(meta.libc ? { libc: meta.libc } : {}),
    files: [`bin/${binName}`],
  };
  writeJson(path.join(pkgDir, 'package.json'), pkgJson);
  fs.writeFileSync(
    path.join(pkgDir, 'README.md'),
    `# @smotana/netget-${key}\n\nPrebuilt \`netget\` binary for ${key}. ` +
      `Install [@smotana/netget](https://www.npmjs.com/package/@smotana/netget) instead of this package directly.\n`
  );
  console.log(`generated netget-${key}`);
}

// --- Main package ---
const mainSrc = path.join(repoRoot, 'npm', 'netget');
const mainDir = path.join(outRoot, 'netget');
fs.mkdirSync(path.join(mainDir, 'bin'), { recursive: true });
fs.copyFileSync(
  path.join(mainSrc, 'bin', 'netget.js'),
  path.join(mainDir, 'bin', 'netget.js')
);
fs.copyFileSync(path.join(mainSrc, 'README.md'), path.join(mainDir, 'README.md'));

const mainPkg = JSON.parse(
  fs.readFileSync(path.join(mainSrc, 'package.json'), 'utf8')
);
mainPkg.version = version;
mainPkg.optionalDependencies = Object.fromEntries(
  Object.keys(binaries).map((key) => [`@smotana/netget-${key}`, version])
);
writeJson(path.join(mainDir, 'package.json'), mainPkg);
console.log(
  `generated netget (main) with ${Object.keys(binaries).length} platform dep(s)`
);
