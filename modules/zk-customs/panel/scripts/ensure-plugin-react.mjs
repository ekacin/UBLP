// Self-healing workaround for a reproducible npm installer bug (confirmed across npm 12.0.2
// locally and the npm bundled with Node 22 in CI, both with cache cleared and node_modules
// fully removed before a fresh install): @vitejs/plugin-react's package-lock.json entry is
// always well-formed and its tarball is always fetchable directly (`npm pack` succeeds every
// time), but npm's own installer silently never extracts it into node_modules — verbose output
// shows npm's internal "actual tree" shrinkwrap disagreeing with disk state for exactly this
// one nested package, and every remedy that should force a real reinstall (npm ci from a fully
// clean tree, --force, cache clean --force, pinning to an older pre-beta-dependency version)
// reproduced the same silent skip. This runs as this workspace's own `postinstall` (which both
// `npm install` and `npm ci` execute) and fetches+extracts the exact pinned tarball directly
// if npm's own installer didn't. No-ops instantly once npm actually installs it correctly on
// its own — safe to leave in place even if this turns out to be fixed by a future npm release.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const panelRoot = path.join(__dirname, '..');
const targetDir = path.join(panelRoot, 'node_modules', '@vitejs', 'plugin-react');

if (existsSync(path.join(targetDir, 'package.json'))) {
  process.exit(0); // npm already installed it correctly — nothing to do
}

const pkg = JSON.parse(readFileSync(path.join(panelRoot, 'package.json'), 'utf8'));
const version = pkg.devDependencies['@vitejs/plugin-react'];
console.log(`[ensure-plugin-react] npm's installer didn't place @vitejs/plugin-react@${version} — fetching it directly.`);

const tmp = mkdtempSync(path.join(tmpdir(), 'ensure-plugin-react-'));
try {
  const packOutput = execFileSync('npm', ['pack', `@vitejs/plugin-react@${version}`, '--silent'], {
    cwd: tmp,
    encoding: 'utf8',
  }).trim();
  const tarballName = packOutput.split('\n').pop();
  mkdirSync(targetDir, { recursive: true });
  // Shell out to the system `tar` (present on every GitHub Actions runner and any normal dev
  // machine) rather than an npm package — this script's whole job is working around npm's own
  // installer misbehaving, so it must not itself depend on npm correctly installing something.
  execFileSync('tar', ['-xzf', path.join(tmp, tarballName), '-C', targetDir, '--strip-components=1']);
  console.log('[ensure-plugin-react] done.');
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
