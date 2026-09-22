// Pack the already-validated browser bindings. Never build/install the Tor peer.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, glob, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, posix, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

if (process.argv.length !== 3 || !/^[0-9a-f]{40}$/.test(process.env.CI_COMMIT_SHA ?? '')) {
  throw new Error('Owned artifact directory and exact CI_COMMIT_SHA required');
}
const repository = fileURLToPath(new URL('../', import.meta.url));
const source = join(repository, 'browser'), artifacts = resolve(process.argv[2]);
await mkdir(artifacts, { recursive: true });
const scratch = await mkdtemp(join(tmpdir(), 'cmsg-browser-package-'));
const evidence = { source: process.env.CI_COMMIT_SHA, runtime: process.version, ok: false,
  scope: 'Packed browser bindings and declared import closure; Tor peer remains external' };
const execute = promisify(execFile);
const sha256 = value => createHash('sha256').update(value).digest('hex');
function packagePath(path) {
  assert(typeof path === 'string' && !posix.isAbsolute(path) && posix.normalize(path) === path
    && path !== '..' && !path.startsWith('../') && !path.includes('\\'), 'Invalid package path: ' + path);
  assert(!/(^|\/)(?:\.git|\.ci|\.crow|node_modules|fixtures?|tests?|src)(\/|$)/.test(path)
    && !/(^|\/)(?:[^/]*[.-])?(?:test|tests|fixture|contract)(?:[.-]|$)/.test(path)
    && !/\.(?:py|rs|sh|toml)$/.test(path) && !path.endsWith('/private-network.md')
    && !path.endsWith('/.npmrc'), 'Test or protected source selected for package: ' + path);
}
function exportTargets(value) {
  if (typeof value === 'string') return [value];
  assert(value && typeof value === 'object', 'Explicit browser export target required');
  return Object.values(value).flatMap(exportTargets);
}
try {
  const manifestBytes = await readFile(join(source, 'package.json'));
  const manifest = JSON.parse(manifestBytes);
  assert(Array.isArray(manifest.files) && manifest.files.length, 'Explicit npm files list required');
  const sourceRoot = await realpath(source);
  const staged = new Set(['package.json', 'LICENSE.md']);
  await writeFile(join(scratch, 'package.json'), manifestBytes);
  const license = await readFile(join(repository, 'LICENSE.md'));
  await writeFile(join(scratch, 'LICENSE.md'), license);
  for await (const path of glob(manifest.files, { cwd: source })) {
    if (path === 'LICENSE.md' || path === 'package.json') continue;
    packagePath(path);
    const input = join(source, path), stat = await lstat(input);
    assert(!stat.isSymbolicLink(), 'Package input must not be a symlink: ' + path);
    if (stat.isDirectory()) continue;
    assert(stat.isFile() && (await realpath(input)).startsWith(sourceRoot + sep), 'Package source must stay in browser/: ' + path);
    const output = join(scratch, path);
    await mkdir(dirname(output), { recursive: true });
    await copyFile(input, output); staged.add(path);
  }
  // Literal entries include the generated Wasm, glue and declarations. Missing
  // generated output must fail rather than produce a smaller plausible archive.
  for (const path of manifest.files.filter(path => !['*', '?', '{', '}', '[', ']'].some(token => path.includes(token)))) {
    assert(staged.has(path), 'Declared package file is missing: ' + path);
  }
  let packed;
  try {
    const result = await execute('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', artifacts],
      { cwd: scratch, timeout: 120_000, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024,
        env: { ...process.env, npm_config_update_notifier: 'false' } });
    await writeFile(join(artifacts, 'browser-npm-pack.json'), result.stdout);
    await writeFile(join(artifacts, 'browser-npm-pack.stderr.log'), result.stderr);
    packed = JSON.parse(result.stdout);
  } catch (error) {
    await writeFile(join(artifacts, 'browser-npm-pack.stderr.log'), String(error.stderr ?? error));
    throw error;
  }
  assert.equal(packed.length, 1, 'Pack exactly one browser package');
  const pack = packed[0];
  assert.equal(pack.name, manifest.name); assert.equal(pack.version, manifest.version);
  assert.equal(pack.filename, basename(pack.filename), 'Archive must stay in the owned artifact directory');
  const files = new Set(pack.files.map(file => file.path));
  for (const path of files) { packagePath(path); assert(staged.has(path), 'Unstaged file in npm archive: ' + path); }
  for (const path of staged) assert(files.has(path), 'Declared input omitted by npm: ' + path);
  const exports = [...new Set(exportTargets(manifest.exports))];
  for (const target of exports) {
    assert(target.startsWith('./') && files.has(target.slice(2)), 'Missing browser export: ' + target);
  }
  const imports = [];
  for (const path of files) {
    if (!/\.(?:m?js|d\.ts)$/.test(path)) continue;
    const text = await readFile(join(scratch, path), 'utf8');
    const specifiers = [
      ...text.matchAll(/\b(?:import|export)\s+(?:type\s+)?(?:[^;'"`]*?\s+from\s*)?['"](\.{1,2}\/[^'"]+)['"]/g),
      ...text.matchAll(/\bimport\s*\(\s*['"](\.{1,2}\/[^'"]+)['"]/g),
      ...text.matchAll(/\bnew\s+URL\s*\(\s*['"]([^'"]+)['"]\s*,\s*import\.meta\.url\s*\)/g),
    ].map(match => match[1]);
    for (const specifier of new Set(specifiers)) {
      assert(!/^[a-z]+:/i.test(specifier) && !specifier.startsWith('/'), 'Unexpected module asset URL: ' + specifier);
      const target = posix.normalize(posix.join(posix.dirname(path), decodeURIComponent(specifier.split(/[?#]/)[0])));
      packagePath(target);
      // TypeScript substitutes a .d.ts declaration for a .js specifier in .d.ts
      // files; this does not require shipping an unused .js runtime duplicate.
      const declaration = path.endsWith('.d.ts') && target.endsWith('.js') ? target.slice(0, -3) + '.d.ts' : undefined;
      const resolved = files.has(target) ? target : declaration && files.has(declaration) ? declaration : undefined;
      assert(resolved, 'Missing relative import: ' + path + ' -> ' + specifier);
      imports.push({ source: path, specifier, target: resolved });
    }
  }
  const archivePath = join(artifacts, pack.filename), archive = await readFile(archivePath);
  const integrity = 'sha512-' + createHash('sha512').update(archive).digest('base64');
  assert.equal(integrity, pack.integrity, 'Packed archive integrity');
  assert(files.has('LICENSE.md'), 'Package must include its license');
  const packedLicense = await execute('tar', ['--extract', '--to-stdout', '--file', archivePath, 'package/LICENSE.md'],
    { encoding: 'buffer', timeout: 30_000, maxBuffer: 1024 * 1024 });
  assert(packedLicense.stdout.equals(license), 'Packed license must match the repository grant');
  evidence.package = { name: manifest.name, version: manifest.version, archive: pack.filename,
    sha256: sha256(archive), integrity, files: [...files].sort(), exports, relativeImports: imports,
    licenseSha256: sha256(license), peerDependencies: manifest.peerDependencies, peerDependenciesMeta: manifest.peerDependenciesMeta };
  evidence.ok = true;
} catch (error) { evidence.error = String(error.stack ?? error); }
finally {
  try { await rm(scratch, { recursive: true, force: true }); }
  catch (error) { evidence.ok = false; evidence.cleanupError = String(error); }
  await writeFile(join(artifacts, 'browser-package-evidence.json'), JSON.stringify(evidence, null, 2) + '\n');
}
process.stdout.write(JSON.stringify({ ok: evidence.ok, evidence: join(artifacts, 'browser-package-evidence.json'), error: evidence.error }) + '\n');
if (!evidence.ok) process.exitCode = 1;
