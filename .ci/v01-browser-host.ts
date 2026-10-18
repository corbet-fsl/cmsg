// CI artifact assembly only. Does not serve pages, start owners or select a Tor
// implementation. The generated API and maintained CTRN modules remain intact.
import { readFile, writeFile, cp, readdir, lstat, realpath, rename } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve, dirname, join } from 'node:path';

type Hashes = Record<string, string>;
type Port = 'cmsg' | 'ctrn' | 'cfry';
type SelectedName = Port | 'wasm-bindgen';
type Selection = Record<SelectedName, { id: string; version: string; source: string | null; root: string }>;
interface Metadata {
  resolve: { root: string; nodes: Array<{ id: string; deps: Array<{ pkg: string }> }> };
  packages: Array<{ id: string; name: string; version: string; source: string | null; manifest_path: string }>;
}
interface CargoArtifact {
  reason: string;
  package_id: string;
  target: { name: string; kind: string[] };
  filenames: string[];
}
interface PackageReceipt {
  status: string;
  source_commit: string | undefined;
  selection: Selection;
  product_acceptance: boolean;
  runtime_executed: boolean;
  missing: string[];
  files?: Hashes;
}
interface ServiceReceipt {
  ctrn_package_id: string;
  stage: string;
  upstream_inputs: Hashes;
  dist_files: Hashes;
}

if (!process.env.CI) throw new Error('CI worker required');
const [command, directory, argument] = process.argv.slice(2);
if (!directory) throw new Error('artifact directory required');
const out = resolve(directory);
const json = async <T>(path: string): Promise<T> => JSON.parse(await readFile(path, 'utf8')) as T;
const save = (path: string, value: unknown) => writeFile(path, JSON.stringify(value, null, 2) + '\n');
const require: (condition: unknown, message: string) => asserts condition = (condition, message) => { if (!condition) throw new Error(message); };
const hash = async (path: string) => createHash('sha256').update(await readFile(path)).digest('hex');
const equal = (a: object | undefined, b: object | undefined) => JSON.stringify(Object.entries(a ?? {}).sort())
  === JSON.stringify(Object.entries(b ?? {}).sort());
async function files(root: string, prefix = ''): Promise<Hashes> {
  const result: Hashes = {};
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    require(!entry.isSymbolicLink(), 'artifact symlinks are not accepted');
    if (entry.isDirectory()) Object.assign(result, await files(root, name));
    else {
      require(entry.isFile(), 'unexpected artifact file type');
      result[name] = await hash(join(root, name));
    }
  }
  return Object.fromEntries(Object.entries(result).sort(([a], [b]) => a.localeCompare(b)));
}

if (command === 'select') {
  const metadata = await json<Metadata>(join(out, 'metadata.json'));
  require(metadata.resolve?.root, 'root dependency resolution required');
  const nodes = new Map(metadata.resolve.nodes.map(node => [node.id, node]));
  const reachable = new Set<string>();
  function visit(id: string) {
    if (reachable.has(id)) return;
    reachable.add(id);
    require(nodes.has(id), 'incomplete dependency resolution');
    for (const dependency of nodes.get(id)!.deps) visit(dependency.pkg);
  }
  visit(metadata.resolve.root);
  const packages = metadata.packages.filter(pkg => reachable.has(pkg.id));
  const selected = {} as Selection;
  for (const name of ['cmsg', 'ctrn', 'cfry', 'wasm-bindgen'] as const) {
    const matches = packages.filter(pkg => pkg.name === name);
    require(matches.length === 1, `expected exactly one resolved ${name}`);
    const pkg = matches[0];
    selected[name] = { id: pkg.id, version: pkg.version, source: pkg.source,
      root: dirname(pkg.manifest_path) };
  }
  require(selected.cmsg.id === metadata.resolve.root
    && await realpath(selected.cmsg.root) === await realpath(argument!), 'wrong CMSG source root');
  // Cargo preserves source-ID spellings across process-scoped Git redirects.
  // The parent owns Forgejo routing; this package follows the root resolution.
  await save(join(out, 'selection.json'), selected);
  await save(join(out, 'upstream-inputs.json'),
    await files(join(selected.ctrn.root, 'browser/upstream')));
} else if (command === 'service-source') {
  const selected = await json<Selection>(join(out, 'selection.json'));
  const receipt = await json<PackageReceipt>(join(out, 'package-status.json'));
  require(receipt.status === 'ports-only' && receipt.source_commit === process.env.CI_COMMIT_SHA
    && equal(receipt.selection, selected), 'expected ports from this CMSG revision');
  require(equal(await json<Hashes>(join(out, 'upstream-inputs.json')),
    await files(join(selected.ctrn.root, 'browser/upstream'))), 'selected upstream inputs changed');
  console.log(selected.ctrn.root);
} else if (command === 'bindgen') {
  const selected = await json<Selection>(join(out, 'selection.json'));
  require(argument === `wasm-bindgen ${selected['wasm-bindgen'].version}`,
    'provisioned wasm-bindgen does not match the resolved crate; no download fallback');
} else if (command === 'artifact') {
  const selected = await json<Selection>(join(out, 'selection.json'));
  require(['cmsg', 'ctrn', 'cfry'].includes(argument!), 'unknown port');
  const messages = (await readFile(join(out, 'wasm-build.jsonl'), 'utf8'))
    .split('\n').filter(Boolean).map(line => JSON.parse(line) as CargoArtifact);
  const artifacts = messages.filter(message => message.reason === 'compiler-artifact'
    && message.package_id === selected[argument as Port].id && message.target.name === argument
    && message.target.kind.includes('cdylib')).flatMap(message => message.filenames)
    .filter(path => path.endsWith('.wasm'));
  require(artifacts.length === 1, `expected one compiled ${argument} Wasm artifact`);
  console.log(artifacts[0]);
} else if (command === 'package') {
  const selected = await json<Selection>(join(out, 'selection.json'));
  const target = join(out, 'public/cmsg');
  // Provisioned esbuild compiles the TS snippet pulled in by wasm-bindgen.
  // Keep bare deployment imports external and the Wasm URL beside cmsg.js.
  const wasmEntry = join(out, 'generated/wasm/cmsg.js');
  const bundledEntry = join(out, 'generated/wasm/cmsg.bundle.js');
  execFileSync('esbuild', [wasmEntry, '--bundle', '--packages=external', '--platform=browser',
    '--format=esm', '--target=es2022', `--outfile=${bundledEntry}`], { stdio: 'inherit' });
  await rename(bundledEntry, wasmEntry);
  execFileSync('esbuild', [join(selected.ctrn.root, 'browser/tor-streams.ts'),
    '--format=esm', '--target=es2022', `--outfile=${join(target, 'vendor/ctrn/browser/tor-streams.js')}`],
    { stdio: 'inherit' });
  await cp(join(out, 'generated/wasm'), join(target, 'wasm'), { recursive: true, errorOnExist: true, force: false });
  for (const name of ['registry', 'openapi', 'mcp', 'cli']) {
    await cp(join(out, `generated/${name}.json`), join(target, `${name}.json`),
      { errorOnExist: true, force: false });
  }
  for (const [name, module] of [['cfry', 'streams.mjs']] as const) {
    // Only original runtime modules; never copy source closures or fixtures.
    const browser = join(selected[name].root, 'browser');
    await cp(join(browser, module), join(target, `vendor/${name}/browser`, module),
      { errorOnExist: true, force: false });
  }
  const imports = {
    'ctrn/browser/pkg/ctrn.js': '/cmsg/vendor/ctrn/browser/pkg/ctrn.js',
    'ctrn/browser/tor-streams.js': '/cmsg/vendor/ctrn/browser/tor-streams.js',
    'tor-js/wasm-file': '/cmsg/vendor/torjs/entryPoints/wasm-file/index.js',
  };
  await save(join(target, 'importmap.json'), { imports });
  await writeFile(join(target, 'importmap.html'),
    `<script type="importmap">${JSON.stringify({ imports })}</script>\n`);
  const entries = {
    member: "export { createConfiguredVaultClient as createClient } from './browser.js';\n",
    vault: "export { startConfiguredVaultHost, prepareConfiguredWalletHost } from './browser.js';\n",
    popup: "export { preparePopupLogin } from './browser.js';\n",
  };
  for (const [name, source] of Object.entries(entries)) {
    await writeFile(join(target, `${name}.js`), source);
    await writeFile(join(target, `${name}.d.ts`), source);
  }
  await save(join(target, 'package.json'), { private: true, type: 'module', exports: {
    '.': { types: './member.d.ts', default: './member.js' },
    './vault': { types: './vault.d.ts', default: './vault.js' },
    './popup': { types: './popup.d.ts', default: './popup.js' },
    './browser': { types: './browser.d.ts', default: './browser.js' },
  } });
  const receipt: PackageReceipt = { status: 'ports-only', source_commit: process.env.CI_COMMIT_SHA,
    selection: selected, product_acceptance: false, runtime_executed: false,
    missing: ['maintained service-stage TorJS artifact and matching build receipt'] };
  receipt.files = await files(join(out, 'public'));
  await save(join(out, 'package-status.json'), receipt);
} else if (command === 'assemble') {
  const selected = await json<Selection>(join(out, 'selection.json'));
  const receipt = await json<PackageReceipt>(join(out, 'package-status.json'));
  const target = join(out, 'public/cmsg');
  require(receipt.status === 'ports-only' && receipt.source_commit === process.env.CI_COMMIT_SHA
    && equal(receipt.selection, selected), 'expected unchanged ports from this CMSG revision');
  require(equal(receipt.files, await files(join(out, 'public'))), 'ports artifact changed');
  require(process.env.CMSG_TORJS_DIST && process.env.CMSG_TORJS_RECEIPT,
    'maintained TorJS service-stage artifact/receipt missing; ports retained');
  const dist = await realpath(process.env.CMSG_TORJS_DIST);
  const supplied = await json<ServiceReceipt>(process.env.CMSG_TORJS_RECEIPT);
  require(supplied.ctrn_package_id === selected.ctrn.id && supplied.stage === 'service',
    'TorJS receipt must identify the selected CTRN and production service stage');
  const upstream = await json<Hashes>(join(out, 'upstream-inputs.json'));
  require(equal(supplied.upstream_inputs, upstream), 'TorJS upstream patch/lock inputs differ');
  require(equal(supplied.dist_files, await files(dist)), 'TorJS artifact hashes differ');
  require((await lstat(join(dist, 'entryPoints/wasm-file/index.js'))).isFile(), 'missing TorJS entry');
  await cp(dist, join(target, 'vendor/torjs'), { recursive: true, errorOnExist: true, force: false });
  require(equal(supplied.dist_files, await files(join(target, 'vendor/torjs'))), 'copied TorJS hashes differ');
  await save(join(out, 'torjs-receipt.json'), supplied);
  receipt.status = 'assembled';
  receipt.missing = [];
  receipt.files = await files(join(out, 'public'));
  await save(join(out, 'package-status.json'), receipt);
} else {
  throw new Error('expected select, service-source, bindgen, artifact, package or assemble');
}
