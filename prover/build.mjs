// Build the proving Web Worker bundle: dist/prover.worker.js plus the two inner workers bb.js starts
// (dist/main.worker.js, dist/thread.worker.js), shared chunks and the two noir wasm files. Copy dist/
// next to the cmsg package's bundle (the host glue starts ./prover.worker.js relative to it).
// `node build.mjs --page` also bundles the test page (host glue included) for the browser tests.
import { build } from 'esbuild';
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('./', import.meta.url));
const bbBrowser = `${root}node_modules/@aztec/bb.js/dest/browser/barretenberg_wasm`;
const out = `${root}dist`;
rmSync(out, { recursive: true, force: true }); // the one build output directory of this package
mkdirSync(out, { recursive: true });
// bb.js ships its wasm as a base64 data URL inside a JS module and fetches that URL. A data: URL would
// need `data:` in connect-src, so the build writes the same gzip bytes as plain files next to the worker
// (bb.js reads them through `wasmPath`) and replaces the two data-URL modules with an empty stub.
const fetchCode = `${bbBrowser}/fetch_code/browser`;
for (const [name, file] of [['barretenberg.wasm.gz', 'barretenberg.js'], ['barretenberg-threads.wasm.gz', 'barretenberg-threads.js']]) {
  const text = readFileSync(`${fetchCode}/${file}`, 'utf8');
  const match = /"data:application\/gzip;base64,([A-Za-z0-9+/=]+)"/.exec(text);
  if (!match) throw new Error(`${file}: the bb.js wasm data URL is not where the build expects it`);
  writeFileSync(`${out}/${name}`, Buffer.from(match[1], 'base64'));
}
const withoutDataUrls = {
  name: 'bb-wasm-as-files',
  setup(b) {
    b.onResolve({ filter: /^\.\/barretenberg(-threads)?\.js$/ }, (args) =>
      args.importer.includes('fetch_code') ? { path: args.path, namespace: 'stub' } : undefined);
    b.onLoad({ filter: /.*/, namespace: 'stub' }, () => ({ contents: 'export default ""', loader: 'js' }));
  },
};
const entryPoints = {
  'prover.worker': `${root}src/worker.ts`,
  // bb.js starts these two with new Worker(new URL('./x.worker.js', import.meta.url)): they sit next to the chunks.
  'main.worker': `${bbBrowser}/barretenberg_wasm_main/factory/browser/main.worker.js`,
  'thread.worker': `${bbBrowser}/barretenberg_wasm_thread/factory/browser/thread.worker.js`,
};
if (process.argv.includes('--page')) entryPoints.page = `${root}tests/harness/page.ts`;
await build({
  entryPoints,
  outdir: out,
  bundle: true,
  plugins: [withoutDataUrls],
  splitting: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  minify: true,
  sourcemap: false,
  define: { __PROVER_DEBUG__: String(process.argv.includes('--page')) },
  logLevel: 'warning',
});
for (const [from, to] of [
  ['@noir-lang/acvm_js/web/acvm_js_bg.wasm', 'acvm_js_bg.wasm'],
  ['@noir-lang/noirc_abi/web/noirc_abi_wasm_bg.wasm', 'noirc_abi_wasm_bg.wasm'],
]) copyFileSync(`${root}node_modules/${from}`, `${out}/${to}`);
console.log(`built ${out}`);
