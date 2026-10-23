// Build the wasm-probe test bundle into a fresh directory: the worker bundle (build.mjs), the page
// that drives the generated glue, and the wasm itself. Only writes; never deletes.
//   node build-probe.mjs --glue <wasm-bindgen --target web output dir> --out <fresh dir>
import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import { copyFileSync, readdirSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('./', import.meta.url));
const arg = (name) => {
  const at = process.argv.indexOf(name);
  if (at < 0 || !process.argv[at + 1]) throw new Error(`${name} <path> is required`);
  return resolve(process.argv[at + 1]);
};
const glue = arg('--glue');
const out = arg('--out');
execFileSync('node', [join(root, 'build.mjs'), '--out', out], { stdio: 'inherit' });
// wasm-bindgen copies the Rust side's JS module next to the glue under snippets/<crate>-<hash>/.
const snippets = readdirSync(join(glue, 'snippets')).map((name) => join(glue, 'snippets', name, 'src/door/browser/prover.ts')).filter(existsSync);
if (snippets.length !== 1) throw new Error(`expected exactly one prover.ts snippet in ${glue}/snippets, found ${snippets.length}`);
await build({
  entryPoints: { 'probe-page': join(root, 'tests/harness/probe-page.ts') },
  outdir: out,
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  alias: { 'cmsg-glue': join(glue, 'cmsg.js'), 'cmsg-prover-snippet': snippets[0] },
  logLevel: 'warning',
});
copyFileSync(join(glue, 'cmsg_bg.wasm'), join(out, 'cmsg_bg.wasm'));
console.log(`built probe bundle in ${out}`);
