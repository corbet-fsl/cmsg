// The wallet-origin double: one static origin that serves the page, the worker bundle and the
// pinned setup prefix, each with the policy the deployed wallet origin sends. It counts requests
// per path and can serve a tampered setup. `ISOLATED=1` adds COOP/COEP (test of the thread
// branch only; the deployment adds no such headers).
import { createServer, type Server } from 'node:http';
import { readFileSync, existsSync, statSync, openSync, readSync, closeSync } from 'node:fs';
import { extname, join } from 'node:path';

// The wallet frame's page policy (cmeet build/vault-policy.ts, without the Tor additions) and the
// policy the worker scripts are served with. A dedicated worker takes its policy from the
// response of its own script, so the deployment must send this header on every worker file.
export const PAGE_POLICY =
  "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; " +
  "script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; worker-src 'self'";
export const WORKER_POLICY =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; worker-src 'self'";

const TYPES: Record<string, string> = { '.js': 'text/javascript', '.wasm': 'application/wasm', '.html': 'text/html', '.json': 'application/json' };

export interface Harness {
  origin: string;
  hits: Map<string, number>;
  control: { tamperG1: boolean; tamperG2: boolean };
  close(): Promise<void>;
}

function readRange(path: string, length: number): Buffer {
  const out = Buffer.alloc(length);
  const fd = openSync(path, 'r');
  try {
    readSync(fd, out, 0, length, 0);
  } finally {
    closeSync(fd);
  }
  return out;
}

export async function startHarness(options: { dist: string; setupDir: string; port?: number; isolated?: boolean }): Promise<Harness> {
  const hits = new Map<string, number>();
  const control = { tamperG1: false, tamperG2: false };
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>wallet</title></head><body><script type="module" src="/page.js"></script></body></html>`;
  const server: Server = createServer((req, res) => {
    const path = new URL(req.url ?? '/', 'http://x').pathname;
    hits.set(path, (hits.get(path) ?? 0) + 1);
    const common: Record<string, string> = { 'cache-control': 'no-store' };
    if (options.isolated) {
      common['cross-origin-opener-policy'] = 'same-origin';
      common['cross-origin-embedder-policy'] = 'require-corp';
      common['cross-origin-resource-policy'] = 'same-origin';
    }
    const send = (status: number, type: string, body: Buffer | string, extra: Record<string, string> = {}) => {
      res.writeHead(status, { 'content-type': type, 'content-length': Buffer.byteLength(body), ...common, ...extra });
      res.end(body);
    };
    if (path === '/favicon.ico') return send(204, 'image/x-icon', '');
    if (path === '/') return send(200, 'text/html', html, { 'content-security-policy': PAGE_POLICY });
    const srs = /^\/prover\/srs\/g1-(\d+)\.dat$/.exec(path);
    if (srs) {
      const bytes = readRange(join(options.setupDir, 'g1.dat'), Number(srs[1]) * 32);
      if (control.tamperG1) bytes[bytes.length >> 1] ^= 1;
      return send(200, 'application/octet-stream', bytes);
    }
    if (path === '/prover/srs/g2.dat') {
      const bytes = readRange(join(options.setupDir, 'g2.dat'), 128);
      if (control.tamperG2) bytes[7] ^= 1;
      return send(200, 'application/octet-stream', bytes);
    }
    if (path === '/probe.worker.js') {
      // A worker script served like the prover's: the test asks it to reach another origin.
      const probe = `const other = new URL(location.href).searchParams.get('other');
        const out = {};
        for (const kind of ['fetch', 'import', 'socket']) {
          try {
            if (kind === 'fetch') await fetch(other + '/leak-fetch', { mode: 'no-cors' });
            else if (kind === 'import') await import(other + '/leak-import.js');
            else await new Promise((ok, no) => { const w = new WebSocket(other.replace('http', 'ws') + '/leak-socket'); w.onopen = ok; w.onerror = () => no(new Error('blocked')); });
            out[kind] = 'reached';
          } catch (e) { out[kind] = 'blocked'; }
        }
        postMessage(out);`;
      return send(200, 'text/javascript', probe, { 'content-security-policy': WORKER_POLICY });
    }
    const file = join(options.dist, path.slice(1));
    if (!path.includes('..') && existsSync(file) && statSync(file).isFile()) {
      // Every script of the worker bundle carries the worker policy; the page script is the page's.
      const worker = /\.worker\.js$|^\/(barretenberg|chunk)-/.test(path);
      return send(200, TYPES[extname(file)] ?? 'application/octet-stream', readFileSync(file), worker ? { 'content-security-policy': WORKER_POLICY } : {});
    }
    send(404, 'text/plain', 'not found');
  });
  await new Promise<void>((resolve) => server.listen(options.port ?? 0, '127.0.0.1', resolve));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return {
    origin: `http://127.0.0.1:${port}`,
    hits,
    control,
    close: () => new Promise((resolve) => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}
