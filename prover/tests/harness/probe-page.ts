// The wallet-origin test page of the wasm probe: it loads the REAL cmsg wasm (built with the
// `browser-prover-probe` feature) and drives the same Rust prover path the wallet frame lends:
// deployed material fetched and checked against pinned digests, public inputs derived by the
// engine, the Web Worker, and the engine's check of the reply. It knows no key and no vault.
// The two aliases are filled in by build-probe.mjs: the generated glue and its copy of the
// frame-host glue (the snippet the Rust side imports, so the page shares its state: the running
// worker and the member's one-shot permission).
import init, { probe_prove, probe_calibrate, probe_setup } from 'cmsg-glue';
import { ALLOW_SLOW_EVENT, PROGRESS_EVENT, cancelProof, storeMillis, storedMillis } from 'cmsg-prover-snippet';

const events: unknown[] = [];
addEventListener(PROGRESS_EVENT, (event) => events.push((event as CustomEvent).detail));

const outcome = async <T>(run: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false; error: string }> => {
  try {
    return { ok: true, value: await run() };
  } catch (error) {
    return { ok: false, error: String(error) };
  }
};

await init({ module_or_path: new URL('./cmsg_bg.wasm', import.meta.url) });
Object.assign(window, {
  probe: {
    events,
    isolated: self.crossOriginIsolated,
    cancel: cancelProof,
    setup: (deployment: string) => outcome(() => probe_setup(deployment)),
    prove: (deployment: string, publicJson: string, input: string) => outcome(() => probe_prove(deployment, publicJson, input)),
    calibrate: (deployment: string) => outcome(() => probe_calibrate(deployment)),
    stored: storedMillis,
    store: storeMillis,
    /** What the wallet frame's own "Try anyway" button does. */
    allowSlow: () => dispatchEvent(new CustomEvent(ALLOW_SLOW_EVENT)),
  },
});
