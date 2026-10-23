// The wallet-origin test page: it drives the REAL host glue (src/door/browser/prover.ts) with a
// setup and an input the native engine produced, and reports the reply. It knows no key.
import { proveInWorker, cancelProof, PROGRESS_EVENT } from '../../../src/door/browser/prover.ts';

const events: unknown[] = [];
addEventListener(PROGRESS_EVENT, (event) => events.push((event as CustomEvent).detail));
Object.assign(window, {
  prover: {
    events,
    cancel: cancelProof,
    async prove(setup: string, input: string): Promise<{ ok: true; reply: string } | { ok: false; error: string }> {
      try {
        return { ok: true, reply: await proveInWorker(setup, new TextEncoder().encode(input)) };
      } catch (error) {
        return { ok: false, error: String((error as Error).message) };
      }
    },
    isolated: self.crossOriginIsolated,
  },
});
