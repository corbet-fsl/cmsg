// Trusted deployment imports. Resolve these to the selected CTRN source and its
// maintained TorJS build; neither import nor an engine factory is action input.
import initCtrn from 'ctrn/browser/pkg/ctrn.js';
import { createTorJsBackend, type OnionIdentity, type TorImplementation } from 'ctrn/browser/tor-streams.js';

interface FactoryOptions {
  scope: Uint8Array;
  identity: OnionIdentity;
  signal: AbortSignal;
  snowflake: boolean;
}

export function monotonicMillis() { return performance.now(); }

export function factory(bootstrapDeadlineMs: number, operationDeadlineMs: number, maximumStreams: number) {
  return async ({ scope, identity, signal, snowflake }: FactoryOptions) => {
    if (snowflake !== true || !(scope instanceof Uint8Array) || scope.length !== 32
        || typeof identity?.onionKey !== 'function' || !signal || signal.aborted) {
      throw new Error('cmsg:Unavailable');
    }
    try {
      await initCtrn();
      const implementation: TorImplementation = await import('tor-js/wasm-file');
      if (signal.aborted) throw new Error('cmsg:Unavailable');
      // Original TorJS storage, private to this one scoped runtime. This stores
      // Tor cache data; the encrypted member checkpoint belongs to CVLT/CWST.
      const storage = new implementation.storage.MemoryStorage();
      return await createTorJsBackend({
        scope, identity, signal, snowflake: true, storage,
        bootstrapDeadlineMs, operationDeadlineMs, maximumStreams,
        load: async () => implementation,
      });
    } catch {
      throw new Error('cmsg:Unavailable');
    }
  };
}
