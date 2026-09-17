import { BrowserOnionEndpoint } from './pkg/cmsg.js';
import { OnionFramedStream } from './internal/streams.mjs';

const failed = () => new Error('cmsg:Transport');
const bounded = (value, maximum) => Number.isInteger(value) && value >= 1 && value <= maximum;

function dispose(value) {
  try { value.close(); } catch { /* disposal must not expose upstream context */ }
  try { value.free(); } catch { /* freeing is still attempted after close fails */ }
}

async function beforeDeadline(operation, deadlineMs, close, discard) {
  let timer;
  let active = true;
  const expires = performance.now() + deadlineMs;
  try {
    return await Promise.race([
      Promise.resolve().then(operation).then(value => {
        if (!active || performance.now() >= expires) {
          discard?.(value);
          throw failed();
        }
        return value;
      }),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(failed()), deadlineMs);
      }),
    ]);
  } catch {
    try { close(); } catch { /* coarse errors only */ }
    throw failed();
  } finally { active = false; clearTimeout(timer); }
}

/** Owns actual browser Arti circuits and a fresh, optional onion service.
 * Requires the separately built and tested pinned upstream service stage.
 * No gateway is selected. The stock npm artifact fails before bootstrap.
 */
export async function createTorJsOnionNode({ gateway, storage, bootstrapDeadlineMs, operationDeadlineMs } = {}) {
  const gateways = typeof gateway === 'string' ? [gateway] : gateway;
  if (!Array.isArray(gateways) || gateways.length === 0
      || [...gateways].some((address) => typeof address !== 'string' || address.length === 0)
      || !bounded(bootstrapDeadlineMs, 300_000) || !bounded(operationDeadlineMs, 60_000)) {
    throw new Error('cmsg:InvalidState');
  }
  const entryGateways = [...gateways];
  const bootstrapEnd = performance.now() + bootstrapDeadlineMs;
  const implementation = await beforeDeadline(async () => {
    const implementation = await import('tor-js/wasm-file');
    const { TorClient } = implementation;
    if (typeof TorClient?.onionClientSupported !== 'function'
        || typeof TorClient.onionStreamSupported !== 'function'
        || typeof TorClient.onionServiceSupported !== 'function'
        || await TorClient.onionClientSupported() !== true
        || await TorClient.onionStreamSupported() !== true
        || await TorClient.onionServiceSupported() !== true) return null;
    return implementation;
  }, bootstrapDeadlineMs, () => {});
  if (!implementation) throw new Error('cmsg:TorOnionSupportRequired');
  const { TorClient, Log } = implementation;
  if (performance.now() >= bootstrapEnd) throw failed();
  let client;
  try {
    client = new TorClient({ gateway: entryGateways, storage,
      log: new Log({ rawLog: () => {} }), logLevel: 'error' });
  } catch { throw failed(); }
  let closed = false;
  let listener;
  const streams = new Set();
  const close = () => {
    if (closed) return;
    closed = true;
    listener?.close();
    for (const stream of streams) stream.close();
    streams.clear();
    try { client.close(); } catch { /* never disclose upstream context */ }
  };
  const own = (raw) => {
    if (closed) {
      dispose(raw);
      throw failed();
    }
    for (const stream of streams) if (stream.closed) streams.delete(stream);
    if (streams.size >= 64) {
      dispose(raw);
      throw failed();
    }
    const stream = new OnionFramedStream(raw, operationDeadlineMs);
    streams.add(stream);
    return stream;
  };
  const remainingBootstrap = bootstrapEnd - performance.now();
  if (remainingBootstrap <= 0) { close(); throw failed(); }
  await beforeDeadline(() => client.ready(), remainingBootstrap, close);
  if (closed) throw failed();
  return {
    async connect(host, port) {
      if (closed) throw failed();
      const endpoint = new BrowserOnionEndpoint(host, port);
      const validatedHost = endpoint.host;
      const validatedPort = endpoint.port;
      endpoint.free();
      const raw = await beforeDeadline(() => client.connectOnion(validatedHost, validatedPort, operationDeadlineMs), operationDeadlineMs, close, dispose);
      return own(raw);
    },
    async listen({ port, maximumStreams, deadlineMs } = {}) {
      if (closed || listener || !bounded(port, 65535) || !bounded(maximumStreams, 32)
          || !bounded(deadlineMs, 600_000)) throw new Error('cmsg:InvalidState');
      // Reserve the single launch before awaiting to prevent concurrent launch.
      listener = { close: () => {} };
      const service = await beforeDeadline(() => client.hostOnion(port, maximumStreams, deadlineMs), deadlineMs, close, dispose);
      if (closed) { dispose(service); throw failed(); }
      let endpoint;
      let readiness;
      try {
        readiness = service.readiness;
        if (readiness !== 'running' && readiness !== 'degraded-reachable') throw failed();
        endpoint = new BrowserOnionEndpoint(service.host, service.port);
      }
      catch { dispose(service); close(); throw failed(); }
      const host = endpoint.host;
      const actualPort = endpoint.port;
      endpoint.free();
      if (actualPort !== port) { dispose(service); close(); throw failed(); }
      let listening = true;
      listener = {
        host, port: actualPort,
        get readiness() { return readiness; },
        async accept() {
          if (closed || !listening) throw failed();
          try {
            const raw = await beforeDeadline(() => service.accept(operationDeadlineMs), operationDeadlineMs, close, dispose);
            if (!listening) { dispose(raw); throw failed(); }
            return own(raw);
          } catch { throw failed(); }
        },
        close() {
          if (!listening) return;
          listening = false;
          dispose(service);
        },
      };
      return listener;
    },
    close,
  };
}
