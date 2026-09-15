import { BrowserOnionEndpoint } from './pkg/cmsg.js';
import { OnionFramedStream } from './internal/streams.mjs';

const failed = () => new Error('cmsg:Transport');
const bounded = (value, maximum) => Number.isInteger(value) && value >= 1 && value <= maximum;

async function beforeDeadline(operation, deadlineMs, close) {
  let timer;
  try {
    return await Promise.race([
      operation,
      new Promise((_, reject) => {
        timer = setTimeout(() => { close(); reject(failed()); }, deadlineMs);
      }),
    ]);
  } catch { close(); throw failed(); }
  finally { clearTimeout(timer); }
}

/** Owns actual browser Arti circuits and a fresh, optional onion service.
 * Requires the separately built and tested pinned upstream service stage.
 * No gateway is selected. The stock npm artifact fails before bootstrap.
 */
export async function createTorJsOnionNode({ gateway, storage, bootstrapDeadlineMs, operationDeadlineMs } = {}) {
  const gateways = typeof gateway === 'string' ? [gateway] : gateway;
  if (!Array.isArray(gateways) || gateways.length === 0
      || gateways.some((address) => typeof address !== 'string' || address.length === 0)
      || !bounded(bootstrapDeadlineMs, 300_000) || !bounded(operationDeadlineMs, 60_000)) {
    throw new Error('cmsg:InvalidState');
  }
  const { TorClient, Log } = await import('tor-js/wasm-file');
  if (typeof TorClient.onionClientSupported !== 'function'
      || typeof TorClient.onionStreamSupported !== 'function'
      || typeof TorClient.onionServiceSupported !== 'function'
      || !await TorClient.onionClientSupported()
      || !await TorClient.onionStreamSupported()
      || !await TorClient.onionServiceSupported()) {
    throw new Error('cmsg:TorOnionSupportRequired');
  }
  let client;
  try {
    client = new TorClient({ gateway: [...gateways], storage,
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
      try { raw.close(); raw.free(); } catch { /* already closed */ }
      throw failed();
    }
    for (const stream of streams) if (stream.closed) streams.delete(stream);
    if (streams.size >= 64) {
      try { raw.close(); raw.free(); } catch { /* already closed */ }
      throw failed();
    }
    const stream = new OnionFramedStream(raw, operationDeadlineMs);
    streams.add(stream);
    return stream;
  };
  await beforeDeadline(client.ready(), bootstrapDeadlineMs, close);
  if (closed) throw failed();
  return {
    async connect(host, port) {
      if (closed) throw failed();
      const endpoint = new BrowserOnionEndpoint(host, port);
      const validatedHost = endpoint.host;
      const validatedPort = endpoint.port;
      endpoint.free();
      const raw = await beforeDeadline(client.connectOnion(validatedHost, validatedPort, operationDeadlineMs), operationDeadlineMs, close);
      return own(raw);
    },
    async listen({ port, maximumStreams, deadlineMs } = {}) {
      if (closed || listener || !bounded(port, 65535) || !bounded(maximumStreams, 32)
          || !bounded(deadlineMs, 60_000)) throw new Error('cmsg:InvalidState');
      // Reserve the single launch before awaiting to prevent concurrent launch.
      listener = { close: () => {} };
      const service = await beforeDeadline(client.hostOnion(port, maximumStreams, deadlineMs), deadlineMs, close);
      if (closed) { try { service.close(); service.free(); } catch {} throw failed(); }
      let endpoint;
      try { endpoint = new BrowserOnionEndpoint(service.host, service.port); }
      catch { try { service.close(); service.free(); } catch {} close(); throw failed(); }
      const host = endpoint.host;
      const actualPort = endpoint.port;
      endpoint.free();
      if (actualPort !== port) { try { service.close(); service.free(); } catch {} close(); throw failed(); }
      let listening = true;
      listener = {
        host, port: actualPort,
        async accept() {
          if (closed || !listening) throw failed();
          try {
            const raw = await service.accept(operationDeadlineMs);
            if (!listening) { raw.close(); raw.free(); throw failed(); }
            return own(raw);
          } catch { throw failed(); }
        },
        close() {
          if (!listening) return;
          listening = false;
          try { service.close(); service.free(); } catch { /* coarse public errors only */ }
        },
      };
      return listener;
    },
    close,
  };
}
