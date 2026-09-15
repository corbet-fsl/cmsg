import { OnionHttpTransport } from './internal/http.mjs';

/**
 * Create an onion-only request/reply transport using the pinned onion-enabled
 * TorJS build in upstream/. Stock TorJS 0.4.1 lacks the onion client feature.
 * The caller
 * explicitly supplies gateway KPS addresses and a 1..60000ms request deadline.
 * This adapter neither hosts an onion service nor supplies offline delivery.
 * `init()` from the main cmsg module must have completed first.
 */
export async function createTorJsOnionTransport({ gateway, deadlineMs, storage } = {}) {
  const gateways = typeof gateway === 'string' ? [gateway] : gateway;
  if (!Array.isArray(gateways) || gateways.length === 0
      || gateways.some((address) => typeof address !== 'string' || address.length === 0)
      || !Number.isInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 60_000) {
    throw new Error('cmsg:InvalidState');
  }
  // The local-file entrypoint keeps Tor's Wasm asset in the application's own
  // deployment. No Tor gateway, CDN fallback or operator address is selected.
  const { TorClient, Log } = await import('tor-js/wasm-file');
  if (typeof TorClient.onionClientSupported !== 'function'
      || !await TorClient.onionClientSupported()) {
    throw new Error('cmsg:TorOnionSupportRequired');
  }
  const client = new TorClient({
    gateway: [...gateways],
    storage,
    log: new Log({ rawLog: () => {} }),
    logLevel: 'error',
  });
  return new OnionHttpTransport(client, deadlineMs);
}
