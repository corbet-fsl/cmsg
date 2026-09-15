import { BrowserFrameCodec, BrowserOnionEndpoint } from '../pkg/cmsg.js';

const MAX_WIRE_BYTES = 1024 * 1024;
const CONTENT_TYPE = 'application/vnd.cmsg.frame';
const PATH = '/cmsg/v1/exchange';

const failure = (code) => new Error(`cmsg:${code}`);

// A single trusted TorJS client belongs to this adapter. The constructor is
// internal: public consumers use createTorJsOnionTransport, which loads the
// pinned TorJS implementation. Boundary tests inject a scripted client here;
// those tests are not Tor connectivity evidence.
export class OnionHttpTransport {
  #client;
  #deadline;
  #active = null;
  #closed = false;

  constructor(client, deadlineMs) {
    if (!Number.isInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 60_000) {
      throw failure('InvalidState');
    }
    this.#client = client;
    this.#deadline = deadlineMs;
  }

  async exchange(host, port, wire) {
    if (this.#closed) throw failure('Transport');
    if (this.#active) throw failure('InvalidState');
    if (!(wire instanceof Uint8Array) || wire.byteLength === 0 || wire.byteLength > MAX_WIRE_BYTES) {
      throw failure('InvalidMessage');
    }
    // Revalidate before any transport call. This cannot represent a clearnet
    // destination, userinfo, a path/query override or a redirect destination.
    const endpoint = new BrowserOnionEndpoint(host, port);
    const url = `http://${endpoint.host}:${endpoint.port}${PATH}`;
    endpoint.free();
    const codec = new BrowserFrameCodec(MAX_WIRE_BYTES);
    const body = codec.encode(wire);
    const abort = new AbortController();
    let timer;
    let rejectCancelled;
    const cancelled = new Promise((_, reject) => { rejectCancelled = reject; });
    this.#active = { abort, reject: rejectCancelled };
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => {
        this.close();
        reject(failure('Transport'));
      }, this.#deadline);
    });
    let reader;
    const operation = (async () => {
      await this.#client.ready();
      if (abort.signal.aborted) throw failure('Transport');
      const response = await this.#client.fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': CONTENT_TYPE,
          Accept: CONTENT_TYPE,
          'User-Agent': 'cmsg/1',
          'Cache-Control': 'no-store',
        },
        body,
        signal: abort.signal,
      });
      // TorJS 0.4.1 returns redirects without following them. Pin that version;
      // browser fetch is not a compatible substitute for this Tor-only call.
      if (abort.signal.aborted || response.status !== 200 || response.redirected) {
        response.body?.cancel().catch(() => {});
        throw failure('Transport');
      }
      const rawLength = response.headers.get('content-length');
      if (response.headers.get('content-type') !== CONTENT_TYPE
          || response.headers.has('transfer-encoding')
          || response.headers.has('content-encoding')
          || !rawLength || !/^[1-9][0-9]*$/.test(rawLength)) {
        response.body?.cancel().catch(() => {});
        throw failure('InvalidMessage');
      }
      const length = Number(rawLength);
      if (!Number.isSafeInteger(length) || length < 5 || length > MAX_WIRE_BYTES + 4 || !response.body) {
        response.body?.cancel().catch(() => {});
        throw failure('InvalidMessage');
      }
      reader = response.body.getReader();
      let total = 0;
      let result;
      while (true) {
        const { value, done } = await reader.read();
        if (abort.signal.aborted) throw failure('Transport');
        if (done) break;
        if (!(value instanceof Uint8Array) || value.byteLength === 0 || total + value.byteLength > length) {
          throw failure('InvalidMessage');
        }
        total += value.byteLength;
        for (const frame of codec.push(value)) {
          if (result) throw failure('InvalidMessage');
          result = frame;
        }
      }
      codec.finish();
      if (total !== length || !result) throw failure('InvalidMessage');
      return result;
    })();
    try {
      return await Promise.race([operation, deadline, cancelled]);
    } catch {
      this.close();
      // Never forward errors from the Tor implementation: they may embed
      // destination addresses, request headers or other identifying context.
      throw failure('Transport');
    } finally {
      clearTimeout(timer);
      this.#active = null;
      if (this.#closed) reader?.cancel().catch(() => {});
      else reader?.releaseLock();
      codec.free();
      body.fill(0);
    }
  }

  close() {
    if (this.#closed) return;
    this.#closed = true;
    this.#active?.abort.abort();
    this.#active?.reject(failure('Transport'));
    // Shutdown must never leak an upstream exception containing addresses or
    // headers, including from the timer callback and public close().
    try { this.#client.close(); } catch { /* already closed locally */ }
  }
}
