import { BrowserFrameCodec } from '../pkg/cmsg.js';

const MAX_WIRE_BYTES = 1024 * 1024;
const failed = () => new Error('cmsg:Transport');

// Only production factory-created TorJS streams enter this class. Tests may
// script the byte boundary; that is not evidence of Tor network operation.
export class OnionFramedStream {
  #stream;
  #codec = new BrowserFrameCodec(MAX_WIRE_BYTES);
  #deadline;
  #frames = [];
  #closed = false;
  #reading = false;
  #writing = false;

  constructor(stream, deadlineMs) {
    if (!Number.isInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > 60_000) throw failed();
    this.#stream = stream;
    this.#deadline = deadlineMs;
  }

  get closed() { return this.#closed; }

  async send(wire) {
    if (this.#closed || this.#writing) throw failed();
    if (!(wire instanceof Uint8Array) || wire.length === 0 || wire.length > MAX_WIRE_BYTES) {
      throw new Error('cmsg:InvalidMessage');
    }
    this.#writing = true;
    let frame;
    try {
      frame = this.#codec.encode(wire);
      await this.#stream.write(frame, this.#deadline);
      if (this.#closed) throw failed();
    } catch {
      this.close();
      throw failed();
    } finally {
      frame?.fill(0);
      this.#writing = false;
    }
  }

  async receive() {
    if (this.#closed || this.#reading) throw failed();
    this.#reading = true;
    const expires = performance.now() + this.#deadline;
    try {
      while (this.#frames.length === 0) {
        const remaining = Math.ceil(expires - performance.now());
        if (remaining < 1) throw failed();
        const chunk = await this.#stream.read(65536, Math.min(remaining, 60_000));
        if (this.#closed) throw failed();
        if (!(chunk instanceof Uint8Array) || chunk.length === 0 || chunk.length > 65536) {
          throw failed();
        }
        this.#frames = this.#codec.push(chunk);
      }
      return this.#frames.shift();
    } catch {
      this.close();
      throw failed();
    } finally {
      this.#reading = false;
    }
  }

  close() {
    if (this.#closed) return;
    this.#closed = true;
    this.#frames = [];
    try { this.#stream.close(); } catch { /* preserve coarse public boundary */ }
    try { this.#stream.free(); } catch { /* upstream may already be freed */ }
    this.#codec.free();
  }
}
