// Pair a real framed stream with the live Inbox gate. Each stream has a fresh
// signed challenge; transport writes are never reported as delivered messages.
const failure = () => new Error('cmsg:Transport');
const queues = new WeakMap();
function mutate(inbox, operation) {
  const previous = queues.get(inbox) ?? Promise.resolve();
  const next = previous.catch(() => {}).then(operation);
  queues.set(inbox, next.catch(() => {}));
  return next;
}

export class LiveInboxStream {
  #stream; #inbox; #key; #context; #persist; #nonce; #session;
  #closed = false; #closing;
  constructor(stream, inbox, { key, context, persist }) {
    if (!(key instanceof Uint8Array) || key.length !== 32 || !(context instanceof Uint8Array) || typeof persist !== 'function') throw failure();
    this.#stream = stream; this.#inbox = inbox; this.#key = key.slice(); this.#context = context.slice(); this.#persist = persist;
  }
  static async open(stream, inbox, { peerDevice, until, ...storage }) {
    const live = new LiveInboxStream(stream, inbox, storage);
    try {
      const hello = await mutate(inbox, async () => {
        const wire = await inbox.beginLiveSession(peerDevice, until, live.#key, live.#context, live.#persist);
        live.#nonce = inbox.liveOpeningNonce(peerDevice);
        return wire;
      });
      await stream.send(hello);
      while (!live.#session) {
        const wire = await stream.receive();
        const received = await mutate(inbox, () => inbox.receive(wire, live.#key, live.#context, live.#persist));
        const kind = received.kind; received.free();
        if (kind !== 'liveControl') throw failure();
        await live.#flushControls();
        live.#session = inbox.liveSessionForOpening(live.#nonce);
      }
      return live;
    } catch { await live.close(); throw failure(); }
  }
  get closed() { return this.#closed; }
  async #flushControls() {
    await mutate(this.#inbox, async () => {
      for (const wire of this.#inbox.pendingLiveControlsFor(this.#nonce)) {
        if (this.#closed) throw failure();
        await this.#stream.send(wire);
      }
      await this.#inbox.clearLiveControlsFor(this.#nonce, this.#key, this.#context, this.#persist);
    });
  }
  async send(bytes) {
    if (this.#closed) throw failure();
    let wire;
    try {
      wire = await mutate(this.#inbox, () => this.#inbox.sendLiveBytes(this.#session, bytes, this.#key, this.#context, this.#persist));
      if (this.#closed || !this.#inbox.canTransmitLiveWire(wire)) throw failure();
      await this.#stream.send(wire);
      if (this.#closed) throw failure();
      // Acceptance is observed through the Inbox delivery journal, not here.
    } catch { await this.close(); throw failure(); }
    finally { wire?.fill(0); }
  }
  async receive() {
    if (this.#closed) throw failure();
    try {
      for (;;) {
        const wire = await this.#stream.receive();
        const result = await mutate(this.#inbox, () => this.#inbox.receive(wire, this.#key, this.#context, this.#persist));
        let returned = false;
        try {
          if (this.#closed) throw failure();
          await this.#flushControls();
          if (result.kind === 'liveControl') continue;
          returned = true;
          return result;
        } finally {
          if (!returned) result.free();
        }
      }
    } catch { await this.close(); throw failure(); }
  }
  close() {
    if (this.#closing) return this.#closing;
    this.#closed = true;
    try { this.#stream.close(); } catch { /* fixed error boundary */ }
    this.#closing = mutate(this.#inbox, async () => {
      if (this.#nonce) await this.#inbox.cancelLiveOpening(this.#nonce, this.#key, this.#context, this.#persist);
      else if (this.#session) await this.#inbox.loseLiveSession(this.#session, this.#key, this.#context, this.#persist);
    }).finally(() => { this.#key.fill(0); this.#context.fill(0); });
    return this.#closing;
  }
}
