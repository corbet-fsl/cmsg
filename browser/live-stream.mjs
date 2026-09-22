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
  #stream; #inbox; #key; #context; #persist; #schedule; #nonce; #session;
  #closed = false; #closing;
  constructor(stream, inbox, { key, context, persist, schedule }) {
    if (!(key instanceof Uint8Array) || key.length !== 32 || !(context instanceof Uint8Array) || typeof persist !== 'function') throw failure();
    if (schedule !== undefined && typeof schedule !== 'function') throw failure();
    this.#stream = stream; this.#inbox = inbox; this.#key = key.slice(); this.#context = context.slice(); this.#persist = persist;
    this.#schedule = schedule;
  }
  #run(category, operation) {
    const queued = () => mutate(this.#inbox, operation);
    try { return Promise.resolve(this.#schedule ? this.#schedule(category, queued) : queued()); }
    catch (error) { return Promise.reject(error); }
  }
  static async open(stream, inbox, { peerDevice, until, ...storage }) {
    if (!(peerDevice instanceof Uint8Array) || peerDevice.length !== 32) throw failure();
    peerDevice = peerDevice.slice();
    const live = new LiveInboxStream(stream, inbox, storage);
    try {
      await live.#run('control', async () => {
        const wire = await inbox.beginLiveSession(peerDevice, until, live.#key, live.#context, live.#persist);
        live.#nonce = inbox.liveOpeningNonce(peerDevice);
        await stream.send(wire);
      });
      while (!live.#session) {
        const wire = await stream.receive();
        live.#session = await live.#run('receive', async () => {
          const received = await inbox.receive(wire, live.#key, live.#context, live.#persist);
          try {
            if (received.kind !== 'liveControl') throw failure();
            await live.#flushControls();
            return inbox.liveSessionForOpening(live.#nonce);
          } finally { received.free(); }
        });
      }
      return live;
    } catch { await live.close(); throw failure(); }
  }
  get closed() { return this.#closed; }
  // Called only from #run's cmsg queue. The embedding scheduler therefore
  // covers both these synchronous getters and the mutation that produced the
  // control wires, without holding its queue during a peer read.
  async #flushControls() {
    for (const wire of this.#inbox.pendingLiveControlsFor(this.#nonce)) {
      if (this.#closed) throw failure();
      await this.#stream.send(wire);
    }
    await this.#inbox.clearLiveControlsFor(this.#nonce, this.#key, this.#context, this.#persist);
  }
  async send(bytes) {
    if (this.#closed) throw failure();
    if (!(bytes instanceof Uint8Array)) throw failure();
    const payload = bytes.slice();
    let wire;
    try {
      wire = await this.#run('send', async () => {
        let produced;
        try {
          produced = await this.#inbox.sendLiveBytes(this.#session, payload, this.#key, this.#context, this.#persist);
          if (this.#closed || !this.#inbox.canTransmitLiveWire(produced)) throw failure();
          await this.#stream.send(produced);
          if (this.#closed) throw failure();
          return produced;
        } catch (error) {
          produced?.fill(0);
          throw error;
        }
      });
      // Acceptance is observed through the Inbox delivery journal, not here.
    } catch { await this.close(); throw failure(); }
    finally { wire?.fill(0); payload.fill(0); }
  }
  async receive() {
    if (this.#closed) throw failure();
    try {
      for (;;) {
        const wire = await this.#stream.receive();
        const result = await this.#run('receive', async () => {
          const received = await this.#inbox.receive(wire, this.#key, this.#context, this.#persist);
          let returned = false;
          try {
            if (this.#closed) throw failure();
            await this.#flushControls();
            if (received.kind === 'liveControl') return null;
            returned = true;
            return received;
          } finally { if (!returned) received.free(); }
        });
        if (result) return result;
      }
    } catch { await this.close(); throw failure(); }
  }
  close() {
    if (this.#closing) return this.#closing;
    this.#closed = true;
    try { this.#stream.close(); } catch { /* fixed error boundary */ }
    this.#closing = this.#run('control', async () => {
      if (this.#nonce) await this.#inbox.cancelLiveOpening(this.#nonce, this.#key, this.#context, this.#persist);
      else if (this.#session) await this.#inbox.loseLiveSession(this.#session, this.#key, this.#context, this.#persist);
    }).finally(() => { this.#key.fill(0); this.#context.fill(0); });
    return this.#closing;
  }
}
