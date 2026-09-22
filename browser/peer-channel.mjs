const rejected = () => new Error('cmsg:Transport');
const lanes = Object.freeze({ invitation: 1, mls: 2, accounting: 3 });

/** Bounded routing over one already selected onion stream. Lane bytes carry
 * no identity or authorization: consumers still authenticate their MLS frames
 * and cryptographic proofs. Keepalives do not renew a signed live session. */
export function createPeerChannel(stream, { maxFrameBytes, maxQueuedFrames, keepaliveMs, receiveDeadlineMs }) {
  for (const [value, maximum] of [[maxFrameBytes, 1_048_575], [maxQueuedFrames, 32],
    [keepaliveMs, 30_000], [receiveDeadlineMs, 3_600_000]]) {
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw rejected();
  }
  if (!stream || !['send', 'receive', 'close'].every(key => typeof stream[key] === 'function')) throw rejected();
  let closed = false, writing = Promise.resolve(), queuedWrites = 0, timer;
  const queues = new Map(Object.values(lanes).map(id => [id, []]));
  const readers = new Map();
  function scheduleKeepalive() {
    clearTimeout(timer);
    if (!closed) timer = setTimeout(keepalive, keepaliveMs);
  }
  function close() {
    if (closed) return;
    closed = true; clearTimeout(timer);
    for (const reader of readers.values()) { clearTimeout(reader.timer); reader.reject(rejected()); }
    readers.clear();
    for (const queue of queues.values()) { for (const bytes of queue) bytes.fill(0); queue.length = 0; }
    try { stream.close(); } catch {}
  }
  function send(tag, bytes) {
    const emptyAllowed = tag === 0;
    if (closed || !(bytes instanceof Uint8Array) || (!emptyAllowed && bytes.length === 0) ||
      (emptyAllowed && bytes.length !== 0) || bytes.length > maxFrameBytes || queuedWrites >= maxQueuedFrames) {
      return Promise.reject(rejected());
    }
    const frame = new Uint8Array(bytes.length + 1); frame[0] = tag; frame.set(bytes, 1);
    queuedWrites++;
    const next = writing.then(async () => {
      if (closed) throw rejected();
      await stream.send(frame);
      scheduleKeepalive();
    });
    writing = next.catch(() => close());
    return next.catch(() => { close(); throw rejected(); }).finally(() => { queuedWrites--; frame.fill(0); });
  }
  async function pump() {
    try {
      while (!closed) {
        const frame = await stream.receive();
        if (!(frame instanceof Uint8Array) || frame.length < 1 || frame.length > maxFrameBytes + 1) throw rejected();
        const tag = frame[0];
        if (tag === 0) { if (frame.length !== 1) throw rejected(); continue; }
        const queue = queues.get(tag);
        if (!queue || frame.length === 1) throw rejected();
        const bytes = frame.slice(1), reader = readers.get(tag);
        if (reader) { readers.delete(tag); clearTimeout(reader.timer); reader.resolve(bytes); }
        else { if (queue.length >= maxQueuedFrames) throw rejected(); queue.push(bytes); }
      }
    } catch { close(); }
  }
  async function keepalive() {
    timer = undefined;
    if (closed) return;
    if (queuedWrites) { scheduleKeepalive(); return; }
    try { await send(0, new Uint8Array()); }
    catch { if (!closed) close(); return; }
  }
  void pump();
  scheduleKeepalive();
  return Object.freeze({
    get closed() { return closed; },
    lane(name) {
      if (!Object.hasOwn(lanes, name)) throw rejected();
      const tag = lanes[name];
      return Object.freeze({
        get closed() { return closed; },
        send: bytes => send(tag, bytes),
        receive() {
          if (closed || readers.has(tag)) return Promise.reject(rejected());
          const queue = queues.get(tag);
          if (queue.length) return Promise.resolve(queue.shift());
          return new Promise((resolve, reject) => {
            readers.set(tag, { resolve, reject, timer: setTimeout(close, receiveDeadlineMs) });
          });
        },
        close,
      });
    },
    close,
  });
}
