import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPeerChannel } from '../browser/peer-channel.mjs';

const wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

class ScriptedStream {
  constructor({ blockSends = false, failSends = false } = {}) {
    this.incoming = [];
    this.waiters = [];
    this.sent = [];
    this.closed = false;
    this.blockSends = blockSends;
    this.failSends = failSends;
    this.releaseSends = null;
  }
  async send(bytes) {
    if (this.closed || this.failSends) throw new Error('scripted send failure');
    this.sent.push(Uint8Array.from(bytes));
    if (this.blockSends) await new Promise(resolve => { this.releaseSends = resolve; });
  }
  receive() {
    if (this.incoming.length) return Promise.resolve(this.incoming.shift());
    if (this.closed) return Promise.reject(new Error('scripted stream closed'));
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }
  inject(bytes) {
    if (this.closed) return;
    const waiter = this.waiters.shift();
    if (waiter) waiter.resolve(Uint8Array.from(bytes));
    else this.incoming.push(Uint8Array.from(bytes));
  }
  close() {
    if (this.closed) return;
    this.closed = true;
    for (const waiter of this.waiters.splice(0)) waiter.reject(new Error('scripted stream closed'));
  }
}

function options(overrides = {}) {
  return { maxFrameBytes: 64, maxQueuedFrames: 2, keepaliveMs: 10, receiveDeadlineMs: 100, ...overrides };
}

async function eventually(check, timeout = 250) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    if (check()) return;
    await wait(2);
  }
  assert.fail('condition did not become true');
}

async function testRouting() {
  const stream = new ScriptedStream();
  const channel = createPeerChannel(stream, options());
  try {
    const invitation = channel.lane('invitation');
    const mls = channel.lane('mls');
    await mls.send(Uint8Array.from([4, 5]));
    assert.deepEqual([...stream.sent[0]], [2, 4, 5]);
    const received = invitation.receive();
    stream.inject([1, 8, 9]);
    assert.deepEqual([...await received], [8, 9]);
    await eventually(() => stream.sent.some(frame => frame.length === 1 && frame[0] === 0));
  } finally {
    channel.close();
  }
}

test('peer channel routes bounded tagged lanes and emits keepalive frames without auth semantics', testRouting);

test('incoming keepalives do not suppress the return traffic needed by the peer read deadline', async () => {
  const stream = new ScriptedStream();
  const channel = createPeerChannel(stream, options());
  const incoming = setInterval(() => stream.inject([0]), 2);
  try {
    await eventually(() => stream.sent.some(frame => frame.length === 1 && frame[0] === 0));
  } finally { clearInterval(incoming); channel.close(); }
});

test('peer channel rejects malformed tags and frames and closes the underlying stream', async () => {
  for (const malformed of [[0, 1], [2], [9, 1], new Array(66).fill(1)]) {
    const stream = new ScriptedStream();
    const channel = createPeerChannel(stream, options());
    stream.inject(malformed);
    await eventually(() => channel.closed);
    assert.equal(stream.closed, true);
  }
});

test('peer channel bounds queued writes and closes after a write failure', async () => {
  const blockedStream = new ScriptedStream({ blockSends: true });
  const blocked = createPeerChannel(blockedStream, options({ maxQueuedFrames: 1 }));
  const first = blocked.lane('accounting').send(Uint8Array.from([1]));
  await assert.rejects(blocked.lane('accounting').send(Uint8Array.from([2])));
  blockedStream.releaseSends();
  await first;
  blocked.close();

  const failingStream = new ScriptedStream({ failSends: true });
  const failing = createPeerChannel(failingStream, options());
  await assert.rejects(failing.lane('mls').send(Uint8Array.from([3])));
  await eventually(() => failing.closed);
  assert.equal(failingStream.closed, true);
});

test('peer channel refuses an empty application lane frame', async () => {
  const stream = new ScriptedStream();
  const channel = createPeerChannel(stream, options());
  await assert.rejects(channel.lane('invitation').send(new Uint8Array()));
  assert.equal(stream.sent.length, 0);
  channel.close();
});

test('peer channel bounds lane queues, duplicate readers, and receive deadlines', async () => {
  const stream = new ScriptedStream();
  const channel = createPeerChannel(stream, options({ maxQueuedFrames: 1 }));
  stream.inject([1, 1]);
  stream.inject([1, 2]);
  await eventually(() => channel.closed);
  assert.equal(stream.closed, true);

  const readerStream = new ScriptedStream();
  const readerChannel = createPeerChannel(readerStream, options({ receiveDeadlineMs: 15 }));
  const lane = readerChannel.lane('invitation');
  const pending = lane.receive();
  await assert.rejects(lane.receive());
  await assert.rejects(pending);
  assert.equal(readerChannel.closed, true);
  assert.equal(readerStream.closed, true);
});
