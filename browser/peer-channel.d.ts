import type { LiveFramedStream } from './live-stream.mjs';
export function createPeerChannel(stream: LiveFramedStream, options: {
  maxFrameBytes: number; maxQueuedFrames: number; keepaliveMs: number; receiveDeadlineMs: number;
}): {
  readonly closed: boolean;
  lane(name: 'invitation' | 'mls' | 'accounting'): LiveFramedStream;
  close(): void;
};
