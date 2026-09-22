import type { BrowserInbox, BrowserReceived } from './pkg/cmsg.js';
import type { InboxPublication } from './indexeddb-store.js';

export interface LiveFramedStream {
  readonly closed: boolean;
  send(wire: Uint8Array): Promise<void>;
  receive(): Promise<Uint8Array>;
  close(): void;
}
export interface LiveInboxStorage {
  key: Uint8Array;
  context: Uint8Array;
  persist(checkpoint: Uint8Array, outbound: Uint8Array[], metadata: InboxPublication): Promise<true>;
  /**
   * Serialize the complete cmsg operation, including synchronous Wasm
   * getters used by that operation, with the embedding application's state.
   * The callback must not wait for peer input; transport reads belong outside
   * this callback. `control` covers opening, control flushes, and close.
   */
  schedule?: <T>(category: 'send' | 'receive' | 'control', operation: () => Promise<T>) => Promise<T>;
}
export class LiveInboxStream {
  private constructor();
  static open(stream: LiveFramedStream, inbox: BrowserInbox,
    options: LiveInboxStorage & { peerDevice: Uint8Array; until: number }): Promise<LiveInboxStream>;
  readonly closed: boolean;
  send(bytes: Uint8Array): Promise<void>;
  receive(): Promise<BrowserReceived>;
  close(): Promise<void>;
}
