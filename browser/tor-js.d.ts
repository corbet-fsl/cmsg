import type { TorStorage } from 'tor-js/wasm-file';

export interface OnionTransport {
  /** Exchange one bounded encrypted frame with a peer-owned onion endpoint. */
  exchange(host: string, port: number, wire: Uint8Array): Promise<Uint8Array>;
  close(): void;
}

export interface TorJsOptions {
  /** Explicit gateway KPS addresses, as accepted by TorJS 0.4.1. */
  gateway: string | string[];
  /** Whole exchange deadline, including Tor readiness, from 1 to 60000ms. */
  deadlineMs: number;
  /** Persistent Tor directory/guard storage; never cmsg plaintext storage. */
  storage?: TorStorage;
}

export function createTorJsOnionTransport(options: TorJsOptions): Promise<OnionTransport>;
