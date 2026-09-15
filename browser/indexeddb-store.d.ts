export interface InboxPublication {
  version: 1;
  liveOnly: boolean;
  entries: Array<{ kind: 'control' } | { kind: 'application'; messageId: number[]; sessionId: number[] }>;
  cancelApplicationIds: number[][];
  expectedVersion: number;
  nextVersion: number;
  devicePublicKey: number[];
}

export interface StoredInbox {
  checkpoint: Uint8Array;
  outbound: Uint8Array[];
  metadata: InboxPublication;
  version: number;
}

export interface IndexedDbInboxStore {
  persist(id: string): (checkpoint: Uint8Array, outbound: Uint8Array[], metadata: InboxPublication) => Promise<true>;
  read(id: string): Promise<StoredInbox | undefined>;
  close(): void;
}

/** Uses a dedicated database. Missing storage accepts only a new version-zero Inbox. */
export function openIndexedDbInboxStore(name: string): Promise<IndexedDbInboxStore>;
