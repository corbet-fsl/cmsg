// One local publication chain per Inbox. IndexedDB serializes competing writes
// across tabs; the encrypted checkpoint and its outbound records commit together.
const invalid = () => new Error('cmsg:InvalidStore');
const conflict = () => new Error('cmsg:StorageConflict');
const validId = id => typeof id === 'string' && id.length > 0;
const integer = value => Number.isSafeInteger(value) && value >= 0;

function publication(checkpoint, outbound, metadata) {
  if (!(checkpoint instanceof Uint8Array) || checkpoint.length === 0
      || !Array.isArray(outbound) || outbound.some(wire => !(wire instanceof Uint8Array))
      || !metadata || !integer(metadata.expectedVersion) || !integer(metadata.nextVersion)
      || metadata.nextVersion !== metadata.expectedVersion + 1
      || !Array.isArray(metadata.devicePublicKey) || metadata.devicePublicKey.length !== 32
      || metadata.devicePublicKey.some(byte => !Number.isInteger(byte) || byte < 0 || byte > 255)) throw invalid();
  // Capture arguments before yielding, including callers' mutable typed arrays.
  return { checkpoint: checkpoint.slice(), outbound: outbound.map(wire => wire.slice()),
    metadata: structuredClone(metadata), version: metadata.nextVersion };
}

/** Open a dedicated local Inbox database; this never imports or resets a chain. */
export async function openIndexedDbInboxStore(name) {
  if (!validId(name) || !globalThis.indexedDB) throw invalid();
  const db = await new Promise((resolve, reject) => {
    let settled = false;
    const fail = () => { settled = true; reject(invalid()); };
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
      if (settled) { request.transaction.abort(); return; }
      if (!request.result.objectStoreNames.contains('sessions')) request.result.createObjectStore('sessions');
    };
    request.onerror = request.onblocked = fail;
    request.onsuccess = () => {
      if (settled || !request.result.objectStoreNames.contains('sessions')) {
        request.result.close(); fail(); return;
      }
      settled = true; resolve(request.result);
    };
  });
  db.onversionchange = () => db.close();
  return Object.freeze({
    persist(id) {
      if (!validId(id)) throw invalid();
      return async (checkpoint, outbound, metadata) => {
        const record = publication(checkpoint, outbound, metadata);
        return new Promise((resolve, reject) => {
          let transaction, stale = false;
          try { transaction = db.transaction('sessions', 'readwrite', { durability: 'strict' }); }
          catch { reject(invalid()); return; }
          transaction.oncomplete = () => resolve(true);
          transaction.onabort = () => reject(stale ? conflict() : invalid());
          if (transaction.durability !== 'strict') { transaction.abort(); return; }
          const records = transaction.objectStore('sessions');
          const previous = records.get(id);
          previous.onsuccess = () => {
            try {
              const version = previous.result === undefined ? 0 : previous.result.version;
              if (!integer(version) || version !== record.metadata.expectedVersion) {
                stale = true; transaction.abort(); return;
              }
              records.put(record, id);
            } catch { transaction.abort(); }
          };
        });
      };
    },
    async read(id) {
      if (!validId(id)) throw invalid();
      return new Promise((resolve, reject) => {
        let transaction, record;
        try { transaction = db.transaction('sessions', 'readonly'); }
        catch { reject(invalid()); return; }
        transaction.onabort = () => reject(invalid());
        transaction.oncomplete = () => resolve(record);
        const request = transaction.objectStore('sessions').get(id);
        request.onsuccess = () => { record = request.result; };
      });
    },
    close() { db.close(); },
  });
}
