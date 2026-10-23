// The proving setup (SRS) of the wallet origin. It is fetched from this origin only, verified
// against digests pinned by the engine, and cached in IndexedDB in the proof system's expanded
// form. A cached copy is verified again on every load; on any mismatch it is discarded and the
// compressed setup is fetched again. Nothing is read from any other origin.
import { Failure, type Progress, type Setup } from './wire.js';

const DATABASE = 'cmeet-prover-srs';
const STORE = 'srs';
const key = (points: number) => `g1-expanded-${points}`;

export const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource)));
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function cachedGet(name: string): Promise<Uint8Array | undefined> {
  try {
    const db = await open();
    try {
      return await new Promise((resolve, reject) => {
        const request = db.transaction(STORE).objectStore(STORE).get(name);
        request.onsuccess = () => resolve(request.result as Uint8Array | undefined);
        request.onerror = () => reject(request.error);
      });
    } finally {
      db.close();
    }
  } catch {
    return undefined; // storage unavailable or blocked: behave as an empty cache
  }
}
async function cachedPut(name: string, value: Uint8Array | null): Promise<void> {
  try {
    const db = await open();
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE, 'readwrite');
        if (value === null) tx.objectStore(STORE).delete(name);
        else tx.objectStore(STORE).put(value.slice(), name); // a plain, unshared copy
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  } catch {
    // A full or blocked store only costs the next start the expansion; it never fails a proof.
  }
}

/** Fetch exactly `length` bytes from this origin. The buffer is allocated up front, so a
 * hostile response cannot grow it; redirects and credentials are refused. */
async function fetchExactly(
  path: string,
  length: number,
  mode: RequestCache,
  report?: (progress: Progress) => void,
): Promise<Uint8Array> {
  let response: Response;
  try {
    response = await fetch(path, { cache: mode, credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer' });
  } catch {
    throw new Failure('srs_fetch');
  }
  if (!response.ok || !response.body) throw new Failure('srs_fetch');
  const out = new Uint8Array(length);
  let offset = 0;
  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (offset + value.length > length) throw new Failure('srs_fetch');
      out.set(value, offset);
      offset += value.length;
      report?.({ stage: 'srs-fetch', loaded: offset, total: length });
    }
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new Failure('srs_fetch');
  }
  if (offset !== length) throw new Failure('srs_fetch');
  return out;
}

/** Fetch a pinned file: verify, and on a digest mismatch fetch once more bypassing every HTTP
 * cache layer; a second mismatch is a refusal. */
async function fetchPinned(
  path: string,
  length: number,
  digest: string,
  report?: (progress: Progress) => void,
): Promise<Uint8Array> {
  for (const mode of ['default', 'reload'] as const) {
    const bytes = await fetchExactly(path, length, mode, report);
    report?.({ stage: 'srs-verify' });
    if ((await sha256Hex(bytes)) === digest) return bytes;
  }
  throw new Failure('srs_digest');
}

export interface Srs {
  g2: Uint8Array;
  /** Either the verified expanded points (`expanded`) or the verified compressed points. */
  g1: Uint8Array;
  expanded: boolean;
}

/** Load the setup the plan names: from the verified cache when possible, else from the origin. */
export async function loadSrs(plan: Setup['srs'], report: (progress: Progress) => void): Promise<Srs> {
  const g2 = await fetchPinned(plan.g2_path, 128, plan.g2_sha256);
  const name = key(plan.points);
  const cached = await cachedGet(name);
  if (cached !== undefined) {
    report({ stage: 'srs-cache' });
    if (cached.length === plan.points * 64 && (await sha256Hex(cached)) === plan.g1_expanded_sha256) {
      return { g2, g1: cached, expanded: true };
    }
    await cachedPut(name, null);
  }
  const g1 = await fetchPinned(plan.g1_path, plan.points * 32, plan.g1_sha256, report);
  return { g2, g1, expanded: false };
}

/** Keep the expanded points the proof system produced, but only if they are the pinned ones. */
export async function cacheExpanded(plan: Setup['srs'], expanded: Uint8Array): Promise<void> {
  if (expanded.length !== plan.points * 64 || (await sha256Hex(expanded)) !== plan.g1_expanded_sha256) {
    throw new Failure('srs_digest');
  }
  await cachedPut(key(plan.points), expanded);
}
