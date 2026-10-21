/**
 * Device key management using WebCrypto and IndexedDB.
 *
 * Crypto concept: Non-extractable ECDSA P-256 private key bound to browser storage.
 * Threat mitigated: Private key exfiltration via XSS, script injection, or token theft.
 */

const DB_NAME = "mini_upi_keystore";
const STORE_NAME = "device_keys";
const KEY_NAME = "primary_device_keypair";

function getCryptoSubtle(): SubtleCrypto {
  if (typeof window !== "undefined" && window.crypto && window.crypto.subtle) {
    return window.crypto.subtle;
  }
  if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto.subtle;
  }
  throw new Error("WebCrypto SubtleCrypto is not available in this environment");
}

let inMemoryStore: CryptoKeyPair | null = null;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      return reject(new Error("IndexedDB is not supported"));
    }
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/**
 * Generate a new non-extractable ECDSA P-256 keypair.
 * extractable: false guarantees the private key can NEVER be exported by any script.
 */
export async function generateDeviceKeyPair(extractable = false): Promise<CryptoKeyPair> {
  const subtle = getCryptoSubtle();
  return subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    extractable,
    ["sign", "verify"]
  );
}

/**
 * Export public key to JWK for registration with the server.
 */
export async function exportPublicKeyJwk(publicKey: CryptoKey): Promise<JsonWebKey> {
  const subtle = getCryptoSubtle();
  return subtle.exportKey("jwk", publicKey);
}

/**
 * Store device keypair in IndexedDB (or in-memory fallback if IndexedDB unavailable).
 */
export async function storeDeviceKey(keyPair: CryptoKeyPair): Promise<void> {
  try {
    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const req = store.put(keyPair, KEY_NAME);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  } catch {
    inMemoryStore = keyPair;
  }
}

/**
 * Retrieve device keypair from storage.
 */
export async function getDeviceKey(): Promise<CryptoKeyPair | null> {
  try {
    const db = await openDb();
    return await new Promise<CryptoKeyPair | null>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(KEY_NAME);
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror = () => reject(req.error);
    });
  } catch {
    return inMemoryStore;
  }
}

/**
 * Get existing device keypair, or generate and persist a new non-extractable one.
 */
export async function getOrCreateDeviceKey(): Promise<CryptoKeyPair> {
  let keyPair = await getDeviceKey();
  if (!keyPair) {
    keyPair = await generateDeviceKeyPair(false);
    await storeDeviceKey(keyPair);
  }
  return keyPair;
}

/**
 * Delete device keypair from storage (e.g. on device revocation or logout).
 */
export async function clearDeviceKey(): Promise<void> {
  inMemoryStore = null;
  try {
    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const req = store.delete(KEY_NAME);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  } catch {
    // Ignore error if IndexedDB not present
  }
}
