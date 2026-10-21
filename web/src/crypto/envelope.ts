/**
 * Application-layer envelope encryption using WebCrypto.
 *
 * Crypto concept: Hybrid encryption using ECDH (P-256) + HKDF-SHA256 + AES-256-GCM.
 * Threat mitigated: Payload eavesdropping, TLS termination sniffing, middlebox tampering.
 */

import { base64ToBytes, bytesToBase64 } from "./sign";

const ENVELOPE_INFO = new TextEncoder().encode("miniupi/v1/envelope");

function getCryptoSubtle(): SubtleCrypto {
  if (typeof window !== "undefined" && window.crypto && window.crypto.subtle) {
    return window.crypto.subtle;
  }
  if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto.subtle;
  }
  throw new Error("WebCrypto SubtleCrypto is not available in this environment");
}

function getRandomBytes(len: number): Uint8Array {
  const bytes = new Uint8Array(len);
  if (typeof window !== "undefined" && window.crypto) {
    window.crypto.getRandomValues(bytes);
  } else if (typeof globalThis !== "undefined" && globalThis.crypto) {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    throw new Error("No cryptographic random source available");
  }
  return bytes;
}

export interface RequestEnvelope {
  v: number;
  eph_pub: JsonWebKey;
  salt: string;
  iv: string;
  ct: string;
  tag: string;
  txn_id: string;
  ts: number | string;
}

export interface ResponseEnvelope {
  v: number;
  iv: string;
  ct: string;
  tag: string;
  txn_id: string;
}

/**
 * Encrypt payload for server using ephemeral ECDH + HKDF + AES-256-GCM.
 * Returns the request envelope and the derived symmetric key (for response decryption).
 */
export async function createRequestEnvelope(
  serverPublicJwk: JsonWebKey,
  plaintext: Uint8Array | string,
  txnId: string,
  ts: number | string = Date.now()
): Promise<{ envelope: RequestEnvelope; derivedKey: CryptoKey }> {
  const subtle = getCryptoSubtle();

  const plaintextBytes =
    typeof plaintext === "string"
      ? new TextEncoder().encode(plaintext)
      : plaintext;

  // 1. Generate ephemeral ECDH keypair
  const ephKeyPair = await subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits", "deriveKey"]
  );

  // 2. Import server static public key
  const serverPubKey = await subtle.importKey(
    "jwk",
    serverPublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  // 3. Perform ECDH to get shared bits
  const sharedBits = await subtle.deriveBits(
    { name: "ECDH", public: serverPubKey },
    ephKeyPair.privateKey,
    256
  );

  // 4. Import shared bits into HKDF master key
  const hkdfKey = await subtle.importKey(
    "raw",
    sharedBits,
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );

  // 5. Derive AES-256-GCM symmetric key
  const salt = getRandomBytes(16);
  const derivedKey = await subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: ENVELOPE_INFO as BufferSource,
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  // 6. Encrypt with AES-GCM
  const iv = getRandomBytes(12);
  const aad = new TextEncoder().encode(`${txnId}${ts}`);
  const ctWithTagBuffer = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource,
      additionalData: aad as BufferSource,
      tagLength: 128,
    },
    derivedKey,
    plaintextBytes as BufferSource
  );

  const ctWithTag = new Uint8Array(ctWithTagBuffer);
  const ct = ctWithTag.slice(0, ctWithTag.length - 16);
  const tag = ctWithTag.slice(ctWithTag.length - 16);

  const ephPubJwk = await subtle.exportKey("jwk", ephKeyPair.publicKey);

  const envelope: RequestEnvelope = {
    v: 1,
    eph_pub: ephPubJwk,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(ct),
    tag: bytesToBase64(tag),
    txn_id: txnId,
    ts: ts,
  };

  return { envelope, derivedKey };
}

/**
 * Decrypt a response envelope using the derived AES-256-GCM key.
 */
export async function decryptResponseEnvelope(
  derivedKey: CryptoKey,
  envelope: ResponseEnvelope,
  txnId: string
): Promise<Uint8Array> {
  const subtle = getCryptoSubtle();

  if (envelope.v !== 1) {
    throw new Error(`Unsupported response envelope version: ${envelope.v}`);
  }

  const iv = base64ToBytes(envelope.iv);
  const ct = base64ToBytes(envelope.ct);
  const tag = base64ToBytes(envelope.tag);

  const ctWithTag = new Uint8Array(ct.length + tag.length);
  ctWithTag.set(ct);
  ctWithTag.set(tag, ct.length);

  const aad = new TextEncoder().encode(`${txnId}resp`);

  const decryptedBuffer = await subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource,
      additionalData: aad as BufferSource,
      tagLength: 128,
    },
    derivedKey,
    ctWithTag as BufferSource
  );

  return new Uint8Array(decryptedBuffer);
}
