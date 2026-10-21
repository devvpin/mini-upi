/**
 * Digital signature generation and verification via WebCrypto ECDSA-SHA256.
 *
 * Crypto concept: Digital signature over canonical JSON producing IEEE P1363 raw (r || s).
 * Threat mitigated: Transaction parameter tampering, repudiation.
 */

import { canonicalBytes, canonicalJson } from "./canonical";

function getCryptoSubtle(): SubtleCrypto {
  if (typeof window !== "undefined" && window.crypto && window.crypto.subtle) {
    return window.crypto.subtle;
  }
  if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto.subtle;
  }
  throw new Error("WebCrypto SubtleCrypto is not available in this environment");
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const len = bytes.length;
  for (let i = 0; i < len; i++) {
    const b = bytes[i];
    if (b !== undefined) {
      binary += String.fromCharCode(b);
    }
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Sign payload using ECDSA P-256 and SHA-256.
 * Returns raw 64-byte (r || s) signature encoded as base64, along with the canonical string.
 */
export async function signPayload(
  privateKey: CryptoKey,
  payload: unknown
): Promise<{ signatureB64: string; canonicalStr: string }> {
  const subtle = getCryptoSubtle();
  const canonicalStr = canonicalJson(payload);
  const data = new TextEncoder().encode(canonicalStr);

  const signatureBuffer = await subtle.sign(
    {
      name: "ECDSA",
      hash: "SHA-256",
    },
    privateKey,
    data as BufferSource
  );

  const sigBytes = new Uint8Array(signatureBuffer);
  const signatureB64 = bytesToBase64(sigBytes);

  return { signatureB64, canonicalStr };
}

/**
 * Verify ECDSA-SHA256 raw 64-byte signature against payload.
 */
export async function verifyPayloadSignature(
  publicKey: CryptoKey,
  payload: unknown,
  signatureB64: string
): Promise<boolean> {
  const subtle = getCryptoSubtle();
  const data = canonicalBytes(payload);
  const sigBytes = base64ToBytes(signatureB64);

  return subtle.verify(
    {
      name: "ECDSA",
      hash: "SHA-256",
    },
    publicKey,
    sigBytes as BufferSource,
    data as BufferSource
  );
}
