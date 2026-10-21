/**
 * Canonical JSON serializer for WebCrypto digital signatures.
 *
 * Crypto concept: Deterministic serialization (JSON Canonicalization Scheme).
 * Threat mitigated: Signature invalidation due to whitespace, key ordering,
 * or Unicode normalization differences between client and server.
 *
 * Rules:
 * 1. UTF-8 encoded.
 * 2. Object keys sorted lexicographically.
 * 3. No insignificant whitespace (separators: ',', ':').
 * 4. Integers only — floats are strictly prohibited.
 * 5. Strings are Unicode NFC normalized.
 * 6. Booleans serialized as 'true' / 'false', null as 'null'.
 */

function normalizeValue(value: unknown): unknown {
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error(
        `Floats are prohibited in canonical JSON (got ${value}). Use integer paise.`
      );
    }
    return value;
  }
  if (typeof value === "string") {
    return value.normalize("NFC");
  }
  if (value === null || typeof value === "boolean") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(normalizeValue);
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const sortedKeys = Object.keys(obj).sort();
    const result: Record<string, unknown> = {};
    for (const key of sortedKeys) {
      result[key.normalize("NFC")] = normalizeValue(obj[key]);
    }
    return result;
  }
  return String(value);
}

export function canonicalJson(obj: unknown): string {
  const normalized = normalizeValue(obj);
  return JSON.stringify(normalized);
}

export function canonicalBytes(obj: unknown): Uint8Array {
  const jsonStr = canonicalJson(obj);
  return new TextEncoder().encode(jsonStr);
}
