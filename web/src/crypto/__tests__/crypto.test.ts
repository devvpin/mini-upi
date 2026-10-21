import { describe, it, expect } from "vitest";
import {
  canonicalJson,
  generateDeviceKeyPair,
  exportPublicKeyJwk,
  signPayload,
  verifyPayloadSignature,
  createRequestEnvelope,
  decryptResponseEnvelope,
  bytesToBase64,
} from "../index";

describe("WebCrypto Canonical JSON", () => {
  it("sorts keys lexicographically and produces NFC utf-8", () => {
    const input = {
      z: 100,
      a: "hello",
      m: {
        b: true,
        a: null,
      },
    };
    const expected = '{"a":"hello","m":{"a":null,"b":true},"z":100}';
    expect(canonicalJson(input)).toBe(expected);
  });

  it("rejects non-integer floating point numbers", () => {
    expect(() => canonicalJson({ amount: 12.34 })).toThrow(/Floats are prohibited/);
    expect(() => canonicalJson({ amount: NaN })).toThrow(/Floats are prohibited/);
    expect(() => canonicalJson({ amount: Infinity })).toThrow(/Floats are prohibited/);
  });

  it("accepts integers and 0", () => {
    expect(canonicalJson({ amount: 150000, zero: 0 })).toBe('{"amount":150000,"zero":0}');
  });
});

describe("WebCrypto Non-Extractable Device Keys", () => {
  it("generates non-extractable private key and rejects exportKey", async () => {
    const keyPair = await generateDeviceKeyPair(false);

    expect(keyPair.privateKey.extractable).toBe(false);
    expect(keyPair.publicKey.extractable).toBe(true);

    // Attempting to export non-extractable private key must fail
    await expect(
      crypto.subtle.exportKey("jwk", keyPair.privateKey)
    ).rejects.toThrow();

    // Public key export should succeed
    const pubJwk = await exportPublicKeyJwk(keyPair.publicKey);
    expect(pubJwk.kty).toBe("EC");
    expect(pubJwk.crv).toBe("P-256");
    expect(pubJwk.x).toBeDefined();
    expect(pubJwk.y).toBeDefined();
  });

  it("signs canonical payload and verifies signature", async () => {
    const keyPair = await generateDeviceKeyPair(false);
    const payload = {
      amount_paise: 50000,
      payee_vpa: "canteen@gcet",
      payer_vpa: "student@gcet",
      txn_id: "test-txn-1234",
    };

    const { signatureB64, canonicalStr } = await signPayload(keyPair.privateKey, payload);
    expect(typeof signatureB64).toBe("string");
    expect(signatureB64.length).toBeGreaterThan(0);
    expect(canonicalStr).toBe('{"amount_paise":50000,"payee_vpa":"canteen@gcet","payer_vpa":"student@gcet","txn_id":"test-txn-1234"}');

    const valid = await verifyPayloadSignature(keyPair.publicKey, payload, signatureB64);
    expect(valid).toBe(true);

    // Tampered payload fails verification
    const tamperedPayload = { ...payload, amount_paise: 999999 };
    const invalid = await verifyPayloadSignature(keyPair.publicKey, tamperedPayload, signatureB64);
    expect(invalid).toBe(false);
  });
});

describe("WebCrypto Envelope Encryption", () => {
  it("encrypts with ephemeral ECDH and roundtrips with server side", async () => {
    // Simulate server ECDH keypair
    const serverKey = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey", "deriveBits"]
    );
    const serverPubJwk = await crypto.subtle.exportKey("jwk", serverKey.publicKey);

    const txnId = "simulated-txn-uuid-001";
    const ts = Math.floor(Date.now() / 1000);
    const clientPayload = { mpin: "1234", note: "Virtual lunch" };

    const { envelope, derivedKey } = await createRequestEnvelope(
      serverPubJwk,
      canonicalJson(clientPayload),
      txnId,
      ts
    );

    expect(envelope.eph_pub).toBeDefined();
    expect(envelope.salt).toBeDefined();
    expect(envelope.iv).toBeDefined();
    expect(envelope.ct).toBeDefined();
    expect(envelope.tag).toBeDefined();
    expect(envelope.txn_id).toBe(txnId);
    expect(envelope.ts).toBe(ts);

    // Simulate server response encryption using same derived key
    const respPayload = { status: "SUCCESS", balance_paise: 120000 };
    const respIv = crypto.getRandomValues(new Uint8Array(12));
    const respAad = new TextEncoder().encode(`${txnId}resp`);
    const respPlaintext = new TextEncoder().encode(canonicalJson(respPayload));

    const ctWithTag = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: respIv,
        additionalData: respAad,
        tagLength: 128,
      },
      derivedKey,
      respPlaintext
    );

    const ctBytes = new Uint8Array(ctWithTag.slice(0, ctWithTag.byteLength - 16));
    const tagBytes = new Uint8Array(ctWithTag.slice(ctWithTag.byteLength - 16));

    const respEnvelope = {
      v: 1,
      iv: bytesToBase64(respIv),
      ct: bytesToBase64(ctBytes),
      tag: bytesToBase64(tagBytes),
      txn_id: txnId,
    };

    // Client decrypts server response
    const decryptedBytes = await decryptResponseEnvelope(derivedKey, respEnvelope, txnId);
    const decryptedStr = new TextDecoder().decode(decryptedBytes);
    expect(JSON.parse(decryptedStr)).toEqual(respPayload);
  });
});
