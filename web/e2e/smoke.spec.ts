import { webcrypto } from "node:crypto";
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

interface RequestEnvelope {
  v: number;
  eph_pub: JsonWebKey;
  salt: string;
  iv: string;
  ct: string;
  tag: string;
  txn_id: string;
  ts: number;
}

function decodeBase64(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "base64"));
}

function encodeBase64(value: Uint8Array): string {
  return Buffer.from(value).toString("base64");
}

async function navigate(page: Page, label: string): Promise<void> {
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: label }).click();
}

test("first login, wallet, payment, and verified receipt work end to end", async ({ page }) => {
  const pair = await webcrypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const serverPublicKey = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  const serverPrivateKey = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
  let registeredDevice: Record<string, unknown> | null = null;

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;

    if (path === "/api/v1/auth/login") {
      await route.fulfill({
        json: {
          access_token: "smoke-token",
          user: {
            id: "user-1",
            college_id: "22IT002",
            full_name: "Diya Patel",
            email: "diya@example.test",
            role: "student",
            status: "active",
            department_code: "it",
            class_name: "TY-IT",
            must_change_password: true,
          },
        },
      });
      return;
    }
    if (path === "/api/v1/auth/change-password" || path === "/api/v1/mpin/set") {
      await route.fulfill({ json: { status: "ok" } });
      return;
    }
    if (path === "/api/v1/devices" && request.method() === "GET") {
      await route.fulfill({ json: registeredDevice ? [registeredDevice] : [] });
      return;
    }
    if (path === "/api/v1/devices/register") {
      registeredDevice = {
        id: "device-1",
        label: "This browser",
        status: "active",
        public_key_jwk: request.postDataJSON().public_key_jwk,
        created_at: new Date().toISOString(),
        revoked_at: null,
      };
      await route.fulfill({
        status: 201,
        json: registeredDevice,
      });
      return;
    }
    if (path === "/api/v1/wallet") {
      await route.fulfill({
        json: {
          account_id: "account-1",
          balance_paise: 245000,
          balance_rupees: 2450,
          primary_vpa: "22it002@gcet",
          recent_transactions: [],
        },
      });
      return;
    }
    if (path === "/api/v1/vpa/resolve") {
      await route.fulfill({
        json: { handle: "22it001@gcet", masked_name: "A**** S******" },
      });
      return;
    }
    if (path === "/api/v1/crypto/server-key") {
      await route.fulfill({ json: { public_key: serverPublicKey } });
      return;
    }
    if (path === "/api/v1/vpa/me") {
      await route.fulfill({
        json: {
          primary_vpa: "22it002@gcet",
          all_vpas: ["22it002@gcet"],
          qr_payload: "miniupi://pay?vpa=22it002%40gcet",
        },
      });
      return;
    }
    if (path === "/api/v1/payments/pay") {
      const envelope = request.postDataJSON() as RequestEnvelope;
      const serverPrivate = await webcrypto.subtle.importKey(
        "jwk",
        serverPrivateKey,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"],
      );
      const clientPublic = await webcrypto.subtle.importKey(
        "jwk",
        envelope.eph_pub,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        [],
      );
      const sharedBits = await webcrypto.subtle.deriveBits(
        { name: "ECDH", public: clientPublic },
        serverPrivate,
        256,
      );
      const hkdf = await webcrypto.subtle.importKey("raw", sharedBits, { name: "HKDF" }, false, ["deriveKey"]);
      const aesKey = await webcrypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: decodeBase64(envelope.salt),
          info: new TextEncoder().encode("miniupi/v1/envelope"),
        },
        hkdf,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt", "encrypt"],
      );
      const ciphertext = new Uint8Array([
        ...decodeBase64(envelope.ct),
        ...decodeBase64(envelope.tag),
      ]);
      let plaintext: ArrayBuffer;
      try {
        plaintext = await webcrypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: decodeBase64(envelope.iv),
            additionalData: new TextEncoder().encode(`${envelope.txn_id}${envelope.ts}`),
            tagLength: 128,
          },
          aesKey,
          ciphertext,
        );
      } catch {
        await route.fulfill({
          status: 400,
          json: { detail: "Envelope invalid: ciphertext authentication failed." },
        });
        return;
      }
      const inner = JSON.parse(new TextDecoder().decode(plaintext)) as {
        device_sig: string;
        mpin: string;
        payload: { amount_paise: number; payer_vpa: string; payee_vpa: string };
      };
      expect(inner.device_sig).toBeTruthy();
      expect(inner.mpin).toBe("123456");
      expect(inner.payload.amount_paise).toBe(100);
      expect(inner.payload.payer_vpa).toBe("22it002@gcet");
      expect(inner.payload.payee_vpa).toBe("22it001@gcet");

      const iv = webcrypto.getRandomValues(new Uint8Array(12));
      const encryptedReceipt = new Uint8Array(await webcrypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: new TextEncoder().encode(`${envelope.txn_id}resp`),
          tagLength: 128,
        },
        aesKey,
        new TextEncoder().encode("{}"),
      ));
      const split = encryptedReceipt.length - 16;
      await route.fulfill({
        json: {
          envelope: {
            v: 1,
            txn_id: envelope.txn_id,
            iv: encodeBase64(iv),
            ct: encodeBase64(encryptedReceipt.slice(0, split)),
            tag: encodeBase64(encryptedReceipt.slice(split)),
          },
        },
      });
      return;
    }
    if (/\/api\/v1\/transactions\/[0-9a-f-]+$/i.test(path)) {
      await route.fulfill({
        json: {
          id: path.split("/").at(-1),
          amount_paise: 100,
          amount_rupees: 1,
          payer_vpa: "22it002@gcet",
          payee_vpa: "22it001@gcet",
          payer_name: "D*** P****",
          payee_name: "A**** S******",
          direction: "DEBIT",
          note: "Campus payment",
          status: "success",
          created_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
          receipt: {},
          security_lens: {
            device_signature_verified: true,
            psp_signature_verified: true,
            switch_mac_verified: true,
            bank_signature_verified: true,
            bank_cert_subject: "CN=GCET Campus Bank",
            bank_cert_issuer: "CN=Mini-UPI Root CA",
            audit_chain_seq: 1,
            audit_entry_hash: "test-hash",
            audit_chain_verified: true,
          },
        },
      });
      return;
    }
    await route.fulfill({ status: 404, json: { detail: `Unexpected API request: ${path}` } });
  });

  await page.setViewportSize({ width: 360, height: 800 });
  await page.goto("/");
  await page.getByLabel("College ID").fill("22IT002");
  await page.getByLabel("Password").fill("temporary-password");
  await page.getByRole("button", { name: "Enter campus wallet" }).click();

  await page.getByLabel("New password (at least 8 characters)").fill("ChangedPassword@123");
  await page.getByRole("button", { name: "Change password" }).click();
  await page.getByLabel("Choose a six-digit MPIN").fill("123456");
  await page.getByRole("button", { name: "Set MPIN and bind browser" }).click();

  await expect(page.getByText("Welcome, Diya.")).toBeVisible();
  await expect(page.getByText("₹2,450.00")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await navigate(page, "Pay");
  await page.getByLabel("Pay to VPA").fill("22it001@gcet");
  await page.getByRole("button", { name: "1", exact: true }).click();
  await page.getByRole("button", { name: "Review payment" }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await expect(page.getByText("A**** S******")).toBeVisible();
  await page.getByLabel("Six-digit MPIN").fill("123456");
  await page.getByRole("button", { name: "Confirm & send" }).click();
  await expect(page.getByText("Payment complete — bank receipt verified.")).toBeVisible();

  test.skip(process.env.VITE_DEMO_MODE !== "true", "Build with VITE_DEMO_MODE=true to test the tamper demo.");
  await navigate(page, "Pay");
  await page.getByLabel("Pay to VPA").fill("22it001@gcet");
  await page.getByRole("button", { name: "1", exact: true }).click();
  await page.getByRole("button", { name: "Review payment" }).click();
  const tamperToggle = page.getByLabel("Demo tamper test");
  await expect(tamperToggle).toBeVisible();
  await tamperToggle.check();
  await page.getByLabel("Six-digit MPIN").fill("123456");
  await page.getByRole("button", { name: "Confirm & send" }).click();
  await expect(page.getByText("Envelope invalid: ciphertext authentication failed.")).toBeVisible();
});

test("collect requests can be created and incoming requests declined", async ({ page }) => {
  const createdRequest = {
    id: "collect-1",
    requester_vpa: "22it002@gcet",
    payer_vpa: "22it001@gcet",
    requester_name: "Diya Patel",
    amount_paise: 25000,
    amount_rupees: 250,
    note: "Lunch",
    status: "pending",
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 86_400_000).toISOString(),
  };
  const incomingRequest = {
    ...createdRequest,
    id: "incoming-1",
    requester_vpa: "22it001@gcet",
    payer_vpa: "22it002@gcet",
    requester_name: "Aarav Sharma",
  };
  let declined = false;

  await page.route("**/api/v1/**", async (route) => {
    const incoming = route.request();
    const path = new URL(incoming.url()).pathname;
    if (path === "/api/v1/auth/login") {
      await route.fulfill({
        json: {
          access_token: "smoke-token",
          user: {
            id: "user-1",
            college_id: "22IT002",
            full_name: "Diya Patel",
            email: "diya@example.test",
            role: "student",
            status: "active",
            department_code: "it",
            class_name: "TY-IT",
            must_change_password: false,
          },
        },
      });
    } else if (path === "/api/v1/wallet") {
      await route.fulfill({
        json: {
          account_id: "account-1",
          balance_paise: 245000,
          balance_rupees: 2450,
          primary_vpa: "22it002@gcet",
          recent_transactions: [],
        },
      });
    } else if (path === "/api/v1/vpa/resolve") {
      await route.fulfill({ json: { handle: "22it001@gcet", masked_name: "A**** S******" } });
    } else if (path === "/api/v1/payments/collect" && incoming.method() === "POST") {
      await route.fulfill({ status: 201, json: createdRequest });
    } else if (path === "/api/v1/payments/collect/incoming") {
      await route.fulfill({ json: declined ? [] : [incomingRequest] });
    } else if (path === "/api/v1/payments/collect/incoming-1/decline") {
      declined = true;
      await route.fulfill({ json: { ok: true, collect_status: "declined" } });
    } else {
      await route.fulfill({ status: 404, json: { detail: `Unexpected API request: ${path}` } });
    }
  });

  await page.goto("/");
  await page.getByLabel("College ID").fill("22IT002");
  await page.getByLabel("Password").fill("password");
  await page.getByRole("button", { name: "Enter campus wallet" }).click();
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: "Requests" }).click();

  await page.getByLabel("Request from VPA").fill("22it001@gcet");
  await page.getByLabel("Amount (whole rupees)").fill("250");
  await page.getByLabel("Note (optional)").fill("Lunch");
  await page.getByRole("button", { name: "Send request" }).click();
  await expect(page.getByText("Request sent to A**** S******.")).toBeVisible();
  await expect(page.getByText("Aarav Sharma")).toBeVisible();
  await page.getByLabel("MPIN").fill("123456");
  await page.getByRole("button", { name: "Decline" }).click();
  await expect(page.getByText("Aarav Sharma")).toHaveCount(0);
});
