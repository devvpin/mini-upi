/**
 * Parse Mini-UPI QR payloads before they enter the payment confirmation form.
 *
 * Crypto concept: payment details remain user-confirmed before authorization.
 * Threat mitigated: misdirected payments from untrusted or malformed QR data.
 */

export function parsePaymentQr(value: string): { vpa: string; amount?: string } {
  const text = value.trim();
  if (/^[a-z0-9._-]+@[a-z0-9.-]+$/i.test(text)) return { vpa: text };

  let parsed: URL;
  try {
    parsed = new URL(text);
  } catch {
    throw new Error("This QR code is not a Mini-UPI payment address.");
  }
  if (parsed.protocol !== "miniupi:") {
    throw new Error("This QR code is not a Mini-UPI payment address.");
  }
  const vpa = parsed.searchParams.get("vpa");
  if (!vpa) throw new Error("This QR code does not contain a payment VPA.");

  const amountPaise = parsed.searchParams.get("am");
  if (!amountPaise) return { vpa };
  if (!/^\d+$/.test(amountPaise) || Number(amountPaise) < 100) {
    throw new Error("This QR code contains an invalid payment amount.");
  }
  if (Number(amountPaise) % 100 !== 0) {
    throw new Error("This QR code uses paise. Enter the amount manually.");
  }
  return { vpa, amount: String(Number(amountPaise) / 100) };
}
