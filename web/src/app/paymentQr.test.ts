import { describe, expect, it } from "vitest";
import { parsePaymentQr } from "./paymentQr";

describe("Mini-UPI payment QR parsing", () => {
  it("accepts a campus VPA directly", () => {
    expect(parsePaymentQr(" 22it001@gcet ")).toEqual({ vpa: "22it001@gcet" });
  });

  it("parses Mini-UPI VPA and optional whole-rupee amount", () => {
    expect(parsePaymentQr("miniupi://pay?vpa=22it001%40gcet&am=25000")).toEqual({
      vpa: "22it001@gcet",
      amount: "250",
    });
  });

  it("rejects unsupported schemes and malformed amounts", () => {
    expect(() => parsePaymentQr("https://example.test/pay?vpa=student@gcet")).toThrow(
      /not a Mini-UPI payment address/,
    );
    expect(() => parsePaymentQr("miniupi://pay?vpa=student%40gcet&am=150")).toThrow(
      /Enter the amount manually/,
    );
  });
});
