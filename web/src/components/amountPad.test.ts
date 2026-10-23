import { describe, expect, it } from "vitest";
import { applyAmountPadKey } from "./UI";

describe("amount pad", () => {
  it("appends digits without exceeding the ₹5,000 transaction limit", () => {
    expect(applyAmountPadKey("", "5")).toBe("5");
    expect(applyAmountPadKey("500", "0")).toBe("5000");
    expect(applyAmountPadKey("5000", "1")).toBe("5000");
  });

  it("deletes a digit and clears the current amount", () => {
    expect(applyAmountPadKey("123", "⌫")).toBe("12");
    expect(applyAmountPadKey("123", "Clear")).toBe("");
  });

  it("rejects non-digit keys and normalizes leading zeroes", () => {
    expect(applyAmountPadKey("12", "x")).toBe("12");
    expect(applyAmountPadKey("0", "4")).toBe("4");
  });
});
