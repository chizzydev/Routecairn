import { it, expect } from "vitest";
import { reviewedScalar, assertReviewedScalar } from "./ReviewedPolicyInput";
it("requires explicit finite numeric policy values while preserving zero and typed strings", () => {
  for (const s of [" ", "0x10", "Infinity", "NaN", "1e999", "01"]) {
    const v = reviewedScalar(s, true);
    expect(v).toBe(s);
    expect(() => assertReviewedScalar(v, "number")).toThrow("explicit finite decimal");
  }
  for (const [s, n] of [
    ["0", 0],
    ["-1.25", -1.25],
    ["1e2", 100]
  ] as const) {
    expect(reviewedScalar(s, true)).toBe(n);
    expect(() => assertReviewedScalar(n, "number")).not.toThrow();
  }
  expect(reviewedScalar("001", false)).toBe("001");
});
