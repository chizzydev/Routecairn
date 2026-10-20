import { describe, it, expect } from "vitest";
import { cleanupMac, verifyCleanupMac } from "../../src/dashboard/worker/CleanupAttemptProtocol.js";
describe("private cleanup request and result receipt authentication", () => {
  it("authenticates normalized field order", () => {
    const a = { attemptId: "owned", workerGeneration: "generation", ordinal: 1 },
      hmac = cleanupMac("fixture-secret", a);
    expect(() =>
      verifyCleanupMac("fixture-secret", { ordinal: 1, workerGeneration: "generation", attemptId: "owned", hmac })
    ).not.toThrow();
  });
  it("refuses an altered generation or request ordinal", () => {
    const a = { attemptId: "owned", workerGeneration: "generation", ordinal: 1 },
      hmac = cleanupMac("fixture-secret", a);
    expect(() => verifyCleanupMac("fixture-secret", { ...a, workerGeneration: "replacement", hmac })).toThrow(
      "AUTHENTICATION"
    );
    expect(() => verifyCleanupMac("fixture-secret", { ...a, ordinal: 2, hmac })).toThrow("AUTHENTICATION");
  });
  it("refuses missing or malformed receipt authentication", () => {
    for (const hmac of [undefined, "invalid", "0".repeat(64)])
      expect(() => verifyCleanupMac("fixture-secret", { attemptId: "owned", hmac })).toThrow("AUTHENTICATION");
  });
});
