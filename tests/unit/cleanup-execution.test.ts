import { describe, expect, it } from "vitest";
import { CleanupExecution, cleanupTimeoutMs, workerRestorationGraceMs } from "../../src/core/engine/CleanupExecution.js";

describe("independent bounded restoration", () => {
  it("does not inherit an already aborted scan signal", async () => {
    const parent = new AbortController(); parent.abort();
    const cleanup = new CleanupExecution(40, parent.signal);
    try {
      expect(cleanup.signal.aborted).toBe(false);
      await expect(cleanup.wait(500)).rejects.toThrow();
      expect(cleanup.signal.aborted).toBe(true);
      expect(workerRestorationGraceMs).toBeGreaterThan(cleanupTimeoutMs);
    } finally { cleanup.dispose(); }
  });
  it("starts lazily and does not restart the budget on subsequent requests", async () => {
    const cleanup = new CleanupExecution(25);
    try {
      await new Promise((resolve) => setTimeout(resolve, 40));
      expect(cleanup.signal.aborted).toBe(false);
      cleanup.start();
      await expect(cleanup.wait(100)).rejects.toThrow();
      expect(cleanup.start().aborted).toBe(true);
    } finally { cleanup.dispose(); }
  });
});
