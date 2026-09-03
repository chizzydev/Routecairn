import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { runLocalTargetValidation } from "../../src/validation/LocalTargetValidation.js";

describe("full disposable live-target acceptance", () => {
  it("runs real login, actor setup, browser, workers, finding/proof, fix comparison, protected action and recovery", async () => {
    const directory = await mkdtemp(join(tmpdir(), "routecairn-local-acceptance-test-"));
    try {
      const result = await runLocalTargetValidation(directory);
      expect(result.status).toBe("PASSED");
      expect(result.externalTargetsTested).toBe(false);
      expect(result.credentialsReusable).toBe(false);
      expect(Object.values(result.checks).every(Boolean)).toBe(true);
      expect(result.timelineEvents).toBeGreaterThan(10);
      expect(result.staleReads).toBeGreaterThan(0);
      expect(JSON.parse(await readFile(join(result.directory, "validation-summary.json"), "utf8"))).toMatchObject({ status: "PASSED", fixtureOnly: true, simulatedHumanReview: true });
    } finally { await rm(directory, { recursive: true, force: true }); }
  }, 120000);
});
