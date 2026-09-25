import { createPublicKey, verify } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { broaderAcceptanceLaneIds, runBroaderAcceptanceValidation } from "../../src/validation/BroaderAcceptanceValidation.js";

describe("broader acceptance laboratory", () => {
  it("executes all eight lanes, restores state, signs evidence, and persists no replayable secrets", async () => {
    const parent = await mkdtemp(join(tmpdir(), "routecairn-broader-test-"));
    try {
      const summary = await runBroaderAcceptanceValidation(parent);
      expect(summary.status).toBe("PASSED");
      expect(summary.externalTargetsTested).toBe(false);
      expect(summary.lanes.map((lane) => lane.id)).toEqual(broaderAcceptanceLaneIds);
      expect(summary.lanes.every((lane) => lane.status === "PASSED" && /^[a-f0-9]{64}$/.test(lane.evidenceDigest))).toBe(true);
      expect(summary.cleanup.verified).toBe(true);
      expect(summary.requestCount).toBeGreaterThanOrEqual(35);
      const publicKey = createPublicKey({ key: Buffer.from(summary.attestation.publicKey, "base64url"), type: "spki", format: "der" });
      expect(verify(null, Buffer.from(summary.attestation.digest, "hex"), publicKey, Buffer.from(summary.attestation.signature, "base64url"))).toBe(true);
      const evidence = await readFile(join(summary.directory, "broader-acceptance-requests.json"), "utf8");
      expect(evidence).not.toContain("Bearer ");
      expect(evidence).not.toContain("signature\"");
      expect(evidence).not.toContain("secret\"");
      expect(JSON.parse(evidence).requests.every((item: Record<string, unknown>) => typeof item.path === "string" && !String(item.path).includes("?"))).toBe(true);
      expect(await readFile(join(summary.directory, "broader-acceptance-report.md"), "utf8")).toContain("not external-target certification");
    } finally {
      await rm(parent, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
    }
  }, 30000);
});
