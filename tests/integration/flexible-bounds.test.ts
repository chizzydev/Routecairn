import { it, expect } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { flexibleFixture } from "../helpers/flexible-assessment-fixture.js";
import { actorRegistryDigest } from "../../src/core/auth/ActorRegistry.js";
it("bounds private credential input files before parsing or target I/O", async () => {
  const f = await flexibleFixture(1);
  try {
    const wrapper = JSON.parse(readFileSync(f.registryPath, "utf8"));
    writeFileSync(wrapper.profiles.actor0, " ".repeat(262145));
    await expect(f.run()).rejects.toThrow("ACTOR_REGISTRY_FILE_BOUND");
    expect(f.wire).toEqual([]);
  } finally {
    await f.close();
  }
});
it("expired available credential cannot be transmitted and does not block public coverage", async () => {
  const f = await flexibleFixture(1);
  try {
    const input = JSON.parse(readFileSync(f.registryPath, "utf8"));
    input.registry.actors[0].authentication.credentialExpiresAt = new Date(Date.now() - 1000).toISOString();
    const authorization = JSON.parse(readFileSync(f.authorizationPath, "utf8"));
    authorization.productionCampaign.actorRegistryDigest = actorRegistryDigest(input.registry);
    writeFileSync(f.registryPath, JSON.stringify(input));
    writeFileSync(f.authorizationPath, JSON.stringify(authorization));
    const { report, result } = await f.run();
    expect(result.status).toBe("COMPLETED");
    expect(f.wire.some((w) => w.path === "/" && w.actor === "anonymous")).toBe(true);
    expect(f.wire.some((w) => w.actor === "actor0")).toBe(false);
    expect(report.assessmentCapabilities.actors[0].assurance).toBe("REVOKED_OR_INVALID");
    expect(report.assessmentCapabilities.workflows[0].reason).toBe("CREDENTIAL_EXPIRED");
  } finally {
    await f.close();
  }
});
it("the shared request budget prevents unperformed comparisons becoming passes", async () => {
  const f = await flexibleFixture(5);
  try {
    const authorization = JSON.parse(readFileSync(f.authorizationPath, "utf8"));
    authorization.productionCampaign.maxRequests = 3;
    writeFileSync(f.authorizationPath, JSON.stringify(authorization));
    const { report } = await f.run();
    expect(f.wire.length).toBeLessThanOrEqual(3);
    expect(report.requestBudget.totalTransmitted).toBeLessThanOrEqual(3);
    expect(report.findings).toEqual([]);
    expect(
      report.apiGraphql.checks
        .filter((c: { checkId: string }) => c.checkId.startsWith("compare"))
        .every((c: { outcome: string }) => c.outcome !== "PASS")
    ).toBe(true);
  } finally {
    await f.close();
  }
});
