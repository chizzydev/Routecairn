import { it, expect } from "vitest";
import { flexibleFixture } from "../helpers/flexible-assessment-fixture.js";
it.each([0, 1, 2, 3, 5])("real Windows native registry/cardinality assessment %s", async (count) => {
  const f = await flexibleFixture(count);
  try {
    const { result, report } = await f.run();
    expect(result.status).toBe("COMPLETED");
    expect(report.scanPlan.actorRegistry.actors).toHaveLength(count);
    expect(f.wire.some((r) => r.path === (count ? "/private" : "/"))).toBe(true);
    expect(report.assessmentCapabilities.actors).toHaveLength(count);
    expect(report.apiGraphql.checks.every((c: any) => c.outcome !== "FAIL")).toBe(true);
    expect(JSON.stringify(report)).not.toContain(f.tokens[0] ?? "NEVER_PRESENT_SECRET");
    if (count >= 2)
      expect(report.apiGraphql.checks.find((c: any) => c.checkId === "compare-actor1").outcome).toBe("PASS");
  } finally {
    await f.close();
  }
});
it.each(["COOKIE", "API_KEY"] as const)("uses actual %s credentials without a bearer token", async (mechanism) => {
  const f = await flexibleFixture(1, { mechanism });
  try {
    const { result } = await f.run();
    expect(result.status).toBe("COMPLETED");
    expect(f.wire.some((r) => r.actor === "actor0" && r.path === "/private")).toBe(true);
  } finally {
    await f.close();
  }
});
it("does not require an identity endpoint for credential-bound observation and blocks stronger ownership proof", async () => {
  const f = await flexibleFixture(2, { noIdentity: true });
  try {
    const { report } = await f.run();
    expect(f.wire.some((r) => r.path === "/who")).toBe(false);
    expect(f.wire.some((r) => r.path === "/private" && r.actor === "actor1")).toBe(true);
    expect(report.apiGraphql.checks.find((c: any) => c.checkId === "compare-actor1").outcome).toBe("BLOCKED");
    expect(report.findings).toEqual([]);
  } finally {
    await f.close();
  }
});
it("finds a reviewed real cross-account resource flaw using only two principal-only accounts", async () => {
  const f = await flexibleFixture(2, { vulnerable: true });
  try {
    const { report } = await f.run();
    expect(report.apiGraphql.checks.find((c: any) => c.checkId === "compare-actor1").outcome).toBe("FAIL");
    expect(report.findings.length).toBeGreaterThan(0);
  } finally {
    await f.close();
  }
});
