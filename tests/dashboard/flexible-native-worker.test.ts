import { it as platformTest, expect } from "vitest";
const it = platformTest.skipIf(process.platform !== "win32");
import { flexibleDashboardFixture } from "../helpers/flexible-dashboard-fixture.js";
it.each([0, 1, 2, 3, 5])("encrypted vault to actual Windows custodied native worker with %s actors", async (count) => {
  const f = await flexibleDashboardFixture(count);
  try {
    const before = f.wire.length;
    expect(f.prepared.requestsSent).toBe(0);
    expect(before).toBe(0);
    const r = await f.run();
    expect(r.receipts.integrity).toEqual([{ integrity_check: "ok" }]);
    expect(r.receipts.foreignKeys).toEqual([]);
    expect(r.report.scanPlan.actorRegistry.actors).toHaveLength(count);
    expect(r.receipts.plans[0]).toMatchObject({ plan_binding: r.receipts.plans[0]!.worker_verified_binding });
    expect(f.wire.some((w) => w.path === (count ? "/private" : "/") && (count ? w.actor === "actor0" : true))).toBe(
      true
    );
    for (const token of f.tokens) expect(JSON.stringify(r.report)).not.toContain(token);
  } finally {
    await f.close();
  }
});
it("supports an actual native dashboard worker with one account and no identity endpoint", async () => {
  const f = await flexibleDashboardFixture(1, true);
  try {
    const r = await f.run();
    expect(f.wire.some((w) => w.path === "/who")).toBe(false);
    expect(r.report.assessmentCapabilities.actors[0].assurance).toBe("CREDENTIAL_SUPPLIED_IDENTITY_UNVERIFIED");
    expect(r.report.apiGraphql.checks.some((c: { requests: unknown[] }) => c.requests.length > 0)).toBe(true);
  } finally {
    await f.close();
  }
});
