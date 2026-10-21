import { expect, it as platformTest } from "vitest";
import { flexibleDashboardFixture } from "../helpers/flexible-dashboard-fixture.js";
import { prepareAssessmentActors } from "../../src/dashboard/execution/AssessmentActorRegistry.js";
const it = platformTest.skipIf(process.platform !== "win32");
export const objectPolicy = {
  id: "owned-object",
  kind: "OBJECT_OWNERSHIP",
  path: "/object/actor0",
  pathTemplate: "/object/:id",
  policyReference: "Owner-reviewed synthetic object is private to actor0",
  reviewed: true,
  ownerActorId: "actor0",
  ownerPath: "owner",
  ownerValue: "actor0",
  allowedStatuses: [200],
  deniedStatuses: [401, 403, 404]
};
it("canonical two-account preparation compiles reviewed owner and foreign cells and executes a real worker", async () => {
  const f = await flexibleDashboardFixture(2);
  try {
    const p = prepareAssessmentActors(f.database, f.vault, f.org, { ...f.input, resources: [objectPolicy] });
    expect(p.requestsSent).toBe(0);
    expect(p.apiGraphql.checks.filter((c) => c.matrixId === "resource-owned-object")).toHaveLength(2);
    Object.assign(f.request, {
      actorRegistry: p.registry,
      actorCredentials: p.actorCredentials,
      apiGraphql: p.apiGraphql,
      targetAuthorization: p.targetAuthorization
    });
    const r = await f.run();
    const cells = r.report.apiGraphql.checks.filter((c: { checkId: string }) =>
      c.checkId.startsWith("resource-owned-object-")
    );
    expect(cells.map((c: { outcome: string }) => c.outcome)).toEqual(["PASS", "PASS"]);
    expect(f.wire.filter((w) => w.path === "/object/actor0").map((w) => w.actor)).toEqual(["actor0", "actor1"]);
    f.capture("R3_REVIEWED_POLICY_NATIVE", {
      cells,
      capabilities: r.report.assessmentCapabilities,
      receipts: r.receipts
    });
  } finally {
    await f.close();
  }
});
it.each(["COOKIE", "API_KEY"] as const)(
  "exact reviewed ownership propagates %s through the encrypted Windows worker boundary",
  async (mechanism) => {
    const f = await flexibleDashboardFixture(2, false, { mechanism });
    try {
      const p = prepareAssessmentActors(f.database, f.vault, f.org, { ...f.input, resources: [objectPolicy] });
      Object.assign(f.request, {
        actorRegistry: p.registry,
        actorCredentials: p.actorCredentials,
        apiGraphql: p.apiGraphql,
        targetAuthorization: p.targetAuthorization
      });
      const r = await f.run(),
        cells = r.report.apiGraphql.checks.filter((c: { checkId: string }) =>
          c.checkId.startsWith("resource-owned-object-")
        );
      expect(cells.map((c: { outcome: string }) => c.outcome)).toEqual(["PASS", "PASS"]);
      expect(
        r.report.assessmentCapabilities.actors.every((a: { mechanism: string }) => a.mechanism === mechanism)
      ).toBe(true);
      for (const token of f.tokens) expect(JSON.stringify(r.report)).not.toContain(token);
      f.capture("R3_NATIVE_MECHANISM_POLICY", { mechanism, cells, receipts: r.receipts });
    } finally {
      await f.close();
    }
  }
);
