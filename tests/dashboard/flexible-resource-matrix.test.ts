import { expect, it as platformTest } from "vitest";
import { flexibleDashboardFixture } from "../helpers/flexible-dashboard-fixture.js";
import { prepareAssessmentActors } from "../../src/dashboard/execution/AssessmentActorRegistry.js";
const it = platformTest.skipIf(process.platform !== "win32");
const common = { policyReference: "Explicit synthetic read-only ownership/field/business policy", reviewed: true };
const collection = {
  kind: "COLLECTION",
  algorithm: "bounded-native-collection-v1",
  collectionPath: "items",
  itemIdentityPath: "id",
  ownerPath: "owner",
  ownerRule: "EXACT_VERIFIED_ACTOR_PRINCIPAL_STRING",
  maxItems: 4,
  maxResponseBytes: 4096,
  coverage: "THIS_RESPONSE_ONLY",
  pagination: { kind: "HAS_MORE_BOOLEAN", path: "hasMore" }
};
it.each(["SECURE", "VULNERABLE", "EMPTY", "INCOMPLETE", "DUPLICATE"] as const)(
  "native flexible reviewed collection, field and chained business reads: %s",
  async (mode) => {
    const f = await flexibleDashboardFixture(2, false, { reviewedResourceFixture: mode });
    try {
      const p = prepareAssessmentActors(f.database, f.vault, f.org, {
        ...f.input,
        resources: [
          { ...common, id: "entries", kind: "COLLECTION_OWNERSHIP", path: "/collection", collection },
          {
            ...common,
            id: "fields",
            kind: "FIELD_EXPOSURE",
            path: "/fields",
            fieldPath: "internal",
            permittedActorIds: ["actor0"]
          },
          {
            ...common,
            id: "state",
            kind: "BUSINESS_READ",
            path: "/state",
            actorIds: ["actor0", "actor1"],
            markerPath: "state",
            markerValue: "ready"
          },
          {
            ...common,
            id: "next-state",
            kind: "BUSINESS_READ",
            path: "/state",
            actorIds: ["actor0", "actor1"],
            prerequisiteResourceId: "state",
            markerPath: "state",
            markerValue: "ready"
          }
        ]
      });
      Object.assign(f.request, {
        actorRegistry: p.registry,
        actorCredentials: p.actorCredentials,
        apiGraphql: p.apiGraphql,
        targetAuthorization: p.targetAuthorization
      });
      const r = await f.run(),
        cells = r.report.apiGraphql.checks;
      const expected = mode === "SECURE" ? "PASS" : mode === "VULNERABLE" ? "FAIL" : "INCONCLUSIVE";
      expect(
        cells
          .filter((c: { checkId: string }) => c.checkId.startsWith("resource-entries-"))
          .map((c: { outcome: string }) => c.outcome)
      ).toEqual([expected, expected]);
      expect(cells.find((c: { checkId: string }) => c.checkId === "resource-fields-actor1").outcome).toBe(
        mode === "VULNERABLE" ? "FAIL" : "PASS"
      );
      expect(
        cells
          .filter((c: { checkId: string }) => c.checkId.startsWith("resource-next-state-"))
          .every((c: { outcome: string }) => c.outcome === "PASS")
      ).toBe(true);
      if (mode === "VULNERABLE") expect(r.report.findings.length).toBeGreaterThan(0);
      f.capture("R3_RESOURCE_MATRIX", {
        mode,
        cells,
        findings: r.report.findings,
        capabilities: r.report.assessmentCapabilities,
        wire: f.wire
      });
    } finally {
      await f.close();
    }
  }
);
it("missing identity disables only stronger resources; reviewed session observation continues", async () => {
  const f = await flexibleDashboardFixture(2, true);
  try {
    const p = prepareAssessmentActors(f.database, f.vault, f.org, {
      ...f.input,
      resources: [
        { ...common, id: "session", kind: "SESSION_READ", path: "/private", actorIds: ["actor0", "actor1"] },
        {
          ...common,
          id: "fields",
          kind: "FIELD_EXPOSURE",
          path: "/private",
          fieldPath: "internal",
          permittedActorIds: ["actor0"]
        }
      ]
    });
    Object.assign(f.request, {
      actorRegistry: p.registry,
      actorCredentials: p.actorCredentials,
      apiGraphql: p.apiGraphql,
      targetAuthorization: p.targetAuthorization
    });
    const r = await f.run();
    expect(
      r.report.apiGraphql.checks
        .filter((c: { checkId: string }) => c.checkId.startsWith("resource-fields-"))
        .every((c: { outcome: string }) => c.outcome === "BLOCKED")
    ).toBe(true);
    expect(
      r.report.apiGraphql.checks
        .filter((c: { checkId: string }) => c.checkId.startsWith("resource-session-"))
        .every((c: { requests: unknown[] }) => c.requests.length === 1)
    ).toBe(true);
    expect(f.wire.some((w) => w.path === "/who")).toBe(false);
    f.capture("R3_OPTIONAL_IDENTITY", { report: r.report, wire: f.wire });
  } finally {
    await f.close();
  }
});
it("one principal can review exact field policy and session reads without a second or third account", async () => {
  const f = await flexibleDashboardFixture(1, false, { reviewedResourceFixture: "SECURE" });
  try {
    const p = prepareAssessmentActors(f.database, f.vault, f.org, {
      ...f.input,
      resources: [
        {
          ...common,
          id: "own-field",
          kind: "FIELD_EXPOSURE",
          path: "/fields",
          fieldPath: "internal",
          permittedActorIds: ["actor0"]
        },
        { ...common, id: "own-session", kind: "SESSION_READ", path: "/private", actorIds: ["actor0"] }
      ]
    });
    Object.assign(f.request, {
      actorRegistry: p.registry,
      actorCredentials: p.actorCredentials,
      apiGraphql: p.apiGraphql,
      targetAuthorization: p.targetAuthorization
    });
    const r = await f.run();
    expect(
      r.report.apiGraphql.checks.find((c: { checkId: string }) => c.checkId === "resource-own-field-actor0").outcome
    ).toBe("PASS");
    expect(r.report.assessmentCapabilities.actors[0].roleVerified).toBe(false);
    f.capture("R3_SINGLE_PRINCIPAL_FIELD", { report: r.report, wire: f.wire });
  } finally {
    await f.close();
  }
});
