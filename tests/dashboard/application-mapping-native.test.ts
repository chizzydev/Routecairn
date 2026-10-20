import { it, expect } from "vitest";
import { authorizationWorkbenchFixture } from "../helpers/authorization-workbench-fixture.js";
import { ApplicationMappingService } from "../../src/dashboard/execution/ApplicationMappingService.js";
it("acquires a real native application map before binding and proves the same-object authorization and remediation journey", async () => {
  const f = await authorizationWorkbenchFixture({ prepareObservation: false });
  try {
    expect(f.wire).toHaveLength(0);
    expect(f.database.db.prepare("SELECT COUNT(*) n FROM scans").get()).toEqual({ n: 0 });
    const service = new ApplicationMappingService(f.database, f.vault, f.execution),
      input = {
        targetId: f.input.targetId,
        credentials: f.input.credentials,
        identityContextConfirmed: true,
        readOnlyRoutesConfirmed: true,
        routes: f.input.expectations.map((e) => ({
          id: e.routeId,
          kind: e.routeId === "admin" ? "FUNCTION" : "OBJECT",
          url: e.url,
          pathTemplate:
            e.routeId === "admin"
              ? "/api/admin/summary"
              : "/api/" + (e.routeId === "document" ? "documents" : e.routeId) + "/:id",
          method: "GET",
          identityPath: "id",
          tenantPath: "tenant"
        }))
      };
    const revision = await service.create(f.org, input, "operator");
    expect(revision.transportIntents).toHaveLength(20);
    expect(f.wire).toHaveLength(0);
    const dispatched = await service.execute(f.org, revision.revisionId, revision.digest, "operator");
    await f.wait(dispatched.scanId!);
    const observed = service.result(f.org, revision.revisionId);
    expect(observed.status).toBe("COMPLETED");
    expect(observed.observations).toHaveLength(4);
    expect(observed.provenance?.securityCases.cases.length).toBeGreaterThan(0);
    expect(observed.observationIsPolicyOrFinding).toBe(false);
    expect(observed.observations[0]!.cells[0]!.observedMarkers).toHaveLength(2);
    expect(JSON.stringify(observed.observations)).not.toContain('"expectedValue"');
    const expectations = f.input.expectations.map((e) => ({
      ...e,
      decisions: { primary: "ALLOW", "account-a": "DENY", "account-b": "DENY", anonymous: "DENY" }
    }));
    const before = await service.createMatrix(
      f.org,
      revision.revisionId,
      { expectations, policyConfirmed: true },
      "operator"
    );
    expect(before.blockers).toEqual([]);
    expect(before.matrix).toHaveLength(16);
    const beforeRun = await f.service.execute(f.org, before.revisionId, before.digest, "operator");
    await f.wait(beforeRun.scanId!);
    const vulnerable = f.service.result(f.org, before.revisionId);
    if (!("checks" in vulnerable)) throw Error("Missing executed evidence");
    expect(vulnerable.findings).toHaveLength(2);
    expect(vulnerable.checks.filter((c) => c.checkId.startsWith("masked-") && c.outcome === "FAIL")).toHaveLength(0);
    f.setFixed();
    const after = await service.createMatrix(
        f.org,
        revision.revisionId,
        { expectations, policyConfirmed: true },
        "operator"
      ),
      afterRun = await f.service.execute(f.org, after.revisionId, after.digest, "operator");
    await f.wait(afterRun.scanId!);
    const fixed = f.service.result(f.org, after.revisionId);
    expect(fixed).toMatchObject({ status: "INCONCLUSIVE", verifiedPass: false, findings: [] });
    expect(f.wire).toHaveLength(60);
    f.capture("GUIDED_NATIVE_OBSERVE_BIND_PROVE_REMEDIATE");
  } finally {
    await f.close();
  }
});
