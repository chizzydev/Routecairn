import { it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { tenantlessApplicationFixture } from "../helpers/tenantless-application-fixture.js";
import { TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
it("binds real native tenantless observations to organization, target and recorded identity model", async () => {
  const f = await tenantlessApplicationFixture();
  try {
    const a = await f.acquire(),
      count = f.wire.length;
    expect(() => f.mapping.result(randomUUID(), a.revision.revisionId)).toThrow("NOT_FOUND");
    expect(() => f.hypotheses.generate(randomUUID(), { mapRevisionId: a.revision.revisionId }, "operator")).toThrow(
      "NOT_FOUND"
    );
    const original = new TargetRepository(f.database).get(f.onboard.targetId)!,
      targetId = new TargetRepository(f.database).create({
        organizationId: f.org,
        displayName: "Other native source target",
        tags: [],
        baseOrigin: f.origin,
        classification: "LOCAL",
        authorizationType: "OWNED",
        authorizationSummary: "Separate generated source target",
        approvedScope: original.approvedScope
      });
    await expect(
      f.workbench.preview(f.org, {
        targetId,
        sourceScanId: a.run.scanId,
        credentials: {},
        expectations: [
          {
            routeId: "onboarded-seed",
            url: f.origin + "/object",
            kind: "OBJECT_AUTHORIZATION",
            explanation: "Source evidence may not be moved to this other owned target",
            decisions: { primary: "ALLOW", anonymous: "DENY" },
            identity: { path: "id", expectedValue: "generated-shared-object" }
          }
        ]
      })
    ).rejects.toThrow("COMPLETED_BOUND_OBSERVATION_REQUIRED");
    const row = f.database.db
      .prepare("SELECT input_json,request_json,digest FROM application_mapping_revisions WHERE id=?")
      .get(a.revision.revisionId) as { input_json: string; request_json: string; digest: string };
    f.capture("SOURCE_BEFORE_TEST_ONLY_ROW_FAULT", { row, report: a.report });
    expect(() =>
      f.database.db
        .prepare("UPDATE application_mapping_revisions SET input_json=? WHERE id=?")
        .run(JSON.stringify({ ...JSON.parse(row.input_json), identityModel: "TENANT_AWARE" }), a.revision.revisionId)
    ).toThrow("IMMUTABLE_MAPPING_REVISION");
    expect(
      f.database.db
        .prepare("SELECT input_json,request_json,digest FROM application_mapping_revisions WHERE id=?")
        .get(a.revision.revisionId)
    ).toEqual(row);
    expect(f.mapping.result(f.org, a.revision.revisionId).input.identityModel).toBe("PRINCIPAL_ROLE");
    await expect(f.mapping.preview(f.org, { ...f.onboard.input, identityModel: "TENANT_AWARE" })).rejects.toThrow(
      "IDENTITY_MODEL_MISMATCH"
    );
    expect(f.wire.length).toBe(count);
    f.capture("CROSS_CONTEXT_AND_MODE_REPLAY_REFUSAL", { requestsAfterSource: 0, ownerDataTouched: false });
  } finally {
    await f.close();
  }
});
