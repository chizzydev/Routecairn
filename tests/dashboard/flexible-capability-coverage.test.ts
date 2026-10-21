import { it as platformTest, expect } from "vitest";
const it = platformTest.skipIf(process.platform !== "win32");
import { flexibleDashboardFixture } from "../helpers/flexible-dashboard-fixture.js";
import { runtimeAssessmentCapabilities } from "../../src/core/auth/AssessmentCapabilities.js";
import {
  recordCapabilityCoverage,
  readCapabilityCoverage
} from "../../src/dashboard/execution/AssessmentCapabilityCoverage.js";
it("real SQLite retains all 64 capability decisions within existing event bounds and labels partial inline evidence", async () => {
  const f = await flexibleDashboardFixture(0);
  try {
    const preview = await f.execution.preview(f.request),
      id = await f.execution.enqueue(
        { ...f.request, studio: { ...f.request.studio!, previewIdentity: preview.previewIdentity } },
        undefined,
        undefined,
        f.org
      );
    f.execution.cancel(id);
    await f.execution.shutdown();
    const base = runtimeAssessmentCapabilities(f.prepared.registry, undefined, undefined, undefined),
      value = {
        ...base,
        workflows: Array.from({ length: 64 }, (_, i) => ({
          ...base.workflows[0]!,
          workflowId: "storage-" + i,
          evidence: Array.from({ length: 100 }, (_, j) => ({
            checkId: "case-" + j,
            comparisonFingerprint: "a".repeat(64),
            outcome: "INCONCLUSIVE" as const,
            reason: "STORAGE_TEST_NOT_NATIVE_PROOF",
            observedRequests: 0
          }))
        }))
      };
    f.database.transaction(() => recordCapabilityCoverage(f.database, id, value, "source-json-artifact"));
    const coverage = readCapabilityCoverage(f.database, id);
    expect(coverage && "workflows" in coverage ? coverage.workflows.length : 0).toBe(64);
    const rows = f.database.db
      .prepare(
        "SELECT safe_metadata_json FROM scan_events WHERE scan_id=? AND json_extract(safe_metadata_json,'$.kind') LIKE 'ASSESSMENT_CAPABILITY_%'"
      )
      .all(id) as Array<{ safe_metadata_json: string }>;
    expect(rows.every((r) => r.safe_metadata_json.length <= 4000)).toBe(true);
    expect(rows.some((r) => JSON.parse(r.safe_metadata_json).truncated)).toBe(false);
    const read = coverage && "workflows" in coverage ? coverage.workflows[0] : undefined;
    expect(read).toMatchObject({
      evidenceCount: 100,
      evidenceCoverage: "FULL_EVIDENCE_IN_SOURCE_REPORT",
      reportArtifactId: "source-json-artifact"
    });
    f.capture("CAPABILITY_BOUNDARY_SQLITE_RECEIPT", {
      rows,
      integrity: f.database.db.pragma("integrity_check"),
      foreignKeys: f.database.db.pragma("foreign_key_check"),
      storageTestOnly: true,
      nativeProof: false
    });
  } finally {
    await f.close();
  }
});
it("an interrupted capability snapshot is explicitly inconclusive", async () => {
  const f = await flexibleDashboardFixture(0);
  try {
    const preview = await f.execution.preview(f.request),
      id = await f.execution.enqueue(
        { ...f.request, studio: { ...f.request.studio!, previewIdentity: preview.previewIdentity } },
        undefined,
        undefined,
        f.org
      );
    f.execution.cancel(id);
    await f.execution.shutdown();
    f.database.appendEvent(id, "OBSERVATION_RECORDED", "Owned incomplete read-model fault fixture", {
      kind: "ASSESSMENT_CAPABILITY_SNAPSHOT",
      registryId: f.prepared.registry.registryId,
      actors: 0,
      workflows: 1,
      reportArtifactId: "not-executed"
    });
    expect(readCapabilityCoverage(f.database, id)).toEqual({
      state: "INCONCLUSIVE",
      reason: "CAPABILITY_READ_MODEL_INCOMPLETE"
    });
  } finally {
    await f.close();
  }
});
