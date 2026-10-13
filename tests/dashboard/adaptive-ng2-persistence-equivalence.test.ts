import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { recordWorkflowCaseExecutions } from "../../src/dashboard/comparisons/WorkflowCaseExecutionRecorder.js";
import { AdaptiveSecurityService } from "../../src/dashboard/execution/AdaptiveSecurityService.js";
import type { AdaptiveInventory, AdaptiveRecommendation } from "../../src/dashboard/execution/AdaptiveSynthesisCore.js";
import { projectAdaptiveSecurityCases } from "../../src/dashboard/execution/AdaptiveSecurityCaseProjection.js";
import { ng2Origin, ng2Report, ng2Scope } from "../helpers/adaptive-ng2-fixture.js";

/** DB proof is separate so the direct IR/projection suite imports no database or credential system. */
describe("RC-NG2 independent persistence equivalence", () => {
  it("projects identical ordered cases from independent databases and different IDs/timestamps", () => {
    const databases: DashboardDatabase[] = [];
    vi.useFakeTimers();
    try {
      const report = ng2Report("account_a");
      const observe = (time: string) => {
        vi.setSystemTime(new Date(time));
        const database = new DashboardDatabase(":memory:"); databases.push(database); database.migrate();
        const savedFixtures = { accountAProfileId: randomUUID(), accountBProfileId: randomUUID() };
        const targetId = new TargetRepository(database).create({ displayName: "NG2 disposable fixture", baseOrigin: ng2Origin, tags: [], classification: "PRIVATE", authorizationType: "OWNED", authorizationSummary: "Owned in-memory shadow projection fixture", productionEnabled: false, approvedScope: ng2Scope, defaultAuthTemplate: savedFixtures });
        const scanId = randomUUID();
        new ScanRepository(database).create({ id: scanId, source: "DASHBOARD", status: "COMPLETED", targetOrigin: ng2Origin, safeTargetLabel: "NG2 fixture", profile: "full", evidenceLevel: "strong", safeConfigurationSummary: {}, targetId });
        recordWorkflowCaseExecutions(database.db, scanId, structuredClone(report));
        const snapshot = new AdaptiveSecurityService(database).observeCompletedScan(scanId, structuredClone(report), targetId) as unknown as { id: string; inventory: AdaptiveInventory; createdAt: string };
        const rows = database.db.prepare("SELECT * FROM adaptive_security_recommendations WHERE snapshot_id=? ORDER BY rowid").all(snapshot.id) as Array<Record<string, unknown>>;
        const recommendations = rows.map((row) => ({ category: String(row.category), engineId: String(row.engine_id), laneKind: String(row.lane_kind), sourceFingerprint: String(row.source_fingerprint), mutationHypothesis: Boolean(row.mutation_hypothesis), operatorApprovalRequired: Boolean(row.operator_approval_required), requiredBindings: JSON.parse(String(row.required_bindings_json)), draft: JSON.parse(String(row.safe_draft_json)) })) as AdaptiveRecommendation[];
        return { targetId, scanId, snapshot, savedFixtures, output: projectAdaptiveSecurityCases(ng2Origin, snapshot.inventory, recommendations) };
      };
      const left = observe("2026-10-13T10:00:00.000Z");
      const right = observe("2026-10-14T12:00:00.000Z");
      expect(left.targetId).not.toBe(right.targetId); expect(left.scanId).not.toBe(right.scanId);
      expect(left.snapshot.id).not.toBe(right.snapshot.id); expect(left.snapshot.createdAt).not.toBe(right.snapshot.createdAt);
      expect(left.output.diagnostics).toEqual([]);
      expect(left.output).toEqual(right.output);
      expect(left.output.cases.map((value) => value.caseId)).toEqual(right.output.cases.map((value) => value.caseId));
      expect(left.output.cases.some((value) => value.actors === "ACCOUNT_PAIR_REQUIRED")).toBe(true);
      for (const id of [left.targetId, right.targetId, left.scanId, right.scanId, left.snapshot.id, right.snapshot.id, ...Object.values(left.savedFixtures), ...Object.values(right.savedFixtures)]) expect(JSON.stringify(left.output)).not.toContain(id);
    } finally { for (const database of databases) database.close(); vi.useRealTimers(); }
  });
});
