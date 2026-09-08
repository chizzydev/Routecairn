import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { AdaptiveSecurityService } from "../../src/dashboard/execution/AdaptiveSecurityService.js";
import type { BrowserAuthenticationReport, BrowserLearnedTestCase, RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { reportFixture } from "../helpers/assisted-review.js";
import { recordWorkflowCaseExecutions } from "../../src/dashboard/comparisons/WorkflowCaseExecutionRecorder.js";

describe("adaptive security model and recommendation loop", () => {
  it("captures canonical models, detects high-risk drift, and requires review before execution evidence can verify a proposal", () => {
    const database = new DashboardDatabase(":memory:"); database.migrate();
    const targetId = target(database);
    const firstScan = scan(database, targetId);
    const service = new AdaptiveSecurityService(database);
    const initial = service.observeCompletedScan(firstScan, report(false)) as any;
    expect(initial.inventory.routes.map((item: any) => item.pathTemplate)).toContain("/api/logout");
    expect(initial.state.recommendations.some((item: any) => item.category === "LIFECYCLE_LOGOUT_INVALIDATION")).toBe(true);
    expect(JSON.stringify(initial)).not.toContain("disposable@example.test");
    const initialRecommendationFingerprint = initial.state.recommendations.find((item: any) => item.category === "LIFECYCLE_LOGOUT_INVALIDATION").sourceFingerprint;
    service.acceptBaseline(initial.id, initial.modelDigest, "owner");

    const secondScan = scan(database, targetId);
    const changed = service.observeCompletedScan(secondScan, report(true)) as any;
    expect(changed.state.drifts).toEqual(expect.arrayContaining([
      expect.objectContaining({ drift_type: "FIELD_ACCESS_CHANGED", severity: "HIGH" }),
      expect.objectContaining({ drift_type: "COOKIE_SECURITY_CHANGED", severity: "HIGH" })
    ]));
    const recommendation = changed.state.recommendations.find((item: any) => item.category === "LIFECYCLE_LOGOUT_INVALIDATION");
    expect(recommendation.sourceFingerprint).toBe(initialRecommendationFingerprint);
    const exactCaseFingerprint = "d".repeat(64);
    expect(() => service.linkRecommendation(recommendation.id, secondScan, exactCaseFingerprint, "owner")).toThrow("APPROVAL_REQUIRED");
    service.decideRecommendation(recommendation.id, "APPROVED", "Exact logout lifecycle case is required for this route.", "owner");
    const executionScan = scan(database, targetId);
    database.db.prepare("UPDATE scans SET created_at=? WHERE id=?").run(new Date(Date.now() + 1_000).toISOString(), executionScan);
    database.db.prepare("INSERT INTO scan_module_executions (id,scan_id,module_id,module_label,planned_order,status) VALUES (?,?,?,?,1,'COMPLETED')").run(randomUUID(), executionScan, "authentication-lifecycle", "Authentication lifecycle");
    database.db.prepare("INSERT INTO scan_workflow_case_executions (id,scan_id,workflow_id,module_id,safe_case_alias,safe_case_fingerprint,execution_state,request_transmitted,matched_expectation,evidence_strength,safe_semantics_json,safe_result_json,created_at) VALUES (?,?,?,?,?,?,'COMPLETED',1,1,'ROLLBACK_VERIFIED','{}','{}',?)").run(randomUUID(), executionScan, "authentication-lifecycle", "authentication-lifecycle", "logout", exactCaseFingerprint, new Date().toISOString());
    const approvedState = service.state(targetId) as any;
    expect(approvedState.recommendations.find((item: any) => item.id === recommendation.id).executionCandidates).toEqual([expect.objectContaining({ scanId: executionScan, caseFingerprint: exactCaseFingerprint })]);
    const verified = service.linkRecommendation(recommendation.id, executionScan, exactCaseFingerprint, "owner") as any;
    expect(verified.recommendations.find((item: any) => item.id === recommendation.id)).toMatchObject({ status: "VERIFIED", executionOutcome: "VERIFIED", linkedScanId: executionScan, linkedCaseFingerprint: exactCaseFingerprint });
    database.close();
  });

  it("does not let an operator-only NOT_APPLICABLE statement satisfy required adaptive coverage", () => {
    const database = new DashboardDatabase(":memory:"); database.migrate();
    const targetId = target(database); const evidenceScan = scan(database, targetId); const now = new Date().toISOString();
    const planId = randomUUID(); const runId = randomUUID();
    database.db.prepare(`INSERT INTO live_acceptance_plans (id,name,target_id,environment,status,plan_digest,target_row_version,scope_digest,authorization_mode,authorization_expires_at,lane_count,algorithm,key_version,nonce,ciphertext,auth_tag,created_by,created_at,updated_at,row_version) VALUES (?,?,?,'STAGING','REVIEWED',?,1,?,'INTERNAL_STAGING',?,1,'aes','1','n','c','t','owner',?,?,1)`).run(planId, "Fixture plan", targetId, "a".repeat(64), "b".repeat(64), new Date(Date.now() + 60_000).toISOString(), now, now);
    database.db.prepare("INSERT INTO live_acceptance_runs (id,plan_id,plan_digest,status,requested_by,created_at,completed_at) VALUES (?,?,?,'COMPLETED','owner',?,?)").run(runId, planId, "a".repeat(64), now, now);
    const laneId = randomUUID(); database.db.prepare("INSERT INTO live_acceptance_run_lanes (id,run_id,lane_id,label,kind,required,disposition,configured_outcome,safe_reason,ordinal) VALUES (?,?,?,?,?,1,'NOT_APPLICABLE','NOT_APPLICABLE',?,1)").run(laneId, runId, "tenant", "Tenant model", "DATA_AUTHORIZATION", "No tenant model was declared by the operator.");
    const service = new AdaptiveSecurityService(database);
    const withoutEvidence = service.setPolicy({ targetId, requiredLanes: ["DATA_AUTHORIZATION"], requireEvidenceForNotApplicable: true, detectRemovedSurfaces: true, confirmation: "I_CONFIRM_TARGET_SECURITY_MODEL_POLICY" }, "owner") as any;
    expect(withoutEvidence.coverage).toMatchObject({ complete: false, gaps: 1, lanes: [{ state: "EVIDENCE_REQUIRED" }] });
    database.db.prepare("UPDATE live_acceptance_run_lanes SET evidence_scan_id=? WHERE id=?").run(evidenceScan, laneId);
    const withEvidence = service.state(targetId) as any;
    expect(withEvidence.coverage).toMatchObject({ complete: true, gaps: 0, lanes: [{ state: "NOT_APPLICABLE", evidenceScanId: evidenceScan }] });
    database.close();
  });

  it("persists the exact dedicated-engine contract fingerprint and keeps cleanup failure out of eligible evidence", () => {
    const database = new DashboardDatabase(":memory:"); database.migrate(); const targetId = target(database); const scanId = scan(database, targetId);
    const fingerprint = "e".repeat(64);
    recordWorkflowCaseExecutions(database.db, scanId, { authenticationLifecycle: { observations: [{ caseId: "logout", category: "LOGOUT_INVALIDATION", comparisonFingerprint: fingerprint, outcome: "PASS", cleanupOutcome: "ROLLBACK_VERIFIED", actorModel: [], steps: [] }] } } as any);
    const retained = database.db.prepare("SELECT workflow_id,module_id,safe_case_fingerprint,execution_state FROM scan_workflow_case_executions WHERE scan_id=?").get(scanId);
    expect(retained).toEqual({ workflow_id: "authentication-lifecycle", module_id: "authentication-lifecycle", safe_case_fingerprint: fingerprint, execution_state: "COMPLETED" });
    const failedScan = scan(database, targetId);
    recordWorkflowCaseExecutions(database.db, failedScan, { authenticationLifecycle: { observations: [{ caseId: "logout", category: "LOGOUT_INVALIDATION", comparisonFingerprint: fingerprint, outcome: "PASS", cleanupOutcome: "CLEANUP_FAILED", actorModel: [], steps: [] }] } } as any);
    expect(database.db.prepare("SELECT execution_state FROM scan_workflow_case_executions WHERE scan_id=?").get(failedScan)).toEqual({ execution_state: "FAILED" });
    database.close();
  });
});

function target(database: DashboardDatabase): string { return new TargetRepository(database).create({ displayName: "Adaptive fixture", baseOrigin: "https://app.test", tags: [], classification: "PRIVATE", authorizationType: "OWNED", authorizationSummary: "Owned disposable adaptive fixture", productionEnabled: false, approvedScope: { program: "fixture", allowedDomains: ["app.test"], disallowedPaths: [], allowedMethods: ["GET", "POST"], rateLimitPerSecond: 1, concurrency: 1, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" } }); }
function scan(database: DashboardDatabase, targetId: string): string { const id = randomUUID(); new ScanRepository(database).create({ id, source: "DASHBOARD", status: "COMPLETED", targetOrigin: "https://app.test", safeTargetLabel: "fixture", profile: "full", evidenceLevel: "strong", safeConfigurationSummary: {}, targetId }); return id; }
function report(changed: boolean): RouteCairnReport {
  const learned: BrowserLearnedTestCase = { id: changed ? "learned-logout-new-candidate" : "learned-logout", source: "browser-learned-traffic", method: "POST", endpoint: "https://app.test/api/logout", observedFieldNames: [], requestSecretBindings: {}, observedStatusCodes: [204], responseCookieNames: ["session"], authorizationContext: "BLOCKED_MUTATION_HYPOTHESIS", transmitted: false, suggestedLifecycleCategories: ["LOGOUT_INVALIDATION"], classification: "MUTATION_HYPOTHESIS", state: "DRAFT_REQUIRES_OPERATOR_CASE", executable: false, operatorApprovalRequired: true };
  const authentication = { mode: "learned-login-flow", bootstrapSucceeded: true, sessionIsolated: true, sessionSecretsPersisted: false, loginStepsExecuted: 1, loginWriteRequestsAllowed: 1, loginWriteRequestsBlocked: 1, browserRestartCount: 0, storage: [{ origin: "https://app.test", storage: "cookie", name: "session", valueLength: 64, valueDigest: "c".repeat(64), classification: "authentication", httpOnly: true, secure: !changed, sameSite: "Lax" }], fields: [{ pageUrl: "https://app.test/settings", name: "profile-name", controlType: "text", access: changed ? "writable" : "read-only" }], adminRoutes: changed ? ["https://app.test/admin"] : [], learnedTestCases: [learned], lifecycleLearningBundle: { schemaVersion: 1, artifactPath: "redacted-learning.json", candidateCount: 1, loginCandidateCount: 0, mutationHypothesisCount: 1, automaticallyCompilableCategories: [], secretsStored: false }, identityCorrelation: { principal: "MATCHED", tenant: "MATCHED", role: "MATCHED", rawIdentityStored: false }, protectedActionProof: "REQUIRES_APPROVED_OPERATOR_CASE", rollbackVerification: "REQUIRES_APPROVED_OPERATOR_CASE" } as BrowserAuthenticationReport;
  return { ...reportFixture(), apiMapper: { endpoints: [{ method: changed ? "POST" : "GET", endpoint: changed ? "https://app.test/api/admin" : "https://app.test/api/profile", source: "html" }], graphQlEndpoints: [], websocketEndpoints: [], rpcEndpoints: [], documentationUrls: [] }, browserCrawl: { startUrl: "https://app.test", renderedLinks: [], networkRequests: [], consoleErrors: [], formsDetected: 1, formsSubmitted: 0, authentication, notes: [] } } as RouteCairnReport;
}
