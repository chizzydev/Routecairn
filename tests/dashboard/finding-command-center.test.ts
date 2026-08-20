import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { DashboardDatabase, nowIso } from "../../src/dashboard/db/DashboardDatabase.js";
import { FindingFingerprintService } from "../../src/dashboard/findings/FindingFingerprintService.js";
import { FindingNormalizer } from "../../src/dashboard/findings/FindingNormalizer.js";
import { FindingCommandCenterService, FindingCommandError } from "../../src/dashboard/findings/FindingCommandCenterService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import type { DashboardPrincipal } from "../../src/dashboard/auth/Permissions.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { RetestTemplateVault } from "../../src/dashboard/retests/RetestTemplateVault.js";
import { ProjectRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";

describe("finding command center domain", () => {
  it("keeps stable identity and immutable occurrences while title and secrets change", () => {
    withDatabase(({ database, normalizer, service }) => {
      seedScan(database, scanId(1), "COMPLETED");
      seedScan(database, scanId(2), "COMPLETED");
      normalizer.normalizeReport(scanId(1), report({ title: "Original analyst title", secret: "token-one" }));
      normalizer.normalizeReport(scanId(2), report({ title: "Edited scanner title", secret: "token-two" }));
      expect(service.list().total).toBe(1);
      const finding = service.list().findings[0]!;
      const detail = service.detail(finding.id) as { occurrences: Array<{ title: string; severity: string }> };
      expect(detail.occurrences).toHaveLength(2);
      expect(detail.occurrences.map((item) => item.title)).toEqual(["Edited scanner title", "Original analyst title"]);
      service.review({ findingId: finding.id, newStatus: "IN_REVIEW", expectedVersion: finding.rowVersion, principal: owner });
      expect((service.detail(finding.id) as { occurrences: Array<{ severity: string }> }).occurrences.map((item) => item.severity)).toEqual(["High", "High"]);
      expect(JSON.stringify(service.detail(finding.id))).not.toContain("token-one");
      expect(JSON.stringify(service.detail(finding.id))).not.toContain("token-two");
    });
  });

  it("enforces review transitions, reasons, append-only history, duplicates, and stale versions", () => {
    withDatabase(({ database, normalizer, service }) => {
      seedScan(database, scanId(1), "COMPLETED");
      normalizer.normalizeReport(scanId(1), report({ boundary: "role:user" }));
      normalizer.normalizeReport(scanId(1), report({ boundary: "role:admin" }));
      const findings = service.list({ sort: "last_seen_desc" }).findings;
      const first = findings[0]!;
      const canonical = findings[1]!;
      expect(() => service.review({ findingId: first.id, newStatus: "FALSE_POSITIVE", expectedVersion: first.rowVersion, principal: analyst })).toThrow(/reason/i);
      const inReview = service.review({ findingId: first.id, newStatus: "IN_REVIEW", expectedVersion: first.rowVersion, principal: analyst });
      expect(() => service.review({ findingId: first.id, newStatus: "CONFIRMED", expectedVersion: first.rowVersion, principal: analyst })).toThrow(FindingCommandError);
      const confirmed = service.review({ findingId: first.id, newStatus: "CONFIRMED", expectedVersion: inReview.rowVersion, principal: analyst });
      const duplicate = service.review({ findingId: first.id, newStatus: "DUPLICATE", duplicateTargetFindingId: canonical.id, expectedVersion: confirmed.rowVersion, principal: analyst });
      expect(duplicate.reviewStatus).toBe("DUPLICATE");
      const detail = service.detail(first.id) as { reviews: unknown[] };
      expect(detail.reviews).toHaveLength(3);
      expect(() => service.review({ findingId: canonical.id, newStatus: "DUPLICATE", duplicateTargetFindingId: canonical.id, expectedVersion: canonical.rowVersion, principal: analyst })).toThrow(/itself/i);
    });
  });

  it("separates remediation, requires compatible retest verification, and reopens recurrence", () => {
    withDatabase(({ database, normalizer, service }) => {
      seedUser(database, analyst.userId, "analyst@example.test", "ANALYST");
      seedUser(database, owner.userId, "owner@example.test", "OWNER");
      seedScan(database, scanId(1), "COMPLETED");
      normalizer.normalizeReport(scanId(1), report({}));
      let finding = service.list().findings[0]!;
      finding = service.review({ findingId: finding.id, newStatus: "CONFIRMED", expectedVersion: finding.rowVersion, principal: analyst });
      finding = service.remediation({ findingId: finding.id, newState: "ASSIGNED", assigneeUserId: analyst.userId, expectedVersion: finding.rowVersion, principal: analyst });
      finding = service.remediation({ findingId: finding.id, newState: "FIX_IN_PROGRESS", expectedVersion: finding.rowVersion, principal: analyst });
      finding = service.remediation({ findingId: finding.id, newState: "FIXED_PENDING_RETEST", expectedVersion: finding.rowVersion, principal: analyst });
      expect(() => service.verifyFixed({ findingId: finding.id, reason: "Developer says fixed", ownerOverride: false, expectedVersion: finding.rowVersion, principal: analyst })).toThrow(/compatible passing retest/i);

      seedScan(database, scanId(2), "COMPLETED");
      const retest = service.linkRetest({ findingId: finding.id, scanId: scanId(2), expectedVersion: finding.rowVersion, principal: analyst });
      expect(retest).toMatchObject({ compatible: true, state: "RETEST_PASSED" });
      finding = service.verifyFixed({ findingId: finding.id, reason: "Compatible bounded retest passed.", ownerOverride: false, expectedVersion: retest.finding.rowVersion, principal: analyst });
      expect(finding).toMatchObject({ reviewStatus: "RESOLVED", remediationStatus: "FIXED_VERIFIED" });

      seedScan(database, scanId(3), "COMPLETED");
      normalizer.normalizeReport(scanId(3), report({}));
      const reopened = service.list().findings[0]!;
      expect(reopened).toMatchObject({ reviewStatus: "REOPENED", remediationStatus: "OPEN", newOccurrenceKind: "RECURRENCE_REOPENED" });
      const detail = service.detail(reopened.id) as { reviews: Array<{ new_review_status: string }>; remediationHistory: unknown[] };
      expect(detail.reviews.map((item) => item.new_review_status)).toEqual(expect.arrayContaining(["CONFIRMED", "RESOLVED", "REOPENED"]));
      expect(detail.remediationHistory.length).toBeGreaterThanOrEqual(4);
    });
  });

  it("marks incompatible retests inconclusive and preserves false-positive and accepted-risk recurrence semantics", () => {
    withDatabase(({ database, normalizer, service }) => {
      for (const id of [1, 2, 3, 4]) seedScan(database, scanId(id), "COMPLETED", id === 2 ? "https://other.test" : "https://app.test");
      normalizer.normalizeReport(scanId(1), report({ boundary: "role:user" }));
      normalizer.normalizeReport(scanId(1), report({ boundary: "role:admin" }));
      const [first, second] = service.list().findings;
      const fp = service.review({ findingId: first!.id, newStatus: "FALSE_POSITIVE", reason: "Fixture mismatch", expectedVersion: first!.rowVersion, principal: analyst });
      const review = service.review({ findingId: second!.id, newStatus: "IN_REVIEW", expectedVersion: second!.rowVersion, principal: analyst });
      service.review({ findingId: second!.id, newStatus: "ACCEPTED_RISK", reason: "Documented temporary acceptance", expectedVersion: review.rowVersion, principal: analyst });
      const incompatible = service.linkRetest({ findingId: first!.id, scanId: scanId(2), expectedVersion: fp.rowVersion, principal: analyst });
      expect(incompatible).toMatchObject({ compatible: false, state: "RETEST_INCONCLUSIVE" });
      normalizer.normalizeReport(scanId(3), report({ boundary: boundaryFor(database, first!.id) }));
      normalizer.normalizeReport(scanId(4), report({ boundary: boundaryFor(database, second!.id) }));
      const states = service.list({ pageSize: 10 }).findings;
      expect(states.find((item) => item.id === first!.id)).toMatchObject({ reviewStatus: "FALSE_POSITIVE", newOccurrenceKind: "AFTER_FALSE_POSITIVE" });
      expect(states.find((item) => item.id === second!.id)).toMatchObject({ reviewStatus: "ACCEPTED_RISK", newOccurrenceKind: "ACCEPTED_RISK_RECURRENCE" });
    });
  });

  it("supports composed paging, saved views, bounded bulk review, notes, and proof readiness safely", () => {
    withDatabase(({ database, normalizer, service }) => {
      seedUser(database, analyst.userId, "analyst@example.test", "ANALYST");
      seedScan(database, scanId(1), "COMPLETED");
      normalizer.normalizeReport(scanId(1), report({ boundary: "role:user", severity: "Critical" }));
      normalizer.normalizeReport(scanId(1), report({ boundary: "role:admin", severity: "Low" }));
      const page = service.list({ severity: "High", reviewStatus: "UNREVIEWED", page: 1, pageSize: 1, sort: "severity_desc" });
      expect(page).toMatchObject({ total: 1, pageSize: 1 });
      const finding = page.findings[0]!;
      const bulk = service.bulkReview({ findingIds: [finding.id], newStatus: "CONFIRMED", versions: { [finding.id]: finding.rowVersion }, principal: analyst });
      expect(bulk.failed).toEqual([]);
      expect(service.refreshProofReadiness(finding.id)).toBe("READY");
      const reviewed = service.list({ search: finding.id }).findings[0]!;
      const remediation = service.bulkRemediation({ findingIds: [finding.id], newState: "ASSIGNED", assigneeUserId: analyst.userId, versions: { [finding.id]: reviewed.rowVersion }, principal: analyst });
      expect(remediation.failed).toEqual([]);
      expect(service.bulkNote({ findingIds: [finding.id], text: "Shared bounded triage note.", principal: analyst }).failed).toEqual([]);
      const noteId = service.addNote({ findingId: finding.id, text: "Validated against the controlled local fixture.", principal: analyst });
      expect(noteId).toMatch(/[0-9a-f-]{36}/);
      expect(() => service.addNote({ findingId: finding.id, text: "Authorization: Bearer super-secret-token", principal: analyst })).toThrow(/secret material/i);
      expect(() => service.saveView({ name: "Invalid columns", query: {}, columns: ["title", "not-a-column"], isDefault: false, shared: false, principal: analyst })).toThrow(/unsupported finding column/i);
      const viewId = service.saveView({ name: "Critical confirmed", query: { severity: "Critical", reviewStatus: "CONFIRMED" }, columns: ["severity", "title"], isDefault: true, shared: false, principal: analyst });
      expect(service.savedViews(analyst)).toEqual(expect.arrayContaining([expect.objectContaining({ id: viewId, safe_name: "Critical confirmed" })]));
      service.deleteView(viewId, analyst);
      expect(service.savedViews(analyst)).toEqual([]);
    });
  });

  it("requires explicit cooperative takeover and preserves both analysts in history", () => {
    withDatabase(({ database, normalizer, service }) => {
      seedUser(database, analyst.userId, analyst.login, "ANALYST");
      seedUser(database, secondAnalyst.userId, secondAnalyst.login, "ANALYST");
      seedScan(database, scanId(1), "COMPLETED");
      normalizer.normalizeReport(scanId(1), report({}));
      const finding = service.list().findings[0]!;
      const claimed = service.review({ findingId: finding.id, newStatus: "IN_REVIEW", expectedVersion: finding.rowVersion, principal: analyst });
      expect(claimed).toMatchObject({ reviewerUserId: analyst.userId, reviewerLabel: analyst.login });
      expect(() => service.review({ findingId: finding.id, newStatus: "CONFIRMED", expectedVersion: claimed.rowVersion, principal: secondAnalyst })).toThrow(/confirm takeover/i);
      const taken = service.review({ findingId: finding.id, newStatus: "IN_REVIEW", takeover: true, expectedVersion: claimed.rowVersion, principal: secondAnalyst });
      expect(taken).toMatchObject({ reviewerUserId: secondAnalyst.userId, reviewerLabel: secondAnalyst.login });
      const detail = service.detail(finding.id) as { reviews: Array<{ actor_label: string; safe_metadata_json: string }> };
      expect(detail.reviews.map((item) => item.actor_label)).toEqual([analyst.login, secondAnalyst.login]);
      expect(detail.reviews[1]!.safe_metadata_json).toContain('"takeover":true');
      expect(() => service.review({ findingId: finding.id, newStatus: "CONFIRMED", takeover: true, expectedVersion: claimed.rowVersion, principal: analyst })).toThrow(/changed after it was loaded/i);
    });
  });

  it("creates a secret-free retest draft and records fixed launch intent", () => {
    withDatabase(({ database, normalizer, service }) => {
      seedUser(database, analyst.userId, analyst.login, "ANALYST");
      seedScan(database, scanId(1), "COMPLETED");
      database.db.prepare("UPDATE scans SET safe_configuration_summary = ? WHERE id = ?").run(JSON.stringify({ target: "https://app.test", profile: "authenticated", auth: true, studio: { evidenceLevel: "strong", scope: { allowedDomains: ["app.test"], allowedMethods: ["GET"], rateLimitPerSecond: 1, concurrency: 1, sameOriginOnly: true, includeSubdomains: false, disallowedPaths: [] }, authentication: { mode: "primary", primary: { source: "ephemeral", safeAlias: "Account A", headerNames: ["Authorization"] } } } }), scanId(1));
      normalizer.normalizeReport(scanId(1), report({ secret: "historical-token-value" }));
      const finding = service.list().findings[0]!;
      const templates = new RetestTemplateVault(database.db, { bytes: Buffer.alloc(32, 4), version: "test" });
      templates.save(scanId(1), [{ workflowId: "authorization-matrix", enabled: true, editorMode: "guided", disabledCaseIds: [], config: JSON.parse(readFileSync(resolve("examples", "authorization-matrix.example.json"), "utf8")) }]);
      const templateAwareService = new FindingCommandCenterService(database, templates);
      const draft = templateAwareService.retestDraft(finding.id) as { context: Parameters<FindingCommandCenterService["validateRetestContext"]>[0]; freshCredentialsRequired: boolean; reusableWorkflows: unknown[]; workflowTemplateStatus: string };
      expect(draft.freshCredentialsRequired).toBe(true);
      expect(draft.workflowTemplateStatus).toBe("RESTORED");
      expect(draft.reusableWorkflows).toEqual([expect.objectContaining({ workflowId: "authorization-matrix" })]);
      expect(JSON.stringify(draft)).not.toContain("historical-token-value");
      seedScan(database, scanId(2), "COMPLETED");
      templateAwareService.validateRetestContext(draft.context);
      templateAwareService.recordRetestLaunch({ context: draft.context, newScanId: scanId(2), principal: analyst });
      expect(database.db.prepare("SELECT finding_id, source_scan_id, new_scan_id FROM finding_retest_launches").get()).toEqual({ finding_id: finding.id, source_scan_id: scanId(1), new_scan_id: scanId(2) });
    });
  });

  it("omits a historical saved target that does not match the retained scan origin", () => {
    withDatabase(({ database, normalizer, service }) => {
      const projectId = new ProjectRepository(database).create({ name: "Fixture project", tags: [], defaultScope: {} });
      const targetId = new TargetRepository(database).create({
        projectId,
        displayName: "Different saved target",
        baseOrigin: "https://different.test",
        tags: [],
        classification: "LOCAL",
        authorizationType: "CONTROLLED_LAB",
        authorizationSummary: "Controlled mismatch fixture.",
        approvedScope: {}
      });
      seedScan(database, scanId(1), "COMPLETED", "https://app.test");
      database.db.prepare("UPDATE scans SET project_id = ?, target_id = ? WHERE id = ?").run(projectId, targetId, scanId(1));
      normalizer.normalizeReport(scanId(1), report({}));
      const finding = service.list().findings[0]!;
      const draft = service.retestDraft(finding.id) as { projectId?: string; targetId?: string; target: string; warning: string };
      expect(draft).toMatchObject({ projectId, target: "https://app.test" });
      expect(draft.targetId).toBeUndefined();
      expect(draft.warning).toMatch(/saved-target reference.*not restored/i);
    });
  });
});

const analyst: DashboardPrincipal = { mode: "server", userId: "11111111-1111-4111-8111-111111111111", login: "analyst@example.test", role: "ANALYST", csrfToken: "test" };
const owner: DashboardPrincipal = { mode: "server", userId: "22222222-2222-4222-8222-222222222222", login: "owner@example.test", role: "OWNER", csrfToken: "test" };
const secondAnalyst: DashboardPrincipal = { mode: "server", userId: "33333333-3333-4333-8333-333333333333", login: "analyst-two@example.test", role: "ANALYST", csrfToken: "test" };

function withDatabase(run: (context: { database: DashboardDatabase; normalizer: FindingNormalizer; service: FindingCommandCenterService }) => void): void {
  const dir = mkdtempSync(resolve(tmpdir(), "routecairn-finding-command-"));
  const paths = resolveDashboardPaths(dir);
  const database = new DashboardDatabase(paths.databasePath);
  try {
    database.migrate();
    run({ database, normalizer: new FindingNormalizer(database.db, new FindingFingerprintService(paths.fingerprintKeyPath)), service: new FindingCommandCenterService(database) });
  } finally {
    database.close();
    rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 30 });
  }
}

function seedUser(database: DashboardDatabase, id: string, login: string, role: "OWNER" | "ANALYST"): void {
  database.db.prepare(`INSERT INTO dashboard_users
    (id, login, normalized_login, password_hash, role, enabled, created_at, updated_at, password_changed_at)
    VALUES (?, ?, ?, 'fixture-hash', ?, 1, ?, ?, ?)`
  ).run(id, login, login, role, nowIso(), nowIso(), nowIso());
}

function seedScan(database: DashboardDatabase, id: string, status: "COMPLETED", target = "https://app.test"): void {
  database.db.prepare(`INSERT INTO scans
    (id, source, status, target_origin, safe_target_label, profile, evidence_level,
     created_at, completed_at, safe_configuration_summary)
    VALUES (?, 'DASHBOARD', ?, ?, ?, 'authenticated', 'normal', ?, ?, '{}')`
  ).run(id, status, target, target, nowIso(), nowIso());
  database.db.prepare(`INSERT INTO scan_module_executions
    (id, scan_id, module_id, module_label, planned_order, status)
    VALUES (?, ?, 'authorization-matrix-testing', 'Authorization Matrix', 1, 'COMPLETED')`
  ).run(randomChildId(id), id);
  database.db.prepare(`INSERT INTO scan_plan_snapshots (id,scan_id,planner_version,profile,modules_json,limits_json,evidence_policy_json,browser_policy_summary_json,scope_summary_json,authentication_summary_json,controlled_workflow_summary_json,redacted_plan_json,created_at) VALUES (?,?, '1','authenticated','[{"id":"authorization-matrix-testing"}]','{}','{}','{}','{"allowedDomains":["app.test"],"disallowedPaths":[],"includeSubdomains":false}','{"mode":"public"}','{"authorizationMatrixTesting":true}','{}',?)`).run(randomUUID(), id, nowIso());
  database.db.prepare(`INSERT INTO scan_workflow_case_executions (id,scan_id,workflow_id,module_id,safe_case_alias,safe_case_fingerprint,execution_state,request_transmitted,matched_expectation,evidence_strength,safe_semantics_json,safe_result_json,created_at) VALUES (?,?,'authorization-matrix','authorization-matrix-testing','fixture/case','fixture-case','COMPLETED',1,1,'MATRIX_ROW','{}','{}',?)`).run(randomUUID(), id, nowIso());
}

function report(input: { title?: string; secret?: string; boundary?: string; severity?: string }): RouteCairnReport {
  const boundary = input.boundary ?? "role:user";
  const secret = input.secret ?? "fixture-secret";
  return {
    routeCairnVersion: "0.1.0", target: "https://app.test", mode: "authenticated", program: "fixture",
    scope: { allowedDomains: ["app.test"], disallowedPaths: [], allowedMethods: ["GET"], rateLimitPerSecond: 1, concurrency: 1, sameOriginOnly: true, includeSubdomains: false },
    metadata: { startedAt: new Date(0).toISOString(), completedAt: new Date(1).toISOString(), durationMs: 1, totalRequests: 1, failedRequests: 0 },
    scopeDecisions: [], requestAudit: [], responses: [], technologies: [], discoveredUrls: [],
    findings: [{ id: "fixture", title: input.title ?? "Cross-role record access", type: "Authorization", severity: (input.severity ?? "High") as "High", confidence: "High", url: `https://app.test/api/orders/123?token=${secret}`, method: "GET", sourceModule: "authorization-matrix-testing", tags: ["authorization", boundary], evidence: { url: "https://app.test/api/orders/:id?token=<redacted>", method: "GET", source: "Authorization matrix fixture/case;", title: "Controlled observation", bodyHash: "safe-hash", reproductionNotes: "Repeat the exact safe GET." } }]
  };
}

function scanId(number: number): string { return `00000000-0000-4000-8000-${String(number).padStart(12, "0")}`; }
function randomChildId(id: string): string { return `${id.slice(0, 24)}${String(Number(id.slice(24)) + 100).padStart(12, "0")}`; }
function boundaryFor(database: DashboardDatabase, findingId: string): string { return (database.db.prepare("SELECT safe_authorization_boundary_identity AS boundary FROM findings WHERE id = ?").get(findingId) as { boundary: string }).boundary.split("|").find((item) => item.startsWith("role:")) ?? "role:user"; }
