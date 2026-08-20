import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { PlanRepository, ScanRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { FindingNormalizer } from "../../src/dashboard/findings/FindingNormalizer.js";
import { FindingFingerprintService } from "../../src/dashboard/findings/FindingFingerprintService.js";
import { ComparisonService } from "../../src/dashboard/services/ComparisonService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { ScanExecutionService } from "../../src/dashboard/execution/ScanExecutionService.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { randomUUID } from "node:crypto";

describe("scan comparison and regression intelligence", () => {
  it("classifies durable findings using fingerprints and actual completed-module coverage", () => withDatabase(({ database, normalizer }) => {
    const previous = id(1), oldScan = id(2), newScan = id(3);
    seedScan(database, previous, "quick", "2026-01-01T00:00:00.000Z", ["baseline"]);
    seedScan(database, oldScan, "quick", "2026-01-02T00:00:00.000Z", ["baseline"]);
    seedScan(database, newScan, "full", "2026-01-03T00:00:00.000Z", ["baseline"]);
    normalizer.normalizeReport(previous, report([finding("Regression", "Low")]));
    normalizer.normalizeReport(oldScan, report([finding("Persisting", "Medium"), finding("Resolved", "High"), finding("Changed", "Low")]));
    normalizer.normalizeReport(newScan, report([finding("Persisting", "Medium"), finding("Changed", "High"), finding("New", "Low"), finding("Regression", "Low")]));
    database.db.prepare("UPDATE finding_occurrences SET created_at = '2026-01-01T00:00:00.000Z' WHERE scan_id = ?").run(previous);
    const result = new ComparisonService(database).compare(oldScan, newScan);
    expect(result.summary).toEqual({ new: 2, regressions: 0, recurrences: 1, persisting: 1, changed: 1, resolved: 1, notRetested: 0, incomparable: 0, severityIncreases: 1 });
    expect(result.findings.changed[0]).toMatchObject({ classification: "CHANGED", materialChanges: [expect.objectContaining({ field: "severity", older: "Low", newer: "High", direction: "WORSENED" })] });
    expect(result.findings.new.find((item) => item.finding.title === "Regression")?.regressionFlags).toEqual(["RECURRENCE"]);
    expect(result.coverage).toMatchObject({ sameTarget: true, sharedModules: ["baseline"], oldProfile: "quick", newProfile: "full" });
    expect(result.warnings.join(" ")).toContain("Profiles differ");
  }));

  it("never claims resolution when the newer scan omitted the finding module", () => withDatabase(({ database, normalizer }) => {
    const oldScan = id(4), newScan = id(5);
    seedScan(database, oldScan, "full", "2026-02-01T00:00:00.000Z", ["header-review"]);
    seedScan(database, newScan, "quick", "2026-02-02T00:00:00.000Z", ["baseline"]);
    normalizer.normalizeReport(oldScan, report([finding("Header finding", "Medium", "header-review")]));
    normalizer.normalizeReport(newScan, report([]));
    const result = new ComparisonService(database).compare(oldScan, newScan);
    expect(result.findings.resolved).toHaveLength(0);
    expect(result.findings.notRetested).toEqual([expect.objectContaining({ reasonCode: "MODULE_NOT_PLANNED" })]);
    expect(result.coverage.omittedModules).toEqual(["header-review"]);
  }));

  it("requires matching executed case semantics across all seven authorization workflows", () => withDatabase(({ database, normalizer }) => {
    const oldScan = id(20), newScan = id(21);
    const workflows = [
      ["object-pair", "object-pair-testing", "case-a", "Object pair case-a A_TO_B;"],
      ["field-exposure", "field-exposure-testing", "case-b", "Field exposure case-b;"],
      ["authorization-matrix", "authorization-matrix-testing", "matrix/case-c", "Authorization matrix matrix/case-c;"],
      ["equivalent-route", "equivalent-route-testing", "routes/case-d", "Equivalent route routes/case-d;"],
      ["collection-authorization", "collection-authorization-testing", "collection/case-e", "Collection authorization collection/case-e;"],
      ["bulk-authorization", "bulk-authorization-testing", "bulk/case-f", "Bulk authorization bulk/case-f;"],
      ["file-authorization", "file-authorization-testing", "files/case-g", "File authorization files/case-g;"]
    ] as const;
    seedScan(database, oldScan, "authenticated", "2026-03-01T00:00:00.000Z", workflows.map((value) => value[1]));
    seedScan(database, newScan, "authenticated", "2026-03-02T00:00:00.000Z", workflows.map((value) => value[1]));
    normalizer.normalizeReport(oldScan, report(workflows.map(([, module, alias, source]) => caseFinding(alias, module, source))));
    normalizer.normalizeReport(newScan, report([]));
    for (const [workflow, module, alias] of workflows) { seedCase(database, oldScan, workflow, module, alias, `${workflow}-stable`); seedCase(database, newScan, workflow, module, alias, `${workflow}-stable`); }
    const result = new ComparisonService(database).compare(oldScan, newScan);
    expect(result.summary.resolved).toBe(7);
    expect(result.coverage.workflows.filter((value) => value.comparable)).toHaveLength(7);
    expect(result.coverage.cases.every((value) => value.state === "CASE_MATCHED_EXECUTED")).toBe(true);
  }));

  it("prevents false resolution for missing and incompatible workflow evidence", () => withDatabase(({ database, normalizer }) => {
    const oldScan = id(30), newScan = id(31);
    seedScan(database, oldScan, "authenticated", "2026-04-01T00:00:00.000Z", ["file-authorization-testing", "collection-authorization-testing"]);
    seedScan(database, newScan, "authenticated", "2026-04-02T00:00:00.000Z", ["file-authorization-testing", "collection-authorization-testing"]);
    normalizer.normalizeReport(oldScan, report([caseFinding("files/download", "file-authorization-testing", "File authorization files/download;"), caseFinding("lists/private", "collection-authorization-testing", "Collection authorization lists/private;")]));
    normalizer.normalizeReport(newScan, report([]));
    seedCase(database, oldScan, "file-authorization", "file-authorization-testing", "files/download", "full-stream");
    seedCase(database, oldScan, "collection-authorization", "collection-authorization-testing", "lists/private", "complete");
    seedCase(database, newScan, "collection-authorization", "collection-authorization-testing", "lists/private", "unknown-completeness");
    const result = new ComparisonService(database).compare(oldScan, newScan);
    expect(result.findings.notRetested).toEqual([expect.objectContaining({ reasonCode: "CASE_MISSING" })]);
    expect(result.findings.incomparable).toEqual([expect.objectContaining({ reasonCode: "COLLECTION_COMPLETENESS_WEAKER" })]);
    expect(result.findings.resolved).toHaveLength(0);
  }));

  it("distinguishes recurrence from a verified regression and persists deterministic results", () => withDatabase(({ database, normalizer }) => {
    const first = id(40), baseline = id(41), current = id(42);
    seedScan(database, first, "full", "2026-05-01T00:00:00.000Z", ["baseline"]); seedScan(database, baseline, "full", "2026-05-02T00:00:00.000Z", ["baseline"]); seedScan(database, current, "full", "2026-05-03T00:00:00.000Z", ["baseline"]);
    normalizer.normalizeReport(first, report([finding("Returned issue", "High")])); normalizer.normalizeReport(baseline, report([]));
    const findingId = (database.db.prepare("SELECT id FROM findings WHERE canonical_title='Returned issue'").get() as { id: string }).id;
    database.db.prepare("INSERT INTO finding_remediation_history (id,finding_id,previous_state,new_state,safe_note,owner_override,source,created_at) VALUES (?,?, 'FIXED_PENDING_RETEST','FIXED_VERIFIED','Compatible retest verified.',0,'HUMAN','2026-05-02T12:00:00.000Z')").run(randomUUID(), findingId);
    normalizer.normalizeReport(current, report([finding("Returned issue", "High")]));
    database.db.prepare("UPDATE finding_occurrences SET created_at='2026-05-01T00:00:00.000Z' WHERE scan_id=?").run(first);
    database.db.prepare("UPDATE finding_occurrences SET created_at='2026-05-03T00:00:00.000Z' WHERE scan_id=?").run(current);
    const service = new ComparisonService(database), one = service.compare(baseline, current), two = service.compare(baseline, current);
    expect(one.comparisonId).toBe(two.comparisonId);
    expect(one.findings.regressions).toEqual([expect.objectContaining({ regressionFlags: ["REGRESSION"] })]);
    expect((database.db.prepare("SELECT COUNT(*) count FROM scan_comparison_findings WHERE comparison_id=?").get(one.comparisonId) as { count: number }).count).toBe(1);
  }));

  it("pages and filters comparison findings in SQL with stable, bounded sorting", () => withDatabase(({ database, normalizer }) => {
    const oldScan = id(50), newScan = id(51);
    seedScan(database, oldScan, "full", "2026-06-01T00:00:00.000Z", ["baseline"]);
    seedScan(database, newScan, "full", "2026-06-02T00:00:00.000Z", ["baseline"]);
    normalizer.normalizeReport(oldScan, report([finding("Alpha", "Low"), finding("Bravo", "High"), finding("Resolved page", "Medium")]));
    normalizer.normalizeReport(newScan, report([finding("Alpha", "Low"), finding("Bravo", "High"), finding("New page", "High")]));
    const service = new ComparisonService(database), comparison = service.compare(oldScan, newScan);
    const first = service.get(comparison.comparisonId, { page: 1, pageSize: 2, sort: "severity", direction: "desc" });
    const second = service.get(comparison.comparisonId, { page: 2, pageSize: 2, sort: "severity", direction: "desc" });
    expect(first.findingPage).toEqual({ page: 1, pageSize: 2, total: 4, totalPages: 2 });
    expect(new Set([...first.items, ...second.items].map((item) => item.id)).size).toBe(4);
    const resolved = service.get(comparison.comparisonId, { classification: "RESOLVED", pageSize: 999 });
    expect(resolved.findingPage).toMatchObject({ pageSize: 100, total: 1 });
    expect(resolved.items[0]).toMatchObject({ classification: "RESOLVED", finding: { title: "Resolved page" } });
    expect(() => service.get(comparison.comparisonId, { sort: "created_at; DROP TABLE findings" })).toThrow(/Unsupported comparison finding sort field/);
  }));

  it("writes one dedicated audit event for an automatic comparison and none for reuse", () => withDatabase(({ database, normalizer, paths }) => {
    const oldScan = id(60), newScan = id(61);
    seedScan(database, oldScan, "full", "2026-07-01T00:00:00.000Z", ["baseline"]);
    seedScan(database, newScan, "full", "2026-07-02T00:00:00.000Z", ["baseline"]);
    normalizer.normalizeReport(oldScan, report([finding("Automatic audit", "Medium")]));
    normalizer.normalizeReport(newScan, report([finding("Automatic audit", "Medium")]));
    const execution = new ScanExecutionService(database, paths);
    (execution as unknown as { createAutomaticComparison(scanId: string): void }).createAutomaticComparison(newScan);
    (execution as unknown as { createAutomaticComparison(scanId: string): void }).createAutomaticComparison(newScan);
    const events = database.db.prepare("SELECT action, resource_type, resource_id, safe_metadata_json FROM audit_events WHERE action = 'comparison.automatic_created'").all() as Array<Record<string, string>>;
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ action: "comparison.automatic_created", resource_type: "SCAN_COMPARISON" });
    expect(JSON.parse(events[0]!.safe_metadata_json)).toMatchObject({ olderScanId: oldScan, newerScanId: newScan });
  }));
});

function withDatabase(run: (value: { database: DashboardDatabase; normalizer: FindingNormalizer; paths: ReturnType<typeof resolveDashboardPaths> }) => void): void {
  const dir = mkdtempSync(resolve(tmpdir(), "routecairn-comparison-"));
  const paths = resolveDashboardPaths(dir);
  const database = new DashboardDatabase(paths.databasePath);
  try { database.migrate(); run({ database, paths, normalizer: new FindingNormalizer(database.db, new FindingFingerprintService(paths.fingerprintKeyPath)) }); }
  finally { database.close(); rmSync(dir, { recursive: true, force: true }); }
}

function seedScan(database: DashboardDatabase, scanId: string, profile: string, createdAt: string, modules: string[]): void {
  new ScanRepository(database).create({ id: scanId, source: "DASHBOARD", status: "COMPLETED", targetOrigin: "https://app.test", safeTargetLabel: "app", profile, evidenceLevel: "normal", safeConfigurationSummary: {} });
  new PlanRepository(database).create(scanId, { plannerVersion: "1", profile, modules: modules.map((moduleId) => ({ id: moduleId })), limits: { maxRequests: 100 }, evidencePolicy: { level: "normal" }, browserPolicySummary: {}, scopeSummary: { allowedDomains: ["app.test"], disallowedPaths: [], includeSubdomains: false }, authenticationSummary: { mode: "public" }, controlledWorkflowSummary: {}, redactedPlan: { profile, modules } });
  database.db.prepare("UPDATE scans SET created_at = ?, completed_at = ? WHERE id = ?").run(createdAt, createdAt, scanId);
  for (const [index, moduleId] of modules.entries()) database.db.prepare("INSERT INTO scan_module_executions (id, scan_id, module_id, module_label, planned_order, status) VALUES (?, ?, ?, ?, ?, 'COMPLETED')").run(randomUUID(), scanId, moduleId, moduleId, index + 1);
}

function report(findings: RouteCairnReport["findings"]): RouteCairnReport {
  return { routeCairnVersion: "0.1.0", target: "https://app.test", mode: "full", program: "fixture", scope: { allowedDomains: ["app.test"], disallowedPaths: [], allowedMethods: ["GET"], rateLimitPerSecond: 1, concurrency: 1, sameOriginOnly: true, includeSubdomains: false }, metadata: { startedAt: new Date(0).toISOString(), completedAt: new Date(1).toISOString(), durationMs: 1, totalRequests: 1, failedRequests: 0 }, scopeDecisions: [], requestAudit: [], responses: [], technologies: [], discoveredUrls: [], findings };
}

function finding(title: string, severity: "Low" | "Medium" | "High", sourceModule = "baseline"): RouteCairnReport["findings"][number] {
  return { id: title, title, type: "Fixture", severity, confidence: "High", url: `https://app.test/${title.toLowerCase().replaceAll(" ", "-")}`, method: "GET", sourceModule, evidence: { url: "https://app.test/safe", method: "GET", source: "fixture", title } };
}

function caseFinding(alias: string, module: string, source: string): RouteCairnReport["findings"][number] { const value = finding(`Case ${alias}`, "High", module); return { ...value, evidence: { ...value.evidence, source } }; }

function seedCase(database: DashboardDatabase, scanId: string, workflow: string, module: string, alias: string, fingerprint: string): void {
  database.db.prepare(`INSERT INTO scan_workflow_case_executions (id,scan_id,workflow_id,module_id,safe_case_alias,safe_case_fingerprint,execution_state,request_transmitted,matched_expectation,evidence_strength,safe_semantics_json,safe_result_json,created_at) VALUES (?,?,?,?,?,?,'COMPLETED',1,1,'PROOF','{}','{}','2026-01-01T00:00:00.000Z')`).run(randomUUID(), scanId, workflow, module, alias, fingerprint);
}

function id(value: number): string { return `00000000-0000-4000-8000-${String(value).padStart(12, "0")}`; }
