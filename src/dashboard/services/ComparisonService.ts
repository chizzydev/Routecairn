// @ts-nocheck Legacy schema-v2 implementation retained temporarily for migration traceability.
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { FindingRepository } from "../db/DashboardRepositories.js";
import type { ComparisonResult, DashboardFindingSummary } from "../types/DashboardTypes.js";

export { ScanComparisonService as ComparisonService } from "../comparisons/ScanComparisonService.js";

class LegacyComparisonService {
  private readonly findings: FindingRepository;

  public constructor(private readonly database: DashboardDatabase) {
    this.findings = new FindingRepository(database);
  }

  public compare(oldScanId: string, newScanId: string): ComparisonResult {
    if (oldScanId === newScanId) throw new Error("Choose two different scans to compare.");
    const oldScan = this.scan(oldScanId);
    const newScan = this.scan(newScanId);
    const warnings: string[] = [];
    const sameTarget = oldScan.target_origin === newScan.target_origin;
    if (!sameTarget) warnings.push("Targets differ; no absent finding can be classified as resolved.");
    if (oldScan.profile !== newScan.profile) warnings.push("Profiles differ; resolution is evaluated per completed module rather than by profile name.");
    if (oldScan.status !== "COMPLETED" && oldScan.status !== "IMPORTED") warnings.push("The older scan is not complete or imported.");
    if (newScan.status !== "COMPLETED" && newScan.status !== "IMPORTED") warnings.push("The newer scan is not complete or imported; absent findings are not considered resolved.");

    const oldModules = this.completedModules(oldScanId);
    const newModules = this.completedModules(newScanId);
    const sharedModules = [...oldModules].filter((id) => newModules.has(id)).sort();
    const omittedModules = [...oldModules].filter((id) => !newModules.has(id)).sort();
    const addedModules = [...newModules].filter((id) => !oldModules.has(id)).sort();
    if (omittedModules.length > 0) warnings.push(`Newer scan did not complete ${omittedModules.length} previously covered module(s).`);

    const oldOccurrences = this.occurrences(oldScanId);
    const newOccurrences = this.occurrences(newScanId);
    const oldByFingerprint = new Map(oldOccurrences.map((item) => [item.fingerprint, item]));
    const newByFingerprint = new Map(newOccurrences.map((item) => [item.fingerprint, item]));
    const added: DashboardFindingSummary[] = [];
    const regressions: DashboardFindingSummary[] = [];
    const persisting: DashboardFindingSummary[] = [];
    const changed: ComparisonResult["findings"]["changed"] = [];
    const resolved: DashboardFindingSummary[] = [];
    const notRetested: ComparisonResult["findings"]["notRetested"] = [];

    for (const current of newOccurrences) {
      const previous = oldByFingerprint.get(current.fingerprint);
      const finding = this.requiredFinding(current.finding_id);
      if (!previous) {
        if (this.existedBefore(current.finding_id, oldScan.created_at)) regressions.push(finding);
        else added.push(finding);
      } else if (previous.severity !== current.severity || previous.confidence !== current.confidence) {
        changed.push({
          finding,
          previousSeverity: previous.severity,
          currentSeverity: current.severity,
          previousConfidence: previous.confidence,
          currentConfidence: current.confidence,
          direction: severityRank(current.severity) > severityRank(previous.severity) ? "WORSENED" : severityRank(current.severity) < severityRank(previous.severity) ? "IMPROVED" : "CONFIDENCE_CHANGED"
        });
      } else persisting.push(finding);
    }

    const newerComplete = newScan.status === "COMPLETED" || newScan.status === "IMPORTED";
    for (const previous of oldOccurrences) {
      if (newByFingerprint.has(previous.fingerprint)) continue;
      const finding = this.requiredFinding(previous.finding_id);
      if (sameTarget && newerComplete && newModules.has(previous.module)) resolved.push(finding);
      else notRetested.push({ finding, reason: !sameTarget ? "TARGET_MISMATCH" : !newerComplete ? "NEW_SCAN_INCOMPLETE" : "MODULE_NOT_COMPLETED" });
    }

    const oldScope = this.snapshotValue(oldScanId, "scope_summary_json");
    const newScope = this.snapshotValue(newScanId, "scope_summary_json");
    const oldAuthentication = this.snapshotValue(oldScanId, "authentication_summary_json");
    const newAuthentication = this.snapshotValue(newScanId, "authentication_summary_json");
    const scopeEquivalent = oldScope !== undefined && newScope !== undefined && oldScope === newScope;
    const authenticationEquivalent = oldAuthentication !== undefined && newAuthentication !== undefined && oldAuthentication === newAuthentication;
    if (!scopeEquivalent) warnings.push("Resolved scope summaries differ; module-level coverage is shown but operator review is required.");
    if (!authenticationEquivalent) warnings.push("Authentication summaries differ; authorization regressions require operator review.");
    return {
      schemaVersion: 2,
      oldScanId,
      newScanId,
      compatible: sameTarget && newerComplete && sharedModules.length > 0,
      warnings,
      coverage: {
        sameTarget,
        scopeEquivalent,
        authenticationEquivalent,
        oldProfile: oldScan.profile,
        newProfile: newScan.profile,
        oldCompletedModules: [...oldModules].sort(),
        newCompletedModules: [...newModules].sort(),
        sharedModules,
        omittedModules,
        addedModules
      },
      summary: { new: added.length, regressions: regressions.length, persisting: persisting.length, changed: changed.length, resolved: resolved.length, notRetested: notRetested.length },
      findings: { new: added, regressions, persisting, changed, resolved, notRetested }
    };
  }

  private scan(id: string): ScanRow {
    const row = this.database.db.prepare("SELECT id, status, target_origin, profile, created_at FROM scans WHERE id = ? AND deleted_at IS NULL").get(id) as ScanRow | undefined;
    if (!row) throw new Error(`Scan ${id} was not found.`);
    return row;
  }

  private completedModules(scanId: string): Set<string> {
    const rows = this.database.db.prepare("SELECT module_id FROM scan_module_executions WHERE scan_id = ? AND status = 'COMPLETED'").all(scanId) as Array<{ module_id: string }>;
    if (rows.length > 0) return new Set(rows.map((row) => row.module_id));
    return new Set(this.occurrences(scanId).map((row) => row.module));
  }

  private occurrences(scanId: string): OccurrenceRow[] {
    return this.database.db.prepare(
      `SELECT o.finding_id, o.module, o.severity, o.confidence, f.fingerprint
       FROM finding_occurrences o JOIN findings f ON f.id = o.finding_id
       WHERE o.scan_id = ? ORDER BY f.fingerprint ASC`
    ).all(scanId) as OccurrenceRow[];
  }

  private requiredFinding(id: string): DashboardFindingSummary {
    const finding = this.findings.get(id);
    if (!finding) throw new Error(`Comparison finding ${id} is unavailable.`);
    return finding;
  }

  private existedBefore(findingId: string, oldScanCreatedAt: string): boolean {
    return Boolean(this.database.db.prepare("SELECT 1 FROM finding_occurrences WHERE finding_id = ? AND created_at < ? LIMIT 1").get(findingId, oldScanCreatedAt));
  }

  private snapshotValue(scanId: string, column: "scope_summary_json" | "authentication_summary_json"): string | undefined {
    const row = this.database.db.prepare(`SELECT ${column} AS value FROM scan_plan_snapshots WHERE scan_id = ?`).get(scanId) as { value: string } | undefined;
    return row?.value ? stableJson(row.value) : undefined;
  }
}

function stableJson(value: string): string {
  try { return JSON.stringify(sortObject(JSON.parse(value))); } catch { return value; }
}

function sortObject(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => [key, sortObject(child)]));
}

function severityRank(value: string): number {
  return ({ Info: 0, Low: 1, Medium: 2, High: 3, Critical: 4 } as Record<string, number>)[value] ?? 0;
}

interface ScanRow { id: string; status: string; target_origin: string; profile: string; created_at: string; }
interface OccurrenceRow { finding_id: string; fingerprint: string; module: string; severity: string; confidence: string; }
