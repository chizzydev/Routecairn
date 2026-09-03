import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { assistedFindingModules } from "../../core/findings/AssistedWorkflowFindingAcceptance.js";

export type CoverageDisposition = "ADEQUATE" | "NOT_RETESTED" | "INCOMPARABLE";

export interface CoverageDecision {
  disposition: CoverageDisposition;
  reasonCode: string;
  explanation: string;
  facts: Record<string, unknown>;
}

interface ScanRow { id: string; source: string; status: string; target_origin: string; target_id: string | null; project_id: string | null; profile: string; evidence_level: string; safe_configuration_summary: string; import_limitation_summary: string | null; }
interface OccurrenceRow { id: string; finding_id: string; module: string; safe_endpoint: string; safe_actor_relationship: string | null; safe_tenant_or_role_boundary: string | null; safe_state_boundary: string | null; workflow_case_alias: string | null; coverage_reference_json: string; source_kind: string; }
interface ModuleRow { module_id: string; status: string; planned_request_count: number | null; executed_request_count: number; safe_failure_category: string | null; safe_failure_summary: string | null; }
interface CaseRow { id: string; workflow_id: string; module_id: string; safe_case_alias: string; safe_case_fingerprint: string; execution_state: string; request_transmitted: number; evidence_strength: string; safe_semantics_json: string; safe_result_json: string; }

const workflowByModule: Record<string, string> = {
  "object-pair-testing": "object-pair", "field-exposure-testing": "field-exposure",
  "authorization-matrix-testing": "authorization-matrix", "equivalent-route-testing": "equivalent-route",
  "collection-authorization-testing": "collection-authorization", "bulk-authorization-testing": "bulk-authorization",
  "file-authorization-testing": "file-authorization",
  "privilege-mutation-testing": "privilege-mutation"
};

export class ScanComparisonCoverageService {
  public constructor(private readonly database: DashboardDatabase) {}

  public scan(id: string): ScanRow {
    const row = this.database.db.prepare(`SELECT id, source, status, target_origin, target_id, project_id, profile,
      evidence_level, safe_configuration_summary, import_limitation_summary FROM scans WHERE id = ? AND deleted_at IS NULL`).get(id) as ScanRow | undefined;
    if (!row) throw new Error(`Scan ${id} was not found.`);
    return row;
  }

  public sourceQuality(scanId: string): "NATIVE_FULL" | "NATIVE_PARTIAL" | "IMPORTED_WITH_COVERAGE" | "IMPORTED_FINDINGS_ONLY" {
    const scan = this.scan(scanId);
    const snapshot = Boolean(this.database.db.prepare("SELECT 1 FROM scan_plan_snapshots WHERE scan_id = ?").get(scanId));
    const modules = Boolean(this.database.db.prepare("SELECT 1 FROM scan_module_executions WHERE scan_id = ? LIMIT 1").get(scanId));
    if (scan.source === "DASHBOARD") return scan.status === "COMPLETED" && snapshot && modules ? "NATIVE_FULL" : "NATIVE_PARTIAL";
    return snapshot && modules ? "IMPORTED_WITH_COVERAGE" : "IMPORTED_FINDINGS_ONLY";
  }

  public compareAuthentication(olderScanId: string, newerScanId: string): "EQUIVALENT" | "CHANGED" | "INCOMPARABLE" {
    const older = this.snapshotObject(olderScanId, "authentication_summary_json");
    const newer = this.snapshotObject(newerScanId, "authentication_summary_json");
    if (!older || !newer) return "INCOMPARABLE";
    return stable(authSemantics(older)) === stable(authSemantics(newer)) ? "EQUIVALENT" : "CHANGED";
  }

  public compareIdentity(olderScanId: string, newerScanId: string): "EQUIVALENT" | "CHANGED" | "INCOMPARABLE" {
    const older = this.snapshotObject(olderScanId, "authentication_summary_json");
    const newer = this.snapshotObject(newerScanId, "authentication_summary_json");
    if (!older || !newer) return "INCOMPARABLE";
    return stable(identitySemantics(older)) === stable(identitySemantics(newer)) ? "EQUIVALENT" : "CHANGED";
  }

  public scopeState(olderScanId: string, newerScanId: string): "EXPANDED" | "REDUCED" | "EQUIVALENT_FOR_FINDING" | "MATERIALLY_CHANGED" | "INCOMPARABLE" {
    const older = this.scope(olderScanId); const newer = this.scope(newerScanId);
    if (!older || !newer) return "INCOMPARABLE";
    if (stable(older) === stable(newer)) return "EQUIVALENT_FOR_FINDING";
    const oldDomains = strings(older.allowedDomains); const newDomains = strings(newer.allowedDomains);
    const oldDenied = strings(older.disallowedPaths); const newDenied = strings(newer.disallowedPaths);
    if (oldDomains.every((v) => domainCovered(v, newer)) && oldDenied.every((v) => newDenied.includes(v))) return "EXPANDED";
    if (newDomains.every((v) => domainCovered(v, older)) || newDenied.some((v) => !oldDenied.includes(v))) return "REDUCED";
    return "MATERIALLY_CHANGED";
  }

  public evaluateFinding(olderScanId: string, newerScanId: string, occurrence: OccurrenceRow): CoverageDecision {
    const older = this.scan(olderScanId); const newer = this.scan(newerScanId);
    if (!sameTarget(older, newer)) return decision("INCOMPARABLE", "TARGET_INCOMPATIBLE", "The scans represent different durable targets or origins; remediation cannot be inferred across them.", { olderTarget: older.target_origin, newerTarget: newer.target_origin });
    if (!["COMPLETED", "IMPORTED"].includes(newer.status)) return decision("NOT_RETESTED", newer.status === "CANCELLED" ? "SCAN_CANCELLED" : "SCAN_INCOMPLETE", "The newer scan did not complete, so absence cannot establish resolution.", { newerStatus: newer.status });
    if (this.sourceQuality(newerScanId) === "IMPORTED_FINDINGS_ONLY") return decision("NOT_RETESTED", "HISTORICAL_DATA_INSUFFICIENT", "The newer imported report contains findings but no execution coverage capable of proving resolution.", { sourceQuality: "IMPORTED_FINDINGS_ONLY" });
    const assisted = assistedFindingModules.has(occurrence.module) && !workflowByModule[occurrence.module];
    const scope = assisted && occurrence.safe_endpoint.startsWith("redacted:") && this.scopeState(olderScanId, newerScanId) === "EQUIVALENT_FOR_FINDING"
      ? { covered: true, incomparable: false, reasonCode: "SCOPE_EQUIVALENT", explanation: "Identical scope snapshots cover the explicitly configured case.", facts: {} }
      : this.endpointCoverage(newerScanId, occurrence.safe_endpoint);
    if (!scope.covered) return decision(scope.incomparable ? "INCOMPARABLE" : "NOT_RETESTED", scope.reasonCode, scope.explanation, scope.facts);
    const module = this.module(newerScanId, occurrence.module);
    if (!module) return decision("NOT_RETESTED", "MODULE_NOT_PLANNED", "The newer scan did not plan the module that produced the older finding.", { module: occurrence.module });
    if (module.status !== "COMPLETED") {
      const code = module.status === "CANCELLED" ? "SCAN_CANCELLED" : /budget/i.test(`${module.safe_failure_category ?? ""} ${module.safe_failure_summary ?? ""}`) ? "BUDGET_EXHAUSTED" : "MODULE_NOT_COMPLETED";
      return decision("NOT_RETESTED", code, `The relevant module did not complete (${module.status}).`, { module: occurrence.module, moduleStatus: module.status });
    }
    const workflow = workflowByModule[occurrence.module];
    if (assisted) return this.evaluateAssistedCase(olderScanId, newerScanId, occurrence);
    if (!workflow) return decision("ADEQUATE", "COMPATIBLE_MODULE_COVERAGE", "The newer scan covered the same target and endpoint and completed the relevant module.", { module: occurrence.module, moduleStatus: module.status });
    if (this.compareAuthentication(olderScanId, newerScanId) === "CHANGED") return decision("INCOMPARABLE", "ACTOR_MODEL_INCOMPATIBLE", "The safe authentication actor model changed for an authorization-sensitive finding.", { workflow });
    if (this.compareIdentity(olderScanId, newerScanId) === "CHANGED") return decision("INCOMPARABLE", "IDENTITY_MODEL_INCOMPATIBLE", "The verified identity model changed for an authorization-sensitive finding.", { workflow });
    const alias = occurrence.workflow_case_alias;
    if (!alias) return decision("NOT_RETESTED", "CASE_IDENTITY_UNAVAILABLE", "The older occurrence lacks a safe workflow-case identity, so module completion alone cannot prove that its security boundary was retested.", { workflow });
    const oldCase = this.caseByAlias(olderScanId, workflow, alias);
    const newCase = this.caseByAlias(newerScanId, workflow, alias);
    if (!newCase) return decision("NOT_RETESTED", "CASE_MISSING", `The newer scan did not execute the relevant ${workflow} case.`, { workflow, safeCaseAlias: alias });
    if (!oldCase) return decision("INCOMPARABLE", "HISTORICAL_DATA_INSUFFICIENT", "The older scan lacks persisted case semantics needed to prove compatible workflow coverage.", { workflow, safeCaseAlias: alias });
    if (oldCase.safe_case_fingerprint !== newCase.safe_case_fingerprint) return decision("INCOMPARABLE", workflowReason(workflow), workflowExplanation(workflow), { workflow, safeCaseAlias: alias, olderEvidenceStrength: oldCase.evidence_strength, newerEvidenceStrength: newCase.evidence_strength });
    if (newCase.execution_state === "BUDGET_EXHAUSTED") return decision("NOT_RETESTED", "BUDGET_EXHAUSTED", "The matching workflow case exhausted its request or evidence budget before adequate execution.", { workflow, safeCaseAlias: alias });
    if (newCase.execution_state === "BLOCKED") return decision("NOT_RETESTED", "CASE_BLOCKED", "The matching workflow case was blocked before adequate execution.", { workflow, safeCaseAlias: alias });
    if (newCase.execution_state !== "COMPLETED" || !newCase.request_transmitted) return decision("NOT_RETESTED", "CASE_NOT_EXECUTED", "The matching workflow case did not transmit and complete the relevant request.", { workflow, safeCaseAlias: alias, caseState: newCase.execution_state });
    if (workflow === "privilege-mutation") {
      const result = parseJson(newCase.safe_result_json);
      if (!["ROLLBACK_VERIFIED", "NOT_REQUIRED"].includes(String(result.cleanupOutcome))) return decision("NOT_RETESTED", "CLEANUP_NOT_VERIFIED", "The matching mutation case did not independently verify restoration, so the newer scan cannot prove resolution.", { workflow, safeCaseAlias: alias, cleanupOutcome: result.cleanupOutcome });
      if (!["SECURE_FOR_CASE", "MUTATION_REJECTED"].includes(String(result.securityOutcome))) return decision("NOT_RETESTED", "SECURITY_PROOF_INCOMPLETE", "The matching mutation case did not prove rejection of the configured authority change.", { workflow, safeCaseAlias: alias, securityOutcome: result.securityOutcome });
    }
    return decision("ADEQUATE", "COMPATIBLE_CASE_COVERAGE", `The newer scan covered the same target, endpoint, module, ${workflow} case, actor semantics, and evidence model; the matching request completed.`, { workflow, safeCaseAlias: alias, evidenceStrength: newCase.evidence_strength });
  }

  public modules(scanId: string): ModuleRow[] { return this.database.db.prepare("SELECT module_id, status, planned_request_count, executed_request_count, safe_failure_category, safe_failure_summary FROM scan_module_executions WHERE scan_id = ? ORDER BY planned_order").all(scanId) as ModuleRow[]; }

  private evaluateAssistedCase(olderScanId: string, newerScanId: string, occurrence: OccurrenceRow): CoverageDecision {
    const facts = { workflow: occurrence.module, safeCaseAlias: occurrence.workflow_case_alias };
    if (this.compareAuthentication(olderScanId, newerScanId) !== "EQUIVALENT" || this.compareIdentity(olderScanId, newerScanId) !== "EQUIVALENT") return decision("INCOMPARABLE", "ACTOR_MODEL_INCOMPATIBLE", "Comparable authenticated actor and identity snapshots are required.", facts);
    if (!occurrence.workflow_case_alias) return decision("NOT_RETESTED", "CASE_IDENTITY_UNAVAILABLE", "The older finding lacks an explicit case identity.", facts);
    const query = this.database.db.prepare("SELECT assessment_outcome, conclusion, cleanup_unresolved, comparison_fingerprint FROM assisted_case_results WHERE scan_id = ? AND workflow_id = ? AND case_id = ?");
    type Case = { assessment_outcome: string; conclusion: string; cleanup_unresolved: number; comparison_fingerprint: string | null };
    const before = query.get(olderScanId, occurrence.module, occurrence.workflow_case_alias) as Case | undefined;
    const after = query.get(newerScanId, occurrence.module, occurrence.workflow_case_alias) as Case | undefined;
    if (!after) return decision("NOT_RETESTED", "CASE_MISSING", "The newer scan did not execute this assisted workflow case.", facts);
    if (!before?.comparison_fingerprint || !after.comparison_fingerprint || before.comparison_fingerprint !== after.comparison_fingerprint) return decision("INCOMPARABLE", "CASE_CHANGED", "The exact case contracts and comparison fingerprints must match.", facts);
    if (after.cleanup_unresolved) return decision("NOT_RETESTED", "CLEANUP_NOT_VERIFIED", "Unresolved cleanup independently prevents remediation acceptance.", facts);
    if (after.assessment_outcome !== "PROVEN" || after.conclusion !== "NO_FINDING") return decision("NOT_RETESTED", "SECURITY_PROOF_INCOMPLETE", "Only a proven clean execution of the same case establishes remediation.", { ...facts, outcome: after.assessment_outcome, conclusion: after.conclusion });
    return decision("ADEQUATE", "COMPATIBLE_CASE_COVERAGE", "The same assisted case completed with matching contracts, actors, and a proven clean conclusion.", facts);
  }
  public cases(scanId: string): CaseRow[] { return this.database.db.prepare("SELECT id, workflow_id, module_id, safe_case_alias, safe_case_fingerprint, execution_state, request_transmitted, evidence_strength, safe_semantics_json, safe_result_json FROM scan_workflow_case_executions WHERE scan_id = ? ORDER BY workflow_id, safe_case_alias").all(scanId) as CaseRow[]; }

  private module(scanId: string, moduleId: string): ModuleRow | undefined { return this.database.db.prepare("SELECT module_id, status, planned_request_count, executed_request_count, safe_failure_category, safe_failure_summary FROM scan_module_executions WHERE scan_id = ? AND module_id = ? ORDER BY planned_order LIMIT 1").get(scanId, moduleId) as ModuleRow | undefined; }
  private caseByAlias(scanId: string, workflow: string, alias: string): CaseRow | undefined { return this.database.db.prepare("SELECT id, workflow_id, module_id, safe_case_alias, safe_case_fingerprint, execution_state, request_transmitted, evidence_strength, safe_semantics_json, safe_result_json FROM scan_workflow_case_executions WHERE scan_id = ? AND workflow_id = ? AND safe_case_alias = ? LIMIT 1").get(scanId, workflow, alias) as CaseRow | undefined; }
  private snapshotObject(scanId: string, column: string): Record<string, unknown> | undefined { const row = this.database.db.prepare(`SELECT ${column} AS value FROM scan_plan_snapshots WHERE scan_id = ?`).get(scanId) as { value: string } | undefined; return row ? object(row.value) : undefined; }
  private scope(scanId: string): Record<string, unknown> | undefined { const scan = this.scan(scanId); const summary = object(scan.safe_configuration_summary); const studio = record(summary?.studio); return record(studio?.scope) ?? this.snapshotObject(scanId, "scope_summary_json"); }
  private endpointCoverage(scanId: string, endpoint: string): { covered: boolean; incomparable: boolean; reasonCode: string; explanation: string; facts: Record<string, unknown> } {
    const scope = this.scope(scanId); if (!scope) return { covered: false, incomparable: true, reasonCode: "HISTORICAL_DATA_INSUFFICIENT", explanation: "The newer scan lacks a scope snapshot capable of proving endpoint coverage.", facts: {} };
    let url: URL; try { url = new URL(endpoint); } catch { return { covered: false, incomparable: true, reasonCode: "SCOPE_INCOMPARABLE", explanation: "The older occurrence endpoint cannot be safely interpreted for semantic scope comparison.", facts: {} }; }
    if (!domainCovered(url.hostname, scope)) return { covered: false, incomparable: false, reasonCode: "SCOPE_NOT_COVERED", explanation: "The newer scope does not cover the older finding host.", facts: { host: url.hostname } };
    const denied = strings(scope.disallowedPaths).find((path) => pathMatches(url.pathname, path));
    if (denied) return { covered: false, incomparable: false, reasonCode: "SCOPE_NOT_COVERED", explanation: "A newer denied-path rule excludes the older finding endpoint.", facts: { endpointPath: url.pathname, deniedPath: denied } };
    return { covered: true, incomparable: false, reasonCode: "SCOPE_COVERED", explanation: "The newer semantic scope covers the older finding endpoint.", facts: { endpointPath: url.pathname } };
  }
}

function decision(disposition: CoverageDisposition, reasonCode: string, explanation: string, facts: Record<string, unknown>): CoverageDecision { return { disposition, reasonCode, explanation, facts }; }
function sameTarget(a: ScanRow, b: ScanRow): boolean { return a.target_id && b.target_id ? a.target_id === b.target_id : normalizedOrigin(a.target_origin) === normalizedOrigin(b.target_origin); }
function normalizedOrigin(value: string): string { try { return new URL(value).origin.toLowerCase(); } catch { return value.toLowerCase(); } }
function domainCovered(host: string, scope: Record<string, unknown>): boolean { const domains = strings(scope.allowedDomains); const include = scope.includeSubdomains === true; return domains.some((domain) => host.toLowerCase() === domain.toLowerCase() || (include && host.toLowerCase().endsWith(`.${domain.toLowerCase()}`))); }
function pathMatches(path: string, rule: string): boolean { const prefix = rule.endsWith("*") ? rule.slice(0, -1) : rule; return path === prefix || path.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`); }
function strings(value: unknown): string[] { return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : []; }
function object(value: string): Record<string, unknown> | undefined { try { return record(JSON.parse(value)); } catch { return undefined; } }
function record(value: unknown): Record<string, unknown> | undefined { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function parseJson(value: string): Record<string, unknown> { try { const parsed = JSON.parse(value) as unknown; return record(parsed) ?? {}; } catch { return {}; } }
function authSemantics(value: Record<string, unknown>): unknown { return { mode: value.mode ?? "public", actors: [value.primary, value.accountA, value.accountB].filter(Boolean).map((v) => { const actor = record(v); return { identityVerification: actor?.identityVerification ?? "disabled", sourceKind: actor?.source ? "configured" : undefined }; }) }; }
function identitySemantics(value: Record<string, unknown>): unknown { return [value.primary, value.accountA, value.accountB].filter(Boolean).map((v) => { const actor = record(v); return { identityVerification: actor?.identityVerification ?? "disabled" }; }); }
function stable(value: unknown): string { return JSON.stringify(sort(value)); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (!value || typeof value !== "object") return value; return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, sort(v)])); }
function workflowReason(workflow: string): string { return workflow === "collection-authorization" ? "COLLECTION_COMPLETENESS_WEAKER" : workflow === "file-authorization" ? "FILE_PROOF_WEAKER" : workflow === "bulk-authorization" ? "EVIDENCE_MODEL_INCOMPATIBLE" : "CASE_CHANGED"; }
function workflowExplanation(workflow: string): string { if (workflow === "collection-authorization") return "Collection completeness or reference semantics changed; weaker collection evidence cannot prove absence."; if (workflow === "file-authorization") return "File identity, content-proof, stream, or signed-follow semantics changed; weaker file evidence cannot prove remediation."; if (workflow === "bulk-authorization") return "Bulk safety, baseline, or postcondition semantics changed and cannot prove the same non-mutating contract."; return `The matching ${workflow} case changed materially and cannot safely substitute for the older security boundary.`; }
