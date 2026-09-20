import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { LiveAcceptanceLane } from "../contracts/LiveAcceptanceSchemas.js";

export type LiveAcceptanceFeature =
  | "MULTI_TENANT_AUTHORIZATION"
  | "SUPABASE_TABLE_RLS"
  | "SUPABASE_STORAGE"
  | "SUPABASE_RPC"
  | "OAUTH_OIDC"
  | "MFA"
  | "PASSKEY"
  | "GRAPHQL_AUTHORIZATION"
  | "SIGNED_LINK"
  | "SIGNED_PORTAL"
  | "PROTECTED_EXPORT"
  | "SYNTHETIC_PAYMENT"
  | "WEBHOOK"
  | "CRON"
  | "REMEDIATION_COMPARISON";

export interface LiveAcceptanceProofContract {
  requiredModules: string[];
  requiredWorkflows: string[];
  requiredFeatures: LiveAcceptanceFeature[];
  minimumCompletedCases: number;
  minimumTransmittedCases: number;
  requireStrongEvidence: boolean;
  requireProviderAdapter: boolean;
  requireResolvedCleanup: boolean;
  requireComparableRemediation: boolean;
  requireNoUnretestedCases: boolean;
}

export interface LiveAcceptanceProofResult {
  verified: boolean;
  missing: string[];
  completedModules: string[];
  completedWorkflows: string[];
  features: LiveAcceptanceFeature[];
  completedCases: number;
  transmittedCases: number;
  providerAdapterBound: boolean;
  evidenceLevel?: string;
  comparison?: {
    id: string;
    state: string;
    compatibility: string;
    baselineScanId: string;
    rerunScanId: string;
    matchedCases: number;
    unresolvedCases: number;
    unresolvedFindings: number;
  };
}

const standardContracts: Partial<Record<LiveAcceptanceLane["kind"], Partial<LiveAcceptanceProofContract>>> = {
  MULTI_TENANT_APPLICATION: {
    requiredFeatures: ["MULTI_TENANT_AUTHORIZATION"],
    minimumCompletedCases: 1,
    minimumTransmittedCases: 1
  },
  SUPABASE_RLS_STORAGE_RPC: {
    requiredModules: ["supabase-authorization"],
    requiredWorkflows: ["supabase-authorization"],
    requiredFeatures: ["SUPABASE_TABLE_RLS", "SUPABASE_STORAGE", "SUPABASE_RPC"],
    minimumCompletedCases: 3,
    minimumTransmittedCases: 3
  },
  OAUTH_MFA_PASSKEYS: {
    requiredModules: ["authentication-lifecycle"],
    requiredWorkflows: ["authentication-lifecycle"],
    requiredFeatures: ["OAUTH_OIDC", "MFA", "PASSKEY"],
    minimumCompletedCases: 3,
    minimumTransmittedCases: 3
  },
  GRAPHQL_AUTHORIZATION: {
    requiredModules: ["api-graphql-authorization"],
    requiredWorkflows: ["api-graphql-authorization"],
    requiredFeatures: ["GRAPHQL_AUTHORIZATION"],
    minimumCompletedCases: 1,
    minimumTransmittedCases: 1
  },
  SIGNED_PORTALS_EXPORTS: {
    requiredModules: ["link-portal-export-security"],
    requiredWorkflows: ["link-portal-export-security"],
    requiredFeatures: ["SIGNED_LINK", "SIGNED_PORTAL", "PROTECTED_EXPORT"],
    minimumCompletedCases: 3,
    minimumTransmittedCases: 3
  },
  SYNTHETIC_PAYMENT_PROVIDER: {
    requiredModules: ["billing-entitlement-security"],
    requiredWorkflows: ["billing-entitlement-security"],
    requiredFeatures: ["SYNTHETIC_PAYMENT"],
    minimumCompletedCases: 1,
    minimumTransmittedCases: 1,
    requireProviderAdapter: true
  },
  WEBHOOKS_CRON: {
    requiredModules: ["operational-endpoint-security"],
    requiredWorkflows: ["operational-endpoint-security"],
    requiredFeatures: ["WEBHOOK", "CRON"],
    minimumCompletedCases: 2,
    minimumTransmittedCases: 2
  },
  REMEDIATION_RERUNS: {
    requiredFeatures: ["REMEDIATION_COMPARISON"],
    requireComparableRemediation: true,
    requireNoUnretestedCases: true
  }
};

export function effectiveLiveAcceptanceProof(lane: LiveAcceptanceLane, broaderStandard: boolean): LiveAcceptanceProofContract {
  const supplied = lane.proof;
  const required = broaderStandard ? standardContracts[lane.kind] ?? {} : {};
  return {
    requiredModules: unique([...(required.requiredModules ?? []), ...supplied.requiredModules]),
    requiredWorkflows: unique([...(required.requiredWorkflows ?? []), ...supplied.requiredWorkflows]),
    requiredFeatures: unique([...(required.requiredFeatures ?? []), ...supplied.requiredFeatures]) as LiveAcceptanceFeature[],
    minimumCompletedCases: Math.max(required.minimumCompletedCases ?? 0, supplied.minimumCompletedCases),
    minimumTransmittedCases: Math.max(required.minimumTransmittedCases ?? 0, supplied.minimumTransmittedCases),
    requireStrongEvidence: required.requireStrongEvidence === true || supplied.requireStrongEvidence,
    requireProviderAdapter: required.requireProviderAdapter === true || supplied.requireProviderAdapter,
    requireResolvedCleanup: required.requireResolvedCleanup === true || supplied.requireResolvedCleanup,
    requireComparableRemediation: required.requireComparableRemediation === true || supplied.requireComparableRemediation,
    requireNoUnretestedCases: required.requireNoUnretestedCases === true || supplied.requireNoUnretestedCases
  };
}

export function evaluateLiveAcceptanceProof(
  database: DashboardDatabase,
  scanId: string | undefined,
  contract: LiveAcceptanceProofContract,
  remediation?: { baselineScanId: string; rerunScanId: string; comparisonId: string }
): LiveAcceptanceProofResult {
  const missing: string[] = [];
  const scan = scanId ? database.db.prepare("SELECT evidence_level FROM scans WHERE id=? AND deleted_at IS NULL").get(scanId) as { evidence_level: string } | undefined : undefined;
  const modules = scanId ? database.db.prepare("SELECT module_id,status FROM scan_module_executions WHERE scan_id=?").all(scanId) as Array<{ module_id: string; status: string }> : [];
  const cases = scanId ? database.db.prepare("SELECT workflow_id,execution_state,request_transmitted,safe_case_fingerprint,evidence_strength,safe_semantics_json FROM scan_workflow_case_executions WHERE scan_id=?").all(scanId) as CaseRow[] : [];
  const completedModules = unique(modules.filter((item) => item.status === "COMPLETED").map((item) => item.module_id)).sort();
  const rawCompletedCases = cases.filter((item) => item.execution_state === "COMPLETED");
  const allCompletedCases = rawCompletedCases.filter(isDurableCase);
  const completedCases = contract.requiredWorkflows.length ? allCompletedCases.filter((item) => contract.requiredWorkflows.includes(item.workflow_id)) : allCompletedCases;
  const transmittedCases = completedCases.filter((item) => Boolean(item.request_transmitted));
  const completedWorkflows = unique(allCompletedCases.map((item) => item.workflow_id)).sort();
  const features = unique(allCompletedCases.flatMap(featuresForCase)) as LiveAcceptanceFeature[];
  const adapterBindings = scanId ? database.db.prepare(`SELECT p.engine_id
    FROM scan_provider_adapter_bindings b
    JOIN provider_adapters p ON p.id=b.profile_id
    JOIN provider_adapter_versions v ON v.id=b.version_id AND v.profile_id=p.id
    JOIN scans s ON s.id=b.scan_id
    WHERE b.scan_id=? AND p.target_id=s.target_id AND p.deleted_at IS NULL
      AND b.adapter_digest=v.adapter_digest AND v.status IN ('REVIEWED','SUPERSEDED')`).all(scanId) as Array<{ engine_id: string }> : [];
  const providerAdapterBound = adapterBindings.some((binding) => contract.requiredModules.length === 0 || contract.requiredModules.includes(binding.engine_id));

  if (!scan) missing.push("A same-target scan is not linked to this lane.");
  for (const moduleId of contract.requiredModules) if (!completedModules.includes(moduleId)) missing.push(`Required module ${moduleId} did not complete.`);
  for (const workflowId of contract.requiredWorkflows) if (!completedWorkflows.includes(workflowId)) missing.push(`Required workflow ${workflowId} has no completed case.`);
  for (const workflowId of contract.requiredWorkflows) {
    if (rawCompletedCases.some((item) => item.workflow_id === workflowId && !isDurableCase(item))) missing.push(`Required workflow ${workflowId} has completed records without a durable case fingerprint or evidence classification.`);
  }
  for (const feature of contract.requiredFeatures) if (feature !== "REMEDIATION_COMPARISON" && !features.includes(feature)) missing.push(`Required feature evidence ${feature} is absent.`);
  if (completedCases.length < contract.minimumCompletedCases) missing.push(`Only ${completedCases.length} completed case(s) were retained; ${contract.minimumCompletedCases} required.`);
  if (transmittedCases.length < contract.minimumTransmittedCases) missing.push(`Only ${transmittedCases.length} completed transmitted case(s) were retained; ${contract.minimumTransmittedCases} required.`);
  if (contract.requireStrongEvidence && scan?.evidence_level !== "strong") missing.push("Strong evidence retention was required for this lane.");
  if (contract.requireProviderAdapter && !providerAdapterBound) missing.push("A reviewed provider-adapter version was not bound to this scan.");

  let comparison: LiveAcceptanceProofResult["comparison"];
  if (remediation) {
    const row = database.db.prepare("SELECT id,older_scan_id,newer_scan_id,state,compatibility_state FROM scan_comparisons WHERE id=? AND deleted_at IS NULL").get(remediation.comparisonId) as ComparisonRow | undefined;
    if (!row || row.older_scan_id !== remediation.baselineScanId || row.newer_scan_id !== remediation.rerunScanId) {
      missing.push("The persisted comparison does not bind the exact baseline and rerun scans.");
    } else {
      const comparisonCoverageGaps = (database.db.prepare("SELECT COUNT(*) AS count FROM scan_comparison_case_coverage WHERE comparison_id=? AND state!='CASE_MATCHED_EXECUTED'").get(row.id) as { count: number }).count;
      const baselineCases = durableRemediationCases(database, remediation.baselineScanId);
      const rerunCases = durableRemediationCases(database, remediation.rerunScanId);
      const rerunCaseKeys = new Set(rerunCases.map((item) => `${item.workflow_id}\0${item.safe_case_fingerprint}`));
      const matchedCases = baselineCases.filter((item) => rerunCaseKeys.has(`${item.workflow_id}\0${item.safe_case_fingerprint}`)).length;
      const unresolvedCases = baselineCases.length - matchedCases + comparisonCoverageGaps;
      const unresolvedFindings = (database.db.prepare("SELECT COUNT(*) AS count FROM scan_comparison_findings WHERE comparison_id=? AND classification IN ('NOT_RETESTED','INCOMPARABLE')").get(row.id) as { count: number }).count;
      comparison = { id: row.id, state: row.state, compatibility: row.compatibility_state, baselineScanId: row.older_scan_id, rerunScanId: row.newer_scan_id, matchedCases, unresolvedCases, unresolvedFindings };
      if (contract.requireComparableRemediation && (row.state !== "COMPLETED" || row.compatibility_state !== "COMPATIBLE")) missing.push("The remediation comparison did not complete with compatible target, scope, authentication, identity, and coverage semantics.");
      if (contract.requireComparableRemediation && baselineCases.length === 0) missing.push("The remediation baseline contains no durable case fingerprint to rerun.");
      if (contract.requireStrongEvidence) {
        const baseline = database.db.prepare("SELECT evidence_level FROM scans WHERE id=?").get(remediation.baselineScanId) as { evidence_level: string } | undefined;
        if (baseline?.evidence_level !== "strong") missing.push("The remediation baseline did not retain strong evidence.");
      }
      if (contract.requireNoUnretestedCases && (unresolvedCases > 0 || unresolvedFindings > 0)) missing.push(`The remediation comparison retains ${unresolvedCases} unmatched case(s) and ${unresolvedFindings} unretested or incomparable finding(s).`);
      if (!missing.some((item) => item.startsWith("The persisted comparison"))) features.push("REMEDIATION_COMPARISON");
    }
  } else if (contract.requiredFeatures.includes("REMEDIATION_COMPARISON") || contract.requireComparableRemediation) {
    missing.push("An exact persisted remediation comparison is required.");
  }

  return { verified: missing.length === 0, missing, completedModules, completedWorkflows, features: unique(features).sort() as LiveAcceptanceFeature[], completedCases: completedCases.length, transmittedCases: transmittedCases.length, providerAdapterBound, ...(scan?.evidence_level ? { evidenceLevel: scan.evidence_level } : {}), ...(comparison ? { comparison } : {}) };
}

function featuresForCase(row: CaseRow): LiveAcceptanceFeature[] {
  const value = parse(row.safe_semantics_json);
  const category = text(value.category);
  const surface = text(value.surface);
  const kind = text(value.kind);
  const boundary = text(value.boundary);
  const relationship = text(value.actorRelationship);
  const protocols = Array.isArray(value.protocols) ? value.protocols.map(text) : [];
  const output: LiveAcceptanceFeature[] = [];
  if (/CROSS_TENANT/.test(`${boundary} ${relationship}`) || kind === "TENANT_ISOLATION") output.push("MULTI_TENANT_AUTHORIZATION");
  if (row.workflow_id === "supabase-authorization" && surface === "TABLE") output.push("SUPABASE_TABLE_RLS");
  if (row.workflow_id === "supabase-authorization" && surface === "STORAGE") output.push("SUPABASE_STORAGE");
  if (row.workflow_id === "supabase-authorization" && surface === "RPC") output.push("SUPABASE_RPC");
  if (row.workflow_id === "authentication-lifecycle" && category === "OAUTH_OIDC_STATE_REDIRECT_VALIDATION") output.push("OAUTH_OIDC");
  if (row.workflow_id === "authentication-lifecycle" && category === "MFA_ENROLLMENT_REMOVAL") output.push("MFA");
  if (row.workflow_id === "authentication-lifecycle" && category === "PASSKEY_ENROLLMENT_REMOVAL") output.push("PASSKEY");
  if (row.workflow_id === "api-graphql-authorization" && protocols.includes("GRAPHQL") && ["OBJECT_AUTHORIZATION", "FUNCTION_AUTHORIZATION", "FIELD_AUTHORIZATION", "TENANT_ISOLATION"].includes(kind)) output.push("GRAPHQL_AUTHORIZATION");
  if (row.workflow_id === "link-portal-export-security" && (category.startsWith("SIGNED_LINK_") || ["SIGNATURE_TAMPERING", "ID_SUBSTITUTION", "CROSS_TENANT_SIGNED_LINK"].includes(category))) output.push("SIGNED_LINK");
  if (row.workflow_id === "link-portal-export-security" && category === "PORTAL_TENANT_BINDING") output.push("SIGNED_PORTAL");
  if (row.workflow_id === "link-portal-export-security" && ["EXPORT_AUTHORIZATION", "EVIDENCE_ARTIFACT_AUTHORIZATION"].includes(category)) output.push("PROTECTED_EXPORT");
  if (row.workflow_id === "billing-entitlement-security") output.push("SYNTHETIC_PAYMENT");
  if (row.workflow_id === "operational-endpoint-security" && category.startsWith("WEBHOOK_")) output.push("WEBHOOK");
  if (row.workflow_id === "operational-endpoint-security" && category.startsWith("CRON_")) output.push("CRON");
  return output;
}

function parse(value: string): Record<string, unknown> { try { const result = JSON.parse(value) as unknown; return result && typeof result === "object" && !Array.isArray(result) ? result as Record<string, unknown> : {}; } catch { return {}; } }
function text(value: unknown): string { return typeof value === "string" ? value : ""; }
function unique<T>(values: readonly T[]): T[] { return [...new Set(values)]; }
function isDurableCase(row: CaseRow): boolean { return /^[a-f0-9]{64}$/.test(row.safe_case_fingerprint) && row.evidence_strength.trim().length > 0; }
function durableRemediationCases(database: DashboardDatabase, scanId: string): Array<{ workflow_id: string; safe_case_fingerprint: string }> {
  const rows = database.db.prepare("SELECT workflow_id,safe_case_fingerprint,evidence_strength FROM scan_workflow_case_executions WHERE scan_id=? AND execution_state='COMPLETED' AND request_transmitted=1").all(scanId) as Array<{ workflow_id: string; safe_case_fingerprint: string; evidence_strength: string }>;
  return rows.filter((row) => /^[a-f0-9]{64}$/.test(row.safe_case_fingerprint) && row.evidence_strength.trim().length > 0).map(({ workflow_id, safe_case_fingerprint }) => ({ workflow_id, safe_case_fingerprint }));
}
interface CaseRow { workflow_id: string; execution_state: string; request_transmitted: number; safe_case_fingerprint: string; evidence_strength: string; safe_semantics_json: string }
interface ComparisonRow { id: string; older_scan_id: string; newer_scan_id: string; state: string; compatibility_state: string }
