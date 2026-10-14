import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { planAdaptiveDiscoveryCandidates } from "./AdaptiveDiscoveryCandidatePlanner.js";
import { TrustedDiscoverySource, discoveryDeny, type TrustedDiscoveryActor } from "./TrustedDiscoverySource.js";

export interface DiscoveryWorkspaceStatus {
  availability: "PREVIEW_ONLY";
  execution: "UNAVAILABLE";
  targets: Array<{ id: string; label: string }>;
  scans: Array<{ id: string; targetId: string; label: string }>;
  truncated: boolean;
}
export interface DiscoveryCandidateProjection {
  scanId: string;
  targetId: string;
  candidates: Array<{ candidateId: string; label: string; method: "GET"; executionAuthority: "NONE" }>;
  truncated: boolean;
  executionAuthority: "NONE";
}
const cap = 64;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
/** Read-only metadata: no dispatcher, ScanContext, witness, request ledger or transport. */
export function discoveryWorkspaceStatus(database: DashboardDatabase, actor: TrustedDiscoveryActor): DiscoveryWorkspaceStatus {
  const targets = database.db.prepare(`SELECT id,base_origin FROM targets WHERE organization_id=? AND archived_at IS NULL
    AND classification='LOCAL' AND authorization_type IN ('OWNED','CONTROLLED_LAB') AND authorization_summary<>''
    AND production_mutation_enabled=0 AND default_credential_profile_id IS NULL AND default_auth_template_json='{}'
    ORDER BY id LIMIT 65`).all(actor.organizationId) as Array<{ id: string; base_origin: string }>;
  const accepted = targets.filter((target) => {
    try {
      const u = new URL(target.base_origin);
      return uuid.test(target.id) && u.origin === target.base_origin && u.protocol === "http:" && !u.username && !u.password && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
    } catch { return false; }
  }).slice(0, cap);
  const scans = database.db.prepare(`SELECT s.id,s.target_id FROM scans s JOIN targets t ON t.id=s.target_id
    WHERE s.organization_id=? AND t.organization_id=? AND s.status='COMPLETED' AND s.source='DASHBOARD'
    AND s.deleted_at IS NULL AND s.archived_at IS NULL AND s.json_report_artifact_id IS NOT NULL
    AND t.archived_at IS NULL ORDER BY s.created_at DESC,s.id LIMIT 65`).all(actor.organizationId, actor.organizationId) as Array<{ id: string; target_id: string }>;
  const ids = new Set(accepted.map((target) => target.id));
  return {
    availability: "PREVIEW_ONLY", execution: "UNAVAILABLE",
    targets: accepted.map((target) => ({ id: target.id, label: `Local target ${target.id.slice(0, 8)}` })),
    scans: scans.filter((scan) => uuid.test(scan.id) && ids.has(scan.target_id)).slice(0, cap).map((scan) => ({ id: scan.id, targetId: scan.target_id, label: `Completed scan ${scan.id.slice(0, 8)}` })),
    truncated: targets.length > cap || scans.length > cap
  };
}
export function discoveryCandidateProjection(database: DashboardDatabase, reportRoot: string, scanId: string, actor: TrustedDiscoveryActor): DiscoveryCandidateProjection {
  if (!uuid.test(scanId)) discoveryDeny("DENIED_SOURCE_STALE");
  const source = new TrustedDiscoverySource(database, reportRoot), snapshot = source.capture(scanId, actor);
  const plan = planAdaptiveDiscoveryCandidates(snapshot.report);
  if (plan.diagnostics.length || plan.upstreamDiagnostics.length || plan.accountingLedger.length !== plan.accountedObservations || plan.accountingLedger.some((entry) => entry.state !== "CANDIDATE")) discoveryDeny("DENIED_SOURCE_STALE");
  const matcher = new ScopeMatcher(snapshot.origin, snapshot.scope);
  // Conservative metadata eligibility; the original review rederives ALL authority.
  const candidates = plan.candidates.filter((candidate) => {
    if (candidate.method !== "GET" || candidate.originRelation !== "PRIMARY_TARGET" || candidate.targetOrigin !== snapshot.origin || candidate.reportCompleteness !== "COMPLETED_REPORTED" || candidate.upstreamEvidenceIncomplete || candidate.alreadyObservedExchange || candidate.nextStep !== "REVIEW_FOR_POTENTIAL_PROBE" || candidate.sourceReferences.length !== 1) return false;
    const ref = candidate.sourceReferences[0]!;
    if (ref.producer !== "API_MAPPER" || ref.disposition !== "API_DISCOVERY_CANDIDATE") return false;
    const original = snapshot.report.apiMapper?.endpoints[ref.sourceIndex];
    if (!original || original.method !== "GET" || original.hasObjectId || (original.authRelevance && original.authRelevance !== "low") || typeof original.endpoint !== "string" || original.endpoint.length > 512 || /[%\\?#@]/.test(original.endpoint) || /(?:^|\/)\.\.?(?:\/|$)/.test(original.endpoint)) return false;
    try {
      const url = new URL(original.endpoint, snapshot.origin);
      return url.origin === snapshot.origin && !url.search && !url.hash && url.pathname.length <= 160 && url.pathname.split("/").filter(Boolean).every((segment) => /^[a-z][a-z_-]{0,31}$/.test(segment) && !segment.split(/[-_]/).some((word) => /^(?:logout|admin|delete|reset|purchase|trigger|action|callback|token|signed|sign|invite|secret|session|payment|cart|remove|update|create|withdraw|restore|transfer)$/.test(word))) && matcher.decide(url.href, "GET").allowed;
    } catch { return false; }
  });
  source.assertCurrent(snapshot, actor);
  return { scanId, targetId: snapshot.targetId, executionAuthority: "NONE", truncated: candidates.length > cap, candidates: candidates.slice(0, cap).map((candidate) => ({ candidateId: candidate.candidateId, label: `Anonymous GET candidate ${candidate.routeOrdinal + 1}`, method: "GET", executionAuthority: "NONE" })) };
}
