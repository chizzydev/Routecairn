import { readCollectionObservation } from "./CollectionMappingEvidence.js";
import { applicationIdentityModel } from "../../core/auth/IdentityModel.js";
import { readFileSync, lstatSync } from "node:fs";
import { createHash } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import type { AuthorizationWorkbenchInput } from "../contracts/AuthorizationWorkbenchContracts.js";
import type { ApplicationMappingInput } from "../contracts/ApplicationMappingContracts.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
import { observedMarkerFingerprint } from "../../modules/apiGraphql/ObservedMarker.js";
export function mappingObservation(db: DashboardDatabase, org: string, id: string) {
  const row = db.db
    .prepare("SELECT * FROM application_mapping_revisions WHERE id=? AND organization_id=?")
    .get(id, org) as Record<string, string> | undefined;
  if (!row) throw Error("WORKBENCH_MAPPING_NOT_FOUND");
  const input = JSON.parse(row.input_json!) as ApplicationMappingInput;
  const ack = db.db
    .prepare(
      "SELECT a.scan_id,s.status,s.error_summary,s.target_origin,f.canonical_path,f.scoped_or_full_safe_hash FROM application_mapping_acknowledgements a JOIN scans s ON s.id=a.scan_id LEFT JOIN artifacts f ON f.id=s.json_report_artifact_id WHERE a.revision_id=? AND s.organization_id=? AND s.target_id=? AND s.deleted_at IS NULL"
    )
    .get(id, org, row.target_id) as
    | {
        scan_id: string;
        status: string;
        error_summary: string | null;
        target_origin: string;
        canonical_path: string;
        scoped_or_full_safe_hash: string;
      }
    | undefined;
  let report: RouteCairnReport | undefined, sourceHash: string | undefined;
  if (ack?.status === "COMPLETED") {
    const s = lstatSync(ack.canonical_path);
    if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1 || s.size > 8 * 1024 * 1024)
      throw Error("WORKBENCH_MAPPING_SOURCE_CUSTODY_INVALID");
    const bytes = readFileSync(ack.canonical_path);
    sourceHash = createHash("sha256").update(bytes).digest("hex");
    if (sourceHash !== ack.scoped_or_full_safe_hash) throw Error("WORKBENCH_MAPPING_SOURCE_CHANGED");
    report = JSON.parse(bytes.toString()) as RouteCairnReport;
    const request = JSON.parse(row.request_json!);
    const expectedIds = (request.apiGraphql.checks as Array<{ id: string }>).map((c) => c.id).sort();
    const nativeIds = report.apiGraphql?.checks.map((c) => c.checkId).sort() ?? [];
    const planIds = report.scanPlan?.apiGraphql?.checks.map((c) => c.id).sort() ?? [];
    const exactIdentities =
      new Set(expectedIds).size === expectedIds.length &&
      new Set(nativeIds).size === nativeIds.length &&
      JSON.stringify(expectedIds) === JSON.stringify(nativeIds) &&
      JSON.stringify(expectedIds) === JSON.stringify(planIds);
    if (
      !exactIdentities ||
      report.scanPlan?.apiGraphql?.actors.some(
        (a) =>
          a.authSlot !== "anonymous" &&
          applicationIdentityModel(a.identityModel) !== applicationIdentityModel(input.identityModel)
      ) ||
      ack.target_origin !== request.target ||
      new URL(report.target).origin !== request.target ||
      report.execution?.status !== "COMPLETED" ||
      report.execution.partial ||
      !report.apiGraphql?.enabled ||
      !report.scanPlan?.apiGraphql ||
      report.apiGraphql.checks.length !== request.apiGraphql.checks.length ||
      report.apiGraphql.plannedChecks !== report.apiGraphql.checks.length
    )
      throw Error("WORKBENCH_MAPPING_RESULT_INCOMPLETE");
  }
  return {
    row,
    input,
    report,
    sourceHash,
    scanId: ack?.scan_id,
    failureReason: ack?.error_summary ?? undefined,
    status:
      ack?.status ??
      (db.db.prepare("SELECT 1 FROM application_mapping_dispatches WHERE revision_id=?").get(id)
        ? "UNKNOWN"
        : "REVIEW_REQUIRED")
  };
}
export function guidedMappingBlockers(
  db: DashboardDatabase,
  org: string,
  input: AuthorizationWorkbenchInput
): string[] {
  if (!input.mappingAcquisitionId) return [];
  const o = mappingObservation(db, org, input.mappingAcquisitionId),
    blocked: string[] = [];
  if (
    !o.report ||
    o.scanId !== input.sourceScanId ||
    o.input.targetId !== input.targetId ||
    adaptiveDigest(o.input.credentials) !== adaptiveDigest(input.credentials)
  )
    return ["MAPPING_BOUND_OBSERVATION_REQUIRED"];
  for (const e of input.expectations) {
    const route = o.input.routes.find((r) => r.id === e.routeId);
    if (route?.observation?.kind === "COLLECTION") {
      if (
        e.url !== route.url ||
        adaptiveDigest(e.collection) !== adaptiveDigest(route.observation) ||
        e.kind !== "OBJECT_AUTHORIZATION" ||
        e.identity ||
        e.tenant
      )
        blocked.push("MAPPING_EXACT_COLLECTION_POLICY_REQUIRED:" + e.routeId);
      const primary = readCollectionObservation(o, e.routeId, "primary");
      if (!primary.valid || primary.evidence?.status !== "SELF_COLLECTION_OBSERVED")
        blocked.push("MAPPING_NONEMPTY_COLLECTION_CONTROL_REQUIRED:" + e.routeId);
      for (const actor of ["primary", "account-a", "account-b"])
        if (!readCollectionObservation(o, e.routeId, actor).valid)
          blocked.push("MAPPING_COLLECTION_ACTOR_EVIDENCE_REQUIRED:" + actor);
      continue;
    }
    if (e.collection) {
      blocked.push("MAPPING_UNEXPECTED_COLLECTION_POLICY:" + e.routeId);
      continue;
    }
    if (
      !route ||
      e.url !== route.url ||
      e.identity?.path !== route.identityPath ||
      (e.tenant && e.tenant.path !== route.tenantPath) ||
      (route.kind === "FUNCTION") !== (e.kind === "FUNCTION_AUTHORIZATION")
    ) {
      blocked.push("MAPPING_EXACT_SEED_BINDING_REQUIRED:" + e.routeId);
      continue;
    }
    if (
      e.states &&
      JSON.stringify(e.states.map((s) => s.path).sort()) !== JSON.stringify([...(route.statePaths ?? [])].sort())
    )
      blocked.push("MAPPING_EXACT_STATE_FIELDS_REQUIRED:" + e.routeId);
    for (const [actor, decision] of Object.entries(e.decisions)) {
      if (decision !== "ALLOW") continue;
      const c = o.report.apiGraphql!.checks.find((c) => c.checkId === e.routeId + "-observe-" + actor);
      const matches = (marker: { path: string; expectedValue: string | number } | undefined) =>
        !!marker &&
        c?.observedMarkers?.some(
          (m) => m.path === marker.path && m.valueFingerprint === observedMarkerFingerprint(marker.expectedValue)
        );
      if (
        c?.outcome !== "PASS" ||
        c.requests[0]?.decision !== "ALLOWED" ||
        !matches(e.identity) ||
        (e.states && !e.states.every(matches)) ||
        ((e.kind === "TENANT_ISOLATION" || !!e.tenant) && !matches(e.tenant))
      )
        blocked.push("MAPPING_ALLOW_CONTROL_MARKER_NOT_OBSERVED:" + e.routeId + ":" + actor);
    }
  }
  return blocked;
}
