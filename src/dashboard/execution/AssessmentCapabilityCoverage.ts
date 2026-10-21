import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
type Coverage = NonNullable<RouteCairnReport["assessmentCapabilities"]>;
const headerKind = "ASSESSMENT_CAPABILITY_SNAPSHOT";
/** Bounded event records preserve the existing 4,000-character event limit.
 * Complete native evidence remains in the immutable JSON report artifact. */
export function recordCapabilityCoverage(
  database: DashboardDatabase,
  scanId: string,
  value: Coverage,
  reportArtifactId: string
) {
  if (value.actors.length > 8 || value.workflows.length > 64) throw Error("CAPABILITY_COVERAGE_CARDINALITY_INVALID");
  const append = (metadata: Record<string, unknown>) => {
    if (JSON.stringify(metadata).length > 3900) throw Error("CAPABILITY_EVENT_BOUND_EXCEEDED");
    database.appendEvent(
      scanId,
      "OBSERVATION_RECORDED",
      "Assessment capability coverage; full native evidence is retained in the source report.",
      metadata
    );
  };
  append({
    kind: headerKind,
    contractVersion: value.contractVersion,
    registryId: value.registryId,
    actors: value.actors.length,
    workflows: value.workflows.length,
    reportArtifactId,
    nativeProof: false,
    independentAccuracy: false,
    applicationSecureConclusion: false
  });
  value.actors.forEach((actor, index) =>
    append({ kind: "ASSESSMENT_CAPABILITY_ACTOR", registryId: value.registryId, index, actor })
  );
  value.workflows.forEach((workflow, index) => {
    const base = {
      ...workflow,
      evidence: [],
      evidenceCount: workflow.evidence.length,
      evidenceCoverage: workflow.evidence.length ? "FULL_EVIDENCE_IN_SOURCE_REPORT" : "NO_NATIVE_CASE_EVIDENCE",
      reportArtifactId
    };
    let row: Record<string, unknown> = {
      kind: "ASSESSMENT_CAPABILITY_WORKFLOW",
      registryId: value.registryId,
      index,
      workflow: {
        ...base,
        evidence: workflow.evidence.slice(0, 4),
        evidenceCoverage: workflow.evidence.length > 4 ? "FULL_EVIDENCE_IN_SOURCE_REPORT" : "COMPLETE_INLINE"
      }
    };
    if (JSON.stringify(row).length > 3900) row = { ...row, workflow: base };
    append(row);
  });
}
export function readCapabilityCoverage(
  database: DashboardDatabase,
  scanId: string
): Coverage | { state: "INCONCLUSIVE"; reason: string } | undefined {
  const header = database.db
    .prepare(
      "SELECT seq,safe_metadata_json FROM scan_events WHERE scan_id=? AND json_extract(safe_metadata_json,'$.kind')=? ORDER BY seq DESC LIMIT 1"
    )
    .get(scanId, headerKind) as { seq: number; safe_metadata_json: string } | undefined;
  if (!header) return undefined;
  const snapshot = JSON.parse(header.safe_metadata_json) as {
    registryId: string;
    actors: number;
    workflows: number;
    reportArtifactId: string;
  };
  if (snapshot.actors > 8 || snapshot.workflows > 64)
    return { state: "INCONCLUSIVE", reason: "CAPABILITY_SNAPSHOT_BOUND_INVALID" };
  const rows = database.db
    .prepare(
      "SELECT safe_metadata_json FROM scan_events WHERE scan_id=? AND seq>? AND json_extract(safe_metadata_json,'$.kind') IN ('ASSESSMENT_CAPABILITY_ACTOR','ASSESSMENT_CAPABILITY_WORKFLOW') ORDER BY seq ASC LIMIT 73"
    )
    .all(scanId, header.seq) as Array<{ safe_metadata_json: string }>;
  const actors: Coverage["actors"] = [],
    workflows: Coverage["workflows"] = [];
  for (const row of rows) {
    const item = JSON.parse(row.safe_metadata_json);
    if (item.registryId !== snapshot.registryId)
      return { state: "INCONCLUSIVE", reason: "CAPABILITY_REGISTRY_RECORD_MISMATCH" };
    if (item.kind === "ASSESSMENT_CAPABILITY_ACTOR") {
      if (item.index !== actors.length) return { state: "INCONCLUSIVE", reason: "CAPABILITY_ACTOR_ORDER_INVALID" };
      actors.push(item.actor);
    } else {
      if (item.index !== workflows.length)
        return { state: "INCONCLUSIVE", reason: "CAPABILITY_WORKFLOW_ORDER_INVALID" };
      workflows.push(item.workflow);
    }
  }
  if (actors.length !== snapshot.actors || workflows.length !== snapshot.workflows)
    return { state: "INCONCLUSIVE", reason: "CAPABILITY_READ_MODEL_INCOMPLETE" };
  return {
    contractVersion: 2,
    registryId: snapshot.registryId,
    actors,
    workflows,
    nativeProof: false,
    independentAccuracy: false,
    applicationSecureConclusion: false
  };
}
