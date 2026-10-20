import { assertHypothesisReviewBinding } from "./ApplicationHypothesisBinding.js";
import { readFileSync, lstatSync } from "node:fs";
import { createHash } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import { applicationAuthorityContext } from "./ApplicationAuthorityBinding.js";
import { assertApplicationMappingBinding } from "./ApplicationMappingBinding.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
export function workbenchContext(
  db: DashboardDatabase,
  organizationId: string,
  targetId: string,
  sourceScanId: string,
  credentialIds: readonly string[]
) {
  const { target, credentials } = applicationAuthorityContext(db, organizationId, targetId, credentialIds);
  const source = db.db
    .prepare(
      "SELECT s.status,s.target_origin,a.canonical_path,a.scoped_or_full_safe_hash FROM scans s JOIN artifacts a ON a.id=s.json_report_artifact_id WHERE s.id=? AND s.organization_id=? AND s.target_id=? AND s.deleted_at IS NULL AND s.status='COMPLETED'"
    )
    .get(sourceScanId, organizationId, targetId) as
    { target_origin: string; canonical_path: string; scoped_or_full_safe_hash: string } | undefined;
  if (!source || source.target_origin !== target.base_origin)
    throw Error("WORKBENCH_COMPLETED_BOUND_OBSERVATION_REQUIRED");
  const stat = lstatSync(source.canonical_path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 8 * 1024 * 1024)
    throw Error("WORKBENCH_SOURCE_CUSTODY_INVALID");
  const bytes = readFileSync(source.canonical_path),
    sourceHash = createHash("sha256").update(bytes).digest("hex");
  if (sourceHash !== source.scoped_or_full_safe_hash) throw Error("WORKBENCH_OBSERVATION_CHANGED");
  return {
    target,
    sourceHash,
    reportText: bytes.toString("utf8"),
    digest: adaptiveDigest({ target, sourceScanId, sourceHash, credentials })
  };
}
export function assertAuthorizationWorkbenchBinding(db: DashboardDatabase, request: DashboardScanCreateRequest) {
  if (request.authorizationWorkbenchBinding && request.applicationMappingBinding)
    throw Error("WORKBENCH_AMBIGUOUS_BINDING");
  assertApplicationMappingBinding(db, request);
  const binding = request.authorizationWorkbenchBinding;
  if (!binding) return;
  const row = db.db
    .prepare(
      "SELECT r.*,d.requested_by FROM authorization_workbench_revisions r JOIN authorization_workbench_dispatches d ON d.revision_id=r.id WHERE r.id=?"
    )
    .get(binding.revisionId) as Record<string, string> | undefined;
  if (
    !row ||
    row.digest !== binding.digest ||
    !Number.isFinite(Date.parse(row.expires_at!)) ||
    Date.parse(row.expires_at!) <= Date.now()
  )
    throw Error("WORKBENCH_REVIEW_UNAVAILABLE_OR_EXPIRED");
  const { authorizationWorkbenchBinding: _binding, ...plain } = request;
  if (adaptiveDigest(plain) !== adaptiveDigest(JSON.parse(row.request_json!))) throw Error("WORKBENCH_REQUEST_CHANGED");
  const input = JSON.parse(row.input_json!);
  assertHypothesisReviewBinding(db, row.organization_id!, input, row.created_by!);
  const current = workbenchContext(
    db,
    row.organization_id!,
    row.target_id!,
    row.source_scan_id!,
    Object.values(input.credentials)
  );
  if (current.digest !== row.context_digest) throw Error("WORKBENCH_BINDINGS_CHANGED");
}
