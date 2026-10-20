import { assertOwnedApplicationIntakeBinding } from "./OwnedApplicationIntake.js";
import { assertApplicationDiscoveryBinding } from "./ApplicationDiscoveryBinding.js";
import { assertApplicationSchemaBinding } from "./ApplicationSchemaService.js";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import { applicationAuthorityContext } from "./ApplicationAuthorityBinding.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
export function mappingContext(db: DashboardDatabase, org: string, target: string, credentials: readonly string[]) {
  const context = applicationAuthorityContext(db, org, target, credentials);
  return { ...context, digest: adaptiveDigest(context) };
}
export function assertApplicationMappingBinding(db: DashboardDatabase, request: DashboardScanCreateRequest) {
  const b = request.applicationMappingBinding;
  if (!b) return;
  const row = db.db
    .prepare(
      "SELECT r.* FROM application_mapping_revisions r JOIN application_mapping_dispatches d ON d.revision_id=r.id WHERE r.id=?"
    )
    .get(b.revisionId) as Record<string, string> | undefined;
  if (
    !row ||
    row.digest !== b.digest ||
    !Number.isFinite(Date.parse(row.expires_at!)) ||
    Date.parse(row.expires_at!) <= Date.now()
  )
    throw Error("WORKBENCH_MAPPING_REVIEW_EXPIRED_OR_UNAVAILABLE");
  const { applicationMappingBinding: _binding, ...plain } = request;
  if (adaptiveDigest(plain) !== adaptiveDigest(JSON.parse(row.request_json!)))
    throw Error("WORKBENCH_MAPPING_REQUEST_CHANGED");
  const input = JSON.parse(row.input_json!);
  assertOwnedApplicationIntakeBinding(db, row.organization_id!, input);
  assertApplicationSchemaBinding(db, row.organization_id!, input);
  assertApplicationDiscoveryBinding(db, row.organization_id!, input);
  if (
    mappingContext(db, row.organization_id!, row.target_id!, Object.values(input.credentials)).digest !==
    row.context_digest
  )
    throw Error("WORKBENCH_MAPPING_BINDINGS_CHANGED");
}
