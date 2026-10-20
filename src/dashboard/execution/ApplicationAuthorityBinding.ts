import type { DashboardDatabase } from "../db/DashboardDatabase.js";
export function applicationAuthorityContext(
  db: DashboardDatabase,
  organizationId: string,
  targetId: string,
  credentialIds: readonly string[]
) {
  const target = db.db
    .prepare("SELECT * FROM targets WHERE id=? AND organization_id=? AND archived_at IS NULL")
    .get(targetId, organizationId) as Record<string, unknown> | undefined;
  if (
    !target ||
    target.classification !== "LOCAL" ||
    target.authorization_type !== "OWNED" ||
    new URL(String(target.base_origin)).hostname !== "127.0.0.1"
  )
    throw Error("WORKBENCH_OWNED_LOOPBACK_TARGET_REQUIRED");
  const credentials = credentialIds.map((id) => {
    const row = db.db
      .prepare(
        "SELECT id,organization_id,target_id,enabled,secret_version,safe_identity_summary_json,expires_at,deleted_at,nonce,ciphertext,auth_tag FROM credential_profiles WHERE id=? AND organization_id=? AND target_id=? AND enabled=1 AND deleted_at IS NULL"
      )
      .get(id, organizationId, targetId) as Record<string, unknown> | undefined;
    if (
      !row ||
      (row.expires_at &&
        (!Number.isFinite(Date.parse(String(row.expires_at))) || Date.parse(String(row.expires_at)) <= Date.now()))
    )
      throw Error("WORKBENCH_CREDENTIAL_BINDING_INVALID");
    return row;
  });
  return { target, credentials };
}
