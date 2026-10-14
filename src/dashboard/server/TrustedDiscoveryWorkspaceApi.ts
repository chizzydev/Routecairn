import { SessionError } from "../auth/LocalSession.js";
import { OrganizationPermissionError } from "../operations/OrganizationService.js";
import { TrustedDiscoveryDenial } from "../execution/TrustedDiscoverySource.js";
import { discoveryCandidateProjection, discoveryWorkspaceStatus } from "../execution/TrustedDiscoveryProjection.js";
import { withTrustedDiscoveryDatabaseDeadline } from "../execution/TrustedDiscoveryDatabaseDeadline.js";
import { requireRuntimeSession, sendJson, type ApiContext } from "./DashboardApiContext.js";

const candidatePath = /^\/api\/trusted-discovery\/candidates\/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/i;
export function isDiscoveryWorkspaceRead(context: ApiContext): boolean {
  return context.request.method === "GET" && (context.url.pathname === "/api/trusted-discovery/status" || candidatePath.test(context.url.pathname));
}
/** Exactly two authenticated metadata GETs. No mutation/consent/execution authority. */
export function handleDiscoveryWorkspaceRead(context: ApiContext): void {
  context.response.setHeader("cache-control", "no-store");
  try {
    withTrustedDiscoveryDatabaseDeadline(context.database, () => {
      const principal = requireRuntimeSession(context);
      if (context.mode !== "server" || !context.trustedDiscovery || !context.serverSessions || context.infrastructure.config.mode !== "local" || !isDiscoveryWorkspaceRead(context) || context.url.search) {
        sendJson(context.response, 404, { code: "DISABLED", execution: "UNAVAILABLE" }); return;
      }
      const selected = context.request.headers["x-routecairn-organization-id"];
      if (typeof selected !== "string" || !/^[a-f0-9-]{36}$/i.test(selected) || context.request.headers["sec-fetch-site"] === "cross-site") throw new OrganizationPermissionError("resources.use");
      // requireSession resolves the native cookie against current DB. Its current
      // CSRF HASH identifies that session for the additional read-only live checks;
      // neither hash nor serialized principal is accepted from the caller.
      const row = context.database.db.prepare(`SELECT s.created_at,s.expires_at,s.last_seen_at,s.session_version,u.enabled,u.role,u.locked_until,u.password_changed_at
        FROM dashboard_sessions s JOIN dashboard_users u ON u.id=s.user_id
        WHERE s.user_id=? AND s.csrf_token_hash=? AND s.revoked_at IS NULL`).get(principal.userId, principal.csrfToken) as { created_at: string; expires_at: string; last_seen_at: string; session_version: number; enabled: number; role: string; locked_until: string | null; password_changed_at: string } | undefined;
      const now = Date.now();
      if (!row || row.enabled !== 1 || row.role !== "OWNER" || !Number.isSafeInteger(row.session_version) || row.session_version < 1 || ![row.created_at, row.expires_at, row.last_seen_at, row.password_changed_at].every((v) => Number.isFinite(Date.parse(v))) || Date.parse(row.created_at) > now || Date.parse(row.password_changed_at) > Date.parse(row.created_at) || now >= Date.parse(row.expires_at) || now >= Date.parse(row.last_seen_at) + 2 * 60 * 60 * 1000 || (row.locked_until !== null && (!Number.isFinite(Date.parse(row.locked_until)) || now < Date.parse(row.locked_until)))) throw new SessionError("Owner session required.");
      if (context.organizations.require(selected, principal.userId, "resources.use", false) !== "OWNER") throw new OrganizationPermissionError("resources.use");
      const actor = { organizationId: selected, userId: principal.userId };
      const scan = candidatePath.exec(context.url.pathname)?.[1];
      const result = scan ? discoveryCandidateProjection(context.database, context.paths.reportsDir, scan, actor) : discoveryWorkspaceStatus(context.database, actor);
      if (Buffer.byteLength(JSON.stringify(result)) > 48 * 1024) throw Error("PROJECTION_LIMIT");
      sendJson(context.response, 200, result);
    });
  } catch (error) {
    const status = error instanceof SessionError ? 401 : error instanceof OrganizationPermissionError ? 403 : error instanceof TrustedDiscoveryDenial ? 409 : 503;
    sendJson(context.response, status, { code: status === 409 ? "SOURCE_UNAVAILABLE" : status === 503 ? "UNAVAILABLE" : "DENIED_AUTHORITY", execution: "UNAVAILABLE" });
  }
}
