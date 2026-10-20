import { handleObservedState } from "./DashboardObservedStateApi.js";
import { handleApplicationMapping } from "./DashboardApplicationMappingApi.js";
import { PermissionError } from "../auth/ServerSession.js";
import { SessionError } from "../auth/LocalSession.js";
import { OrganizationPermissionError } from "../operations/OrganizationService.js";
import { ZodError } from "zod";
import { AuthorizationWorkbenchService } from "../execution/AuthorizationWorkbenchService.js";
import {
  authorizationWorkbenchInputSchema,
  authorizationWorkbenchExecuteSchema
} from "../contracts/AuthorizationWorkbenchContracts.js";
import { HttpError } from "./DashboardHttpSupport.js";
import {
  readJson,
  sendJson,
  resourceOrganization,
  requirePermission,
  requireSelectedResource,
  type ApiContext
} from "./DashboardApiContext.js";
export async function handleAuthorizationWorkbench(context: ApiContext): Promise<boolean> {
  const path = context.url.pathname;
  if (!path.startsWith("/api/authorization-workbench")) return false;
  requirePermission(context, "scans.read");
  const org = resourceOrganization(context),
    service = new AuthorizationWorkbenchService(context.database, context.vault, context.execution);
  context.response.setHeader("Cache-Control", "no-store");
  try {
    if (await handleObservedState(context)) return true;
    if (await handleApplicationMapping(context)) return true;
    if (context.request.method === "GET" && path === "/api/authorization-workbench") {
      requirePermission(context, "credentials.readSummary");
      sendJson(context.response, 200, {
        targets: context.targets
          .list({ organizationId: org })
          .filter((t) => t.classification === "LOCAL" && new URL(t.baseOrigin).hostname === "127.0.0.1"),
        scans: context.database.db
          .prepare(
            "SELECT id,target_id,status,created_at FROM scans WHERE organization_id=? AND deleted_at IS NULL AND status='COMPLETED' ORDER BY created_at DESC LIMIT 100"
          )
          .all(org),
        credentials: context.vault
          .list(org)
          .map((c) => ({ id: c.id, safeAlias: c.safeAlias, targetId: c.targetId, enabled: c.enabled })),
        revisions: context.database.db
          .prepare(
            "SELECT id,target_id,version,created_at,expires_at FROM authorization_workbench_revisions WHERE organization_id=? ORDER BY created_at DESC LIMIT 100"
          )
          .all(org)
      });
      return true;
    }
    const match = /^\/api\/authorization-workbench\/([a-f0-9-]{36})(?:\/(execute|compare))?$/.exec(path);
    if (context.request.method === "GET" && match && !match[2]) {
      requirePermission(context, "credentials.readSummary");
      const r = service.row(org, match[1]!);
      sendJson(context.response, 200, {
        ...JSON.parse(r.review_json!),
        revisionId: r.id,
        digest: r.digest,
        input: JSON.parse(r.input_json!),
        contract: JSON.parse(r.request_json!),
        expiresAt: r.expires_at,
        result: service.result(org, r.id!)
      });
      return true;
    }
    if (context.request.method !== "POST") throw new HttpError(404, "Workbench route not found.");
    requirePermission(context, "scans.create");
    requirePermission(context, "credentials.use");
    resourceOrganization(context, "resources.use");
    if (path === "/api/authorization-workbench/preview" || path === "/api/authorization-workbench/revisions") {
      const input = authorizationWorkbenchInputSchema.parse(await readJson(context.request));
      requireSelectedResource(context, "target", input.targetId, "resources.use");
      requireSelectedResource(context, "scan", input.sourceScanId, "resources.use");
      for (const id of Object.values(input.credentials).filter((v): v is string => typeof v === "string"))
        requireSelectedResource(context, "credential", id, "resources.use");
      const result = path.endsWith("/preview")
        ? await service.preview(org, input)
        : await service.create(org, input, context.principal!.userId);
      sendJson(context.response, path.endsWith("/preview") ? 200 : 201, result);
      return true;
    }
    if (match?.[2] === "execute") {
      const input = authorizationWorkbenchExecuteSchema.parse(await readJson(context.request)),
        r = service.row(org, match[1]!);
      requireSelectedResource(context, "target", r.target_id!, "resources.use");
      const result = await service.execute(org, match[1]!, input.digest, context.principal!.userId);
      sendJson(context.response, 202, result);
      return true;
    }
    if (match?.[2] === "compare") {
      requirePermission(context, "comparisons.create");
      requirePermission(context, "comparisons.read");
      const input = (await readJson(context.request)) as { baselineRevisionId?: string };
      if (!input.baselineRevisionId || !/^[a-f0-9-]{36}$/.test(input.baselineRevisionId))
        throw new HttpError(400, "Bound baseline revision required.");
      const old = service.row(org, input.baselineRevisionId),
        current = service.row(org, match[1]!);
      if (old.target_id !== current.target_id || old.input_json !== current.input_json)
        throw new HttpError(
          409,
          "Identical target, actor and policy bindings are required for remediation comparison."
        );
      const a = service.result(org, old.id!),
        b = service.result(org, current.id!);
      if (!a.scanId || !b.scanId || a.status === "UNKNOWN" || b.status === "UNKNOWN")
        throw new HttpError(409, "Both executions require retained completed evidence.");
      const comparison = context.comparison.compare(a.scanId, b.scanId, { createdByUserId: context.principal!.userId });
      sendJson(context.response, 200, { comparison, historicalGatesChanged: false });
      return true;
    }
    throw new HttpError(404, "Workbench route not found.");
  } catch (e) {
    if (
      e instanceof HttpError ||
      e instanceof PermissionError ||
      e instanceof SessionError ||
      e instanceof OrganizationPermissionError ||
      e instanceof ZodError
    )
      throw e;
    const message =
      e instanceof Error && /^(WORKBENCH_|OBSERVED_STATE_)/.test(e.message)
        ? e.message
        : "WORKBENCH_EVIDENCE_OR_INPUT_UNAVAILABLE";
    throw new HttpError(message.endsWith("_NOT_FOUND") ? 404 : 409, message);
  }
}
