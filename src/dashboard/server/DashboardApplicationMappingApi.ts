import { ApplicationAssessmentReadiness } from "../execution/ApplicationAssessmentReadiness.js";
import { OwnedApplicationIntakeService } from "../execution/OwnedApplicationIntake.js";
import { ownedApplicationIntakeSchema } from "../contracts/OwnedApplicationIntakeContracts.js";
import { ApplicationOnboardingService } from "../execution/ApplicationOnboardingService.js";
import { hasPermission } from "../auth/Permissions.js";
import { handleApplicationDiscovery } from "./DashboardApplicationDiscoveryApi.js";
import { handleApplicationHypotheses } from "./DashboardApplicationHypothesesApi.js";
import { ApplicationSchemaService } from "../execution/ApplicationSchemaService.js";
import { ApplicationMapComparisonService } from "../execution/ApplicationMapComparison.js";
import { schemaImportSchema, mapComparisonSchema } from "../contracts/ApplicationSchemaContracts.js";
import { ApplicationMappingService } from "../execution/ApplicationMappingService.js";
import {
  applicationMappingInputSchema,
  applicationMappingExecuteSchema
} from "../contracts/ApplicationMappingContracts.js";
import {
  readJson,
  sendJson,
  resourceOrganization,
  requirePermission,
  requireSelectedResource,
  type ApiContext
} from "./DashboardApiContext.js";
import { HttpError } from "./DashboardHttpSupport.js";
export async function handleApplicationMapping(context: ApiContext): Promise<boolean> {
  const path = context.url.pathname,
    base = "/api/authorization-workbench/mapping";
  if (path !== base && !path.startsWith(base + "/")) return false;
  const org = resourceOrganization(context),
    service = new ApplicationMappingService(context.database, context.vault, context.execution);
  if (context.request.method === "GET") requirePermission(context, "credentials.readSummary");
  if (context.request.method === "GET" && path === base + "/readiness") {
    sendJson(
      context.response,
      200,
      new ApplicationAssessmentReadiness(context.database).get(org, Object.fromEntries(context.url.searchParams))
    );
    return true;
  }
  if (context.request.method === "GET" && (path === base + "/intakes" || path.startsWith(base + "/intakes/"))) {
    const intake = new OwnedApplicationIntakeService(context.database),
      match = /^\/api\/authorization-workbench\/mapping\/intakes\/([a-f0-9-]{36})$/.exec(path);
    if (match) {
      sendJson(context.response, 200, intake.get(org, match[1]!));
      return true;
    }
    const target = context.url.searchParams.get("targetId");
    if (path !== base + "/intakes" || !target || !/^[a-f0-9-]{36}$/.test(target))
      throw new HttpError(400, "Exact intake or target required");
    sendJson(context.response, 200, intake.list(org, target));
    return true;
  }
  if (context.request.method === "POST" && path === base + "/onboarding") {
    requirePermission(context, "targets.manage");
    requirePermission(context, "credentials.create");
    requirePermission(context, "credentials.readSummary");
    resourceOrganization(context, "resources.use");
    sendJson(
      context.response,
      201,
      new ApplicationOnboardingService(context.database, context.vault).create(
        org,
        await readJson(context.request),
        context.principal!.userId
      )
    );
    return true;
  }
  if (context.request.method === "POST" && path === base + "/intake") {
    requirePermission(context, "imports.create");
    requirePermission(context, "credentials.readSummary");
    requirePermission(context, "credentials.use");
    const input = ownedApplicationIntakeSchema.parse(await readJson(context.request));
    requireSelectedResource(context, "target", input.targetId, "resources.use");
    for (const id of Object.values(input.credentials))
      requireSelectedResource(context, "credential", id, "resources.use");
    sendJson(
      context.response,
      201,
      new OwnedApplicationIntakeService(context.database).create(org, input, context.principal!.userId)
    );
    return true;
  }
  if (await handleApplicationDiscovery(context)) return true;
  if (await handleApplicationHypotheses(context)) return true;
  const schemaService = new ApplicationSchemaService(context.database),
    comparisons = new ApplicationMapComparisonService(context.database);
  const saved = /^\/api\/authorization-workbench\/mapping\/(schemas|comparisons)\/([a-f0-9-]{36})$/.exec(path);
  if (context.request.method === "GET" && saved) {
    if (saved[1] === "comparisons") requirePermission(context, "comparisons.read");
    sendJson(
      context.response,
      200,
      saved[1] === "schemas" ? schemaService.result(org, saved[2]!) : comparisons.result(org, saved[2]!)
    );
    return true;
  }
  if (context.request.method === "POST" && path === base + "/comparisons") {
    requirePermission(context, "credentials.readSummary");
    requirePermission(context, "comparisons.read");
    requirePermission(context, "comparisons.create");
    sendJson(
      context.response,
      201,
      comparisons.create(org, mapComparisonSchema.parse(await readJson(context.request)), context.principal!.userId)
    );
    return true;
  }
  if (context.request.method === "POST" && path === base + "/schemas") {
    requirePermission(context, "imports.create");
    requirePermission(context, "credentials.readSummary");
    const input = schemaImportSchema.parse(await readJson(context.request));
    requireSelectedResource(context, "target", input.targetId, "resources.use");
    sendJson(context.response, 201, schemaService.create(org, input, context.principal!.userId));
    return true;
  }
  if (context.request.method === "GET" && path === base) {
    requirePermission(context, "credentials.readSummary");
    sendJson(context.response, 200, {
      onboardingAllowed:
        context.mode === "local" ||
        Boolean(
          context.principal &&
          hasPermission(context.principal.role, "targets.manage") &&
          hasPermission(context.principal.role, "credentials.create")
        ),
      targets: context.targets
        .list({ organizationId: org })
        .filter(
          (t) =>
            t.classification === "LOCAL" &&
            t.authorizationType === "OWNED" &&
            new URL(t.baseOrigin).hostname === "127.0.0.1"
        ),
      credentials: context.vault
        .list(org)
        .filter((c) => c.enabled)
        .map((c) => ({
          id: c.id,
          targetId: c.targetId,
          alias: c.safeAlias,
          identity: {
            identityModel: c.safeIdentitySummary.identityModel ?? "TENANT_AWARE",
            principalId: c.safeIdentitySummary.principalId,
            tenantId: c.safeIdentitySummary.tenantId,
            role: c.safeIdentitySummary.role
          },
          expiresAt: c.expiresAt
        })),
      schemas: context.database.db
        .prepare(
          "SELECT id,target_id,created_at FROM application_schema_revisions WHERE organization_id=? ORDER BY created_at DESC LIMIT 100"
        )
        .all(org),
      comparisons: context.database.db
        .prepare(
          "SELECT id,baseline_revision_id,current_revision_id,created_at FROM application_map_comparisons WHERE organization_id=? ORDER BY created_at DESC LIMIT 100"
        )
        .all(org),
      acquisitions: context.database.db
        .prepare(
          "SELECT id,target_id,version,created_at FROM application_mapping_revisions WHERE organization_id=? ORDER BY created_at DESC LIMIT 100"
        )
        .all(org)
    });
    return true;
  }
  const match = /^\/api\/authorization-workbench\/mapping\/([a-f0-9-]{36})(?:\/(execute|bindings))?$/.exec(path);
  if (context.request.method === "GET" && match && !match[2]) {
    requirePermission(context, "credentials.readSummary");
    sendJson(context.response, 200, service.result(org, match[1]!));
    return true;
  }
  if (context.request.method !== "POST") throw new HttpError(404, "Mapping route not found");
  requirePermission(context, "scans.create");
  requirePermission(context, "credentials.use");
  resourceOrganization(context, "resources.use");
  if (path === base + "/preview" || path === base + "/acquisitions") {
    const input = applicationMappingInputSchema.parse(await readJson(context.request));
    requireSelectedResource(context, "target", input.targetId, "resources.use");
    for (const id of Object.values(input.credentials))
      requireSelectedResource(context, "credential", id, "resources.use");
    sendJson(
      context.response,
      path.endsWith("/preview") ? 200 : 201,
      path.endsWith("/preview")
        ? await service.preview(org, input)
        : await service.create(org, input, context.principal!.userId)
    );
    return true;
  }
  if (match) {
    const review = service.result(org, match[1]!);
    requireSelectedResource(context, "target", review.input.targetId, "resources.use");
    if (match[2] === "execute") {
      const input = applicationMappingExecuteSchema.parse(await readJson(context.request));
      sendJson(context.response, 202, await service.execute(org, match[1]!, input.digest, context.principal!.userId));
      return true;
    }
    if (match[2] === "bindings") {
      sendJson(
        context.response,
        201,
        await service.createMatrix(org, match[1]!, await readJson(context.request), context.principal!.userId)
      );
      return true;
    }
  }
  throw new HttpError(404, "Mapping route not found");
}
