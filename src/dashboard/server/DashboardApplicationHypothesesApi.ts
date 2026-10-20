import { ApplicationAnalystHandoff } from "../execution/ApplicationAnalystHandoff.js";
import { ApplicationEvidenceTriage } from "../execution/ApplicationEvidenceTriage.js";
import { AuthorizationWorkbenchService } from "../execution/AuthorizationWorkbenchService.js";
import { ApplicationHypothesisService } from "../execution/ApplicationHypothesisService.js";
import { hypothesisGenerateSchema, hypothesisDecisionSchema } from "../contracts/ApplicationHypothesisContracts.js";
import { hypothesisProposal, hypothesisSource } from "../execution/ApplicationHypothesisBinding.js";
import {
  readJson,
  sendJson,
  requirePermission,
  resourceOrganization,
  requireSelectedResource,
  type ApiContext
} from "./DashboardApiContext.js";
import { HttpError } from "./DashboardHttpSupport.js";
export async function handleApplicationHypotheses(context: ApiContext): Promise<boolean> {
  const base = "/api/authorization-workbench/mapping/hypotheses",
    path = context.url.pathname;
  if (path !== base && !path.startsWith(base + "/")) return false;
  requirePermission(context, "credentials.readSummary");
  const org = resourceOrganization(context),
    service = new ApplicationHypothesisService(context.database, context.vault, context.execution),
    match =
      /^\/api\/authorization-workbench\/mapping\/hypotheses\/([a-f0-9-]{36})(?:\/(decisions|triage|triage-notes|history|handoff))?$/.exec(
        path
      );
  if (context.request.method === "GET") {
    if (path === base) {
      const id = context.url.searchParams.get("mapRevisionId");
      if (!id || !/^[a-f0-9-]{36}$/.test(id)) throw new HttpError(400, "Exact map revision required");
      const row = context.database.db
        .prepare("SELECT 1 FROM application_mapping_revisions WHERE id=? AND organization_id=?")
        .get(id, org);
      if (!row) throw new HttpError(404, "Map not found");
      sendJson(
        context.response,
        200,
        context.database.db
          .prepare(
            "SELECT id,digest,supersedes,created_at FROM application_hypothesis_proposals WHERE organization_id=? AND map_revision_id=? ORDER BY created_at DESC,id LIMIT 100"
          )
          .all(org, id)
      );
      return true;
    }
    if (match && (match[2] === "history" || match[2] === "handoff")) {
      const workbench = new AuthorizationWorkbenchService(context.database, context.vault, context.execution),
        triage = new ApplicationEvidenceTriage(context.database, service, workbench),
        handoff = new ApplicationAnalystHandoff(context.database, triage, workbench);
      sendJson(
        context.response,
        200,
        match[2] === "handoff"
          ? handoff.export(org, match[1]!)
          : handoff.page(org, match[1]!, Object.fromEntries(context.url.searchParams))
      );
      return true;
    }
    if (match?.[2] === "triage") {
      sendJson(
        context.response,
        200,
        new ApplicationEvidenceTriage(
          context.database,
          service,
          new AuthorizationWorkbenchService(context.database, context.vault, context.execution)
        ).get(org, match[1]!)
      );
      return true;
    }
    if (match && !match[2]) {
      sendJson(context.response, 200, service.get(org, match[1]!));
      return true;
    }
    throw new HttpError(404, "Hypothesis route not found");
  }
  if (context.request.method !== "POST") throw new HttpError(404, "Hypothesis route not found");
  requirePermission(context, "scans.create");
  requirePermission(context, "credentials.use");
  resourceOrganization(context, "resources.use");
  const allow = (source: ReturnType<typeof hypothesisSource>) => {
    requireSelectedResource(context, "target", source.input.targetId, "resources.use");
    for (const id of Object.values(source.input.credentials))
      requireSelectedResource(context, "credential", id, "resources.use");
  };
  if (path === base) {
    const input = hypothesisGenerateSchema.parse(await readJson(context.request));
    allow(hypothesisSource(context.database, org, input.mapRevisionId));
    if (input.transition) allow(hypothesisSource(context.database, org, input.transition.beforeMapRevisionId));
    sendJson(context.response, 201, service.generate(org, input, context.principal!.userId));
    return true;
  }
  if (match?.[2] === "triage-notes") {
    const p = hypothesisProposal(context.database, org, match[1]!);
    allow(hypothesisSource(context.database, org, p.row.map_revision_id!));
    sendJson(
      context.response,
      201,
      new ApplicationEvidenceTriage(
        context.database,
        service,
        new AuthorizationWorkbenchService(context.database, context.vault, context.execution)
      ).note(org, match[1]!, await readJson(context.request), context.principal!.userId)
    );
    return true;
  }
  if (match?.[2] === "decisions") {
    const p = hypothesisProposal(context.database, org, match[1]!);
    allow(hypothesisSource(context.database, org, p.row.map_revision_id!));
    sendJson(
      context.response,
      201,
      await service.decide(
        org,
        match[1]!,
        hypothesisDecisionSchema.parse(await readJson(context.request)),
        context.principal!.userId
      )
    );
    return true;
  }
  throw new HttpError(404, "Hypothesis route not found");
}
