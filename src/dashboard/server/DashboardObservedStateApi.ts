import { ObservedStateRegressionService } from "../execution/ObservedStateRegressionService.js";
import { observedStateDraftSchema, observedStateDecisionSchema } from "../contracts/ObservedStateContracts.js";
import {
  requirePermission,
  requireSelectedResource,
  resourceOrganization,
  readJson,
  sendJson,
  type ApiContext
} from "./DashboardApiContext.js";
import { HttpError } from "./DashboardHttpSupport.js";
export async function handleObservedState(context: ApiContext): Promise<boolean> {
  const base = "/api/authorization-workbench/observed-state",
    path = context.url.pathname;
  if (path !== base && !path.startsWith(base + "/")) return false;
  requirePermission(context, "scans.read");
  requirePermission(context, "credentials.readSummary");
  requirePermission(context, "comparisons.read");
  const org = resourceOrganization(context),
    service = new ObservedStateRegressionService(context.database);
  const policy =
    /^\/api\/authorization-workbench\/observed-state\/policies\/([a-f0-9-]{36})(?:\/(decisions|assessments))?$/.exec(
      path
    );
  const assessment = /^\/api\/authorization-workbench\/observed-state\/assessments\/([a-f0-9-]{36})$/.exec(path);
  if (context.request.method === "GET") {
    if (path === base + "/policies") {
      let canReviewPolicies = false;
      try {
        requirePermission(context, "controlledMutation.approve");
        resourceOrganization(context, "resources.use");
        canReviewPolicies = true;
      } catch {
        /* Advisory capability fails closed; actions still recheck exact resources. */
      }
      sendJson(context.response, 200, { policies: service.list(org), canReviewPolicies });
      return true;
    }
    if (policy) {
      const p = service.get(org, policy[1]!);
      if (policy[2] === "decisions") throw new HttpError(404, "Read decisions through immutable policy history");
      if (policy[2] === "assessments") {
        const ids = context.database.db
          .prepare(
            "SELECT id FROM application_observation_assessments WHERE policy_version_id=? ORDER BY created_at DESC,id LIMIT 50"
          )
          .all(p.id) as { id: string }[];
        sendJson(context.response, 200, { assessments: ids.map((r) => service.assessment(org, r.id)) });
      } else sendJson(context.response, 200, p);
      return true;
    }
    if (assessment) {
      sendJson(context.response, 200, service.assessment(org, assessment[1]!));
      return true;
    }
    if (path === base + "/attention") {
      const rows = context.database.db
        .prepare(
          "SELECT n.id,n.category,n.severity,n.safe_summary,n.acknowledged_at,r.id run_id,r.policy_id,r.gate_status,r.safe_summary_json,r.created_at FROM continuous_assurance_notifications n JOIN continuous_assurance_runs r ON r.id=n.run_id JOIN continuous_assurance_policies p ON p.id=r.policy_id JOIN targets t ON t.id=p.target_id WHERE t.organization_id=? AND json_extract(r.safe_summary_json,'$.scope')='OBSERVED_STATE_POLICY_ONLY' AND (n.acknowledged_at IS NULL OR r.id=(SELECT x.id FROM continuous_assurance_runs x WHERE x.policy_id=r.policy_id ORDER BY x.created_at DESC,x.id DESC LIMIT 1)) ORDER BY n.created_at DESC,n.id LIMIT 100"
        )
        .all(org) as Array<Record<string, string>>;
      sendJson(context.response, 200, {
        alerts: rows.map((r) => ({ ...r, summary: JSON.parse(r.safe_summary_json!), safe_summary_json: undefined })),
        policiesConfigured: service.list(org).length,
        stateChangeAuthorizationAssessment: "NOT_TESTED",
        verifiedApplicationPass: false,
        automaticReplay: false
      });
      return true;
    }
    throw new HttpError(404, "Observed-state route not found");
  }
  if (context.request.method !== "POST") throw new HttpError(404, "Observed-state route not found");
  requirePermission(context, "controlledMutation.approve");
  resourceOrganization(context, "resources.use");
  const allow = (p: ReturnType<ObservedStateRegressionService["preview"]>) => {
    requireSelectedResource(context, "target", p.snapshot.expectations.targetId, "resources.use");
    requireSelectedResource(context, "scan", p.snapshot.expectations.sourceScanId, "resources.use");
    for (const id of Object.values(p.snapshot.expectations.credentials))
      if (id) requireSelectedResource(context, "credential", id, "resources.use");
  };
  if (path === base + "/preview" || path === base + "/policies") {
    requirePermission(context, "credentials.use");
    const input = observedStateDraftSchema.parse(await readJson(context.request)),
      p = service.preview(org, input);
    allow(p);
    sendJson(
      context.response,
      path.endsWith("/preview") ? 200 : 201,
      path.endsWith("/preview") ? p : service.create(org, input, context.principal!.userId)
    );
    return true;
  }
  if (policy?.[2] === "decisions") {
    const input = observedStateDecisionSchema.parse(await readJson(context.request)),
      p = service.get(org, policy[1]!);
    requireSelectedResource(context, "target", p.targetId, "resources.use");
    if (input.action === "APPROVE") {
      requirePermission(context, "credentials.use");
      allow(service.preview(org, p.snapshot.input));
    }
    sendJson(context.response, 201, service.decide(org, p.id, input, context.principal!.userId));
    return true;
  }
  throw new HttpError(404, "Observed-state route not found");
}
