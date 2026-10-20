import { ApplicationDiscoveryService } from "../execution/ApplicationDiscoveryService.js";
import { hypothesisSource } from "../execution/ApplicationHypothesisBinding.js";
import { discoveryProposalSchema } from "../contracts/ApplicationDiscoveryContracts.js";
import {
  readJson,
  sendJson,
  requirePermission,
  requireSelectedResource,
  resourceOrganization,
  type ApiContext
} from "./DashboardApiContext.js";
import { HttpError } from "./DashboardHttpSupport.js";
export async function handleApplicationDiscovery(context: ApiContext): Promise<boolean> {
  const base = "/api/authorization-workbench/mapping/discovery",
    path = context.url.pathname;
  if (path !== base && !path.startsWith(base + "/")) return false;
  requirePermission(context, "credentials.readSummary");
  const org = resourceOrganization(context),
    service = new ApplicationDiscoveryService(context.database),
    m = /^\/api\/authorization-workbench\/mapping\/discovery\/([a-f0-9-]{36})$/.exec(path);
  if (context.request.method === "GET" && m) {
    requirePermission(context, "scans.read");
    resourceOrganization(context, "org.read");
    const review = service.get(org, m[1]!);
    requireSelectedResource(context, "target", review.targetId, "org.read");
    for (const id of Object.values(review.credentials)) requireSelectedResource(context, "credential", id, "org.read");
    sendJson(context.response, 200, review);
    return true;
  }
  if (context.request.method === "POST" && path === base) {
    requirePermission(context, "scans.create");
    requirePermission(context, "credentials.use");
    resourceOrganization(context, "resources.use");
    const input = discoveryProposalSchema.parse(await readJson(context.request)),
      source = hypothesisSource(context.database, org, input.mapRevisionId);
    requireSelectedResource(context, "target", source.input.targetId, "resources.use");
    for (const id of Object.values(source.input.credentials))
      requireSelectedResource(context, "credential", id, "resources.use");
    sendJson(context.response, 201, service.create(org, input, context.principal!.userId));
    return true;
  }
  throw new HttpError(404, "Discovery review route not found");
}
