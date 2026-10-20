import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { ApplicationMappingInput } from "../contracts/ApplicationMappingContracts.js";
import { ApplicationDiscoveryService } from "./ApplicationDiscoveryService.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
export function assertApplicationDiscoveryBinding(db: DashboardDatabase, org: string, input: ApplicationMappingInput) {
  const b = input.discoveryBinding;
  if (!b) return;
  const p = new ApplicationDiscoveryService(db).fresh(org, b.proposalId);
  if (
    input.schemaBinding ||
    p.digest !== b.digest ||
    p.targetId !== input.targetId ||
    adaptiveDigest(p.credentials) !== adaptiveDigest(input.credentials)
  )
    throw Error("WORKBENCH_DISCOVERY_EXACT_CONTEXT_REQUIRED");
  if (
    b.selections.length !== input.routes.length ||
    new Set(b.selections.map((s) => s.routeId)).size !== input.routes.length ||
    new Set(b.selections.map((s) => s.candidateId)).size !== input.routes.length
  )
    throw Error("WORKBENCH_DISCOVERY_EXACT_SELECTION_REQUIRED");
  for (const r of input.routes) {
    const s = b.selections.find((s) => s.routeId === r.id),
      c = p.candidates.find((c) => c.candidateId === s?.candidateId);
    if (!c || r.url !== c.url || r.method !== "GET") throw Error("WORKBENCH_DISCOVERY_EXACT_SELECTION_REQUIRED");
  }
  if (4 + 4 * input.routes.length > p.requestCeiling) throw Error("WORKBENCH_DISCOVERY_REQUEST_BUDGET");
  return { globalRequests: 4 + 4 * input.routes.length, engineRequests: 4 * input.routes.length };
}
