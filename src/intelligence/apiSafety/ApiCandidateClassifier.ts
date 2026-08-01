import type { ApiEndpointAnalysis } from "../../reports/ReportTypes.js";

export type StateAwareApiCandidateReason = "object-id" | "export-download" | "graphql" | "auth-relevant" | "sensitive-data" | "admin-like";

export interface StateAwareApiCandidate {
  endpoint: string;
  routeType: string;
  reasons: StateAwareApiCandidateReason[];
  priority: "low" | "medium" | "high";
}

export function classifyStateAwareApiCandidate(endpoint: ApiEndpointAnalysis): StateAwareApiCandidate | undefined {
  const reasons = new Set<StateAwareApiCandidateReason>();
  const lowered = endpoint.endpoint.toLowerCase();

  if (endpoint.hasObjectId || endpoint.riskTags.includes("object-id")) {
    reasons.add("object-id");
  }

  if (/\b(export|download|invoice|receipt|statement|report)\b/.test(lowered) || endpoint.riskTags.includes("export")) {
    reasons.add("export-download");
  }

  if (endpoint.routeType === "graphql") {
    reasons.add("graphql");
  }

  if (endpoint.authRelevance !== "low") {
    reasons.add("auth-relevant");
  }

  if (endpoint.dataExposureSensitivity !== "low") {
    reasons.add("sensitive-data");
  }

  if (/\b(admin|internal|manage|settings|account|user|users|tenant|org|organization)\b/.test(lowered)) {
    reasons.add("admin-like");
  }

  if (reasons.size === 0) {
    return undefined;
  }

  const priority = reasons.has("object-id") || reasons.has("export-download") || reasons.has("sensitive-data") ? "high" : reasons.has("auth-relevant") || reasons.has("admin-like") ? "medium" : "low";

  return {
    endpoint: endpoint.endpoint,
    routeType: endpoint.routeType,
    reasons: [...reasons],
    priority
  };
}
