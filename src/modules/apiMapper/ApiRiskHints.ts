import type { ApiEndpointAnalysis } from "../../reports/ReportTypes.js";

export function apiMapperNotes(endpoints: ApiEndpointAnalysis[]): string[] {
  const notes: string[] = [];

  if (endpoints.length === 0) {
    return ["No API endpoints were classified."];
  }

  const graphQlCount = endpoints.filter((endpoint) => endpoint.routeType === "graphql").length;
  const objectIdCount = endpoints.filter((endpoint) => endpoint.hasObjectId).length;
  const highRateLimitCount = endpoints.filter((endpoint) => endpoint.rateLimitSensitivity === "high").length;

  notes.push(`API endpoints classified: ${endpoints.length}.`);

  if (graphQlCount > 0) {
    notes.push(`GraphQL endpoints detected: ${graphQlCount}.`);
  }

  if (objectIdCount > 0) {
    notes.push(`Endpoints with object identifiers detected: ${objectIdCount}.`);
  }

  if (highRateLimitCount > 0) {
    notes.push(`Endpoints with high rate-limit testing relevance: ${highRateLimitCount}.`);
  }

  return notes;
}
