import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { HttpMethod, HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { ApiProbeEndpointReview, ApiProbeReport } from "../../reports/ReportTypes.js";

const safeMethods: readonly HttpMethod[] = ["OPTIONS", "HEAD", "GET"];

export class ApiProbeModule implements RouteCairnPlugin {
  public readonly name = "api-probe";
  public readonly description = "Safely probes API behavior with OPTIONS, HEAD, GET, schema hints, and evidence-gated GraphQL checks.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await probeApis(context);
    return { pluginName: this.name, apiProbe: report, notes: report.notes };
  }
}

async function probeApis(context: ScanContext): Promise<ApiProbeReport> {
  const settings = context.moduleSettings("api-probe");
  const methods = settings.safeMethods ?? safeMethods;
  const endpoints = candidateEndpoints(context).slice(0, settings.maxEndpoints ?? 40);
  const client = context.createHttpClient();
  const reviews: ApiProbeEndpointReview[] = [];

  for (const endpoint of endpoints) {
    const decision = context.scopeMatcher.decide(endpoint, "GET");
    context.state.recordScopeDecision(decision);
    if (!decision.allowed || !decision.normalizedUrl) continue;

    const responses = new Map<HttpMethod, HttpResponse>();
    for (const method of methods) responses.set(method, await client.send({ url: decision.normalizedUrl, method }));

    const getResponse = responses.get("GET");
    const optionResponse = responses.get("OPTIONS");
    const graphqlEvidence = hasGraphQlEvidence(endpoint, getResponse);
    const graphQlIntrospection = graphqlEvidence ? detectGraphQlIntrospection(getResponse) : { attempted: false as const, available: false, evidence: "GraphQL probing skipped because endpoint evidence was insufficient." };

    reviews.push({
      endpoint: decision.normalizedUrl,
      methodsTested: [...methods],
      statusByMethod: Object.fromEntries([...responses.entries()].map(([method, response]) => [method, response.statusCode ?? "error"])),
      contentTypes: unique([...responses.values()].map((response) => response.contentType).filter((value): value is string => Boolean(value))),
      allowedMethods: allowedMethods(optionResponse),
      corsHints: corsHints(optionResponse),
      schemaHints: schemaHints(endpoint, getResponse),
      graphQl: graphQlIntrospection,
      notes: notesForEndpoint(endpoint, responses, graphqlEvidence)
    });
  }

  return {
    safeMethods: [...methods],
    skippedMethods: ["POST", "PUT", "PATCH", "DELETE"],
    endpointsReviewed: reviews,
    schemaHints: unique(reviews.flatMap((review) => review.schemaHints)),
    graphQlEndpoints: reviews.filter((review) => review.graphQl.attempted).map((review) => review.endpoint),
    notes: [
      "API probing used OPTIONS, HEAD, and safe GET only.",
      "POST, PUT, PATCH, and DELETE are intentionally skipped to avoid mutating application state.",
      "GraphQL introspection is reported only when endpoint evidence suggests real GraphQL behavior.",
      "API probe output is behavior intelligence, not confirmed vulnerability evidence."
    ]
  };
}

function candidateEndpoints(context: ScanContext): string[] {
  const urls = new Set<string>();
  for (const endpoint of context.state.getApiMapper()?.endpoints ?? []) urls.add(endpoint.endpoint);
  for (const review of context.state.getStateAwareApi()?.reviewedEndpoints ?? []) urls.add(review.endpoint);
  for (const observation of context.state.getDiscoveredUrls()) if (observation.falsePositiveStatus !== "likely-false-positive" && isApiLike(observation.url)) urls.add(observation.url);
  return [...urls].sort();
}

function isApiLike(url: string): boolean {
  try {
    const parsed = new URL(url);
    return /\/(api|graphql|openapi|swagger|schema)(?:\/|$)/i.test(parsed.pathname) || /\.(?:json)$/i.test(parsed.pathname);
  } catch {
    return false;
  }
}

function allowedMethods(response: HttpResponse | undefined): string[] {
  const headers = response ? headersForAnalysis(response) : {};
  return splitMethods(headerValue(headers, "allow") ?? headerValue(headers, "access-control-allow-methods"));
}

function corsHints(response: HttpResponse | undefined): string[] {
  const headers = response ? headersForAnalysis(response) : {};
  const hints = [
    headerValue(headers, "access-control-allow-origin") ? `allow-origin=${headerValue(headers, "access-control-allow-origin")}` : undefined,
    headerValue(headers, "access-control-allow-credentials") ? `allow-credentials=${headerValue(headers, "access-control-allow-credentials")}` : undefined,
    headerValue(headers, "access-control-allow-methods") ? `allow-methods=${headerValue(headers, "access-control-allow-methods")}` : undefined,
    headerValue(headers, "access-control-allow-headers") ? `allow-headers=${headerValue(headers, "access-control-allow-headers")}` : undefined
  ];
  return hints.filter((value): value is string => Boolean(value));
}

function schemaHints(endpoint: string, response: HttpResponse | undefined): string[] {
  const hints = new Set<string>();
  const path = new URL(endpoint).pathname.toLowerCase();
  const body = response ? bodyPreviewForAnalysis(response) ?? "" : "";
  const type = response?.contentType ?? "";
  if (/openapi|swagger|api-docs/.test(path) || /"openapi"\s*:|"swagger"\s*:/i.test(body)) hints.add("openapi");
  if (/graphql/.test(path) || /graphql|__schema|__typename/i.test(body)) hints.add("graphql");
  if (/json/i.test(type)) hints.add("json");
  if (/application\/schema\+json/i.test(type) || /"\$schema"\s*:/i.test(body)) hints.add("json-schema");
  return [...hints].sort();
}

function hasGraphQlEvidence(endpoint: string, response: HttpResponse | undefined): boolean {
  return schemaHints(endpoint, response).includes("graphql");
}

function detectGraphQlIntrospection(response: HttpResponse | undefined): ApiProbeEndpointReview["graphQl"] {
  const body = response ? bodyPreviewForAnalysis(response) ?? "" : "";
  if (/__schema|__type|IntrospectionQuery|queryType|mutationType/i.test(body)) {
    return { attempted: true, available: true, evidence: "GET response contained GraphQL introspection-like fields." };
  }
  if (/graphql/i.test(body) || /application\/graphql|application\/json/i.test(response?.contentType ?? "")) {
    return { attempted: true, available: false, evidence: "GraphQL-like endpoint observed, but safe GET response did not expose introspection fields." };
  }
  return { attempted: false, available: false, evidence: "GraphQL probing skipped because endpoint evidence was insufficient." };
}

function notesForEndpoint(endpoint: string, responses: Map<HttpMethod, HttpResponse>, graphqlEvidence: boolean): string[] {
  const notes = [`Safe methods tested: ${[...responses.keys()].join(", ")}.`];
  const allow = allowedMethods(responses.get("OPTIONS"));
  if (allow.length > 0) notes.push(`Allowed methods advertised: ${allow.join(", ")}.`);
  if (schemaHints(endpoint, responses.get("GET")).length > 0) notes.push(`Schema/content hints: ${schemaHints(endpoint, responses.get("GET")).join(", ")}.`);
  if (!graphqlEvidence) notes.push("GraphQL-specific probing skipped; endpoint did not look like GraphQL.");
  return notes;
}

function splitMethods(value: string | undefined): string[] {
  return unique((value ?? "").split(/[,\s]+/).map((item) => item.trim().toUpperCase()).filter(Boolean));
}

function headerValue(headers: Readonly<Record<string, string | readonly string[]>>, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  return typeof value === "string" ? value : value?.join(", ");
}

function unique(values: string[]): string[] {
  return [...new Set(values)].sort();
}
