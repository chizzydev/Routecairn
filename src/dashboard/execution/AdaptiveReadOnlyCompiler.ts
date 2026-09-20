import { createHash } from "node:crypto";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { apiGraphqlInputSchema } from "../../modules/apiGraphql/ApiGraphqlPlanner.js";
import { billingEntitlementInputSchema } from "../../modules/billingEntitlement/BillingEntitlementPlanner.js";
import { businessInvariantInputSchema } from "../../modules/businessInvariant/BusinessInvariantPlanner.js";
import { operationalEndpointSecurityInputSchema } from "../../modules/operationalEndpointSecurity/OperationalEndpointSecurityPlanner.js";
import { supabaseAuthorizationInputSchema } from "../../modules/supabaseAuthorization/SupabaseAuthorizationPlanner.js";

export interface AdaptiveRouteEvidence {
  protocol: "REST" | "GRAPHQL";
  method: string;
  pathTemplate: string;
  source: string;
  stateChanging: boolean;
}

export interface AdaptiveSupabaseEvidence {
  surface: string;
  resource: string;
  operations: string[];
  actors: string[];
}

export interface AdaptiveCompiledReadOnlyCase {
  engineId: "api-graphql-authorization" | "operational-endpoint-security" | "billing-entitlement-security" | "business-invariant" | "supabase-authorization";
  engineConfiguration: Record<string, unknown>;
  requestCount: number;
  evidenceStrength: "EXACT_ANONYMOUS_RESPONSE" | "EXACT_ENGINE_OBSERVATION";
  evidenceFingerprint: string;
  summary: string;
}

/**
 * Converts only exact, stable, credential-free observations into executable
 * engine input. The compiler never guesses identifiers, GraphQL documents,
 * actors, tenant relationships, expected object ownership, or mutation data.
 */
export function compileRouteReadOnlyCase(report: RouteCairnReport, route: AdaptiveRouteEvidence): AdaptiveCompiledReadOnlyCase | undefined {
  if (route.stateChanging || !["GET", "HEAD", "OPTIONS"].includes(route.method)) return;
  const url = executableUrl(report.target, route.pathTemplate);
  if (!url) return;
  const observed = exactAnonymousObservation(report, url, route.method);
  if (!observed) return;
  const id = `adaptive-rest-${digest(`${route.method}:${url.pathname}`).slice(0, 16)}`;
  const expectedDecision = decisionFor(observed.statusCode);
  const configuration = apiGraphqlInputSchema.parse({
    schemaVersion: 1,
    maxRequests: 1,
    maxResponseBytes: 65_536,
    maxJsonDepth: 12,
    maxGraphqlDocumentBytes: 16_384,
    maxGraphqlAliases: 5,
    maxGraphqlBatchOperations: 3,
    actors: [{ id: "anonymous", safeAlias: "Anonymous", authSlot: "anonymous", relationship: "PUBLIC" }],
    routes: [{ id: `${id}-route`, safeAlias: "Observed public route", protocol: "REST", kind: "FUNCTION", url: url.toString(), pathTemplate: url.pathname, documented: route.source === "api-graphql-inventory", documentedMethods: [route.method] }],
    checks: [{
      id,
      matrixId: `${id}-matrix`,
      label: `Revalidate the observed ${route.method} authorization boundary`,
      kind: "FUNCTION_AUTHORIZATION",
      routeId: `${id}-route`,
      actorId: "anonymous",
      requireVerifiedIdentity: false,
      request: { method: route.method },
      response: responseContract(observed.statusCode, expectedDecision)
    }]
  }) as Record<string, unknown>;
  return compiled("api-graphql-authorization", configuration, 1, "EXACT_ANONYMOUS_RESPONSE", {
    method: route.method,
    url: url.toString(),
    statusCode: observed.statusCode,
    bodyHash: observed.bodyHash,
    auditOutcome: observed.auditOutcome
  }, "Exact anonymous REST observation compiled into a status-bound authorization regression case.");
}

export function compileGraphqlIntrospectionCase(report: RouteCairnReport, path: string): AdaptiveCompiledReadOnlyCase | undefined {
  const url = executableUrl(report.target, path);
  if (!url) return;
  const observed = exactAnonymousObservation(report, url, "POST");
  const prior = report.apiGraphql?.checks.find((check) => check.kind === "GRAPHQL_INTROSPECTION" && check.routeAliases.some((alias) => report.apiGraphql?.inventory.some((route) => route.safeAlias === alias && route.path === url.pathname)));
  if (!observed && !prior) return;
  const expectedClassification = prior?.introspectionClassification && prior.introspectionClassification !== "INCONCLUSIVE" ? prior.introspectionClassification : "OBSERVE";
  const id = `adaptive-graphql-${digest(url.pathname).slice(0, 16)}`;
  const configuration = apiGraphqlInputSchema.parse({
    schemaVersion: 1,
    maxRequests: 1,
    maxResponseBytes: 65_536,
    maxJsonDepth: 12,
    maxGraphqlDocumentBytes: 16_384,
    maxGraphqlAliases: 5,
    maxGraphqlBatchOperations: 3,
    actors: [{ id: "anonymous", safeAlias: "Anonymous", authSlot: "anonymous", relationship: "PUBLIC" }],
    routes: [{ id: `${id}-route`, safeAlias: "Observed GraphQL endpoint", protocol: "GRAPHQL", kind: "FUNCTION", url: url.toString(), pathTemplate: url.pathname, documented: false, documentedMethods: ["POST"] }],
    checks: [{ id, label: "Revalidate the anonymous GraphQL introspection boundary", kind: "GRAPHQL_INTROSPECTION", routeId: `${id}-route`, actorId: "anonymous", requireVerifiedIdentity: false, expectedClassification }]
  }) as Record<string, unknown>;
  return compiled("api-graphql-authorization", configuration, 1, "EXACT_ANONYMOUS_RESPONSE", {
    url: url.toString(),
    statusCode: observed?.statusCode,
    priorClassification: prior?.introspectionClassification ?? "UNAVAILABLE",
    priorFingerprint: prior?.comparisonFingerprint
  }, "Observed GraphQL endpoint compiled into a generated, read-only introspection classification case.");
}

export function compileOperationalHealthCase(report: RouteCairnReport, route: AdaptiveRouteEvidence): AdaptiveCompiledReadOnlyCase | undefined {
  if (!/\/(?:health|healthz|status|ready|readiness|live|liveness)\/?$/i.test(route.pathTemplate) || !["GET", "HEAD"].includes(route.method) || route.stateChanging) return;
  const url = executableUrl(report.target, route.pathTemplate);
  if (!url) return;
  const observed = exactAnonymousObservation(report, url, route.method);
  if (!observed || !observed.contentType?.toLowerCase().includes("json")) return;
  const id = `adaptive-health-${digest(`${route.method}:${url.pathname}`).slice(0, 16)}`;
  const assertions: Array<Record<string, unknown>> = [
    { kind: "STATUS_IN", values: [observed.statusCode] },
    ...["databaseUrl", "databasePassword", "stack", "environment", "secrets", "privateKey"].map((path) => ({ kind: "JSON_FIELD_ABSENT", path, classification: path === "stack" || path === "environment" ? "INTERNAL" : "SECRET" }))
  ];
  const configuration = operationalEndpointSecurityInputSchema.parse({
    schemaVersion: 1,
    maxCases: 1,
    maxStepsPerCase: 1,
    maxRequests: 1,
    maxResponseBytes: 65_536,
    actors: [{ id: "public", safeAlias: "Public", authSlot: "anonymous", relationship: "PUBLIC" }],
    endpoints: [{ id: `${id}-endpoint`, safeAlias: "Observed health endpoint", kind: "HEALTH", pathTemplate: url.pathname, allowedOrigins: [url.origin] }],
    cases: [{ id, label: "Revalidate health endpoint information exposure", category: "HEALTH_INFORMATION_EXPOSURE", authorization: { mode: "OBSERVE_ONLY", environment: "PRODUCTION" }, cleanupRequired: false, steps: [{ id: "observe", phase: "VERIFY", actorId: "public", endpointId: `${id}-endpoint`, request: { method: route.method, urlTemplate: url.toString(), stateChanging: false, secretSource: "anonymous", headers: {} }, assertions }] }]
  }) as Record<string, unknown>;
  return compiled("operational-endpoint-security", configuration, 1, "EXACT_ANONYMOUS_RESPONSE", {
    method: route.method,
    url: url.toString(),
    statusCode: observed.statusCode,
    bodyHash: observed.bodyHash,
    contentType: observed.contentType
  }, "Exact public JSON health response compiled into status and sensitive-field-absence assertions.");
}

export function compileSupabaseReadOnlyCase(report: RouteCairnReport, resource: AdaptiveSupabaseEvidence): AdaptiveCompiledReadOnlyCase | undefined {
  const observation = report.supabaseAuthorization?.observations.find((item) => item.resource === resource.resource && item.operation === "SELECT" && item.actor === "ANONYMOUS" && ["GET", "HEAD"].includes(item.method));
  const projectOrigin = report.supabaseAuthorization?.projectOrigin;
  if (!observation || !projectOrigin) return;
  const url = safeSupabaseUrl(projectOrigin, observation.url);
  if (!url) return;
  const expectedDecision = observation.expectedDecision;
  const configured = report.scanPlan.supabaseAuthorization;
  const anonKeyEnv = configured?.anonKeyEnv ?? "SUPABASE_ANON_KEY";
  const id = `adaptive-supabase-${digest(`${resource.surface}:${resource.resource}:${url.pathname}${url.search}`).slice(0, 16)}`;
  const configuration = supabaseAuthorizationInputSchema.parse({
    schemaVersion: 1,
    projectUrl: new URL(projectOrigin).origin,
    anonKeyEnv,
    maxCases: 1,
    maxResponseBytes: 131_072,
    maxSignedUrlBytes: 8_192,
    cases: [{ id, surface: resource.surface, resource: resource.resource, operation: "SELECT", actor: "ANONYMOUS", expectedDecision, boundary: executableSupabaseBoundary(observation.boundary), method: observation.method, url: `${url.pathname}${url.search}`, headers: {}, responseShape: "LIST", identityAssertions: [], forbiddenColumns: [], requireVerifiedIdentity: false }],
    catalog: { exposedSchemas: ["public"], expectedExposedSchemas: ["public"], tables: [], functions: [], storageBuckets: [], relationships: [] }
  }) as Record<string, unknown>;
  return compiled("supabase-authorization", configuration, 1, "EXACT_ENGINE_OBSERVATION", {
    comparisonFingerprint: observation.comparisonFingerprint,
    observedDecision: observation.observedDecision,
    expectedDecision,
    statusCode: observation.statusCode,
    resource: resource.resource,
    url: `${url.pathname}${url.search}`
  }, "Exact anonymous Supabase SELECT observation compiled into a decision-bound regression case.");
}

/**
 * Billing observations are safe to replay only when the discovery was an
 * exact anonymous read. The generated case uses OBSERVE_ONLY and never
 * declares a fixture mutation, payment event, or cleanup step.
 */
export function compileBillingReadOnlyCase(report: RouteCairnReport, route: AdaptiveRouteEvidence): AdaptiveCompiledReadOnlyCase | undefined {
  if (route.stateChanging || !["GET", "HEAD"].includes(route.method)) return;
  const url = executableUrl(report.target, route.pathTemplate);
  if (!url || !/(?:checkout|billing|payment|subscription|plan|entitlement|premium|refund|invoice)/i.test(url.pathname)) return;
  const observed = exactAnonymousObservation(report, url, route.method);
  if (!observed?.contentType || observed.statusCode < 200 || observed.statusCode >= 300) return;
  const endpointKind = /premium/i.test(url.pathname) ? "PREMIUM_ACCESS" : /subscription/i.test(url.pathname) ? "SUBSCRIPTION_STATE" : "ENTITLEMENT_STATE";
  const category = endpointKind === "PREMIUM_ACCESS" ? "CROSS_ACCOUNT_PREMIUM_ACCESS" : "CANCELLATION_ENTITLEMENT_PERSISTENCE";
  const dimension = endpointKind === "PREMIUM_ACCESS" ? "ACCESS" : endpointKind === "SUBSCRIPTION_STATE" ? "SUBSCRIPTION_STATUS" : "ENTITLEMENT";
  const id = `adaptive-billing-${digest(`${route.method}:${url.pathname}`).slice(0, 16)}`;
  const configuration = billingEntitlementInputSchema.parse({
    schemaVersion: 1,
    maxCases: 1,
    maxRequests: 1,
    maxResponseBytes: 65_536,
    maxConcurrency: 2,
    provider: { kind: "CUSTOM_SYNTHETIC", mode: "LOCAL_EMULATOR", fixturePathPrefix: "/__routecairn__/adaptive-fixtures", realPaymentExecution: "FORBIDDEN" },
    actors: [{ id: "anonymous", safeAlias: "Anonymous", authSlot: "anonymous", relationship: "PUBLIC", sendAuthentication: false }],
    endpoints: [{ id: `${id}-endpoint`, safeAlias: "Observed billing read endpoint", kind: endpointKind, pathTemplate: url.pathname, allowedOrigins: [url.origin] }],
    cases: [{
      id,
      label: "Revalidate the observed anonymous billing state response",
      category,
      authorization: { mode: "OBSERVE_ONLY", environment: "STAGING", disposableFixtures: false },
      cleanupRequired: false,
      steps: [{ id: "observe", phase: "VERIFY", actorId: "anonymous", endpointId: `${id}-endpoint`, operation: "OBSERVE", request: { method: route.method, urlTemplate: url.toString(), stateChanging: false, secretSource: "anonymous", headers: {} }, execution: { mode: "ONCE", attempts: 1, maxDispatchSkewMs: 250 }, captures: [{ name: "contentType", source: "HEADER", header: "content-type" }] }],
      assertions: [{ id: "content-type-stable", scope: "MAIN", kind: "VALUE_EQUALS_LITERAL", dimension, capture: "contentType", expected: observed.contentType }]
    }]
  }) as Record<string, unknown>;
  return compiled("billing-entitlement-security", configuration, 1, "EXACT_ANONYMOUS_RESPONSE", {
    method: route.method, url: url.toString(), statusCode: observed.statusCode, bodyHash: observed.bodyHash, contentType: observed.contentType
  }, "Exact anonymous billing or entitlement observation compiled into an OBSERVE_ONLY regression case.");
}

/**
 * A business-invariant read-only case compares two credential-free state
 * observations. It is intentionally limited to stable paths and a captured
 * response header; no action, object identifier, or cleanup contract is
 * invented from discovery metadata.
 */
export function compileBusinessInvariantReadOnlyCase(report: RouteCairnReport, route: AdaptiveRouteEvidence): AdaptiveCompiledReadOnlyCase | undefined {
  if (route.stateChanging || !["GET", "HEAD"].includes(route.method)) return;
  const url = executableUrl(report.target, route.pathTemplate);
  if (!url || !/(?:state|balance|entitlement|subscription|order|cart|quota|limit|invoice|account|profile)/i.test(url.pathname)) return;
  const observed = exactAnonymousObservation(report, url, route.method);
  if (!observed?.contentType || observed.statusCode < 200 || observed.statusCode >= 300) return;
  const id = `adaptive-invariant-${digest(`${route.method}:${url.pathname}`).slice(0, 16)}`;
  const configuration = businessInvariantInputSchema.parse({
    schemaVersion: 1,
    maxCases: 1,
    maxRequests: 2,
    maxResponseBytes: 65_536,
    maxConcurrency: 1,
    cases: [{
      id,
      label: "Revalidate stable anonymous business state observation",
      category: "CUSTOM",
      actors: [{ id: "anonymous", safeAlias: "Anonymous", authSlot: "anonymous", requestAuthentication: "NONE", relationship: "PUBLIC", declaredState: "OBSERVED" }],
      authorization: { mode: "OBSERVE_ONLY", environment: "PRODUCTION" },
      preState: [{ id: "before", actorId: "anonymous", request: { method: route.method, url: url.toString(), stateChanging: false, headers: {} }, captures: [{ name: "contentTypeBefore", source: "HEADER", header: "content-type" }] }],
      actions: [],
      postState: [{ id: "after", actorId: "anonymous", request: { method: route.method, url: url.toString(), stateChanging: false, headers: {} }, captures: [{ name: "contentTypeAfter", source: "HEADER", header: "content-type" }] }],
      invariants: [{ id: "content-type-stable", kind: "VALUE_COMPARE", left: { source: "CAPTURE", ref: "contentTypeBefore" }, operator: "EQ", right: { source: "CAPTURE", ref: "contentTypeAfter" } }],
      cleanupRequired: false,
      cleanup: [],
      cleanupVerification: [],
      cleanupInvariants: []
    }]
  }) as Record<string, unknown>;
  return compiled("business-invariant", configuration, 2, "EXACT_ANONYMOUS_RESPONSE", {
    method: route.method, url: url.toString(), statusCode: observed.statusCode, bodyHash: observed.bodyHash, contentType: observed.contentType
  }, "Exact anonymous state observations compiled into a read-only business-invariant stability case.");
}

function compiled(engineId: AdaptiveCompiledReadOnlyCase["engineId"], engineConfiguration: Record<string, unknown>, requestCount: number, evidenceStrength: AdaptiveCompiledReadOnlyCase["evidenceStrength"], evidence: unknown, summary: string): AdaptiveCompiledReadOnlyCase {
  return { engineId, engineConfiguration, requestCount, evidenceStrength, evidenceFingerprint: digest(evidence), summary };
}

function exactAnonymousObservation(report: RouteCairnReport, url: URL, method: string): { statusCode: number; bodyHash?: string; contentType?: string; auditOutcome: string } | undefined {
  const audit = report.requestAudit.find((item) => item.method.toUpperCase() === method && sameUrl(item.requestedUrl, url.toString()) && item.outcome === "sent" && !Object.keys(item.requestHeaders).some((name) => /^(?:authorization|cookie|proxy-authorization|x-api-key|apikey)$/i.test(name)));
  if (!audit) return;
  const response = report.responses.find((item) => item.method === method && sameUrl(item.requestedUrl, url.toString()) && item.statusCode !== undefined);
  if (!response?.statusCode) return;
  return { statusCode: response.statusCode, ...(response.bodyHash ? { bodyHash: response.bodyHash } : {}), ...(response.contentType ? { contentType: response.contentType } : {}), auditOutcome: audit.outcome };
}

function responseContract(statusCode: number, expectedDecision: "ALLOW" | "DENY" | "OBSERVE"): Record<string, unknown> {
  const standardAllowed = [200, 201, 202, 204, 206, 304];
  const standardDenied = [400, 401, 403, 404, 405, 409, 410, 422, 429];
  const allowedStatuses = unique(expectedDecision === "ALLOW" ? [statusCode, ...standardAllowed] : standardAllowed.filter((value) => value !== statusCode));
  const deniedStatuses = unique(expectedDecision === "DENY" ? [statusCode, ...standardDenied] : standardDenied.filter((value) => value !== statusCode));
  return { expectedDecision, allowedStatuses, deniedStatuses, fieldRules: [] };
}

function decisionFor(status: number): "ALLOW" | "DENY" | "OBSERVE" {
  if ([401, 403, 404, 405, 410].includes(status)) return "DENY";
  if ((status >= 200 && status < 400) || status === 206) return "ALLOW";
  return "OBSERVE";
}

function executableUrl(target: string, path: string): URL | undefined {
  try {
    const targetUrl = new URL(target);
    const value = new URL(path, targetUrl.origin);
    if (value.origin !== targetUrl.origin || value.username || value.password || value.search || value.hash || value.pathname !== path || !isStablePath(value.pathname)) return;
    return value;
  } catch { return; }
}

function safeSupabaseUrl(origin: string, raw: string): URL | undefined {
  try {
    const value = new URL(raw, origin);
    if (value.origin !== new URL(origin).origin || value.username || value.password || !isStablePath(value.pathname)) return;
    for (const [name, candidate] of value.searchParams) {
      if (!["select", "limit", "offset", "order"].includes(name) || candidate.length > 160 || /(?:bearer|token|secret|password|signature|@)/i.test(candidate)) return;
    }
    return value;
  } catch { return; }
}

function isStablePath(path: string): boolean {
  if (!path.startsWith("/") || /[%\\;]|\/\//.test(path) || path.split("/").some((part) => part === "." || part === ".." || /^\d{2,}$/.test(part) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(part) || /^[A-Za-z0-9_-]{32,}$/.test(part) || part === ":id" || part === ":token")) return false;
  return path.length <= 500;
}

function sameUrl(left: string, right: string): boolean {
  try { const a = new URL(left); const b = new URL(right); return a.origin === b.origin && a.pathname === b.pathname && a.search === b.search; }
  catch { return false; }
}

function unique(values: readonly number[]): number[] { return [...new Set(values)]; }
function executableSupabaseBoundary(value: string): "NONE" | "CROSS_USER" | "CROSS_TENANT" | "SERVICE_ROLE" { return ["CROSS_USER", "CROSS_TENANT", "SERVICE_ROLE"].includes(value) ? value as "CROSS_USER" | "CROSS_TENANT" | "SERVICE_ROLE" : "NONE"; }
function digest(value: unknown): string { return createHash("sha256").update(JSON.stringify(sort(value))).digest("hex"); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (!value || typeof value !== "object") return value; return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, child]) => [key, sort(child)])); }
