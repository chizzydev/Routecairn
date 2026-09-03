import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import type { AuthProfile } from "../../core/auth/AuthProfile.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import { securityContractFingerprint } from "../../core/comparisons/SecurityContractFingerprint.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { parseSafeFieldPath } from "../fieldExposureTesting/SafeFieldPath.js";
import type {
  ApiGraphqlActorPlan,
  ApiGraphqlCheckPlan,
  ApiGraphqlReviewPlan,
  ApiRequestPlan,
  ApiResponseContractPlan,
  ApiRouteSecurityPlan
} from "./ApiGraphqlTypes.js";

const maxFileBytes = 512 * 1024;
const identifier = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/);
const scalar = z.union([z.string().max(512), z.number().finite(), z.boolean(), z.null()]);
const actorSlot = z.enum(["anonymous", "primary", "account_a", "account_b"]);
const method = z.enum(["GET", "HEAD", "OPTIONS", "POST"]);
const statusList = z.array(z.number().int().min(100).max(599)).min(1).max(30);
const defaultAllowed = [200, 201, 202, 204] as const;
const defaultDenied = [400, 401, 403, 404, 405, 409, 422] as const;
const secretLiteral = /(?:bearer\s+[a-z0-9._~+/=-]+|authorization|session(?:id)?|password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key)/i;
const templateReference = /^\{\{(?:SECRET|CAPTURE):[A-Za-z0-9._-]+\}\}$/;

const actorSchema = z.object({
  id: identifier,
  safeAlias: z.string().min(1).max(80),
  authSlot: actorSlot,
  relationship: z.string().min(1).max(120),
  principalId: z.string().min(1).max(256).optional(),
  tenantId: z.string().min(1).max(256).optional(),
  role: z.string().min(1).max(120).optional()
}).strict();

const routeSchema = z.object({
  id: identifier,
  safeAlias: z.string().min(1).max(100),
  protocol: z.enum(["REST", "GRAPHQL"]),
  kind: z.enum(["OBJECT", "COLLECTION", "FUNCTION", "SCHEMA", "DOCUMENTATION"]),
  url: z.string().url().max(2048),
  pathTemplate: z.string().min(1).max(1000).optional(),
  version: z.string().min(1).max(40).optional(),
  objectType: z.string().min(1).max(100).optional(),
  functionName: z.string().min(1).max(120).optional(),
  documented: z.boolean().default(true),
  documentedMethods: z.array(method).min(1).max(4).default(["GET"]),
  documentedResponseFields: z.array(z.string().min(1).max(160)).max(100).default([]),
  schemaSourceId: identifier.optional(),
  schemaPath: z.string().min(1).max(1000).optional(),
  inventoryActorId: identifier.optional(),
  operatorConfirmedNonMutatingPost: z.boolean().default(false)
}).strict();

const fieldRuleSchema = z.object({
  path: z.string().min(1).max(160),
  classification: z.enum(["PUBLIC", "INTERNAL", "PERSONAL", "FINANCIAL", "SECRET", "TENANT_BOUND", "OBJECT_IDENTITY"]),
  expectation: z.enum(["MUST_BE_PRESENT", "MUST_BE_ABSENT", "MUST_BE_REDACTED", "OBSERVE"])
}).strict();

const responseSchema = z.object({
  expectedDecision: z.enum(["ALLOW", "DENY", "OBSERVE"]),
  allowedStatuses: statusList.default([...defaultAllowed]),
  deniedStatuses: statusList.default([...defaultDenied]),
  fieldRules: z.array(fieldRuleSchema).max(100).default([]),
  identity: z.object({ path: z.string().min(1).max(160), expectedValue: scalar }).strict().optional(),
  tenant: z.object({ path: z.string().min(1).max(160), expectedValue: scalar.optional(), forbiddenValues: z.array(scalar).max(20).default([]) }).strict().optional(),
  maxItems: z.number().int().min(1).max(1000).optional()
}).strict();

const graphqlOperationSchema = z.object({
  operationName: z.string().min(1).max(120).optional(),
  document: z.string().min(1).max(65536),
  variables: z.record(z.unknown()).default({})
}).strict();

const requestSchema = z.object({
  method: method.default("GET"),
  headers: z.record(z.string().max(1000)).default({}),
  body: z.unknown().optional(),
  graphql: graphqlOperationSchema.optional(),
  operatorConfirmedNonMutating: z.boolean().default(false),
  nonMutatingMarkerPath: z.string().min(1).max(160).optional(),
  nonMutatingMarkerValue: scalar.optional()
}).strict();

const authorizationCheckSchema = z.object({
  id: identifier,
  matrixId: identifier,
  label: z.string().min(1).max(180),
  kind: z.enum(["OBJECT_AUTHORIZATION", "FUNCTION_AUTHORIZATION", "FIELD_AUTHORIZATION", "TENANT_ISOLATION"]),
  routeId: identifier,
  actorId: identifier,
  requireVerifiedIdentity: z.boolean().default(true),
  request: requestSchema,
  response: responseSchema
}).strict();

const methodConfusionSchema = z.object({
  id: identifier,
  label: z.string().min(1).max(180),
  kind: z.literal("METHOD_CONFUSION"),
  routeId: identifier,
  actorId: identifier,
  requireVerifiedIdentity: z.boolean().default(true),
  canonicalMethod: method,
  alternateMethods: z.array(method).min(1).max(3),
  expectation: z.enum(["MUST_MATCH_CANONICAL", "ALTERNATES_MUST_DENY"]),
  request: requestSchema.omit({ method: true }),
  allowedStatuses: statusList.default([...defaultAllowed]),
  deniedStatuses: statusList.default([...defaultDenied])
}).strict();

const introspectionSchema = z.object({
  id: identifier,
  label: z.string().min(1).max(180),
  kind: z.literal("GRAPHQL_INTROSPECTION"),
  routeId: identifier,
  actorId: identifier,
  requireVerifiedIdentity: z.boolean().default(true),
  expectedClassification: z.enum(["DISABLED", "RESTRICTED", "AVAILABLE", "OBSERVE"])
}).strict();

const graphqlLimitSchema = z.object({
  id: identifier,
  label: z.string().min(1).max(180),
  kind: z.enum(["GRAPHQL_ALIAS_LIMIT", "GRAPHQL_BATCH_LIMIT"]),
  routeId: identifier,
  actorId: identifier,
  requireVerifiedIdentity: z.boolean().default(true),
  operationCount: z.number().int().min(2).max(10),
  documents: z.array(graphqlOperationSchema).min(1).max(10),
  expectation: z.enum(["MUST_REJECT", "MUST_ALLOW", "OBSERVE"]),
  allowedStatuses: statusList.default([...defaultAllowed]),
  deniedStatuses: statusList.default([...defaultDenied])
}).strict();

const versionBoundarySchema = z.object({
  id: identifier,
  label: z.string().min(1).max(180),
  kind: z.literal("VERSION_BOUNDARY"),
  baselineRouteId: identifier,
  candidateRouteId: identifier,
  actorId: identifier,
  requireVerifiedIdentity: z.boolean().default(true),
  request: requestSchema,
  expectation: z.enum(["MUST_MATCH_AUTHORIZATION", "CANDIDATE_MUST_NOT_EXPOSE_MORE_FIELDS", "MUST_MATCH_FIELD_SET"]),
  allowedStatuses: statusList.default([...defaultAllowed]),
  deniedStatuses: statusList.default([...defaultDenied])
}).strict();

const checkSchema = z.discriminatedUnion("kind", [authorizationCheckSchema, methodConfusionSchema, introspectionSchema, graphqlLimitSchema, versionBoundarySchema]);

export const apiGraphqlInputSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  maxRequests: z.number().int().min(1).max(300).default(60),
  maxResponseBytes: z.number().int().min(512).max(512 * 1024).default(65536),
  maxJsonDepth: z.number().int().min(2).max(24).default(12),
  maxGraphqlDocumentBytes: z.number().int().min(256).max(65536).default(16384),
  maxGraphqlAliases: z.number().int().min(2).max(10).default(5),
  maxGraphqlBatchOperations: z.number().int().min(2).max(5).default(3),
  actors: z.array(actorSchema).min(1).max(4),
  routes: z.array(routeSchema).min(1).max(100),
  checks: z.array(checkSchema).min(1).max(100)
}).strict();

export type ApiGraphqlInput = z.infer<typeof apiGraphqlInputSchema>;
type PlannerContext = { target: string; scope: RouteCairnScope; authProfile?: AuthProfile; authProfileSet?: AuthProfileSet };

export async function loadApiGraphqlInput(filePath: string): Promise<ApiGraphqlInput> {
  const raw = await readFile(filePath);
  if (raw.byteLength > maxFileBytes) throw new AppError(`API/GraphQL manifest exceeds ${maxFileBytes} bytes.`, "API_GRAPHQL_FILE_TOO_LARGE");
  let json: unknown;
  try { json = JSON.parse(raw.toString("utf8").replace(/^\uFEFF/, "")); }
  catch { throw new AppError("API/GraphQL manifest is not valid JSON.", "API_GRAPHQL_JSON_INVALID"); }
  const parsed = apiGraphqlInputSchema.safeParse(json);
  if (!parsed.success) throw new AppError(parsed.error.message, "API_GRAPHQL_INPUT_INVALID");
  return parsed.data;
}

export function planApiGraphqlReview(input: ApiGraphqlInput, context: PlannerContext): ApiGraphqlReviewPlan {
  const parsed = apiGraphqlInputSchema.parse(input);
  const origin = new URL(context.target).origin;
  const matcher = new ScopeMatcher(context.target, context.scope);
  ensureUnique(parsed.actors.map((value) => value.id), "actor");
  ensureUnique(parsed.routes.map((value) => value.id), "route");
  ensureUnique(parsed.checks.map((value) => value.id), "check");

  const actors = parsed.actors.map((value) => planActor(value, context));
  const actorIds = new Set(actors.map((value) => value.id));
  const routes = parsed.routes.map((value) => planRoute(value, matcher, origin));
  const routeById = new Map(routes.map((value) => [value.id, value]));
  validateSchemaReferences(routes, routeById);
  for (const route of routes) if (route.inventoryActorId && !actorIds.has(route.inventoryActorId)) throw new AppError(`Route ${route.id} references unknown inventory actor ${route.inventoryActorId}.`, "API_GRAPHQL_UNKNOWN_ACTOR");
  const checks = parsed.checks.map((value) => planCheck(value, routeById, actorIds, parsed));
  validateAuthorizationMatrices(checks);
  for (const check of checks) validateCheckScope(check, routeById, matcher);
  const requestCount = routes.filter((value) => value.kind === "SCHEMA" || value.kind === "DOCUMENTATION").length + checks.reduce((sum, value) => sum + requestCountFor(value), 0);
  if (requestCount > parsed.maxRequests) throw new AppError(`API/GraphQL plan requires ${requestCount} requests, exceeding maxRequests ${parsed.maxRequests}.`, "API_GRAPHQL_REQUEST_BUDGET_EXCEEDED");

  return deepFreeze({
    schemaVersion: 1,
    enabled: true,
    targetOrigin: origin,
    maxRequests: parsed.maxRequests,
    maxResponseBytes: parsed.maxResponseBytes,
    maxJsonDepth: parsed.maxJsonDepth,
    maxGraphqlDocumentBytes: parsed.maxGraphqlDocumentBytes,
    maxGraphqlAliases: parsed.maxGraphqlAliases,
    maxGraphqlBatchOperations: parsed.maxGraphqlBatchOperations,
    actors,
    routes,
    checks,
    notes: [
      "The route inventory and every authorization cell are explicit operator input; responses never generate new targets or operations.",
      "GraphQL execution is restricted to query operations, bounded aliases/batches, no redirects, and no retries.",
      "REST POST requires a route-level and check-level non-mutating attestation; mutations belong in controlled mutation or invariant plans."
    ]
  });
}

function planActor(value: ApiGraphqlInput["actors"][number], context: PlannerContext): ApiGraphqlActorPlan {
  const profile = value.authSlot === "primary" ? context.authProfile : value.authSlot === "account_a" ? context.authProfileSet?.accountA : value.authSlot === "account_b" ? context.authProfileSet?.accountB : undefined;
  if (value.authSlot === "anonymous") {
    if (value.principalId || value.tenantId || value.role) throw new AppError(`Anonymous actor ${value.id} must not declare authenticated identity metadata.`, "API_GRAPHQL_ANONYMOUS_METADATA_INVALID");
  } else if (value.authSlot === "primary" && !context.authProfile) throw new AppError(`Actor ${value.id} requires a primary auth profile.`, "API_GRAPHQL_AUTH_PROFILE_REQUIRED");
  else if ((value.authSlot === "account_a" || value.authSlot === "account_b") && !context.authProfileSet) throw new AppError(`Actor ${value.id} requires Account A/B profiles.`, "API_GRAPHQL_AUTH_PAIR_REQUIRED");
  if (value.principalId && profile?.principalId && value.principalId !== profile.principalId) throw new AppError(`Actor ${value.id} principal metadata does not match its auth profile.`, "API_GRAPHQL_PRINCIPAL_MISMATCH");
  if (value.tenantId && profile?.tenantId && value.tenantId !== profile.tenantId) throw new AppError(`Actor ${value.id} tenant metadata does not match its auth profile.`, "API_GRAPHQL_TENANT_MISMATCH");
  if (value.role && profile?.role && value.role !== profile.role) throw new AppError(`Actor ${value.id} role metadata does not match its auth profile.`, "API_GRAPHQL_ROLE_MISMATCH");
  const principalId = value.principalId ?? profile?.principalId; const tenantId = value.tenantId ?? profile?.tenantId; const role = value.role ?? profile?.role;
  return {
    id: value.id,
    safeAlias: value.safeAlias,
    authSlot: value.authSlot,
    relationship: value.relationship,
    ...(principalId ? { principalFingerprint: identityFingerprint(principalId) } : {}),
    ...(tenantId ? { tenantFingerprint: identityFingerprint(tenantId) } : {}),
    ...(role ? { role } : {})
  };
}

function planRoute(value: ApiGraphqlInput["routes"][number], matcher: ScopeMatcher, origin: string): ApiRouteSecurityPlan {
  const parsed = new URL(value.url);
  if (parsed.origin !== origin) throw new AppError(`Route ${value.id} must use the target origin.`, "API_GRAPHQL_CROSS_ORIGIN_ROUTE");
  for (const declaredMethod of value.documentedMethods) {
    const decision = matcher.decide(value.url, declaredMethod);
    if (!decision.allowed) throw new AppError(`Route ${value.id} method ${declaredMethod} is out of scope: ${decision.reason}.`, "API_GRAPHQL_ROUTE_OUT_OF_SCOPE");
  }
  if (value.protocol === "GRAPHQL" && value.kind === "SCHEMA") throw new AppError(`GraphQL route ${value.id} cannot be an OpenAPI schema source.`, "API_GRAPHQL_ROUTE_KIND_INVALID");
  if (value.kind === "OBJECT" && !value.objectType) throw new AppError(`Object route ${value.id} requires objectType.`, "API_GRAPHQL_OBJECT_TYPE_REQUIRED");
  if (value.kind === "OBJECT" && !value.pathTemplate) throw new AppError(`Object route ${value.id} requires a safe pathTemplate that omits the supplied object identifier.`, "API_GRAPHQL_PATH_TEMPLATE_REQUIRED");
  if (value.pathTemplate && (!value.pathTemplate.startsWith("/") || /[?#\r\n]/.test(value.pathTemplate) || /\{\{/.test(value.pathTemplate))) throw new AppError(`Route ${value.id} pathTemplate is invalid.`, "API_GRAPHQL_PATH_TEMPLATE_INVALID");
  if (value.kind === "FUNCTION" && !value.functionName) throw new AppError(`Function route ${value.id} requires functionName.`, "API_GRAPHQL_FUNCTION_NAME_REQUIRED");
  for (const path of value.documentedResponseFields) safePath(path);
  return {
    id: value.id,
    safeAlias: value.safeAlias,
    protocol: value.protocol,
    kind: value.kind,
    url: value.url,
    path: value.pathTemplate ?? parsed.pathname,
    ...(value.version ? { version: value.version } : {}),
    ...(value.objectType ? { objectType: value.objectType } : {}),
    ...(value.functionName ? { functionName: value.functionName } : {}),
    documented: value.documented,
    documentedMethods: [...new Set(value.documentedMethods)],
    documentedResponseFields: [...new Set(value.documentedResponseFields)],
    ...(value.schemaSourceId ? { schemaSourceId: value.schemaSourceId } : {}),
    ...(value.schemaPath ? { schemaPath: value.schemaPath } : {}),
    ...(value.inventoryActorId ? { inventoryActorId: value.inventoryActorId } : {}),
    operatorConfirmedNonMutatingPost: value.operatorConfirmedNonMutatingPost
  };
}

function planCheck(value: ApiGraphqlInput["checks"][number], routes: Map<string, ApiRouteSecurityPlan>, actors: Set<string>, limits: ApiGraphqlInput): ApiGraphqlCheckPlan {
  if (!actors.has(value.actorId)) throw new AppError(`Check ${value.id} references unknown actor ${value.actorId}.`, "API_GRAPHQL_UNKNOWN_ACTOR");
  const comparedRoutes = (value.kind === "VERSION_BOUNDARY" ? [value.baselineRouteId, value.candidateRouteId] : [value.routeId]).map((id) => requiredRoute(routes, id, value.id));
  const comparisonFingerprint = securityContractFingerprint("api-graphql-authorization", { check: value, routes: comparedRoutes, actor: limits.actors.find((actor) => actor.id === value.actorId) });
  if (value.kind === "VERSION_BOUNDARY") {
    const baseline = requiredRoute(routes, value.baselineRouteId, value.id); const candidate = requiredRoute(routes, value.candidateRouteId, value.id);
    if (!baseline.version || !candidate.version || baseline.version === candidate.version) throw new AppError(`Version check ${value.id} requires two distinct declared versions.`, "API_GRAPHQL_VERSION_PAIR_INVALID");
    if (baseline.protocol !== candidate.protocol) throw new AppError(`Version check ${value.id} must compare the same protocol.`, "API_GRAPHQL_VERSION_PROTOCOL_MISMATCH");
    const request = planRequest(value.request, baseline, limits);
    return { id: value.id, label: value.label, kind: value.kind, baselineRouteId: baseline.id, candidateRouteId: candidate.id, actorId: value.actorId, requireVerifiedIdentity: value.requireVerifiedIdentity, request, expectation: value.expectation, allowedStatuses: value.allowedStatuses, deniedStatuses: value.deniedStatuses, comparisonFingerprint };
  }
  const route = requiredRoute(routes, value.routeId, value.id);
  if (value.kind === "GRAPHQL_INTROSPECTION") {
    requireGraphql(route, value.id);
    return { ...value, comparisonFingerprint };
  }
  if (value.kind === "GRAPHQL_ALIAS_LIMIT" || value.kind === "GRAPHQL_BATCH_LIMIT") {
    requireGraphql(route, value.id);
    const bound = value.kind === "GRAPHQL_ALIAS_LIMIT" ? limits.maxGraphqlAliases : limits.maxGraphqlBatchOperations;
    if (value.operationCount > bound) throw new AppError(`Check ${value.id} exceeds the configured GraphQL ${value.kind === "GRAPHQL_ALIAS_LIMIT" ? "alias" : "batch"} bound.`, "API_GRAPHQL_OPERATION_BOUND_EXCEEDED");
    if (value.kind === "GRAPHQL_ALIAS_LIMIT" && value.documents.length !== 1) throw new AppError(`Alias check ${value.id} requires one fixed document.`, "API_GRAPHQL_ALIAS_DOCUMENT_INVALID");
    if (value.kind === "GRAPHQL_BATCH_LIMIT" && value.documents.length !== value.operationCount) throw new AppError(`Batch check ${value.id} operationCount must equal document count.`, "API_GRAPHQL_BATCH_DOCUMENT_INVALID");
    for (const operation of value.documents) validateGraphqlOperation(operation, limits.maxGraphqlDocumentBytes, value.id);
    if (value.kind === "GRAPHQL_ALIAS_LIMIT" && countAliases(value.documents[0]!.document) !== value.operationCount) throw new AppError(`Alias check ${value.id} declared count does not match its fixed document.`, "API_GRAPHQL_ALIAS_COUNT_MISMATCH");
    return { ...value, documents: value.documents.map((entry) => ({ document: entry.document, ...(entry.operationName ? { operationName: entry.operationName } : {}), variables: validateTemplateValue(entry.variables, `${value.id}.variables`) as Record<string, unknown> })), comparisonFingerprint };
  }
  if (value.kind === "METHOD_CONFUSION") {
    if (route.protocol !== "REST") throw new AppError(`Method confusion check ${value.id} requires a REST route.`, "API_GRAPHQL_METHOD_PROTOCOL_INVALID");
    if (new Set([value.canonicalMethod, ...value.alternateMethods]).size !== value.alternateMethods.length + 1) throw new AppError(`Method confusion check ${value.id} contains duplicate methods.`, "API_GRAPHQL_METHOD_DUPLICATE");
    for (const candidate of [value.canonicalMethod, ...value.alternateMethods]) validatePostSafety(candidate, value.request, route, value.id);
    const request = planRequest({ ...value.request, method: value.canonicalMethod }, route, limits);
    const { method: _method, ...withoutMethod } = request;
    return { id: value.id, label: value.label, kind: value.kind, routeId: route.id, actorId: value.actorId, requireVerifiedIdentity: value.requireVerifiedIdentity, canonicalMethod: value.canonicalMethod, alternateMethods: value.alternateMethods, expectation: value.expectation, request: withoutMethod, allowedStatuses: value.allowedStatuses, deniedStatuses: value.deniedStatuses, comparisonFingerprint };
  }
  const authorizationValue = value as z.infer<typeof authorizationCheckSchema>;
  if ((authorizationValue.kind === "OBJECT_AUTHORIZATION" && route.kind !== "OBJECT") || (authorizationValue.kind === "FUNCTION_AUTHORIZATION" && route.kind !== "FUNCTION")) throw new AppError(`Check ${authorizationValue.id} does not match route kind ${route.kind}.`, "API_GRAPHQL_CHECK_ROUTE_KIND_MISMATCH");
  const request = planRequest(authorizationValue.request, route, limits);
  const response = planResponse(authorizationValue.response);
  return { id: authorizationValue.id, matrixId: authorizationValue.matrixId, label: authorizationValue.label, kind: authorizationValue.kind, routeId: route.id, actorId: authorizationValue.actorId, requireVerifiedIdentity: authorizationValue.requireVerifiedIdentity, request, response, comparisonFingerprint };
}

function planRequest(value: z.infer<typeof requestSchema>, route: ApiRouteSecurityPlan, limits: ApiGraphqlInput): ApiRequestPlan {
  validatePostSafety(value.method, value, route, route.id);
  validateHeaders(value.headers, route.id);
  if (route.protocol === "GRAPHQL") {
    if (value.method !== "POST" || !value.graphql || value.body !== undefined) throw new AppError(`GraphQL route ${route.id} requires a fixed POST graphql operation.`, "API_GRAPHQL_REQUEST_SHAPE_INVALID");
    validateGraphqlOperation(value.graphql, limits.maxGraphqlDocumentBytes, route.id);
    return { method: "POST", headers: value.headers, graphql: { document: value.graphql.document, ...(value.graphql.operationName ? { operationName: value.graphql.operationName } : {}), variables: validateTemplateValue(value.graphql.variables, `${route.id}.variables`) as Record<string, unknown> } };
  }
  if (value.graphql) throw new AppError(`REST route ${route.id} cannot contain a GraphQL operation.`, "API_GRAPHQL_REQUEST_SHAPE_INVALID");
  if (value.method !== "POST" && value.body !== undefined) throw new AppError(`Request for ${route.id} may only carry a body with POST.`, "API_GRAPHQL_REQUEST_BODY_INVALID");
  const body = value.body === undefined ? undefined : validateTemplateValue(value.body, `${route.id}.body`);
  if (value.method === "POST" && value.nonMutatingMarkerPath) {
    safePath(value.nonMutatingMarkerPath);
    if (!hasExactPath(body, value.nonMutatingMarkerPath, value.nonMutatingMarkerValue)) throw new AppError(`POST request for ${route.id} is missing its exact non-mutating marker.`, "API_GRAPHQL_NON_MUTATING_MARKER_MISSING");
  }
  return { method: value.method, headers: value.headers, ...(body !== undefined ? { body } : {}) };
}

function planResponse(value: z.infer<typeof responseSchema>): ApiResponseContractPlan {
  ensureDisjoint(value.allowedStatuses, value.deniedStatuses, "response status sets");
  for (const rule of value.fieldRules) safePath(rule.path);
  if (value.identity) safePath(value.identity.path);
  if (value.tenant) safePath(value.tenant.path);
  return {
    expectedDecision: value.expectedDecision,
    allowedStatuses: value.allowedStatuses,
    deniedStatuses: value.deniedStatuses,
    fieldRules: value.fieldRules,
    ...(value.identity ? { identity: { ...value.identity, expectedFingerprint: fingerprint(String(value.identity.expectedValue), "identity") } } : {}),
    ...(value.tenant ? { tenant: { path: value.tenant.path, ...(value.tenant.expectedValue !== undefined ? { expectedValue: value.tenant.expectedValue, expectedFingerprint: fingerprint(String(value.tenant.expectedValue), "tenant") } : {}), forbiddenValues: value.tenant.forbiddenValues, forbiddenValueFingerprints: value.tenant.forbiddenValues.map((entry) => fingerprint(String(entry), "forbidden-tenant")) } } : {}),
    ...(value.maxItems ? { maxItems: value.maxItems } : {})
  };
}

function validatePostSafety(methodValue: string, request: { operatorConfirmedNonMutating: boolean; nonMutatingMarkerPath?: string | undefined; nonMutatingMarkerValue?: unknown }, route: ApiRouteSecurityPlan, checkId: string): void {
  if (methodValue !== "POST") return;
  if (route.protocol === "GRAPHQL") return;
  if (!route.operatorConfirmedNonMutatingPost || !request.operatorConfirmedNonMutating || !request.nonMutatingMarkerPath || request.nonMutatingMarkerValue === undefined) throw new AppError(`REST POST in ${checkId} requires route and request non-mutating attestations plus an exact body marker.`, "API_GRAPHQL_POST_SAFETY_REQUIRED");
}

function validateGraphqlOperation(value: { document: string; variables: Record<string, unknown> }, maxBytes: number, label: string): void {
  if (Buffer.byteLength(value.document, "utf8") > maxBytes) throw new AppError(`GraphQL document ${label} exceeds maxGraphqlDocumentBytes.`, "API_GRAPHQL_DOCUMENT_TOO_LARGE");
  const stripped = value.document.replace(/#[^\n\r]*/g, " ").replace(/"""[\s\S]*?"""/g, '""').trim();
  if (/\b(?:mutation|subscription)\b/i.test(stripped) || !/^(?:query\b|\{)/i.test(stripped)) throw new AppError(`GraphQL document ${label} must be a query operation.`, "API_GRAPHQL_MUTATION_FORBIDDEN");
  if (graphQlDepth(stripped) > 16) throw new AppError(`GraphQL document ${label} exceeds the hard depth bound.`, "API_GRAPHQL_DEPTH_EXCEEDED");
  validateTemplateValue(value.variables, `${label}.variables`);
}

function validateHeaders(headers: Record<string, string>, label: string): void {
  for (const [name, value] of Object.entries(headers)) {
    if (/^(?:authorization|cookie|proxy-authorization|x-api-key)$/i.test(name) || secretLiteral.test(value)) throw new AppError(`Request ${label} embeds authentication or secret-like headers.`, "API_GRAPHQL_SECRET_HEADER_FORBIDDEN");
    if (/[\r\n]/.test(name + value)) throw new AppError(`Request ${label} contains unsafe header characters.`, "API_GRAPHQL_HEADER_INVALID");
  }
}

function validateTemplateValue(value: unknown, label: string): unknown {
  if (Array.isArray(value)) return value.map((entry, index) => validateTemplateValue(entry, `${label}[${index}]`));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, validateTemplateValue(entry, `${label}.${key}`)]));
  if (typeof value === "string" && secretLiteral.test(value) && !templateReference.test(value)) throw new AppError(`${label} contains literal secret-like material; use a SECRET reference.`, "API_GRAPHQL_LITERAL_SECRET_FORBIDDEN");
  return value;
}

function validateSchemaReferences(routes: readonly ApiRouteSecurityPlan[], routeById: Map<string, ApiRouteSecurityPlan>): void {
  for (const route of routes) {
    if (!route.schemaSourceId) continue;
    const source = routeById.get(route.schemaSourceId);
    if (!source || (source.kind !== "SCHEMA" && source.kind !== "DOCUMENTATION") || source.protocol !== "REST") throw new AppError(`Route ${route.id} references an invalid schema source.`, "API_GRAPHQL_SCHEMA_SOURCE_INVALID");
    if (!route.schemaPath) throw new AppError(`Route ${route.id} with schemaSourceId requires schemaPath.`, "API_GRAPHQL_SCHEMA_PATH_REQUIRED");
  }
}

function requestCountFor(value: ApiGraphqlCheckPlan): number {
  if (value.kind === "METHOD_CONFUSION") return 1 + value.alternateMethods.length;
  if (value.kind === "VERSION_BOUNDARY") return 2;
  return 1;
}

function validateAuthorizationMatrices(checks: readonly ApiGraphqlCheckPlan[]): void {
  const cells = checks.filter((check): check is Extract<ApiGraphqlCheckPlan, { kind: "OBJECT_AUTHORIZATION" | "FUNCTION_AUTHORIZATION" | "FIELD_AUTHORIZATION" | "TENANT_ISOLATION" }> => "matrixId" in check);
  for (const matrixId of new Set(cells.map((cell) => cell.matrixId))) {
    const matrix = cells.filter((cell) => cell.matrixId === matrixId); const first = matrix[0]!;
    if (matrix.some((cell) => cell.kind !== first.kind || cell.routeId !== first.routeId)) throw new AppError(`Authorization matrix ${matrixId} must contain one check kind and route.`, "API_GRAPHQL_MATRIX_INCONSISTENT");
    if (new Set(matrix.map((cell) => cell.actorId)).size !== matrix.length) throw new AppError(`Authorization matrix ${matrixId} contains duplicate actor cells.`, "API_GRAPHQL_MATRIX_DUPLICATE_ACTOR");
  }
}

function validateCheckScope(check: ApiGraphqlCheckPlan, routes: Map<string, ApiRouteSecurityPlan>, matcher: ScopeMatcher): void {
  const targets: Array<{ route: ApiRouteSecurityPlan; methods: readonly string[] }> = check.kind === "VERSION_BOUNDARY"
    ? [{ route: routes.get(check.baselineRouteId)!, methods: [check.request.method] }, { route: routes.get(check.candidateRouteId)!, methods: [check.request.method] }]
    : check.kind === "METHOD_CONFUSION"
      ? [{ route: routes.get(check.routeId)!, methods: [check.canonicalMethod, ...check.alternateMethods] }]
      : check.kind === "GRAPHQL_INTROSPECTION" || check.kind === "GRAPHQL_ALIAS_LIMIT" || check.kind === "GRAPHQL_BATCH_LIMIT"
        ? [{ route: routes.get(check.routeId)!, methods: ["POST"] }]
        : "request" in check ? [{ route: routes.get(check.routeId)!, methods: [check.request.method] }] : [];
  for (const target of targets) for (const requestMethod of target.methods) {
    const decision = matcher.decide(target.route.url, requestMethod);
    if (!decision.allowed) throw new AppError(`Check ${check.id} method ${requestMethod} is out of scope: ${decision.reason}.`, "API_GRAPHQL_CHECK_OUT_OF_SCOPE");
  }
}

function requiredRoute(routes: Map<string, ApiRouteSecurityPlan>, id: string, checkId: string): ApiRouteSecurityPlan {
  const route = routes.get(id);
  if (!route) throw new AppError(`Check ${checkId} references unknown route ${id}.`, "API_GRAPHQL_UNKNOWN_ROUTE");
  return route;
}

function requireGraphql(route: ApiRouteSecurityPlan, checkId: string): void {
  if (route.protocol !== "GRAPHQL") throw new AppError(`Check ${checkId} requires a GraphQL route.`, "API_GRAPHQL_PROTOCOL_REQUIRED");
}

function graphQlDepth(document: string): number { let depth = 0; let maximum = 0; for (const character of document) { if (character === "{") maximum = Math.max(maximum, ++depth); else if (character === "}") depth -= 1; } return maximum; }
function countAliases(document: string): number { return (document.match(/(?:^|[\s{])[_A-Za-z][_0-9A-Za-z]*\s*:/g) ?? []).length; }
function safePath(path: string): void { parseSafeFieldPath(path, { maxDepth: 12, maxArrayIndex: 100, code: "API_GRAPHQL_FIELD_PATH_INVALID" }); }
function hasExactPath(value: unknown, path: string, expected: unknown): boolean { let current = value; for (const part of path.replace(/\[(\d+)\]/g, ".$1").split(".")) { if (!current || typeof current !== "object") return false; current = (current as Record<string, unknown>)[part]; } return JSON.stringify(current) === JSON.stringify(expected); }
function ensureDisjoint(left: readonly number[], right: readonly number[], label: string): void { if (left.some((value) => right.includes(value))) throw new AppError(`${label} must be disjoint.`, "API_GRAPHQL_STATUS_OVERLAP"); }
function ensureUnique(values: readonly string[], label: string): void { if (new Set(values).size !== values.length) throw new AppError(`API/GraphQL manifest contains duplicate ${label} IDs.`, "API_GRAPHQL_DUPLICATE_ID"); }
function fingerprint(value: string, domain: string): string { return createHash("sha256").update(`${domain}\0${value}`).digest("hex"); }
function identityFingerprint(value: string): string { return createHash("sha256").update("routecairn-identity-v1").update("\0").update(value).digest("hex").slice(0, 16); }
function deepFreeze<T>(value: T): T { if (value && typeof value === "object" && !Object.isFrozen(value)) { Object.freeze(value); for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child); } return value; }
