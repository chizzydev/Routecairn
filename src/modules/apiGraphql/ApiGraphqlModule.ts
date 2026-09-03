import { createHash } from "node:crypto";
import { authHeadersForProfile, authenticationLifecycleSecrets } from "../../core/auth/AuthProfile.js";
import type { AuthProfile } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { Finding } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import { securityContractFingerprint } from "../../core/comparisons/SecurityContractFingerprint.js";
import type { HttpRequest, HttpResponse } from "../../core/http/HttpTypes.js";
import type { RequestSafetyBroker } from "../../core/http/RequestSafetyBroker.js";
import { bodyPreviewForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type {
  ApiAuthorizationMatrixObservation,
  ApiFieldExposureObservation,
  ApiGraphqlCheckObservation,
  ApiGraphqlReviewReport,
  ApiRequestObservation,
  ApiRouteInventoryObservation,
  ApiSchemaComparisonObservation
} from "../../reports/ApiGraphqlReport.js";
import type {
  ApiGraphqlActorPlan,
  ApiGraphqlCheckPlan,
  ApiGraphqlOutcome,
  ApiGraphqlReviewPlan,
  ApiRequestPlan,
  ApiResponseContractPlan,
  ApiRouteSecurityPlan,
  GraphqlLimitCheckPlan,
  MethodConfusionCheckPlan,
  VersionBoundaryCheckPlan
} from "./ApiGraphqlTypes.js";

const introspectionDocument = "query RouteCairnIntrospection { __schema { queryType { name } mutationType { name } types { name kind } } }";

interface Snapshot {
  response: HttpResponse;
  statusCode?: number;
  json?: unknown;
  fields: Set<string>;
  bodyShapeFingerprint: string;
  fieldSetFingerprint: string;
  itemCount?: number;
  graphqlErrors: number;
  graphqlHasData: boolean;
}

export class ApiGraphqlModule implements RouteCairnPlugin {
  public readonly name = "api-graphql-authorization";
  public readonly description = "Executes explicit REST and GraphQL authorization matrices, schema comparisons, method checks, and bounded GraphQL controls.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const plan = context.options.plan.apiGraphql;
    if (!plan?.enabled) return { pluginName: this.name, apiGraphql: disabledReport() };
    const transport = context.createApiGraphqlHttpClient(plan.maxRequests, plan.maxResponseBytes);
    const schemas = await loadSchemas(context, transport, plan);
    const schemaComparisons = compareSchemas(plan, schemas);
    const checks: ApiGraphqlCheckObservation[] = [];
    for (const check of plan.checks) checks.push(await executeCheck(context, transport, plan, check));
    const inventory = inventoryReport(plan, checks);
    const report = buildReport(plan, inventory, checks, schemaComparisons, schemas.size);
    context.state.recordApiGraphql(report);
    return { pluginName: this.name, apiGraphql: report, findings: findingsFrom(report), notes: [...report.notes] };
  }
}

async function executeCheck(context: ScanContext, transport: RequestSafetyBroker, plan: ApiGraphqlReviewPlan, check: ApiGraphqlCheckPlan): Promise<ApiGraphqlCheckObservation> {
  const actor = plan.actors.find((value) => value.id === check.actorId)!;
  const routeMap = new Map(plan.routes.map((value) => [value.id, value]));
  const routeIds = check.kind === "VERSION_BOUNDARY" ? [check.baselineRouteId, check.candidateRouteId] : [check.routeId];
  const routes = routeIds.map((id) => routeMap.get(id)!);
  if (identityBlocked(context, actor, check.requireVerifiedIdentity)) return blocked(check, actor, routes, "VERIFIED_IDENTITY_REQUIRED");
  try {
    if (check.kind === "METHOD_CONFUSION") return executeMethodCheck(context, transport, check, actor, routes[0]!);
    if (check.kind === "GRAPHQL_INTROSPECTION") return executeIntrospection(context, transport, check, actor, routes[0]!);
    if (check.kind === "GRAPHQL_ALIAS_LIMIT" || check.kind === "GRAPHQL_BATCH_LIMIT") return executeLimit(context, transport, check, actor, routes[0]!);
    if (check.kind === "VERSION_BOUNDARY") return executeVersion(context, transport, check, actor, routes[0]!, routes[1]!);
    const authorizationCheck = check as Extract<ApiGraphqlCheckPlan, { kind: "OBJECT_AUTHORIZATION" | "FUNCTION_AUTHORIZATION" | "FIELD_AUTHORIZATION" | "TENANT_ISOLATION" }>;
    const snapshot = await send(context, transport, actor, routes[0]!, authorizationCheck.request);
    return authorizationObservation(authorizationCheck, actor, routes[0]!, snapshot);
  } catch {
    return inconclusive(check, actor, routes, "TRANSPORT_OR_CAPTURE_FAILURE");
  }
}

async function executeMethodCheck(context: ScanContext, transport: RequestSafetyBroker, check: MethodConfusionCheckPlan, actor: ApiGraphqlActorPlan, route: ApiRouteSecurityPlan): Promise<ApiGraphqlCheckObservation> {
  const methods = [check.canonicalMethod, ...check.alternateMethods];
  const snapshots: Snapshot[] = [];
  for (const method of methods) snapshots.push(await send(context, transport, actor, route, { ...check.request, method }));
  const decisions = snapshots.map((snapshot) => decision(snapshot, check.allowedStatuses, check.deniedStatuses));
  if (decisions.includes("UNCLASSIFIED")) return baseObservation(check, actor, [route], "INCONCLUSIVE", "METHOD_RESPONSE_UNCLASSIFIED", snapshots.map((value, index) => requestObservation(methods[index]!, value, decisions[index]!, route)));
  const canonical = decisions[0];
  const matched = check.expectation === "MUST_MATCH_CANONICAL" ? decisions.slice(1).every((value) => value === canonical) : decisions.slice(1).every((value) => value === "DENIED");
  return baseObservation(check, actor, [route], matched ? "PASS" : "FAIL", matched ? "METHOD_POLICY_MATCHED" : "METHOD_CONFUSION_CONFIRMED", snapshots.map((value, index) => requestObservation(methods[index]!, value, decisions[index]!, route)));
}

async function executeIntrospection(context: ScanContext, transport: RequestSafetyBroker, check: Extract<ApiGraphqlCheckPlan, { kind: "GRAPHQL_INTROSPECTION" }>, actor: ApiGraphqlActorPlan, route: ApiRouteSecurityPlan): Promise<ApiGraphqlCheckObservation> {
  const snapshot = await send(context, transport, actor, route, { method: "POST", headers: {}, graphql: { operationName: "RouteCairnIntrospection", document: introspectionDocument, variables: {} } });
  const schema = at(snapshot.json, "data.__schema");
  const classification = schema && typeof schema === "object" ? "AVAILABLE" : snapshot.graphqlErrors > 0 ? "RESTRICTED" : snapshot.statusCode === 404 || snapshot.statusCode === 405 ? "DISABLED" : "INCONCLUSIVE";
  const matched = check.expectedClassification === "OBSERVE" || check.expectedClassification === classification;
  const outcome: ApiGraphqlOutcome = classification === "INCONCLUSIVE" ? "INCONCLUSIVE" : matched ? "PASS" : "FAIL";
  return { ...baseObservation(check, actor, [route], outcome, outcome === "PASS" ? "INTROSPECTION_EXPECTATION_MATCHED" : outcome === "FAIL" ? "INTROSPECTION_EXPECTATION_CONTRADICTED" : "INTROSPECTION_UNCLASSIFIED", [requestObservation("introspection", snapshot, schema ? "ALLOWED" : snapshot.graphqlErrors ? "DENIED" : "UNCLASSIFIED", route)]), introspectionClassification: classification };
}

async function executeLimit(context: ScanContext, transport: RequestSafetyBroker, check: GraphqlLimitCheckPlan, actor: ApiGraphqlActorPlan, route: ApiRouteSecurityPlan): Promise<ApiGraphqlCheckObservation> {
  const body = check.kind === "GRAPHQL_BATCH_LIMIT"
    ? check.documents.map((value) => graphqlBody(value, profileFor(context, actor)))
    : graphqlBody(check.documents[0]!, profileFor(context, actor));
  const snapshot = await sendBody(context, transport, actor, route, body, {});
  const observed = decision(snapshot, check.allowedStatuses, check.deniedStatuses);
  const matched = check.expectation === "OBSERVE" || (check.expectation === "MUST_REJECT" ? observed === "DENIED" : observed === "ALLOWED");
  const outcome: ApiGraphqlOutcome = observed === "UNCLASSIFIED" ? "INCONCLUSIVE" : matched ? "PASS" : "FAIL";
  return { ...baseObservation(check, actor, [route], outcome, outcome === "PASS" ? "GRAPHQL_LIMIT_EXPECTATION_MATCHED" : outcome === "FAIL" ? "GRAPHQL_LIMIT_NOT_ENFORCED" : "GRAPHQL_LIMIT_UNCLASSIFIED", [requestObservation(check.kind === "GRAPHQL_BATCH_LIMIT" ? "batch" : "aliases", snapshot, observed, route)]), operationCount: check.operationCount };
}

async function executeVersion(context: ScanContext, transport: RequestSafetyBroker, check: VersionBoundaryCheckPlan, actor: ApiGraphqlActorPlan, baselineRoute: ApiRouteSecurityPlan, candidateRoute: ApiRouteSecurityPlan): Promise<ApiGraphqlCheckObservation> {
  const baseline = await send(context, transport, actor, baselineRoute, check.request); const candidate = await send(context, transport, actor, candidateRoute, check.request);
  const baselineDecision = decision(baseline, check.allowedStatuses, check.deniedStatuses); const candidateDecision = decision(candidate, check.allowedStatuses, check.deniedStatuses);
  if (baselineDecision === "UNCLASSIFIED" || candidateDecision === "UNCLASSIFIED") return baseObservation(check, actor, [baselineRoute, candidateRoute], "INCONCLUSIVE", "VERSION_RESPONSE_UNCLASSIFIED", [requestObservation("baseline", baseline, baselineDecision, baselineRoute), requestObservation("candidate", candidate, candidateDecision, candidateRoute)]);
  const extraFields = [...candidate.fields].filter((field) => !baseline.fields.has(field));
  const matched = check.expectation === "MUST_MATCH_AUTHORIZATION" ? baselineDecision === candidateDecision : check.expectation === "MUST_MATCH_FIELD_SET" ? baseline.fieldSetFingerprint === candidate.fieldSetFingerprint : extraFields.length === 0;
  return baseObservation(check, actor, [baselineRoute, candidateRoute], matched ? "PASS" : "FAIL", matched ? "VERSION_BOUNDARY_MATCHED" : "VERSION_BOUNDARY_REGRESSION", [requestObservation("baseline", baseline, baselineDecision, baselineRoute), requestObservation("candidate", candidate, candidateDecision, candidateRoute)], [], extraFields.length ? [`Candidate exposed ${extraFields.length} field path(s) absent from the baseline; names omitted.`] : []);
}

function authorizationObservation(check: Extract<ApiGraphqlCheckPlan, { kind: "OBJECT_AUTHORIZATION" | "FUNCTION_AUTHORIZATION" | "FIELD_AUTHORIZATION" | "TENANT_ISOLATION" }>, actor: ApiGraphqlActorPlan, route: ApiRouteSecurityPlan, snapshot: Snapshot): ApiGraphqlCheckObservation {
  const observedDecision = decision(snapshot, check.response.allowedStatuses, check.response.deniedStatuses);
  if (observedDecision === "UNCLASSIFIED") return baseObservation(check, actor, [route], "INCONCLUSIVE", "AUTHORIZATION_RESPONSE_UNCLASSIFIED", [requestObservation("authorization", snapshot, observedDecision, route)]);
  const decisionMatched = check.response.expectedDecision === "OBSERVE" || (check.response.expectedDecision === "ALLOW" ? observedDecision === "ALLOWED" : observedDecision === "DENIED");
  const fields = check.response.fieldRules.map((rule) => fieldObservation(rule, snapshot.json));
  const fieldsMatched = fields.every((value) => value.outcome === "PASS");
  const identityConfirmed = check.response.identity ? equal(at(snapshot.json, check.response.identity.path), check.response.identity.expectedValue) : undefined;
  const tenant = tenantMatched(check.response, snapshot.json);
  const itemBoundMatched = check.response.maxItems === undefined || snapshot.itemCount === undefined || snapshot.itemCount <= check.response.maxItems;
  const observable = observedDecision === "ALLOWED";
  const assertionsMatched = (!observable || identityConfirmed !== false) && (!observable || tenant !== false) && fieldsMatched && itemBoundMatched;
  const matched = decisionMatched && assertionsMatched;
  return {
    ...baseObservation(check, actor, [route], matched ? "PASS" : "FAIL", matched ? "AUTHORIZATION_CONTRACT_MATCHED" : reasonForAuthorizationFailure(check.kind, decisionMatched, fieldsMatched, identityConfirmed, tenant, itemBoundMatched), [requestObservation("authorization", snapshot, observedDecision, route)], fields),
    ...(identityConfirmed !== undefined ? { objectIdentityConfirmed: identityConfirmed } : {}),
    ...(tenant !== undefined ? { tenantBoundaryConfirmed: tenant } : {})
  };
}

async function send(context: ScanContext, transport: RequestSafetyBroker, actor: ApiGraphqlActorPlan, route: ApiRouteSecurityPlan, request: ApiRequestPlan): Promise<Snapshot> {
  const profile = profileFor(context, actor);
  const body = request.graphql ? graphqlBody(request.graphql, profile) : request.body === undefined ? undefined : expand(request.body, profile);
  return sendBody(context, transport, actor, route, body, request.headers, request.method);
}

async function sendBody(context: ScanContext, transport: RequestSafetyBroker, actor: ApiGraphqlActorPlan, route: ApiRouteSecurityPlan, body: unknown, headers: Readonly<Record<string, string>>, method: ApiRequestPlan["method"] = "POST"): Promise<Snapshot> {
  const profile = profileFor(context, actor); const merged = { ...(profile ? authHeadersForProfile(profile) : {}), ...headers };
  let encodedBody: string | undefined;
  if (body !== undefined) { encodedBody = JSON.stringify(body); setHeader(merged, "Content-Type", "application/json"); }
  const request: HttpRequest = { url: route.url, method, headers: merged, ...(encodedBody !== undefined ? { body: encodedBody } : {}), skipCache: true, disableRetries: true, disableRedirects: true, retainBodyPreview: true };
  return snapshot(await transport.send(request), context.options.plan.apiGraphql?.maxJsonDepth ?? 12);
}

function snapshot(response: HttpResponse, maxDepth: number): Snapshot {
  const body = bodyPreviewForAnalysis(response) ?? ""; let json: unknown;
  try { json = JSON.parse(body); } catch { json = undefined; }
  const fields = json === undefined ? new Set<string>() : fieldPaths(json, "", new Set<string>(), 0, maxDepth);
  const shape = jsonShape(json, 0, maxDepth);
  const root = json && typeof json === "object" && "data" in (json as Record<string, unknown>) ? (json as Record<string, unknown>).data : json;
  const itemCount = Array.isArray(root) ? root.length : undefined;
  return { response, ...(response.statusCode !== undefined ? { statusCode: response.statusCode } : {}), ...(json !== undefined ? { json } : {}), fields, bodyShapeFingerprint: hash(JSON.stringify(shape)), fieldSetFingerprint: hash([...fields].sort().join("\n")), ...(itemCount !== undefined ? { itemCount } : {}), graphqlErrors: graphqlErrorCount(json), graphqlHasData: graphqlDataPresent(json) };
}

function decision(value: Snapshot, allowed: readonly number[], denied: readonly number[]): "ALLOWED" | "DENIED" | "UNCLASSIFIED" {
  if (denied.includes(value.statusCode ?? 0)) return "DENIED";
  if (value.graphqlErrors > 0 && !value.graphqlHasData) return "DENIED";
  if (allowed.includes(value.statusCode ?? 0)) return "ALLOWED";
  return "UNCLASSIFIED";
}

function requestObservation(label: string, value: Snapshot, observedDecision: "ALLOWED" | "DENIED" | "UNCLASSIFIED", route: ApiRouteSecurityPlan): ApiRequestObservation {
  const documented = route.documentedResponseFields; const present = documented.filter((path) => value.fields.has(path)).length; const missing = documented.length - present; const undocumented = documented.length ? [...value.fields].filter((path) => !documented.includes(path)).length : 0;
  return { label, method: value.response.method, ...(value.statusCode !== undefined ? { statusCode: value.statusCode } : {}), decision: observedDecision, bodyShapeFingerprint: value.bodyShapeFingerprint, fieldSetFingerprint: value.fieldSetFingerprint, fieldCount: value.fields.size, ...(value.itemCount !== undefined ? { itemCount: value.itemCount } : {}), graphqlErrors: value.graphqlErrors, ...(documented.length ? { documentedFieldsPresent: present, documentedFieldsMissing: missing, undocumentedFieldsObserved: undocumented } : {}) };
}

function fieldObservation(rule: ApiResponseContractPlan["fieldRules"][number], json: unknown): ApiFieldExposureObservation {
  const value = at(json, rule.path); const present = value !== undefined; const redacted = present && (value === null || value === "" || (typeof value === "string" && /^(?:redacted|masked|\*+)$/i.test(value)));
  const observed = !present ? "ABSENT" : redacted ? "REDACTED" : "PRESENT";
  const matched = rule.expectation === "OBSERVE" || (rule.expectation === "MUST_BE_PRESENT" ? present : rule.expectation === "MUST_BE_ABSENT" ? !present : redacted);
  return { path: rule.path, classification: rule.classification, expectation: rule.expectation, observed, outcome: matched ? "PASS" : "FAIL" };
}

function tenantMatched(response: ApiResponseContractPlan, json: unknown): boolean | undefined {
  if (!response.tenant) return undefined;
  const observed = at(json, response.tenant.path);
  if (observed === undefined) return false;
  if (response.tenant.expectedValue !== undefined && !equal(observed, response.tenant.expectedValue)) return false;
  return !response.tenant.forbiddenValues.some((value) => equal(observed, value));
}

async function loadSchemas(context: ScanContext, transport: RequestSafetyBroker, plan: ApiGraphqlReviewPlan): Promise<Map<string, Snapshot>> {
  const output = new Map<string, Snapshot>();
  for (const route of plan.routes.filter((value) => value.kind === "SCHEMA" || value.kind === "DOCUMENTATION")) {
    const actor = route.inventoryActorId ? plan.actors.find((value) => value.id === route.inventoryActorId) : undefined;
    const selected = actor ?? { id: "schema-anonymous", safeAlias: "anonymous", authSlot: "anonymous", relationship: "PUBLIC" } as ApiGraphqlActorPlan;
    try { output.set(route.id, await send(context, transport, selected, route, { method: "GET", headers: {} })); } catch { /* comparison remains inconclusive */ }
  }
  return output;
}

function compareSchemas(plan: ApiGraphqlReviewPlan, schemas: Map<string, Snapshot>): ApiSchemaComparisonObservation[] {
  return plan.routes.filter((route) => route.schemaSourceId && route.schemaPath).map((route) => {
    const comparisonFingerprint = securityContractFingerprint("api-schema-comparison", { routeId: route.id, path: route.path, schemaSourceId: route.schemaSourceId, schemaPath: route.schemaPath, documented: route.documented, documentedMethods: [...route.documentedMethods].sort() });
    const source = plan.routes.find((value) => value.id === route.schemaSourceId)!; const snapshotValue = schemas.get(source.id); const paths = snapshotValue?.json && typeof snapshotValue.json === "object" ? (snapshotValue.json as Record<string, unknown>).paths : undefined;
    if (!snapshotValue?.statusCode || snapshotValue.statusCode < 200 || snapshotValue.statusCode >= 300 || !paths || typeof paths !== "object") return { comparisonFingerprint, routeId: route.id, routeAlias: route.safeAlias, schemaSourceAlias: source.safeAlias, schemaPath: route.schemaPath!, pathDocumented: false, missingDocumentedMethods: [], undocumentedConfiguredMethods: [], outcome: "INCONCLUSIVE", reasonCode: "SCHEMA_UNAVAILABLE_OR_INVALID" };
    const pathEntry = (paths as Record<string, unknown>)[route.schemaPath!]; const pathDocumented = Boolean(pathEntry && typeof pathEntry === "object"); const schemaMethods = pathDocumented ? Object.keys(pathEntry as Record<string, unknown>).filter((value) => /^(?:get|head|options|post|put|patch|delete)$/i.test(value)).map((value) => value.toUpperCase()) : [];
    const missingDocumentedMethods = route.documented ? route.documentedMethods.filter((value) => !schemaMethods.includes(value)) : []; const undocumentedConfiguredMethods = route.documented ? schemaMethods.filter((value) => !route.documentedMethods.includes(value as never)) : schemaMethods;
    const matched = route.documented ? pathDocumented && missingDocumentedMethods.length === 0 && undocumentedConfiguredMethods.length === 0 : !pathDocumented;
    return { comparisonFingerprint, routeId: route.id, routeAlias: route.safeAlias, schemaSourceAlias: source.safeAlias, schemaPath: route.schemaPath!, pathDocumented, missingDocumentedMethods, undocumentedConfiguredMethods, outcome: matched ? "PASS" : "FAIL", reasonCode: matched ? "SCHEMA_ROUTE_MATCHED" : "SCHEMA_ROUTE_DRIFT" };
  });
}

function inventoryReport(plan: ApiGraphqlReviewPlan, checks: readonly ApiGraphqlCheckObservation[]): ApiRouteInventoryObservation[] {
  return plan.routes.map((route) => ({ routeId: route.id, safeAlias: route.safeAlias, protocol: route.protocol, kind: route.kind, path: route.path, ...(route.version ? { version: route.version } : {}), documented: route.documented, documentedMethods: route.documentedMethods, checksExecuted: checks.filter((value) => value.routeAliases.includes(route.safeAlias)).length }));
}

function buildReport(plan: ApiGraphqlReviewPlan, inventory: readonly ApiRouteInventoryObservation[], checks: readonly ApiGraphqlCheckObservation[], schemaComparisons: readonly ApiSchemaComparisonObservation[], schemaRequests: number): ApiGraphqlReviewReport {
  const count = (kind: ApiGraphqlCheckPlan["kind"]) => plan.checks.filter((value) => value.kind === kind).length;
  return { enabled: true, inventory, checks, authorizationMatrices: matrixReport(plan, checks), schemaComparisons, plannedChecks: plan.checks.length, executedChecks: checks.filter((value) => value.outcome !== "BLOCKED").length, passedChecks: checks.filter((value) => value.outcome === "PASS").length, failedChecks: checks.filter((value) => value.outcome === "FAIL").length, inconclusiveChecks: checks.filter((value) => value.outcome === "INCONCLUSIVE").length, blockedChecks: checks.filter((value) => value.outcome === "BLOCKED").length, restChecks: checks.filter((value) => value.routeAliases.some((alias) => inventory.find((route) => route.safeAlias === alias)?.protocol === "REST")).length, graphqlChecks: checks.filter((value) => value.routeAliases.some((alias) => inventory.find((route) => route.safeAlias === alias)?.protocol === "GRAPHQL")).length, objectAuthorizationChecks: count("OBJECT_AUTHORIZATION"), functionAuthorizationChecks: count("FUNCTION_AUTHORIZATION"), fieldAuthorizationChecks: count("FIELD_AUTHORIZATION"), tenantIsolationChecks: count("TENANT_ISOLATION"), methodConfusionChecks: count("METHOD_CONFUSION"), introspectionChecks: count("GRAPHQL_INTROSPECTION"), aliasLimitChecks: count("GRAPHQL_ALIAS_LIMIT"), batchLimitChecks: count("GRAPHQL_BATCH_LIMIT"), versionBoundaryChecks: count("VERSION_BOUNDARY"), requestsTransmitted: checks.reduce((sum, value) => sum + value.requests.length, 0) + schemaRequests, requestBudget: plan.maxRequests, notes: [...plan.notes, "Reports retain route aliases, paths, status classes, counts, and structural fingerprints; credentials, variables, bodies, object values, and tenant values are omitted."] };
}

function matrixReport(plan: ApiGraphqlReviewPlan, observations: readonly ApiGraphqlCheckObservation[]): ApiAuthorizationMatrixObservation[] {
  const cells = plan.checks.filter((check): check is Extract<ApiGraphqlCheckPlan, { kind: "OBJECT_AUTHORIZATION" | "FUNCTION_AUTHORIZATION" | "FIELD_AUTHORIZATION" | "TENANT_ISOLATION" }> => "matrixId" in check);
  return [...new Set(cells.map((check) => check.matrixId))].map((matrixId) => {
    const planned = cells.filter((check) => check.matrixId === matrixId);
    const results = planned.map((check) => observations.find((value) => value.checkId === check.id)!);
    const dimension = planned[0]!.kind === "OBJECT_AUTHORIZATION" ? "OBJECT" : planned[0]!.kind === "FUNCTION_AUTHORIZATION" ? "FUNCTION" : planned[0]!.kind === "FIELD_AUTHORIZATION" ? "FIELD" : "TENANT";
    return { matrixId, dimension, routeAliases: [...new Set(results.flatMap((value) => value.routeAliases))], cells: results.map((value) => ({ checkId: value.checkId, actorAlias: value.actorAlias, relationship: value.actorRelationship, outcome: value.outcome, observedDecision: value.requests[0]?.decision ?? "NOT_EXECUTED" })) };
  });
}

function baseObservation(check: ApiGraphqlCheckPlan, actor: ApiGraphqlActorPlan, routes: readonly ApiRouteSecurityPlan[], outcome: ApiGraphqlOutcome, reasonCode: string, requests: readonly ApiRequestObservation[], fields: readonly ApiFieldExposureObservation[] = [], notes: readonly string[] = []): ApiGraphqlCheckObservation {
  return { checkId: check.id, label: check.label, kind: check.kind, routeAliases: routes.map((value) => value.safeAlias), protocols: [...new Set(routes.map((value) => value.protocol))], actorAlias: actor.safeAlias, actorRelationship: actor.relationship, outcome, reasonCode, comparisonFingerprint: check.comparisonFingerprint, requests, fields, notes };
}
function blocked(check: ApiGraphqlCheckPlan, actor: ApiGraphqlActorPlan, routes: readonly ApiRouteSecurityPlan[], reason: string): ApiGraphqlCheckObservation { return baseObservation(check, actor, routes, "BLOCKED", reason, [], [], ["The check was blocked before network transmission."]); }
function inconclusive(check: ApiGraphqlCheckPlan, actor: ApiGraphqlActorPlan, routes: readonly ApiRouteSecurityPlan[], reason: string): ApiGraphqlCheckObservation { return baseObservation(check, actor, routes, "INCONCLUSIVE", reason, [], [], ["No authorization finding was emitted because the response could not be classified safely."]); }

function identityBlocked(context: ScanContext, actor: ApiGraphqlActorPlan, required: boolean): boolean {
  if (!required || actor.authSlot === "anonymous") return false;
  const report = context.state.getIdentityVerification(); const result = actor.authSlot === "primary" ? report?.primary : actor.authSlot === "account_a" ? report?.accountA : report?.accountB;
  if (!result?.verified) return true;
  if (actor.principalFingerprint && result.principalHash && actor.principalFingerprint !== result.principalHash) return true;
  return Boolean(actor.tenantFingerprint && result.tenantHash && actor.tenantFingerprint !== result.tenantHash);
}

function profileFor(context: ScanContext, actor: ApiGraphqlActorPlan): AuthProfile | undefined { return actor.authSlot === "anonymous" ? undefined : actor.authSlot === "primary" ? context.options.authProfile : actor.authSlot === "account_a" ? context.options.authProfileSet?.accountA : context.options.authProfileSet?.accountB; }
function graphqlBody(operation: { operationName?: string; document: string; variables: Readonly<Record<string, unknown>> }, profile: AuthProfile | undefined): Record<string, unknown> { return { query: operation.document, ...(operation.operationName ? { operationName: operation.operationName } : {}), variables: expand(operation.variables, profile) }; }
function expand(value: unknown, profile: AuthProfile | undefined): unknown { const secrets = profile ? authenticationLifecycleSecrets(profile) : {}; if (Array.isArray(value)) return value.map((entry) => expand(entry, profile)); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, expand(child, profile)])); if (typeof value !== "string") return value; return value.replace(/\{\{SECRET:([A-Za-z0-9._-]+)\}\}/g, (_match, name: string) => { if (!(name in secrets)) throw new Error("secret unavailable"); return secrets[name]!; }); }
function setHeader(headers: Record<string, string>, name: string, value: string): void { const key = Object.keys(headers).find((entry) => entry.toLowerCase() === name.toLowerCase()) ?? name; headers[key] = value; }
function at(value: unknown, path: string): unknown { let current = value; for (const part of path.replace(/\[(\d+)\]/g, ".$1").split(".")) { if (!current || typeof current !== "object") return undefined; current = (current as Record<string, unknown>)[part]; } return current; }
function equal(left: unknown, right: unknown): boolean { return JSON.stringify(left) === JSON.stringify(right); }
function fieldPaths(value: unknown, prefix = "", output = new Set<string>(), depth = 0, maxDepth = 12): Set<string> { if (depth >= maxDepth || value === null || typeof value !== "object") return output; if (Array.isArray(value)) { if (value.length) fieldPaths(value[0], prefix ? `${prefix}[0]` : "[0]", output, depth + 1, maxDepth); return output; } for (const [key, child] of Object.entries(value as Record<string, unknown>)) { const path = prefix ? `${prefix}.${key}` : key; output.add(path); fieldPaths(child, path, output, depth + 1, maxDepth); } return output; }
function jsonShape(value: unknown, depth = 0, maxDepth = 12): unknown { if (depth >= maxDepth) return "depth-limit"; if (Array.isArray(value)) return [value.length ? jsonShape(value[0], depth + 1, maxDepth) : "empty"]; if (value && typeof value === "object") return Object.fromEntries(Object.keys(value as Record<string, unknown>).sort().map((key) => [key, jsonShape((value as Record<string, unknown>)[key], depth + 1, maxDepth)])); return value === null ? "null" : typeof value; }
function graphqlErrorCount(value: unknown): number { if (Array.isArray(value)) return value.reduce((sum, entry) => sum + graphqlErrorCount(entry), 0); const errors = value && typeof value === "object" ? (value as Record<string, unknown>).errors : undefined; return Array.isArray(errors) ? errors.length : 0; }
function graphqlDataPresent(value: unknown): boolean { if (Array.isArray(value)) return value.some(graphqlDataPresent); if (!value || typeof value !== "object" || !("data" in (value as Record<string, unknown>))) return false; const data = (value as Record<string, unknown>).data; return data !== null && data !== undefined; }
function hash(value: string): string { return createHash("sha256").update(value).digest("hex"); }

function reasonForAuthorizationFailure(kind: string, decisionMatched: boolean, fieldsMatched: boolean, identity: boolean | undefined, tenant: boolean | undefined, itemBound: boolean): string { if (!decisionMatched) return kind === "FUNCTION_AUTHORIZATION" ? "FUNCTION_AUTHORIZATION_BYPASS" : kind === "TENANT_ISOLATION" ? "TENANT_AUTHORIZATION_BYPASS" : kind === "FIELD_AUTHORIZATION" ? "FIELD_AUTHORIZATION_BYPASS" : "OBJECT_AUTHORIZATION_BYPASS"; if (!fieldsMatched) return "RESPONSE_FIELD_EXPOSURE"; if (identity === false) return "OBJECT_IDENTITY_MISMATCH"; if (tenant === false) return "TENANT_ISOLATION_MISMATCH"; if (!itemBound) return "RESPONSE_ITEM_BOUND_EXCEEDED"; return "AUTHORIZATION_CONTRACT_CONTRADICTED"; }

function findingsFrom(report: ApiGraphqlReviewReport): Finding[] {
  const scorer = new RiskScorer(); const findings: Finding[] = [];
  for (const result of report.checks.filter((value) => value.outcome === "FAIL" && (value.kind !== "GRAPHQL_INTROSPECTION" || value.introspectionClassification === "AVAILABLE"))) {
    const type = findingType(result); const request = result.requests[0]; const base = { id: `api-graphql-${hash(result.comparisonFingerprint).slice(0, 12)}`, title: `${type}: ${result.label}`, type, severity: type === "GraphQL Introspection Exposure" ? "Medium" as const : "High" as const, confidence: "High" as const, url: `redacted://${result.routeAliases.join("-vs-")}`, method: request?.method ?? "N/A", ...(request?.statusCode ? { statusCode: request.statusCode } : {}), evidence: { url: `redacted://${result.routeAliases.join("-vs-")}`, method: request?.method ?? "N/A", ...(request?.statusCode ? { statusCode: request.statusCode } : {}), ...(request?.bodyShapeFingerprint ? { bodyHash: request.bodyShapeFingerprint } : {}), source: `api-graphql:${result.checkId}:${result.comparisonFingerprint}`, severityReason: `Explicit ${result.kind} contract failed with reason ${result.reasonCode}.`, reproductionNotes: ["Use the same explicitly configured actor, route alias, fixed operation, and expected policy.", "Credentials, bodies, variables, object values, tenant values, and response values are omitted from evidence."] }, impact: impactFor(type), recommendation: recommendationFor(type), manualTestingSuggestions: ["Confirm the intended API authorization and documentation policy with the application owner.", "Repeat only the fixed bounded case after applying the server-side control."], tags: ["api", result.kind.toLowerCase(), ...(result.kind.startsWith("GRAPHQL") ? ["graphql"] : [])], falsePositiveStatus: "likely-valid" as const, workflowCase: { id: result.checkId, comparisonFingerprint: result.comparisonFingerprint }, sourceModule: "api-graphql-authorization", timestamp: new Date().toISOString() };
    findings.push({ ...base, riskScore: scorer.score(base) });
  }
  for (const drift of report.schemaComparisons.filter((value) => value.outcome === "FAIL")) {
    const base = { id: `api-schema-${hash(`${drift.routeId}:${drift.schemaPath}`).slice(0, 12)}`, title: `API Schema Drift: ${drift.routeAlias}`, type: "API Schema Drift" as const, severity: "Medium" as const, confidence: "High" as const, url: `redacted://${drift.schemaSourceAlias}`, method: "GET", evidence: { url: `redacted://${drift.schemaSourceAlias}`, method: "GET", source: `api-schema:${drift.routeId}`, severityReason: drift.reasonCode, reproductionNotes: [`Schema path ${drift.schemaPath}; method names and response bodies omitted.`] }, impact: impactFor("API Schema Drift"), recommendation: recommendationFor("API Schema Drift"), manualTestingSuggestions: ["Reconcile the deployed route inventory with the authoritative API schema."], tags: ["api", "schema-drift"], falsePositiveStatus: "maybe-false-positive" as const, workflowCase: { id: `schema/${drift.routeId}`, ...(drift.comparisonFingerprint ? { comparisonFingerprint: drift.comparisonFingerprint } : {}) }, sourceModule: "api-graphql-authorization", timestamp: new Date().toISOString() };
    findings.push({ ...base, riskScore: scorer.score(base) });
  }
  return findings;
}

function findingType(result: ApiGraphqlCheckObservation): "API Authorization Issue" | "GraphQL Authorization Issue" | "API Method Confusion" | "GraphQL Introspection Exposure" | "GraphQL Limit Issue" | "API Version Boundary Issue" { if (result.kind === "METHOD_CONFUSION") return "API Method Confusion"; if (result.kind === "GRAPHQL_INTROSPECTION") return "GraphQL Introspection Exposure"; if (result.kind === "GRAPHQL_ALIAS_LIMIT" || result.kind === "GRAPHQL_BATCH_LIMIT") return "GraphQL Limit Issue"; if (result.kind === "VERSION_BOUNDARY") return "API Version Boundary Issue"; return result.protocols.includes("GRAPHQL") ? "GraphQL Authorization Issue" : "API Authorization Issue"; }
function impactFor(type: string): string { if (type === "API Schema Drift") return "Undocumented or mismatched routes and methods can escape security review and client policy assumptions."; if (type === "GraphQL Introspection Exposure") return "Schema metadata is available outside the configured exposure policy and may expand attack-surface knowledge."; if (type === "GraphQL Limit Issue") return "Aliases or batched operations may bypass the configured request-amplification boundary."; if (type === "API Method Confusion") return "An alternate HTTP method may bypass the route's intended authorization decision."; if (type === "API Version Boundary Issue") return "An older or parallel API version may expose broader authorization or response fields."; return "A principal may access an API object, function, field, or tenant-scoped representation outside the declared policy."; }
function recommendationFor(type: string): string { if (type === "API Schema Drift") return "Generate and validate the deployed route inventory from the authoritative schema in CI, and block undocumented production routes or methods."; if (type === "GraphQL Introspection Exposure") return "Apply the intended introspection policy consistently per environment and authorization context."; if (type === "GraphQL Limit Issue") return "Enforce bounded alias, batch, depth, and complexity limits before resolver execution and account limits per authenticated principal."; if (type === "API Method Confusion") return "Enforce authorization and routing policy before method dispatch, reject unsupported methods, and do not trust method-override headers by default."; if (type === "API Version Boundary Issue") return "Apply identical authorization middleware and field policy across supported versions, then retire unsupported versions."; return "Enforce object, function, field, and tenant authorization server-side for every resolver and API route, independent of client-supplied identifiers."; }
function disabledReport(): ApiGraphqlReviewReport { return { enabled: false, inventory: [], checks: [], authorizationMatrices: [], schemaComparisons: [], plannedChecks: 0, executedChecks: 0, passedChecks: 0, failedChecks: 0, inconclusiveChecks: 0, blockedChecks: 0, restChecks: 0, graphqlChecks: 0, objectAuthorizationChecks: 0, functionAuthorizationChecks: 0, fieldAuthorizationChecks: 0, tenantIsolationChecks: 0, methodConfusionChecks: 0, introspectionChecks: 0, aliasLimitChecks: 0, batchLimitChecks: 0, versionBoundaryChecks: 0, requestsTransmitted: 0, requestBudget: 0, notes: ["API/GraphQL authorization review was not configured."] }; }
