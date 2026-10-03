import { createHash } from "node:crypto";
import { isConclusiveAdaptiveOutcome, isVerifiedAdaptiveCleanup, isReadOnlyAdaptiveApiOperation } from "./AdaptiveEvidenceSafety.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { validateAdvancedEngineInput, type AdvancedEngineId } from "../contracts/AdvancedEngineSchemas.js";

export type AdaptiveAuthenticationRequirement = "public" | "primary" | "account-pair";

export interface AdaptiveCompiledContract {
  engineId: AdvancedEngineId;
  engineConfiguration: Record<string, unknown>;
  requestCount: number;
  cleanupRequestCount: number;
  evidenceStrength: "EXACT_EXECUTED_CONTRACT";
  evidenceFingerprint: string;
  summary: string;
  authentication: AdaptiveAuthenticationRequirement;
  mutationApprovalRequired: boolean;
  sourceCaseFingerprints: string[];
}

type ContractSource = {
  engineId: AdaptiveCompiledContract["engineId"];
  plan: Record<string, unknown>;
  observations: readonly unknown[];
  workflow: string;
};

/**
 * Rehydrates executable input from a plan that was already validated and run.
 * Only contracts with a matching, conclusive result fingerprint are accepted.
 * Raw credentials are never copied; actors retain only their authentication slot.
 */
export function compileExecutedContracts(report: RouteCairnReport): AdaptiveCompiledContract[] {
  const plan = report.scanPlan;
  if (!plan) return [];
  const sources: ContractSource[] = [
    source("api-graphql-authorization", plan.apiGraphql, report.apiGraphql?.checks, "API/GraphQL"),
    source("authentication-lifecycle", plan.authenticationLifecycle, report.authenticationLifecycle?.observations, "authentication lifecycle"),
    source("link-portal-export-security", plan.linkPortalSecurity, report.linkPortalSecurity?.observations, "link/portal/export"),
    source("operational-endpoint-security", plan.operationalEndpointSecurity, report.operationalEndpointSecurity?.observations, "operational endpoint"),
    source("business-invariant", plan.businessInvariant, report.businessInvariant?.observations, "business invariant"),
    source("billing-entitlement-security", plan.billingEntitlement, report.billingEntitlement?.observations, "billing/entitlement"),
    source("supabase-authorization", plan.supabaseAuthorization, report.supabaseAuthorization?.observations, "Supabase")
  ].filter((value): value is ContractSource => Boolean(value));
  return sources.flatMap((value) => compileSource(value));
}

function source(engineId: ContractSource["engineId"], plan: unknown, observations: readonly unknown[] | undefined, workflow: string): ContractSource | undefined {
  return isRecord(plan) && observations?.length ? { engineId, plan, observations, workflow } : undefined;
}

function compileSource(sourceValue: ContractSource): AdaptiveCompiledContract[] {
  const cases = sourceValue.engineId === "api-graphql-authorization" ? records(sourceValue.plan.checks) : records(sourceValue.plan.cases);
  const observations = records(sourceValue.observations);
  const exact = cases.filter((item) => {
    const fingerprint = fingerprintOf(item);
    const observation = observations.find((candidate) => fingerprintOf(candidate) === fingerprint);
    return Boolean(fingerprint && observation && conclusive(observation) && cleanupSafe(item, observation, sourceValue.engineId));
  });
  if (!exact.length) return [];

  return exact.flatMap((casePlan) => {
    const observation = observations.find((candidate) => fingerprintOf(candidate) === fingerprintOf(casePlan))!;
    const config = inputForCase(sourceValue.engineId, sourceValue.plan, casePlan);
    if (!config || containsUnreplayableCredential(config)) return [];
    if (sourceValue.engineId === "api-graphql-authorization" && !isReadOnlyApiReplay(config)) return [];
    const mutation = isMutation(sourceValue.engineId, config);
    const approvalProbe = mutation ? authorizeConfiguration(config, {
      reviewedAt: new Date(Date.now() - 1_000).toISOString(),
      reviewedBy: "adaptive-contract-compiler",
      rationale: "Previously executed exact contract validation",
      expiresAt: new Date(Date.now() + 60_000).toISOString()
    }) : config;
    const validated = validateAdvancedEngineInput(sourceValue.engineId, approvalProbe);
    if (!validated.valid) return [];
    const auth = authenticationRequirement(config);
    const evidence = {
      engineId: sourceValue.engineId,
      comparisonFingerprint: fingerprintOf(casePlan),
      outcome: observation.outcome ?? observation.observedDecision,
      cleanupOutcome: observation.cleanupOutcome ?? "NOT_REQUIRED",
      configuration: config
    };
    return [{
      engineId: sourceValue.engineId,
      engineConfiguration: config,
      requestCount: requestCount(config),
      cleanupRequestCount: cleanupRequestCount(config),
      evidenceStrength: "EXACT_EXECUTED_CONTRACT" as const,
      evidenceFingerprint: digest(evidence),
      summary: `Exact completed ${sourceValue.workflow} contract compiled for deterministic replay.`,
      authentication: auth,
      mutationApprovalRequired: mutation,
      sourceCaseFingerprints: [fingerprintOf(casePlan)!]
    }];
  });
}

export function authorizeConfiguration(configuration: Record<string, unknown>, approval: { reviewedAt: string; reviewedBy: string; rationale: string; expiresAt: string }): Record<string, unknown> {
  const value = clone(configuration);
  for (const item of records(value.cases)) {
    const current = isRecord(item.authorization) ? item.authorization : {};
    const ticket = approval.rationale.slice(0, 160);
    if (current.mode === "CONTROLLED_LIFECYCLE") item.authorization = { mode: "CONTROLLED_LIFECYCLE", environment: current.environment, confirmation: "I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING", authorizedBy: approval.reviewedBy, changeTicket: ticket, authorizedAt: approval.reviewedAt, expiresAt: approval.expiresAt, disposableAccounts: true, productionAcknowledged: current.environment === "PRODUCTION" };
    if (current.mode === "CONTROLLED_INVARIANT") item.authorization = { mode: "CONTROLLED_INVARIANT", environment: current.environment, confirmation: "I_AUTHORIZE_CONTROLLED_BUSINESS_INVARIANT_TESTING", authorizedBy: approval.reviewedBy, changeTicket: ticket, authorizedAt: approval.reviewedAt, expiresAt: approval.expiresAt, disposableEntities: true, productionAcknowledged: current.environment === "PRODUCTION" };
    if (current.mode === "CONTROLLED_LINK_FLOW") item.authorization = { mode: "CONTROLLED_LINK_FLOW", environment: current.environment, confirmation: "I_AUTHORIZE_CONTROLLED_LINK_PORTAL_EXPORT_TESTING", authorizedBy: approval.reviewedBy, changeTicket: ticket, authorizedAt: approval.reviewedAt, expiresAt: approval.expiresAt, disposableResource: true, productionAcknowledged: current.environment === "PRODUCTION" };
    if (current.mode === "CONTROLLED_OPERATIONAL_FLOW") item.authorization = { mode: "CONTROLLED_OPERATIONAL_FLOW", environment: current.environment, confirmation: "I_AUTHORIZE_CONTROLLED_OPERATIONAL_ENDPOINT_TESTING", authorizedBy: approval.reviewedBy, changeTicket: ticket, authorizedAt: approval.reviewedAt, expiresAt: approval.expiresAt, disposableTarget: true, productionAcknowledged: current.environment === "PRODUCTION" };
    if (current.mode === "CONTROLLED_SYNTHETIC_BILLING") item.authorization = { mode: "CONTROLLED_SYNTHETIC_BILLING", environment: current.environment, confirmation: "I_AUTHORIZE_SYNTHETIC_BILLING_TESTING", authorizedBy: approval.reviewedBy, changeTicket: ticket, authorizedAt: approval.reviewedAt, expiresAt: approval.expiresAt, disposableFixtures: true };
  }
  return value;
}

function inputForCase(engineId: ContractSource["engineId"], plan: Record<string, unknown>, casePlan: Record<string, unknown>): Record<string, unknown> | undefined {
  const cleanCase = stripPlanFields(casePlan);
  if (engineId === "api-graphql-authorization") {
    const routeIds = new Set<string>();
    for (const key of ["routeId", "baselineRouteId", "candidateRouteId"]) if (typeof casePlan[key] === "string") routeIds.add(casePlan[key] as string);
    const routePlans = records(plan.routes);
    for (const id of routeIds) { const route = routePlans.find((item) => item.id === id); if (typeof route?.schemaSourceId === "string") routeIds.add(route.schemaSourceId); if (routeIds.size > 100) return; }
    const actorId = String(casePlan.actorId ?? "");
    const routes = records(plan.routes).filter((item) => routeIds.has(String(item.id))).map((item) => {
      const value = stripPlanFields(item);
      value.pathTemplate = value.path;
      delete value.path;
      return value;
    });
    const actors = records(plan.actors).filter((item) => item.id === actorId).map(stripPlanFields);
    return select(plan, ["schemaVersion", "maxRequests", "maxResponseBytes", "maxJsonDepth", "maxGraphqlDocumentBytes", "maxGraphqlAliases", "maxGraphqlBatchOperations"], { actors, routes, checks: [cleanCase] });
  }
  if (engineId === "authentication-lifecycle") {
    if (records(casePlan.steps).some((step) => step.providerCall || (Array.isArray(step.fixtureActions) && step.fixtureActions.length))) return;
    return select(plan, ["schemaVersion", "maxCases", "maxStepsPerCase", "maxRequests", "maxResponseBytes"], { fixtures: {}, cases: [authorizationTemplate(cleanCase)] });
  }
  if (engineId === "link-portal-export-security") {
    const actorIds = new Set(records(casePlan.steps).map((item) => String(item.actorId)));
    const resourceIds = new Set(records(casePlan.steps).map((item) => String(item.resourceId)));
    const actors = records(plan.actors).filter((item) => actorIds.has(String(item.id))).map(stripPlanFields);
    const resources = records(plan.resources).filter((item) => resourceIds.has(String(item.id))).map(stripPlanFields);
    return select(plan, ["schemaVersion", "maxCases", "maxStepsPerCase", "maxRequests", "maxResponseBytes"], { actors, resources, cases: [authorizationTemplate(cleanCase)] });
  }
  if (engineId === "business-invariant") return select(plan, ["schemaVersion", "maxCases", "maxRequests", "maxResponseBytes", "maxConcurrency"], { cases: [authorizationTemplate(cleanCase)] });
  if (engineId === "operational-endpoint-security") {
    const actorIds = new Set(records(casePlan.steps).map((item) => String(item.actorId)));
    const endpointIds = new Set(records(casePlan.steps).map((item) => String(item.endpointId)));
    return select(plan, ["schemaVersion", "maxCases", "maxStepsPerCase", "maxRequests", "maxResponseBytes"], {
      actors: records(plan.actors).filter((item) => actorIds.has(String(item.id))).map(stripPlanFields),
      endpoints: records(plan.endpoints).filter((item) => endpointIds.has(String(item.id))).map(stripPlanFields),
      cases: [authorizationTemplate(cleanCase)]
    });
  }
  if (engineId === "billing-entitlement-security") {
    const actorIds = new Set(records(casePlan.steps).map((item) => String(item.actorId)));
    const endpointIds = new Set(records(casePlan.steps).map((item) => String(item.endpointId)));
    return select(plan, ["schemaVersion", "maxCases", "maxRequests", "maxResponseBytes", "maxConcurrency", "provider"], {
      actors: records(plan.actors).filter((item) => actorIds.has(String(item.id))).map(stripPlanFields),
      endpoints: records(plan.endpoints).filter((item) => endpointIds.has(String(item.id))).map(stripPlanFields),
      cases: [authorizationTemplate(cleanCase)]
    });
  }
  if (engineId === "supabase-authorization") {
    if (casePlan.mutationContractCaseId || ["INSERT", "UPDATE", "DELETE", "INVOKE"].includes(String(casePlan.operation))) return;
    return select(plan, ["schemaVersion", "anonKeyEnv", "serviceRoleKeyEnv", "maxCases", "maxResponseBytes", "maxSignedUrlBytes", "catalog"], { projectUrl: plan.projectOrigin, cases: [cleanCase] });
  }
  return;
}

function authorizationTemplate(value: Record<string, unknown>): Record<string, unknown> {
  const auth = isRecord(value.authorization) ? value.authorization : {};
  if (auth.mode === "OBSERVE_ONLY") value.authorization = { mode: "OBSERVE_ONLY", environment: auth.environment };
  else if (auth.mode === "CONTROLLED_LIFECYCLE") value.authorization = { mode: auth.mode, environment: auth.environment, disposableAccounts: true, productionAcknowledged: auth.environment === "PRODUCTION" };
  else if (auth.mode === "CONTROLLED_INVARIANT") value.authorization = { mode: auth.mode, environment: auth.environment, disposableEntities: true, productionAcknowledged: auth.environment === "PRODUCTION" };
  else if (auth.mode === "CONTROLLED_LINK_FLOW") value.authorization = { mode: auth.mode, environment: auth.environment, disposableResource: true, productionAcknowledged: auth.environment === "PRODUCTION" };
  else if (auth.mode === "CONTROLLED_OPERATIONAL_FLOW") value.authorization = { mode: auth.mode, environment: auth.environment, disposableTarget: true, productionAcknowledged: auth.environment === "PRODUCTION" };
  else if (auth.mode === "CONTROLLED_SYNTHETIC_BILLING") value.authorization = { mode: auth.mode, environment: auth.environment, disposableFixtures: true };
  return value;
}

function stripPlanFields(input: Record<string, unknown>): Record<string, unknown> {
  const output = clone(input);
  walk(output, (item) => {
    for (const key of ["comparisonFingerprint", "principalFingerprint", "tenantFingerprint", "expectedValueHash", "authorizationIdentityConfirmed", "changeTicketConfirmed", "confirmationAccepted"]) delete item[key];
    if (isRecord(item.identity)) delete item.identity.expectedFingerprint;
    if (isRecord(item.tenant)) {
      delete item.tenant.expectedFingerprint;
      delete item.tenant.forbiddenValueFingerprints;
    }
  });
  return output;
}

function conclusive(observation: Record<string, unknown>): boolean {
  const outcome = String(observation.outcome ?? observation.observedDecision ?? "").toUpperCase();
  return isConclusiveAdaptiveOutcome(outcome);
}

function cleanupSafe(casePlan: Record<string, unknown>, observation: Record<string, unknown>, engineId: string): boolean {
  if (engineId === "api-graphql-authorization") return casePlan.cleanupRequired !== true;
  if (!casePlan.cleanupRequired && !containsStateChanging(casePlan)) return true;
  return isVerifiedAdaptiveCleanup(observation.cleanupOutcome);
}

function isMutation(engineId: string, configuration: Record<string, unknown>): boolean {
  if (engineId === "api-graphql-authorization" || engineId === "supabase-authorization") return false;
  return containsStateChanging(configuration) || records(configuration.cases).some((item) => item.cleanupRequired === true || isRecord(item.authorization) && String(item.authorization.mode).startsWith("CONTROLLED_"));
}

function containsStateChanging(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsStateChanging);
  if (!isRecord(value)) return false;
  if (value.stateChanging === true || (typeof value.method === "string" && !["GET", "HEAD", "OPTIONS"].includes(value.method) && value.stateChanging !== false)) return true;
  return Object.values(value).some(containsStateChanging);
}

function authenticationRequirement(value: unknown): AdaptiveAuthenticationRequirement {
  const slots = new Set<string>();
  walk(value, (item) => { if (typeof item.authSlot === "string") slots.add(item.authSlot); if (typeof item.secretSource === "string") slots.add(item.secretSource); if (typeof item.actor === "string") slots.add(item.actor === "ACCOUNT_A" ? "account_a" : item.actor === "ACCOUNT_B" ? "account_b" : item.actor === "SERVICE_ROLE" ? "primary" : "anonymous"); });
  return slots.has("account_a") || slots.has("account_b") ? "account-pair" : slots.has("primary") ? "primary" : "public";
}

function requestCount(value: Record<string, unknown>): number {
  const cases = records(value.cases);
  if (cases.length) return Math.max(1, cases.reduce((sum, item) => sum + records(item.steps).reduce((stepSum, step) => stepSum + Number(isRecord(step.execution) ? step.execution.attempts ?? 1 : 1), 0) + records(item.preState).length + records(item.actions).reduce((actionSum, action) => actionSum + Number(isRecord(action.execution) ? action.execution.attempts ?? 1 : 1), 0) + records(item.postState).length + records(item.cleanup).length + records(item.cleanupVerification).length, 0));
  return Math.max(1, records(value.routes).filter((route) => ["SCHEMA", "DOCUMENTATION"].includes(String(route.kind))).length + records(value.checks).reduce((sum, check) => sum + (check.kind === "VERSION_BOUNDARY" ? 2 : check.kind === "METHOD_CONFUSION" ? 1 + (Array.isArray(check.alternateMethods) ? check.alternateMethods.length : 0) : 1), 0));
}

function cleanupRequestCount(value: Record<string, unknown>): number {
  return records(value.cases).reduce((sum, item) => sum + records(item.steps).filter((step) => step.phase === "CLEANUP").reduce((stepSum, step) => stepSum + Number(isRecord(step.execution) ? step.execution.attempts ?? 1 : 1), 0) + records(item.cleanup).length + records(item.cleanupVerification).length, 0);
}

function fingerprintOf(value: Record<string, unknown>): string | undefined { return typeof value.comparisonFingerprint === "string" && /^[a-f0-9]{64}$/i.test(value.comparisonFingerprint) ? value.comparisonFingerprint.toLowerCase() : undefined; }
function records(value: unknown): Record<string, unknown>[] { return Array.isArray(value) ? value.filter(isRecord) : []; }
function isRecord(value: unknown): value is Record<string, unknown> { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
function clone<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T; }
function walk(value: unknown, visit: (item: Record<string, unknown>) => void): void { if (Array.isArray(value)) { value.forEach((item) => walk(item, visit)); return; } if (!isRecord(value)) return; visit(value); Object.values(value).forEach((item) => walk(item, visit)); }
function select(sourceValue: Record<string, unknown>, keys: string[], extras: Record<string, unknown>): Record<string, unknown> { return { ...Object.fromEntries(keys.filter((key) => sourceValue[key] !== undefined).map((key) => [key, clone(sourceValue[key])])), ...extras }; }
function digest(value: unknown): string { return createHash("sha256").update(JSON.stringify(sort(value))).digest("hex"); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (!isRecord(value)) return value; return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => [key, sort(child)])); }

function isReadOnlyApiReplay(configuration: Record<string, unknown>): boolean {
  const routes = new Map(records(configuration.routes).map((route) => [route.id, route]));
  return records(configuration.checks).every((check) => {
    const ids = [check.routeId, check.baselineRouteId, check.candidateRouteId].filter((id) => typeof id === "string");
    const request = isRecord(check.request) ? check.request : undefined;
    return ids.length > 0 && ids.every((id) => { const route = routes.get(id); return Boolean(route && isReadOnlyAdaptiveApiOperation(check, route, request, String(request?.method ?? check.canonicalMethod ?? (route.protocol === "GRAPHQL" ? "POST" : "GET")))); });
  });
}

function containsUnreplayableCredential(value: unknown): boolean {
  let found = false;
  walk(value, (item) => {
    if (isRecord(item.headers)) for (const [name, content] of Object.entries(item.headers)) if (typeof content === "string" && /(?:authorization|cookie|api[-_]?key|auth[-_]?token|session)/i.test(name) && !/^\{\{(?:SECRET|CAPTURE):[A-Za-z0-9._-]+\}\}$/.test(content)) found = true;
    for (const child of Object.values(item)) if (typeof child === "string" && /(?:\bBearer\s+(?!\{\{)|<redacted>|\[redacted\]|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)/i.test(child)) found = true;
  });
  return found;
}
