import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import { authenticationLifecycleSecrets, authHeadersForProfile, type AuthProfile } from "../../core/auth/AuthProfile.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import { securityContractFingerprint } from "../../core/comparisons/SecurityContractFingerprint.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { businessInvariantCategories, type BusinessInvariantCasePlan, type BusinessInvariantPlan } from "./BusinessInvariantTypes.js";

const identifier = z.string().regex(/^[A-Za-z0-9._-]{1,100}$/);
const path = z.string().regex(/^[A-Za-z_$][A-Za-z0-9_$]*(?:\[(?:0|[1-9][0-9]{0,2})\]|\.[A-Za-z_$][A-Za-z0-9_$]*){0,8}$/).refine((value) => !value.replace(/\[(\d+)\]/g, ".$1").split(".").some((part) => ["__proto__", "prototype", "constructor"].includes(part)), "Capture path contains a forbidden segment.");
const method = z.enum(["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"]);
const actor = z.object({ id: identifier, safeAlias: z.string().min(1).max(80), authSlot: z.enum(["anonymous", "primary", "account_a", "account_b"]), requestAuthentication: z.enum(["NONE", "PROFILE"]).optional(), relationship: z.string().min(1).max(80), declaredState: z.string().min(1).max(80), tenantAlias: z.string().min(1).max(80).optional() }).strict();
const authorization = z.object({ mode: z.literal("CONTROLLED_INVARIANT"), environment: z.enum(["LOCAL", "TEST", "STAGING", "PRODUCTION"]), confirmation: z.literal("I_AUTHORIZE_CONTROLLED_BUSINESS_INVARIANT_TESTING"), authorizedBy: z.string().min(2).max(160), changeTicket: z.string().min(1).max(160), authorizedAt: z.string().datetime(), expiresAt: z.string().datetime(), disposableEntities: z.literal(true), productionAcknowledged: z.boolean().default(false) }).strict();
const capture = z.discriminatedUnion("source", [z.object({ name: identifier, source: z.literal("JSON"), path }).strict(), z.object({ name: identifier, source: z.literal("HEADER"), header: z.string().min(1).max(100) }).strict(), z.object({ name: identifier, source: z.literal("COOKIE"), cookie: z.string().min(1).max(100) }).strict()]);
const request = z.object({ method, url: z.string().url().max(2048), stateChanging: z.boolean().default(false), headers: z.record(z.string().max(8192)).default({}), bodyFormat: z.enum(["JSON", "FORM"]).optional(), fields: z.record(z.unknown()).optional() }).strict();
const observation = z.object({ id: identifier, actorId: identifier, request, captures: z.array(capture).min(1).max(20) }).strict();
const action = z.object({ id: identifier, actorId: identifier, request, execution: z.object({ mode: z.enum(["ONCE", "SEQUENTIAL_DUPLICATE", "CONCURRENT_DUPLICATE"]).default("ONCE"), attempts: z.number().int().min(1).max(5).default(1), maxConcurrency: z.number().int().min(1).max(4).default(1) }).strict().default({}), expectation: z.object({ authorization: z.enum(["ALLOW", "DENY"]), businessRule: z.enum(["ACCEPT", "REJECT", "NOT_EVALUATED"]), authorizationAllowedStatuses: z.array(z.number().int().min(100).max(599)).min(1).max(20).default([200, 201, 202, 204, 400, 409, 422]), authorizationDeniedStatuses: z.array(z.number().int().min(100).max(599)).min(1).max(20).default([401, 403, 404]), businessAcceptedStatuses: z.array(z.number().int().min(100).max(599)).min(1).max(20).default([200, 201, 202, 204]), businessRejectedStatuses: z.array(z.number().int().min(100).max(599)).min(1).max(20).default([400, 409, 422]) }).strict(), captures: z.array(capture).max(20).default([]), captureFromAttempt: z.enum(["FIRST", "LAST"]).default("LAST") }).strict();
const operand = z.discriminatedUnion("source", [z.object({ source: z.literal("CAPTURE"), ref: identifier }).strict(), z.object({ source: z.literal("LITERAL"), value: z.union([z.string().max(200), z.number().finite(), z.boolean(), z.null()]) }).strict()]);
const comparisonOperator = z.enum(["EQ", "NEQ", "LT", "LTE", "GT", "GTE"]);
const invariant = z.discriminatedUnion("kind", [
  z.object({ id: identifier, kind: z.literal("VALUE_COMPARE"), left: operand, operator: comparisonOperator, right: operand }).strict(),
  z.object({ id: identifier, kind: z.literal("NUMERIC_DELTA"), before: identifier, after: identifier, operator: z.enum(["EQ", "LT", "LTE", "GT", "GTE"]), expected: z.number().finite() }).strict(),
  z.object({ id: identifier, kind: z.literal("STATE_TRANSITION"), before: identifier, after: identifier, allowed: z.array(z.object({ from: z.string().min(1).max(100), to: z.string().min(1).max(100) }).strict()).min(1).max(50) }).strict(),
  z.object({ id: identifier, kind: z.literal("ACTION_OUTCOME_COUNT"), actionId: identifier, outcome: z.enum(["ACCEPTED", "REJECTED", "AUTHORIZED", "DENIED"]), operator: z.enum(["EQ", "LT", "LTE", "GT", "GTE"]), expected: z.number().int().min(0).max(5) }).strict(),
  z.object({ id: identifier, kind: z.literal("ACTION_RESPONSE_EQUIVALENCE"), actionId: identifier, compareStatus: z.boolean().default(true), compareShape: z.boolean().default(true), compareBodyDigest: z.boolean().default(false), expectedEquivalent: z.boolean().default(true) }).strict()
]);
const cleanupAction = z.object({ id: identifier, actorId: identifier, request, successStatusCodes: z.array(z.number().int().min(100).max(599)).min(1).max(20) }).strict();
const stateMachine = z.object({ beforeCapture: identifier, afterCapture: identifier, states: z.array(z.string().min(1).max(100)).min(2).max(50), allowedTransitions: z.array(z.object({ from: z.string().min(1).max(100), to: z.string().min(1).max(100) }).strict()).min(1).max(100) }).strict();
const testCase = z.object({ id: identifier, label: z.string().min(1).max(160), category: z.enum(businessInvariantCategories), actors: z.array(actor).min(1).max(8), authorization, preState: z.array(observation).min(1).max(20), actions: z.array(action).min(1).max(20), postState: z.array(observation).min(1).max(20), invariants: z.array(invariant).min(1).max(40), stateMachine: stateMachine.optional(), cleanupRequired: z.literal(true), cleanup: z.array(cleanupAction).min(1).max(20), cleanupVerification: z.array(observation).min(1).max(20), cleanupInvariants: z.array(invariant).min(1).max(40) }).strict();
export const businessInvariantInputSchema = z.object({ schemaVersion: z.literal(1).default(1), maxCases: z.number().int().min(1).max(20).default(10), maxRequests: z.number().int().min(1).max(500).default(100), maxResponseBytes: z.number().int().min(256).max(262144).default(32768), maxConcurrency: z.number().int().min(1).max(4).default(2), cases: z.array(testCase).min(1).max(20) }).strict();
export type BusinessInvariantInput = z.infer<typeof businessInvariantInputSchema>;
type PlannedActor = z.infer<typeof actor> & { requestAuthentication: "NONE" | "PROFILE" };
type CredentialContext = { authProfile?: AuthProfile; authProfileSet?: AuthProfileSet };

export async function loadBusinessInvariantInput(file: string): Promise<BusinessInvariantInput> {
  const value: unknown = JSON.parse((await readFile(file, "utf8")).replace(/^\uFEFF/, ""));
  assertSafeObject(value);
  const parsed = businessInvariantInputSchema.safeParse(value);
  if (!parsed.success) throw new AppError(parsed.error.message, "BUSINESS_INVARIANT_INPUT_INVALID");
  return parsed.data;
}

export function planBusinessInvariant(input: BusinessInvariantInput, context: { target: string; scope: RouteCairnScope; authProfile?: AuthProfile; authProfileSet?: AuthProfileSet; now?: Date }): BusinessInvariantPlan {
  assertSafeObject(input);
  const parsed = businessInvariantInputSchema.parse(input);
  if (parsed.cases.length > parsed.maxCases) throw new AppError("Business invariant cases exceed maxCases.", "BUSINESS_INVARIANT_LIMIT_EXCEEDED");
  const matcher = new ScopeMatcher(context.target, context.scope); const origin = new URL(context.target).origin; const now = context.now ?? new Date();
  let requestCount = 0; const caseIds = new Set<string>();
  const cases = parsed.cases.map((item) => {
    if (caseIds.has(item.id)) throw new AppError(`Duplicate business invariant case ${item.id}.`, "BUSINESS_INVARIANT_DUPLICATE_ID"); caseIds.add(item.id);
    const actors = item.actors.map((value) => ({ ...value, requestAuthentication: value.requestAuthentication ?? (value.authSlot === "anonymous" ? "NONE" as const : "PROFILE" as const) }));
    validateActors(actors, context, item.id); validateAuthorization(item.authorization, now, item.id);
    const actorIds = new Set(actors.map((value) => value.id)); const captureNames = new Set<string>(); const actionIds = new Set<string>(); const nodeIds = new Set<string>(); const invariantIds = new Set<string>();
    for (const state of item.preState) { claimId(state.id, nodeIds, "workflow node"); validateObservation(state, actorIds, actors, captureNames, matcher, origin, context); requestCount += 1; }
    for (const current of item.actions) {
      claimId(current.id, nodeIds, "workflow node");
      actionIds.add(current.id);
      validateAction(current, actorIds, actors, captureNames, matcher, origin, context, parsed.maxConcurrency);
      requestCount += current.execution.attempts;
    }
    for (const state of item.postState) { claimId(state.id, nodeIds, "workflow node"); validateObservation(state, actorIds, actors, captureNames, matcher, origin, context); requestCount += 1; }
    for (const current of item.invariants) { claimId(current.id, invariantIds, "invariant"); validateInvariant(current, captureNames, actionIds); }
    if (item.stateMachine) validateStateMachine(item.stateMachine, captureNames);
    for (const current of item.cleanup) {
      claimId(current.id, nodeIds, "workflow node");
      validateRequest(current.request, matcher, origin, current.id, true, captureNames);
      validateActorAndSecrets(current.actorId, current.request, actorIds, actors, context);
      requestCount += 1;
    }
    for (const state of item.cleanupVerification) { claimId(state.id, nodeIds, "workflow node"); validateObservation(state, actorIds, actors, captureNames, matcher, origin, context); requestCount += 1; }
    for (const current of item.cleanupInvariants) { claimId(current.id, invariantIds, "invariant"); validateInvariant(current, captureNames, actionIds); }
    const sanitizedAuthorization = { mode: "CONTROLLED_INVARIANT" as const, environment: item.authorization.environment, authorizationIdentityConfirmed: true as const, changeTicketConfirmed: true as const, authorizedAt: item.authorization.authorizedAt, expiresAt: item.authorization.expiresAt, disposableEntities: true as const, productionAcknowledged: item.authorization.productionAcknowledged, confirmationAccepted: true as const };
    const planCase = { ...item, actors, authorization: sanitizedAuthorization, comparisonFingerprint: fingerprint(item, actors) };
    return JSON.parse(JSON.stringify(planCase)) as BusinessInvariantCasePlan;
  });
  if (requestCount > parsed.maxRequests) throw new AppError(`Business invariant plan requires ${requestCount} requests, exceeding maxRequests.`, "BUSINESS_INVARIANT_LIMIT_EXCEEDED");
  return { schemaVersion: 1, enabled: true, targetOrigin: origin, maxCases: parsed.maxCases, maxRequests: parsed.maxRequests, maxResponseBytes: parsed.maxResponseBytes, maxConcurrency: parsed.maxConcurrency, cases, notes: ["Every case uses operator-supplied disposable entities, explicit invariants, authoritative state reads, and verified cleanup.", "Authorization decisions and business-rule decisions are evaluated independently.", "Concurrent duplicates are bounded, never retried, never redirected, and execute while holding the global mutation lock."] };
}

function validateActors(actors: PlannedActor[], context: CredentialContext, caseId: string): void {
  const ids = new Set<string>();
  for (const value of actors) {
    if (ids.has(value.id)) throw new AppError(`Duplicate actor in ${caseId}.`, "BUSINESS_INVARIANT_DUPLICATE_ID");
    ids.add(value.id);
    if (value.authSlot === "anonymous" && value.requestAuthentication === "PROFILE") throw new AppError(`Anonymous actor ${value.id} cannot send profile authentication.`, "BUSINESS_INVARIANT_ACTOR_INVALID");
    if (value.authSlot === "primary" && !context.authProfile) throw new AppError(`Actor ${value.id} requires primary authentication.`, "BUSINESS_INVARIANT_CREDENTIAL_REQUIRED");
    if ((value.authSlot === "account_a" || value.authSlot === "account_b") && !context.authProfileSet) throw new AppError(`Actor ${value.id} requires Account A/B authentication.`, "BUSINESS_INVARIANT_CREDENTIAL_REQUIRED");
  }
}

function validateAuthorization(value: z.infer<typeof authorization>, now: Date, caseId: string): void {
  if (new Date(value.authorizedAt).getTime() > now.getTime() || new Date(value.expiresAt).getTime() <= now.getTime()) throw new AppError(`Authorization for ${caseId} is not currently valid.`, "BUSINESS_INVARIANT_AUTHORIZATION_EXPIRED");
  if (value.environment === "PRODUCTION" && !value.productionAcknowledged) throw new AppError(`Production case ${caseId} requires productionAcknowledged=true.`, "BUSINESS_INVARIANT_PRODUCTION_ACK_REQUIRED");
}

function validateObservation(value: z.infer<typeof observation>, actorIds: Set<string>, actors: PlannedActor[], captures: Set<string>, matcher: ScopeMatcher, origin: string, context: CredentialContext): void {
  if (value.request.method !== "GET" && value.request.method !== "HEAD") throw new AppError(`Observation ${value.id} must use GET or HEAD for authoritative state.`, "BUSINESS_INVARIANT_OBSERVATION_INVALID");
  validateRequest(value.request, matcher, origin, value.id, false, captures);
  validateActorAndSecrets(value.actorId, value.request, actorIds, actors, context);
  addCaptures(value.captures, captures);
}
function validateAction(value: z.infer<typeof action>, actorIds: Set<string>, actors: PlannedActor[], captures: Set<string>, matcher: ScopeMatcher, origin: string, context: CredentialContext, maxConcurrency: number): void {
  validateRequest(value.request, matcher, origin, value.id, true, captures);
  if (value.execution.mode === "ONCE" && value.execution.attempts !== 1) throw new AppError(`ONCE action ${value.id} requires attempts=1.`, "BUSINESS_INVARIANT_EXECUTION_INVALID");
  if (value.execution.mode !== "ONCE" && value.execution.attempts < 2) throw new AppError(`Duplicate action ${value.id} requires at least two attempts.`, "BUSINESS_INVARIANT_EXECUTION_INVALID");
  if (value.execution.mode === "CONCURRENT_DUPLICATE" && value.execution.maxConcurrency < 2) throw new AppError(`Concurrent action ${value.id} requires maxConcurrency of at least two.`, "BUSINESS_INVARIANT_EXECUTION_INVALID");
  if (value.execution.mode !== "CONCURRENT_DUPLICATE" && value.execution.maxConcurrency !== 1) throw new AppError(`Only concurrent duplicates may set maxConcurrency above one.`, "BUSINESS_INVARIANT_EXECUTION_INVALID");
  if (value.execution.maxConcurrency > maxConcurrency || value.execution.maxConcurrency > value.execution.attempts) throw new AppError(`Action ${value.id} exceeds concurrency bounds.`, "BUSINESS_INVARIANT_EXECUTION_INVALID");
  if (value.expectation.authorization === "DENY" && value.expectation.businessRule !== "NOT_EVALUATED") throw new AppError(`Denied action ${value.id} cannot claim a business-rule decision.`, "BUSINESS_INVARIANT_EXPECTATION_INVALID");

  const allowed = new Set(value.expectation.authorizationAllowedStatuses);
  const denied = new Set(value.expectation.authorizationDeniedStatuses);
  const accepted = new Set(value.expectation.businessAcceptedStatuses);
  const rejected = new Set(value.expectation.businessRejectedStatuses);
  if ([...allowed].some((status) => denied.has(status)) || [...accepted].some((status) => rejected.has(status))) throw new AppError(`Action ${value.id} has overlapping decision status sets.`, "BUSINESS_INVARIANT_EXPECTATION_INVALID");
  if ([...accepted, ...rejected].some((status) => !allowed.has(status))) throw new AppError(`Action ${value.id} business-rule statuses must be authorization-allowed statuses.`, "BUSINESS_INVARIANT_EXPECTATION_INVALID");
  validateActorAndSecrets(value.actorId, value.request, actorIds, actors, context);
  addCaptures(value.captures, captures);
}

function validateActorAndSecrets(actorId: string, requestValue: z.infer<typeof request>, actorIds: Set<string>, actors: PlannedActor[], context: CredentialContext): void {
  if (!actorIds.has(actorId)) throw new AppError(`Unknown actor ${actorId}.`, "BUSINESS_INVARIANT_ACTOR_INVALID");
  const selected = actors.find((value) => value.id === actorId);
  if (!selected) return;
  const profile = selected.authSlot === "primary" ? context.authProfile : selected.authSlot === "account_a" ? context.authProfileSet?.accountA : selected.authSlot === "account_b" ? context.authProfileSet?.accountB : undefined;
  const available = new Set(Object.keys(profile ? authenticationLifecycleSecrets(profile) : {}));
  for (const ref of secretRefs(requestValue)) if (!available.has(ref)) throw new AppError(`Request references unavailable secret ${ref}.`, "BUSINESS_INVARIANT_SECRET_REQUIRED");
  if (profile && selected.requestAuthentication === "PROFILE") {
    const ambient = new Set(Object.keys(authHeadersForProfile(profile)).map((name) => name.toLowerCase()));
    for (const name of Object.keys(requestValue.headers)) if (ambient.has(name.toLowerCase())) throw new AppError(`Request header ${name} conflicts with actor profile authentication. Use requestAuthentication=NONE for explicit credential substitution.`, "BUSINESS_INVARIANT_AUTH_HEADER_CONFLICT");
  }
}
function validateRequest(value: z.infer<typeof request>, matcher: ScopeMatcher, origin: string, label: string, mutation: boolean, captures: Set<string>): void {
  const decision = matcher.decide(value.url, value.method);
  if (!decision.allowed || new URL(value.url).origin !== origin) throw new AppError(`Request ${label} is outside the exact target origin or scope.`, "BUSINESS_INVARIANT_SCOPE_INVALID");
  const unsafe = ["POST", "PATCH", "PUT", "DELETE"].includes(value.method);
  if (mutation !== unsafe || value.stateChanging !== mutation) throw new AppError(`Request ${label} has an invalid stateChanging declaration.`, "BUSINESS_INVARIANT_MUTATION_DECLARATION_REQUIRED");
  if (value.fields && !value.bodyFormat) throw new AppError(`Request ${label} with fields requires bodyFormat.`, "BUSINESS_INVARIANT_REQUEST_INVALID");
  for (const [name, header] of Object.entries(value.headers)) {
    if (/^(host|content-length|connection|transfer-encoding)$/i.test(name) || /[\r\n]/.test(header)) throw new AppError(`Unsafe header in ${label}.`, "BUSINESS_INVARIANT_REQUEST_INVALID");
    validateSensitiveValue(name, header, label);
  }
  inspectFields(value.fields, label);
  const parsedUrl = new URL(value.url);
  for (const [name, fieldValue] of parsedUrl.searchParams) validateSensitiveValue(name, fieldValue, label);
  for (const ref of captureRefs(value)) if (!captures.has(ref)) throw new AppError(`Request ${label} references unavailable capture ${ref}.`, "BUSINESS_INVARIANT_REFERENCE_INVALID");
  for (const text of stringValues(value)) {
    const residual = text.replace(/\{\{(?:SECRET|CAPTURE):[A-Za-z0-9._-]+\}\}/g, "");
    if (/\{\{|\}\}/.test(residual)) throw new AppError(`Request ${label} contains a malformed template reference.`, "BUSINESS_INVARIANT_REFERENCE_INVALID");
  }
}
function validateInvariant(value: z.infer<typeof invariant>, captures: Set<string>, actions: Set<string>): void {
  const needed = value.kind === "VALUE_COMPARE"
    ? [value.left, value.right].filter((item) => item.source === "CAPTURE").map((item) => (item as { ref: string }).ref)
    : value.kind === "NUMERIC_DELTA" || value.kind === "STATE_TRANSITION"
      ? [value.before, value.after]
      : [];
  for (const name of needed) if (!captures.has(name)) throw new AppError(`Invariant ${value.id} references unknown capture ${name}.`, "BUSINESS_INVARIANT_REFERENCE_INVALID");
  if ((value.kind === "ACTION_OUTCOME_COUNT" || value.kind === "ACTION_RESPONSE_EQUIVALENCE") && !actions.has(value.actionId)) throw new AppError(`Invariant ${value.id} references unknown action.`, "BUSINESS_INVARIANT_REFERENCE_INVALID");
}

function validateStateMachine(value: z.infer<typeof stateMachine>, captures: Set<string>): void {
  if (!captures.has(value.beforeCapture) || !captures.has(value.afterCapture)) throw new AppError("State machine references unknown captures.", "BUSINESS_INVARIANT_REFERENCE_INVALID");
  const states = new Set(value.states);
  if (states.size !== value.states.length) throw new AppError("State machine contains duplicate states.", "BUSINESS_INVARIANT_STATE_MACHINE_INVALID");
  for (const edge of value.allowedTransitions) if (!states.has(edge.from) || !states.has(edge.to)) throw new AppError("State-machine transition references undeclared state.", "BUSINESS_INVARIANT_STATE_MACHINE_INVALID");
}

function secretRefs(value: unknown): string[] {
  return [...new Set([...JSON.stringify(value).matchAll(/\{\{SECRET:([A-Za-z0-9._-]+)\}\}/g)].map((match) => match[1]!))];
}

function captureRefs(value: unknown): string[] {
  return [...new Set([...JSON.stringify(value).matchAll(/\{\{CAPTURE:([A-Za-z0-9._-]+)\}\}/g)].map((match) => match[1]!))];
}

function stringValues(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(stringValues);
  if (value && typeof value === "object") return Object.values(value as Record<string, unknown>).flatMap(stringValues);
  return [];
}

function addCaptures(values: readonly z.infer<typeof capture>[], captures: Set<string>): void {
  for (const item of values) {
    if (captures.has(item.name)) throw new AppError(`Duplicate capture ${item.name}.`, "BUSINESS_INVARIANT_DUPLICATE_ID");
    captures.add(item.name);
  }
}

function claimId(value: string, values: Set<string>, kind: string): void {
  if (values.has(value)) throw new AppError(`Duplicate ${kind} ${value}.`, "BUSINESS_INVARIANT_DUPLICATE_ID");
  values.add(value);
}
function validateSensitiveValue(key: string, value: string, label: string): void {
  if (!/(?:password|token|secret|cookie|authorization|email|username|code|session|credential|idempotency|csrf|api[-_]?key|user(?:id)?|account(?:id)?|tenant(?:id)?|principal(?:id)?|transaction(?:id)?|payment(?:id)?|order(?:id)?|object(?:id)?|identity|invite|verification|recovery)/i.test(key)) return;
  const refs = value.match(/\{\{(?:SECRET|CAPTURE):[A-Za-z0-9._-]+\}\}/g) ?? [];
  const framing = value.replace(/\{\{(?:SECRET|CAPTURE):[A-Za-z0-9._-]+\}\}/g, "").trim();
  if (refs.length === 0 || !/^(?:Bearer|Basic)?[\s,;:=._-]*$/i.test(framing)) throw new AppError(`Sensitive value ${key} in ${label} must be reference-only.`, "BUSINESS_INVARIANT_LITERAL_SECRET_REJECTED");
}
function inspectFields(value: unknown, label: string, key = ""): void {
  if (Array.isArray(value)) { value.forEach((entry) => inspectFields(entry, label, key)); return; }
  if (!value || typeof value !== "object") { if (typeof value === "string") validateSensitiveValue(key, value, label); return; }
  for (const [childKey, child] of Object.entries(value as Record<string, unknown>)) inspectFields(child, label, childKey);
}
function assertSafeObject(value: unknown): void {
  if (Array.isArray(value)) { value.forEach(assertSafeObject); return; }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (["__proto__", "prototype", "constructor"].includes(key)) throw new AppError(`Unsafe object key ${key}.`, "BUSINESS_INVARIANT_INPUT_INVALID");
    assertSafeObject(child);
  }
}
function fingerprint(item: z.infer<typeof testCase>, actors: PlannedActor[]): string {
  return securityContractFingerprint("business-invariant", {
    schemaVersion: 1,
    category: item.category,
    actors,
    authorization: item.authorization,
    preState: item.preState,
    actions: item.actions,
    postState: item.postState,
    invariants: item.invariants,
    stateMachine: item.stateMachine ?? null,
    cleanupRequired: item.cleanupRequired,
    cleanup: item.cleanup,
    cleanupVerification: item.cleanupVerification,
    cleanupInvariants: item.cleanupInvariants
  });
}
