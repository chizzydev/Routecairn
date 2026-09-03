import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import { authenticationLifecycleSecrets, authHeadersForProfile, type AuthProfile } from "../../core/auth/AuthProfile.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import { securityContractFingerprint } from "../../core/comparisons/SecurityContractFingerprint.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { controlledRaceCategories, type ControlledRaceCasePlan, type ControlledRacePlan } from "./ControlledRaceTypes.js";

const identifier = z.string().regex(/^[A-Za-z0-9._-]{1,100}$/);
const jsonPath = z.string().regex(/^[A-Za-z_$][A-Za-z0-9_$]*(?:\[(?:0|[1-9][0-9]{0,2})\]|\.[A-Za-z_$][A-Za-z0-9_$]*){0,8}$/).refine((value) => !segments(value).some((part) => ["__proto__", "prototype", "constructor"].includes(part)), "Capture path contains a forbidden segment.");
const actorSchema = z.object({ id: identifier, safeAlias: z.string().min(1).max(80), authSlot: z.enum(["anonymous", "primary", "account_a", "account_b"]), requestAuthentication: z.enum(["NONE", "PROFILE"]).optional(), relationship: z.string().min(1).max(80), declaredState: z.string().min(1).max(80), tenantAlias: z.string().min(1).max(80).optional() }).strict();
const authorizationSchema = z.object({ mode: z.literal("CONTROLLED_RACE"), environment: z.enum(["LOCAL", "TEST", "STAGING", "PRODUCTION"]), confirmation: z.literal("I_AUTHORIZE_CONTROLLED_RACE_TESTING"), authorizedBy: z.string().min(2).max(160), changeTicket: z.string().min(1).max(160), authorizedAt: z.string().datetime(), expiresAt: z.string().datetime(), disposableEntities: z.literal(true), productionAcknowledged: z.boolean().default(false) }).strict();
const targetSchema = z.object({ type: z.string().min(1).max(80), safeAlias: z.string().min(1).max(80), identityFingerprint: z.string().regex(/^[a-f0-9]{64}$/), disposable: z.literal(true) }).strict();
const captureSchema = z.discriminatedUnion("source", [z.object({ name: identifier, source: z.literal("JSON"), path: jsonPath }).strict(), z.object({ name: identifier, source: z.literal("HEADER"), header: z.string().min(1).max(100) }).strict(), z.object({ name: identifier, source: z.literal("COOKIE"), cookie: z.string().min(1).max(100) }).strict()]);
const requestSchema = z.object({ method: z.enum(["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"]), url: z.string().url().max(2048), stateChanging: z.boolean(), headers: z.record(z.string().max(8192)).default({}), bodyFormat: z.enum(["JSON", "FORM"]).optional(), fields: z.record(z.unknown()).optional() }).strict();
const observationSchema = z.object({ id: identifier, actorId: identifier, request: requestSchema, captures: z.array(captureSchema).min(1).max(20) }).strict();
const expectationSchema = z.object({ authorization: z.enum(["ALLOW", "DENY"]), businessRule: z.enum(["ACCEPT", "REJECT", "NOT_EVALUATED"]), authorizationAllowedStatuses: z.array(z.number().int().min(100).max(599)).min(1).max(20).default([200, 201, 202, 204, 400, 409, 422]), authorizationDeniedStatuses: z.array(z.number().int().min(100).max(599)).min(1).max(20).default([401, 403, 404]), businessAcceptedStatuses: z.array(z.number().int().min(100).max(599)).min(1).max(20).default([200, 201, 202, 204]), businessRejectedStatuses: z.array(z.number().int().min(100).max(599)).min(1).max(20).default([400, 409, 422]) }).strict();
const synchronizedRequestSchema = z.object({ id: identifier, actorId: identifier, request: requestSchema, expectation: expectationSchema }).strict();
const groupSchema = z.object({ id: identifier, label: z.string().min(1).max(160), synchronization: z.literal("READY_BARRIER").default("READY_BARRIER"), maxDispatchSkewMs: z.number().int().min(1).max(1000).default(100), requests: z.array(synchronizedRequestSchema).min(2).max(5) }).strict();
const operandSchema = z.discriminatedUnion("source", [z.object({ source: z.literal("CAPTURE"), ref: identifier }).strict(), z.object({ source: z.literal("LITERAL"), value: z.union([z.string().max(200), z.number().finite(), z.boolean(), z.null()]) }).strict()]);
const operatorSchema = z.enum(["EQ", "NEQ", "LT", "LTE", "GT", "GTE"]);
const numericOperatorSchema = z.enum(["EQ", "LT", "LTE", "GT", "GTE"]);
const assertionSchema = z.discriminatedUnion("kind", [
  z.object({ id: identifier, kind: z.literal("VALUE_COMPARE"), left: operandSchema, operator: operatorSchema, right: operandSchema }).strict(),
  z.object({ id: identifier, kind: z.literal("NUMERIC_DELTA"), before: identifier, after: identifier, operator: numericOperatorSchema, expected: z.number().finite() }).strict(),
  z.object({ id: identifier, kind: z.literal("EVENT_COUNT_DELTA"), before: identifier, after: identifier, operator: numericOperatorSchema, expected: z.number().finite() }).strict(),
  z.object({ id: identifier, kind: z.literal("GROUP_OUTCOME_COUNT"), groupId: identifier, outcome: z.enum(["ACCEPTED", "REJECTED", "AUTHORIZED", "DENIED"]), operator: numericOperatorSchema, expected: z.number().int().min(0).max(5) }).strict(),
  z.object({ id: identifier, kind: z.literal("STATE_TRANSITION"), before: identifier, after: identifier, allowed: z.array(z.object({ from: z.string().min(1).max(100), to: z.string().min(1).max(100) }).strict()).min(1).max(50) }).strict()
]);
const cleanupSchema = z.object({ id: identifier, actorId: identifier, request: requestSchema, successStatusCodes: z.array(z.number().int().min(100).max(599)).min(1).max(20) }).strict();
const caseSchema = z.object({ id: identifier, label: z.string().min(1).max(160), category: z.enum(controlledRaceCategories), target: targetSchema, actors: z.array(actorSchema).min(1).max(8), authorization: authorizationSchema, preState: z.array(observationSchema).min(1).max(20), groups: z.array(groupSchema).min(1).max(3), postState: z.array(observationSchema).min(1).max(20), invariants: z.array(assertionSchema).min(1).max(40), cleanupRequired: z.literal(true), cleanup: z.array(cleanupSchema).min(1).max(20), cleanupVerification: z.array(observationSchema).min(1).max(20), cleanupInvariants: z.array(assertionSchema).min(1).max(40) }).strict();

export const controlledRaceInputSchema = z.object({ schemaVersion: z.literal(1).default(1), maxCases: z.number().int().min(1).max(20).default(10), maxGroupsPerCase: z.number().int().min(1).max(3).default(2), maxRequests: z.number().int().min(1).max(500).default(100), maxResponseBytes: z.number().int().min(256).max(262144).default(32768), maxConcurrency: z.number().int().min(2).max(5).default(5), cases: z.array(caseSchema).min(1).max(20) }).strict();
export type ControlledRaceInput = z.infer<typeof controlledRaceInputSchema>;
type PlannedActor = z.infer<typeof actorSchema> & { requestAuthentication: "NONE" | "PROFILE" };
type PlannerContext = { target: string; scope: RouteCairnScope; authProfile?: AuthProfile; authProfileSet?: AuthProfileSet; now?: Date };

export async function loadControlledRaceInput(file: string): Promise<ControlledRaceInput> {
  const value: unknown = JSON.parse((await readFile(file, "utf8")).replace(/^\uFEFF/, ""));
  assertSafeObject(value);
  const parsed = controlledRaceInputSchema.safeParse(value);
  if (!parsed.success) throw new AppError(parsed.error.message, "CONTROLLED_RACE_INPUT_INVALID");
  return parsed.data;
}

export function planControlledRace(input: ControlledRaceInput, context: PlannerContext): ControlledRacePlan {
  assertSafeObject(input);
  const parsed = controlledRaceInputSchema.parse(input);
  if (parsed.cases.length > parsed.maxCases) throw new AppError("Controlled race cases exceed maxCases.", "CONTROLLED_RACE_LIMIT_EXCEEDED");
  const matcher = new ScopeMatcher(context.target, context.scope);
  const origin = new URL(context.target).origin;
  const now = context.now ?? new Date();
  const caseIds = new Set<string>();
  let requestCount = 0;
  const cases = parsed.cases.map((item) => {
    claim(item.id, caseIds, "case");
    if (item.groups.length > parsed.maxGroupsPerCase) throw new AppError(`Case ${item.id} exceeds maxGroupsPerCase.`, "CONTROLLED_RACE_LIMIT_EXCEEDED");
    const actors = item.actors.map((value) => ({ ...value, requestAuthentication: value.requestAuthentication ?? (value.authSlot === "anonymous" ? "NONE" as const : "PROFILE" as const) }));
    validateActors(actors, context, item.id);
    validateAuthorization(item.authorization, now, item.id);
    const actorIds = new Set(actors.map((value) => value.id));
    const captures = new Set<string>();
    const groupIds = new Set<string>();
    const nodeIds = new Set<string>();
    const invariantIds = new Set<string>();
    for (const observation of item.preState) { claim(observation.id, nodeIds, "workflow node"); validateObservation(observation, actorIds, actors, captures, matcher, origin, context); requestCount += 1; }
    for (const group of item.groups) {
      claim(group.id, groupIds, "race group");
      if (group.requests.length > parsed.maxConcurrency) throw new AppError(`Race group ${group.id} exceeds maxConcurrency.`, "CONTROLLED_RACE_LIMIT_EXCEEDED");
      for (const raceRequest of group.requests) { claim(raceRequest.id, nodeIds, "workflow node"); validateMutationRequest(raceRequest, actorIds, actors, captures, matcher, origin, context); requestCount += 1; }
    }
    for (const observation of item.postState) { claim(observation.id, nodeIds, "workflow node"); validateObservation(observation, actorIds, actors, captures, matcher, origin, context); requestCount += 1; }
    for (const assertion of item.invariants) { claim(assertion.id, invariantIds, "invariant"); validateAssertion(assertion, captures, groupIds); }
    for (const cleanup of item.cleanup) { claim(cleanup.id, nodeIds, "workflow node"); validateRequest(cleanup.request, matcher, origin, cleanup.id, true, captures); validateActorSecrets(cleanup.actorId, cleanup.request, actorIds, actors, context); requestCount += 1; }
    for (const observation of item.cleanupVerification) { claim(observation.id, nodeIds, "workflow node"); validateObservation(observation, actorIds, actors, captures, matcher, origin, context); requestCount += 1; }
    for (const assertion of item.cleanupInvariants) { claim(assertion.id, invariantIds, "invariant"); validateAssertion(assertion, captures, groupIds); }
    const authorization = { mode: "CONTROLLED_RACE" as const, environment: item.authorization.environment, authorizationIdentityConfirmed: true as const, changeTicketConfirmed: true as const, authorizedAt: item.authorization.authorizedAt, expiresAt: item.authorization.expiresAt, disposableEntities: true as const, productionAcknowledged: item.authorization.productionAcknowledged, confirmationAccepted: true as const };
    return JSON.parse(JSON.stringify({ ...item, actors, authorization, comparisonFingerprint: fingerprint(item, actors) })) as ControlledRaceCasePlan;
  });
  if (requestCount > parsed.maxRequests) throw new AppError(`Controlled race plan requires ${requestCount} requests, exceeding maxRequests.`, "CONTROLLED_RACE_LIMIT_EXCEEDED");
  return { schemaVersion: 1, enabled: true, targetOrigin: origin, maxCases: parsed.maxCases, maxGroupsPerCase: parsed.maxGroupsPerCase, maxRequests: parsed.maxRequests, maxResponseBytes: parsed.maxResponseBytes, maxConcurrency: parsed.maxConcurrency, cases, notes: ["Race groups contain exactly two to five explicitly declared mutation requests released by one ready barrier.", "Ordinary pacing is bypassed only inside the bounded race group; scope, DNS pinning, budgets, audit redaction, response caps, and cancellation remain enforced.", "Every case requires authoritative pre/post state, explicit event or outcome invariants, and verified cleanup of disposable entities."] };
}

function validateActors(actors: PlannedActor[], context: PlannerContext, caseId: string): void {
  const ids = new Set<string>();
  for (const actor of actors) {
    claim(actor.id, ids, "actor");
    if (actor.authSlot === "anonymous" && actor.requestAuthentication === "PROFILE") throw new AppError(`Anonymous actor ${actor.id} cannot send profile authentication.`, "CONTROLLED_RACE_ACTOR_INVALID");
    if (actor.authSlot === "primary" && !context.authProfile) throw new AppError(`Actor ${actor.id} requires primary authentication.`, "CONTROLLED_RACE_CREDENTIAL_REQUIRED");
    if ((actor.authSlot === "account_a" || actor.authSlot === "account_b") && !context.authProfileSet) throw new AppError(`Actor ${actor.id} requires Account A/B authentication.`, "CONTROLLED_RACE_CREDENTIAL_REQUIRED");
  }
  void caseId;
}

function validateAuthorization(value: z.infer<typeof authorizationSchema>, now: Date, caseId: string): void {
  if (new Date(value.authorizedAt).getTime() > now.getTime() || new Date(value.expiresAt).getTime() <= now.getTime()) throw new AppError(`Authorization for ${caseId} is not currently valid.`, "CONTROLLED_RACE_AUTHORIZATION_EXPIRED");
  if (value.environment === "PRODUCTION" && !value.productionAcknowledged) throw new AppError(`Production case ${caseId} requires productionAcknowledged=true.`, "CONTROLLED_RACE_PRODUCTION_ACK_REQUIRED");
}

function validateObservation(value: z.infer<typeof observationSchema>, actorIds: Set<string>, actors: PlannedActor[], captures: Set<string>, matcher: ScopeMatcher, origin: string, context: PlannerContext): void {
  if (value.request.method !== "GET" && value.request.method !== "HEAD") throw new AppError(`Observation ${value.id} must use GET or HEAD.`, "CONTROLLED_RACE_OBSERVATION_INVALID");
  validateRequest(value.request, matcher, origin, value.id, false, captures);
  validateActorSecrets(value.actorId, value.request, actorIds, actors, context);
  for (const capture of value.captures) claim(capture.name, captures, "capture");
}

function validateMutationRequest(value: z.infer<typeof synchronizedRequestSchema>, actorIds: Set<string>, actors: PlannedActor[], captures: Set<string>, matcher: ScopeMatcher, origin: string, context: PlannerContext): void {
  validateRequest(value.request, matcher, origin, value.id, true, captures);
  validateActorSecrets(value.actorId, value.request, actorIds, actors, context);
  validateExpectation(value.expectation, value.id);
}

function validateExpectation(value: z.infer<typeof expectationSchema>, id: string): void {
  if (value.authorization === "DENY" && value.businessRule !== "NOT_EVALUATED") throw new AppError(`Denied request ${id} cannot claim a business-rule decision.`, "CONTROLLED_RACE_EXPECTATION_INVALID");
  const allowed = new Set(value.authorizationAllowedStatuses); const denied = new Set(value.authorizationDeniedStatuses); const accepted = new Set(value.businessAcceptedStatuses); const rejected = new Set(value.businessRejectedStatuses);
  if ([...allowed].some((status) => denied.has(status)) || [...accepted].some((status) => rejected.has(status))) throw new AppError(`Request ${id} has overlapping decision status sets.`, "CONTROLLED_RACE_EXPECTATION_INVALID");
  if ([...accepted, ...rejected].some((status) => !allowed.has(status))) throw new AppError(`Request ${id} business-rule statuses must be authorization-allowed.`, "CONTROLLED_RACE_EXPECTATION_INVALID");
}

function validateActorSecrets(actorId: string, request: z.infer<typeof requestSchema>, actorIds: Set<string>, actors: PlannedActor[], context: PlannerContext): void {
  if (!actorIds.has(actorId)) throw new AppError(`Unknown actor ${actorId}.`, "CONTROLLED_RACE_ACTOR_INVALID");
  const actor = actors.find((value) => value.id === actorId)!;
  const profile = actor.authSlot === "primary" ? context.authProfile : actor.authSlot === "account_a" ? context.authProfileSet?.accountA : actor.authSlot === "account_b" ? context.authProfileSet?.accountB : undefined;
  const available = new Set(Object.keys(profile ? authenticationLifecycleSecrets(profile) : {}));
  for (const ref of refs(request, "SECRET")) if (!available.has(ref)) throw new AppError(`Request references unavailable secret ${ref}.`, "CONTROLLED_RACE_SECRET_REQUIRED");
  if (profile && actor.requestAuthentication === "PROFILE") {
    const ambient = new Set(Object.keys(authHeadersForProfile(profile)).map((name) => name.toLowerCase()));
    for (const name of Object.keys(request.headers)) if (ambient.has(name.toLowerCase())) throw new AppError(`Request header ${name} conflicts with actor profile authentication.`, "CONTROLLED_RACE_AUTH_HEADER_CONFLICT");
  }
}

function validateRequest(value: z.infer<typeof requestSchema>, matcher: ScopeMatcher, origin: string, label: string, mutation: boolean, captures: Set<string>): void {
  const decision = matcher.decide(value.url, value.method);
  if (!decision.allowed || new URL(value.url).origin !== origin) throw new AppError(`Request ${label} is outside exact scope or origin.`, "CONTROLLED_RACE_SCOPE_INVALID");
  const unsafe = ["POST", "PATCH", "PUT", "DELETE"].includes(value.method);
  if (unsafe !== mutation || value.stateChanging !== mutation) throw new AppError(`Request ${label} has an invalid stateChanging declaration.`, "CONTROLLED_RACE_MUTATION_DECLARATION_REQUIRED");
  if (value.fields && !value.bodyFormat) throw new AppError(`Request ${label} with fields requires bodyFormat.`, "CONTROLLED_RACE_REQUEST_INVALID");
  for (const [name, header] of Object.entries(value.headers)) { if (/^(host|content-length|connection|transfer-encoding)$/i.test(name) || /[\r\n]/.test(header)) throw new AppError(`Unsafe header in ${label}.`, "CONTROLLED_RACE_REQUEST_INVALID"); validateSensitive(name, header, label); }
  inspectFields(value.fields, label);
  for (const [name, entry] of new URL(value.url).searchParams) validateSensitive(name, entry, label);
  for (const ref of refs(value, "CAPTURE")) if (!captures.has(ref)) throw new AppError(`Request ${label} references unavailable capture ${ref}.`, "CONTROLLED_RACE_REFERENCE_INVALID");
  for (const text of stringValues(value)) if (/\{\{|\}\}/.test(text.replace(/\{\{(?:SECRET|CAPTURE):[A-Za-z0-9._-]+\}\}/g, ""))) throw new AppError(`Request ${label} contains a malformed reference.`, "CONTROLLED_RACE_REFERENCE_INVALID");
}

function validateAssertion(value: z.infer<typeof assertionSchema>, captures: Set<string>, groups: Set<string>): void {
  const captureRefs = value.kind === "VALUE_COMPARE" ? [value.left, value.right].filter((item) => item.source === "CAPTURE").map((item) => (item as { ref: string }).ref) : value.kind === "NUMERIC_DELTA" || value.kind === "EVENT_COUNT_DELTA" || value.kind === "STATE_TRANSITION" ? [value.before, value.after] : [];
  for (const ref of captureRefs) if (!captures.has(ref)) throw new AppError(`Invariant ${value.id} references unknown capture ${ref}.`, "CONTROLLED_RACE_REFERENCE_INVALID");
  if (value.kind === "GROUP_OUTCOME_COUNT" && !groups.has(value.groupId)) throw new AppError(`Invariant ${value.id} references unknown race group.`, "CONTROLLED_RACE_REFERENCE_INVALID");
}

function fingerprint(item: z.infer<typeof caseSchema>, actors: PlannedActor[]): string {
  return securityContractFingerprint("controlled-race", {
    schemaVersion: 1,
    category: item.category,
    target: item.target,
    actors,
    authorization: item.authorization,
    preState: item.preState,
    groups: item.groups,
    postState: item.postState,
    invariants: item.invariants,
    cleanupRequired: item.cleanupRequired,
    cleanup: item.cleanup,
    cleanupVerification: item.cleanupVerification,
    cleanupInvariants: item.cleanupInvariants
  });
}

function claim(value: string, values: Set<string>, kind: string): void { if (values.has(value)) throw new AppError(`Duplicate ${kind} ${value}.`, "CONTROLLED_RACE_DUPLICATE_ID"); values.add(value); }
function refs(value: unknown, kind: "SECRET" | "CAPTURE"): string[] { return [...new Set([...JSON.stringify(value).matchAll(new RegExp(`\\{\\{${kind}:([A-Za-z0-9._-]+)\\}\\}`, "g"))].map((match) => match[1]!))]; }
function segments(value: string): string[] { return value.replace(/\[(\d+)\]/g, ".$1").split("."); }
function stringValues(value: unknown): string[] { if (typeof value === "string") return [value]; if (Array.isArray(value)) return value.flatMap(stringValues); if (value && typeof value === "object") return Object.values(value as Record<string, unknown>).flatMap(stringValues); return []; }
function validateSensitive(key: string, value: string, label: string): void { if (!/(?:password|token|secret|cookie|authorization|email|username|code|session|credential|idempotency|csrf|api[-_]?key|user(?:id)?|account(?:id)?|tenant(?:id)?|principal(?:id)?|transaction(?:id)?|payment(?:id)?|order(?:id)?|object(?:id)?|identity|invite|verification|recovery)/i.test(key)) return; const references = value.match(/\{\{(?:SECRET|CAPTURE):[A-Za-z0-9._-]+\}\}/g) ?? []; const framing = value.replace(/\{\{(?:SECRET|CAPTURE):[A-Za-z0-9._-]+\}\}/g, "").trim(); if (references.length === 0 || !/^(?:Bearer|Basic)?[\s,;:=._-]*$/i.test(framing)) throw new AppError(`Sensitive value ${key} in ${label} must be reference-only.`, "CONTROLLED_RACE_LITERAL_SECRET_REJECTED"); }
function inspectFields(value: unknown, label: string, key = ""): void { if (Array.isArray(value)) { value.forEach((entry) => inspectFields(entry, label, key)); return; } if (!value || typeof value !== "object") { if (typeof value === "string") validateSensitive(key, value, label); return; } for (const [childKey, child] of Object.entries(value as Record<string, unknown>)) inspectFields(child, label, childKey); }
function assertSafeObject(value: unknown): void { if (Array.isArray(value)) { value.forEach(assertSafeObject); return; } if (!value || typeof value !== "object") return; for (const [key, child] of Object.entries(value as Record<string, unknown>)) { if (["__proto__", "prototype", "constructor"].includes(key)) throw new AppError(`Unsafe object key ${key}.`, "CONTROLLED_RACE_INPUT_INVALID"); assertSafeObject(child); } }
