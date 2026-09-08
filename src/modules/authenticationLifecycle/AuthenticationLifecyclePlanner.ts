import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import { authenticationLifecycleSecrets, type AuthProfile } from "../../core/auth/AuthProfile.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import { securityContractFingerprint } from "../../core/comparisons/SecurityContractFingerprint.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { authenticationLifecycleCategories, type AuthenticationLifecycleCasePlan, type AuthenticationLifecyclePlan } from "./AuthenticationLifecycleTypes.js";

const identifier = z.string().regex(/^[A-Za-z0-9._-]{1,100}$/);
const placeholder = /^\{\{(SECRET|CAPTURE):([A-Za-z0-9._-]{1,100})\}\}$/;
const embeddedPlaceholder = /\{\{(?:SECRET|CAPTURE):[A-Za-z0-9._-]{1,100}\}\}/g;
const pathPattern = /^[A-Za-z_$][A-Za-z0-9_$]*(?:\[(?:0|[1-9][0-9]{0,2})\]|\.[A-Za-z_$][A-Za-z0-9_$]*){0,8}$/;
const methodSchema = z.enum(["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"]);
const actorSchema = z.object({
  id: identifier,
  safeAlias: z.string().min(1).max(80),
  authSlot: z.enum(["anonymous", "primary", "account_a", "account_b"]),
  requestAuthentication: z.enum(["NONE", "PROFILE"]).optional(),
  relationship: z.string().min(1).max(80),
  declaredState: z.string().min(1).max(80),
  tenantAlias: z.string().min(1).max(80).optional()
}).strict();
const authorizationSchema = z.object({
  mode: z.enum(["OBSERVE_ONLY", "CONTROLLED_LIFECYCLE"]),
  environment: z.enum(["LOCAL", "TEST", "STAGING", "PRODUCTION"]),
  confirmation: z.literal("I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING").optional(),
  authorizedBy: z.string().min(2).max(160).optional(),
  changeTicket: z.string().min(1).max(160).optional(),
  authorizedAt: z.string().datetime().optional(),
  expiresAt: z.string().datetime().optional(),
  disposableAccounts: z.boolean().default(false),
  productionAcknowledged: z.boolean().default(false)
}).strict();
const captureSchema = z.discriminatedUnion("source", [
  z.object({ name: identifier, source: z.literal("JSON"), path: z.string().regex(pathPattern) }).strict(),
  z.object({ name: identifier, source: z.literal("HEADER"), header: z.string().min(1).max(100) }).strict(),
  z.object({ name: identifier, source: z.literal("COOKIE"), cookie: z.string().min(1).max(100) }).strict()
]);
const assertionSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("STATUS_IN"), values: z.array(z.number().int().min(100).max(599)).min(1).max(20) }).strict(),
  z.object({ kind: z.literal("STATUS_NOT_IN"), values: z.array(z.number().int().min(100).max(599)).min(1).max(20) }).strict(),
  z.object({ kind: z.literal("HEADER_PRESENT"), header: z.string().min(1).max(100) }).strict(),
  z.object({ kind: z.literal("HEADER_ABSENT"), header: z.string().min(1).max(100) }).strict(),
  z.object({ kind: z.literal("JSON_EQUALS"), path: z.string().regex(pathPattern), expected: z.union([z.string().max(200), z.number(), z.boolean(), z.null()]) }).strict(),
  z.object({ kind: z.literal("JSON_EQUALS_SECRET"), path: z.string().regex(pathPattern), secretRef: identifier }).strict(),
  z.object({ kind: z.literal("REDIRECT_LOCATION_ALLOWED"), allowedOrigins: z.array(z.string().url()).min(1).max(10), allowedPathPrefixes: z.array(z.string().startsWith("/").max(500)).min(1).max(20) }).strict(),
  z.object({ kind: z.literal("REDIRECT_QUERY_EQUALS_SECRET"), parameter: identifier, secretRef: identifier }).strict(),
  z.object({ kind: z.literal("CAPTURE_ROTATED"), capture: identifier, comparedTo: z.object({ source: z.enum(["SECRET", "CAPTURE"]), ref: identifier }).strict() }).strict(),
  z.object({ kind: z.literal("CAPTURE_UNCHANGED"), capture: identifier, comparedTo: z.object({ source: z.enum(["SECRET", "CAPTURE"]), ref: identifier }).strict() }).strict(),
  z.object({ kind: z.literal("RESPONSE_SIMILAR"), stepId: identifier, compareStatus: z.boolean().default(true), compareShape: z.boolean().default(true), compareBodyDigest: z.boolean().default(true), compareTiming: z.boolean().default(false), maxLengthDelta: z.number().int().min(0).max(8192).default(128), maxResponseTimeDeltaMs: z.number().int().min(0).max(60_000).default(250) }).strict(),
  z.object({ kind: z.literal("RESPONSE_DIFFERENT"), stepId: identifier, compareStatus: z.boolean().default(true), compareShape: z.boolean().default(true), compareBodyDigest: z.boolean().default(true), compareTiming: z.boolean().default(false), maxLengthDelta: z.number().int().min(0).max(8192).default(128), maxResponseTimeDeltaMs: z.number().int().min(0).max(60_000).default(250) }).strict()
]);
const stepSchema = z.object({
  id: identifier,
  phase: z.enum(["SETUP", "ACTION", "VERIFY", "CLEANUP"]),
  actorId: identifier,
  waitBeforeMs: z.number().int().min(0).max(3_600_000).default(0),
  request: z.object({
    method: methodSchema,
    url: z.string().url().max(2048),
    stateChanging: z.boolean().default(false),
    headers: z.record(z.string().max(8192)).default({}),
    bodyFormat: z.enum(["JSON", "FORM"]).optional(),
    fields: z.record(z.unknown()).optional()
  }).strict(),
  captures: z.array(captureSchema).max(12).default([]),
  assertions: z.array(assertionSchema).max(20).default([])
}).strict();
export const authenticationLifecycleCaseInputSchema = z.object({
  id: identifier,
  label: z.string().min(1).max(160),
  category: z.enum(authenticationLifecycleCategories),
  actors: z.array(actorSchema).min(1).max(8),
  authorization: authorizationSchema,
  cleanupRequired: z.boolean().default(false),
  steps: z.array(stepSchema).min(1).max(40)
}).strict();

export const authenticationLifecycleInputSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  maxCases: z.number().int().min(1).max(50).default(20),
  maxStepsPerCase: z.number().int().min(1).max(40).default(20),
  maxRequests: z.number().int().min(1).max(500).default(100),
  maxResponseBytes: z.number().int().min(256).max(262144).default(32768),
  cases: z.array(authenticationLifecycleCaseInputSchema).min(1).max(50)
}).strict();

export type AuthenticationLifecycleInput = z.infer<typeof authenticationLifecycleInputSchema>;

export async function loadAuthenticationLifecycleInput(path: string): Promise<AuthenticationLifecycleInput> {
  const raw = (await readFile(path, "utf8")).replace(/^\uFEFF/, "");
  const parsed = authenticationLifecycleInputSchema.safeParse(JSON.parse(raw));
  if (!parsed.success) throw new AppError(parsed.error.message, "AUTH_LIFECYCLE_INPUT_INVALID");
  return parsed.data;
}

export function planAuthenticationLifecycle(input: AuthenticationLifecycleInput, context: { target: string; scope: RouteCairnScope; authProfile?: AuthProfile; authProfileSet?: AuthProfileSet; now?: Date }): AuthenticationLifecyclePlan {
  const parsed = authenticationLifecycleInputSchema.parse(input);
  const matcher = new ScopeMatcher(context.target, context.scope);
  const targetOrigin = new URL(context.target).origin;
  if (parsed.cases.length > parsed.maxCases) throw new AppError("Authentication lifecycle cases exceed maxCases.", "AUTH_LIFECYCLE_LIMIT_EXCEEDED");
  const ids = new Set<string>();
  let requests = 0;
  const now = context.now ?? new Date();
  const cases = parsed.cases.map((testCase) => {
  if (ids.has(testCase.id)) throw new AppError(`Duplicate lifecycle case id ${testCase.id}.`, "AUTH_LIFECYCLE_DUPLICATE_ID");
    assertNonIdentifyingLabel(testCase.id, `case id ${testCase.id}`);
    assertNonIdentifyingLabel(testCase.label, `case label ${testCase.id}`);
    ids.add(testCase.id);
    if (testCase.steps.length > parsed.maxStepsPerCase) throw new AppError(`Lifecycle case ${testCase.id} exceeds maxStepsPerCase.`, "AUTH_LIFECYCLE_LIMIT_EXCEEDED");
    requests += testCase.steps.length;
    validateCase(testCase, matcher, targetOrigin, context, now);
    return JSON.parse(JSON.stringify({
      ...testCase,
      actors: testCase.actors.map((actor) => ({ ...actor, requestAuthentication: actor.requestAuthentication ?? (actor.authSlot === "anonymous" ? "NONE" : "PROFILE") })),
      authorization: {
        mode: testCase.authorization.mode,
        environment: testCase.authorization.environment,
        authorizationIdentityConfirmed: Boolean(testCase.authorization.authorizedBy),
        changeTicketConfirmed: Boolean(testCase.authorization.changeTicket),
        ...(testCase.authorization.authorizedAt ? { authorizedAt: testCase.authorization.authorizedAt } : {}),
        ...(testCase.authorization.expiresAt ? { expiresAt: testCase.authorization.expiresAt } : {}),
        disposableAccounts: testCase.authorization.disposableAccounts,
        productionAcknowledged: testCase.authorization.productionAcknowledged,
        confirmationAccepted: testCase.authorization.confirmation === "I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING"
      },
      comparisonFingerprint: comparisonFingerprint(testCase)
    })) as AuthenticationLifecycleCasePlan;
  });
  if (requests > parsed.maxRequests) throw new AppError("Authentication lifecycle steps exceed maxRequests.", "AUTH_LIFECYCLE_LIMIT_EXCEEDED");
  return {
    schemaVersion: 1,
    enabled: true,
    source: "EXPLICIT_MANIFEST",
    targetOrigin,
    maxCases: parsed.maxCases,
    maxStepsPerCase: parsed.maxStepsPerCase,
    maxRequests: parsed.maxRequests,
    maxResponseBytes: parsed.maxResponseBytes,
    cases,
    notes: [
      "Lifecycle traffic is never learned as mutation authorization; every state-changing step requires its own expiring controlled authorization.",
      "Secrets resolve only from worker-held credential profiles and captured values remain case-local.",
      "Cleanup steps are attempted after any transmitted state change, including after verification failure."
    ]
  };
}

function validateCase(testCase: z.infer<typeof authenticationLifecycleCaseInputSchema>, matcher: ScopeMatcher, targetOrigin: string, context: { authProfile?: AuthProfile; authProfileSet?: AuthProfileSet }, now: Date): void {
  const actorIds = new Set<string>();
  for (const actor of testCase.actors) {
    if (actorIds.has(actor.id)) throw new AppError(`Duplicate actor ${actor.id} in lifecycle case ${testCase.id}.`, "AUTH_LIFECYCLE_DUPLICATE_ID");
    actorIds.add(actor.id);
    if (actor.authSlot === "anonymous" && actor.requestAuthentication === "PROFILE") throw new AppError(`Anonymous lifecycle actor ${actor.id} cannot send profile authentication.`, "AUTH_LIFECYCLE_ACTOR_INVALID");
    for (const [value, label] of [[actor.safeAlias, "safeAlias"], [actor.relationship, "relationship"], [actor.declaredState, "declaredState"], [actor.tenantAlias, "tenantAlias"]] as const) if (value) assertNonIdentifyingLabel(value, `actor ${actor.id} ${label}`);
    if (actor.authSlot === "primary" && !context.authProfile) throw new AppError(`Lifecycle actor ${actor.id} requires a primary auth profile.`, "AUTH_LIFECYCLE_CREDENTIAL_REQUIRED");
    if ((actor.authSlot === "account_a" || actor.authSlot === "account_b") && !context.authProfileSet) throw new AppError(`Lifecycle actor ${actor.id} requires Account A/B auth profiles.`, "AUTH_LIFECYCLE_CREDENTIAL_REQUIRED");
  }
  if (context.authProfileSet && profilesShareIdentityOrCredentials(context.authProfileSet.accountA, context.authProfileSet.accountB)) throw new AppError("Account A and Account B lifecycle actors must have distinct declared identities and credential material.", "AUTH_LIFECYCLE_ACTOR_CONFUSION");
  const stepIds = new Set<string>();
  const captureNames = new Set<string>();
  let hasMutation = false;
  let securityAssertionCount = 0;
  for (const step of testCase.steps) {
    const priorStepIds = new Set(stepIds);
    if (stepIds.has(step.id)) throw new AppError(`Duplicate step ${step.id} in lifecycle case ${testCase.id}.`, "AUTH_LIFECYCLE_DUPLICATE_ID");
    stepIds.add(step.id);
    if (!actorIds.has(step.actorId)) throw new AppError(`Step ${step.id} references an undeclared actor.`, "AUTH_LIFECYCLE_ACTOR_INVALID");
    const decision = matcher.decide(step.request.url, step.request.method);
    if (!decision.allowed || new URL(step.request.url).origin !== targetOrigin) throw new AppError(`Lifecycle step ${step.id} is outside the exact target origin.`, "AUTH_LIFECYCLE_SCOPE_INVALID");
    if (["POST", "PATCH", "PUT", "DELETE"].includes(step.request.method) && !step.request.stateChanging) throw new AppError(`Unsafe-method step ${step.id} must declare stateChanging=true.`, "AUTH_LIFECYCLE_MUTATION_DECLARATION_REQUIRED");
    if (step.request.stateChanging) hasMutation = true;
    validateTemplates(step.request.headers, step.request.fields, `case ${testCase.id} step ${step.id}`);
    validateUrlTemplate(step.request.url, `case ${testCase.id} step ${step.id}`);
    validateCaptureReferences(step, captureNames);
    validateSecretReferences(step, testCase.actors, context);
    for (const capture of step.captures) {
      if (captureNames.has(capture.name)) throw new AppError(`Capture ${capture.name} is assigned more than once.`, "AUTH_LIFECYCLE_CAPTURE_INVALID");
      captureNames.add(capture.name);
    }
    if ((step.phase === "VERIFY" || step.phase === "CLEANUP") && step.assertions.length === 0) throw new AppError(`${step.phase} step ${step.id} requires an assertion.`, "AUTH_LIFECYCLE_ASSERTION_REQUIRED");
    if (step.phase !== "CLEANUP") securityAssertionCount += step.assertions.length;
    for (const assertion of step.assertions) if ((assertion.kind === "RESPONSE_SIMILAR" || assertion.kind === "RESPONSE_DIFFERENT") && !priorStepIds.has(assertion.stepId)) throw new AppError(`Response comparison in ${step.id} must reference an earlier step.`, "AUTH_LIFECYCLE_ASSERTION_INVALID");
  }
  for (const step of testCase.steps) for (const assertion of step.assertions) {
    if ((assertion.kind === "RESPONSE_SIMILAR" || assertion.kind === "RESPONSE_DIFFERENT") && !stepIds.has(assertion.stepId)) throw new AppError(`Assertion references unknown step ${assertion.stepId}.`, "AUTH_LIFECYCLE_ASSERTION_INVALID");
    if (assertion.kind === "JSON_EQUALS" && typeof assertion.expected === "string" && (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(assertion.expected) || /^Bearer\s+/i.test(assertion.expected))) throw new AppError(`Credential-like JSON assertion literal in ${step.id} was rejected.`, "AUTH_LIFECYCLE_LITERAL_SECRET_REJECTED");
  }
  if (testCase.cleanupRequired && !testCase.steps.some((step) => step.phase === "CLEANUP")) throw new AppError(`Lifecycle case ${testCase.id} requires cleanup steps.`, "AUTH_LIFECYCLE_CLEANUP_REQUIRED");
  if (securityAssertionCount === 0) throw new AppError(`Lifecycle case ${testCase.id} has no non-cleanup security assertion.`, "AUTH_LIFECYCLE_ASSERTION_REQUIRED");
  if (hasMutation) {
    const auth = testCase.authorization;
    if (auth.mode !== "CONTROLLED_LIFECYCLE" || auth.confirmation !== "I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING" || !auth.authorizedBy || !auth.changeTicket || !auth.authorizedAt || !auth.expiresAt || !auth.disposableAccounts) throw new AppError(`State-changing lifecycle case ${testCase.id} lacks an exact controlled authorization contract.`, "AUTH_LIFECYCLE_AUTHORIZATION_REQUIRED");
    if (new Date(auth.authorizedAt).getTime() > now.getTime() || new Date(auth.expiresAt).getTime() <= now.getTime()) throw new AppError(`Lifecycle authorization for ${testCase.id} is not currently valid.`, "AUTH_LIFECYCLE_AUTHORIZATION_EXPIRED");
    if (auth.environment === "PRODUCTION" && !auth.productionAcknowledged) throw new AppError(`Production lifecycle case ${testCase.id} requires productionAcknowledged=true.`, "AUTH_LIFECYCLE_PRODUCTION_ACK_REQUIRED");
    if (!testCase.cleanupRequired || !testCase.steps.some((step) => step.phase === "CLEANUP")) throw new AppError(`State-changing lifecycle case ${testCase.id} requires verified cleanup.`, "AUTH_LIFECYCLE_CLEANUP_REQUIRED");
  }
}

function profilesShareIdentityOrCredentials(accountA: AuthProfile, accountB: AuthProfile): boolean {
  if (accountA.principalId && accountB.principalId && accountA.principalId === accountB.principalId) return true;
  const signature = (profile: AuthProfile) => JSON.stringify({
    headers: Object.entries(profile.headers).sort(([left], [right]) => left.localeCompare(right)),
    cookies: profile.cookies.map((cookie) => [cookie.name, cookie.value]).sort(([left], [right]) => String(left).localeCompare(String(right))),
    lifecycleSecrets: Object.entries(profile.lifecycleSecrets ?? {}).sort(([left], [right]) => left.localeCompare(right))
  });
  return signature(accountA) === signature(accountB);
}

function validateSecretReferences(step: z.infer<typeof stepSchema>, actors: z.infer<typeof actorSchema>[], context: { authProfile?: AuthProfile; authProfileSet?: AuthProfileSet }): void {
  const actor = actors.find((item) => item.id === step.actorId)!;
  const profile = actor.authSlot === "primary" ? context.authProfile : actor.authSlot === "account_a" ? context.authProfileSet?.accountA : actor.authSlot === "account_b" ? context.authProfileSet?.accountB : undefined;
  const available = profile ? authenticationLifecycleSecrets(profile) : {};
  const values = [step.request.url, ...Object.values(step.request.headers), ...leafStrings(step.request.fields), ...step.assertions.flatMap((assertion) => assertion.kind === "JSON_EQUALS_SECRET" || assertion.kind === "REDIRECT_QUERY_EQUALS_SECRET" ? [`{{SECRET:${assertion.secretRef}}}`] : assertion.kind === "CAPTURE_ROTATED" || assertion.kind === "CAPTURE_UNCHANGED" ? assertion.comparedTo.source === "SECRET" ? [`{{SECRET:${assertion.comparedTo.ref}}}`] : [] : [])];
  for (const value of values) {
    const matches = value.matchAll(/\{\{SECRET:([A-Za-z0-9._-]+)\}\}/g);
    for (const match of matches) if (!Object.prototype.hasOwnProperty.call(available, match[1]!)) throw new AppError(`Lifecycle step ${step.id} references unavailable secret ${match[1]}.`, "AUTH_LIFECYCLE_SECRET_REQUIRED");
  }
}

function leafStrings(value: unknown): string[] {
  const values: string[] = [];
  walk(value, [], (entry) => { if (typeof entry === "string") values.push(entry); });
  return values;
}

function validateTemplates(headers: Record<string, string>, fields: Record<string, unknown> | undefined, label: string): void {
  for (const [name, value] of Object.entries(headers)) {
    if (/^(host|content-length|connection|transfer-encoding)$/i.test(name) || /[\r\n]/.test(value)) throw new AppError(`Unsafe header in ${label}.`, "AUTH_LIFECYCLE_TEMPLATE_INVALID");
    validateLeaf(value, name, label);
  }
  walk(fields, [], (value, path) => validateLeaf(value, path.at(-1) ?? "field", label));
}

function validateLeaf(value: unknown, key: string, label: string): void {
  if (typeof value !== "string") return;
  const placeholders = value.match(embeddedPlaceholder) ?? [];
  if (value.includes("{{") && placeholders.length === 0) throw new AppError(`Invalid placeholder in ${label}.`, "AUTH_LIFECYCLE_TEMPLATE_INVALID");
  const sensitiveKey = /(password|token|secret|cookie|authorization|email|username|code|session|credential|user|account|tenant|principal|identity|invite|verification|recovery)/i.test(key);
  const safeCredentialTemplate = placeholder.test(value) || (/authorization/i.test(key) && /^Bearer \{\{(?:SECRET|CAPTURE):[A-Za-z0-9._-]+\}\}$/.test(value)) || (/cookie/i.test(key) && /^(?:[A-Za-z0-9._-]+=\{\{(?:SECRET|CAPTURE):[A-Za-z0-9._-]+\}\})(?:; [A-Za-z0-9._-]+=\{\{(?:SECRET|CAPTURE):[A-Za-z0-9._-]+\}\})*$/.test(value));
  if (sensitiveKey && !safeCredentialTemplate) throw new AppError(`Sensitive field ${key} in ${label} must use a SECRET or CAPTURE reference.`, "AUTH_LIFECYCLE_LITERAL_SECRET_REJECTED");
  if ((/^Bearer\s+/i.test(value) || /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) && !safeCredentialTemplate) throw new AppError(`Credential-like literal in ${label} was rejected.`, "AUTH_LIFECYCLE_LITERAL_SECRET_REJECTED");
}

function validateUrlTemplate(value: string, label: string): void {
  const parsed = new URL(value);
  for (const segment of parsed.pathname.split("/").filter(Boolean)) if (looksLikeRawIdentifier(decodeURIComponent(segment))) throw new AppError(`Identifier-like path segment in ${label} must use a SECRET or CAPTURE reference.`, "AUTH_LIFECYCLE_LITERAL_SECRET_REJECTED");
  for (const [name, entry] of parsed.searchParams) {
    if (/(password|token|secret|email|username|code|session|credential|state|user|account|tenant|principal|identity|invite|verification|recovery)/i.test(name) && !(entry.match(embeddedPlaceholder)?.length)) throw new AppError(`Sensitive query field ${name} in ${label} must use a reference.`, "AUTH_LIFECYCLE_LITERAL_SECRET_REJECTED");
    if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(entry)) throw new AppError(`Email-like query literal in ${label} was rejected.`, "AUTH_LIFECYCLE_LITERAL_SECRET_REJECTED");
  }
}

function assertNonIdentifyingLabel(value: string, label: string): void {
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value) || looksLikeRawIdentifier(value)) throw new AppError(`Lifecycle ${label} must be a non-identifying operator label.`, "AUTH_LIFECYCLE_LITERAL_SECRET_REJECTED");
}

function looksLikeRawIdentifier(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value) || /^[0-9a-f]{24,}$/i.test(value) || /^[A-Za-z0-9_-]{40,}$/.test(value);
}

function validateCaptureReferences(step: z.infer<typeof stepSchema>, availableBeforeStep: Set<string>): void {
  const availableForAssertions = new Set([...availableBeforeStep, ...step.captures.map((capture) => capture.name)]);
  const requestValues = [step.request.url, ...Object.values(step.request.headers), ...leafStrings(step.request.fields)];
  for (const value of requestValues) for (const match of value.matchAll(/\{\{CAPTURE:([A-Za-z0-9._-]+)\}\}/g)) if (!availableBeforeStep.has(match[1]!)) throw new AppError(`Lifecycle step ${step.id} references capture ${match[1]} before it exists.`, "AUTH_LIFECYCLE_CAPTURE_INVALID");
  for (const assertion of step.assertions) if ((assertion.kind === "CAPTURE_ROTATED" || assertion.kind === "CAPTURE_UNCHANGED") && (!availableForAssertions.has(assertion.capture) || (assertion.comparedTo.source === "CAPTURE" && !availableForAssertions.has(assertion.comparedTo.ref)))) throw new AppError(`Lifecycle assertion in ${step.id} references an unavailable capture.`, "AUTH_LIFECYCLE_CAPTURE_INVALID");
}

function walk(value: unknown, path: string[], fn: (value: unknown, path: string[]) => void): void {
  if (Array.isArray(value)) return value.forEach((entry, index) => walk(entry, [...path, String(index)], fn));
  if (value && typeof value === "object") return Object.entries(value as Record<string, unknown>).forEach(([key, entry]) => walk(entry, [...path, key], fn));
  fn(value, path);
}

function comparisonFingerprint(testCase: z.infer<typeof authenticationLifecycleCaseInputSchema>): string {
  return securityContractFingerprint("authentication-lifecycle", {
    schemaVersion: 1,
    category: testCase.category,
    actors: testCase.actors.map((actor) => ({ ...actor, requestAuthentication: actor.requestAuthentication ?? (actor.authSlot === "anonymous" ? "NONE" : "PROFILE") })),
    authorization: testCase.authorization,
    cleanupRequired: testCase.cleanupRequired,
    steps: testCase.steps
  });
}
