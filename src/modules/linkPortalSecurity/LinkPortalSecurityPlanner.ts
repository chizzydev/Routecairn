import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import { authenticationLifecycleSecrets, type AuthProfile } from "../../core/auth/AuthProfile.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import { securityContractFingerprint } from "../../core/comparisons/SecurityContractFingerprint.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { parseSafeFieldPath } from "../fieldExposureTesting/SafeFieldPath.js";
import { linkPortalSecurityCategories, type LinkPortalActorPlan, type LinkPortalAuthSlot, type LinkPortalSecurityCasePlan, type LinkPortalSecurityPlan } from "./LinkPortalSecurityTypes.js";

const maxFileBytes = 512 * 1024;
const identifier = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/);
const authSlot = z.enum(["anonymous", "primary", "account_a", "account_b"]);
const method = z.enum(["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"]);
const statuses = z.array(z.number().int().min(100).max(599)).min(1).max(30);
const reference = /\{\{(SECRET|CAPTURE):([A-Za-z0-9._-]{1,100})\}\}/g;
const exactCapture = /^\{\{CAPTURE:([A-Za-z0-9._-]{1,100})\}\}$/;
const forbiddenHeader = /^(?:host|content-length|connection|transfer-encoding|upgrade|expect|te|trailer)$/i;
const secretLikeKey = /(?:signature|sig|token|secret|key|code|invite|ticket|credential|authorization|password)/i;

const actorSchema = z.object({
  id: identifier,
  safeAlias: z.string().min(1).max(80),
  authSlot,
  sendAuthentication: z.boolean().optional(),
  relationship: z.string().min(1).max(120),
  principalId: z.string().min(1).max(256).optional(),
  tenantId: z.string().min(1).max(256).optional()
}).strict();

const resourceSchema = z.object({
  id: identifier,
  safeAlias: z.string().min(1).max(100),
  kind: z.enum(["SIGNED_LINK", "INVITE", "PORTAL", "EXPORT", "EVIDENCE_ARTIFACT", "OBJECT_PATH"]),
  pathTemplate: z.string().startsWith("/").max(1000),
  allowedOrigins: z.array(z.string().url().max(1000)).min(1).max(8),
  ownerActorId: identifier.optional(),
  tenantId: z.string().min(1).max(256).optional(),
  declaredState: z.string().min(1).max(80).optional(),
  expiresAt: z.string().datetime().optional()
}).strict();

const authorizationSchema = z.object({
  mode: z.enum(["OBSERVE_ONLY", "CONTROLLED_LINK_FLOW"]),
  environment: z.enum(["LOCAL", "TEST", "STAGING", "PRODUCTION"]),
  confirmation: z.literal("I_AUTHORIZE_CONTROLLED_LINK_PORTAL_EXPORT_TESTING").optional(),
  authorizedBy: z.string().min(2).max(160).optional(),
  changeTicket: z.string().min(1).max(160).optional(),
  authorizedAt: z.string().datetime().optional(),
  expiresAt: z.string().datetime().optional(),
  disposableResource: z.boolean().default(false),
  productionAcknowledged: z.boolean().default(false)
}).strict();

const captureSchema = z.discriminatedUnion("source", [
  z.object({ name: identifier, source: z.literal("JSON"), path: z.string().min(1).max(160) }).strict(),
  z.object({ name: identifier, source: z.literal("HEADER"), header: z.string().min(1).max(100) }).strict()
]);

const assertionSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("STATUS_IN"), values: statuses }).strict(),
  z.object({ kind: z.literal("STATUS_NOT_IN"), values: statuses }).strict(),
  z.object({ kind: z.literal("DECISION"), expected: z.enum(["ALLOW", "DENY"]), allowedStatuses: statuses.default([200, 201, 202, 204, 206]), deniedStatuses: statuses.default([400, 401, 403, 404, 405, 409, 410, 422]) }).strict(),
  z.object({ kind: z.literal("HEADER_PRESENT"), header: z.string().min(1).max(100) }).strict(),
  z.object({ kind: z.literal("HEADER_ABSENT"), header: z.string().min(1).max(100) }).strict(),
  z.object({ kind: z.literal("JSON_EQUALS_SECRET"), path: z.string().min(1).max(160), secretSource: authSlot, secretRef: identifier }).strict(),
  z.object({ kind: z.literal("JSON_NOT_EQUALS_SECRET"), path: z.string().min(1).max(160), secretSource: authSlot, secretRef: identifier }).strict(),
  z.object({ kind: z.literal("BODY_FINGERPRINT"), expectedSha256: z.string().regex(/^[a-f0-9]{64}$/i) }).strict(),
  z.object({ kind: z.literal("RESPONSE_FINGERPRINT_MATCH"), stepId: identifier }).strict(),
  z.object({ kind: z.literal("RESPONSE_FINGERPRINT_DIFFERENT"), stepId: identifier }).strict()
]);

const requestSchema = z.object({
  method,
  urlTemplate: z.string().min(1).max(4096),
  stateChanging: z.boolean().default(false),
  secretSource: authSlot.default("anonymous"),
  headers: z.record(z.string().max(8192)).default({}),
  bodyFormat: z.enum(["JSON", "FORM"]).optional(),
  fields: z.record(z.unknown()).optional(),
  tamper: z.object({ kind: z.literal("QUERY_PARAMETER"), parameter: identifier, strategy: z.literal("FLIP_LAST_CHARACTER").default("FLIP_LAST_CHARACTER") }).strict().optional()
}).strict();

const stepSchema = z.object({
  id: identifier,
  phase: z.enum(["CONTROL", "ACTION", "VERIFY", "CLEANUP"]),
  actorId: identifier,
  resourceId: identifier,
  waitBeforeMs: z.number().int().min(0).max(3_600_000).default(0),
  request: requestSchema,
  captures: z.array(captureSchema).max(12).default([]),
  assertions: z.array(assertionSchema).max(20).default([])
}).strict();

const caseSchema = z.object({
  id: identifier,
  label: z.string().min(1).max(160),
  category: z.enum(linkPortalSecurityCategories),
  authorization: authorizationSchema,
  cleanupRequired: z.boolean().default(false),
  steps: z.array(stepSchema).min(1).max(30)
}).strict();

export const linkPortalSecurityInputSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  maxCases: z.number().int().min(1).max(60).default(30),
  maxStepsPerCase: z.number().int().min(1).max(30).default(16),
  maxRequests: z.number().int().min(1).max(500).default(120),
  maxResponseBytes: z.number().int().min(512).max(1024 * 1024).default(65536),
  actors: z.array(actorSchema).min(1).max(8),
  resources: z.array(resourceSchema).min(1).max(100),
  cases: z.array(caseSchema).min(1).max(60)
}).strict();

export type LinkPortalSecurityInput = z.infer<typeof linkPortalSecurityInputSchema>;
type PlannerContext = { target: string; scope: RouteCairnScope; authProfile?: AuthProfile; authProfileSet?: AuthProfileSet; now?: Date };

export async function loadLinkPortalSecurityInput(filePath: string): Promise<LinkPortalSecurityInput> {
  const raw = await readFile(filePath);
  if (raw.byteLength > maxFileBytes) throw new AppError(`Link/portal security manifest exceeds ${maxFileBytes} bytes.`, "LINK_PORTAL_FILE_TOO_LARGE");
  let json: unknown;
  try { json = JSON.parse(raw.toString("utf8").replace(/^\uFEFF/, "")); }
  catch { throw new AppError("Link/portal security manifest is not valid JSON.", "LINK_PORTAL_JSON_INVALID"); }
  const parsed = linkPortalSecurityInputSchema.safeParse(json);
  if (!parsed.success) throw new AppError(parsed.error.message, "LINK_PORTAL_INPUT_INVALID");
  return parsed.data;
}

export function planLinkPortalSecurity(input: LinkPortalSecurityInput, context: PlannerContext): LinkPortalSecurityPlan {
  const parsed = linkPortalSecurityInputSchema.parse(input);
  if (parsed.cases.length > parsed.maxCases) throw new AppError("Link/portal cases exceed maxCases.", "LINK_PORTAL_LIMIT_EXCEEDED");
  const matcher = new ScopeMatcher(context.target, context.scope);
  const targetOrigin = new URL(context.target).origin;
  const profiles = profilesFor(context);
  ensureUnique(parsed.actors.map((value) => value.id), "actor");
  ensureUnique(parsed.resources.map((value) => value.id), "resource");
  ensureUnique(parsed.cases.map((value) => value.id), "case");
  const actors = parsed.actors.map((value) => planActor(value, profiles));
  const actorById = new Map(actors.map((value) => [value.id, value]));
  const resources = parsed.resources.map((value) => {
    assertSafeLabel(value.safeAlias, `resource ${value.id} safeAlias`);
    if (/[?#\r\n\0]/.test(value.pathTemplate) || /\.\.(?:\/|\\)/.test(value.pathTemplate)) throw new AppError(`Resource ${value.id} has an unsafe pathTemplate.`, "LINK_PORTAL_PATH_TEMPLATE_INVALID");
    if (!/\{[A-Za-z][A-Za-z0-9_-]{0,39}\}/.test(value.pathTemplate)) throw new AppError(`Resource ${value.id} pathTemplate must contain a safe placeholder instead of an object or capability identifier.`, "LINK_PORTAL_PATH_TEMPLATE_INVALID");
    const origins = [...new Set(value.allowedOrigins.map(normalizeOrigin))];
    for (const origin of origins) if (!matcher.decide(`${origin}/`, "GET").allowed) throw new AppError(`Resource ${value.id} origin is outside scope.`, "LINK_PORTAL_ORIGIN_OUT_OF_SCOPE");
    if (value.ownerActorId && !actorById.has(value.ownerActorId)) throw new AppError(`Resource ${value.id} references an unknown owner actor.`, "LINK_PORTAL_UNKNOWN_ACTOR");
    return {
      id: value.id, safeAlias: value.safeAlias, kind: value.kind, pathTemplate: value.pathTemplate, allowedOrigins: origins,
      ...(value.ownerActorId ? { ownerActorId: value.ownerActorId } : {}),
      ...(value.tenantId ? { tenantFingerprint: fingerprint("tenant", value.tenantId) } : {}),
      ...(value.declaredState ? { declaredState: value.declaredState } : {}),
      ...(value.expiresAt ? { expiresAt: value.expiresAt } : {})
    };
  });
  const resourceById = new Map(resources.map((value) => [value.id, value]));
  let requestCount = 0;
  const now = context.now ?? new Date();
  const cases = parsed.cases.map((value) => {
    assertSafeLabel(value.label, `case ${value.id} label`);
    if (value.steps.length > parsed.maxStepsPerCase) throw new AppError(`Case ${value.id} exceeds maxStepsPerCase.`, "LINK_PORTAL_LIMIT_EXCEEDED");
    requestCount += value.steps.length;
    validateCase(value, actorById, resourceById, profiles, matcher, now);
    const authorization = {
      mode: value.authorization.mode,
      environment: value.authorization.environment,
      ...(value.authorization.authorizedAt ? { authorizedAt: value.authorization.authorizedAt } : {}),
      ...(value.authorization.expiresAt ? { expiresAt: value.authorization.expiresAt } : {}),
      authorizationIdentityConfirmed: Boolean(value.authorization.authorizedBy),
      changeTicketConfirmed: Boolean(value.authorization.changeTicket),
      disposableResource: value.authorization.disposableResource,
      productionAcknowledged: value.authorization.productionAcknowledged,
      confirmationAccepted: value.authorization.confirmation === "I_AUTHORIZE_CONTROLLED_LINK_PORTAL_EXPORT_TESTING"
    };
    return { id: value.id, label: value.label, category: value.category, authorization, cleanupRequired: value.cleanupRequired, steps: value.steps, comparisonFingerprint: caseFingerprint(value, actors, resources) } satisfies LinkPortalSecurityCasePlan;
  });
  if (requestCount > parsed.maxRequests) throw new AppError(`Link/portal plan requires ${requestCount} requests, exceeding maxRequests.`, "LINK_PORTAL_LIMIT_EXCEEDED");
  return { schemaVersion: 1, enabled: true, targetOrigin, maxCases: parsed.maxCases, maxStepsPerCase: parsed.maxStepsPerCase, maxRequests: parsed.maxRequests, maxResponseBytes: parsed.maxResponseBytes, actors, resources, cases, notes: [
    "Every executable URL is operator-supplied or a case-local capture and is revalidated against exact allowed origins and scan scope after secret expansion.",
    "Replay, acceptance, and revocation mutations require expiring authorization plus durable journaling and cleanup or an explicitly disposable resource.",
    "Signed values, invite tokens, object identifiers, emails, response bodies, and captured URLs remain worker-local and are excluded from reports."
  ] };
}

function planActor(value: z.infer<typeof actorSchema>, profiles: Readonly<Record<LinkPortalAuthSlot, AuthProfile | undefined>>): LinkPortalActorPlan {
  assertSafeLabel(value.safeAlias, `actor ${value.id} safeAlias`); assertSafeLabel(value.relationship, `actor ${value.id} relationship`);
  const profile = profiles[value.authSlot];
  const sendAuthentication = value.sendAuthentication ?? value.authSlot !== "anonymous";
  if (value.authSlot === "anonymous" && sendAuthentication) throw new AppError(`Anonymous actor ${value.id} cannot send profile authentication.`, "LINK_PORTAL_ACTOR_INVALID");
  if (value.authSlot !== "anonymous" && !profile) throw new AppError(`Actor ${value.id} requires an available auth profile.`, "LINK_PORTAL_CREDENTIAL_REQUIRED");
  if (value.principalId && profile?.principalId && value.principalId !== profile.principalId) throw new AppError(`Actor ${value.id} principal metadata does not match its profile.`, "LINK_PORTAL_ACTOR_IDENTITY_MISMATCH");
  if (value.tenantId && profile?.tenantId && value.tenantId !== profile.tenantId) throw new AppError(`Actor ${value.id} tenant metadata does not match its profile.`, "LINK_PORTAL_ACTOR_IDENTITY_MISMATCH");
  const principal = value.principalId ?? profile?.principalId; const tenant = value.tenantId ?? profile?.tenantId;
  return { id: value.id, safeAlias: value.safeAlias, authSlot: value.authSlot, sendAuthentication, relationship: value.relationship, ...(principal ? { principalFingerprint: fingerprint("principal", principal) } : {}), ...(tenant ? { tenantFingerprint: fingerprint("tenant", tenant) } : {}) };
}

function validateCase(value: z.infer<typeof caseSchema>, actors: ReadonlyMap<string, LinkPortalActorPlan>, resources: ReadonlyMap<string, LinkPortalSecurityPlan["resources"][number]>, profiles: Readonly<Record<LinkPortalAuthSlot, AuthProfile | undefined>>, matcher: ScopeMatcher, now: Date): void {
  ensureUnique(value.steps.map((step) => step.id), `step in case ${value.id}`);
  const captureNames = new Set<string>(); const priorSteps = new Set<string>(); let assertionCount = 0; let mutationCount = 0; let tamperCount = 0;
  for (const step of value.steps) {
    const actor = actors.get(step.actorId); const resource = resources.get(step.resourceId);
    if (!actor) throw new AppError(`Case ${value.id} step ${step.id} references an unknown actor.`, "LINK_PORTAL_UNKNOWN_ACTOR");
    if (!resource) throw new AppError(`Case ${value.id} step ${step.id} references an unknown resource.`, "LINK_PORTAL_UNKNOWN_RESOURCE");
    if (step.request.stateChanging) mutationCount++;
    if (["POST", "PATCH", "PUT", "DELETE"].includes(step.request.method) && !step.request.stateChanging) throw new AppError(`Unsafe method in ${value.id}/${step.id} requires stateChanging=true.`, "LINK_PORTAL_MUTATION_DECLARATION_REQUIRED");
    if (step.request.method === "DELETE" && step.phase !== "CLEANUP" && value.category !== "SIGNED_LINK_REVOCATION") throw new AppError(`DELETE is limited to revocation actions or cleanup.`, "LINK_PORTAL_METHOD_UNSAFE");
    validateHeaders(step.request.headers, `${value.id}/${step.id}`); validateValue(step.request.fields, `${value.id}/${step.id}`);
    validateUrlTemplate(step.request.urlTemplate, step.request.method, resource.allowedOrigins, matcher, captureNames, `${value.id}/${step.id}`);
    validateReferences(step.request.urlTemplate, step.request.headers, step.request.fields, step.request.secretSource, profiles, captureNames, `${value.id}/${step.id}`);
    if (step.request.tamper) {
      tamperCount++;
      if (step.request.method !== "GET" && step.request.method !== "HEAD") throw new AppError(`Signature tampering in ${value.id}/${step.id} must be read-only.`, "LINK_PORTAL_TAMPER_METHOD_UNSAFE");
      if (!exactCapture.test(step.request.urlTemplate)) {
        const parsed = parseTemplateUrl(step.request.urlTemplate);
        if (!parsed.searchParams.has(step.request.tamper.parameter)) throw new AppError(`Tamper parameter is absent from ${value.id}/${step.id}.`, "LINK_PORTAL_TAMPER_PARAMETER_MISSING");
      }
    }
    for (const capture of step.captures) {
      if (captureNames.has(capture.name)) throw new AppError(`Capture ${capture.name} is assigned more than once.`, "LINK_PORTAL_CAPTURE_INVALID");
      if (capture.source === "JSON") parseSafeFieldPath(capture.path, { maxDepth: 8, maxArrayIndex: 50, code: "LINK_PORTAL_FIELD_PATH_INVALID" });
      captureNames.add(capture.name);
    }
    for (const assertion of step.assertions) {
      assertionCount++;
      if (assertion.kind === "DECISION" && assertion.allowedStatuses.some((status) => assertion.deniedStatuses.includes(status))) throw new AppError(`Decision assertion in ${value.id}/${step.id} has overlapping allowed and denied status classes.`, "LINK_PORTAL_ASSERTION_INVALID");
      if (assertion.kind === "JSON_EQUALS_SECRET" || assertion.kind === "JSON_NOT_EQUALS_SECRET") {
        parseSafeFieldPath(assertion.path, { maxDepth: 8, maxArrayIndex: 50, code: "LINK_PORTAL_FIELD_PATH_INVALID" });
        requireSecret(profiles, assertion.secretSource, assertion.secretRef, `${value.id}/${step.id}`);
      }
      if ((assertion.kind === "RESPONSE_FINGERPRINT_MATCH" || assertion.kind === "RESPONSE_FINGERPRINT_DIFFERENT") && !priorSteps.has(assertion.stepId)) throw new AppError(`Response comparison in ${value.id}/${step.id} must reference an earlier step.`, "LINK_PORTAL_ASSERTION_INVALID");
    }
    if ((step.phase === "VERIFY" || step.phase === "CLEANUP") && step.assertions.length === 0) throw new AppError(`${step.phase} step ${value.id}/${step.id} requires an assertion.`, "LINK_PORTAL_ASSERTION_REQUIRED");
    priorSteps.add(step.id);
  }
  if (assertionCount === 0) throw new AppError(`Case ${value.id} requires a security assertion.`, "LINK_PORTAL_ASSERTION_REQUIRED");
  if (value.category === "SIGNATURE_TAMPERING" && tamperCount === 0) throw new AppError(`Signature-tampering case ${value.id} requires an automatic tamper request.`, "LINK_PORTAL_TAMPER_REQUIRED");
  if (["SIGNED_LINK_REPLAY", "INVITE_REPLAY"].includes(value.category) && value.steps.filter((step) => step.phase !== "CLEANUP").length < 2) throw new AppError(`Replay case ${value.id} requires at least two ordered attempts.`, "LINK_PORTAL_REPLAY_STEPS_REQUIRED");
  if (value.category === "SIGNED_LINK_REVOCATION" && mutationCount === 0) throw new AppError(`Revocation case ${value.id} requires an explicit state-changing revocation action.`, "LINK_PORTAL_REVOCATION_ACTION_REQUIRED");
  if (value.category === "INVITE_EMAIL_BINDING" && !value.steps.some((step) => step.assertions.some((assertion) => assertion.kind === "JSON_EQUALS_SECRET" || assertion.kind === "JSON_NOT_EQUALS_SECRET"))) throw new AppError(`Invite email-binding case ${value.id} requires a secret-backed binding assertion.`, "LINK_PORTAL_BINDING_ASSERTION_REQUIRED");
  const caseActors = [...new Set(value.steps.map((step) => step.actorId))].map((id) => actors.get(id)!);
  if (["CROSS_TENANT_SIGNED_LINK", "PORTAL_TENANT_BINDING"].includes(value.category)) {
    const tenants = new Set(caseActors.map((actor) => actor.tenantFingerprint).filter(Boolean));
    if (tenants.size < 2) throw new AppError(`Cross-tenant case ${value.id} requires two distinct declared tenant identities.`, "LINK_PORTAL_TENANT_PAIR_REQUIRED");
  }
  if (["EXPORT_AUTHORIZATION", "EVIDENCE_ARTIFACT_AUTHORIZATION", "OBJECT_PATH_OWNERSHIP", "ID_SUBSTITUTION"].includes(value.category) && caseActors.length < 2) throw new AppError(`Authorization case ${value.id} requires at least two explicit actors.`, "LINK_PORTAL_ACTOR_MATRIX_REQUIRED");
  if (mutationCount > 0) validateAuthorization(value, now);
  if (value.cleanupRequired && !value.steps.some((step) => step.phase === "CLEANUP")) throw new AppError(`Case ${value.id} requires cleanup steps.`, "LINK_PORTAL_CLEANUP_REQUIRED");
  if (!value.cleanupRequired && value.steps.some((step) => step.phase === "CLEANUP")) throw new AppError(`Case ${value.id} provides cleanup steps but cleanupRequired is false.`, "LINK_PORTAL_CLEANUP_DECLARATION_INVALID");
  if (mutationCount > 0 && !value.cleanupRequired && !value.authorization.disposableResource) throw new AppError(`Mutating case ${value.id} requires cleanup or an explicitly disposable resource.`, "LINK_PORTAL_CLEANUP_REQUIRED");
}

function validateAuthorization(value: z.infer<typeof caseSchema>, now: Date): void {
  const auth = value.authorization;
  if (auth.mode !== "CONTROLLED_LINK_FLOW" || auth.confirmation !== "I_AUTHORIZE_CONTROLLED_LINK_PORTAL_EXPORT_TESTING" || !auth.authorizedBy || !auth.changeTicket || !auth.authorizedAt || !auth.expiresAt) throw new AppError(`Mutating case ${value.id} lacks explicit controlled authorization.`, "LINK_PORTAL_AUTHORIZATION_REQUIRED");
  const authorizedAt = Date.parse(auth.authorizedAt); const expiresAt = Date.parse(auth.expiresAt);
  if (authorizedAt > now.getTime() || expiresAt <= now.getTime() || expiresAt <= authorizedAt) throw new AppError(`Mutating case ${value.id} authorization is not currently valid.`, "LINK_PORTAL_AUTHORIZATION_EXPIRED");
  if (auth.environment === "PRODUCTION" && !auth.productionAcknowledged) throw new AppError(`Production case ${value.id} requires productionAcknowledged=true.`, "LINK_PORTAL_PRODUCTION_ACK_REQUIRED");
}

function validateUrlTemplate(template: string, requestMethod: string, allowedOrigins: readonly string[], matcher: ScopeMatcher, captures: ReadonlySet<string>, label: string): void {
  const captured = exactCapture.exec(template);
  if (captured) {
    if (!captures.has(captured[1]!)) throw new AppError(`Captured URL in ${label} must be produced by an earlier step.`, "LINK_PORTAL_CAPTURE_INVALID");
    return;
  }
  const parsed = parseTemplateUrl(template);
  if (!allowedOrigins.includes(parsed.origin)) throw new AppError(`URL origin in ${label} is not allowed by its resource.`, "LINK_PORTAL_ORIGIN_INVALID");
  const decision = matcher.decide(parsed.toString(), requestMethod);
  if (!decision.allowed) throw new AppError(`URL in ${label} is outside scope: ${decision.reason}.`, "LINK_PORTAL_SCOPE_INVALID");
  for (const [key, value] of parsed.searchParams) if (secretLikeKey.test(key) && !templateValueHasReference(template, key) && value.length > 0) throw new AppError(`Sensitive query parameter ${key} in ${label} must use a secret or capture reference.`, "LINK_PORTAL_LITERAL_SECRET_REJECTED");
}

function validateReferences(template: string, headers: Record<string, string>, fields: Record<string, unknown> | undefined, source: LinkPortalAuthSlot, profiles: Readonly<Record<LinkPortalAuthSlot, AuthProfile | undefined>>, captures: ReadonlySet<string>, label: string): void {
  const values = [template, ...Object.values(headers), ...leafStrings(fields)];
  for (const value of values) for (const match of value.matchAll(reference)) {
    if (match[1] === "CAPTURE") { if (!captures.has(match[2]!)) throw new AppError(`Unknown or forward capture reference in ${label}.`, "LINK_PORTAL_CAPTURE_INVALID"); }
    else requireSecret(profiles, source, match[2]!, label);
  }
  for (const value of values) if (value.includes("{{") && !(value.match(reference)?.length)) throw new AppError(`Invalid template reference in ${label}.`, "LINK_PORTAL_TEMPLATE_INVALID");
}

function requireSecret(profiles: Readonly<Record<LinkPortalAuthSlot, AuthProfile | undefined>>, source: LinkPortalAuthSlot, name: string, label: string): void {
  const profile = profiles[source];
  if (!profile || !Object.prototype.hasOwnProperty.call(authenticationLifecycleSecrets(profile), name)) throw new AppError(`Secret ${name} for ${label} is unavailable from ${source}.`, "LINK_PORTAL_SECRET_REQUIRED");
}

function validateHeaders(headers: Record<string, string>, label: string): void { for (const [name, value] of Object.entries(headers)) if (forbiddenHeader.test(name) || /[\r\n\0]/.test(name + value)) throw new AppError(`Unsafe header in ${label}.`, "LINK_PORTAL_HEADER_INVALID"); }
function validateValue(value: unknown, label: string): void { walk(value, (entry, key) => { if (typeof entry === "string" && secretLikeKey.test(key) && ![...entry.matchAll(reference)].length) throw new AppError(`Secret-like field ${key} in ${label} must use a reference.`, "LINK_PORTAL_LITERAL_SECRET_REJECTED"); }); }
function walk(value: unknown, visit: (entry: unknown, key: string) => void, key = ""): void { visit(value, key); if (Array.isArray(value)) value.forEach((entry, index) => walk(entry, visit, String(index))); else if (value && typeof value === "object") for (const [childKey, entry] of Object.entries(value as Record<string, unknown>)) walk(entry, visit, childKey); }
function leafStrings(value: unknown): string[] { const result: string[] = []; walk(value, (entry) => { if (typeof entry === "string") result.push(entry); }); return result; }
function parseTemplateUrl(template: string): URL { try { const value = template.replace(reference, "routecairn-placeholder"); const parsed = new URL(value); if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error(); return parsed; } catch { throw new AppError("URL template is invalid or uses an unsupported scheme.", "LINK_PORTAL_TEMPLATE_INVALID"); } }
function templateValueHasReference(template: string, key: string): boolean { const raw = template.split("?")[1] ?? ""; return raw.split("&").some((part) => decodeURIComponent(part.split("=")[0] ?? "") === key && /\{\{(?:SECRET|CAPTURE):/.test(part)); }
function normalizeOrigin(value: string): string { const parsed = new URL(value); if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) throw new AppError(`Allowed origin ${value} must be an exact HTTP(S) origin.`, "LINK_PORTAL_ORIGIN_INVALID"); return parsed.origin; }
function ensureUnique(values: readonly string[], label: string): void { if (new Set(values).size !== values.length) throw new AppError(`Duplicate ${label} identifier.`, "LINK_PORTAL_DUPLICATE_ID"); }
function assertSafeLabel(value: string, label: string): void { if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value) || /bearer\s|https?:\/\/|[?&=]/i.test(value) || /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value) || /^[A-Za-z0-9_-]{40,}$/.test(value)) throw new AppError(`${label} appears to contain identifying or secret material.`, "LINK_PORTAL_UNSAFE_LABEL"); }
function profilesFor(context: PlannerContext): Readonly<Record<LinkPortalAuthSlot, AuthProfile | undefined>> { return { anonymous: undefined, primary: context.authProfile, account_a: context.authProfileSet?.accountA, account_b: context.authProfileSet?.accountB }; }
function fingerprint(kind: string, value: string): string { return createHash("sha256").update(`routecairn-link-portal-v1\0${kind}\0${value}`).digest("hex"); }
function caseFingerprint(value: z.infer<typeof caseSchema>, actors: LinkPortalSecurityPlan["actors"], resources: LinkPortalSecurityPlan["resources"]): string {
  const actorIds = new Set(value.steps.map((step) => step.actorId));
  const resourceIds = new Set(value.steps.map((step) => step.resourceId));
  return securityContractFingerprint("link-portal-security", {
    schemaVersion: 1,
    category: value.category,
    actors: actors.filter((actor) => actorIds.has(actor.id)),
    resources: resources.filter((resource) => resourceIds.has(resource.id)),
    authorization: value.authorization,
    cleanupRequired: value.cleanupRequired,
    steps: value.steps
  });
}
