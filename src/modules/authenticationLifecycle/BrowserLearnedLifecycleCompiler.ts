import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import { authenticationLifecycleSecrets, type AuthProfile } from "../../core/auth/AuthProfile.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import type { BrowserAuthenticationReport, BrowserLearnedTestCase } from "../../reports/ReportTypes.js";
import { authenticationLifecycleInputSchema, planAuthenticationLifecycle, type AuthenticationLifecycleInput } from "./AuthenticationLifecyclePlanner.js";
import type { AuthenticationLifecycleCategory, AuthenticationLifecyclePlan, BrowserLearnedLifecycleAutomationPlan, LifecycleAuthorizationPlan } from "./AuthenticationLifecycleTypes.js";

const identifier = z.string().regex(/^[A-Za-z0-9._-]{1,100}$/);
const supportedCategories = ["LOGIN_ENUMERATION_RESISTANCE", "SESSION_ROTATION_AFTER_LOGIN", "SESSION_FIXATION"] as const;
const authorizationSchema = z.object({
  mode: z.literal("CONTROLLED_LIFECYCLE"),
  environment: z.enum(["LOCAL", "TEST", "STAGING", "PRODUCTION"]),
  confirmation: z.literal("I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING"),
  authorizedBy: z.string().min(2).max(160),
  changeTicket: z.string().min(1).max(160),
  authorizedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
  disposableAccounts: z.literal(true),
  productionAcknowledged: z.boolean().default(false)
}).strict();
const requestSchema = z.object({
  method: z.enum(["POST", "PATCH", "PUT", "DELETE"]),
  url: z.string().url().max(2048),
  headers: z.record(z.string().max(8192)).default({}),
  bodyFormat: z.enum(["JSON", "FORM"]).optional(),
  fields: z.record(z.unknown()).optional(),
  successStatusCodes: z.array(z.number().int().min(100).max(599)).min(1).max(20).default([200, 204, 401])
}).strict();

export const browserLearnedLifecycleAutomationInputSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  categories: z.array(z.enum(supportedCategories)).min(1).max(3).default([...supportedCategories]),
  actor: z.object({
    id: identifier.default("member"),
    safeAlias: z.string().min(1).max(80).default("disposable-member"),
    authSlot: z.literal("primary").default("primary"),
    relationship: z.string().min(1).max(80).default("SELF"),
    declaredState: z.string().min(1).max(80).default("ACTIVE"),
    tenantAlias: z.string().min(1).max(80).optional()
  }).strict().default({}),
  authorization: authorizationSchema,
  login: z.object({
    fieldSecretRefs: z.record(identifier, identifier).default({}),
    accountField: identifier.optional(),
    passwordField: identifier.optional(),
    unknownAccountSecretRef: identifier.optional(),
    invalidPasswordSecretRef: identifier.optional(),
    fixedSessionSecretRef: identifier.optional(),
    sessionCookieName: z.string().min(1).max(100).optional(),
    successStatusCodes: z.array(z.number().int().min(100).max(599)).min(1).max(20).default([200, 201, 204, 302, 303]),
    failureStatusCodes: z.array(z.number().int().min(100).max(599)).min(1).max(20).default([400, 401, 403, 422])
  }).strict(),
  cleanup: requestSchema,
  maxResponseBytes: z.number().int().min(256).max(262144).default(32768)
}).strict();

export type BrowserLearnedLifecycleAutomationInput = z.infer<typeof browserLearnedLifecycleAutomationInputSchema>;

export interface BrowserLearnedLifecycleCompilation {
  plan?: AuthenticationLifecyclePlan;
  generatedCategories: AuthenticationLifecycleCategory[];
  blockers: Array<{ category: AuthenticationLifecycleCategory; reasons: string[] }>;
  sourceCandidateId?: string;
}

export async function loadBrowserLearnedLifecycleAutomationInput(path: string): Promise<BrowserLearnedLifecycleAutomationInput> {
  const raw = (await readFile(path, "utf8")).replace(/^\uFEFF/, "");
  const parsed = browserLearnedLifecycleAutomationInputSchema.safeParse(JSON.parse(raw));
  if (!parsed.success) throw new AppError(parsed.error.message, "AUTH_LIFECYCLE_AUTOMATION_INPUT_INVALID");
  return parsed.data;
}

export function planBrowserLearnedLifecycleAutomation(input: BrowserLearnedLifecycleAutomationInput, target: string): AuthenticationLifecyclePlan {
  const parsed = browserLearnedLifecycleAutomationInputSchema.parse(input);
  const now = Date.now();
  if (new Date(parsed.authorization.authorizedAt).getTime() > now || new Date(parsed.authorization.expiresAt).getTime() <= now) throw new AppError("Browser-learned lifecycle authorization is not currently valid.", "AUTH_LIFECYCLE_AUTHORIZATION_EXPIRED");
  if (parsed.authorization.environment === "PRODUCTION" && !parsed.authorization.productionAcknowledged) throw new AppError("Production browser-learned lifecycle automation requires productionAcknowledged=true.", "AUTH_LIFECYCLE_PRODUCTION_ACK_REQUIRED");
  const authorization: LifecycleAuthorizationPlan = {
    mode: parsed.authorization.mode,
    environment: parsed.authorization.environment,
    authorizationIdentityConfirmed: true,
    changeTicketConfirmed: true,
    authorizedAt: parsed.authorization.authorizedAt,
    expiresAt: parsed.authorization.expiresAt,
    disposableAccounts: true,
    productionAcknowledged: parsed.authorization.productionAcknowledged,
    confirmationAccepted: true
  };
  return {
    schemaVersion: 1,
    enabled: true,
    source: "BROWSER_LEARNED",
    targetOrigin: new URL(target).origin,
    maxCases: parsed.categories.length,
    maxStepsPerCase: 4,
    maxRequests: parsed.categories.length * 4,
    maxResponseBytes: parsed.maxResponseBytes,
    cases: [],
    automation: {
      categories: parsed.categories,
      actor: { id: parsed.actor.id, safeAlias: parsed.actor.safeAlias, authSlot: parsed.actor.authSlot, requestAuthentication: "NONE", relationship: parsed.actor.relationship, declaredState: parsed.actor.declaredState, ...(parsed.actor.tenantAlias ? { tenantAlias: parsed.actor.tenantAlias } : {}) },
      authorization,
      login: { fieldSecretRefs: parsed.login.fieldSecretRefs, successStatusCodes: parsed.login.successStatusCodes, failureStatusCodes: parsed.login.failureStatusCodes, ...(parsed.login.accountField ? { accountField: parsed.login.accountField } : {}), ...(parsed.login.passwordField ? { passwordField: parsed.login.passwordField } : {}), ...(parsed.login.unknownAccountSecretRef ? { unknownAccountSecretRef: parsed.login.unknownAccountSecretRef } : {}), ...(parsed.login.invalidPasswordSecretRef ? { invalidPasswordSecretRef: parsed.login.invalidPasswordSecretRef } : {}), ...(parsed.login.fixedSessionSecretRef ? { fixedSessionSecretRef: parsed.login.fixedSessionSecretRef } : {}), ...(parsed.login.sessionCookieName ? { sessionCookieName: parsed.login.sessionCookieName } : {}) },
      cleanup: { method: parsed.cleanup.method, url: parsed.cleanup.url, headers: parsed.cleanup.headers, successStatusCodes: parsed.cleanup.successStatusCodes, ...(parsed.cleanup.bodyFormat ? { bodyFormat: parsed.cleanup.bodyFormat } : {}), ...(parsed.cleanup.fields ? { fields: parsed.cleanup.fields } : {}) }
    },
    notes: ["Lifecycle cases will be compiled at runtime from the authenticated browser learning bundle.", "Learning selects request structure; the expiring operator authorization remains the mutation authority."]
  };
}

export function compileBrowserLearnedLifecycle(
  automationPlan: AuthenticationLifecyclePlan,
  browser: BrowserAuthenticationReport | undefined,
  context: { target: string; scope: RouteCairnScope; authProfile?: AuthProfile; authProfileSet?: AuthProfileSet; now?: Date }
): BrowserLearnedLifecycleCompilation {
  const automation = automationPlan.automation;
  if (!automation) return { generatedCategories: [], blockers: [] };
  const selectedLoginCandidate = selectLoginCandidate(browser?.learnedTestCases ?? [], automationPlan.targetOrigin);
  if (!selectedLoginCandidate) return {
    generatedCategories: [],
    blockers: automation.categories.map((category) => ({ category, reasons: ["NO_UNAMBIGUOUS_EXPLICIT_LOGIN_CANDIDATE"] }))
  };
  const learnedCookieNames = [...new Set((browser?.storage ?? []).filter((item) => item.storage === "cookie" && item.classification === "authentication").map((item) => item.name))];
  const loginCandidate = selectedLoginCandidate.responseCookieNames.length === 0 && learnedCookieNames.length === 1 ? { ...selectedLoginCandidate, responseCookieNames: learnedCookieNames } : selectedLoginCandidate;
  const cases: AuthenticationLifecycleInput["cases"] = [];
  const blockers: BrowserLearnedLifecycleCompilation["blockers"] = [];
  const availableSecretNames = new Set(Object.keys(context.authProfile ? authenticationLifecycleSecrets(context.authProfile) : {}));
  for (const category of automation.categories) {
    const result = compileCategory(category, loginCandidate, automation);
    const missingSecrets = result.testCase ? secretReferences(result.testCase).filter((name) => !availableSecretNames.has(name)).map((name) => `SECRET_REF_UNAVAILABLE:${name}`) : [];
    if (result.reasons.length > 0 || missingSecrets.length > 0 || !result.testCase) blockers.push({ category, reasons: [...new Set([...result.reasons, ...missingSecrets])] });
    else cases.push(result.testCase);
  }
  if (cases.length === 0) return { generatedCategories: [], blockers, sourceCandidateId: loginCandidate.id };
  const input = authenticationLifecycleInputSchema.parse({
    schemaVersion: 1,
    maxCases: cases.length,
    maxStepsPerCase: 4,
    maxRequests: cases.length * 4,
    maxResponseBytes: automationPlan.maxResponseBytes,
    cases
  });
  const plan = planAuthenticationLifecycle(input, context);
  return { plan: { ...plan, source: "BROWSER_LEARNED", notes: [...automationPlan.notes, ...plan.notes] }, generatedCategories: cases.map((item) => item.category), blockers, sourceCandidateId: loginCandidate.id };
}

function compileCategory(category: BrowserLearnedLifecycleAutomationPlan["categories"][number], candidate: BrowserLearnedTestCase, automation: BrowserLearnedLifecycleAutomationPlan): { testCase?: AuthenticationLifecycleInput["cases"][number]; reasons: string[] } {
  const reasons: string[] = [];
  const bindings = { ...candidate.requestSecretBindings, ...automation.login.fieldSecretRefs };
  const accountField = automation.login.accountField ?? findField(candidate.observedFieldNames, /(?:^|\.)(?:email|username|user|login|identifier)$/i);
  const passwordField = automation.login.passwordField ?? findField(candidate.observedFieldNames, /(?:^|\.)(?:password|pass|passwd)$/i);
  if (!candidate.requestBodyFormat) reasons.push("LOGIN_BODY_FORMAT_NOT_LEARNED");
  for (const field of [...new Set([...candidate.observedFieldNames, ...Object.keys(bindings)])]) if (!safeFieldPath(field)) reasons.push(`UNSUPPORTED_FIELD_PATH:${field}`);
  if (!accountField) reasons.push("ACCOUNT_FIELD_NOT_RESOLVED");
  if (!passwordField) reasons.push("PASSWORD_FIELD_NOT_RESOLVED");
  for (const field of candidate.observedFieldNames.filter((name) => /password|pass|email|username|user|login|token|code|secret/i.test(name))) if (!bindings[field] && field !== accountField && field !== passwordField) reasons.push(`SENSITIVE_FIELD_UNBOUND:${field}`);
  const cookie = automation.login.sessionCookieName ?? candidate.responseCookieNames[0];
  if (category === "LOGIN_ENUMERATION_RESISTANCE") {
    if (!automation.login.unknownAccountSecretRef) reasons.push("UNKNOWN_ACCOUNT_SECRET_REF_REQUIRED");
    if (!automation.login.invalidPasswordSecretRef) reasons.push("INVALID_PASSWORD_SECRET_REF_REQUIRED");
  } else {
    if (!automation.login.fixedSessionSecretRef) reasons.push("FIXED_SESSION_SECRET_REF_REQUIRED");
    if (!cookie) reasons.push("SESSION_COOKIE_NOT_RESOLVED");
    if (accountField && !bindings[accountField]) reasons.push("VALID_ACCOUNT_SECRET_REF_NOT_LEARNED");
    if (passwordField && !bindings[passwordField]) reasons.push("VALID_PASSWORD_SECRET_REF_NOT_LEARNED");
  }
  if (reasons.length > 0 || !accountField || !passwordField || !candidate.requestBodyFormat) return { reasons: [...new Set(reasons)] };
  const actor = automation.actor;
  const authorization = authorizationInput(automation.authorization);
  const cleanup = cleanupStep(automation, actor.id, cookie, category !== "LOGIN_ENUMERATION_RESISTANCE");
  if (category === "LOGIN_ENUMERATION_RESISTANCE") {
    const knownFields = requestFields(bindings, { [accountField]: bindings[accountField] ?? "", [passwordField]: automation.login.invalidPasswordSecretRef! }, candidate.requestBodyFormat);
    if (!bindings[accountField]) return { reasons: ["VALID_ACCOUNT_SECRET_REF_NOT_LEARNED"] };
    const unknownFields = requestFields(bindings, { [accountField]: automation.login.unknownAccountSecretRef!, [passwordField]: automation.login.invalidPasswordSecretRef! }, candidate.requestBodyFormat);
    return { reasons: [], testCase: {
      id: `learned-login-enumeration-${candidate.id.slice(-8)}`,
      label: "Browser-learned login enumeration equivalence",
      category,
      actors: [actor], authorization, cleanupRequired: true,
      steps: [
        actionStep("known-account-failure", actor.id, candidate, knownFields, [{ kind: "STATUS_IN", values: [...automation.login.failureStatusCodes] }]),
        { ...actionStep("unknown-account-failure", actor.id, candidate, unknownFields, [{ kind: "RESPONSE_SIMILAR", stepId: "known-account-failure", compareStatus: true, compareShape: true, compareBodyDigest: true, compareTiming: false, maxLengthDelta: 128, maxResponseTimeDeltaMs: 250 }]), phase: "VERIFY" },
        cleanup
      ]
    } };
  }
  const fields = requestFields(bindings, {}, candidate.requestBodyFormat);
  const captureName = "learned_session";
  return { reasons: [], testCase: {
    id: `learned-${category === "SESSION_FIXATION" ? "session-fixation" : "session-rotation"}-${candidate.id.slice(-8)}`,
    label: category === "SESSION_FIXATION" ? "Browser-learned fixed session is rejected after login" : "Browser-learned session rotates after login",
    category, actors: [actor], authorization, cleanupRequired: true,
    steps: [
      { ...actionStep("login-with-fixed-session", actor.id, candidate, fields, [{ kind: "CAPTURE_ROTATED", capture: captureName, comparedTo: { source: "SECRET", ref: automation.login.fixedSessionSecretRef! } }]), request: { method: candidate.method as "POST" | "PATCH" | "PUT" | "DELETE", url: candidate.endpoint, stateChanging: true, headers: { Cookie: `${cookie}={{SECRET:${automation.login.fixedSessionSecretRef}}}` }, bodyFormat: candidate.requestBodyFormat, fields }, captures: [{ name: captureName, source: "COOKIE", cookie: cookie! }] },
      cleanupStep(automation, actor.id, cookie, true, captureName)
    ]
  } };
}

function selectLoginCandidate(candidates: readonly BrowserLearnedTestCase[], origin: string): BrowserLearnedTestCase | undefined {
  const matches = candidates.filter((item) => item.authorizationContext === "EXPLICIT_LOGIN" && item.transmitted && new URL(item.endpoint).origin === origin);
  return matches.length === 1 ? matches[0] : undefined;
}

function findField(fields: readonly string[], pattern: RegExp): string | undefined { return fields.find((field) => pattern.test(field)); }
function secretReferences(value: unknown): string[] { return [...new Set([...JSON.stringify(value).matchAll(/\{\{SECRET:([A-Za-z0-9._-]+)\}\}/g)].map((match) => match[1]!))]; }
function safeFieldPath(value: string): boolean { return value.length <= 200 && value.split(".").every((part) => /^[A-Za-z_$][A-Za-z0-9_$]{0,99}$/.test(part) && !["__proto__", "prototype", "constructor"].includes(part)); }
function requestFields(bindings: Record<string, string>, overrides: Record<string, string>, format: "JSON" | "FORM"): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [field, ref] of Object.entries({ ...bindings, ...overrides }).filter(([, value]) => value)) {
    if (format === "FORM") result[field] = `{{SECRET:${ref}}}`;
    else setField(result, field, `{{SECRET:${ref}}}`);
  }
  return result;
}
function setField(target: Record<string, unknown>, path: string, value: string): void {
  const parts = path.split(".");
  let cursor = target;
  for (const [index, part] of parts.entries()) {
    if (index === parts.length - 1) { cursor[part] = value; return; }
    const next = cursor[part];
    if (!next || typeof next !== "object" || Array.isArray(next)) cursor[part] = {};
    cursor = cursor[part] as Record<string, unknown>;
  }
}
function actionStep(id: string, actorId: string, candidate: BrowserLearnedTestCase, fields: Record<string, unknown>, assertions: AuthenticationLifecycleInput["cases"][number]["steps"][number]["assertions"]): AuthenticationLifecycleInput["cases"][number]["steps"][number] {
  return { id, phase: "ACTION", actorId, waitBeforeMs: 0, request: { method: candidate.method as "POST" | "PATCH" | "PUT" | "DELETE", url: candidate.endpoint, stateChanging: true, headers: {}, bodyFormat: candidate.requestBodyFormat!, fields }, captures: [], assertions };
}
function cleanupStep(automation: BrowserLearnedLifecycleAutomationPlan, actorId: string, cookie: string | undefined, bindSession: boolean, capture = "learned_session"): AuthenticationLifecycleInput["cases"][number]["steps"][number] {
  const headers = { ...automation.cleanup.headers, ...(bindSession && cookie ? { Cookie: `${cookie}={{CAPTURE:${capture}}}` } : {}) };
  return { id: "learned-cleanup", phase: "CLEANUP", actorId, waitBeforeMs: 0, request: { method: automation.cleanup.method as "POST" | "PATCH" | "PUT" | "DELETE", url: automation.cleanup.url, stateChanging: true, headers, ...(automation.cleanup.bodyFormat ? { bodyFormat: automation.cleanup.bodyFormat } : {}), ...(automation.cleanup.fields ? { fields: automation.cleanup.fields as Record<string, unknown> } : {}) }, captures: [], assertions: [{ kind: "STATUS_IN", values: [...automation.cleanup.successStatusCodes] }] };
}
function authorizationInput(value: LifecycleAuthorizationPlan): AuthenticationLifecycleInput["cases"][number]["authorization"] {
  return { mode: "CONTROLLED_LIFECYCLE", environment: value.environment, confirmation: "I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING", authorizedBy: "confirmed-operator", changeTicket: "confirmed-change", authorizedAt: value.authorizedAt!, expiresAt: value.expiresAt!, disposableAccounts: true, productionAcknowledged: value.productionAcknowledged };
}
