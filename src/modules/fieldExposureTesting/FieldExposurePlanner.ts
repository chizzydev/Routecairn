import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import type {
  FieldExposureActorPlan,
  FieldExposureCasePlan,
  FieldExposureExpectationPlan,
  FieldExposureRequestPlan,
  FieldExposureTestingPlan
} from "../../core/planning/ScanPlan.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";
import { parseSafeFieldPath } from "./SafeFieldPath.js";

const objectPlaceholder = "{{OBJECT_ID}}";
const encodedObjectPlaceholder = "%7B%7BOBJECT_ID%7D%7D";
const maxFieldExposureFileBytes = 256 * 1024;
const maxCaseCount = 20;
const maxFieldsPerCase = 40;
const maxActorsPerCase = 5;
const maxIdentifierLength = 256;
const maxTemplateLength = 2048;
const maxPathDepth = 8;
const maxArrayIndex = 50;
const secretLikePattern = /(?:authorization|cookie|session|csrf|xsrf|token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|bearer\s+[a-z0-9._~+/=-]+)/i;
const generatorPattern = /(?:\.\.|\*|\||=>|function\s*\(|regex|regexp|range|increment|decrement|random|uuid-v|eval|for\s*\(|while\s*\()/i;
const forbiddenEndpointWords = /(?:delete|remove|cancel|purchase|pay|transfer|withdraw|approve|reject|publish|submit|invite|reset|activate|deactivate|suspend|logout|consume-on-read)/i;

const actorTypeSchema = z.enum([
  "OWNER",
  "NON_OWNER",
  "SECONDARY_NON_OWNER",
  "SHARED_PRINCIPAL",
  "LOWER_PRIVILEGED_ROLE",
  "HIGHER_PRIVILEGED_ROLE",
  "SAME_TENANT_MEMBER",
  "CROSS_TENANT_MEMBER",
  "PUBLIC"
]);
const expectationSchema = z.enum([
  "MUST_BE_ABSENT",
  "MUST_BE_NULL",
  "MUST_BE_REDACTED",
  "MUST_DIFFER_FROM_OWNER",
  "MUST_MATCH_PUBLIC_BASELINE",
  "MUST_MATCH_SHARED_BASELINE",
  "MAY_BE_PRESENT",
  "MUST_BE_PRESENT",
  "MASKED_VALUE",
  "OWNER_ONLY_VALUE"
]);
const visibilitySchema = z.enum([
  "OWNER_ONLY",
  "PUBLIC_SUMMARY",
  "PUBLIC_FULL",
  "SHARED_WITH_SPECIFIC_PRINCIPALS",
  "TENANT_VISIBLE",
  "ROLE_VISIBLE",
  "AUTHENTICATED_USERS",
  "UNKNOWN_REQUIRES_REVIEW"
]);

const actorSchema = z
  .object({
    id: z.string().min(1).max(80),
    type: actorTypeSchema,
    authProfile: z.enum(["account_a", "account_b"]).optional(),
    safeAlias: z.string().min(1).max(80).optional(),
    principalId: z.string().min(1).max(maxIdentifierLength).optional(),
    tenantId: z.string().min(1).max(maxIdentifierLength).optional(),
    role: z.string().min(1).max(80).optional()
  })
  .strict();

const fieldExpectationSchema = z
  .object({
    id: z.string().min(1).max(80).optional(),
    path: z.string().min(1).max(160),
    label: z.string().min(1).max(120),
    sensitivity: z.enum(["PUBLIC", "PRIVATE", "OWNER_ONLY", "TENANT", "ROLE", "INTERNAL"]).default("PRIVATE"),
    expectation: expectationSchema,
    allowedActors: z.array(z.string().min(1).max(80)).max(maxActorsPerCase).default([]),
    prohibitedActors: z.array(z.string().min(1).max(80)).max(maxActorsPerCase).default([]),
    redactionPattern: z.string().min(1).max(200).optional(),
    allowPreview: z.boolean().default(false),
    maxLength: z.number().int().positive().max(4096).optional()
  })
  .strict();

const caseSchema = z
  .object({
    id: z.string().min(1).max(120),
    objectType: z.string().min(1).max(80),
    objectId: z.string().min(1).max(maxIdentifierLength),
    declaredOwnerActor: z.string().min(1).max(80),
    expectedVisibility: visibilitySchema,
    requireVerifiedIdentity: z.boolean().default(true),
    template: z
      .object({
        id: z.string().min(1).max(120),
        method: z.enum(["GET"]),
        url: z.string().min(1).max(maxTemplateLength),
        headers: z.record(z.string().max(512)).default({})
      })
      .strict(),
    objectConfirmation: z
      .object({
        expectedObjectIdField: z.string().min(1).max(160),
        expectedOwnerField: z.string().min(1).max(160).optional(),
        expectedTenantField: z.string().min(1).max(160).optional()
      })
      .strict(),
    actors: z.array(actorSchema).min(2).max(maxActorsPerCase),
    fieldExpectations: z.array(fieldExpectationSchema).min(1).max(maxFieldsPerCase)
  })
  .strict();

const fieldExposureInputSchema = z
  .object({
    schemaVersion: z.literal(1).default(1),
    maxCases: z.number().int().positive().max(maxCaseCount).default(5),
    maxResponseBytes: z.number().int().positive().max(512 * 1024).default(65536),
    maxPreviewLength: z.number().int().positive().max(512).default(120),
    cases: z.array(caseSchema).min(1).max(maxCaseCount)
  })
  .strict();

export type FieldExposureInput = z.infer<typeof fieldExposureInputSchema>;

export async function loadFieldExposureInput(filePath: string): Promise<FieldExposureInput> {
  const rawBuffer = await readFile(filePath);
  if (rawBuffer.byteLength > maxFieldExposureFileBytes) {
    throw new AppError(`Field exposure input exceeds maximum size ${maxFieldExposureFileBytes} bytes.`, "FIELD_EXPOSURE_FILE_TOO_LARGE");
  }

  let json: unknown;
  try {
    json = JSON.parse(rawBuffer.toString("utf8").replace(/^\uFEFF/, ""));
  } catch {
    throw new AppError("Field exposure input is not valid JSON.", "FIELD_EXPOSURE_JSON_INVALID");
  }

  const parsed = fieldExposureInputSchema.safeParse(json);
  if (!parsed.success) {
    throw new AppError(parsed.error.message, "FIELD_EXPOSURE_INPUT_INVALID");
  }
  return parsed.data;
}

export function planFieldExposureTesting(input: FieldExposureInput, options: { target: string; scope: RouteCairnScope; authProfileSet?: AuthProfileSet }): FieldExposureTestingPlan {
  validateInputUniqueness(input);
  if (input.cases.length > input.maxCases) {
    throw new AppError(`Field exposure input contains ${input.cases.length} cases, exceeding maxCases ${input.maxCases}.`, "FIELD_EXPOSURE_TOO_MANY_CASES");
  }

  const scopeMatcher = new ScopeMatcher(options.target, options.scope);
  const cases = input.cases.map((testCase) => planCase(testCase, scopeMatcher, options.authProfileSet));
  const requestMatrix = cases.flatMap((testCase) => [...testCase.requestMatrix]);

  return deepFreeze({
    schemaVersion: 1,
    enabled: true,
    cases,
    requestMatrix,
    maxCases: input.maxCases,
    maxFieldsPerCase,
    maxRequests: requestMatrix.length,
    maxResponseBytes: input.maxResponseBytes,
    maxPreviewLength: input.maxPreviewLength,
    notes: [
      "Field exposure testing evaluates only explicitly configured field paths.",
      "The request matrix is fixed during planning; runtime responses do not add actors, fields, objects, or endpoints.",
      "Only JSON response projection for GET requests is supported in this version."
    ]
  });
}

function planCase(testCase: FieldExposureInput["cases"][number], scopeMatcher: ScopeMatcher, authProfileSet: AuthProfileSet | undefined): FieldExposureCasePlan {
  validateIdentifier(testCase.objectId, `${testCase.id}.objectId`);
  validateTemplate(testCase.template);
  parseSafeFieldPath(testCase.objectConfirmation.expectedObjectIdField, { maxDepth: maxPathDepth, maxArrayIndex, code: "FIELD_EXPOSURE_OBJECT_SELECTOR_INVALID" });
  for (const path of [testCase.objectConfirmation.expectedOwnerField, testCase.objectConfirmation.expectedTenantField].filter(Boolean)) {
    parseSafeFieldPath(path as string, { maxDepth: maxPathDepth, maxArrayIndex, code: "FIELD_EXPOSURE_OBJECT_SELECTOR_INVALID" });
  }

  const actors = testCase.actors.map((actor) => actorPlan(actor, authProfileSet));
  const actorIds = new Set(actors.map((actor) => actor.id));
  if (actorIds.size !== actors.length) {
    throw new AppError(`Field exposure case "${testCase.id}" contains duplicate actor IDs.`, "FIELD_EXPOSURE_DUPLICATE_ACTOR");
  }
  if (!actorIds.has(testCase.declaredOwnerActor)) {
    throw new AppError(`Field exposure case "${testCase.id}" declares an unknown owner actor.`, "FIELD_EXPOSURE_UNKNOWN_ACTOR");
  }
  if (actors.find((actor) => actor.id === testCase.declaredOwnerActor)?.type !== "OWNER") {
    throw new AppError(`Field exposure case "${testCase.id}" owner actor must use type OWNER.`, "FIELD_EXPOSURE_OWNER_INVALID");
  }

  validateDistinctAuthenticatedActors(testCase.id, actors);
  validateDistinctAuthMaterial(testCase.id, actors, authProfileSet);
  const fieldExpectations = testCase.fieldExpectations.map((expectation, index) => expectationPlan(expectation, index, actorIds));
  validateFieldUniqueness(testCase.id, fieldExpectations);
  validateBaselineDependencies(testCase.id, actors, fieldExpectations);
  const url = applyObjectPlaceholder(testCase.template.url, testCase.objectId);
  const decision = scopeMatcher.decide(url, testCase.template.method);
  if (!decision.allowed || !decision.normalizedUrl) {
    throw new AppError(`Field exposure request "${testCase.id}" is out of scope: ${decision.reason}.`, "FIELD_EXPOSURE_OUT_OF_SCOPE");
  }

  const normalizedUrl = decision.normalizedUrl;
  const requestMatrix = actors.map((actor) => requestPlan(testCase, actor, normalizedUrl));
  return {
    id: testCase.id,
    objectType: testCase.objectType,
    objectId: testCase.objectId,
    objectIdHash: hashValue(testCase.objectId, "object"),
    ownerActorId: testCase.declaredOwnerActor,
    expectedVisibility: testCase.expectedVisibility,
    template: {
      id: testCase.template.id,
      method: testCase.template.method,
      urlTemplate: testCase.template.url,
      headers: testCase.template.headers
    },
    actors,
    objectConfirmation: {
      expectedObjectIdField: testCase.objectConfirmation.expectedObjectIdField,
      expectedObjectIdHash: hashValue(testCase.objectId, "object"),
      ...(testCase.objectConfirmation.expectedOwnerField ? { expectedOwnerField: testCase.objectConfirmation.expectedOwnerField } : {}),
      ...(testCase.objectConfirmation.expectedTenantField ? { expectedTenantField: testCase.objectConfirmation.expectedTenantField } : {})
    },
    fieldExpectations,
    requestMatrix,
    requireVerifiedIdentity: testCase.requireVerifiedIdentity
  };
}

function actorPlan(actor: FieldExposureInput["cases"][number]["actors"][number], authProfileSet: AuthProfileSet | undefined): FieldExposureActorPlan {
  if (actor.type === "PUBLIC") {
    if (actor.authProfile) {
      throw new AppError(`Public field-exposure actor "${actor.id}" must not reference an auth profile.`, "FIELD_EXPOSURE_PUBLIC_AUTH_INVALID");
    }
    return { id: actor.id, type: actor.type, redactedLabel: actor.safeAlias ?? "Public" };
  }
  if (!authProfileSet) {
    throw new AppError("Field exposure testing with authenticated actors requires --auth-a and --auth-b.", "FIELD_EXPOSURE_AUTH_PAIR_REQUIRED");
  }
  if (!actor.authProfile) {
    throw new AppError(`Authenticated field-exposure actor "${actor.id}" must reference account_a or account_b.`, "FIELD_EXPOSURE_AUTH_PROFILE_REQUIRED");
  }
  const profile = actor.authProfile === "account_a" ? authProfileSet.accountA : authProfileSet.accountB;
  const principalId = actor.principalId ?? profile.principalId;
  if (!principalId) {
    throw new AppError(`Field exposure actor "${actor.id}" requires declared principalId metadata.`, "FIELD_EXPOSURE_PRINCIPAL_ID_REQUIRED");
  }
  if (actor.principalId && profile.principalId && actor.principalId !== profile.principalId) {
    throw new AppError(`Field exposure actor "${actor.id}" principal metadata does not match its auth profile.`, "FIELD_EXPOSURE_PRINCIPAL_ID_MISMATCH");
  }
  if (actor.tenantId && profile.tenantId && actor.tenantId !== profile.tenantId) {
    throw new AppError(`Field exposure actor "${actor.id}" tenant metadata does not match its auth profile.`, "FIELD_EXPOSURE_TENANT_MISMATCH");
  }
  if (actor.role && profile.role && actor.role !== profile.role) {
    throw new AppError(`Field exposure actor "${actor.id}" role metadata does not match its auth profile.`, "FIELD_EXPOSURE_ROLE_MISMATCH");
  }
  return {
    id: actor.id,
    type: actor.type,
    redactedLabel: actor.safeAlias ?? profile.safeAlias ?? profile.label,
    authSlot: actor.authProfile,
    principalIdHash: hashValue(principalId, "principal"),
    ...(actor.tenantId ?? profile.tenantId ? { tenantIdHash: hashValue(actor.tenantId ?? profile.tenantId ?? "", "tenant") } : {}),
    ...(actor.role ?? profile.role ? { roleHash: hashValue(actor.role ?? profile.role ?? "", "role") } : {})
  };
}

function expectationPlan(expectation: FieldExposureInput["cases"][number]["fieldExpectations"][number], index: number, actorIds: Set<string>): FieldExposureExpectationPlan {
  parseSafeFieldPath(expectation.path, { maxDepth: maxPathDepth, maxArrayIndex, code: "FIELD_EXPOSURE_FIELD_PATH_INVALID" });
  for (const actorId of [...expectation.allowedActors, ...expectation.prohibitedActors]) {
    if (!actorIds.has(actorId)) {
      throw new AppError(`Field expectation "${expectation.label}" references unknown actor "${actorId}".`, "FIELD_EXPOSURE_UNKNOWN_ACTOR");
    }
  }
  if (expectation.allowedActors.some((actorId) => expectation.prohibitedActors.includes(actorId))) {
    throw new AppError(`Field expectation "${expectation.label}" both allows and prohibits the same actor.`, "FIELD_EXPOSURE_CONTRADICTORY_POLICY");
  }
  if ((expectation.expectation === "MUST_BE_REDACTED" || expectation.expectation === "MASKED_VALUE") && !expectation.redactionPattern) {
    throw new AppError(`Field expectation "${expectation.label}" requires an explicit redactionPattern.`, "FIELD_EXPOSURE_REDACTION_PATTERN_REQUIRED");
  }
  if (expectation.redactionPattern) {
    try {
      new RegExp(expectation.redactionPattern);
    } catch {
      throw new AppError(`Field expectation "${expectation.label}" has an invalid redactionPattern.`, "FIELD_EXPOSURE_REDACTION_PATTERN_INVALID");
    }
  }
  return {
    id: expectation.id ?? `field-${index + 1}`,
    path: expectation.path,
    label: expectation.label,
    sensitivity: expectation.sensitivity,
    expectation: expectation.expectation,
    allowedActors: expectation.allowedActors,
    prohibitedActors: expectation.prohibitedActors,
    ...(expectation.redactionPattern ? { redactionPattern: expectation.redactionPattern } : {}),
    allowPreview: expectation.allowPreview,
    ...(expectation.maxLength ? { maxLength: expectation.maxLength } : {})
  };
}

function requestPlan(testCase: FieldExposureInput["cases"][number], actor: FieldExposureActorPlan, normalizedUrl: string): FieldExposureRequestPlan {
  const purpose =
    actor.id === testCase.declaredOwnerActor ? "owner-baseline" : actor.type === "PUBLIC" ? "public-baseline" : actor.type === "SHARED_PRINCIPAL" ? "shared-baseline" : "actor-baseline";
  return {
    id: `${testCase.id}:${actor.id}`,
    caseId: testCase.id,
    actorId: actor.id,
    actorType: actor.type,
    ...(actor.authSlot ? { authSlot: actor.authSlot } : {}),
    purpose,
    method: testCase.template.method,
    url: normalizedUrl,
    objectIdHash: hashValue(testCase.objectId, "object")
  };
}

function validateTemplate(template: FieldExposureInput["cases"][number]["template"]): void {
  if (template.method !== "GET") {
    throw new AppError(`Field exposure template "${template.id}" must use GET because body field projection is required.`, "FIELD_EXPOSURE_HEAD_UNSUPPORTED");
  }

  const decodedUrl = template.url.split(encodedObjectPlaceholder).join(objectPlaceholder);
  const placeholderCount = (decodedUrl.match(/\{\{OBJECT_ID\}\}/g) ?? []).length;
  if (placeholderCount !== 1) {
    throw new AppError(`Field exposure template "${template.id}" must contain exactly one {{OBJECT_ID}} placeholder.`, "FIELD_EXPOSURE_TEMPLATE_PLACEHOLDER_INVALID");
  }
  if (!template.url.startsWith("http://") && !template.url.startsWith("https://")) {
    throw new AppError(`Field exposure template "${template.id}" must use http or https.`, "FIELD_EXPOSURE_TEMPLATE_PROTOCOL_INVALID");
  }
  if (forbiddenEndpointWords.test(template.url)) {
    throw new AppError(`Field exposure template "${template.id}" appears to target a state-changing endpoint.`, "FIELD_EXPOSURE_TEMPLATE_UNSAFE_ENDPOINT");
  }
  if (urlHasEmbeddedSecret(template.url)) {
    throw new AppError(`Field exposure template "${template.id}" appears to contain secret-like material.`, "FIELD_EXPOSURE_TEMPLATE_SECRET_FORBIDDEN");
  }
  for (const [name, value] of Object.entries(template.headers)) {
    if (name.toLowerCase() === "authorization" || name.toLowerCase() === "cookie" || name.toLowerCase().startsWith("x-csrf") || secretLikePattern.test(name) || secretLikePattern.test(value)) {
      throw new AppError(`Field exposure template "${template.id}" must not embed authentication or secret-like headers.`, "FIELD_EXPOSURE_TEMPLATE_SECRET_FORBIDDEN");
    }
  }
  try {
    normalizeUrl(applyObjectPlaceholder(template.url, "routecairn-object"));
  } catch {
    throw new AppError(`Field exposure template "${template.id}" does not produce a valid URL.`, "FIELD_EXPOSURE_TEMPLATE_URL_INVALID");
  }
}

function validateIdentifier(value: string, label: string): void {
  if (value.length > maxIdentifierLength || generatorPattern.test(value) || /^\s*\d+\s*-\s*\d+\s*$/.test(value) || value.includes(",") || /[\r\n]/.test(value)) {
    throw new AppError(`Field exposure identifier "${label}" must be one exact operator-supplied value, not a range, wildcard, list, or generator.`, "FIELD_EXPOSURE_IDENTIFIER_UNSAFE");
  }
}

function validateDistinctAuthenticatedActors(caseId: string, actors: readonly FieldExposureActorPlan[]): void {
  const seenPrincipals = new Map<string, string>();
  for (const actor of actors.filter((item) => item.authSlot)) {
    const principalHash = actor.principalIdHash;
    if (!principalHash) continue;
    const previous = seenPrincipals.get(principalHash);
    if (previous && previous !== actor.id) {
      throw new AppError(`Field exposure case "${caseId}" maps two actors to the same declared principal.`, "FIELD_EXPOSURE_IDENTICAL_PRINCIPAL");
    }
    seenPrincipals.set(principalHash, actor.id);
  }
}

function validateDistinctAuthMaterial(caseId: string, actors: readonly FieldExposureActorPlan[], profileSet: AuthProfileSet | undefined): void {
  if (!profileSet) return;
  const usedSlots = new Set(actors.map((actor) => actor.authSlot).filter(Boolean));
  if (!usedSlots.has("account_a") || !usedSlots.has("account_b")) return;
  const accountA = stableAuthFingerprint(profileSet.accountA.headers, profileSet.accountA.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join(";"));
  const accountB = stableAuthFingerprint(profileSet.accountB.headers, profileSet.accountB.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join(";"));
  if (accountA === accountB) {
    throw new AppError(`Field exposure case "${caseId}" maps distinct actors to reused authentication material.`, "FIELD_EXPOSURE_IDENTICAL_AUTH_MATERIAL");
  }
}

function validateBaselineDependencies(caseId: string, actors: readonly FieldExposureActorPlan[], fields: readonly FieldExposureExpectationPlan[]): void {
  const hasPublic = actors.some((actor) => actor.type === "PUBLIC");
  const hasShared = actors.some((actor) => actor.type === "SHARED_PRINCIPAL");
  if (fields.some((field) => field.expectation === "MUST_MATCH_PUBLIC_BASELINE") && !hasPublic) {
    throw new AppError(`Field exposure case "${caseId}" uses MUST_MATCH_PUBLIC_BASELINE without a PUBLIC actor.`, "FIELD_EXPOSURE_PUBLIC_BASELINE_REQUIRED");
  }
  if (fields.some((field) => field.expectation === "MUST_MATCH_SHARED_BASELINE") && !hasShared) {
    throw new AppError(`Field exposure case "${caseId}" uses MUST_MATCH_SHARED_BASELINE without a SHARED_PRINCIPAL actor.`, "FIELD_EXPOSURE_SHARED_BASELINE_REQUIRED");
  }
}

function validateFieldUniqueness(caseId: string, fields: readonly FieldExposureExpectationPlan[]): void {
  const keys = new Set<string>();
  for (const field of fields) {
    if (keys.has(field.path)) {
      throw new AppError(`Field exposure case "${caseId}" contains duplicate field path "${field.path}".`, "FIELD_EXPOSURE_DUPLICATE_FIELD");
    }
    keys.add(field.path);
  }
}

function validateInputUniqueness(input: FieldExposureInput): void {
  const caseIds = new Set<string>();
  for (const testCase of input.cases) {
    if (caseIds.has(testCase.id)) {
      throw new AppError(`Field exposure case "${testCase.id}" is duplicated.`, "FIELD_EXPOSURE_DUPLICATE_CASE");
    }
    caseIds.add(testCase.id);
  }
}

function applyObjectPlaceholder(templateUrl: string, objectId: string): string {
  return templateUrl.split(objectPlaceholder).join(encodeURIComponent(objectId)).split(encodedObjectPlaceholder).join(encodeURIComponent(objectId));
}

function urlHasEmbeddedSecret(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.username || parsed.password) return true;
    for (const [name, value] of parsed.searchParams) {
      if (secretLikePattern.test(name) || secretLikePattern.test(value)) return true;
    }
    return false;
  } catch {
    return secretLikePattern.test(url);
  }
}

function hashValue(value: string, scope: string): string {
  return createHash("sha256").update(`routecairn-field-exposure-${scope}-v1`).update("\0").update(value).digest("hex").slice(0, 16);
}

function stableAuthFingerprint(headers: Record<string, string>, cookies: string): string {
  return createHash("sha256").update(JSON.stringify(Object.entries(headers).sort())).update(cookies).digest("hex");
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null) return value;
  Object.freeze(value);
  for (const item of Object.values(value)) deepFreeze(item);
  return value;
}
