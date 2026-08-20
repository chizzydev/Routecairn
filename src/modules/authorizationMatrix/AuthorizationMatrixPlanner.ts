import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import type {
  AuthorizationMatrixActorPlan,
  AuthorizationMatrixCasePlan,
  AuthorizationMatrixPlan,
  AuthorizationMatrixTestingPlan
} from "../../core/planning/ScanPlan.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";
import { parseSafeFieldPath } from "../fieldExposureTesting/SafeFieldPath.js";

const objectPlaceholder = "{{OBJECT_ID}}";
const encodedObjectPlaceholder = "%7B%7BOBJECT_ID%7D%7D";
const maxFileBytes = 256 * 1024;
const maxMatrices = 5;
const maxCasesPerMatrix = 40;
const maxActors = 3;
const maxIdentifierLength = 256;
const maxTemplateLength = 2048;
const forbiddenEndpointWords = /(?:delete|remove|cancel|purchase|pay|transfer|withdraw|approve|reject|publish|submit|invite|reset|activate|deactivate|suspend|logout|consume-on-read)/i;
const generatorPattern = /(?:\.\.|\*|\||=>|function\s*\(|regex|regexp|range|increment|decrement|random|uuid-v|eval|for\s*\(|while\s*\()/i;
const secretLikePattern = /(?:authorization|cookie|session|csrf|xsrf|token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|bearer\s+[a-z0-9._~+/=-]+)/i;

const relationshipSchema = z.enum([
  "OWNER",
  "NON_OWNER",
  "SAME_TENANT_MEMBER",
  "SAME_TENANT_ADMIN",
  "CROSS_TENANT_MEMBER",
  "CROSS_TENANT_ADMIN",
  "PLATFORM_ADMIN",
  "MODERATOR",
  "SHARED_PRINCIPAL",
  "PUBLIC",
  "CUSTOM_DECLARED_RELATIONSHIP"
]);
const expectedDecisionSchema = z.enum(["MUST_ALLOW", "MUST_DENY", "MUST_REQUIRE_AUTHENTICATION", "MUST_RETURN_NOT_FOUND", "MUST_MATCH_REFERENCE_DECISION", "MUST_NOT_EXCEED_REFERENCE_ACCESS", "OBSERVE_ONLY"]);

const actorSchema = z
  .object({
    id: z.string().min(1).max(80),
    relationship: relationshipSchema,
    authProfile: z.enum(["account_a", "account_b"]).optional(),
    safeAlias: z.string().min(1).max(80).optional(),
    principalId: z.string().min(1).max(maxIdentifierLength).optional(),
    tenantId: z.string().min(1).max(maxIdentifierLength).optional(),
    role: z.string().min(1).max(120).optional(),
    accountState: z.string().min(1).max(120).optional()
  })
  .strict();

const caseSchema = z
  .object({
    id: z.string().min(1).max(120),
    actorId: z.string().min(1).max(80),
    objectId: z.string().min(1).max(maxIdentifierLength),
    expectedObjectState: z.string().min(1).max(120).optional(),
    expectedDecision: expectedDecisionSchema,
    referenceCaseId: z.string().min(1).max(120).optional(),
    requireVerifiedIdentity: z.boolean().default(true),
    expectedTenantId: z.string().min(1).max(maxIdentifierLength).optional(),
    expectedRole: z.string().min(1).max(120).optional(),
    expectedAccountState: z.string().min(1).max(120).optional()
  })
  .strict();

const matrixSchema = z
  .object({
    id: z.string().min(1).max(120),
    name: z.string().min(1).max(160),
    objectType: z.string().min(1).max(80),
    template: z
      .object({
        id: z.string().min(1).max(120),
        method: z.literal("GET"),
        url: z.string().min(1).max(maxTemplateLength),
        headers: z.record(z.string().max(512)).default({})
      })
      .strict(),
    objectIdentityField: z.string().min(1).max(160),
    objectStateField: z.string().min(1).max(160).optional(),
    actors: z.array(actorSchema).min(1).max(maxActors),
    cases: z.array(caseSchema).min(1).max(maxCasesPerMatrix)
  })
  .strict();

export const authorizationMatrixInputSchema = z
  .object({
    schemaVersion: z.literal(1).default(1),
    maxMatrices: z.number().int().positive().max(maxMatrices).default(3),
    maxCasesPerMatrix: z.number().int().positive().max(maxCasesPerMatrix).default(20),
    maxResponseBytes: z.number().int().positive().max(512 * 1024).default(65536),
    maxPreviewLength: z.number().int().positive().max(512).default(120),
    matrices: z.array(matrixSchema).min(1).max(maxMatrices)
  })
  .strict();

export type AuthorizationMatrixInput = z.infer<typeof authorizationMatrixInputSchema>;

export async function loadAuthorizationMatrixInput(filePath: string): Promise<AuthorizationMatrixInput> {
  const rawBuffer = await readFile(filePath);
  if (rawBuffer.byteLength > maxFileBytes) {
    throw new AppError(`Authorization matrix input exceeds maximum size ${maxFileBytes} bytes.`, "AUTHORIZATION_MATRIX_FILE_TOO_LARGE");
  }
  let json: unknown;
  try {
    json = JSON.parse(rawBuffer.toString("utf8").replace(/^\uFEFF/, ""));
  } catch {
    throw new AppError("Authorization matrix input is not valid JSON.", "AUTHORIZATION_MATRIX_JSON_INVALID");
  }
  const parsed = authorizationMatrixInputSchema.safeParse(json);
  if (!parsed.success) {
    throw new AppError(parsed.error.message, "AUTHORIZATION_MATRIX_INPUT_INVALID");
  }
  return parsed.data;
}

export function planAuthorizationMatrixTesting(input: AuthorizationMatrixInput, options: { target: string; scope: RouteCairnScope; authProfileSet?: AuthProfileSet }): AuthorizationMatrixTestingPlan {
  if (input.matrices.length > input.maxMatrices) {
    throw new AppError(`Authorization matrix input contains ${input.matrices.length} matrices, exceeding maxMatrices ${input.maxMatrices}.`, "AUTHORIZATION_MATRIX_TOO_MANY_MATRICES");
  }
  const scopeMatcher = new ScopeMatcher(options.target, options.scope);
  const matrices = input.matrices.map((matrix) => planMatrix(matrix, input.maxCasesPerMatrix, scopeMatcher, options.authProfileSet));
  const requestMatrix = matrices.flatMap((matrix) => [...matrix.cases]);
  return deepFreeze({
    schemaVersion: 1,
    enabled: true,
    matrices,
    requestMatrix,
    maxMatrices: input.maxMatrices,
    maxCasesPerMatrix: input.maxCasesPerMatrix,
    maxRequests: requestMatrix.length,
    maxResponseBytes: input.maxResponseBytes,
    maxPreviewLength: input.maxPreviewLength,
    notes: [
      "Authorization matrix testing executes only operator-supplied GET matrix cells.",
      "Runtime responses do not add actors, roles, tenants, states, endpoints, objects, or cases.",
      "Object identity and configured object state must be confirmed before access is considered allowed."
    ]
  });
}

function planMatrix(input: AuthorizationMatrixInput["matrices"][number], maxCases: number, scopeMatcher: ScopeMatcher, authProfileSet: AuthProfileSet | undefined): AuthorizationMatrixPlan {
  if (input.cases.length > maxCases) {
    throw new AppError(`Authorization matrix "${input.id}" contains ${input.cases.length} cases, exceeding maxCasesPerMatrix ${maxCases}.`, "AUTHORIZATION_MATRIX_TOO_MANY_CASES");
  }
  validateTemplate(input.template);
  parseSafeFieldPath(input.objectIdentityField, { maxDepth: 8, maxArrayIndex: 50, code: "AUTHORIZATION_MATRIX_OBJECT_FIELD_INVALID" });
  if (input.objectStateField) parseSafeFieldPath(input.objectStateField, { maxDepth: 8, maxArrayIndex: 50, code: "AUTHORIZATION_MATRIX_OBJECT_FIELD_INVALID" });

  const actors = input.actors.map((actor) => actorPlan(actor, authProfileSet));
  validateActors(input.id, actors, authProfileSet);
  const actorById = new Map(actors.map((actor) => [actor.id, actor]));
  validateCaseIds(input.id, input.cases);
  validateReferences(input.id, input.cases);

  const cases = input.cases.map((testCase) => {
    const actor = actorById.get(testCase.actorId);
    if (!actor) throw new AppError(`Authorization matrix case "${testCase.id}" references unknown actor "${testCase.actorId}".`, "AUTHORIZATION_MATRIX_UNKNOWN_ACTOR");
    const expectedTenantHash = testCase.expectedTenantId ? hashValue(testCase.expectedTenantId, "tenant") : undefined;
    const expectedRoleHash = testCase.expectedRole ? hashValue(testCase.expectedRole, "role") : undefined;
    const expectedAccountStateHash = testCase.expectedAccountState ? hashValue(testCase.expectedAccountState, "account-state") : undefined;
    if (expectedTenantHash && actor.tenantIdHash && expectedTenantHash !== actor.tenantIdHash) throw new AppError(`Authorization matrix case "${testCase.id}" tenant expectation conflicts with actor metadata.`, "AUTHORIZATION_MATRIX_TENANT_MISMATCH");
    if (expectedRoleHash && actor.roleHash && expectedRoleHash !== actor.roleHash) throw new AppError(`Authorization matrix case "${testCase.id}" role expectation conflicts with actor metadata.`, "AUTHORIZATION_MATRIX_ROLE_MISMATCH");
    if (expectedAccountStateHash && actor.accountStateHash && expectedAccountStateHash !== actor.accountStateHash) throw new AppError(`Authorization matrix case "${testCase.id}" account-state expectation conflicts with actor metadata.`, "AUTHORIZATION_MATRIX_ACCOUNT_STATE_MISMATCH");
    validateIdentifier(testCase.objectId, `${input.id}.${testCase.id}.objectId`);
    if (testCase.expectedObjectState && !input.objectStateField) {
      throw new AppError(`Authorization matrix case "${testCase.id}" declares object state without objectStateField.`, "AUTHORIZATION_MATRIX_OBJECT_STATE_FIELD_REQUIRED");
    }
    const url = applyObjectPlaceholder(input.template.url, testCase.objectId);
    const decision = scopeMatcher.decide(url, "GET");
    if (!decision.allowed || !decision.normalizedUrl) {
      throw new AppError(`Authorization matrix case "${testCase.id}" is out of scope: ${decision.reason}.`, "AUTHORIZATION_MATRIX_OUT_OF_SCOPE");
    }
    return {
      id: testCase.id,
      matrixId: input.id,
      actorId: actor.id,
      relationship: actor.relationship,
      ...(actor.authSlot ? { authSlot: actor.authSlot } : {}),
      objectId: testCase.objectId,
      objectIdHash: hashValue(testCase.objectId, "object"),
      ...(testCase.expectedObjectState ? { expectedObjectState: testCase.expectedObjectState, expectedObjectStateHash: hashValue(testCase.expectedObjectState, "object-state") } : {}),
      expectedDecision: testCase.expectedDecision,
      ...(testCase.referenceCaseId ? { referenceCaseId: testCase.referenceCaseId } : {}),
      requireVerifiedIdentity: testCase.requireVerifiedIdentity,
      ...(expectedTenantHash ? { expectedTenantHash } : {}),
      ...(expectedRoleHash ? { expectedRoleHash } : {}),
      ...(expectedAccountStateHash ? { expectedAccountStateHash } : {}),
      url: decision.normalizedUrl
    } satisfies AuthorizationMatrixCasePlan;
  });

  return {
    id: input.id,
    name: input.name,
    objectType: input.objectType,
    template: { id: input.template.id, method: "GET", urlTemplate: input.template.url, headers: input.template.headers },
    objectIdentityField: input.objectIdentityField,
    ...(input.objectStateField ? { objectStateField: input.objectStateField } : {}),
    actors,
    cases
  };
}

function actorPlan(actor: AuthorizationMatrixInput["matrices"][number]["actors"][number], authProfileSet: AuthProfileSet | undefined): AuthorizationMatrixActorPlan {
  if (actor.relationship === "PUBLIC") {
    if (actor.authProfile) throw new AppError(`Public authorization actor "${actor.id}" must not reference an auth profile.`, "AUTHORIZATION_MATRIX_PUBLIC_AUTH_INVALID");
    return { id: actor.id, relationship: "PUBLIC", redactedLabel: actor.safeAlias ?? "Public" };
  }
  if (!authProfileSet) throw new AppError("Authorization matrix testing with authenticated actors requires --auth-a and --auth-b.", "AUTHORIZATION_MATRIX_AUTH_PAIR_REQUIRED");
  if (!actor.authProfile) throw new AppError(`Authenticated authorization actor "${actor.id}" must reference account_a or account_b.`, "AUTHORIZATION_MATRIX_AUTH_PROFILE_REQUIRED");
  const profile = actor.authProfile === "account_a" ? authProfileSet.accountA : authProfileSet.accountB;
  const principalId = actor.principalId ?? profile.principalId;
  if (!principalId) throw new AppError(`Authorization actor "${actor.id}" requires declared principalId metadata.`, "AUTHORIZATION_MATRIX_PRINCIPAL_ID_REQUIRED");
  if (actor.principalId && profile.principalId && actor.principalId !== profile.principalId) throw new AppError(`Authorization actor "${actor.id}" principal metadata does not match its auth profile.`, "AUTHORIZATION_MATRIX_PRINCIPAL_ID_MISMATCH");
  if (actor.tenantId && profile.tenantId && actor.tenantId !== profile.tenantId) throw new AppError(`Authorization actor "${actor.id}" tenant metadata does not match its auth profile.`, "AUTHORIZATION_MATRIX_TENANT_MISMATCH");
  if (actor.role && profile.role && actor.role !== profile.role) throw new AppError(`Authorization actor "${actor.id}" role metadata does not match its auth profile.`, "AUTHORIZATION_MATRIX_ROLE_MISMATCH");
  if (actor.accountState && profile.accountState && actor.accountState !== profile.accountState) throw new AppError(`Authorization actor "${actor.id}" account-state metadata does not match its auth profile.`, "AUTHORIZATION_MATRIX_ACCOUNT_STATE_MISMATCH");
  return {
    id: actor.id,
    relationship: actor.relationship,
    redactedLabel: actor.safeAlias ?? profile.safeAlias ?? profile.label,
    authSlot: actor.authProfile,
    principalIdHash: hashValue(principalId, "principal"),
    ...(actor.tenantId ?? profile.tenantId ? { tenantIdHash: hashValue(actor.tenantId ?? profile.tenantId ?? "", "tenant") } : {}),
    ...(actor.role ?? profile.role ? { roleHash: hashValue(actor.role ?? profile.role ?? "", "role") } : {}),
    ...(actor.accountState ?? profile.accountState ? { accountStateHash: hashValue(actor.accountState ?? profile.accountState ?? "", "account-state") } : {})
  };
}

function validateTemplate(template: AuthorizationMatrixInput["matrices"][number]["template"]): void {
  if (template.method !== "GET") throw new AppError(`Authorization matrix template "${template.id}" must use GET.`, "AUTHORIZATION_MATRIX_METHOD_UNSAFE");
  const decodedUrl = template.url.split(encodedObjectPlaceholder).join(objectPlaceholder);
  if ((decodedUrl.match(/\{\{OBJECT_ID\}\}/g) ?? []).length !== 1) throw new AppError(`Authorization matrix template "${template.id}" must contain exactly one {{OBJECT_ID}} placeholder.`, "AUTHORIZATION_MATRIX_TEMPLATE_PLACEHOLDER_INVALID");
  if ((decodedUrl.match(/\{\{[A-Z_]+\}\}/g) ?? []).some((placeholder) => placeholder !== objectPlaceholder)) throw new AppError(`Authorization matrix template "${template.id}" contains undeclared placeholders.`, "AUTHORIZATION_MATRIX_TEMPLATE_PLACEHOLDER_INVALID");
  if (!template.url.startsWith("http://") && !template.url.startsWith("https://")) throw new AppError(`Authorization matrix template "${template.id}" must use http or https.`, "AUTHORIZATION_MATRIX_TEMPLATE_PROTOCOL_INVALID");
  if (forbiddenEndpointWords.test(template.url) || generatorPattern.test(template.url)) throw new AppError(`Authorization matrix template "${template.id}" appears unsafe or dynamic.`, "AUTHORIZATION_MATRIX_TEMPLATE_UNSAFE");
  if (urlHasEmbeddedSecret(template.url)) throw new AppError(`Authorization matrix template "${template.id}" appears to contain secret-like material.`, "AUTHORIZATION_MATRIX_TEMPLATE_SECRET_FORBIDDEN");
  for (const [name, value] of Object.entries(template.headers)) {
    if (name.toLowerCase() === "authorization" || name.toLowerCase() === "cookie" || name.toLowerCase().startsWith("x-csrf") || secretLikePattern.test(name) || secretLikePattern.test(value)) {
      throw new AppError(`Authorization matrix template "${template.id}" must not embed authentication or secret-like headers.`, "AUTHORIZATION_MATRIX_TEMPLATE_SECRET_FORBIDDEN");
    }
  }
  try {
    normalizeUrl(applyObjectPlaceholder(template.url, "routecairn-object"));
  } catch {
    throw new AppError(`Authorization matrix template "${template.id}" does not produce a valid URL.`, "AUTHORIZATION_MATRIX_TEMPLATE_URL_INVALID");
  }
}

function validateActors(matrixId: string, actors: readonly AuthorizationMatrixActorPlan[], profileSet: AuthProfileSet | undefined): void {
  if (new Set(actors.map((actor) => actor.id)).size !== actors.length) throw new AppError(`Authorization matrix "${matrixId}" contains duplicate actor IDs.`, "AUTHORIZATION_MATRIX_DUPLICATE_ACTOR");
  const seenPrincipals = new Map<string, string>();
  for (const actor of actors.filter((item) => item.authSlot)) {
    if (!actor.principalIdHash) continue;
    const previous = seenPrincipals.get(actor.principalIdHash);
    if (previous && previous !== actor.id) throw new AppError(`Authorization matrix "${matrixId}" maps distinct actors to the same declared principal.`, "AUTHORIZATION_MATRIX_IDENTICAL_PRINCIPAL");
    seenPrincipals.set(actor.principalIdHash, actor.id);
  }
  if (!profileSet) return;
  const usedSlots = new Set(actors.map((actor) => actor.authSlot).filter(Boolean));
  if (usedSlots.has("account_a") && usedSlots.has("account_b")) {
    const accountA = stableAuthFingerprint(profileSet.accountA.headers, profileSet.accountA.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join(";"));
    const accountB = stableAuthFingerprint(profileSet.accountB.headers, profileSet.accountB.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join(";"));
    if (accountA === accountB) throw new AppError(`Authorization matrix "${matrixId}" maps distinct actors to reused authentication material.`, "AUTHORIZATION_MATRIX_IDENTICAL_AUTH_MATERIAL");
  }
}

function validateCaseIds(matrixId: string, cases: readonly AuthorizationMatrixInput["matrices"][number]["cases"][number][]): void {
  const ids = new Set<string>();
  for (const testCase of cases) {
    if (ids.has(testCase.id)) throw new AppError(`Authorization matrix "${matrixId}" contains duplicate case "${testCase.id}".`, "AUTHORIZATION_MATRIX_DUPLICATE_CASE");
    ids.add(testCase.id);
    if ((testCase.expectedDecision === "MUST_MATCH_REFERENCE_DECISION" || testCase.expectedDecision === "MUST_NOT_EXCEED_REFERENCE_ACCESS") && !testCase.referenceCaseId) throw new AppError(`Authorization matrix case "${testCase.id}" requires referenceCaseId.`, "AUTHORIZATION_MATRIX_REFERENCE_REQUIRED");
  }
}

function validateReferences(matrixId: string, cases: readonly AuthorizationMatrixInput["matrices"][number]["cases"][number][]): void {
  const byId = new Map(cases.map((testCase) => [testCase.id, testCase]));
  for (const testCase of cases) {
    if (testCase.referenceCaseId && !byId.has(testCase.referenceCaseId)) throw new AppError(`Authorization matrix case "${testCase.id}" references missing case "${testCase.referenceCaseId}".`, "AUTHORIZATION_MATRIX_REFERENCE_INVALID");
    const seen = new Set<string>();
    let cursor: string | undefined = testCase.referenceCaseId;
    while (cursor) {
      if (seen.has(cursor) || cursor === testCase.id) throw new AppError(`Authorization matrix "${matrixId}" contains circular reference cases.`, "AUTHORIZATION_MATRIX_REFERENCE_CYCLE");
      seen.add(cursor);
      cursor = byId.get(cursor)?.referenceCaseId;
    }
  }
}

function validateIdentifier(value: string, label: string): void {
  if (value.length > maxIdentifierLength || generatorPattern.test(value) || /^\s*\d+\s*-\s*\d+\s*$/.test(value) || value.includes(",") || /[\r\n]/.test(value)) {
    throw new AppError(`Authorization matrix identifier "${label}" must be one exact operator-supplied value.`, "AUTHORIZATION_MATRIX_IDENTIFIER_UNSAFE");
  }
}

function applyObjectPlaceholder(templateUrl: string, objectId: string): string {
  return templateUrl.split(objectPlaceholder).join(encodeURIComponent(objectId)).split(encodedObjectPlaceholder).join(encodeURIComponent(objectId));
}

function urlHasEmbeddedSecret(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.username || parsed.password) return true;
    for (const [name, value] of parsed.searchParams) if (secretLikePattern.test(name) || secretLikePattern.test(value)) return true;
    return false;
  } catch {
    return secretLikePattern.test(url);
  }
}

function hashValue(value: string, scope: string): string {
  return createHash("sha256").update(`routecairn-authorization-matrix-${scope}-v1`).update("\0").update(value).digest("hex").slice(0, 16);
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
