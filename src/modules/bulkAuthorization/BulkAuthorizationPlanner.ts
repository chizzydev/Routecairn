import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import type {
  BulkActorPlan,
  BulkAuthorizationCasePlan,
  BulkAuthorizationTestingPlan,
  BulkObjectPlan,
  BulkPostconditionCheckPlan,
  BulkSingleObjectBaselinePlan
} from "../../core/planning/ScanPlan.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { parseSafeFieldPath } from "../fieldExposureTesting/SafeFieldPath.js";

const maxFileBytes = 256 * 1024;
const maxDefinitions = 5;
const maxCases = 25;
const maxObjects = 20;
const objectArrayPlaceholder = "{{OBJECT_IDS_ARRAY}}";
const repeatedPlaceholder = "{{OBJECT_ID_LIST_REPEATED}}";
const commaPlaceholder = "{{OBJECT_ID_LIST_COMMA}}";
const generatorPattern = /(?:\.\.|\*|\||=>|function\s*\(|regex|regexp|range|increment|decrement|random|uuid-v|eval|for\s*\(|while\s*\(|<%|%\>|\$\(.*\))/i;
const secretLikePattern = /(?:authorization|cookie|session|csrf|xsrf|token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|bearer\s+[a-z0-9._~+/=-]+)/i;
const forbiddenOperationWords = /(?:delete|update|approve|reject|transfer|move|archive|restore|publish|unpublish|assign|owner|export_file|start_job|queue|webhook)/i;

const actorRelationshipSchema = z.enum(["OWNER", "NON_OWNER", "SAME_TENANT_MEMBER", "SAME_TENANT_ADMIN", "CROSS_TENANT_MEMBER", "CROSS_TENANT_ADMIN", "PLATFORM_ADMIN", "MODERATOR", "SHARED_PRINCIPAL", "ACTIVE_ACCOUNT", "SUSPENDED_ACCOUNT", "DEACTIVATED_ACCOUNT", "PUBLIC", "CUSTOM_DECLARED_RELATIONSHIP"]);
const operationSchema = z.enum(["PREVIEW", "VALIDATE", "DRY_RUN", "EXPORT_SUMMARY", "EXPORT_MANIFEST_PREVIEW", "SELECTION_SUMMARY", "ELIGIBILITY_CHECK", "PERMISSION_CHECK", "SIMULATION", "OBSERVE_ONLY"]);
const environmentSchema = z.enum(["CONTROLLED_TEST", "LOCAL_FIXTURE", "AUTHORIZED_STAGING", "AUTHORIZED_PRODUCTION_TEST_DATA"]);
const requestStyleSchema = z.enum(["GET_REPEATED_QUERY", "GET_COMMA_QUERY", "JSON_POST"]);
const caseTypeSchema = z.enum(["SINGLE_ALLOWED", "SINGLE_DENIED", "ALL_ALLOWED", "ALL_DENIED", "MIXED_OWNERSHIP", "MIXED_TENANT", "MIXED_ROLE_VISIBILITY", "MIXED_OBJECT_STATE", "PUBLIC_MIXED_VISIBILITY", "REFERENCE_COMPARISON"]);
const objectDecisionSchema = z.enum(["ALLOW", "DENY", "FILTER_OUT", "EXPLICIT_REJECTION", "REDACTED_METADATA_ONLY", "PUBLIC_SUMMARY_ONLY", "MATCH_SINGLE_OBJECT_DECISION", "OBSERVE_ONLY"]);
const batchPolicySchema = z.enum(["MUST_ALLOW_ENTIRE_BATCH", "MUST_REJECT_ENTIRE_BATCH", "MUST_FILTER_UNAUTHORIZED_OBJECTS", "MUST_RETURN_PER_OBJECT_DECISIONS", "MUST_NOT_EXPOSE_RESTRICTED_METADATA", "MUST_MATCH_SINGLE_OBJECT_DECISIONS", "MUST_MATCH_REFERENCE_CASE", "OBSERVE_ONLY"]);
const responseContractSchema = z.enum(["ATOMIC_DECISION", "FILTERED_OBJECT_LIST", "PER_OBJECT_DECISIONS", "PREVIEW_OBJECT_LIST", "SUMMARY_ONLY", "EXPORT_MANIFEST_PREVIEW", "VALIDATION_RESULTS", "REFERENCE_ONLY"]);
const postSafetyModeSchema = z.enum(["GET_ONLY", "OPERATOR_ATTESTED_DRY_RUN", "POSTCONDITION_VERIFIED_DRY_RUN"]);
const baselineSourceSchema = z.enum(["SAFE_GET", "REUSE_OBJECT_PAIR_RESULT", "REUSE_AUTHORIZATION_MATRIX_RESULT"]);
const baselineDecisionSchema = z.enum(["MUST_ALLOW", "MUST_DENY", "MUST_REQUIRE_AUTHENTICATION", "MUST_RETURN_NOT_FOUND", "OBSERVE_ONLY"]);

const singleObjectBaselineSchema = z.object({
  id: z.string().min(1).max(120),
  source: baselineSourceSchema.default("SAFE_GET"),
  actorId: z.string().min(1).max(80),
  method: z.literal("GET").default("GET"),
  url: z.string().min(1).max(2048),
  headers: z.record(z.string().max(512)).default({}),
  expectedDecision: baselineDecisionSchema,
  requireVerifiedIdentity: z.boolean().default(true),
  objectIdentityField: z.string().min(1).max(160),
  objectStateField: z.string().min(1).max(160).optional(),
  expectedObjectState: z.string().min(1).max(120).optional(),
  expectedTenantId: z.string().min(1).max(256).optional(),
  expectedRole: z.string().min(1).max(120).optional(),
  maxResponseBytes: z.number().int().positive().max(512 * 1024).default(65536),
  maxJsonDepth: z.number().int().positive().max(24).default(10)
}).strict();

const postconditionFieldSchema = z.object({
  path: z.string().min(1).max(160),
  expectedValue: z.union([z.string(), z.number(), z.boolean(), z.null()]).optional()
}).strict();

const postconditionCheckSchema = z.object({
  id: z.string().min(1).max(120),
  actorId: z.string().min(1).max(80),
  objectId: z.string().min(1).max(256),
  method: z.literal("GET").default("GET"),
  url: z.string().min(1).max(2048),
  headers: z.record(z.string().max(512)).default({}),
  objectIdentityField: z.string().min(1).max(160),
  objectStateField: z.string().min(1).max(160).optional(),
  fields: z.array(postconditionFieldSchema).min(1).max(12),
  requireVerifiedIdentity: z.boolean().default(true),
  expectedTenantId: z.string().min(1).max(256).optional(),
  expectedRole: z.string().min(1).max(120).optional(),
  maxResponseBytes: z.number().int().positive().max(512 * 1024).default(65536),
  maxJsonDepth: z.number().int().positive().max(24).default(10)
}).strict();

const actorSchema = z.object({
  id: z.string().min(1).max(80),
  relationship: actorRelationshipSchema,
  authProfile: z.enum(["account_a", "account_b"]).optional(),
  safeAlias: z.string().min(1).max(80).optional(),
  principalId: z.string().min(1).max(256).optional(),
  tenantId: z.string().min(1).max(256).optional(),
  role: z.string().min(1).max(120).optional(),
  accountState: z.string().min(1).max(120).optional()
}).strict();

const objectSchema = z.object({
  id: z.string().min(1).max(120),
  objectId: z.string().min(1).max(256),
  safeAlias: z.string().min(1).max(80).optional(),
  objectType: z.string().min(1).max(80),
  expectedDecision: objectDecisionSchema,
  ownerActorId: z.string().min(1).max(80).optional(),
  tenantId: z.string().min(1).max(256).optional(),
  state: z.string().min(1).max(120).optional(),
  roleVisibility: z.string().min(1).max(120).optional(),
  verificationSource: z.enum(["DECLARED_ONLY", "REUSE_VERIFIED_OBJECT_RESULT", "SAFE_DETAIL_BASELINE"]).default("DECLARED_ONLY"),
  baseline: singleObjectBaselineSchema.optional()
}).strict();

const safetyContractSchema = z.object({
  operationType: operationSchema,
  operatorConfirmedNonMutating: z.literal(true),
  environment: environmentSchema.default("CONTROLLED_TEST"),
  requiredRequestMarkerPath: z.string().min(1).max(160).optional(),
  requiredRequestMarkerValue: z.union([z.string(), z.number(), z.boolean(), z.null()]).optional(),
  requiredResponseMarkerPath: z.string().min(1).max(160).optional(),
  requiredResponseMarkerValue: z.union([z.string(), z.number(), z.boolean(), z.null()]).optional(),
  disallowedResponsePaths: z.array(z.string().min(1).max(160)).max(12).default([]),
  disallowedStatusCodes: z.array(z.number().int().min(100).max(599)).max(12).default([201, 202]),
  prohibitAsync: z.boolean().default(true),
  prohibitDownloads: z.boolean().default(true)
}).strict();

const responseContractConfigSchema = z.object({
  type: responseContractSchema,
  resultArrayPath: z.string().min(1).max(160).optional(),
  resultObjectIdPath: z.string().min(1).max(160).optional(),
  perObjectDecisionPath: z.string().min(1).max(160).optional(),
  rejectedArrayPath: z.string().min(1).max(160).optional(),
  rejectedObjectIdPath: z.string().min(1).max(160).optional(),
  overallDecisionPath: z.string().min(1).max(160).optional(),
  previewCountPath: z.string().min(1).max(160).optional(),
  metadataPaths: z.array(z.string().min(1).max(160)).max(12).default([]),
  maxItems: z.number().int().positive().max(200).default(50)
}).strict();

const caseSchema = z.object({
  id: z.string().min(1).max(120),
  actorId: z.string().min(1).max(80),
  caseType: caseTypeSchema,
  requestStyle: requestStyleSchema,
  method: z.enum(["GET", "POST"]),
  url: z.string().min(1).max(2048),
  headers: z.record(z.string().max(512)).default({}),
  bodyTemplate: z.unknown().optional(),
  objectOrderMatters: z.boolean().default(true),
  objects: z.array(objectSchema).min(1).max(maxObjects),
  expectedBatchPolicy: batchPolicySchema,
  requireVerifiedIdentity: z.boolean().default(true),
  expectedTenantId: z.string().min(1).max(256).optional(),
  expectedRole: z.string().min(1).max(120).optional(),
  expectedAccountState: z.string().min(1).max(120).optional(),
  safetyContract: safetyContractSchema,
  responseContract: responseContractConfigSchema,
  postSafetyMode: postSafetyModeSchema.optional(),
  postconditionChecks: z.array(postconditionCheckSchema).max(20).default([]),
  maxResponseBytes: z.number().int().positive().max(512 * 1024).default(65536),
  maxJsonDepth: z.number().int().positive().max(24).default(10),
  maxPreviewLength: z.number().int().positive().max(512).default(120)
}).strict();

const definitionSchema = z.object({
  id: z.string().min(1).max(120),
  label: z.string().min(1).max(160),
  actors: z.array(actorSchema).min(1).max(3),
  cases: z.array(caseSchema).min(1).max(maxCases)
}).strict();

export const bulkAuthorizationInputSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  maxDefinitions: z.number().int().positive().max(maxDefinitions).default(3),
  maxCasesPerDefinition: z.number().int().positive().max(maxCases).default(10),
  maxObjectsPerCase: z.number().int().positive().max(maxObjects).default(10),
  maxRequests: z.number().int().positive().max(100).default(25),
  maxRetainedObservations: z.number().int().positive().max(100).default(50),
  definitions: z.array(definitionSchema).min(1).max(maxDefinitions)
}).strict();

export type BulkAuthorizationInput = z.infer<typeof bulkAuthorizationInputSchema>;

export async function loadBulkAuthorizationInput(filePath: string): Promise<BulkAuthorizationInput> {
  const raw = await readFile(filePath);
  if (raw.byteLength > maxFileBytes) throw new AppError(`Bulk authorization input exceeds maximum size ${maxFileBytes} bytes.`, "BULK_AUTHORIZATION_FILE_TOO_LARGE");
  let json: unknown;
  try {
    json = JSON.parse(raw.toString("utf8").replace(/^\uFEFF/, ""));
  } catch {
    throw new AppError("Bulk authorization input is not valid JSON.", "BULK_AUTHORIZATION_JSON_INVALID");
  }
  const parsed = bulkAuthorizationInputSchema.safeParse(json);
  if (!parsed.success) throw new AppError(parsed.error.message, "BULK_AUTHORIZATION_INPUT_INVALID");
  return parsed.data;
}

export function planBulkAuthorizationTesting(input: BulkAuthorizationInput, options: { target: string; scope: RouteCairnScope; authProfileSet?: AuthProfileSet }): BulkAuthorizationTestingPlan {
  const matcher = new ScopeMatcher(options.target, options.scope);
  const definitions = input.definitions.map((definition) => {
    if (definition.cases.length > input.maxCasesPerDefinition) throw new AppError(`Bulk definition "${definition.id}" exceeds maxCasesPerDefinition.`, "BULK_AUTHORIZATION_TOO_MANY_CASES");
    const actors = definition.actors.map((actor) => actorPlan(actor, options.authProfileSet));
    validateActors(definition.id, actors, options.authProfileSet);
    const actorById = new Map(actors.map((actor) => [actor.id, actor]));
    const caseIds = new Set<string>();
    const cases = definition.cases.map((testCase) => {
      if (caseIds.has(testCase.id)) throw new AppError(`Bulk definition "${definition.id}" contains duplicate case "${testCase.id}".`, "BULK_AUTHORIZATION_DUPLICATE_CASE");
      caseIds.add(testCase.id);
      const actor = actorById.get(testCase.actorId);
      if (!actor) throw new AppError(`Bulk case "${testCase.id}" references unknown actor "${testCase.actorId}".`, "BULK_AUTHORIZATION_UNKNOWN_ACTOR");
      if (testCase.objects.length > input.maxObjectsPerCase) throw new AppError(`Bulk case "${testCase.id}" exceeds maxObjectsPerCase.`, "BULK_AUTHORIZATION_TOO_MANY_OBJECTS");
      const objects = testCase.objects.map((object) => objectPlan(object, actorById, matcher));
      validateObjects(testCase.id, objects);
      validateSafety(testCase);
      validateResponseContract(testCase);
      validatePostSafety(testCase);
      const resolved = resolveRequest(testCase, objects);
      const decision = matcher.decide(resolved.url, testCase.method);
      if (!decision.allowed || !decision.normalizedUrl) throw new AppError(`Bulk case "${testCase.id}" is out of scope: ${decision.reason}.`, "BULK_AUTHORIZATION_OUT_OF_SCOPE");
      return deepFreeze({
        id: testCase.id,
        definitionId: definition.id,
        actorId: actor.id,
        actorRelationship: actor.relationship,
        ...(actor.authSlot ? { authSlot: actor.authSlot } : {}),
        caseType: testCase.caseType,
        requestStyle: testCase.requestStyle,
        method: testCase.method,
        url: decision.normalizedUrl,
        headers: { ...testCase.headers, ...(testCase.method === "POST" ? { "content-type": "application/json" } : {}) },
        ...(resolved.body ? { body: resolved.body, bodyHash: hashValue(resolved.body, "body") } : {}),
        objectOrderMatters: testCase.objectOrderMatters,
        objects,
        expectedBatchPolicy: testCase.expectedBatchPolicy,
        requireVerifiedIdentity: testCase.requireVerifiedIdentity && Boolean(actor.authSlot),
        ...(testCase.expectedTenantId ? { expectedTenantHash: hashIdentityValue(testCase.expectedTenantId) } : {}),
        ...(testCase.expectedRole ? { expectedRoleHash: hashIdentityValue(testCase.expectedRole) } : {}),
        ...(testCase.expectedAccountState ? { expectedAccountStateHash: hashIdentityValue(testCase.expectedAccountState) } : {}),
	        safetyContract: safetyPlan(testCase.safetyContract),
	        responseContract: responseContractPlan(testCase.responseContract),
        postSafetyMode: testCase.postSafetyMode ?? (testCase.method === "POST" ? "OPERATOR_ATTESTED_DRY_RUN" : "GET_ONLY"),
        postconditionChecks: postconditionChecks(testCase, actorById, objects, matcher),
	        maxResponseBytes: testCase.maxResponseBytes,
        maxJsonDepth: testCase.maxJsonDepth,
        maxPreviewLength: testCase.maxPreviewLength
      } satisfies BulkAuthorizationCasePlan);
    });
    return deepFreeze({ id: definition.id, label: definition.label, cases });
  });
  const requestMatrix = definitions.flatMap((definition) => [...definition.cases]);
  if (requestMatrix.length > input.maxRequests) throw new AppError(`Bulk authorization resolves ${requestMatrix.length} cases, exceeding maxRequests.`, "BULK_AUTHORIZATION_TOO_MANY_REQUESTS");
  return deepFreeze({
    schemaVersion: 1,
    enabled: true,
    definitions,
    requestMatrix,
    maxDefinitions: input.maxDefinitions,
    maxCasesPerDefinition: input.maxCasesPerDefinition,
    maxObjectsPerCase: input.maxObjectsPerCase,
    maxRequests: input.maxRequests,
    maxRetainedObservations: input.maxRetainedObservations,
    notes: [
      "Bulk authorization executes only resolved non-mutating GET or controlled JSON POST cases.",
      "Object sets, order, request bodies, response paths, and safety contracts are fixed before execution.",
      "Runtime responses do not add objects, split batches, paginate, poll jobs, or create follow-up cases."
    ]
  });
}

function safetyPlan(input: BulkAuthorizationInput["definitions"][number]["cases"][number]["safetyContract"]) {
  return {
    operationType: input.operationType,
    operatorConfirmedNonMutating: true as const,
    environment: input.environment,
    ...(input.requiredRequestMarkerPath ? { requiredRequestMarkerPath: input.requiredRequestMarkerPath } : {}),
    ...(input.requiredRequestMarkerValue !== undefined ? { requiredRequestMarkerValue: input.requiredRequestMarkerValue } : {}),
    ...(input.requiredResponseMarkerPath ? { requiredResponseMarkerPath: input.requiredResponseMarkerPath } : {}),
    ...(input.requiredResponseMarkerValue !== undefined ? { requiredResponseMarkerValue: input.requiredResponseMarkerValue } : {}),
    disallowedResponsePaths: input.disallowedResponsePaths,
    disallowedStatusCodes: input.disallowedStatusCodes,
    prohibitAsync: input.prohibitAsync,
    prohibitDownloads: input.prohibitDownloads
  };
}

function responseContractPlan(input: BulkAuthorizationInput["definitions"][number]["cases"][number]["responseContract"]) {
  return {
    type: input.type,
    ...(input.resultArrayPath ? { resultArrayPath: input.resultArrayPath } : {}),
    ...(input.resultObjectIdPath ? { resultObjectIdPath: input.resultObjectIdPath } : {}),
    ...(input.perObjectDecisionPath ? { perObjectDecisionPath: input.perObjectDecisionPath } : {}),
    ...(input.rejectedArrayPath ? { rejectedArrayPath: input.rejectedArrayPath } : {}),
    ...(input.rejectedObjectIdPath ? { rejectedObjectIdPath: input.rejectedObjectIdPath } : {}),
    ...(input.overallDecisionPath ? { overallDecisionPath: input.overallDecisionPath } : {}),
    ...(input.previewCountPath ? { previewCountPath: input.previewCountPath } : {}),
    metadataPaths: input.metadataPaths,
    maxItems: input.maxItems
  };
}

function actorPlan(actor: BulkAuthorizationInput["definitions"][number]["actors"][number], authProfileSet: AuthProfileSet | undefined): BulkActorPlan {
  if (actor.relationship === "PUBLIC") {
    if (actor.authProfile) throw new AppError(`Public bulk actor "${actor.id}" must not reference an auth profile.`, "BULK_AUTHORIZATION_PUBLIC_AUTH_INVALID");
    return { id: actor.id, relationship: "PUBLIC", redactedLabel: actor.safeAlias ?? "Public" };
  }
  if (!authProfileSet) throw new AppError("Bulk authorization testing with authenticated actors requires --auth-a and --auth-b.", "BULK_AUTHORIZATION_AUTH_PAIR_REQUIRED");
  if (!actor.authProfile) throw new AppError(`Authenticated bulk actor "${actor.id}" must reference account_a or account_b.`, "BULK_AUTHORIZATION_AUTH_PROFILE_REQUIRED");
  const profile = actor.authProfile === "account_a" ? authProfileSet.accountA : authProfileSet.accountB;
  const principalId = actor.principalId ?? profile.principalId;
  if (!principalId) throw new AppError(`Bulk actor "${actor.id}" requires declared principalId metadata.`, "BULK_AUTHORIZATION_PRINCIPAL_ID_REQUIRED");
  return {
    id: actor.id,
    relationship: actor.relationship,
    redactedLabel: actor.safeAlias ?? profile.safeAlias ?? profile.label,
    authSlot: actor.authProfile,
    principalIdHash: hashIdentityValue(principalId),
    ...(actor.tenantId ?? profile.tenantId ? { tenantIdHash: hashIdentityValue(actor.tenantId ?? profile.tenantId ?? "") } : {}),
    ...(actor.role ?? profile.role ? { roleHash: hashIdentityValue(actor.role ?? profile.role ?? "") } : {}),
    ...(actor.accountState ?? profile.accountState ? { accountStateHash: hashIdentityValue(actor.accountState ?? profile.accountState ?? "") } : {})
  };
}

function objectPlan(input: BulkAuthorizationInput["definitions"][number]["cases"][number]["objects"][number], actorById: ReadonlyMap<string, BulkActorPlan>, matcher: ScopeMatcher): BulkObjectPlan {
  if (typeof input.objectId !== "string") throw new AppError(`Bulk object "${input.id}" must declare an exact string objectId.`, "BULK_AUTHORIZATION_OBJECT_ID_UNSAFE");
  if (generatorPattern.test(input.objectId) || secretLikePattern.test(input.objectId) || /[\r\n\0]/.test(input.objectId)) throw new AppError(`Bulk object "${input.id}" has an unsafe objectId.`, "BULK_AUTHORIZATION_OBJECT_ID_UNSAFE");
  const objectIdHash = hashValue(input.objectId, "object");
  return {
    id: input.id,
    objectId: input.objectId,
    objectIdHash,
    redactedAlias: input.safeAlias ?? `<object:${objectIdHash}>`,
    objectType: input.objectType,
    expectedDecision: input.expectedDecision,
    ...(input.ownerActorId ? { ownerActorId: input.ownerActorId } : {}),
    ...(input.tenantId ? { tenantIdHash: hashValue(input.tenantId, "tenant") } : {}),
    ...(input.state ? { state: input.state, stateHash: hashValue(input.state, "state") } : {}),
    ...(input.roleVisibility ? { roleVisibilityHash: hashValue(input.roleVisibility, "role-visibility") } : {}),
    verificationSource: input.verificationSource,
    ...(input.baseline ? { baseline: baselinePlan(input.id, input.objectId, input.baseline, actorById, matcher) } : {})
  };
}

function baselinePlan(
  objectRefId: string,
  objectId: string,
  input: NonNullable<BulkAuthorizationInput["definitions"][number]["cases"][number]["objects"][number]["baseline"]>,
  actorById: ReadonlyMap<string, BulkActorPlan>,
  matcher: ScopeMatcher
): BulkSingleObjectBaselinePlan {
  const actor = actorById.get(input.actorId);
  if (!actor) throw new AppError(`Bulk object "${objectRefId}" baseline references unknown actor "${input.actorId}".`, "BULK_AUTHORIZATION_UNKNOWN_ACTOR");
  if (input.source !== "SAFE_GET") throw new AppError(`Bulk object "${objectRefId}" baseline source "${input.source}" is not available without a compatible completed result.`, "BULK_AUTHORIZATION_BASELINE_SOURCE_UNAVAILABLE");
  validateExactObjectTemplate(input.id, input.url, objectId);
  validateHeaderSafety(input.headers, `baseline "${input.id}"`);
  for (const path of [input.objectIdentityField, input.objectStateField].filter((item): item is string => Boolean(item))) parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 50, code: "BULK_AUTHORIZATION_FIELD_PATH_INVALID" });
  const resolvedUrl = input.url.replace("{{OBJECT_ID}}", encodeURIComponent(objectId));
  const decision = matcher.decide(resolvedUrl, "GET");
  if (!decision.allowed || !decision.normalizedUrl) throw new AppError(`Bulk baseline "${input.id}" is out of scope: ${decision.reason}.`, "BULK_AUTHORIZATION_OUT_OF_SCOPE");
  return {
    id: input.id,
    source: input.source,
    actorId: input.actorId,
    ...(actor.authSlot ? { authSlot: actor.authSlot } : {}),
    method: "GET",
    url: decision.normalizedUrl,
    headers: input.headers,
    expectedDecision: input.expectedDecision,
    requireVerifiedIdentity: input.requireVerifiedIdentity && Boolean(actor.authSlot),
    objectIdentityField: input.objectIdentityField,
    ...(input.objectStateField ? { objectStateField: input.objectStateField } : {}),
    ...(input.expectedObjectState ? { expectedObjectState: input.expectedObjectState, expectedObjectStateHash: hashValue(input.expectedObjectState, "state") } : {}),
    ...(input.expectedTenantId ? { expectedTenantHash: hashIdentityValue(input.expectedTenantId) } : {}),
    ...(input.expectedRole ? { expectedRoleHash: hashIdentityValue(input.expectedRole) } : {}),
    maxResponseBytes: input.maxResponseBytes,
    maxJsonDepth: input.maxJsonDepth
  };
}

function validateObjects(caseId: string, objects: readonly BulkObjectPlan[]): void {
  const seen = new Set<string>();
  for (const object of objects) {
    if (seen.has(object.objectId)) throw new AppError(`Bulk case "${caseId}" contains duplicate supplied object IDs.`, "BULK_AUTHORIZATION_DUPLICATE_OBJECT");
    seen.add(object.objectId);
  }
}

function validateActors(definitionId: string, actors: readonly BulkActorPlan[], authProfileSet: AuthProfileSet | undefined): void {
  const ids = new Set<string>();
  for (const actor of actors) {
    if (ids.has(actor.id)) throw new AppError(`Bulk definition "${definitionId}" contains duplicate actor "${actor.id}".`, "BULK_AUTHORIZATION_DUPLICATE_ACTOR");
    ids.add(actor.id);
  }
  const a = actors.find((actor) => actor.authSlot === "account_a");
  const b = actors.find((actor) => actor.authSlot === "account_b");
  if (a?.principalIdHash && b?.principalIdHash && a.principalIdHash === b.principalIdHash) throw new AppError(`Bulk definition "${definitionId}" account actors declare the same principal.`, "BULK_AUTHORIZATION_SAME_PRINCIPAL");
  if (authProfileSet && authFingerprint(authProfileSet.accountA) === authFingerprint(authProfileSet.accountB)) throw new AppError(`Bulk definition "${definitionId}" rejected reused authentication material.`, "BULK_AUTHORIZATION_REUSED_AUTH_MATERIAL");
}

function validateSafety(testCase: BulkAuthorizationInput["definitions"][number]["cases"][number]): void {
  if (forbiddenOperationWords.test(testCase.safetyContract.operationType)) throw new AppError(`Bulk case "${testCase.id}" operation is not supported.`, "BULK_AUTHORIZATION_OPERATION_UNSAFE");
  if (testCase.method !== "GET" && testCase.method !== "POST") throw new AppError(`Bulk case "${testCase.id}" method is unsupported.`, "BULK_AUTHORIZATION_METHOD_UNSAFE");
  if (testCase.requestStyle === "JSON_POST" && testCase.method !== "POST") throw new AppError(`Bulk case "${testCase.id}" JSON_POST must use POST.`, "BULK_AUTHORIZATION_METHOD_UNSAFE");
  if (testCase.method === "POST" && !testCase.safetyContract.requiredRequestMarkerPath) throw new AppError(`Bulk POST case "${testCase.id}" requires a fixed request safety marker.`, "BULK_AUTHORIZATION_REQUEST_MARKER_REQUIRED");
  validateHeaderSafety(testCase.headers, `case "${testCase.id}"`);
  for (const path of [testCase.safetyContract.requiredRequestMarkerPath, testCase.safetyContract.requiredResponseMarkerPath, ...testCase.safetyContract.disallowedResponsePaths].filter((item): item is string => Boolean(item))) parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 50, code: "BULK_AUTHORIZATION_FIELD_PATH_INVALID" });
}

function validatePostSafety(testCase: BulkAuthorizationInput["definitions"][number]["cases"][number]): void {
  const mode = testCase.postSafetyMode ?? (testCase.method === "POST" ? "OPERATOR_ATTESTED_DRY_RUN" : "GET_ONLY");
  if (mode === "GET_ONLY" && testCase.method === "POST") throw new AppError(`Bulk case "${testCase.id}" uses POST but postSafetyMode is GET_ONLY.`, "BULK_AUTHORIZATION_POST_SAFETY_MODE_INVALID");
  if (mode !== "GET_ONLY" && testCase.method !== "POST") throw new AppError(`Bulk case "${testCase.id}" declares POST safety mode for a non-POST request.`, "BULK_AUTHORIZATION_POST_SAFETY_MODE_INVALID");
  if (mode === "POSTCONDITION_VERIFIED_DRY_RUN" && (testCase.postconditionChecks ?? []).length === 0) throw new AppError(`Bulk POST case "${testCase.id}" requires explicit postcondition checks for verified dry-run mode.`, "BULK_AUTHORIZATION_POSTCONDITION_REQUIRED");
}

function validateResponseContract(testCase: BulkAuthorizationInput["definitions"][number]["cases"][number]): void {
  for (const path of [testCase.responseContract.resultArrayPath, testCase.responseContract.resultObjectIdPath, testCase.responseContract.perObjectDecisionPath, testCase.responseContract.rejectedArrayPath, testCase.responseContract.rejectedObjectIdPath, testCase.responseContract.overallDecisionPath, testCase.responseContract.previewCountPath, ...testCase.responseContract.metadataPaths].filter((item): item is string => Boolean(item))) parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 50, code: "BULK_AUTHORIZATION_FIELD_PATH_INVALID" });
}

function postconditionChecks(
  testCase: BulkAuthorizationInput["definitions"][number]["cases"][number],
  actorById: ReadonlyMap<string, BulkActorPlan>,
  objects: readonly BulkObjectPlan[],
  matcher: ScopeMatcher
): readonly BulkPostconditionCheckPlan[] {
  const objectById = new Map(objects.map((object) => [object.objectId, object]));
  return (testCase.postconditionChecks ?? []).map((input) => {
    const actor = actorById.get(input.actorId);
    if (!actor) throw new AppError(`Bulk postcondition "${input.id}" references unknown actor "${input.actorId}".`, "BULK_AUTHORIZATION_UNKNOWN_ACTOR");
    const object = objectById.get(input.objectId);
    if (!object) throw new AppError(`Bulk postcondition "${input.id}" references object not supplied in case "${testCase.id}".`, "BULK_AUTHORIZATION_POSTCONDITION_OBJECT_INVALID");
    if (generatorPattern.test(input.objectId) || secretLikePattern.test(input.objectId) || /[\r\n\0]/.test(input.objectId)) throw new AppError(`Bulk postcondition "${input.id}" has an unsafe objectId.`, "BULK_AUTHORIZATION_OBJECT_ID_UNSAFE");
    validateExactObjectTemplate(input.id, input.url, input.objectId);
    validateHeaderSafety(input.headers, `postcondition "${input.id}"`);
    for (const path of [input.objectIdentityField, input.objectStateField, ...input.fields.map((field) => field.path)].filter((item): item is string => Boolean(item))) parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 50, code: "BULK_AUTHORIZATION_FIELD_PATH_INVALID" });
    const resolvedUrl = input.url.replace("{{OBJECT_ID}}", encodeURIComponent(input.objectId));
    const decision = matcher.decide(resolvedUrl, "GET");
    if (!decision.allowed || !decision.normalizedUrl) throw new AppError(`Bulk postcondition "${input.id}" is out of scope: ${decision.reason}.`, "BULK_AUTHORIZATION_OUT_OF_SCOPE");
    return {
      id: input.id,
      actorId: input.actorId,
      ...(actor.authSlot ? { authSlot: actor.authSlot } : {}),
      objectId: input.objectId,
      objectIdHash: object.objectIdHash,
      method: "GET",
      url: decision.normalizedUrl,
      headers: input.headers,
      objectIdentityField: input.objectIdentityField,
      ...(input.objectStateField ? { objectStateField: input.objectStateField } : {}),
      fields: input.fields.map((field) => ({
        path: field.path,
        ...(field.expectedValue !== undefined ? { expectedValue: field.expectedValue, expectedValueHash: hashValue(String(field.expectedValue), "postcondition-value") } : {})
      })),
      requireVerifiedIdentity: input.requireVerifiedIdentity && Boolean(actor.authSlot),
      ...(input.expectedTenantId ? { expectedTenantHash: hashIdentityValue(input.expectedTenantId) } : {}),
      ...(input.expectedRole ? { expectedRoleHash: hashIdentityValue(input.expectedRole) } : {}),
      maxResponseBytes: input.maxResponseBytes,
      maxJsonDepth: input.maxJsonDepth
    };
  });
}

function resolveRequest(testCase: BulkAuthorizationInput["definitions"][number]["cases"][number], objects: readonly BulkObjectPlan[]): { url: string; body?: string } {
  if (generatorPattern.test(testCase.url) || secretLikePattern.test(testCase.url)) throw new AppError(`Bulk case "${testCase.id}" URL is not an exact safe template.`, "BULK_AUTHORIZATION_TEMPLATE_UNSAFE");
  const ids = objects.map((object) => object.objectId);
  if (testCase.requestStyle === "GET_REPEATED_QUERY") {
    requireOnlyPlaceholder(testCase.id, testCase.url, repeatedPlaceholder, "URL");
    return { url: testCase.url.replace(repeatedPlaceholder, ids.map((id) => encodeURIComponent(id)).join("&id=")) };
  }
  if (testCase.requestStyle === "GET_COMMA_QUERY") {
    requireOnlyPlaceholder(testCase.id, testCase.url, commaPlaceholder, "URL");
    return { url: testCase.url.replace(commaPlaceholder, ids.map((id) => encodeURIComponent(id)).join(",")) };
  }
  if (testCase.bodyTemplate === undefined) throw new AppError(`Bulk case "${testCase.id}" JSON_POST requires a fixed body template.`, "BULK_AUTHORIZATION_BODY_TEMPLATE_REQUIRED");
  const bodyTemplateText = JSON.stringify(testCase.bodyTemplate);
  if (secretLikePattern.test(bodyTemplateText)) throw new AppError(`Bulk case "${testCase.id}" body template contains auth-like material.`, "BULK_AUTHORIZATION_TEMPLATE_UNSAFE");
  requireOnlyPlaceholder(testCase.id, bodyTemplateText, objectArrayPlaceholder, "JSON body");
  const bodyValue = replaceBodyPlaceholder(testCase.bodyTemplate, ids);
  const markerPath = testCase.safetyContract.requiredRequestMarkerPath;
  if (markerPath && testCase.safetyContract.requiredRequestMarkerValue !== undefined && valueAtPath(bodyValue, markerPath) !== testCase.safetyContract.requiredRequestMarkerValue) throw new AppError(`Bulk case "${testCase.id}" fixed request safety marker is missing.`, "BULK_AUTHORIZATION_REQUEST_MARKER_REQUIRED");
  return { url: testCase.url, body: stableStringify(bodyValue) };
}

function requireOnlyPlaceholder(caseId: string, value: string, expected: string, location: string): void {
  const matches: string[] = value.match(/\{\{[A-Z0-9_]+\}\}/g) ?? [];
  if (!matches.includes(expected)) throw new AppError(`Bulk case "${caseId}" ${location} must contain ${expected}.`, "BULK_AUTHORIZATION_OBJECT_PLACEHOLDER_REQUIRED");
  const unknown = matches.find((match) => match !== expected);
  if (unknown) throw new AppError(`Bulk case "${caseId}" ${location} contains unsupported placeholder ${unknown}.`, "BULK_AUTHORIZATION_TEMPLATE_UNSAFE");
}

function validateExactObjectTemplate(id: string, value: string, objectId: string): void {
  if (generatorPattern.test(value) || secretLikePattern.test(value)) throw new AppError(`Bulk template "${id}" is not an exact safe template.`, "BULK_AUTHORIZATION_TEMPLATE_UNSAFE");
  requireOnlyPlaceholder(id, value, "{{OBJECT_ID}}", "URL");
  if (value.match(/\{\{OBJECT_ID\}\}/g)?.length !== 1) throw new AppError(`Bulk template "${id}" must contain exactly one object placeholder.`, "BULK_AUTHORIZATION_OBJECT_PLACEHOLDER_REQUIRED");
  if (generatorPattern.test(objectId) || secretLikePattern.test(objectId) || /[\r\n\0]/.test(objectId)) throw new AppError(`Bulk template "${id}" references an unsafe objectId.`, "BULK_AUTHORIZATION_OBJECT_ID_UNSAFE");
}

function validateHeaderSafety(headers: Record<string, string>, label: string): void {
  for (const [name, value] of Object.entries(headers)) {
    if (/^(authorization|cookie|x-csrf-token|x-xsrf-token|x-api-key)$/i.test(name) || secretLikePattern.test(value)) throw new AppError(`Bulk ${label} includes auth-like header material.`, "BULK_AUTHORIZATION_TEMPLATE_UNSAFE");
    if (/[\r\n\0]/.test(name) || /[\r\n\0]/.test(value)) throw new AppError(`Bulk ${label} includes an unsafe header.`, "BULK_AUTHORIZATION_TEMPLATE_UNSAFE");
  }
}

function replaceBodyPlaceholder(value: unknown, ids: readonly string[]): unknown {
  if (value === objectArrayPlaceholder) return [...ids];
  if (Array.isArray(value)) return value.map((item) => replaceBodyPlaceholder(item, ids));
  if (typeof value === "object" && value !== null) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replaceBodyPlaceholder(item, ids)]));
  return value;
}

function valueAtPath(source: unknown, path: string): unknown {
  return path.split(".").reduce((value: unknown, part) => (typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>)[part] : undefined), source);
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (typeof value === "object" && value !== null) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify((value as Record<string, unknown>)[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

function authFingerprint(profile: AuthProfileSet["accountA"]): string {
  return hashValue(JSON.stringify({ headers: profile.headers, cookies: profile.cookies }), "auth");
}

function hashValue(value: string, purpose: string): string {
  return createHash("sha256").update(`routecairn-bulk-${purpose}:`).update(value).digest("hex").slice(0, 16);
}

function hashIdentityValue(value: string): string {
  return createHash("sha256").update("routecairn-identity-v1").update("\0").update(value).digest("hex").slice(0, 16);
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null) return value;
  Object.freeze(value);
  for (const item of Object.values(value)) deepFreeze(item);
  return value;
}
