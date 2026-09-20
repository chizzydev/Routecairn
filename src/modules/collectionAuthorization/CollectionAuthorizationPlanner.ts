import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import type {
  CollectionActorPlan,
  CollectionAuthorizationCasePlan,
  CollectionAuthorizationDefinitionPlan,
  CollectionAuthorizationTestingPlan,
  KnownCollectionObjectPlan
} from "../../core/planning/ScanPlan.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { parseSafeFieldPath } from "../fieldExposureTesting/SafeFieldPath.js";

const maxFileBytes = 256 * 1024;
const maxCollections = 5;
const maxCasesPerCollection = 40;
const maxKnownObjects = 30;
const maxActors = 3;
const maxIdentifierLength = 256;
const maxEndpointLength = 2048;
const forbiddenEndpointWords =
  /(?:delete|remove|cancel|purchase|pay|transfer|withdraw|approve|reject|publish|submit|invite|reset|activate|deactivate|suspend|logout|consume-on-read|generate|create-export|start-export|archive)/i;
const generatorPattern = /(?:\.\.|\*|\||=>|function\s*\(|regex|regexp|range|increment|decrement|random|uuid-v|eval|for\s*\(|while\s*\(|\{\{|\}\}|<%|%\>|\$\(.*\))/i;
const secretLikePattern = /(?:authorization|cookie|session|csrf|xsrf|token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|bearer\s+[a-z0-9._~+/=-]+)/i;
const paginationKeyPattern = /^(?:page|p|cursor|next|nextPage|offset|continuation|continuationToken|after|before|start|skip)$/i;

const actorRelationshipSchema = z.enum([
  "OWNER",
  "NON_OWNER",
  "SAME_TENANT_MEMBER",
  "SAME_TENANT_ADMIN",
  "CROSS_TENANT_MEMBER",
  "CROSS_TENANT_ADMIN",
  "PLATFORM_ADMIN",
  "MODERATOR",
  "SHARED_PRINCIPAL",
  "ACTIVE_ACCOUNT",
  "SUSPENDED_ACCOUNT",
  "DEACTIVATED_ACCOUNT",
  "PUBLIC",
  "CUSTOM_DECLARED_RELATIONSHIP"
]);
const endpointCategorySchema = z.enum(["LIST", "SEARCH", "COUNT", "SUMMARY", "DASHBOARD", "RECENT", "ARCHIVE", "ADMIN_LIST", "TENANT_LIST", "PUBLIC_LIST", "CUSTOM_DECLARED"]);
const completenessSchema = z.enum(["COMPLETE_COLLECTION", "FIXED_RESULT_WINDOW", "SEARCH_RESULT_SET", "SUMMARY_ONLY", "UNKNOWN_COMPLETENESS"]);
const membershipExpectationSchema = z.enum([
  "MUST_CONTAIN",
  "MUST_NOT_CONTAIN",
  "MAY_CONTAIN",
  "MUST_MATCH_PUBLIC_MEMBERSHIP",
  "MUST_MATCH_REFERENCE_CASE",
  "MUST_NOT_EXCEED_REFERENCE_MEMBERSHIP",
  "OBSERVE_ONLY"
]);
const countExpectationSchema = z.enum(["MUST_EQUAL", "MUST_MATCH_REFERENCE", "MUST_NOT_EXCEED_REFERENCE", "MUST_BE_ZERO", "MAY_DIFFER", "OBSERVE_ONLY"]);
const summaryExpectationSchema = z.enum(["MUST_EQUAL", "MUST_MATCH_REFERENCE", "MUST_NOT_EXCEED_REFERENCE", "MUST_BE_ZERO", "MAY_DIFFER", "OBSERVE_ONLY"]);

const actorSchema = z
  .object({
    id: z.string().min(1).max(80),
    relationship: actorRelationshipSchema,
    authProfile: z.enum(["account_a", "account_b"]).optional(),
    safeAlias: z.string().min(1).max(80).optional(),
    principalId: z.string().min(1).max(maxIdentifierLength).optional(),
    tenantId: z.string().min(1).max(maxIdentifierLength).optional(),
    role: z.string().min(1).max(120).optional(),
    accountState: z.string().min(1).max(120).optional()
  })
  .strict();

const knownObjectSchema = z
  .object({
    id: z.string().min(1).max(120),
    objectId: z.string().min(1).max(maxIdentifierLength),
    objectType: z.string().min(1).max(80),
    ownerActorId: z.string().min(1).max(80).optional(),
    tenantId: z.string().min(1).max(maxIdentifierLength).optional(),
    state: z.string().min(1).max(120).optional(),
    safeAlias: z.string().min(1).max(80).optional(),
    expectedPublic: z.boolean().default(false),
    expectedShared: z.boolean().default(false),
    confirmedSafeToTest: z.literal(true)
  })
  .strict();

const countExpectationConfigSchema = z
  .object({
    path: z.string().min(1).max(160),
    expectation: countExpectationSchema,
    expectedCount: z.number().int().min(0).optional(),
    referenceCaseId: z.string().min(1).max(120).optional(),
    securitySensitive: z.boolean().default(false),
    volatile: z.boolean().default(true)
  })
  .strict();

const summaryExpectationConfigSchema = z
  .object({
    path: z.string().min(1).max(160),
    expectation: summaryExpectationSchema,
    expectedValue: z.union([z.string(), z.number(), z.boolean(), z.null()]).optional(),
    referenceCaseId: z.string().min(1).max(120).optional(),
    securitySensitive: z.boolean().default(false),
    volatile: z.boolean().default(true)
  })
  .strict();

const paginationSchema = z.discriminatedUnion("mode", [
  z.object({
    mode: z.literal("LINK_HEADER"),
    maxPages: z.number().int().min(2).max(10).default(3),
    allowedQueryParameters: z.array(z.string().regex(/^[A-Za-z0-9_.-]{1,80}$/)).max(12).default([])
  }).strict(),
  z.object({
    mode: z.literal("JSON_URL"),
    nextPath: z.string().min(1).max(160),
    maxPages: z.number().int().min(2).max(10).default(3),
    allowedQueryParameters: z.array(z.string().regex(/^[A-Za-z0-9_.-]{1,80}$/)).max(12).default([])
  }).strict(),
  z.object({
    mode: z.literal("JSON_CURSOR"),
    nextPath: z.string().min(1).max(160),
    cursorQueryParameter: z.string().regex(/^[A-Za-z0-9_.-]{1,80}$/),
    maxPages: z.number().int().min(2).max(10).default(3)
  }).strict()
]);

const caseSchema = z
  .object({
    id: z.string().min(1).max(120),
    actorId: z.string().min(1).max(80),
    knownObjectId: z.string().min(1).max(120).optional(),
    expectedMembership: membershipExpectationSchema.default("OBSERVE_ONLY"),
    expectedActorRelationship: actorRelationshipSchema.optional(),
    expectedTenantId: z.string().min(1).max(maxIdentifierLength).optional(),
    expectedRole: z.string().min(1).max(120).optional(),
    expectedAccountState: z.string().min(1).max(120).optional(),
    expectedObjectState: z.string().min(1).max(120).optional(),
    requireVerifiedIdentity: z.boolean().default(true),
    referenceCaseId: z.string().min(1).max(120).optional(),
    countExpectation: countExpectationConfigSchema.optional(),
    summaryExpectations: z.array(summaryExpectationConfigSchema).max(8).default([])
  })
  .strict();

const collectionSchema = z
  .object({
    id: z.string().min(1).max(120),
    label: z.string().min(1).max(160),
    category: endpointCategorySchema,
    method: z.literal("GET").default("GET"),
    url: z.string().min(1).max(maxEndpointLength),
    headers: z.record(z.string().max(512)).default({}),
    expectedContentType: z.string().min(1).max(120).default("application/json"),
    completeness: completenessSchema.default("FIXED_RESULT_WINDOW"),
    resultArrayPath: z.string().min(1).max(160).optional(),
    objectIdPath: z.string().min(1).max(160).optional(),
    objectTenantPath: z.string().min(1).max(160).optional(),
    objectOwnerPath: z.string().min(1).max(160).optional(),
    objectStatePath: z.string().min(1).max(160).optional(),
    objectTypePath: z.string().min(1).max(160).optional(),
    maxInspectedEntries: z.number().int().positive().max(200).default(50),
    maxResponseBytes: z.number().int().positive().max(512 * 1024).default(65536),
    maxJsonDepth: z.number().int().positive().max(24).default(10),
    pagination: paginationSchema.optional(),
    actors: z.array(actorSchema).min(1).max(maxActors),
    knownObjects: z.array(knownObjectSchema).max(maxKnownObjects).default([]),
    cases: z.array(caseSchema).min(1).max(maxCasesPerCollection)
  })
  .strict();

export const collectionAuthorizationInputSchema = z
  .object({
    schemaVersion: z.literal(1).default(1),
    maxCollections: z.number().int().positive().max(maxCollections).default(3),
    maxCasesPerCollection: z.number().int().positive().max(maxCasesPerCollection).default(20),
    maxKnownObjects: z.number().int().positive().max(maxKnownObjects).default(20),
    maxRequests: z.number().int().positive().max(100).default(40),
    maxRetainedObservations: z.number().int().positive().max(100).default(60),
    maxPreviewLength: z.number().int().positive().max(512).default(120),
    collections: z.array(collectionSchema).min(1).max(maxCollections)
  })
  .strict();

export type CollectionAuthorizationInput = z.infer<typeof collectionAuthorizationInputSchema>;

export async function loadCollectionAuthorizationInput(filePath: string): Promise<CollectionAuthorizationInput> {
  const rawBuffer = await readFile(filePath);
  if (rawBuffer.byteLength > maxFileBytes) {
    throw new AppError(`Collection authorization input exceeds maximum size ${maxFileBytes} bytes.`, "COLLECTION_AUTHORIZATION_FILE_TOO_LARGE");
  }
  let json: unknown;
  try {
    json = JSON.parse(rawBuffer.toString("utf8").replace(/^\uFEFF/, ""));
  } catch {
    throw new AppError("Collection authorization input is not valid JSON.", "COLLECTION_AUTHORIZATION_JSON_INVALID");
  }
  const parsed = collectionAuthorizationInputSchema.safeParse(json);
  if (!parsed.success) {
    throw new AppError(parsed.error.message, "COLLECTION_AUTHORIZATION_INPUT_INVALID");
  }
  return parsed.data;
}

export function planCollectionAuthorizationTesting(
  input: CollectionAuthorizationInput,
  options: { target: string; scope: RouteCairnScope; authProfileSet?: AuthProfileSet }
): CollectionAuthorizationTestingPlan {
  if (input.collections.length > input.maxCollections) {
    throw new AppError(`Collection authorization input contains ${input.collections.length} collections, exceeding maxCollections ${input.maxCollections}.`, "COLLECTION_AUTHORIZATION_TOO_MANY_COLLECTIONS");
  }
  const scopeMatcher = new ScopeMatcher(options.target, options.scope);
  const collections = input.collections.map((collection) => planCollection(collection, input, scopeMatcher, options.authProfileSet));
  const requestMatrix = collections.flatMap((collection) => [...collection.cases]);
  const plannedRequests = collections.reduce((total, collection) => total + collection.cases.length * (collection.pagination?.maxPages ?? 1), 0);
  if (plannedRequests > input.maxRequests) {
    throw new AppError(`Collection authorization input resolves up to ${plannedRequests} requests, exceeding maxRequests ${input.maxRequests}.`, "COLLECTION_AUTHORIZATION_TOO_MANY_REQUESTS");
  }
  return deepFreeze({
    schemaVersion: 1,
    enabled: true,
    collections,
    requestMatrix,
    maxCollections: input.maxCollections,
    maxCasesPerCollection: input.maxCasesPerCollection,
    maxKnownObjects: input.maxKnownObjects,
    maxRequests: input.maxRequests,
    maxRetainedObservations: input.maxRetainedObservations,
    maxPreviewLength: input.maxPreviewLength,
    notes: [
      "Collection authorization testing executes only operator-supplied GET collection cases.",
      "Pagination is followed only when an explicit bounded contract is present; destinations remain on the configured origin and path and query keys are allowlisted.",
      "Only exact supplied object IDs are compared; unmatched returned IDs are discarded from retained evidence."
    ]
  });
}

function planCollection(
  input: CollectionAuthorizationInput["collections"][number],
  limits: CollectionAuthorizationInput,
  scopeMatcher: ScopeMatcher,
  authProfileSet: AuthProfileSet | undefined
): CollectionAuthorizationDefinitionPlan {
  if (input.cases.length > limits.maxCasesPerCollection) throw new AppError(`Collection "${input.id}" exceeds maxCasesPerCollection ${limits.maxCasesPerCollection}.`, "COLLECTION_AUTHORIZATION_TOO_MANY_CASES");
  if (input.knownObjects.length > limits.maxKnownObjects) throw new AppError(`Collection "${input.id}" exceeds maxKnownObjects ${limits.maxKnownObjects}.`, "COLLECTION_AUTHORIZATION_TOO_MANY_OBJECTS");
  validateEndpoint(input);
  const decision = scopeMatcher.decide(input.url, "GET");
  if (!decision.allowed || !decision.normalizedUrl) throw new AppError(`Collection "${input.id}" is out of scope: ${decision.reason}.`, "COLLECTION_AUTHORIZATION_OUT_OF_SCOPE");
  const normalizedUrl = decision.normalizedUrl;
  if (input.completeness !== "SUMMARY_ONLY" && (!input.resultArrayPath || !input.objectIdPath)) {
    throw new AppError(`Collection "${input.id}" requires resultArrayPath and objectIdPath for membership cases.`, "COLLECTION_AUTHORIZATION_PATH_REQUIRED");
  }
  parseOptionalPath(input.resultArrayPath);
  parseOptionalPath(input.objectIdPath);
  parseOptionalPath(input.objectTenantPath);
  parseOptionalPath(input.objectOwnerPath);
  parseOptionalPath(input.objectStatePath);
  parseOptionalPath(input.objectTypePath);
  if (input.pagination?.mode === "JSON_URL" || input.pagination?.mode === "JSON_CURSOR") parseOptionalPath(input.pagination.nextPath);
  validatePagination(input);

  const actors = input.actors.map((actor) => actorPlan(actor, authProfileSet));
  validateActors(input.id, actors, authProfileSet);
  const actorById = new Map(actors.map((actor) => [actor.id, actor]));
  const knownObjects = input.knownObjects.map(objectPlan);
  validateKnownObjects(input.id, knownObjects);
  const objectById = new Map(knownObjects.map((knownObject) => [knownObject.id, knownObject]));
  validateCaseIds(input.id, input.cases);
  validateReferences(input.id, input.cases, objectById);

  const cases: CollectionAuthorizationCasePlan[] = input.cases.map((testCase) => {
    const actor = actorById.get(testCase.actorId);
    if (!actor) throw new AppError(`Collection case "${testCase.id}" references unknown actor "${testCase.actorId}".`, "COLLECTION_AUTHORIZATION_UNKNOWN_ACTOR");
    const knownObject = testCase.knownObjectId ? objectById.get(testCase.knownObjectId) : undefined;
    if (testCase.expectedMembership !== "OBSERVE_ONLY" && input.completeness !== "SUMMARY_ONLY" && !knownObject) {
      throw new AppError(`Collection case "${testCase.id}" requires a known object.`, "COLLECTION_AUTHORIZATION_KNOWN_OBJECT_REQUIRED");
    }
    if (testCase.expectedObjectState && !input.objectStatePath) throw new AppError(`Collection case "${testCase.id}" declares object state without objectStatePath.`, "COLLECTION_AUTHORIZATION_OBJECT_STATE_PATH_REQUIRED");
    if (testCase.countExpectation) parseSafeFieldPath(testCase.countExpectation.path, { maxDepth: 8, maxArrayIndex: 50, code: "COLLECTION_AUTHORIZATION_FIELD_PATH_INVALID" });
    for (const summary of testCase.summaryExpectations ?? []) parseSafeFieldPath(summary.path, { maxDepth: 8, maxArrayIndex: 50, code: "COLLECTION_AUTHORIZATION_FIELD_PATH_INVALID" });
    const expectedTenantHash = testCase.expectedTenantId ? hashValue(testCase.expectedTenantId, "tenant") : knownObject?.tenantIdHash;
    const expectedRoleHash = testCase.expectedRole ? hashValue(testCase.expectedRole, "role") : undefined;
    const expectedAccountStateHash = testCase.expectedAccountState ? hashValue(testCase.expectedAccountState, "account-state") : undefined;
    if (expectedTenantHash && actor.tenantIdHash && expectedTenantHash !== actor.tenantIdHash && !testCase.expectedActorRelationship?.includes("CROSS_TENANT") && !actor.relationship.includes("CROSS_TENANT")) {
      throw new AppError(`Collection case "${testCase.id}" tenant expectation conflicts with actor metadata.`, "COLLECTION_AUTHORIZATION_TENANT_MISMATCH");
    }
    const countExpectation = testCase.countExpectation
      ? {
          path: testCase.countExpectation.path,
          expectation: testCase.countExpectation.expectation,
          ...(testCase.countExpectation.expectedCount !== undefined ? { expectedCount: testCase.countExpectation.expectedCount } : {}),
          ...(testCase.countExpectation.referenceCaseId ? { referenceCaseId: testCase.countExpectation.referenceCaseId } : {}),
          securitySensitive: testCase.countExpectation.securitySensitive,
          volatile: testCase.countExpectation.volatile
        }
      : undefined;
    return {
      id: testCase.id,
      collectionId: input.id,
      actorId: actor.id,
      actorRelationship: testCase.expectedActorRelationship ?? actor.relationship,
      ...(actor.authSlot ? { authSlot: actor.authSlot } : {}),
      ...(knownObject ? { knownObjectId: knownObject.id, objectId: knownObject.objectId, objectIdHash: knownObject.objectIdHash, objectType: knownObject.objectType } : {}),
      expectedMembership: testCase.expectedMembership,
      requireVerifiedIdentity: testCase.requireVerifiedIdentity && Boolean(actor.authSlot),
      ...(testCase.referenceCaseId ? { referenceCaseId: testCase.referenceCaseId } : {}),
      ...(expectedTenantHash ? { expectedTenantHash } : {}),
      ...(expectedRoleHash ? { expectedRoleHash } : {}),
      ...(expectedAccountStateHash ? { expectedAccountStateHash } : {}),
      ...(testCase.expectedObjectState ? { expectedObjectState: testCase.expectedObjectState, expectedObjectStateHash: hashValue(testCase.expectedObjectState, "object-state") } : {}),
      ...(countExpectation ? { countExpectation } : {}),
      summaryExpectations: (testCase.summaryExpectations ?? []).map((summary) => ({
        path: summary.path,
        expectation: summary.expectation,
        ...(summary.expectedValue !== undefined ? { expectedValue: summary.expectedValue } : {}),
        ...(summary.referenceCaseId ? { referenceCaseId: summary.referenceCaseId } : {}),
        securitySensitive: summary.securitySensitive,
        volatile: summary.volatile
      })),
      url: normalizedUrl
    };
  });

  return {
    id: input.id,
    label: input.label,
    category: input.category,
    method: "GET",
    url: normalizedUrl,
    headers: input.headers,
    expectedContentType: input.expectedContentType,
    completeness: input.completeness,
    ...(input.resultArrayPath ? { resultArrayPath: input.resultArrayPath } : {}),
    ...(input.objectIdPath ? { objectIdPath: input.objectIdPath } : {}),
    ...(input.objectTenantPath ? { objectTenantPath: input.objectTenantPath } : {}),
    ...(input.objectOwnerPath ? { objectOwnerPath: input.objectOwnerPath } : {}),
    ...(input.objectStatePath ? { objectStatePath: input.objectStatePath } : {}),
    ...(input.objectTypePath ? { objectTypePath: input.objectTypePath } : {}),
    maxInspectedEntries: input.maxInspectedEntries,
    maxResponseBytes: input.maxResponseBytes,
    maxJsonDepth: input.maxJsonDepth,
    ...(input.pagination ? { pagination: input.pagination } : {}),
    actors,
    knownObjects,
    cases
  };
}

function actorPlan(actor: CollectionAuthorizationInput["collections"][number]["actors"][number], authProfileSet: AuthProfileSet | undefined): CollectionActorPlan {
  if (actor.relationship === "PUBLIC") {
    if (actor.authProfile) throw new AppError(`Public collection actor "${actor.id}" must not reference an auth profile.`, "COLLECTION_AUTHORIZATION_PUBLIC_AUTH_INVALID");
    return { id: actor.id, relationship: "PUBLIC", redactedLabel: actor.safeAlias ?? "Public" };
  }
  if (!authProfileSet) throw new AppError("Collection authorization testing with authenticated actors requires --auth-a and --auth-b.", "COLLECTION_AUTHORIZATION_AUTH_PAIR_REQUIRED");
  if (!actor.authProfile) throw new AppError(`Authenticated collection actor "${actor.id}" must reference account_a or account_b.`, "COLLECTION_AUTHORIZATION_AUTH_PROFILE_REQUIRED");
  const profile = actor.authProfile === "account_a" ? authProfileSet.accountA : authProfileSet.accountB;
  const principalId = actor.principalId ?? profile.principalId;
  if (!principalId) throw new AppError(`Collection actor "${actor.id}" requires declared principalId metadata.`, "COLLECTION_AUTHORIZATION_PRINCIPAL_ID_REQUIRED");
  if (actor.principalId && profile.principalId && actor.principalId !== profile.principalId) throw new AppError(`Collection actor "${actor.id}" principal metadata does not match its auth profile.`, "COLLECTION_AUTHORIZATION_PRINCIPAL_ID_MISMATCH");
  if (actor.tenantId && profile.tenantId && actor.tenantId !== profile.tenantId) throw new AppError(`Collection actor "${actor.id}" tenant metadata does not match its auth profile.`, "COLLECTION_AUTHORIZATION_TENANT_MISMATCH");
  if (actor.role && profile.role && actor.role !== profile.role) throw new AppError(`Collection actor "${actor.id}" role metadata does not match its auth profile.`, "COLLECTION_AUTHORIZATION_ROLE_MISMATCH");
  if (actor.accountState && profile.accountState && actor.accountState !== profile.accountState) throw new AppError(`Collection actor "${actor.id}" account-state metadata does not match its auth profile.`, "COLLECTION_AUTHORIZATION_ACCOUNT_STATE_MISMATCH");
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

function objectPlan(input: CollectionAuthorizationInput["collections"][number]["knownObjects"][number]): KnownCollectionObjectPlan {
  validateIdentifier(input.objectId, `${input.id}.objectId`);
  return {
    id: input.id,
    objectId: input.objectId,
    objectIdHash: hashValue(input.objectId, "object"),
    objectType: input.objectType,
    ...(input.ownerActorId ? { ownerActorId: input.ownerActorId } : {}),
    ...(input.tenantId ? { tenantIdHash: hashValue(input.tenantId, "tenant") } : {}),
    ...(input.state ? { state: input.state, stateHash: hashValue(input.state, "object-state") } : {}),
    redactedLabel: input.safeAlias ?? `<object:${hashValue(input.objectId, "object")}>`,
    expectedPublic: input.expectedPublic,
    expectedShared: input.expectedShared,
    confirmedSafeToTest: true
  };
}

function validateEndpoint(input: CollectionAuthorizationInput["collections"][number]): void {
  if (input.method !== "GET") throw new AppError(`Collection "${input.id}" must use GET.`, "COLLECTION_AUTHORIZATION_METHOD_UNSAFE");
  if (forbiddenEndpointWords.test(input.url)) throw new AppError(`Collection "${input.id}" URL appears to trigger a mutating workflow.`, "COLLECTION_AUTHORIZATION_ENDPOINT_UNSAFE");
  if (generatorPattern.test(input.url)) throw new AppError(`Collection "${input.id}" URL must be exact and cannot contain generators or templates.`, "COLLECTION_AUTHORIZATION_QUERY_GENERATOR_REJECTED");
  if (secretLikePattern.test(input.url)) throw new AppError(`Collection "${input.id}" URL contains sensitive query material.`, "COLLECTION_AUTHORIZATION_SENSITIVE_QUERY_REJECTED");
  let parsed: URL;
  try {
    parsed = new URL(input.url);
  } catch {
    throw new AppError(`Collection "${input.id}" URL is invalid.`, "COLLECTION_AUTHORIZATION_ENDPOINT_INVALID");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new AppError(`Collection "${input.id}" must use http or https.`, "COLLECTION_AUTHORIZATION_PROTOCOL_INVALID");
  for (const key of parsed.searchParams.keys()) if (paginationKeyPattern.test(key)) throw new AppError(`Collection "${input.id}" initial URL contains pagination parameter "${key}". Pagination must start from the configured first page.`, "COLLECTION_AUTHORIZATION_PAGINATION_REJECTED");
  for (const [name, value] of Object.entries(input.headers)) {
    if (secretLikePattern.test(name) || secretLikePattern.test(value)) throw new AppError(`Collection "${input.id}" contains sensitive or auth-like static headers.`, "COLLECTION_AUTHORIZATION_HEADER_UNSAFE");
  }
}

function validatePagination(input: CollectionAuthorizationInput["collections"][number]): void {
  const pagination = input.pagination;
  if (!pagination) return;
  const initial = new URL(input.url);
  const fixedKeys = new Set(initial.searchParams.keys());
  if (pagination.mode === "JSON_CURSOR") {
    if (secretLikePattern.test(pagination.cursorQueryParameter)) throw new AppError(`Collection "${input.id}" cursor parameter is secret-like.`, "COLLECTION_AUTHORIZATION_PAGINATION_INVALID");
    if (fixedKeys.has(pagination.cursorQueryParameter)) throw new AppError(`Collection "${input.id}" initial URL must not contain its generated cursor parameter.`, "COLLECTION_AUTHORIZATION_PAGINATION_INVALID");
    return;
  }
  for (const key of pagination.allowedQueryParameters) {
    if (secretLikePattern.test(key)) throw new AppError(`Collection "${input.id}" pagination allowlist contains a secret-like parameter.`, "COLLECTION_AUTHORIZATION_PAGINATION_INVALID");
  }
}

function validateActors(collectionId: string, actors: readonly CollectionActorPlan[], authProfileSet: AuthProfileSet | undefined): void {
  const ids = new Set<string>();
  for (const actor of actors) {
    if (ids.has(actor.id)) throw new AppError(`Collection "${collectionId}" contains duplicate actor "${actor.id}".`, "COLLECTION_AUTHORIZATION_DUPLICATE_ACTOR");
    ids.add(actor.id);
  }
  const accountA = actors.find((actor) => actor.authSlot === "account_a");
  const accountB = actors.find((actor) => actor.authSlot === "account_b");
  if (accountA?.principalIdHash && accountB?.principalIdHash && accountA.principalIdHash === accountB.principalIdHash) {
    throw new AppError(`Collection "${collectionId}" account_a and account_b actors declare the same principal.`, "COLLECTION_AUTHORIZATION_SAME_PRINCIPAL");
  }
  if (authProfileSet && authFingerprint(authProfileSet.accountA) === authFingerprint(authProfileSet.accountB)) {
    throw new AppError(`Collection "${collectionId}" rejected reused authentication material for Account A and Account B.`, "COLLECTION_AUTHORIZATION_REUSED_AUTH_MATERIAL");
  }
}

function validateKnownObjects(collectionId: string, knownObjects: readonly KnownCollectionObjectPlan[]): void {
  const ids = new Set<string>();
  const objectHashes = new Set<string>();
  for (const knownObject of knownObjects) {
    if (ids.has(knownObject.id)) throw new AppError(`Collection "${collectionId}" contains duplicate known object "${knownObject.id}".`, "COLLECTION_AUTHORIZATION_DUPLICATE_KNOWN_OBJECT");
    if (objectHashes.has(knownObject.objectIdHash)) throw new AppError(`Collection "${collectionId}" contains duplicate supplied object identifiers.`, "COLLECTION_AUTHORIZATION_DUPLICATE_KNOWN_OBJECT");
    ids.add(knownObject.id);
    objectHashes.add(knownObject.objectIdHash);
  }
}

function validateCaseIds(collectionId: string, cases: readonly CollectionAuthorizationInput["collections"][number]["cases"][number][]): void {
  const ids = new Set<string>();
  for (const testCase of cases) {
    if (ids.has(testCase.id)) throw new AppError(`Collection "${collectionId}" contains duplicate case "${testCase.id}".`, "COLLECTION_AUTHORIZATION_DUPLICATE_CASE");
    ids.add(testCase.id);
  }
}

function validateReferences(
  collectionId: string,
  cases: readonly CollectionAuthorizationInput["collections"][number]["cases"][number][],
  objectById: ReadonlyMap<string, KnownCollectionObjectPlan>
): void {
  const byId = new Map(cases.map((testCase) => [testCase.id, testCase]));
  for (const testCase of cases) {
    if (testCase.knownObjectId && !objectById.has(testCase.knownObjectId)) throw new AppError(`Collection case "${testCase.id}" references unknown known object "${testCase.knownObjectId}".`, "COLLECTION_AUTHORIZATION_UNKNOWN_OBJECT");
    const references = [testCase.referenceCaseId, testCase.countExpectation?.referenceCaseId, ...(testCase.summaryExpectations ?? []).map((summary) => summary.referenceCaseId)].filter((reference): reference is string => Boolean(reference));
    for (const reference of references) {
      if (!byId.has(reference)) throw new AppError(`Collection case "${testCase.id}" references missing case "${reference}".`, "COLLECTION_AUTHORIZATION_REFERENCE_MISSING");
      if (reference === testCase.id) throw new AppError(`Collection case "${testCase.id}" references itself.`, "COLLECTION_AUTHORIZATION_REFERENCE_SELF");
    }
  }
  for (const testCase of cases) {
    const seen = new Set<string>();
    let cursor: string | undefined = testCase.referenceCaseId;
    while (cursor) {
      if (seen.has(cursor)) throw new AppError(`Collection "${collectionId}" contains a reference cycle.`, "COLLECTION_AUTHORIZATION_REFERENCE_CYCLE");
      seen.add(cursor);
      cursor = byId.get(cursor)?.referenceCaseId;
    }
  }
}

function parseOptionalPath(path: string | undefined): void {
  if (path) parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 50, code: "COLLECTION_AUTHORIZATION_FIELD_PATH_INVALID" });
}

function validateIdentifier(value: string, label: string): void {
  if (/[\r\n\0]/.test(value) || generatorPattern.test(value) || secretLikePattern.test(value)) {
    throw new AppError(`Collection authorization identifier "${label}" is unsafe.`, "COLLECTION_AUTHORIZATION_IDENTIFIER_UNSAFE");
  }
}

function authFingerprint(profile: AuthProfileSet["accountA"]): string {
  return hashValue(JSON.stringify({ headers: profile.headers, cookies: profile.cookies }), "auth");
}

function hashValue(value: string, purpose: string): string {
  return createHash("sha256").update(`routecairn-collection-${purpose}:`).update(value).digest("hex").slice(0, 16);
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null) return value;
  Object.freeze(value);
  for (const item of Object.values(value)) deepFreeze(item);
  return value;
}
