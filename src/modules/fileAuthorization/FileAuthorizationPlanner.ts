import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { AppError } from "../../core/errors/AppError.js";
import type { FileAuthorizationActorPlan, FileAuthorizationCasePlan, FileAuthorizationTestingPlan, FileReferencePlan } from "../../core/planning/ScanPlan.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { parseSafeFieldPath } from "../fieldExposureTesting/SafeFieldPath.js";

const maxFileBytes = 256 * 1024;
const maxDefinitions = 5;
const maxCases = 40;
const maxFiles = 40;
const filePlaceholder = "{{FILE_ID}}";
const fileKeyPlaceholder = "{{FILE_KEY}}";
const tenantPlaceholder = "{{TENANT_ID}}";
const generatorPattern = /(?:\.\.|\\|\*|\||=>|function\s*\(|regex|regexp|range|increment|decrement|random|uuid-v|eval|for\s*\(|while\s*\(|<%|%\>|\$\(.*\))/i;
const secretLikePattern = /(?:authorization|cookie|session|csrf|xsrf|token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|bearer\s+[a-z0-9._~+/=-]+)/i;

const relationshipSchema = z.enum(["OWNER", "NON_OWNER", "SAME_TENANT_MEMBER", "SAME_TENANT_ADMIN", "CROSS_TENANT_MEMBER", "CROSS_TENANT_ADMIN", "PLATFORM_ADMIN", "MODERATOR", "SHARED_PRINCIPAL", "PUBLIC", "CUSTOM_DECLARED_RELATIONSHIP"]);
const categorySchema = z.enum(["FILE_METADATA", "INLINE_VIEW", "DIRECT_DOWNLOAD", "FILE_PREVIEW", "THUMBNAIL", "ATTACHMENT", "EXPORT_ARTIFACT", "EVIDENCE_FILE", "PRIVATE_DOCUMENT", "SIGNED_URL_ISSUANCE", "SIGNED_URL_DOWNLOAD", "DOWNLOAD_MANIFEST", "OBSERVE_ONLY"]);
const expectationSchema = z.enum(["MUST_ALLOW_METADATA", "MUST_DENY_METADATA", "MUST_ALLOW_CONTENT", "MUST_DENY_CONTENT", "MUST_REQUIRE_AUTHENTICATION", "MUST_RETURN_NOT_FOUND", "MUST_ALLOW_PREVIEW_ONLY", "MUST_NOT_RECEIVE_SIGNED_URL", "MUST_MATCH_REFERENCE_CASE", "OBSERVE_ONLY"]);
const identityStrategySchema = z.enum(["METADATA_FIELD_MATCH", "OPERATOR_SUPPLIED_FINGERPRINT", "SIGNED_URL_FIELD_MATCH", "OBSERVE_ONLY"]);
const proofModeSchema = z.enum(["HEADERS_ONLY", "METADATA_ONLY", "BOUNDED_PREFIX", "FULL_STREAM_FINGERPRINT", "SIGNED_URL_ONLY"]);

const actorSchema = z.object({
  id: z.string().min(1).max(80),
  relationship: relationshipSchema,
  authProfile: z.enum(["account_a", "account_b"]).optional(),
  safeAlias: z.string().min(1).max(80).optional(),
  principalId: z.string().min(1).max(256).optional(),
  tenantId: z.string().min(1).max(256).optional(),
  role: z.string().min(1).max(120).optional(),
  accountState: z.string().min(1).max(120).optional()
}).strict();

const fileSchema = z.object({
  id: z.string().min(1).max(120),
  fileRef: z.string().min(1).max(512),
  safeAlias: z.string().min(1).max(120).optional(),
  fileType: z.string().min(1).max(80).optional(),
  ownerActorId: z.string().min(1).max(80).optional(),
  tenantId: z.string().min(1).max(256).optional(),
  state: z.string().min(1).max(120).optional(),
  expectedPublic: z.boolean().default(false)
}).strict();

const caseSchema = z.object({
  id: z.string().min(1).max(120),
  label: z.string().min(1).max(160),
  category: categorySchema,
  actorId: z.string().min(1).max(80),
  fileRefId: z.string().min(1).max(120),
  method: z.enum(["GET", "HEAD"]),
  url: z.string().min(1).max(2048),
  placeholder: z.enum(["FILE_ID", "FILE_KEY"]).default("FILE_ID"),
  headers: z.record(z.string().max(512)).default({}),
  expectedDecision: expectationSchema,
  requireVerifiedIdentity: z.boolean().default(true),
  expectedTenantId: z.string().min(1).max(256).optional(),
  expectedRole: z.string().min(1).max(120).optional(),
  expectedAccountState: z.string().min(1).max(120).optional(),
  expectedFileState: z.string().min(1).max(120).optional(),
  identityStrategy: identityStrategySchema,
  identityField: z.string().min(1).max(160).optional(),
  stateField: z.string().min(1).max(160).optional(),
  signedUrlField: z.string().min(1).max(160).optional(),
  expectedFingerprint: z.string().regex(/^[a-f0-9]{16,128}$/i).optional(),
  contentProofMode: proofModeSchema,
  rangeStart: z.number().int().min(0).default(0),
  rangeLength: z.number().int().positive().max(65536).optional(),
  maxMetadataBytes: z.number().int().positive().max(256 * 1024).default(65536),
  maxProbeBytes: z.number().int().positive().max(65536).default(4096),
  maxFullStreamBytes: z.number().int().positive().max(1024 * 1024).default(262144),
  allowedRedirectOrigins: z.array(z.string().min(1).max(256)).max(8).default([]),
  followSignedUrl: z.boolean().default(false),
  allowedSignedUrlOrigins: z.array(z.string().min(1).max(256)).max(8).default([])
}).strict();

const definitionSchema = z.object({
  id: z.string().min(1).max(120),
  label: z.string().min(1).max(160),
  actors: z.array(actorSchema).min(1).max(3),
  files: z.array(fileSchema).min(1).max(maxFiles),
  cases: z.array(caseSchema).min(1).max(maxCases)
}).strict();

export const fileAuthorizationInputSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  maxDefinitions: z.number().int().positive().max(maxDefinitions).default(3),
  maxCasesPerDefinition: z.number().int().positive().max(maxCases).default(10),
  maxFilesPerDefinition: z.number().int().positive().max(maxFiles).default(20),
  maxRequests: z.number().int().positive().max(120).default(40),
  maxRetainedObservations: z.number().int().positive().max(120).default(60),
  definitions: z.array(definitionSchema).min(1).max(maxDefinitions)
}).strict();

export type FileAuthorizationInput = z.infer<typeof fileAuthorizationInputSchema>;

export async function loadFileAuthorizationInput(filePath: string): Promise<FileAuthorizationInput> {
  const raw = await readFile(filePath);
  if (raw.byteLength > maxFileBytes) throw new AppError(`File authorization input exceeds maximum size ${maxFileBytes} bytes.`, "FILE_AUTHORIZATION_FILE_TOO_LARGE");
  let json: unknown;
  try {
    json = JSON.parse(raw.toString("utf8").replace(/^\uFEFF/, ""));
  } catch {
    throw new AppError("File authorization input is not valid JSON.", "FILE_AUTHORIZATION_JSON_INVALID");
  }
  const parsed = fileAuthorizationInputSchema.safeParse(json);
  if (!parsed.success) throw new AppError(parsed.error.message, "FILE_AUTHORIZATION_INPUT_INVALID");
  return parsed.data;
}

export function planFileAuthorizationTesting(input: FileAuthorizationInput, options: { target: string; scope: RouteCairnScope; authProfileSet?: AuthProfileSet }): FileAuthorizationTestingPlan {
  const matcher = new ScopeMatcher(options.target, options.scope);
  const definitions = input.definitions.map((definition) => {
    if (definition.cases.length > input.maxCasesPerDefinition) throw new AppError(`File definition "${definition.id}" exceeds maxCasesPerDefinition.`, "FILE_AUTHORIZATION_TOO_MANY_CASES");
    if (definition.files.length > input.maxFilesPerDefinition) throw new AppError(`File definition "${definition.id}" exceeds maxFilesPerDefinition.`, "FILE_AUTHORIZATION_TOO_MANY_FILES");
    const actors = definition.actors.map((actor) => actorPlan(actor, options.authProfileSet));
    validateActors(definition.id, actors, options.authProfileSet);
    const actorById = new Map(actors.map((actor) => [actor.id, actor]));
    const files = definition.files.map(filePlan);
    validateFiles(definition.id, files, actorById);
    const fileById = new Map(files.map((file) => [file.id, file]));
    const caseIds = new Set<string>();
    const cases = definition.cases.map((testCase) => {
      if (caseIds.has(testCase.id)) throw new AppError(`File definition "${definition.id}" contains duplicate case "${testCase.id}".`, "FILE_AUTHORIZATION_DUPLICATE_CASE");
      caseIds.add(testCase.id);
      const actor = actorById.get(testCase.actorId);
      if (!actor) throw new AppError(`File case "${testCase.id}" references unknown actor "${testCase.actorId}".`, "FILE_AUTHORIZATION_UNKNOWN_ACTOR");
      const file = fileById.get(testCase.fileRefId);
      if (!file) throw new AppError(`File case "${testCase.id}" references unknown file "${testCase.fileRefId}".`, "FILE_AUTHORIZATION_UNKNOWN_FILE");
      validateCase(testCase);
      const url = resolveUrl(testCase, file);
      const decision = matcher.decide(url, testCase.method);
      if (!decision.allowed || !decision.normalizedUrl) throw new AppError(`File case "${testCase.id}" is out of scope: ${decision.reason}.`, "FILE_AUTHORIZATION_OUT_OF_SCOPE");
      const rangeHeader = rangeHeaderFor(testCase);
      return deepFreeze({
        id: testCase.id,
        definitionId: definition.id,
        label: testCase.label,
        category: testCase.category,
        actorId: actor.id,
        actorRelationship: actor.relationship,
        ...(actor.authSlot ? { authSlot: actor.authSlot } : {}),
        method: testCase.method,
        url: decision.normalizedUrl,
        headers: { ...testCase.headers, ...(rangeHeader ? { Range: rangeHeader } : {}) },
        fileRefId: file.id,
        fileRef: file.fileRef,
        fileRefHash: file.fileRefHash,
        fileAlias: file.redactedAlias,
        expectedDecision: testCase.expectedDecision,
        requireVerifiedIdentity: testCase.requireVerifiedIdentity && Boolean(actor.authSlot),
        ...(testCase.expectedTenantId ? { expectedTenantHash: hashIdentityValue(testCase.expectedTenantId) } : {}),
        ...(testCase.expectedRole ? { expectedRoleHash: hashIdentityValue(testCase.expectedRole) } : {}),
        ...(testCase.expectedAccountState ? { expectedAccountStateHash: hashIdentityValue(testCase.expectedAccountState) } : {}),
        ...(testCase.expectedFileState ? { expectedFileState: testCase.expectedFileState, expectedFileStateHash: hashValue(testCase.expectedFileState, "state") } : {}),
        identityStrategy: testCase.identityStrategy,
        ...(testCase.identityField ? { identityField: testCase.identityField } : {}),
        ...(testCase.stateField ? { stateField: testCase.stateField } : {}),
        ...(testCase.signedUrlField ? { signedUrlField: testCase.signedUrlField } : {}),
        ...(testCase.expectedFingerprint ? { expectedFingerprint: testCase.expectedFingerprint.toLowerCase() } : {}),
        contentProofMode: testCase.contentProofMode,
        ...(rangeHeader ? { rangeHeader } : {}),
        maxMetadataBytes: testCase.maxMetadataBytes,
        maxProbeBytes: testCase.maxProbeBytes,
        maxFullStreamBytes: testCase.maxFullStreamBytes,
        allowedRedirectOrigins: (testCase.allowedRedirectOrigins ?? []).map(normalizeOrigin),
        followSignedUrl: testCase.followSignedUrl,
        allowedSignedUrlOrigins: (testCase.allowedSignedUrlOrigins ?? []).map(normalizeOrigin)
      } satisfies FileAuthorizationCasePlan);
    });
    return deepFreeze({ id: definition.id, label: definition.label, actors, files, cases });
  });
  const requestMatrix = definitions.flatMap((definition) => [...definition.cases]);
  if (requestMatrix.length > input.maxRequests) throw new AppError(`File authorization resolves ${requestMatrix.length} cases, exceeding maxRequests.`, "FILE_AUTHORIZATION_TOO_MANY_REQUESTS");
  return deepFreeze({
    schemaVersion: 1,
    enabled: true,
    definitions,
    requestMatrix,
    maxDefinitions: input.maxDefinitions,
    maxCasesPerDefinition: input.maxCasesPerDefinition,
    maxFilesPerDefinition: input.maxFilesPerDefinition,
    maxRequests: input.maxRequests,
    maxRetainedObservations: input.maxRetainedObservations,
    notes: [
      "File authorization executes only resolved GET or HEAD cases for exact supplied file references.",
      "File content proof is bounded and fingerprint-only; raw bytes are not persisted.",
      "Runtime responses do not add files, endpoints, ranges, signed URLs, or follow-up cases."
    ]
  });
}

function actorPlan(actor: FileAuthorizationInput["definitions"][number]["actors"][number], authProfileSet: AuthProfileSet | undefined): FileAuthorizationActorPlan {
  if (actor.relationship === "PUBLIC") {
    if (actor.authProfile) throw new AppError(`Public file actor "${actor.id}" must not reference an auth profile.`, "FILE_AUTHORIZATION_PUBLIC_AUTH_INVALID");
    return { id: actor.id, relationship: "PUBLIC", redactedLabel: actor.safeAlias ?? "Public" };
  }
  if (!authProfileSet) throw new AppError("File authorization testing with authenticated actors requires --auth-a and --auth-b.", "FILE_AUTHORIZATION_AUTH_PAIR_REQUIRED");
  if (!actor.authProfile) throw new AppError(`Authenticated file actor "${actor.id}" must reference account_a or account_b.`, "FILE_AUTHORIZATION_AUTH_PROFILE_REQUIRED");
  const profile = actor.authProfile === "account_a" ? authProfileSet.accountA : authProfileSet.accountB;
  const principalId = actor.principalId ?? profile.principalId;
  if (!principalId) throw new AppError(`File actor "${actor.id}" requires declared principalId metadata.`, "FILE_AUTHORIZATION_PRINCIPAL_ID_REQUIRED");
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

function filePlan(input: FileAuthorizationInput["definitions"][number]["files"][number]): FileReferencePlan {
  if (typeof input.fileRef !== "string" || generatorPattern.test(input.fileRef) || secretLikePattern.test(input.fileRef) || /[\r\n\0]/.test(input.fileRef) || /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(input.fileRef)) throw new AppError(`File reference "${input.id}" is unsafe.`, "FILE_AUTHORIZATION_FILE_REF_UNSAFE");
  const fileRefHash = hashValue(input.fileRef, "file");
  return {
    id: input.id,
    fileRef: input.fileRef,
    fileRefHash,
    redactedAlias: input.safeAlias ?? `<file:${fileRefHash}>`,
    ...(input.fileType ? { fileType: input.fileType } : {}),
    ...(input.ownerActorId ? { ownerActorId: input.ownerActorId } : {}),
    ...(input.tenantId ? { tenantIdHash: hashIdentityValue(input.tenantId) } : {}),
    ...(input.state ? { state: input.state, stateHash: hashValue(input.state, "state") } : {}),
    expectedPublic: input.expectedPublic
  };
}

function validateActors(definitionId: string, actors: readonly FileAuthorizationActorPlan[], authProfileSet: AuthProfileSet | undefined): void {
  const ids = new Set<string>();
  for (const actor of actors) {
    if (ids.has(actor.id)) throw new AppError(`File definition "${definitionId}" contains duplicate actor "${actor.id}".`, "FILE_AUTHORIZATION_DUPLICATE_ACTOR");
    ids.add(actor.id);
  }
  const a = actors.find((actor) => actor.authSlot === "account_a");
  const b = actors.find((actor) => actor.authSlot === "account_b");
  if (a?.principalIdHash && b?.principalIdHash && a.principalIdHash === b.principalIdHash) throw new AppError(`File definition "${definitionId}" account actors declare the same principal.`, "FILE_AUTHORIZATION_SAME_PRINCIPAL");
  if (authProfileSet && authFingerprint(authProfileSet.accountA) === authFingerprint(authProfileSet.accountB)) throw new AppError(`File definition "${definitionId}" rejected reused authentication material.`, "FILE_AUTHORIZATION_REUSED_AUTH_MATERIAL");
}

function validateFiles(definitionId: string, files: readonly FileReferencePlan[], actorById: ReadonlyMap<string, FileAuthorizationActorPlan>): void {
  const ids = new Set<string>();
  const refs = new Set<string>();
  for (const file of files) {
    if (ids.has(file.id)) throw new AppError(`File definition "${definitionId}" contains duplicate file "${file.id}".`, "FILE_AUTHORIZATION_DUPLICATE_FILE");
    if (refs.has(file.fileRef)) throw new AppError(`File definition "${definitionId}" contains duplicate file reference.`, "FILE_AUTHORIZATION_DUPLICATE_FILE");
    if (file.ownerActorId && !actorById.has(file.ownerActorId)) throw new AppError(`File "${file.id}" references unknown owner actor "${file.ownerActorId}".`, "FILE_AUTHORIZATION_UNKNOWN_ACTOR");
    ids.add(file.id);
    refs.add(file.fileRef);
  }
}

function validateCase(testCase: FileAuthorizationInput["definitions"][number]["cases"][number]): void {
  validateHeaderSafety(testCase.headers, testCase.id);
  if (testCase.method !== "GET" && testCase.method !== "HEAD") throw new AppError(`File case "${testCase.id}" uses unsupported method.`, "FILE_AUTHORIZATION_METHOD_UNSAFE");
  if (testCase.method === "HEAD" && ["MUST_ALLOW_CONTENT", "MUST_DENY_CONTENT"].includes(testCase.expectedDecision) && testCase.contentProofMode !== "HEADERS_ONLY") throw new AppError(`File HEAD case "${testCase.id}" cannot use content proof.`, "FILE_AUTHORIZATION_METHOD_UNSAFE");
  if (testCase.contentProofMode === "FULL_STREAM_FINGERPRINT" && testCase.maxFullStreamBytes > 1024 * 1024) throw new AppError(`File case "${testCase.id}" full stream cap is too large.`, "FILE_AUTHORIZATION_STREAM_LIMIT_INVALID");
  if (testCase.contentProofMode === "BOUNDED_PREFIX" && !testCase.rangeLength) throw new AppError(`File case "${testCase.id}" requires an explicit bounded range length.`, "FILE_AUTHORIZATION_RANGE_INVALID");
  if (testCase.contentProofMode === "SIGNED_URL_ONLY" && !testCase.signedUrlField) throw new AppError(`File case "${testCase.id}" requires signedUrlField for signed-URL proof.`, "FILE_AUTHORIZATION_IDENTITY_POLICY_INVALID");
  if (testCase.followSignedUrl && testCase.method !== "GET") throw new AppError(`File case "${testCase.id}" signed-URL follow requires a GET issuance case.`, "FILE_AUTHORIZATION_METHOD_UNSAFE");
  if (testCase.followSignedUrl && testCase.allowedSignedUrlOrigins.length === 0) throw new AppError(`File case "${testCase.id}" signed-URL follow requires at least one exact allowed origin.`, "FILE_AUTHORIZATION_ORIGIN_INVALID");
  if (testCase.followSignedUrl && testCase.identityStrategy !== "OPERATOR_SUPPLIED_FINGERPRINT") throw new AppError(`File case "${testCase.id}" signed-URL download proof requires an operator-supplied fingerprint.`, "FILE_AUTHORIZATION_IDENTITY_POLICY_INVALID");
  if (testCase.identityStrategy === "METADATA_FIELD_MATCH" && !testCase.identityField) throw new AppError(`File case "${testCase.id}" requires identityField.`, "FILE_AUTHORIZATION_IDENTITY_POLICY_INVALID");
  if (testCase.identityStrategy === "SIGNED_URL_FIELD_MATCH" && !testCase.signedUrlField) throw new AppError(`File case "${testCase.id}" requires signedUrlField.`, "FILE_AUTHORIZATION_IDENTITY_POLICY_INVALID");
  if (testCase.identityStrategy === "OPERATOR_SUPPLIED_FINGERPRINT" && !testCase.expectedFingerprint) throw new AppError(`File case "${testCase.id}" requires expectedFingerprint.`, "FILE_AUTHORIZATION_IDENTITY_POLICY_INVALID");
  for (const path of [testCase.identityField, testCase.stateField, testCase.signedUrlField].filter((item): item is string => Boolean(item))) parseSafeFieldPath(path, { maxDepth: 8, maxArrayIndex: 50, code: "FILE_AUTHORIZATION_FIELD_PATH_INVALID" });
  (testCase.allowedRedirectOrigins ?? []).forEach(normalizeOrigin);
  (testCase.allowedSignedUrlOrigins ?? []).forEach(normalizeOrigin);
}

function resolveUrl(testCase: FileAuthorizationInput["definitions"][number]["cases"][number], file: FileReferencePlan): string {
  if (generatorPattern.test(testCase.url) || secretLikePattern.test(testCase.url) || /file:|javascript:|data:/i.test(testCase.url)) throw new AppError(`File case "${testCase.id}" URL is unsafe.`, "FILE_AUTHORIZATION_TEMPLATE_UNSAFE");
  const expected = testCase.placeholder === "FILE_KEY" ? fileKeyPlaceholder : filePlaceholder;
  const matches = testCase.url.match(/\{\{[A-Z0-9_]+\}\}/g) ?? [];
  if (matches.filter((match) => match === expected).length !== 1) throw new AppError(`File case "${testCase.id}" must contain exactly one ${expected}.`, "FILE_AUTHORIZATION_PLACEHOLDER_INVALID");
  const unknown = matches.find((match) => match !== expected && match !== tenantPlaceholder);
  if (unknown) throw new AppError(`File case "${testCase.id}" contains unsupported placeholder ${unknown}.`, "FILE_AUTHORIZATION_PLACEHOLDER_INVALID");
  return testCase.url.replace(expected, encodeURIComponent(file.fileRef));
}

function rangeHeaderFor(testCase: FileAuthorizationInput["definitions"][number]["cases"][number]): string | undefined {
  if (testCase.contentProofMode !== "BOUNDED_PREFIX") return undefined;
  const start = testCase.rangeStart ?? 0;
  const end = start + (testCase.rangeLength ?? 1) - 1;
  return `bytes=${start}-${end}`;
}

function validateHeaderSafety(headers: Record<string, string>, label: string): void {
  for (const [name, value] of Object.entries(headers)) {
    if (/^(authorization|cookie|x-csrf-token|x-xsrf-token|x-api-key)$/i.test(name) || secretLikePattern.test(value)) throw new AppError(`File case "${label}" includes auth-like header material.`, "FILE_AUTHORIZATION_TEMPLATE_UNSAFE");
    if (/[\r\n\0]/.test(name) || /[\r\n\0]/.test(value)) throw new AppError(`File case "${label}" includes an unsafe header.`, "FILE_AUTHORIZATION_TEMPLATE_UNSAFE");
  }
}

function normalizeOrigin(value: string): string {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new Error("unsupported");
    return url.origin;
  } catch {
    throw new AppError(`File authorization origin "${value}" is invalid.`, "FILE_AUTHORIZATION_ORIGIN_INVALID");
  }
}

function authFingerprint(profile: AuthProfileSet["accountA"]): string {
  return hashValue(JSON.stringify({ headers: profile.headers, cookies: profile.cookies }), "auth");
}

function hashValue(value: string, purpose: string): string {
  return createHash("sha256").update(`routecairn-file-${purpose}:`).update(value).digest("hex").slice(0, 16);
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
