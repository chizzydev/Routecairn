import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { RouteCairnScope } from "../../config/ConfigSchema.js";
import { AppError } from "../../core/errors/AppError.js";
import { securityContractFingerprint, securityContractValueHash } from "../../core/comparisons/SecurityContractFingerprint.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { authHeadersForProfile } from "../../core/auth/AuthProfile.js";
import { ScopeMatcher } from "../../core/scope/ScopeMatcher.js";
import { parseSafeFieldPath } from "../fieldExposureTesting/SafeFieldPath.js";
import type { SupabaseAuthorizationPlan, SupabaseOperation } from "./SupabaseAuthorizationTypes.js";

const maxInputBytes = 512 * 1024;
const maxCasesCeiling = 200;
const identifier = z.string().regex(/^[A-Za-z_][A-Za-z0-9_$.-]{0,127}$/);
const envName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/);
const operation = z.enum(["SELECT", "INSERT", "UPDATE", "DELETE", "INVOKE", "SIGNED_URL"]);
const actor = z.enum(["ANONYMOUS", "ACCOUNT_A", "ACCOUNT_B", "SERVICE_ROLE"]);
const secretHeader = /(?:authorization|cookie|token|secret|api.?key|csrf|tenant|organi[sz]ation|workspace)/i;
const secretQueryName = /(?:apikey|access.?token|refresh.?token|secret|password|signature|jwt)/i;

const assertionSchema = z.object({
  path: z.string().min(1).max(160),
  equals: z.union([z.string().max(512), z.number(), z.boolean(), z.null()])
}).strict();

const caseSchema = z.object({
  id: z.string().regex(/^[A-Za-z0-9._-]+$/).max(120),
  surface: z.enum(["TABLE", "STORAGE", "RPC", "RELATIONSHIP"]),
  resource: identifier,
  operation,
  actor,
  expectedDecision: z.enum(["ALLOW", "DENY", "OBSERVE_ONLY"]),
  boundary: z.enum(["NONE", "CROSS_USER", "CROSS_TENANT", "SERVICE_ROLE"]).default("NONE"),
  method: z.enum(["GET", "HEAD", "POST", "PATCH", "DELETE"]),
  url: z.string().min(1).max(4096),
  headers: z.record(z.string().max(1024)).default({}),
  responseShape: z.enum(["LIST", "SINGLE", "VOID"]).default("LIST"),
  identityAssertions: z.array(assertionSchema).max(12).default([]),
  forbiddenColumns: z.array(identifier).max(64).default([]),
  requireVerifiedIdentity: z.boolean().default(true),
  mutationContractCaseId: z.string().regex(/^[A-Za-z0-9._-]+$/).max(120).optional(),
  signedUrl: z.object({
    responseField: z.string().min(1).max(160),
    allowedOrigins: z.array(z.string().url()).min(1).max(8),
    expectedPathContains: z.string().min(1).max(512).optional(),
    followOnce: z.boolean().default(false)
  }).strict().optional()
}).strict();

const grantSchema = z.object({ role: identifier, operations: z.array(operation).max(6) }).strict();
const tableSchema = z.object({
  schema: identifier,
  name: identifier,
  exposed: z.boolean().default(true),
  rlsEnabled: z.boolean(),
  rlsForced: z.boolean().default(false),
  ownerColumn: identifier.optional(),
  tenantColumn: identifier.optional(),
  grants: z.array(grantSchema).max(24).default([]),
  columns: z.array(z.object({ name: identifier, sensitive: z.boolean().default(false), exposedTo: z.array(identifier).max(12).default([]) }).strict()).max(256).default([])
}).strict();
const functionSchema = z.object({
  schema: identifier,
  name: identifier,
  exposed: z.boolean().default(true),
  securityDefiner: z.boolean(),
  executableBy: z.array(identifier).max(24).default([]),
  searchPath: z.array(identifier).max(24).default([]),
  usesDynamicSql: z.boolean().default(false)
}).strict();
const bucketSchema = z.object({
  name: identifier,
  public: z.boolean(),
  ownershipEnforced: z.boolean(),
  allowedOperations: z.record(z.array(operation).max(6)).default({})
}).strict();
const relationshipSchema = z.object({ name: identifier, from: identifier, to: identifier, exposed: z.boolean().default(true) }).strict();

export const supabaseAuthorizationInputSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  projectUrl: z.string().url(),
  anonKeyEnv: envName.default("SUPABASE_ANON_KEY"),
  serviceRoleKeyEnv: envName.optional(),
  maxCases: z.number().int().positive().max(maxCasesCeiling).default(100),
  maxResponseBytes: z.number().int().positive().max(1024 * 1024).default(131072),
  maxSignedUrlBytes: z.number().int().positive().max(64 * 1024).default(8192),
  cases: z.array(caseSchema).min(1).max(maxCasesCeiling),
  catalog: z.object({
    exposedSchemas: z.array(identifier).max(32).default(["public"]),
    expectedExposedSchemas: z.array(identifier).max(32).default(["public"]),
    tables: z.array(tableSchema).max(256).default([]),
    functions: z.array(functionSchema).max(256).default([]),
    storageBuckets: z.array(bucketSchema).max(128).default([]),
    relationships: z.array(relationshipSchema).max(512).default([])
  }).strict().default({})
}).strict();

export type SupabaseAuthorizationInput = z.infer<typeof supabaseAuthorizationInputSchema>;

export async function loadSupabaseAuthorizationInput(filePath: string): Promise<SupabaseAuthorizationInput> {
  const raw = await readFile(filePath);
  if (raw.byteLength > maxInputBytes) throw new AppError(`Supabase authorization input exceeds ${maxInputBytes} bytes.`, "SUPABASE_AUTH_FILE_TOO_LARGE");
  let parsedJson: unknown;
  try { parsedJson = JSON.parse(raw.toString("utf8").replace(/^\uFEFF/, "")); }
  catch { throw new AppError("Supabase authorization input is not valid JSON.", "SUPABASE_AUTH_JSON_INVALID"); }
  const parsed = supabaseAuthorizationInputSchema.safeParse(parsedJson);
  if (!parsed.success) throw new AppError(parsed.error.message, "SUPABASE_AUTH_INPUT_INVALID");
  return parsed.data;
}

export function planSupabaseAuthorization(input: SupabaseAuthorizationInput, options: { target: string; scope: RouteCairnScope; authProfileSet?: AuthProfileSet }): SupabaseAuthorizationPlan {
  if (input.cases.length > input.maxCases) throw new AppError(`Supabase input contains ${input.cases.length} cases, exceeding maxCases ${input.maxCases}.`, "SUPABASE_AUTH_TOO_MANY_CASES");
  if (input.cases.some((item) => item.actor === "ACCOUNT_A" || item.actor === "ACCOUNT_B") && !options.authProfileSet) throw new AppError("Supabase Account A/B cases require --auth-a and --auth-b.", "SUPABASE_AUTH_PROFILE_SET_REQUIRED");
  if (input.cases.some((item) => item.actor === "SERVICE_ROLE") && !input.serviceRoleKeyEnv) throw new AppError("Supabase SERVICE_ROLE cases require serviceRoleKeyEnv.", "SUPABASE_AUTH_SERVICE_KEY_REF_REQUIRED");
  if (input.serviceRoleKeyEnv === input.anonKeyEnv) throw new AppError("anonKeyEnv and serviceRoleKeyEnv must reference different environment variables.", "SUPABASE_AUTH_KEY_REF_REUSE");
  if (options.authProfileSet && equivalentAuth(options.authProfileSet)) throw new AppError("Supabase Account A and Account B auth profiles resolve to identical auth material.", "SUPABASE_AUTH_PROFILES_NOT_DISTINCT");
  const origin = new URL(input.projectUrl).origin;
  const projectUrl = new URL(input.projectUrl);
  if (projectUrl.username || projectUrl.password) throw new AppError("Supabase projectUrl must not contain URL credentials.", "SUPABASE_AUTH_PROJECT_URL_INVALID");
  if ((projectUrl.pathname !== "/" && projectUrl.pathname !== "") || projectUrl.search || projectUrl.hash) throw new AppError("Supabase projectUrl must be an origin without a path, query, or fragment.", "SUPABASE_AUTH_PROJECT_URL_INVALID");
  const matcher = new ScopeMatcher(options.target, options.scope);
  const seen = new Set<string>();
  const cases = input.cases.map((item) => {
    if (seen.has(item.id)) throw new AppError(`Duplicate Supabase case id "${item.id}".`, "SUPABASE_AUTH_DUPLICATE_CASE");
    seen.add(item.id);
    validateCase(item);
    const parsedCaseUrl = new URL(item.url, `${origin}/`);
    if (parsedCaseUrl.username || parsedCaseUrl.password) throw new AppError(`Supabase case "${item.id}" URL must not contain credentials.`, "SUPABASE_AUTH_CASE_URL_INVALID");
    if ([...parsedCaseUrl.searchParams.keys()].some((name) => secretQueryName.test(name))) throw new AppError(`Supabase case "${item.id}" URL contains a secret-like query parameter name.`, "SUPABASE_AUTH_SECRET_QUERY_FORBIDDEN");
    const url = parsedCaseUrl.toString();
    const decision = matcher.decide(url, item.method);
    if (!decision.allowed || !decision.normalizedUrl) throw new AppError(`Supabase case "${item.id}" is out of scope: ${decision.reason}.`, "SUPABASE_AUTH_CASE_OUT_OF_SCOPE");
    if (new URL(decision.normalizedUrl).origin !== origin && item.operation !== "SIGNED_URL") throw new AppError(`Supabase case "${item.id}" must target project origin ${origin}.`, "SUPABASE_AUTH_ORIGIN_MISMATCH");
    for (const assertion of item.identityAssertions) parseSafeFieldPath(assertion.path, { maxDepth: 8, maxArrayIndex: 100, code: "SUPABASE_AUTH_FIELD_PATH_INVALID" });
    for (const column of item.forbiddenColumns) parseSafeFieldPath(column, { maxDepth: 8, maxArrayIndex: 100, code: "SUPABASE_AUTH_FIELD_PATH_INVALID" });
    if (item.signedUrl) parseSafeFieldPath(item.signedUrl.responseField, { maxDepth: 8, maxArrayIndex: 100, code: "SUPABASE_AUTH_FIELD_PATH_INVALID" });
    const planned = {
      ...item,
      url: decision.normalizedUrl,
      identityAssertions: item.identityAssertions.map((assertion) => ({ path: assertion.path, expectedValue: assertion.equals, expectedValueHash: securityContractValueHash("supabase-identity-assertion", assertion.equals) })),
      ...(item.signedUrl ? { signedUrl: { ...item.signedUrl, allowedOrigins: item.signedUrl.allowedOrigins.map((value) => new URL(value).origin) } } : {})
    };
    return { ...planned, comparisonFingerprint: securityContractFingerprint("supabase-authorization", { projectOrigin: origin, case: planned }) };
  });
  return deepFreeze({
    schemaVersion: 1,
    enabled: true,
    projectOrigin: origin,
    anonKeyEnv: input.anonKeyEnv,
    ...(input.serviceRoleKeyEnv ? { serviceRoleKeyEnv: input.serviceRoleKeyEnv } : {}),
    cases,
    catalog: input.catalog,
    maxCases: input.maxCases,
    maxResponseBytes: input.maxResponseBytes,
    maxSignedUrlBytes: input.maxSignedUrlBytes,
    notes: [
      "Supabase credentials are resolved from environment variables only at execution time and are excluded from plans, logs, and reports.",
      "Mutating table and RPC cases require an exact expiring controlled-mutation contract with rollback verification.",
      "All resources, actors, filters, assertions, relationships, functions, buckets, and signed URL destinations are operator supplied; runtime enumeration is disabled."
    ]
  });
}

function validateCase(item: SupabaseAuthorizationInput["cases"][number]): void {
  const mutating = item.operation === "INSERT" || item.operation === "UPDATE" || item.operation === "DELETE" || (item.operation === "INVOKE" && item.method === "POST");
  if (mutating && !item.mutationContractCaseId) throw new AppError(`Supabase mutation case "${item.id}" requires mutationContractCaseId.`, "SUPABASE_AUTH_MUTATION_CONTRACT_REQUIRED");
  if (!mutating && item.mutationContractCaseId) throw new AppError(`Read-only Supabase case "${item.id}" cannot bind a mutation contract.`, "SUPABASE_AUTH_UNEXPECTED_MUTATION_CONTRACT");
  if (item.operation === "SELECT" && item.method !== "GET" && item.method !== "HEAD") throw new AppError(`SELECT case "${item.id}" must use GET or HEAD.`, "SUPABASE_AUTH_METHOD_MISMATCH");
  if (item.operation === "INSERT" && item.method !== "POST") throw new AppError(`INSERT case "${item.id}" must use POST.`, "SUPABASE_AUTH_METHOD_MISMATCH");
  if (item.operation === "UPDATE" && item.method !== "PATCH") throw new AppError(`UPDATE case "${item.id}" must use PATCH.`, "SUPABASE_AUTH_METHOD_MISMATCH");
  if (item.operation === "DELETE" && item.method !== "DELETE") throw new AppError(`DELETE case "${item.id}" must use DELETE.`, "SUPABASE_AUTH_METHOD_MISMATCH");
  if (item.operation === "SIGNED_URL" && !item.signedUrl) throw new AppError(`SIGNED_URL case "${item.id}" requires signedUrl settings.`, "SUPABASE_AUTH_SIGNED_URL_REQUIRED");
  if (item.operation === "SIGNED_URL" && item.surface !== "STORAGE") throw new AppError(`SIGNED_URL case "${item.id}" must use STORAGE surface.`, "SUPABASE_AUTH_SURFACE_MISMATCH");
  if (item.surface === "RELATIONSHIP" && item.operation !== "SELECT") throw new AppError(`RELATIONSHIP case "${item.id}" must use SELECT.`, "SUPABASE_AUTH_SURFACE_MISMATCH");
  if (item.surface === "RPC" && item.operation !== "INVOKE") throw new AppError(`RPC case "${item.id}" must use INVOKE.`, "SUPABASE_AUTH_SURFACE_MISMATCH");
  if (item.surface !== "RPC" && item.operation === "INVOKE") throw new AppError(`INVOKE case "${item.id}" must use RPC surface.`, "SUPABASE_AUTH_SURFACE_MISMATCH");
  for (const [name, value] of Object.entries(item.headers)) {
    if (secretHeader.test(name)) throw new AppError(`Supabase case "${item.id}" cannot contain credential header "${name}".`, "SUPABASE_AUTH_SECRET_HEADER_FORBIDDEN");
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/i.test(name) || /[\r\n]/.test(value)) throw new AppError(`Supabase case "${item.id}" contains an invalid header.`, "SUPABASE_AUTH_HEADER_INVALID");
  }
  if (item.signedUrl) for (const allowedOrigin of item.signedUrl.allowedOrigins) { const parsed = new URL(allowedOrigin); if (parsed.username || parsed.password || (parsed.pathname !== "/" && parsed.pathname !== "") || parsed.search || parsed.hash) throw new AppError(`Supabase signed URL allowlist entry in case "${item.id}" must be an origin without credentials, path, query, or fragment.`, "SUPABASE_AUTH_SIGNED_ORIGIN_INVALID"); }
}

function equivalentAuth(profileSet: AuthProfileSet): boolean {
  const normalize = (headers: Record<string, string>) => Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value] as const).sort(([left], [right]) => left.localeCompare(right));
  return JSON.stringify(normalize(authHeadersForProfile(profileSet.accountA))) === JSON.stringify(normalize(authHeadersForProfile(profileSet.accountB)));
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}

export function isWriteOperation(operationValue: SupabaseOperation, method: string): boolean {
  return operationValue === "INSERT" || operationValue === "UPDATE" || operationValue === "DELETE" || (operationValue === "INVOKE" && method === "POST");
}
