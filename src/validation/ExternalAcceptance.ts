import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { gunzipSync } from "node:zlib";
import { z } from "zod";
import { runBoundedHttp } from "../modules/protocolSecurity/ProtocolTransports.js";

export const externalAcceptanceLaneKinds = [
  "MULTI_TENANT_SAAS",
  "SUPABASE_RLS_STORAGE_RPC",
  "GRAPHQL_APPLICATION",
  "AUTH_PROVIDER_MFA_PASSKEY",
  "SIGNED_PORTAL_EXPORT",
  "SYNTHETIC_PAYMENT",
  "WEBHOOK_CRON",
  "REMEDIATION_LIFECYCLE"
] as const;

const semanticValues = [
  "TENANT_OWNER_ALLOWED", "TENANT_FOREIGN_DENIED",
  "SUPABASE_TABLE_OWNER_ALLOWED", "SUPABASE_TABLE_FOREIGN_DENIED", "SUPABASE_STORAGE_OWNER_ALLOWED", "SUPABASE_STORAGE_FOREIGN_DENIED", "SUPABASE_RPC_OWNER_ALLOWED", "SUPABASE_RPC_FOREIGN_DENIED",
  "GRAPHQL_QUERY_OWNER_ALLOWED", "GRAPHQL_QUERY_FOREIGN_DENIED", "GRAPHQL_MUTATION_OWNER_ALLOWED", "GRAPHQL_MUTATION_FOREIGN_DENIED", "GRAPHQL_SUBSCRIPTION_OWNER_ALLOWED", "GRAPHQL_SUBSCRIPTION_FOREIGN_DENIED",
  "OIDC_LIFECYCLE", "MFA_LIFECYCLE", "PASSKEY_LIFECYCLE",
  "SIGNED_PORTAL_OWNER_ALLOWED", "SIGNED_PORTAL_FOREIGN_DENIED", "SIGNED_EXPORT_OWNER_ALLOWED", "SIGNED_EXPORT_FOREIGN_DENIED",
  "SYNTHETIC_CHECKOUT", "SYNTHETIC_PROVIDER_EVENT", "SYNTHETIC_PROVIDER_REPLAY_REJECTED", "SYNTHETIC_PAYMENT_CLEANUP",
  "WEBHOOK_VALID_SIGNATURE", "WEBHOOK_INVALID_SIGNATURE", "WEBHOOK_REPLAY", "CRON_AUTHORIZED", "CRON_UNAUTHORIZED",
  "REMEDIATION_VULNERABLE_BASELINE", "REMEDIATION_FIXED_RERUN", "REMEDIATION_IDENTITY_MATCH"
] as const;

export type ExternalAcceptanceLaneKind = typeof externalAcceptanceLaneKinds[number];
export type ExternalAcceptanceSemantic = typeof semanticValues[number];

const identifier = z.string().regex(/^[A-Za-z0-9._-]{1,100}$/);
const envName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/);
const sha256 = z.string().regex(/^[a-f0-9]{64}$/);
const jsonPath = z.string().regex(/^(?:[A-Za-z_$][A-Za-z0-9_$]*|[0-9]+)(?:\.[A-Za-z_$][A-Za-z0-9_$]*|\.[0-9]+){0,15}$/);
const headerName = z.string().regex(/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$/);
const safeText = z.string().max(4096).refine((value) => !/[\0\r\n]/.test(value), "Value cannot contain control newlines.");
const assertionsSchema = z.object({
  statuses: z.array(z.number().int().min(100).max(599)).min(1).max(20),
  jsonEquals: z.record(jsonPath, z.unknown()).default({}),
  jsonPresent: z.array(jsonPath).max(50).default([]),
  jsonAbsent: z.array(jsonPath).max(50).default([]),
  headerPresent: z.array(headerName).max(30).default([]),
  headerAbsent: z.array(headerName).max(30).default([])
}).strict();
const requestSchema = z.object({
  origin: identifier,
  method: z.enum(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]),
  path: z.string().min(1).max(2048).regex(/^\//),
  headers: z.record(headerName, safeText).default({}),
  body: z.unknown().optional(),
  timeoutMs: z.number().int().min(250).max(120_000).default(20_000)
}).strict();
const actionSchema = z.object({
  id: identifier,
  phase: z.enum(["SETUP", "EXERCISE", "VERIFY", "CLEANUP"]),
  semantic: z.enum(semanticValues),
  caseIdentity: sha256,
  request: requestSchema,
  assertions: assertionsSchema,
  captures: z.record(identifier, jsonPath).default({}),
  synthetic: z.boolean().default(false),
  stateChange: z.boolean().default(false)
}).strict();
const laneSchema = z.object({
  id: identifier,
  kind: z.enum(externalAcceptanceLaneKinds),
  targetProduct: z.string().min(2).max(160),
  targetVersion: z.string().min(1).max(160),
  authProvider: z.enum(["AUTH0", "COGNITO"]).optional(),
  paymentProvider: z.enum(["STRIPE", "ADYEN", "BRAINTREE", "OTHER_SYNTHETIC"]).optional(),
  environment: z.enum(["DEVELOPMENT", "SANDBOX", "STAGING", "PRODUCTION"]),
  independentlyReproducible: z.literal(true),
  reproductionReference: z.string().url().max(2048),
  reproductionSha256: sha256,
  targetFingerprint: sha256,
  actions: z.array(actionSchema).min(1).max(100)
}).strict();

export const externalAcceptanceManifestSchema = z.object({
  schemaVersion: z.literal(1),
  name: z.string().min(3).max(160),
  operator: z.object({
    organization: z.string().min(2).max(160),
    contact: z.string().email().max(254),
    independentOfRouteCairnAuthors: z.literal(true),
    publicKeyId: sha256
  }).strict(),
  release: z.object({
    name: z.literal("routecairn"),
    version: z.string().regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/),
    gitCommit: z.string().regex(/^[a-f0-9]{40}$/),
    artifactSha256: sha256,
    sourceRepository: z.string().url().max(2048)
  }).strict(),
  authorization: z.object({
    proofReference: z.string().min(3).max(500),
    proofSha256: sha256,
    authorizedBy: z.string().min(2).max(160),
    startsAt: z.string().datetime(),
    expiresAt: z.string().datetime(),
    disposableAccountsOnly: z.literal(true),
    syntheticPaymentsOnly: z.literal(true),
    controlledStateChangesAllowed: z.literal(true),
    destructiveAdministrationAllowed: z.literal(false),
    allowedOrigins: z.record(identifier, z.string().url().max(2048)),
    secretEnvironment: z.record(identifier, envName).default({}),
    maxRequests: z.number().int().min(8).max(1000).default(250),
    rateLimitPerSecond: z.number().min(0.1).max(50).default(5)
  }).strict(),
  lanes: z.array(laneSchema).length(8)
}).strict().superRefine((value, ctx) => {
  if (Date.parse(value.authorization.startsAt) >= Date.parse(value.authorization.expiresAt)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["authorization", "expiresAt"], message: "Authorization expiry must follow its start." });
  const actionCount = value.lanes.reduce((sum, lane) => sum + lane.actions.length, 0);
  if (actionCount > value.authorization.maxRequests) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["authorization", "maxRequests"], message: `Request budget ${value.authorization.maxRequests} cannot cover all ${actionCount} declared actions and cleanup.` });
  for (const kind of externalAcceptanceLaneKinds) if (value.lanes.filter((lane) => lane.kind === kind).length !== 1) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes"], message: `Exactly one ${kind} lane is required.` });
  const ids = new Set<string>();
  const caseOwners = new Map<string, string>();
  for (const [laneIndex, lane] of value.lanes.entries()) {
    if (ids.has(lane.id)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "id"], message: "Lane IDs must be unique." });
    ids.add(lane.id);
    if (lane.kind === "AUTH_PROVIDER_MFA_PASSKEY" && !lane.authProvider) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "authProvider"], message: "The authentication lane requires Auth0 or Cognito." });
    if (lane.kind !== "AUTH_PROVIDER_MFA_PASSKEY" && lane.authProvider) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "authProvider"], message: "authProvider is valid only for the authentication lane." });
    if (lane.kind === "SYNTHETIC_PAYMENT" && !lane.paymentProvider) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "paymentProvider"], message: "The payment lane requires a named synthetic provider." });
    if (lane.kind !== "SYNTHETIC_PAYMENT" && lane.paymentProvider) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "paymentProvider"], message: "paymentProvider is valid only for the payment lane." });
    const actionIds = new Set<string>();
    for (const [actionIndex, action] of lane.actions.entries()) {
      if (actionIds.has(action.id)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "actions", actionIndex, "id"], message: "Action IDs must be unique per lane." });
      actionIds.add(action.id);
      if (!requiredSemantics[lane.kind].includes(action.semantic)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "actions", actionIndex, "semantic"], message: `${action.semantic} does not belong to ${lane.kind}.` });
      const owner = caseOwners.get(action.caseIdentity);
      const remediationIdentity = lane.kind === "REMEDIATION_LIFECYCLE" && requiredSemantics.REMEDIATION_LIFECYCLE.includes(action.semantic);
      if (owner && !(remediationIdentity && owner.startsWith(`${lane.id}/`))) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "actions", actionIndex, "caseIdentity"], message: `Case identity is already used by ${owner}.` });
      else caseOwners.set(action.caseIdentity, `${lane.id}/${action.id}`);
      if (!value.authorization.allowedOrigins[action.request.origin]) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "actions", actionIndex, "request", "origin"], message: "Origin alias is not authorized." });
      if (lane.kind === "SYNTHETIC_PAYMENT" && !action.synthetic) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "actions", actionIndex, "synthetic"], message: "Every payment-lane action must be explicitly synthetic." });
      if (positiveSemantics.has(action.semantic) && !action.assertions.statuses.some((status) => status >= 200 && status < 300)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "actions", actionIndex, "assertions", "statuses"], message: `${action.semantic} requires an explicit successful status assertion.` });
      if (negativeSemantics.has(action.semantic) && action.assertions.statuses.some((status) => status >= 200 && status < 300)) {
        const graphqlDenial = action.semantic.startsWith("GRAPHQL_") && action.assertions.statuses.includes(200) && action.assertions.jsonPresent.includes("errors.0");
        const emptyRls = action.semantic === "SUPABASE_TABLE_FOREIGN_DENIED" && action.assertions.statuses.includes(200) && action.assertions.jsonEquals.length === 0;
        if (!graphqlDenial && !emptyRls) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "actions", actionIndex, "assertions"], message: `${action.semantic} cannot treat a successful status as denial without a protocol-specific denial assertion.` });
      }
    }
    const mutation = lane.actions.some((action) => action.stateChange && action.phase !== "CLEANUP");
    if (mutation && !lane.actions.some((action) => action.phase === "CLEANUP")) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "actions"], message: "Every mutating lane requires explicit cleanup." });
    if (lane.actions.some((action) => action.phase === "CLEANUP" && !action.stateChange)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "actions"], message: "Cleanup actions must explicitly declare their state change." });
    for (const semantic of ["MFA_LIFECYCLE", "PASSKEY_LIFECYCLE", "GRAPHQL_MUTATION_OWNER_ALLOWED", "SYNTHETIC_CHECKOUT", "SYNTHETIC_PROVIDER_EVENT", "SYNTHETIC_PAYMENT_CLEANUP", "WEBHOOK_VALID_SIGNATURE", "CRON_AUTHORIZED"] as const) {
      const action = lane.actions.find((item) => item.semantic === semantic);
      if (action && !action.stateChange) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "actions"], message: `${semantic} must declare a controlled state change.` });
    }
    if (lane.kind === "REMEDIATION_LIFECYCLE") {
      const identities = new Set(lane.actions.filter((action) => requiredSemantics.REMEDIATION_LIFECYCLE.includes(action.semantic)).map((action) => action.caseIdentity));
      if (identities.size !== 1) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "actions"], message: "Baseline, fixed rerun, and identity proof must share one case identity." });
    }
    const required = requiredSemantics[lane.kind];
    const present = new Set(lane.actions.map((action) => action.semantic));
    for (const semantic of required) if (!present.has(semantic)) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["lanes", laneIndex, "actions"], message: `${lane.kind} requires ${semantic}.` });
  }
});

export type ExternalAcceptanceManifest = z.infer<typeof externalAcceptanceManifestSchema>;
type ExternalAction = ExternalAcceptanceManifest["lanes"][number]["actions"][number];

const requiredSemantics: Record<ExternalAcceptanceLaneKind, readonly ExternalAcceptanceSemantic[]> = {
  MULTI_TENANT_SAAS: ["TENANT_OWNER_ALLOWED", "TENANT_FOREIGN_DENIED"],
  SUPABASE_RLS_STORAGE_RPC: ["SUPABASE_TABLE_OWNER_ALLOWED", "SUPABASE_TABLE_FOREIGN_DENIED", "SUPABASE_STORAGE_OWNER_ALLOWED", "SUPABASE_STORAGE_FOREIGN_DENIED", "SUPABASE_RPC_OWNER_ALLOWED", "SUPABASE_RPC_FOREIGN_DENIED"],
  GRAPHQL_APPLICATION: ["GRAPHQL_QUERY_OWNER_ALLOWED", "GRAPHQL_QUERY_FOREIGN_DENIED", "GRAPHQL_MUTATION_OWNER_ALLOWED", "GRAPHQL_MUTATION_FOREIGN_DENIED", "GRAPHQL_SUBSCRIPTION_OWNER_ALLOWED", "GRAPHQL_SUBSCRIPTION_FOREIGN_DENIED"],
  AUTH_PROVIDER_MFA_PASSKEY: ["OIDC_LIFECYCLE", "MFA_LIFECYCLE", "PASSKEY_LIFECYCLE"],
  SIGNED_PORTAL_EXPORT: ["SIGNED_PORTAL_OWNER_ALLOWED", "SIGNED_PORTAL_FOREIGN_DENIED", "SIGNED_EXPORT_OWNER_ALLOWED", "SIGNED_EXPORT_FOREIGN_DENIED"],
  SYNTHETIC_PAYMENT: ["SYNTHETIC_CHECKOUT", "SYNTHETIC_PROVIDER_EVENT", "SYNTHETIC_PROVIDER_REPLAY_REJECTED", "SYNTHETIC_PAYMENT_CLEANUP"],
  WEBHOOK_CRON: ["WEBHOOK_VALID_SIGNATURE", "WEBHOOK_INVALID_SIGNATURE", "WEBHOOK_REPLAY", "CRON_AUTHORIZED", "CRON_UNAUTHORIZED"],
  REMEDIATION_LIFECYCLE: ["REMEDIATION_VULNERABLE_BASELINE", "REMEDIATION_FIXED_RERUN", "REMEDIATION_IDENTITY_MATCH"]
};

const positiveSemantics = new Set<ExternalAcceptanceSemantic>([
  "TENANT_OWNER_ALLOWED", "SUPABASE_TABLE_OWNER_ALLOWED", "SUPABASE_STORAGE_OWNER_ALLOWED", "SUPABASE_RPC_OWNER_ALLOWED",
  "GRAPHQL_QUERY_OWNER_ALLOWED", "GRAPHQL_MUTATION_OWNER_ALLOWED", "GRAPHQL_SUBSCRIPTION_OWNER_ALLOWED",
  "OIDC_LIFECYCLE", "MFA_LIFECYCLE", "PASSKEY_LIFECYCLE", "SIGNED_PORTAL_OWNER_ALLOWED", "SIGNED_EXPORT_OWNER_ALLOWED",
  "SYNTHETIC_CHECKOUT", "SYNTHETIC_PROVIDER_EVENT", "SYNTHETIC_PAYMENT_CLEANUP", "WEBHOOK_VALID_SIGNATURE", "CRON_AUTHORIZED",
  "REMEDIATION_VULNERABLE_BASELINE", "REMEDIATION_IDENTITY_MATCH"
]);
const negativeSemantics = new Set<ExternalAcceptanceSemantic>([
  "TENANT_FOREIGN_DENIED", "SUPABASE_TABLE_FOREIGN_DENIED", "SUPABASE_STORAGE_FOREIGN_DENIED", "SUPABASE_RPC_FOREIGN_DENIED",
  "GRAPHQL_QUERY_FOREIGN_DENIED", "GRAPHQL_MUTATION_FOREIGN_DENIED", "GRAPHQL_SUBSCRIPTION_FOREIGN_DENIED",
  "SIGNED_PORTAL_FOREIGN_DENIED", "SIGNED_EXPORT_FOREIGN_DENIED", "SYNTHETIC_PROVIDER_REPLAY_REJECTED",
  "WEBHOOK_INVALID_SIGNATURE", "WEBHOOK_REPLAY", "CRON_UNAUTHORIZED", "REMEDIATION_FIXED_RERUN"
]);

interface ActionEvidence {
  id: string;
  phase: string;
  semantic: ExternalAcceptanceSemantic;
  caseIdentity: string;
  status: "PASSED" | "FAILED";
  request: { method: string; origin: string; path: string; bodySha256?: string };
  response?: { status: number; bodySha256: string; bytes: number; headersSha256: string };
  durationMs: number;
  reason?: string;
}

interface LaneEvidence {
  id: string;
  kind: ExternalAcceptanceLaneKind;
  targetProduct: string;
  targetVersion: string;
  authProvider?: "AUTH0" | "COGNITO";
  paymentProvider?: "STRIPE" | "ADYEN" | "BRAINTREE" | "OTHER_SYNTHETIC";
  environment: string;
  reproductionReference: string;
  reproductionSha256: string;
  targetFingerprint: string;
  status: "PASSED" | "FAILED";
  cleanup: "VERIFIED" | "FAILED" | "NOT_REQUIRED";
  semantics: ExternalAcceptanceSemantic[];
  actions: ActionEvidence[];
  evidenceSha256: string;
}

export interface ExternalAcceptanceSummary {
  schemaVersion: 1;
  standard: "ROUTECAIRN_EXTERNAL_ACCEPTANCE_V1";
  status: "PASSED" | "FAILED";
  startedAt: string;
  completedAt: string;
  release: ExternalAcceptanceManifest["release"];
  operator: Omit<ExternalAcceptanceManifest["operator"], "contact"> & { contactSha256: string };
  authorization: { proofReference: string; proofSha256: string; window: { startsAt: string; expiresAt: string }; policy: { disposableAccountsOnly: true; syntheticPaymentsOnly: true; controlledStateChangesAllowed: true; destructiveAdministrationAllowed: false } };
  manifestSha256: string;
  artifact: { name: string; sha256: string; bytes: number };
  requestCount: number;
  lanes: LaneEvidence[];
  evidenceSha256: string;
  outputDirectory: string;
}

export interface ExternalAcceptanceBundle {
  schemaVersion: 1;
  statement: InTotoStatement;
  envelope: DsseEnvelope;
  publicKeyPem: string;
  summary: ExternalAcceptanceSummary;
}

interface InTotoStatement {
  _type: "https://in-toto.io/Statement/v1";
  subject: Array<{ name: string; digest: { sha256: string } }>;
  predicateType: "https://routecairn.dev/attestations/external-acceptance/v1";
  predicate: Record<string, unknown>;
}
interface DsseEnvelope { payloadType: "application/vnd.in-toto+json"; payload: string; signatures: Array<{ keyid: string; sig: string }> }

export async function loadExternalAcceptanceManifest(path: string): Promise<ExternalAcceptanceManifest> {
  const raw = await readFile(path);
  if (raw.byteLength > 2 * 1024 * 1024) throw new Error("EXTERNAL_ACCEPTANCE_MANIFEST_TOO_LARGE");
  try { return externalAcceptanceManifestSchema.parse(JSON.parse(raw.toString("utf8").replace(/^\uFEFF/, ""))); }
  catch (error) { throw new Error(`EXTERNAL_ACCEPTANCE_MANIFEST_INVALID: ${safeReason(error)}`); }
}

export async function generateExternalAcceptanceKeyPair(privateKeyPath: string, publicKeyPath: string): Promise<{ keyId: string; privateKeyPath: string; publicKeyPath: string }> {
  const keys = generateKeyPairSync("ed25519");
  const privatePem = keys.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const publicPem = keys.publicKey.export({ format: "pem", type: "spki" }).toString();
  await mkdir(dirname(resolve(privateKeyPath)), { recursive: true });
  await mkdir(dirname(resolve(publicKeyPath)), { recursive: true });
  await writeFile(resolve(privateKeyPath), privatePem, { encoding: "utf8", mode: 0o600, flag: "wx" });
  await writeFile(resolve(publicKeyPath), publicPem, { encoding: "utf8", mode: 0o644, flag: "wx" });
  await chmod(resolve(privateKeyPath), 0o600).catch(() => undefined);
  return { keyId: publicKeyId(keys.publicKey), privateKeyPath: resolve(privateKeyPath), publicKeyPath: resolve(publicKeyPath) };
}

export async function runExternalAcceptance(input: ExternalAcceptanceManifest, options: { releaseArtifact: string; outputDirectory?: string; signingKey: string; environment?: NodeJS.ProcessEnv; now?: Date }): Promise<ExternalAcceptanceBundle> {
  const manifest = externalAcceptanceManifestSchema.parse(input);
  const now = options.now ?? new Date();
  if (now.getTime() < Date.parse(manifest.authorization.startsAt) || now.getTime() > Date.parse(manifest.authorization.expiresAt)) throw new Error("EXTERNAL_ACCEPTANCE_AUTHORIZATION_WINDOW_INACTIVE");
  const artifactPath = resolve(options.releaseArtifact);
  const artifactBytes = await readFile(artifactPath);
  const artifactDigest = digest(artifactBytes);
  if (artifactDigest !== manifest.release.artifactSha256) throw new Error("EXTERNAL_ACCEPTANCE_RELEASE_ARTIFACT_DIGEST_MISMATCH");
  validateNpmReleaseArtifact(artifactBytes, manifest.release.version);
  await validateRunningReleaseVersion(manifest.release.version);
  const key = loadPrivateKey(options.signingKey);
  const derivedKeyId = publicKeyId(createPublicKey(key));
  if (derivedKeyId !== manifest.operator.publicKeyId) throw new Error("EXTERNAL_ACCEPTANCE_OPERATOR_KEY_MISMATCH");
  const parent = resolve(options.outputDirectory ?? ".routecairn-external-acceptance");
  await mkdir(parent, { recursive: true });
  const outputDirectory = await mkdtemp(resolve(parent, "run-"));
  const environment = options.environment ?? process.env;
  const secrets = resolveSecrets(manifest.authorization.secretEnvironment, environment);
  const normalizedOrigins = Object.fromEntries(Object.entries(manifest.authorization.allowedOrigins).map(([alias, value]) => [alias, canonicalOrigin(value)]));
  const lanes: LaneEvidence[] = [];
  let requestCount = 0;
  let previousRequestAt = 0;
  const startedAt = now.toISOString();

  for (const lane of manifest.lanes) {
    const captures = new Map<string, string>();
    const actions: ActionEvidence[] = [];
    let primaryFailure = false;
    const ordered = [...lane.actions.filter((action) => action.phase !== "CLEANUP"), ...lane.actions.filter((action) => action.phase === "CLEANUP")];
    for (const action of ordered) {
      if (primaryFailure && action.phase !== "CLEANUP") continue;
      if (action.phase !== "CLEANUP" && Date.now() > Date.parse(manifest.authorization.expiresAt)) {
        primaryFailure = true;
        actions.push({ id: action.id, phase: action.phase, semantic: action.semantic, caseIdentity: action.caseIdentity, status: "FAILED", request: { method: action.request.method, origin: action.request.origin, path: action.request.path }, durationMs: 0, reason: "EXTERNAL_ACCEPTANCE_AUTHORIZATION_EXPIRED" });
        continue;
      }
      if (++requestCount > manifest.authorization.maxRequests) throw new Error("EXTERNAL_ACCEPTANCE_REQUEST_BUDGET_EXCEEDED");
      const minimumGap = Math.ceil(1000 / manifest.authorization.rateLimitPerSecond);
      const wait = Math.max(0, previousRequestAt + minimumGap - Date.now());
      if (wait) await delay(wait);
      previousRequestAt = Date.now();
      const began = Date.now();
      const evidence: ActionEvidence = {
        id: action.id, phase: action.phase, semantic: action.semantic, caseIdentity: action.caseIdentity, status: "FAILED",
        request: { method: action.request.method, origin: action.request.origin, path: action.request.path }, durationMs: 0
      };
      try {
        const requestBody = action.request.body === undefined ? undefined : JSON.stringify(expand(action.request.body, secrets, captures));
        if (requestBody !== undefined) evidence.request.bodySha256 = digest(requestBody);
        const origin = normalizedOrigins[action.request.origin]!;
        const expandedPath = expandString(action.request.path, secrets, captures);
        if (!expandedPath.startsWith("/")) throw new Error("EXTERNAL_ACCEPTANCE_PATH_INVALID");
        const target = new URL(expandedPath, `${origin}/`);
        if (target.origin !== origin) throw new Error("EXTERNAL_ACCEPTANCE_CROSS_ORIGIN_BLOCKED");
        const headers = Object.fromEntries(Object.entries(action.request.headers).map(([name, value]) => [name, expandString(value, secrets, captures)]));
        if (requestBody !== undefined && !findHeader(headers, "content-type")) headers["content-type"] = "application/json";
        const response = await runBoundedHttp(target.toString(), action.request.method, headers, requestBody === undefined ? undefined : Buffer.from(requestBody), { allowedPrivateOrigins: Object.values(normalizedOrigins), timeoutMs: action.request.timeoutMs, maxBytes: 1024 * 1024 });
        const body = response.body;
        let json: unknown;
        if (body.byteLength) try { json = JSON.parse(body.toString("utf8")); } catch { json = undefined; }
        assertResponse(action, response, json, secrets, captures);
        for (const [captureName, path] of Object.entries(action.captures)) {
          const value = valueAt(json, path);
          if (!["string", "number", "boolean"].includes(typeof value)) throw new Error(`CAPTURE_MISSING:${captureName}`);
          captures.set(captureName, String(value));
        }
        evidence.status = "PASSED";
        evidence.response = { status: response.statusCode, bodySha256: digest(body), bytes: body.byteLength, headersSha256: digest(canonical(response.headers)) };
      } catch (error) {
        evidence.reason = redact(safeReason(error), Object.values(secrets));
        if (action.phase !== "CLEANUP") primaryFailure = true;
      }
      evidence.durationMs = Date.now() - began;
      actions.push(evidence);
    }
    const cleanupActions = lane.actions.filter((action) => action.phase === "CLEANUP");
    const cleanup: LaneEvidence["cleanup"] = cleanupActions.length === 0 ? "NOT_REQUIRED" : cleanupActions.every((action) => actions.find((item) => item.id === action.id)?.status === "PASSED") ? "VERIFIED" : "FAILED";
    const status: LaneEvidence["status"] = !primaryFailure && cleanup !== "FAILED" && actions.filter((item) => item.phase !== "CLEANUP").every((item) => item.status === "PASSED") ? "PASSED" : "FAILED";
    const core = { id: lane.id, kind: lane.kind, targetProduct: lane.targetProduct, targetVersion: lane.targetVersion, ...(lane.authProvider ? { authProvider: lane.authProvider } : {}), ...(lane.paymentProvider ? { paymentProvider: lane.paymentProvider } : {}), environment: lane.environment, reproductionReference: lane.reproductionReference, reproductionSha256: lane.reproductionSha256, targetFingerprint: lane.targetFingerprint, status, cleanup, semantics: [...new Set(actions.filter((item) => item.status === "PASSED").map((item) => item.semantic))].sort() as ExternalAcceptanceSemantic[], actions };
    lanes.push({ ...core, evidenceSha256: digest(canonical(core)) });
  }

  const completedAt = new Date().toISOString();
  const manifestSha256 = digest(canonical(manifest));
  const coreSummary = {
    schemaVersion: 1 as const,
    standard: "ROUTECAIRN_EXTERNAL_ACCEPTANCE_V1" as const,
    status: lanes.every((lane) => lane.status === "PASSED") ? "PASSED" as const : "FAILED" as const,
    startedAt, completedAt, release: manifest.release,
    operator: { organization: manifest.operator.organization, independentOfRouteCairnAuthors: manifest.operator.independentOfRouteCairnAuthors, publicKeyId: manifest.operator.publicKeyId, contactSha256: digest(manifest.operator.contact.trim().toLowerCase()) },
    authorization: { proofReference: manifest.authorization.proofReference, proofSha256: manifest.authorization.proofSha256, window: { startsAt: manifest.authorization.startsAt, expiresAt: manifest.authorization.expiresAt }, policy: { disposableAccountsOnly: true as const, syntheticPaymentsOnly: true as const, controlledStateChangesAllowed: true as const, destructiveAdministrationAllowed: false as const } },
    manifestSha256, artifact: { name: basename(artifactPath), sha256: artifactDigest, bytes: artifactBytes.byteLength }, requestCount, lanes
  };
  const evidenceSha256 = digest(canonical(coreSummary));
  const summary: ExternalAcceptanceSummary = { ...coreSummary, evidenceSha256, outputDirectory };
  const statement: InTotoStatement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: basename(artifactPath), digest: { sha256: artifactDigest } }],
    predicateType: "https://routecairn.dev/attestations/external-acceptance/v1",
    predicate: { standard: summary.standard, status: summary.status, release: manifest.release, operator: summary.operator, authorization: summary.authorization, manifestSha256, evidenceSha256, lanes: lanes.map((lane) => ({ id: lane.id, kind: lane.kind, status: lane.status, cleanup: lane.cleanup, evidenceSha256: lane.evidenceSha256, targetProduct: lane.targetProduct, targetVersion: lane.targetVersion, ...(lane.authProvider ? { authProvider: lane.authProvider } : {}), ...(lane.paymentProvider ? { paymentProvider: lane.paymentProvider } : {}), targetFingerprint: lane.targetFingerprint, reproductionReference: lane.reproductionReference, reproductionSha256: lane.reproductionSha256 })) }
  };
  const publicKey = createPublicKey(key);
  const envelope = signStatement(statement, key, derivedKeyId);
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const bundle: ExternalAcceptanceBundle = { schemaVersion: 1, statement, envelope, publicKeyPem, summary };
  await persistBundle(outputDirectory, bundle, manifest);
  return bundle;
}

export async function verifyExternalAcceptanceBundle(bundlePath: string, releaseArtifact: string, trustedPublicKeyPath: string, manifestPath: string): Promise<{ verified: true; keyId: string; releaseSha256: string; status: string; laneCount: number }> {
  const raw = await readFile(bundlePath);
  if (raw.byteLength > 8 * 1024 * 1024) throw new Error("EXTERNAL_ACCEPTANCE_BUNDLE_TOO_LARGE");
  const bundle = JSON.parse(raw.toString("utf8")) as ExternalAcceptanceBundle;
  if (bundle?.schemaVersion !== 1 || bundle.statement?._type !== "https://in-toto.io/Statement/v1" || bundle.statement?.predicateType !== "https://routecairn.dev/attestations/external-acceptance/v1") throw new Error("EXTERNAL_ACCEPTANCE_BUNDLE_INVALID");
  const trusted = createPublicKey(await readFile(trustedPublicKeyPath, "utf8"));
  const keyId = publicKeyId(trusted);
  const manifest = await loadExternalAcceptanceManifest(manifestPath);
  if (manifest.operator.publicKeyId !== keyId) throw new Error("EXTERNAL_ACCEPTANCE_MANIFEST_OPERATOR_KEY_MISMATCH");
  if (digest(canonical(manifest)) !== bundle.summary.manifestSha256) throw new Error("EXTERNAL_ACCEPTANCE_MANIFEST_DIGEST_MISMATCH");
  if (publicKeyId(createPublicKey(bundle.publicKeyPem)) !== keyId) throw new Error("EXTERNAL_ACCEPTANCE_BUNDLED_KEY_MISMATCH");
  const signature = bundle.envelope?.signatures?.find((item) => item.keyid === keyId);
  if (!signature) throw new Error("EXTERNAL_ACCEPTANCE_TRUSTED_SIGNATURE_MISSING");
  const payload = Buffer.from(bundle.envelope.payload, "base64");
  if (payload.toString("utf8") !== canonical(bundle.statement)) throw new Error("EXTERNAL_ACCEPTANCE_STATEMENT_PAYLOAD_MISMATCH");
  if (!verify(null, pae(bundle.envelope.payloadType, payload), trusted, Buffer.from(signature.sig, "base64"))) throw new Error("EXTERNAL_ACCEPTANCE_SIGNATURE_INVALID");
  const artifact = await readFile(releaseArtifact);
  const artifactSha256 = digest(artifact);
  validateNpmReleaseArtifact(artifact, manifest.release.version);
  if (!bundle.statement.subject.some((subject) => subject.digest.sha256 === artifactSha256)) throw new Error("EXTERNAL_ACCEPTANCE_RELEASE_SUBJECT_MISMATCH");
  if (bundle.summary.artifact.sha256 !== artifactSha256) throw new Error("EXTERNAL_ACCEPTANCE_SUMMARY_ARTIFACT_MISMATCH");
  if (canonical(bundle.summary.release) !== canonical(manifest.release)) throw new Error("EXTERNAL_ACCEPTANCE_RELEASE_MANIFEST_MISMATCH");
  const { evidenceSha256: ignored, outputDirectory: ignoredDirectory, ...summaryCore } = bundle.summary;
  if (digest(canonical(summaryCore)) !== bundle.summary.evidenceSha256) throw new Error("EXTERNAL_ACCEPTANCE_EVIDENCE_DIGEST_MISMATCH");
  const predicate = bundle.statement.predicate;
  if (predicate.evidenceSha256 !== bundle.summary.evidenceSha256 || predicate.manifestSha256 !== bundle.summary.manifestSha256 || predicate.status !== bundle.summary.status) throw new Error("EXTERNAL_ACCEPTANCE_PREDICATE_MISMATCH");
  if (!Array.isArray(bundle.summary.lanes) || bundle.summary.lanes.length !== 8) throw new Error("EXTERNAL_ACCEPTANCE_LANES_INVALID");
  for (const lane of bundle.summary.lanes) {
    const { evidenceSha256, ...core } = lane;
    if (digest(canonical(core)) !== evidenceSha256) throw new Error(`EXTERNAL_ACCEPTANCE_LANE_DIGEST_MISMATCH:${lane.id}`);
  }
  verifyManifestEvidenceBinding(manifest, bundle.summary);
  return { verified: true, keyId, releaseSha256: artifactSha256, status: bundle.summary.status, laneCount: bundle.summary.lanes.length };
}

function assertResponse(action: ExternalAction, response: { statusCode: number; headers: Record<string, string | string[]> }, payload: unknown, secrets: Record<string, string>, captures: Map<string, string>): void {
  if (!action.assertions.statuses.includes(response.statusCode)) throw new Error(`HTTP_${response.statusCode}_NOT_ACCEPTED`);
  for (const [path, expected] of Object.entries(action.assertions.jsonEquals)) if (!deepEqual(valueAt(payload, path), expand(expected, secrets, captures))) throw new Error(`JSON_EQUALS_FAILED:${path}`);
  for (const path of action.assertions.jsonPresent) if (valueAt(payload, path) === undefined) throw new Error(`JSON_PRESENT_FAILED:${path}`);
  for (const path of action.assertions.jsonAbsent) if (valueAt(payload, path) !== undefined) throw new Error(`JSON_ABSENT_FAILED:${path}`);
  for (const name of action.assertions.headerPresent) if (!hasHeader(response.headers, name)) throw new Error(`HEADER_PRESENT_FAILED:${name}`);
  for (const name of action.assertions.headerAbsent) if (hasHeader(response.headers, name)) throw new Error(`HEADER_ABSENT_FAILED:${name}`);
}

async function persistBundle(directory: string, bundle: ExternalAcceptanceBundle, manifest: ExternalAcceptanceManifest): Promise<void> {
  const portableBundle = { ...bundle, summary: { ...bundle.summary, outputDirectory: "." } };
  const files: Record<string, string> = {
    "external-acceptance-bundle.json": `${JSON.stringify(portableBundle, null, 2)}\n`,
    "external-acceptance-summary.json": `${JSON.stringify(portableBundle.summary, null, 2)}\n`,
    "external-acceptance-statement.json": `${JSON.stringify(bundle.statement, null, 2)}\n`,
    "external-acceptance-attestation.dsse.json": `${JSON.stringify(bundle.envelope, null, 2)}\n`,
    "external-acceptance-public-key.pem": bundle.publicKeyPem,
    "external-acceptance-manifest.json": `${JSON.stringify(manifest, null, 2)}\n`,
    "external-acceptance-report.md": markdown(bundle.summary)
  };
  const checksums: string[] = [];
  for (const [name, content] of Object.entries(files)) { await writeFile(resolve(directory, name), content, { encoding: "utf8", mode: 0o644 }); checksums.push(`${digest(content)}  ${name}`); }
  await writeFile(resolve(directory, "SHA256SUMS"), `${checksums.sort().join("\n")}\n`, "utf8");
}

function markdown(summary: ExternalAcceptanceSummary): string {
  const lanes = summary.lanes.map((lane) => `| ${lane.kind} | ${markdownCell(lane.targetProduct)} ${markdownCell(lane.targetVersion)} | ${lane.status} | ${lane.cleanup} | ${lane.actions.length} | \`${lane.targetFingerprint}\` | \`${lane.reproductionSha256}\` | \`${lane.evidenceSha256}\` |`).join("\n");
  return `# RouteCairn external acceptance attestation\n\n- Status: **${summary.status}**\n- Release: \`${summary.release.version}\` / \`${summary.release.gitCommit}\`\n- Release artifact SHA-256: \`${summary.artifact.sha256}\`\n- Operator: ${markdownCell(summary.operator.organization)}\n- Independent operator declaration: ${summary.operator.independentOfRouteCairnAuthors ? "yes" : "no"}\n- Authorization reference: ${markdownCell(summary.authorization.proofReference)}\n- Authorization proof SHA-256: \`${summary.authorization.proofSha256}\`\n- Evidence SHA-256: \`${summary.evidenceSha256}\`\n- Requests: ${summary.requestCount}\n\n| Lane | Target | Status | Cleanup | Actions | Target fingerprint | Reproduction digest | Evidence digest |\n| --- | --- | --- | --- | ---: | --- | --- | --- |\n${lanes}\n\nThis report is a signed, release-bound record of the declared authorized run. Verify the DSSE bundle with the operator's independently distributed public key, the exact credential-free manifest, and the exact release artifact.\n`;
}

function signStatement(statement: InTotoStatement, key: KeyObject, keyId: string): DsseEnvelope {
  const payloadType = "application/vnd.in-toto+json" as const;
  const payload = Buffer.from(canonical(statement));
  return { payloadType, payload: payload.toString("base64"), signatures: [{ keyid: keyId, sig: sign(null, pae(payloadType, payload), key).toString("base64") }] };
}
function pae(type: string, payload: Buffer): Buffer { return Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${payload.byteLength} ${payload.toString("utf8")}`, "utf8"); }
function loadPrivateKey(value: string): KeyObject { try { return createPrivateKey(value.includes("BEGIN") ? value : Buffer.from(value, "base64")); } catch { throw new Error("EXTERNAL_ACCEPTANCE_SIGNING_KEY_INVALID"); } }
function publicKeyId(key: KeyObject): string { return digest(key.export({ format: "der", type: "spki" })); }
function resolveSecrets(mapping: Record<string, string>, environment: NodeJS.ProcessEnv): Record<string, string> { return Object.fromEntries(Object.entries(mapping).map(([alias, variable]) => { const value = environment[variable]; if (!value) throw new Error(`EXTERNAL_ACCEPTANCE_SECRET_MISSING:${variable}`); return [alias, value]; })); }
function expand(value: unknown, secrets: Record<string, string>, captures: Map<string, string>): unknown { if (typeof value === "string") return expandString(value, secrets, captures); if (Array.isArray(value)) return value.map((item) => expand(item, secrets, captures)); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, expand(item, secrets, captures)])); return value; }
function expandString(value: string, secrets: Record<string, string>, captures: Map<string, string>): string { return value.replace(/\{\{(SECRET|CAPTURE):([A-Za-z0-9._-]+)\}\}/g, (_all, kind: string, name: string) => { const result = kind === "SECRET" ? secrets[name] : captures.get(name); if (result === undefined) throw new Error(`EXTERNAL_ACCEPTANCE_TEMPLATE_VALUE_MISSING:${kind}:${name}`); return result; }); }
function valueAt(value: unknown, path: string): unknown { let current = value; for (const segment of path.split(".")) { if (current === null || current === undefined || typeof current !== "object") return undefined; current = (current as Record<string, unknown>)[segment]; } return current; }
function deepEqual(left: unknown, right: unknown): boolean { return canonical(left) === canonical(right); }
function canonical(value: unknown, omitUndefined = false): string { return JSON.stringify(sortValue(value, omitUndefined)); }
function sortValue(value: unknown, omitUndefined: boolean): unknown { if (Array.isArray(value)) return value.map((item) => sortValue(item, omitUndefined)); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).filter(([, item]) => !omitUndefined || item !== undefined).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, sortValue(item, omitUndefined)])); return value; }
function digest(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }
function canonicalOrigin(value: string): string { const url = new URL(value); if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) throw new Error("EXTERNAL_ACCEPTANCE_ORIGIN_INVALID"); if (url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "localhost", "::1", "[::1]"].includes(url.hostname))) throw new Error("EXTERNAL_ACCEPTANCE_ORIGIN_NOT_HTTPS_OR_LOOPBACK"); return url.origin; }
function findHeader(headers: Record<string, string>, name: string): string | undefined { return Object.keys(headers).find((item) => item.toLowerCase() === name.toLowerCase()); }
function hasHeader(headers: Record<string, string | string[]>, name: string): boolean { return Object.keys(headers).some((item) => item.toLowerCase() === name.toLowerCase()); }
function redact(value: string, secrets: string[]): string { let result = value; for (const secret of secrets.filter(Boolean).sort((a, b) => b.length - a.length)) result = result.split(secret).join("[REDACTED]"); return result.slice(0, 500); }
function safeReason(error: unknown): string { if (error instanceof z.ZodError) return error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ").slice(0, 1000); return error instanceof Error ? error.message.slice(0, 1000) : "Unknown acceptance failure"; }
function delay(milliseconds: number): Promise<void> { return new Promise((done) => setTimeout(done, milliseconds)); }
function markdownCell(value: string): string { return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll("|", "\\|").replace(/[\r\n]+/g, " "); }

function validateNpmReleaseArtifact(artifact: Buffer, expectedVersion: string): void {
  if (artifact.byteLength > 128 * 1024 * 1024) throw new Error("EXTERNAL_ACCEPTANCE_RELEASE_ARTIFACT_TOO_LARGE");
  let tar: Buffer;
  try { tar = gunzipSync(artifact, { maxOutputLength: 256 * 1024 * 1024 }); }
  catch { throw new Error("EXTERNAL_ACCEPTANCE_RELEASE_ARTIFACT_NOT_GZIP"); }
  let offset = 0;
  let packageJson: Buffer | undefined;
  while (offset + 512 <= tar.byteLength) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((value) => value === 0)) break;
    const name = tarText(header.subarray(0, 100));
    const prefix = tarText(header.subarray(345, 500));
    const path = prefix ? `${prefix}/${name}` : name;
    const rawSize = tarText(header.subarray(124, 136)).trim();
    const size = rawSize ? Number.parseInt(rawSize, 8) : 0;
    if (!Number.isSafeInteger(size) || size < 0 || offset + 512 + size > tar.byteLength) throw new Error("EXTERNAL_ACCEPTANCE_RELEASE_TAR_INVALID");
    if (path === "package/package.json") {
      if (packageJson) throw new Error("EXTERNAL_ACCEPTANCE_RELEASE_PACKAGE_JSON_DUPLICATE");
      if (size > 1024 * 1024) throw new Error("EXTERNAL_ACCEPTANCE_RELEASE_PACKAGE_JSON_TOO_LARGE");
      packageJson = tar.subarray(offset + 512, offset + 512 + size);
    }
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  if (!packageJson) throw new Error("EXTERNAL_ACCEPTANCE_RELEASE_PACKAGE_JSON_MISSING");
  let metadata: Record<string, unknown>;
  try { metadata = JSON.parse(packageJson.toString("utf8")) as Record<string, unknown>; }
  catch { throw new Error("EXTERNAL_ACCEPTANCE_RELEASE_PACKAGE_JSON_INVALID"); }
  const bin = metadata.bin && typeof metadata.bin === "object" && !Array.isArray(metadata.bin) ? metadata.bin as Record<string, unknown> : {};
  if (metadata.name !== "routecairn" || metadata.version !== expectedVersion || bin.routecairn !== "./dist/cli/index.js") throw new Error("EXTERNAL_ACCEPTANCE_RELEASE_PACKAGE_IDENTITY_MISMATCH");
}

async function validateRunningReleaseVersion(expectedVersion: string): Promise<void> {
  let metadata: Record<string, unknown>;
  try { metadata = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8")) as Record<string, unknown>; }
  catch { throw new Error("EXTERNAL_ACCEPTANCE_RUNNING_PACKAGE_METADATA_UNAVAILABLE"); }
  if (metadata.name !== "routecairn" || metadata.version !== expectedVersion) throw new Error("EXTERNAL_ACCEPTANCE_RUNNING_RELEASE_VERSION_MISMATCH");
}

function verifyManifestEvidenceBinding(manifest: ExternalAcceptanceManifest, summary: ExternalAcceptanceSummary): void {
  if (summary.operator.publicKeyId !== manifest.operator.publicKeyId || summary.operator.organization !== manifest.operator.organization || summary.operator.contactSha256 !== digest(manifest.operator.contact.trim().toLowerCase())) throw new Error("EXTERNAL_ACCEPTANCE_OPERATOR_MANIFEST_MISMATCH");
  if (summary.authorization.proofSha256 !== manifest.authorization.proofSha256 || summary.authorization.proofReference !== manifest.authorization.proofReference || summary.authorization.window.startsAt !== manifest.authorization.startsAt || summary.authorization.window.expiresAt !== manifest.authorization.expiresAt) throw new Error("EXTERNAL_ACCEPTANCE_AUTHORIZATION_MANIFEST_MISMATCH");
  const retainedActions = summary.lanes.reduce((sum, lane) => sum + lane.actions.length, 0);
  if (summary.requestCount > retainedActions || (summary.status === "PASSED" && summary.requestCount !== retainedActions)) throw new Error("EXTERNAL_ACCEPTANCE_REQUEST_COUNT_MISMATCH");
  if (summary.status !== (summary.lanes.every((lane) => lane.status === "PASSED") ? "PASSED" : "FAILED")) throw new Error("EXTERNAL_ACCEPTANCE_STATUS_INCONSISTENT");
  for (const declared of manifest.lanes) {
    const actual = summary.lanes.find((lane) => lane.id === declared.id);
    if (!actual || actual.kind !== declared.kind) throw new Error(`EXTERNAL_ACCEPTANCE_LANE_MANIFEST_MISMATCH:${declared.id}`);
    if (actual.targetProduct !== declared.targetProduct || actual.targetVersion !== declared.targetVersion || actual.authProvider !== declared.authProvider || actual.paymentProvider !== declared.paymentProvider || actual.environment !== declared.environment || actual.targetFingerprint !== declared.targetFingerprint || actual.reproductionReference !== declared.reproductionReference || actual.reproductionSha256 !== declared.reproductionSha256) throw new Error(`EXTERNAL_ACCEPTANCE_TARGET_MANIFEST_MISMATCH:${declared.id}`);
    for (const action of actual.actions) {
      const expected = declared.actions.find((item) => item.id === action.id);
      if (!expected || expected.phase !== action.phase || expected.semantic !== action.semantic || expected.caseIdentity !== action.caseIdentity || expected.request.method !== action.request.method || expected.request.origin !== action.request.origin || expected.request.path !== action.request.path) throw new Error(`EXTERNAL_ACCEPTANCE_ACTION_MANIFEST_MISMATCH:${declared.id}:${action.id}`);
    }
    if (actual.status === "PASSED") {
      if (actual.actions.length !== declared.actions.length || actual.actions.some((action) => action.status !== "PASSED")) throw new Error(`EXTERNAL_ACCEPTANCE_PASSED_LANE_INCOMPLETE:${declared.id}`);
      for (const semantic of requiredSemantics[declared.kind]) if (!actual.semantics.includes(semantic)) throw new Error(`EXTERNAL_ACCEPTANCE_SEMANTIC_MISSING:${declared.id}:${semantic}`);
      if (declared.actions.some((action) => action.stateChange) && actual.cleanup !== "VERIFIED") throw new Error(`EXTERNAL_ACCEPTANCE_CLEANUP_UNVERIFIED:${declared.id}`);
    }
  }
}

function tarText(value: Buffer): string { const end = value.indexOf(0); return value.subarray(0, end < 0 ? value.length : end).toString("utf8"); }
