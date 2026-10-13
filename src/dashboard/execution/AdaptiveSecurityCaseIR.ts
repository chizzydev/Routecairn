import { createHash } from "node:crypto";
import { z } from "zod";

export const securityCaseIdPurpose = "routecairn-security-case-ir-v1";
export const securityCaseBounds = Object.freeze({ pathLength: 500, graphPaths: 32, sourceCases: 32, bindings: 32, methods: 16, requests: 100_000 });
export const securityCaseFingerprintSchema = z.string().regex(/^[a-f0-9]{64}$/);
const fingerprints = z.array(securityCaseFingerprintSchema).min(1).max(securityCaseBounds.sourceCases);
export const securityCaseOriginSchema = z.string().min(1).max(300).refine((value) => {
  try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) && !url.username && !url.password && value === url.origin; }
  catch { return false; }
}, "A normalized HTTP origin is required.");

/** Already normalized templates only; never strip a query, clip a label or replace a concrete identity. */
export const securityCasePathSchema = z.string().min(1).max(securityCaseBounds.pathLength).refine((path) => {
  if (!/^\/[A-Za-z0-9._~:/-]*$/.test(path) || path.includes("//")) return false;
  const segments = path.split("/");
  if (segments.some((segment) => segment === "." || segment === ".." || /^\d{2,}$/.test(segment) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(segment) || /^[A-Za-z0-9_-]{32,}$/.test(segment))) return false;
  return segments.every((segment, index) => !/^(?:tokens?|secrets?|reset-password|password-reset|verify-email|magic-link)$/i.test(segment) || !segments[index + 1] || segments[index + 1] === ":token");
}, "An identity-safe path template is required.");
export const securityCaseMethodSchema = z.enum(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"]);
export const securityCaseSourceSchema = z.object({
  category: z.string().min(1).max(128).regex(/^[A-Z][A-Z0-9_]*$/).refine((value) => !/^[A-F0-9]{32,}$/.test(value)),
  engineId: z.string().min(1).max(80).regex(/^[a-z][a-z0-9-]*$/).refine((value) => !/^[a-f0-9]{32,}$/.test(value)),
  laneKind: z.enum(["PUBLIC_BASELINE", "AUTHENTICATED_IDENTITY", "ACCOUNT_PAIR_AUTHORIZATION", "BROWSER_LEARNING", "AUTHENTICATION_LIFECYCLE", "API_GRAPHQL_AUTHORIZATION", "DATA_AUTHORIZATION", "BUSINESS_LOGIC", "OPERATIONAL_ENDPOINTS", "BILLING_ENTITLEMENTS", "MUTATION_ACCEPTANCE", "RECOVERY_ACCEPTANCE", "MULTI_TENANT_APPLICATION", "SUPABASE_RLS_STORAGE_RPC", "OAUTH_MFA_PASSKEYS", "GRAPHQL_AUTHORIZATION", "SIGNED_PORTALS_EXPORTS", "SYNTHETIC_PAYMENT_PROVIDER", "WEBHOOKS_CRON", "REMEDIATION_RERUNS", "CUSTOM"]),
  sourceFingerprint: securityCaseFingerprintSchema
}).strict();

export const securityCaseSubjectSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("ROUTE"), pathTemplate: securityCasePathSchema, protocol: z.enum(["REST", "GRAPHQL"]).optional(), methods: z.array(securityCaseMethodSchema).min(1).max(securityCaseBounds.methods).optional() }).strict(),
  z.object({ kind: z.literal("EXACT_SOURCE_CONTRACT"), sourceCaseFingerprints: fingerprints }).strict(),
  z.object({ kind: z.literal("GRAPH_PATH"), pathId: securityCaseFingerprintSchema, mutability: z.enum(["READ_ONLY", "STATE_CHANGING"]) }).strict(),
  z.object({ kind: z.literal("UNRESOLVED"), reason: z.enum(["NO_SUBJECT_EVIDENCE", "ROUTE_ORIGIN_UNKNOWN", "DRIFT_REVIEW"]) }).strict()
]);
const evidenceStrength = z.enum(["EXACT_ANONYMOUS_RESPONSE", "EXACT_ENGINE_OBSERVATION", "EXACT_EXECUTED_CONTRACT"]);
const compilerMetadata = {
  metadataOnly: z.literal(true), compilerVersion: z.union([z.literal(1), z.literal(2)]),
  evidenceStrength, evidenceFingerprint: securityCaseFingerprintSchema,
  requestCount: z.number().int().min(1).max(securityCaseBounds.requests),
  cleanupRequestCount: z.number().int().min(0).max(securityCaseBounds.requests)
};
export const securityCaseReadinessSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("REQUIRES_BINDINGS"), metadataOnly: z.literal(true), compilerVersion: z.literal(1) }).strict(),
  z.object({ kind: z.literal("READY_READ_ONLY"), ...compilerMetadata }).strict(),
  z.object({ kind: z.literal("READY_APPROVAL_GATED"), ...compilerMetadata, compilerVersion: z.literal(2) }).strict()
]);
export const securityCaseBindingNameSchema = z.enum([
  "ACTOR_BINDING", "ACTOR_TENANT_IDENTITIES", "OBJECT_IDENTITIES", "SENSITIVE_COLUMNS", "CLEANUP_BINDING", "CLEANUP_OR_DISPOSABLE_PROOF", "EXPECTED_EFFECT", "ANONYMOUS_RESPONSE_CONTRACT", "RESPONSE_CONTRACT",
  "DISPOSABLE_ACTOR", "EXACT_ASSERTIONS", "EXPIRING_AUTHORIZATION", "VERIFIED_CLEANUP", "TOKEN_FIXTURE", "BOUNDED_WAIT", "ACTOR_OBJECT_IDENTITIES", "EXPECTED_DECISIONS", "RESPONSE_FIELD_RULES", "PRE_STATE", "BOUNDED_ACTIONS", "EXPECTED_INVARIANT", "POST_STATE", "RESOURCE_OWNER", "TENANT_BINDING", "EXPIRY", "TAMPER_REPLAY_ASSERTIONS", "ENDPOINT_KIND", "AUTHORIZED_ACTOR", "AUTH_EXPECTATION", "WORKLOAD_BOUNDS", "TEST_PROVIDER_FIXTURE", "SYNTHETIC_EVENT", "ACCOUNT_OWNERSHIP", "ENTITLEMENT_VERIFICATION", "NAMED_OPERATION", "ACTOR_MATRIX", "FIELD_EXPECTATIONS", "TENANT_EXPECTATION", "EXACT_EXECUTION_CONTRACT", "OPERATOR_REVIEW", "EXACT_REGRESSION_CASE", "AUTHORITATIVE_OUTCOME", "CONCLUSIVE_EVIDENCE", "EXACT_PRECONDITION", "VERIFIED_EFFECT", "COMPLETE_GRAPH_PATH", "CAPTURE_PRODUCER", "UNCLASSIFIED_BINDING"
]);
const graphBinding = z.object({ fingerprint: securityCaseFingerprintSchema, pathIds: z.array(securityCaseFingerprintSchema).min(1).max(securityCaseBounds.graphPaths) }).strict();
const caseShape = z.object({
  schemaVersion: z.literal(1), caseId: securityCaseFingerprintSchema, targetOrigin: securityCaseOriginSchema,
  source: securityCaseSourceSchema,
  proposition: z.object({ kind: z.enum(["AUTHORIZATION", "LIFECYCLE", "CAPABILITY", "BUSINESS_INVARIANT", "BILLING", "OPERATIONAL", "DRIFT", "GRAPH_TRANSITION", "OTHER"]) }).strict(),
  subject: securityCaseSubjectSchema,
  actors: z.enum(["ANONYMOUS", "PRIMARY_FIXTURE_REQUIRED", "ACCOUNT_PAIR_REQUIRED", "UNKNOWN"]),
  observation: z.discriminatedUnion("kind", [
    z.object({ kind: z.literal("EXACT_COMPILER_EVIDENCE"), evidenceStrength, vulnerabilityConclusion: z.literal("NOT_ASSESSED") }).strict(),
    z.object({ kind: z.literal("OBSERVED"), vulnerabilityConclusion: z.literal("NOT_ASSESSED") }).strict(),
    z.object({ kind: z.literal("DECLARED"), vulnerabilityConclusion: z.literal("NOT_ASSESSED") }).strict(),
    z.object({ kind: z.literal("HYPOTHESIZED"), vulnerabilityConclusion: z.literal("NOT_ASSESSED") }).strict()
  ]),
  provenance: z.object({ sourceFingerprint: securityCaseFingerprintSchema, evidenceFingerprint: securityCaseFingerprintSchema.optional(), graph: graphBinding.optional(), sourceCaseFingerprints: fingerprints.optional() }).strict(),
  readiness: securityCaseReadinessSchema,
  safety: z.object({ mutationHypothesis: z.boolean(), operatorApprovalRequired: z.boolean(), executionAuthority: z.literal("NONE"), approval: z.literal("NOT_GRANTED"), cleanup: z.literal("NOT_ASSESSED") }).strict(),
  executable: z.literal(false), unresolvedBindings: z.array(securityCaseBindingNameSchema).max(securityCaseBounds.bindings)
}).strict();

const identitySchema = caseShape.pick({ targetOrigin: true, source: true, subject: true });
export type SecurityCaseIdentityV1 = z.infer<typeof identitySchema>;

/** Only validated allowlist fields enter this new domain. Existing adaptive fingerprints are untouched. */
export function securityCaseIdentityPreimage(identity: SecurityCaseIdentityV1): string {
  const value = identitySchema.parse(identity);
  return JSON.stringify(canonical({ purpose: securityCaseIdPurpose, targetOrigin: value.targetOrigin, source: value.source, subject: value.subject }));
}
export function securityCaseIdV1(identity: SecurityCaseIdentityV1): string {
  return createHash("sha256").update(securityCaseIdentityPreimage(identity), "utf8").digest("hex");
}
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, child]) => [key, canonical(child)]));
}

export const securityCaseV1Schema = caseShape.superRefine((value, context) => {
  const invalid = () => context.addIssue({ code: z.ZodIssueCode.custom, message: "SecurityCase shadow metadata is inconsistent." });
  const identity = identitySchema.safeParse({ targetOrigin: value.targetOrigin, source: value.source, subject: value.subject });
  if (!identity.success) { invalid(); return; }
  if (value.caseId !== securityCaseIdV1(identity.data) || value.provenance.sourceFingerprint !== value.source.sourceFingerprint) invalid();
  if (value.provenance.graph && new Set(value.provenance.graph.pathIds).size !== value.provenance.graph.pathIds.length) invalid();
  if (value.subject.kind === "GRAPH_PATH" && !value.provenance.graph?.pathIds.includes(value.subject.pathId)) invalid();
  if (value.subject.kind === "EXACT_SOURCE_CONTRACT" && (value.subject.sourceCaseFingerprints.some((id) => !value.provenance.sourceCaseFingerprints?.includes(id)) || value.readiness.kind === "REQUIRES_BINDINGS" || value.readiness.compilerVersion !== 2)) invalid();
  if (value.readiness.kind === "REQUIRES_BINDINGS") {
    if (value.observation.kind === "EXACT_COMPILER_EVIDENCE" || value.provenance.evidenceFingerprint || value.actors !== "UNKNOWN" || !value.safety.operatorApprovalRequired) invalid();
  } else {
    if (value.observation.kind !== "EXACT_COMPILER_EVIDENCE" || value.observation.evidenceStrength !== value.readiness.evidenceStrength || value.provenance.evidenceFingerprint !== value.readiness.evidenceFingerprint || value.unresolvedBindings.length || value.actors === "UNKNOWN") invalid();
    if (value.readiness.cleanupRequestCount > value.readiness.requestCount) invalid();
    if (value.readiness.compilerVersion === 1 && (value.readiness.evidenceStrength === "EXACT_EXECUTED_CONTRACT" || value.actors !== "ANONYMOUS" || value.readiness.cleanupRequestCount !== 0)) invalid();
    if (value.readiness.compilerVersion === 2 && value.readiness.evidenceStrength !== "EXACT_EXECUTED_CONTRACT") invalid();
    const mutation = value.readiness.kind === "READY_APPROVAL_GATED";
    if (value.safety.mutationHypothesis !== mutation || value.safety.operatorApprovalRequired !== mutation || (!mutation && value.readiness.cleanupRequestCount !== 0)) invalid();
  }
  if (value.subject.kind === "GRAPH_PATH" && (value.subject.mutability === "STATE_CHANGING") !== value.safety.mutationHypothesis) invalid();
});
export type SecurityCaseV1 = z.infer<typeof securityCaseV1Schema>;
export function parseSecurityCaseV1(input: unknown): SecurityCaseV1 { return securityCaseV1Schema.parse(input); }

export const projectionDiagnosticSchema = z.object({ inputIndex: z.number().int().nonnegative(), code: z.enum(["INVALID_TARGET", "INVALID_SOURCE", "INVALID_READINESS", "INVALID_GRAPH_BINDING", "INVALID_PROVENANCE", "INVALID_SUBJECT", "INVALID_BOUNDS", "INVALID_CASE"]) }).strict();
export type ProjectionDiagnostic = z.infer<typeof projectionDiagnosticSchema>;
