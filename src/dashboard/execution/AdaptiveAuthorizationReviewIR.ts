import { createHash } from "node:crypto";
import { z } from "zod";
import { securityCaseFingerprintSchema as fingerprint, securityCaseOriginSchema } from "./AdaptiveSecurityCaseIR.js";

export const authorizationReviewPurpose = "routecairn-authorization-review-v1";
export const authorizationReviewBounds = Object.freeze({ cases: 500, relationshipsPerCase: 32, questionsPerCase: 32, totalQuestions: 10_000 });
export const authorizationRequirementSchema = z.enum(["ACTOR_FIXTURE", "EXACT_TARGET_RESOURCE", "EXPECTED_ALLOW_DENY", "OWNERSHIP_VERIFICATION", "TENANT_VERIFICATION", "ROLE_EXPECTATION", "COMPARISON_PAIR", "EXACT_REQUEST_CONTRACT", "AUTHORIZATION_SCOPE", "MUTATION_APPROVAL", "POST_STATE_ASSERTIONS", "VERIFIED_CLEANUP"]);
export type AuthorizationRequirement = z.infer<typeof authorizationRequirementSchema>;
const referencesSchema = z.object({ graphFingerprint: fingerprint.optional(), graphPathId: fingerprint.optional(), actorNodeId: fingerprint.optional(), operationNodeId: fingerprint.optional(), roleNodeId: fingerprint.optional(), tenantNodeId: fingerprint.optional(), objectNodeId: fingerprint.optional(), relationshipEdgeIds: z.array(fingerprint).min(1).max(2).optional() }).strict();
const shape = z.object({
  schemaVersion: z.literal(1), questionId: fingerprint, targetOrigin: securityCaseOriginSchema, sourceCaseId: fingerprint,
  questionKind: z.enum(["ACTOR_OPERATION_BOUNDARY", "ROLE_BOUNDARY", "TENANT_BOUNDARY", "OBJECT_OWNERSHIP_BOUNDARY", "UNRESOLVED_AUTHORIZATION_BOUNDARY"]),
  references: referencesSchema, evidenceBasis: z.enum(["DECLARED_CONTRACT", "OBSERVED", "EXACT_EXECUTED_CONTRACT", "MIXED", "UNRESOLVED"]),
  expectedDecision: z.literal("UNKNOWN"), expectedOwnership: z.literal("UNKNOWN"), vulnerabilityConclusion: z.literal("NOT_ASSESSED"), status: z.literal("REQUIRES_OPERATOR_CASE"),
  missingRequirements: z.array(authorizationRequirementSchema).min(1).max(12), executable: z.literal(false), executionAuthority: z.literal("NONE"), operatorApproval: z.literal("NOT_GRANTED"), cleanup: z.literal("NOT_ASSESSED")
}).strict();
const identitySchema = shape.pick({ targetOrigin: true, sourceCaseId: true, questionKind: true, references: true });
export type AuthorizationReviewIdentity = z.infer<typeof identitySchema>;
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => [key, canonical(item)]));
}
/** Identity contains normalized origin and opaque references only; meaningful arrays preserve order. */
export function authorizationReviewIdentityPreimage(input: AuthorizationReviewIdentity): string { const parsed = identitySchema.safeParse(input); if (!parsed.success) throw new Error("INVALID_AUTHORIZATION_REVIEW_IDENTITY"); return JSON.stringify(canonical({ purpose: authorizationReviewPurpose, ...parsed.data })); }
export function authorizationReviewQuestionId(input: AuthorizationReviewIdentity): string { return createHash("sha256").update(authorizationReviewIdentityPreimage(input), "utf8").digest("hex"); }
export const authorizationReviewQuestionV1Schema = shape.superRefine((value, context) => {
  const invalid = () => context.addIssue({ code: z.ZodIssueCode.custom, message: "Authorization review metadata is inconsistent." });
  const identity = identitySchema.safeParse({ targetOrigin: value.targetOrigin, sourceCaseId: value.sourceCaseId, questionKind: value.questionKind, references: value.references });
  if (!identity.success || value.questionId !== authorizationReviewQuestionId(identity.data)) { invalid(); return; }
  const ordered = (items: readonly string[]) => items.every((item, index) => !index || items[index - 1]! < item);
  if (!ordered(value.missingRequirements) || (value.references.relationshipEdgeIds && !ordered(value.references.relationshipEdgeIds))) invalid();
  const required = ["ACTOR_FIXTURE", "EXACT_TARGET_RESOURCE", "EXPECTED_ALLOW_DENY", "EXACT_REQUEST_CONTRACT", "AUTHORIZATION_SCOPE"];
  const r = value.references;
  if (value.questionKind === "UNRESOLVED_AUTHORIZATION_BOUNDARY") {
    if (Object.keys(r).length || value.evidenceBasis !== "UNRESOLVED") invalid();
    required.push("OWNERSHIP_VERIFICATION", "TENANT_VERIFICATION", "COMPARISON_PAIR");
  } else {
    const specific = value.questionKind === "ROLE_BOUNDARY" ? "roleNodeId" : value.questionKind === "TENANT_BOUNDARY" ? "tenantNodeId" : value.questionKind === "OBJECT_OWNERSHIP_BOUNDARY" ? "objectNodeId" : undefined;
    if (!r.graphFingerprint || !r.graphPathId || !r.actorNodeId || !r.operationNodeId || value.evidenceBasis === "UNRESOLVED" || r.relationshipEdgeIds?.length !== (specific ? 2 : 1)) invalid();
    for (const key of ["roleNodeId", "tenantNodeId", "objectNodeId"] as const) if (key === specific ? !r[key] : r[key] !== undefined) invalid();
    if (specific) required.push(specific === "roleNodeId" ? "ROLE_EXPECTATION" : specific === "tenantNodeId" ? "TENANT_VERIFICATION" : "OWNERSHIP_VERIFICATION", "COMPARISON_PAIR");
  }
  if (required.some((item) => !value.missingRequirements.includes(item as AuthorizationRequirement))) invalid();
  const mutation = ["MUTATION_APPROVAL", "POST_STATE_ASSERTIONS", "VERIFIED_CLEANUP"];
  if (mutation.some((item) => value.missingRequirements.includes(item as AuthorizationRequirement)) && mutation.some((item) => !value.missingRequirements.includes(item as AuthorizationRequirement))) invalid();
});
export type AuthorizationReviewQuestionV1 = z.infer<typeof authorizationReviewQuestionV1Schema>;
export const authorizationReviewDiagnosticSchema = z.object({ inputIndex: z.number().int().nonnegative(), sourceCaseId: fingerprint.optional(), code: z.enum(["NO_ELIGIBLE_RELATIONSHIP", "INVALID_GRAPH", "INVALID_RELATIONSHIP", "INPUT_LIMIT", "RELATIONSHIP_LIMIT", "OUTPUT_LIMIT", "INVALID_QUESTION"]) }).strict();
export type AuthorizationReviewDiagnostic = z.infer<typeof authorizationReviewDiagnosticSchema>;
