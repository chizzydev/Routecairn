import { z } from "zod";
import { planAssistedReview, assistedReviewInputSchema } from "../assistedReview/AssistedReviewPlanner.js";
import type { AssistedReviewPlan } from "../assistedReview/AssistedReviewTypes.js";
import type { ModuleId, ScanPlannerInput } from "../../core/planning/ScanPlan.js";

const id = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,119}$/);
const field = z.string().regex(/^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)*$/).refine((value) => !value.split(".").some((part) => ["__proto__", "prototype", "constructor"].includes(part)));
const path = z.string().min(1).max(500).refine((value) => value.startsWith("/") && !value.startsWith("//") && !/[?#%\\]/.test(value) && !value.split("/").some((part) => [".", ".."].includes(part)));
const reference = z.object({ workflowId: id, caseId: z.string().regex(/^[a-zA-Z0-9_.:/-]{1,240}$/) }).strict();
export const preHandoverInputSchema = z.object({
  schemaVersion: z.literal(1), assaultId: id, revision: id,
  environment: z.enum(["LOCAL", "TEST", "STAGING"]),
  targetOrigin: z.string().url().refine((value) => new URL(value).origin === value),
  environmentVerification: z.object({ path, field, expected: z.enum(["LOCAL", "TEST", "STAGING"]) }).strict(),
  setup: z.object({ mode: z.literal("SUPPLIED_DISPOSABLE_ACCOUNTS"), accountA: z.object({ path, disposableField: field }).strict(), accountB: z.object({ path, disposableField: field }).strict() }).strict(),
  objects: z.array(z.object({ id, owner: z.enum(["accountA", "accountB"]), path, disposableField: field, ownerField: field, identityField: field, identityFingerprint: z.string().regex(/^[a-f0-9]{64}$/), cases: z.array(reference).min(1).max(100) }).strict()).min(1).max(100),
  invariants: z.array(reference.extend({ invariantId: id })).max(100),
  races: z.array(reference).max(100),
  sequence: z.array(id).min(1).max(30),
  criticalCases: z.array(reference).min(1).max(500),
  regressions: z.array(reference.extend({ previousFindingId: id, fixReference: id, comparisonFingerprint: z.string().regex(/^[a-f0-9]{64}$/) })).max(500).default([]),
  review: assistedReviewInputSchema
}).strict();

export type PreHandoverPlan = Omit<z.infer<typeof preHandoverInputSchema>, "review" | "sequence"> & { review: AssistedReviewPlan; sequence: ModuleId[] };

export function planPreHandover(input: unknown): PreHandoverPlan {
  const value = preHandoverInputSchema.parse(input);
  const review = planAssistedReview(value.review);
  if (value.environmentVerification.expected !== value.environment) throw new Error("PRE_HANDOVER_ENVIRONMENT_MISMATCH");
  if (!review.requireVerifiedIdentity || !review.requireAccountPair || !review.requireNoBlocked || !review.requireNoInconclusive) throw new Error("PRE_HANDOVER_STRICT_REVIEW_REQUIRED");
  const cases = new Set(review.cases.map(caseKey));
  const refs = [...value.criticalCases, ...value.invariants, ...value.races, ...value.regressions, ...value.objects.flatMap((object) => object.cases)];
  if (refs.some((ref) => !cases.has(caseKey(ref)))) throw new Error("PRE_HANDOVER_UNTRACKED_CASE");
  if (new Set(value.objects.map((object) => object.id)).size !== value.objects.length || new Set(value.sequence).size !== value.sequence.length) throw new Error("PRE_HANDOVER_DUPLICATE_REGISTRY_ENTRY");
  if (value.sequence.some((module) => !review.cases.some((ref) => ref.workflowId === module)) || review.cases.some((ref) => !value.sequence.includes(ref.workflowId))) throw new Error("PRE_HANDOVER_SEQUENCE_INCOMPLETE");
  if (value.invariants.some((ref) => ref.workflowId !== "business-invariant") || value.races.some((ref) => ref.workflowId !== "controlled-race")) throw new Error("PRE_HANDOVER_REGISTRY_MODULE_MISMATCH");
  for (const entries of [value.criticalCases.map(caseKey), value.races.map(caseKey), value.regressions.map(caseKey), value.invariants.map((ref) => `${caseKey(ref)}/${ref.invariantId}`)]) if (new Set(entries).size !== entries.length) throw new Error("PRE_HANDOVER_DUPLICATE_REGISTRY_ENTRY");
  return { ...value, sequence: value.sequence as ModuleId[], review };
}

export function validatePreHandoverBindings(input: ScanPlannerInput): void {
  const plan = input.preHandover;
  if (!plan) { if (input.requestedProfile === "pre-handover") throw new Error("PRE_HANDOVER_MANIFEST_REQUIRED"); return; }
  if (input.requestedProfile !== "pre-handover" || input.targetAuthorization?.mode !== "PRE_HANDOVER_ASSAULT" || input.targetAuthorization.targetOrigin !== plan.targetOrigin) throw new Error("PRE_HANDOVER_TARGET_AUTHORIZATION_REQUIRED");
  if (!input.authProfileSet || !input.authProfileSet.accountA.principalId || !input.authProfileSet.accountB.principalId || input.authProfileSet.accountA.principalId === input.authProfileSet.accountB.principalId) throw new Error("PRE_HANDOVER_DISTINCT_DECLARED_ACTORS_REQUIRED");
  for (const ref of plan.invariants) if (!input.businessInvariant?.cases.some((item) => item.id === ref.caseId && item.invariants.some((invariant) => invariant.id === ref.invariantId))) throw new Error("PRE_HANDOVER_INVARIANT_NOT_CONFIGURED");
  for (const ref of plan.races) if (!input.controlledRace?.cases.some((item) => item.id === ref.caseId)) throw new Error("PRE_HANDOVER_RACE_NOT_CONFIGURED");
  for (const testCase of input.businessInvariant?.cases ?? []) if (!plan.invariants.some((ref) => ref.caseId === testCase.id)) throw new Error("PRE_HANDOVER_INVARIANT_NOT_REGISTERED");
  for (const testCase of input.controlledRace?.cases ?? []) if (!plan.races.some((ref) => ref.caseId === testCase.id)) throw new Error("PRE_HANDOVER_RACE_NOT_REGISTERED");
  const inventory: Array<[string, readonly { id: string }[] | undefined]> = [
    ["authentication-lifecycle", input.authenticationLifecycle?.cases], ["business-invariant", input.businessInvariant?.cases],
    ["controlled-race", input.controlledRace?.cases], ["supabase-authorization", input.supabaseAuthorization?.cases],
    ["api-graphql-authorization", input.apiGraphql?.checks], ["link-portal-export-security", input.linkPortalSecurity?.cases],
    ["operational-endpoint-security", input.operationalEndpointSecurity?.cases], ["billing-entitlement-security", input.billingEntitlement?.cases],
    ["privilege-mutation-testing", input.privilegeMutationTesting?.cases.map((item) => ({ id: item.caseId }))]
  ];
  for (const [workflowId, cases] of inventory) for (const item of cases ?? []) if (!plan.review.cases.some((ref) => ref.workflowId === workflowId && ref.caseId === item.id)) throw new Error("PRE_HANDOVER_EXECUTABLE_CASE_NOT_IN_REVIEW");
}

export function caseKey(ref: { workflowId: string; caseId: string }): string { return `${ref.workflowId}/${ref.caseId}`; }
