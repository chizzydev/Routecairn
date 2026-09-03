import { createHash } from "node:crypto";
import { authHeadersForProfile } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import { bodyPreviewForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { AssistedReviewCase } from "../assistedReview/AssistedReviewTypes.js";
import { caseKey, type PreHandoverPlan } from "./PreHandoverPlanner.js";

export interface PreHandoverReadiness {
  assaultId: string; revision: string; environment: string;
  objectCount: number; invariantCount: number; raceCount: number;
  sequence: readonly string[];
  criticalCoverage: readonly { workflowId: string; caseId: string; passed: boolean }[];
  regressions: readonly { previousFindingId: string; fixReference: string; passed: boolean }[];
  blockers: readonly string[];
}

/** Read-only setup attestation. The profile never grants permission to provision or mutate accounts. */
export async function verifyPreHandoverSetup(context: ScanContext): Promise<void> {
  const plan = context.options.plan.preHandover;
  if (!plan) return;
  if (new URL(context.options.target).origin !== plan.targetOrigin || !context.state.getIdentityVerification()?.distinctVerifiedPrincipals) throw new Error("PRE_HANDOVER_VERIFIED_ACTOR_PAIR_REQUIRED");
  const read = async (path: string, actor?: "accountA" | "accountB"): Promise<unknown> => {
    const response = await context.httpClient.send({ url: new URL(path, plan.targetOrigin).href, method: "GET", skipCache: true, disableRedirects: true, disableRetries: true, ...(actor ? { headers: authHeadersForProfile(context.options.authProfileSet![actor]) } : {}) });
    if (response.error || response.statusCode !== 200 || response.streamTruncated || !response.contentType?.includes("application/json")) throw new Error("PRE_HANDOVER_SETUP_VERIFICATION_UNAVAILABLE");
    try { return JSON.parse(bodyPreviewForAnalysis(response) ?? ""); } catch { throw new Error("PRE_HANDOVER_SETUP_VERIFICATION_INVALID"); }
  };
  const environment = await read(plan.environmentVerification.path);
  if (getField(environment, plan.environmentVerification.field) !== plan.environment) throw new Error("PRE_HANDOVER_ENVIRONMENT_NOT_VERIFIED");
  for (const actor of ["accountA", "accountB"] as const) {
    if (getField(await read(plan.setup[actor].path, actor), plan.setup[actor].disposableField) !== true) throw new Error("PRE_HANDOVER_ACCOUNT_NOT_DISPOSABLE");
  }
  for (const object of plan.objects) {
    const value = await read(object.path, object.owner);
    if (getField(value, object.disposableField) !== true || getField(value, object.ownerField) !== context.options.authProfileSet![object.owner].principalId || disposableIdentityFingerprint(getField(value, object.identityField)) !== object.identityFingerprint) throw new Error("PRE_HANDOVER_OBJECT_OWNERSHIP_NOT_VERIFIED");
  }
  await context.eventSink.emit({ type: "OBSERVATION_RECORDED", message: "Pre-handover environment, disposable actors and object ownership verified.", metadata: { assaultId: plan.assaultId, objectCount: plan.objects.length, revision: plan.revision } });
}

export function preHandoverReadiness(plan: PreHandoverPlan, cases: readonly AssistedReviewCase[]): PreHandoverReadiness {
  const exact = (ref: { workflowId: string; caseId: string }) => cases.filter((item) => caseKey(item) === caseKey(ref));
  const passed = (ref: { workflowId: string; caseId: string }) => { const matches = exact(ref); return matches.length === 1 && matches[0]!.assessmentOutcome === "PROVEN" && matches[0]!.conclusion === "NO_FINDING" && !matches[0]!.cleanupFailed; };
  const criticalCoverage = plan.criticalCases.map((ref) => ({ ...ref, passed: passed(ref) }));
  const regressions = plan.regressions.map((ref) => ({ previousFindingId: ref.previousFindingId, fixReference: ref.fixReference, passed: passed(ref) && exact(ref)[0]?.comparisonFingerprint === ref.comparisonFingerprint }));
  const blockers = [...(criticalCoverage.some((item) => !item.passed) ? ["PRE_HANDOVER_CRITICAL_WORKFLOW_UNPROVEN"] : []), ...(regressions.some((item) => !item.passed) ? ["PRE_HANDOVER_REGRESSION_UNPROVEN"] : []), ...(cases.some((item) => item.cleanupFailed) ? ["CLEANUP_UNRESOLVED"] : [])];
  return { assaultId: plan.assaultId, revision: plan.revision, environment: plan.environment, objectCount: plan.objects.length, invariantCount: plan.invariants.length, raceCount: plan.races.length, sequence: plan.sequence, criticalCoverage, regressions, blockers };
}

export function disposableIdentityFingerprint(value: unknown): string { return createHash("sha256").update(`routecairn-disposable-v1\0${JSON.stringify(value)}`).digest("hex"); }
function getField(value: unknown, path: string): unknown { return path.split(".").reduce<unknown>((current, part) => current && typeof current === "object" && Object.hasOwn(current, part) ? (current as Record<string, unknown>)[part] : undefined, value); }
