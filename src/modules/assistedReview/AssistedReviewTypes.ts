import type { AssistedAssessmentOutcome } from "../../core/findings/Finding.js";

export const assistedReviewLanes = ["BROWSER", "API", "AUTH_LIFECYCLE", "AUTHORIZATION", "PAYMENT_ENTITLEMENT"] as const;
export type AssistedReviewLane = (typeof assistedReviewLanes)[number];

export interface AssistedReviewPlan {
  schemaVersion: 1;
  reviewId: string;
  title: string;
  focus: readonly AssistedReviewLane[];
  requiredLanes: readonly AssistedReviewLane[];
  cases: readonly { workflowId: string; caseId: string; lane: AssistedReviewLane }[];
  requireVerifiedIdentity: boolean;
  requireAccountPair: boolean;
  requireNoBlocked: boolean;
  requireNoInconclusive: boolean;
  requireHumanReviewForFindings: true;
  customerName?: string;
  notes: readonly string[];
}

export interface AssistedReviewCase {
  lane: AssistedReviewLane;
  workflowId: string;
  caseId: string;
  label: string;
  assessmentOutcome: AssistedAssessmentOutcome;
  conclusion: "FINDING" | "NO_FINDING" | "UNRESOLVED" | "NOT_RUN";
  cleanupOutcome?: string;
  cleanupFailed: boolean;
  comparisonFingerprint?: string;
  evidenceRefs: readonly string[];
  proofPackRefs: readonly string[];
}
