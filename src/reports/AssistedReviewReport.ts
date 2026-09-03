import type { AssistedAssessmentOutcome } from "../core/findings/Finding.js";
import type { AssistedReviewCase, AssistedReviewLane } from "../modules/assistedReview/AssistedReviewTypes.js";

export interface AssistedReviewReport {
  preHandover?: import("../modules/preHandover/PreHandoverRuntime.js").PreHandoverReadiness;
  targetMode?: import("../core/authorization/TargetAuthorization.js").TargetAuthorization["mode"];
  enabled: true;
  schemaVersion: 1;
  reviewId: string;
  title: string;
  focus: readonly AssistedReviewLane[];
  cases: readonly AssistedReviewCase[];
  coverageMatrix: Record<AssistedReviewLane, { selected: boolean; required: boolean; total: number; outcomes: Record<AssistedAssessmentOutcome, number>; cleanupFailures: number }>;
  humanReviewQueue: readonly { findingId: string; workflowId: string; caseId: string; severity: string; evidenceRef: string; proofPackRefs: readonly string[]; state: "PENDING_HUMAN_REVIEW" }[];
  timeline: readonly { sequence: number; lane: AssistedReviewLane; workflowId: string; caseId: string; outcome: AssistedAssessmentOutcome }[];
  evidencePackage: { artifactPath: string; caseCount: number; findingCount: number; rawSecretsStored: false };
  customerSafeReport: { artifactPath: string; findingCount: number; operatorEvidenceIncluded: false };
  remediationRoadmap: readonly { priority: number; findingId: string; title: string; severity: string; customerSafeRemediation: string }[];
  completionGate: { state: "READY" | "AWAITING_HUMAN_REVIEW" | "BLOCKED"; blockers: readonly string[]; humanReviewRequired: true };
  notes: readonly string[];
}
