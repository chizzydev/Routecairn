import type { AuthenticationLifecycleCategory } from "../modules/authenticationLifecycle/AuthenticationLifecycleTypes.js";

export type LifecycleCaseOutcome = "PASS" | "FAIL" | "INCONCLUSIVE" | "BLOCKED";
export type LifecycleCleanupOutcome = "NOT_REQUIRED" | "ROLLBACK_VERIFIED" | "CLEANUP_FAILED" | "CLEANUP_NOT_REACHED";

export interface LifecycleAssertionObservation {
  kind: string;
  matched: boolean;
  reasonCode: string;
}

export interface LifecycleStepObservation {
  stepId: string;
  phase: "SETUP" | "ACTION" | "VERIFY" | "CLEANUP";
  actorAlias: string;
  method: string;
  url: string;
  stateChanging: boolean;
  transmitted: boolean;
  statusCode?: number;
  contentType?: string;
  responseLengthBand?: string;
  responseShapeFingerprint?: string;
  capturesRecorded: string[];
  assertions: LifecycleAssertionObservation[];
  outcome: "PASS" | "FAIL" | "INCONCLUSIVE" | "BLOCKED";
  reasonCode?: string;
}

export interface AuthenticationLifecycleCaseObservation {
  caseId: string;
  label: string;
  category: AuthenticationLifecycleCategory;
  actorModel: Array<{ safeAlias: string; authSlot: string; requestAuthentication: "NONE" | "PROFILE"; relationship: string; declaredState: string; tenantAlias?: string }>;
  outcome: LifecycleCaseOutcome;
  cleanupOutcome: LifecycleCleanupOutcome;
  comparisonFingerprint: string;
  steps: LifecycleStepObservation[];
  notes: string[];
}

export interface AuthenticationLifecycleReport {
  enabled: boolean;
  plannedCases: number;
  executedCases: number;
  passedCases: number;
  failedCases: number;
  inconclusiveCases: number;
  blockedCases: number;
  cleanupRequired: number;
  cleanupFailed: number;
  learningAutomation?: {
    source: "BROWSER_LEARNED";
    sourceCandidateId?: string;
    requestedCategories: AuthenticationLifecycleCategory[];
    generatedCategories: AuthenticationLifecycleCategory[];
    blockers: Array<{ category: AuthenticationLifecycleCategory; reasons: string[] }>;
    artifactPath: string;
    secretsStored: false;
  };
  observations: AuthenticationLifecycleCaseObservation[];
  coverage: Record<AuthenticationLifecycleCategory, { planned: number; executed: number; passed: number; failed: number }>;
  notes: string[];
}
