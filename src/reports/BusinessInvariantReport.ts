import type { BusinessInvariantCategory, InvariantOutcome } from "../modules/businessInvariant/BusinessInvariantTypes.js";

export type BusinessInvariantCleanupOutcome = "ROLLBACK_VERIFIED" | "CLEANUP_FAILED" | "CLEANUP_NOT_REACHED";

export interface BusinessInvariantActionObservation {
  actionId: string;
  actorAlias: string;
  method: string;
  url: string;
  executionMode: "ONCE" | "SEQUENTIAL_DUPLICATE" | "CONCURRENT_DUPLICATE";
  attemptsPlanned: number;
  attemptsTransmitted: number;
  statusCodes: number[];
  acceptedCount: number;
  rejectedCount: number;
  authorizedCount: number;
  deniedCount: number;
  authorizationExpectationMatched: boolean;
  businessRuleExpectationMatched: boolean;
  responseShapeFingerprints: string[];
  outcome: InvariantOutcome;
  reasonCode: string;
}

export interface BusinessInvariantAssertionObservation {
  invariantId: string;
  kind: string;
  outcome: InvariantOutcome;
  reasonCode: string;
}

export interface BusinessInvariantCaseObservation {
  caseId: string;
  label: string;
  category: BusinessInvariantCategory;
  actorModel: Array<{ safeAlias: string; authSlot: string; requestAuthentication: "NONE" | "PROFILE"; relationship: string; declaredState: string; tenantAlias?: string }>;
  outcome: InvariantOutcome;
  cleanupOutcome: BusinessInvariantCleanupOutcome;
  comparisonFingerprint: string;
  preStateVerified: boolean;
  postStateVerified: boolean;
  actions: BusinessInvariantActionObservation[];
  invariants: BusinessInvariantAssertionObservation[];
  cleanupInvariants: BusinessInvariantAssertionObservation[];
  stateMachine?: BusinessInvariantAssertionObservation;
  notes: string[];
}

export interface BusinessInvariantReport {
  enabled: boolean;
  plannedCases: number;
  executedCases: number;
  passedCases: number;
  failedCases: number;
  inconclusiveCases: number;
  blockedCases: number;
  cleanupRequired: number;
  cleanupFailed: number;
  duplicateAttempts: number;
  concurrentActions: number;
  observations: BusinessInvariantCaseObservation[];
  coverage: Record<BusinessInvariantCategory, { planned: number; executed: number; passed: number; failed: number }>;
  notes: string[];
}
