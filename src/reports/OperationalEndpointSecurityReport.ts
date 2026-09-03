import type { OperationalEndpointCategory, OperationalEndpointKind } from "../modules/operationalEndpointSecurity/OperationalEndpointSecurityTypes.js";

export type OperationalCaseOutcome = "PASS" | "FAIL" | "INCONCLUSIVE" | "BLOCKED";
export type OperationalCleanupOutcome = "NOT_REQUIRED" | "ROLLBACK_VERIFIED" | "CLEANUP_FAILED" | "CLEANUP_NOT_REACHED";
export interface OperationalAssertionObservation { kind: string; matched: boolean; reasonCode: string }
export interface OperationalStepObservation {
  stepId: string; phase: "PRE_STATE" | "ACTION" | "VERIFY" | "CLEANUP"; actorAlias: string; endpointAlias: string; endpointKind: OperationalEndpointKind; pathTemplate: string; method: string; stateChanging: boolean; signed: boolean; signatureTampered: boolean; transmitted: boolean; statusCode?: number; contentType?: string; responseLengthBand?: string; responseShapeFingerprint?: string; responseBodyFingerprint?: string; capturesRecorded: string[]; assertions: OperationalAssertionObservation[]; outcome: OperationalCaseOutcome; reasonCode?: string;
}
export interface OperationalCaseObservation { caseId: string; label: string; category: OperationalEndpointCategory; outcome: OperationalCaseOutcome; cleanupOutcome: OperationalCleanupOutcome; comparisonFingerprint: string; actorAliases: string[]; endpointAliases: string[]; steps: OperationalStepObservation[]; notes: string[] }
export interface OperationalEndpointSecurityReport {
  enabled: boolean; plannedCases: number; executedCases: number; passedCases: number; failedCases: number; inconclusiveCases: number; blockedCases: number; requestsTransmitted: number; requestBudget: number; cleanupRequired: number; cleanupFailed: number;
  endpointInventory: Array<{ safeAlias: string; kind: OperationalEndpointKind; pathTemplate: string; allowedOriginCount: number; workloadLimitDeclared: boolean; declaredWorkloadLimit?: number }>;
  observations: OperationalCaseObservation[];
  coverage: Record<OperationalEndpointCategory, { planned: number; executed: number; passed: number; failed: number }>;
  notes: string[];
}
