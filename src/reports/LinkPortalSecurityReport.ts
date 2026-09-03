import type { LinkPortalSecurityCategory, LinkPortalResourceKind } from "../modules/linkPortalSecurity/LinkPortalSecurityTypes.js";

export type LinkPortalOutcome = "PASS" | "FAIL" | "INCONCLUSIVE" | "BLOCKED";
export type LinkPortalCleanupOutcome = "NOT_REQUIRED" | "ROLLBACK_VERIFIED" | "CLEANUP_FAILED" | "CLEANUP_NOT_REACHED";

export interface LinkPortalAssertionObservation {
  kind: string;
  matched: boolean;
  reasonCode: string;
}

export interface LinkPortalStepObservation {
  stepId: string;
  phase: "CONTROL" | "ACTION" | "VERIFY" | "CLEANUP";
  actorAlias: string;
  resourceAlias: string;
  resourceKind: LinkPortalResourceKind;
  pathTemplate: string;
  method: string;
  stateChanging: boolean;
  tampered: boolean;
  transmitted: boolean;
  statusCode?: number;
  contentType?: string;
  responseLengthBand?: string;
  responseShapeFingerprint?: string;
  responseBodyFingerprint?: string;
  capturesRecorded: string[];
  assertions: LinkPortalAssertionObservation[];
  outcome: LinkPortalOutcome;
  reasonCode?: string;
}

export interface LinkPortalCaseObservation {
  caseId: string;
  label: string;
  category: LinkPortalSecurityCategory;
  outcome: LinkPortalOutcome;
  cleanupOutcome: LinkPortalCleanupOutcome;
  comparisonFingerprint: string;
  actorAliases: string[];
  resourceAliases: string[];
  steps: LinkPortalStepObservation[];
  notes: string[];
}

export interface LinkPortalSecurityReport {
  enabled: boolean;
  plannedCases: number;
  executedCases: number;
  passedCases: number;
  failedCases: number;
  inconclusiveCases: number;
  blockedCases: number;
  requestsTransmitted: number;
  requestBudget: number;
  cleanupRequired: number;
  cleanupFailed: number;
  resourceInventory: Array<{ safeAlias: string; kind: LinkPortalResourceKind; pathTemplate: string; allowedOriginCount: number; ownerDeclared: boolean; tenantDeclared: boolean; declaredState?: string; expiryDeclared: boolean }>;
  observations: LinkPortalCaseObservation[];
  coverage: Record<LinkPortalSecurityCategory, { planned: number; executed: number; passed: number; failed: number }>;
  notes: string[];
}
