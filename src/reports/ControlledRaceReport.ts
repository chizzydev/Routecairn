import type { ControlledRaceCategory, ControlledRaceOutcome } from "../modules/controlledRace/ControlledRaceTypes.js";

export interface RaceRequestObservation {
  requestId: string;
  actorAlias: string;
  method: string;
  url: string;
  transmitted: boolean;
  statusCode?: number;
  authorizationDecision: "ALLOWED" | "DENIED" | "UNCLASSIFIED";
  businessRuleDecision: "ACCEPTED" | "REJECTED" | "NOT_EVALUATED" | "UNCLASSIFIED";
  expectationMatched: boolean;
  responseShapeFingerprint?: string;
  outcome: ControlledRaceOutcome;
  reasonCode: string;
}

export interface RaceGroupObservation {
  groupId: string;
  label: string;
  synchronized: boolean;
  requestCount: number;
  transmittedCount: number;
  dispatchSkewMs: number;
  maxDispatchSkewMs: number;
  acceptedCount: number;
  rejectedCount: number;
  authorizedCount: number;
  deniedCount: number;
  outcome: ControlledRaceOutcome;
  reasonCode: string;
  requests: RaceRequestObservation[];
}

export interface RaceAssertionObservation {
  invariantId: string;
  kind: string;
  outcome: ControlledRaceOutcome;
  reasonCode: string;
}

export interface ControlledRaceCaseObservation {
  caseId: string;
  label: string;
  category: ControlledRaceCategory;
  targetType: string;
  targetIdentityFingerprint: string;
  outcome: ControlledRaceOutcome;
  cleanupOutcome: "ROLLBACK_VERIFIED" | "CLEANUP_FAILED" | "CLEANUP_NOT_REACHED";
  preStateVerified: boolean;
  postStateVerified: boolean;
  comparisonFingerprint: string;
  groups: RaceGroupObservation[];
  invariants: RaceAssertionObservation[];
  cleanupInvariants: RaceAssertionObservation[];
  notes: string[];
}

export interface ControlledRaceReport {
  enabled: boolean;
  plannedCases: number;
  executedCases: number;
  passedCases: number;
  failedCases: number;
  inconclusiveCases: number;
  blockedCases: number;
  plannedGroups: number;
  synchronizedGroups: number;
  plannedRaceRequests: number;
  transmittedRaceRequests: number;
  cleanupRequired: number;
  cleanupFailed: number;
  observations: ControlledRaceCaseObservation[];
  coverage: Record<ControlledRaceCategory, { planned: number; executed: number; passed: number; failed: number }>;
  notes: string[];
}
