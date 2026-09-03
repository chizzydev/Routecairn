import type { LifecycleActorPlan } from "../authenticationLifecycle/AuthenticationLifecycleTypes.js";
import type { CleanupActionPlan, InvariantOperandPlan, StateObservationPlan } from "../businessInvariant/BusinessInvariantTypes.js";
import type { InvariantRequestPlan } from "../businessInvariant/BusinessInvariantTypes.js";

export const controlledRaceCategories = [
  "SAME_OBJECT",
  "DUPLICATE_REDEMPTION",
  "INVENTORY",
  "PAYMENT_ENTITLEMENT",
  "INVITATION",
  "ONE_TIME_TOKEN",
  "CUSTOM"
] as const;

export type ControlledRaceCategory = (typeof controlledRaceCategories)[number];
export type ControlledRaceOutcome = "PASS" | "FAIL" | "INCONCLUSIVE" | "BLOCKED";

export interface ControlledRaceAuthorizationPlan {
  mode: "CONTROLLED_RACE";
  environment: "LOCAL" | "TEST" | "STAGING" | "PRODUCTION";
  authorizationIdentityConfirmed: true;
  changeTicketConfirmed: true;
  authorizedAt: string;
  expiresAt: string;
  disposableEntities: true;
  productionAcknowledged: boolean;
  confirmationAccepted: true;
}

export interface RaceRequestExpectationPlan {
  authorization: "ALLOW" | "DENY";
  businessRule: "ACCEPT" | "REJECT" | "NOT_EVALUATED";
  authorizationAllowedStatuses: readonly number[];
  authorizationDeniedStatuses: readonly number[];
  businessAcceptedStatuses: readonly number[];
  businessRejectedStatuses: readonly number[];
}

export interface SynchronizedRaceRequestPlan {
  id: string;
  actorId: string;
  request: InvariantRequestPlan;
  expectation: RaceRequestExpectationPlan;
}

export interface SynchronizedRaceGroupPlan {
  id: string;
  label: string;
  synchronization: "READY_BARRIER";
  maxDispatchSkewMs: number;
  requests: readonly SynchronizedRaceRequestPlan[];
}

export type ControlledRaceAssertionPlan =
  | { id: string; kind: "VALUE_COMPARE"; left: InvariantOperandPlan; operator: "EQ" | "NEQ" | "LT" | "LTE" | "GT" | "GTE"; right: InvariantOperandPlan }
  | { id: string; kind: "NUMERIC_DELTA"; before: string; after: string; operator: "EQ" | "LT" | "LTE" | "GT" | "GTE"; expected: number }
  | { id: string; kind: "EVENT_COUNT_DELTA"; before: string; after: string; operator: "EQ" | "LT" | "LTE" | "GT" | "GTE"; expected: number }
  | { id: string; kind: "GROUP_OUTCOME_COUNT"; groupId: string; outcome: "ACCEPTED" | "REJECTED" | "AUTHORIZED" | "DENIED"; operator: "EQ" | "LT" | "LTE" | "GT" | "GTE"; expected: number }
  | { id: string; kind: "STATE_TRANSITION"; before: string; after: string; allowed: readonly { from: string; to: string }[] };

export interface ControlledRaceCasePlan {
  id: string;
  label: string;
  category: ControlledRaceCategory;
  target: { type: string; safeAlias: string; identityFingerprint: string; disposable: true };
  actors: readonly LifecycleActorPlan[];
  authorization: ControlledRaceAuthorizationPlan;
  preState: readonly StateObservationPlan[];
  groups: readonly SynchronizedRaceGroupPlan[];
  postState: readonly StateObservationPlan[];
  invariants: readonly ControlledRaceAssertionPlan[];
  cleanupRequired: true;
  cleanup: readonly CleanupActionPlan[];
  cleanupVerification: readonly StateObservationPlan[];
  cleanupInvariants: readonly ControlledRaceAssertionPlan[];
  comparisonFingerprint: string;
}

export interface ControlledRacePlan {
  schemaVersion: 1;
  enabled: true;
  targetOrigin: string;
  maxCases: number;
  maxGroupsPerCase: number;
  maxRequests: number;
  maxResponseBytes: number;
  maxConcurrency: number;
  cases: readonly ControlledRaceCasePlan[];
  notes: readonly string[];
}
