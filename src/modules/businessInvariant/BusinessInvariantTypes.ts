import type { HttpMethod } from "../../core/http/HttpTypes.js";
import type { LifecycleActorPlan } from "../authenticationLifecycle/AuthenticationLifecycleTypes.js";

export const businessInvariantCategories = ["FINANCIAL_LIMIT", "ONE_TIME_ACTION", "STATE_TRANSITION", "ENTITLEMENT", "SEPARATION_OF_DUTIES", "TRANSACTION_ELIGIBILITY", "ORDERING_CONSTRAINT", "IDEMPOTENCY", "CUSTOM"] as const;
export type BusinessInvariantCategory = (typeof businessInvariantCategories)[number];
export type InvariantOutcome = "PASS" | "FAIL" | "INCONCLUSIVE" | "BLOCKED";

export interface BusinessInvariantAuthorizationPlan {
  mode: "CONTROLLED_INVARIANT";
  environment: "LOCAL" | "TEST" | "STAGING" | "PRODUCTION";
  authorizationIdentityConfirmed: true;
  changeTicketConfirmed: true;
  authorizedAt: string;
  expiresAt: string;
  disposableEntities: true;
  productionAcknowledged: boolean;
  confirmationAccepted: true;
}

export interface InvariantRequestPlan {
  method: HttpMethod;
  url: string;
  stateChanging: boolean;
  headers: Readonly<Record<string, string>>;
  bodyFormat?: "JSON" | "FORM";
  fields?: Readonly<Record<string, unknown>>;
}

export type InvariantCapturePlan =
  | { name: string; source: "JSON"; path: string }
  | { name: string; source: "HEADER"; header: string }
  | { name: string; source: "COOKIE"; cookie: string };

export interface StateObservationPlan {
  id: string;
  actorId: string;
  request: InvariantRequestPlan;
  captures: readonly InvariantCapturePlan[];
}

export interface BusinessActionPlan {
  id: string;
  actorId: string;
  request: InvariantRequestPlan;
  execution: { mode: "ONCE" | "SEQUENTIAL_DUPLICATE" | "CONCURRENT_DUPLICATE"; attempts: number; maxConcurrency: number };
  expectation: {
    authorization: "ALLOW" | "DENY";
    businessRule: "ACCEPT" | "REJECT" | "NOT_EVALUATED";
    authorizationAllowedStatuses: readonly number[];
    authorizationDeniedStatuses: readonly number[];
    businessAcceptedStatuses: readonly number[];
    businessRejectedStatuses: readonly number[];
  };
  captures: readonly InvariantCapturePlan[];
  captureFromAttempt: "FIRST" | "LAST";
}

export type InvariantOperandPlan = { source: "CAPTURE"; ref: string } | { source: "LITERAL"; value: string | number | boolean | null };
export type BusinessInvariantAssertionPlan =
  | { id: string; kind: "VALUE_COMPARE"; left: InvariantOperandPlan; operator: "EQ" | "NEQ" | "LT" | "LTE" | "GT" | "GTE"; right: InvariantOperandPlan }
  | { id: string; kind: "NUMERIC_DELTA"; before: string; after: string; operator: "EQ" | "LT" | "LTE" | "GT" | "GTE"; expected: number }
  | { id: string; kind: "STATE_TRANSITION"; before: string; after: string; allowed: readonly { from: string; to: string }[] }
  | { id: string; kind: "ACTION_OUTCOME_COUNT"; actionId: string; outcome: "ACCEPTED" | "REJECTED" | "AUTHORIZED" | "DENIED"; operator: "EQ" | "LT" | "LTE" | "GT" | "GTE"; expected: number }
  | { id: string; kind: "ACTION_RESPONSE_EQUIVALENCE"; actionId: string; compareStatus: boolean; compareShape: boolean; compareBodyDigest: boolean; expectedEquivalent: boolean };

export interface BusinessStateMachinePlan {
  beforeCapture: string;
  afterCapture: string;
  states: readonly string[];
  allowedTransitions: readonly { from: string; to: string }[];
}

export interface CleanupActionPlan {
  id: string;
  actorId: string;
  request: InvariantRequestPlan;
  successStatusCodes: readonly number[];
}

export interface BusinessInvariantCasePlan {
  id: string;
  label: string;
  category: BusinessInvariantCategory;
  actors: readonly LifecycleActorPlan[];
  authorization: BusinessInvariantAuthorizationPlan;
  preState: readonly StateObservationPlan[];
  actions: readonly BusinessActionPlan[];
  postState: readonly StateObservationPlan[];
  invariants: readonly BusinessInvariantAssertionPlan[];
  stateMachine?: BusinessStateMachinePlan;
  cleanupRequired: boolean;
  cleanup: readonly CleanupActionPlan[];
  cleanupVerification: readonly StateObservationPlan[];
  cleanupInvariants: readonly BusinessInvariantAssertionPlan[];
  comparisonFingerprint: string;
}

export interface BusinessInvariantPlan {
  schemaVersion: 1;
  enabled: true;
  targetOrigin: string;
  maxCases: number;
  maxRequests: number;
  maxResponseBytes: number;
  maxConcurrency: number;
  cases: readonly BusinessInvariantCasePlan[];
  notes: readonly string[];
}
