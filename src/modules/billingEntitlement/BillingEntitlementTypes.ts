import type { HttpMethod } from "../../core/http/HttpTypes.js";

export const billingEntitlementCategories = [
  "CLIENT_PRICE_MANIPULATION",
  "PRODUCT_PLAN_SUBSTITUTION",
  "UNVERIFIED_PAYMENT_ENTITLEMENT",
  "CANCELLATION_ENTITLEMENT_PERSISTENCE",
  "DUPLICATE_WEBHOOK_PROCESSING",
  "REPLAYED_PAYMENT_EVENT",
  "CROSS_ACCOUNT_PREMIUM_ACCESS",
  "REFUND_DOWNGRADE_CONSISTENCY",
  "SUBSCRIPTION_OWNERSHIP_CONFUSION",
  "PAYMENT_EVENT_RACE"
] as const;
export type BillingEntitlementCategory = (typeof billingEntitlementCategories)[number];
export type BillingAuthSlot = "anonymous" | "primary" | "account_a" | "account_b";
export type BillingEndpointKind = "CHECKOUT_VALIDATION" | "SYNTHETIC_WEBHOOK" | "ENTITLEMENT_STATE" | "SUBSCRIPTION_STATE" | "PREMIUM_ACCESS" | "FIXTURE_CONTROL";
export type BillingProofDimension = "PRICE" | "PRODUCT" | "PLAN" | "PAYMENT_VERIFICATION" | "ENTITLEMENT" | "SUBSCRIPTION_STATUS" | "REFUND_STATUS" | "OWNER" | "ACCESS" | "EVENT_COUNT";
export type BillingOutcome = "PASS" | "FAIL" | "INCONCLUSIVE" | "BLOCKED";

export interface BillingProviderPlan { kind: "STRIPE_TEST" | "ADYEN_TEST" | "BRAINTREE_SANDBOX" | "PAYPAL_SANDBOX" | "PADDLE_SANDBOX" | "CUSTOM_SYNTHETIC"; mode: "TEST" | "SANDBOX" | "LOCAL_EMULATOR"; fixturePathPrefix: string; realPaymentExecution: "FORBIDDEN" }
export interface BillingActorPlan { id: string; safeAlias: string; authSlot: BillingAuthSlot; sendAuthentication: boolean; relationship: string; principalFingerprint?: string; tenantFingerprint?: string }
export interface BillingEndpointPlan { id: string; safeAlias: string; kind: BillingEndpointKind; pathTemplate: string; allowedOrigins: readonly string[] }
export interface BillingAuthorizationPlan { mode: "OBSERVE_ONLY" | "CONTROLLED_SYNTHETIC_BILLING"; environment: "LOCAL" | "TEST" | "STAGING"; authorizationIdentityConfirmed: boolean; changeTicketConfirmed: boolean; authorizedAt?: string; expiresAt?: string; disposableFixtures: boolean; confirmationAccepted: boolean }
export interface BillingHmacPlan { kind: "HMAC"; algorithm: "sha256" | "sha512"; secretSource: BillingAuthSlot; secretRef: string; header: string; encoding: "HEX" | "BASE64"; prefix: string; messageFormat: "BODY" | "TIMESTAMP_DOT_BODY"; timestampHeader?: string; timestampSecretRef?: string; tamper: boolean }
export interface BillingRequestPlan { method: HttpMethod; urlTemplate: string; stateChanging: boolean; secretSource: BillingAuthSlot; headers: Readonly<Record<string, string>>; bodyFormat?: "JSON" | "FORM"; fields?: unknown; hmac?: BillingHmacPlan }
export type BillingCapturePlan = { name: string; source: "JSON"; path: string } | { name: string; source: "HEADER"; header: string };
export interface BillingExecutionPlan { mode: "ONCE" | "SEQUENTIAL_DUPLICATE" | "SYNCHRONIZED"; attempts: number; maxDispatchSkewMs: number }
export interface BillingExpectationPlan { authorization: "ALLOW" | "DENY"; businessRule: "ACCEPT" | "REJECT" | "NOT_EVALUATED"; allowedStatuses: readonly number[]; deniedStatuses: readonly number[]; acceptedStatuses: readonly number[]; rejectedStatuses: readonly number[] }
export type BillingAssertionPlan =
  | { id: string; scope: "MAIN" | "CLEANUP"; kind: "VALUE_EQUALS_SECRET"; dimension: BillingProofDimension; capture: string; secretSource: BillingAuthSlot; secretRef: string }
  | { id: string; scope: "MAIN" | "CLEANUP"; kind: "VALUE_EQUALS_LITERAL"; dimension: BillingProofDimension; capture: string; expected: string | number | boolean | null }
  | { id: string; scope: "MAIN" | "CLEANUP"; kind: "VALUE_NOT_EQUALS_SECRET"; dimension: BillingProofDimension; capture: string; secretSource: BillingAuthSlot; secretRef: string }
  | { id: string; scope: "MAIN" | "CLEANUP"; kind: "NUMERIC_DELTA" | "EVENT_COUNT_DELTA"; dimension: BillingProofDimension; before: string; after: string; operator: "EQ" | "LT" | "LTE" | "GT" | "GTE"; expected: number }
  | { id: string; scope: "MAIN" | "CLEANUP"; kind: "STATE_TRANSITION"; dimension: BillingProofDimension; before: string; after: string; allowed: readonly { from: string; to: string }[] }
  | { id: string; scope: "MAIN" | "CLEANUP"; kind: "ACTION_OUTCOME_COUNT"; dimension: BillingProofDimension; stepId: string; outcome: "ACCEPTED" | "REJECTED" | "AUTHORIZED" | "DENIED"; operator: "EQ" | "LT" | "LTE" | "GT" | "GTE"; expected: number };
export interface BillingStepPlan { id: string; phase: "PRE_STATE" | "ACTION" | "VERIFY" | "CLEANUP"; actorId: string; endpointId: string; operation: "OBSERVE" | "CHECKOUT_VALIDATION" | "SYNTHETIC_PAYMENT_EVENT" | "CANCEL_FIXTURE" | "REFUND_FIXTURE" | "DOWNGRADE_FIXTURE" | "PREMIUM_ACCESS_PROBE" | "SUBSCRIPTION_ACCESS_PROBE" | "RESET_FIXTURE"; request: BillingRequestPlan; execution: BillingExecutionPlan; expectation?: BillingExpectationPlan; captures: readonly BillingCapturePlan[] }
export interface BillingEntitlementCasePlan { id: string; label: string; category: BillingEntitlementCategory; authorization: BillingAuthorizationPlan; cleanupRequired: boolean; steps: readonly BillingStepPlan[]; assertions: readonly BillingAssertionPlan[]; comparisonFingerprint: string }
export interface BillingEntitlementPlan { schemaVersion: 1; enabled: true; targetOrigin: string; maxCases: number; maxRequests: number; maxResponseBytes: number; maxConcurrency: number; provider: BillingProviderPlan; actors: readonly BillingActorPlan[]; endpoints: readonly BillingEndpointPlan[]; cases: readonly BillingEntitlementCasePlan[]; notes: readonly string[] }
