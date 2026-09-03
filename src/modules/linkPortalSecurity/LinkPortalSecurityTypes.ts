import type { HttpMethod } from "../../core/http/HttpTypes.js";

export const linkPortalSecurityCategories = [
  "SIGNED_LINK_EXPIRY",
  "SIGNATURE_TAMPERING",
  "ID_SUBSTITUTION",
  "CROSS_TENANT_SIGNED_LINK",
  "SIGNED_LINK_REPLAY",
  "SIGNED_LINK_REVOCATION",
  "INVITE_EMAIL_BINDING",
  "INVITE_REPLAY",
  "INVITE_EXPIRATION",
  "PORTAL_TENANT_BINDING",
  "EXPORT_AUTHORIZATION",
  "EVIDENCE_ARTIFACT_AUTHORIZATION",
  "OBJECT_PATH_OWNERSHIP"
] as const;

export type LinkPortalSecurityCategory = (typeof linkPortalSecurityCategories)[number];
export type LinkPortalAuthSlot = "anonymous" | "primary" | "account_a" | "account_b";
export type LinkPortalResourceKind = "SIGNED_LINK" | "INVITE" | "PORTAL" | "EXPORT" | "EVIDENCE_ARTIFACT" | "OBJECT_PATH";
export type LinkPortalPhase = "CONTROL" | "ACTION" | "VERIFY" | "CLEANUP";

export interface LinkPortalActorPlan {
  id: string;
  safeAlias: string;
  authSlot: LinkPortalAuthSlot;
  sendAuthentication: boolean;
  relationship: string;
  principalFingerprint?: string;
  tenantFingerprint?: string;
}

export interface LinkPortalResourcePlan {
  id: string;
  safeAlias: string;
  kind: LinkPortalResourceKind;
  pathTemplate: string;
  allowedOrigins: readonly string[];
  ownerActorId?: string;
  tenantFingerprint?: string;
  declaredState?: string;
  expiresAt?: string;
}

export interface LinkPortalAuthorizationPlan {
  mode: "OBSERVE_ONLY" | "CONTROLLED_LINK_FLOW";
  environment: "LOCAL" | "TEST" | "STAGING" | "PRODUCTION";
  authorizedAt?: string;
  expiresAt?: string;
  authorizationIdentityConfirmed: boolean;
  changeTicketConfirmed: boolean;
  disposableResource: boolean;
  productionAcknowledged: boolean;
  confirmationAccepted: boolean;
}

export interface LinkPortalRequestPlan {
  method: HttpMethod;
  urlTemplate: string;
  stateChanging: boolean;
  secretSource: LinkPortalAuthSlot;
  headers: Readonly<Record<string, string>>;
  bodyFormat?: "JSON" | "FORM" | undefined;
  fields?: Readonly<Record<string, unknown>> | undefined;
  tamper?: { kind: "QUERY_PARAMETER"; parameter: string; strategy: "FLIP_LAST_CHARACTER" } | undefined;
}

export type LinkPortalCapturePlan =
  | { name: string; source: "JSON"; path: string }
  | { name: string; source: "HEADER"; header: string };

export type LinkPortalAssertionPlan =
  | { kind: "STATUS_IN"; values: readonly number[] }
  | { kind: "STATUS_NOT_IN"; values: readonly number[] }
  | { kind: "DECISION"; expected: "ALLOW" | "DENY"; allowedStatuses: readonly number[]; deniedStatuses: readonly number[] }
  | { kind: "HEADER_PRESENT"; header: string }
  | { kind: "HEADER_ABSENT"; header: string }
  | { kind: "JSON_EQUALS_SECRET"; path: string; secretSource: LinkPortalAuthSlot; secretRef: string }
  | { kind: "JSON_NOT_EQUALS_SECRET"; path: string; secretSource: LinkPortalAuthSlot; secretRef: string }
  | { kind: "BODY_FINGERPRINT"; expectedSha256: string }
  | { kind: "RESPONSE_FINGERPRINT_MATCH"; stepId: string }
  | { kind: "RESPONSE_FINGERPRINT_DIFFERENT"; stepId: string };

export interface LinkPortalStepPlan {
  id: string;
  phase: LinkPortalPhase;
  actorId: string;
  resourceId: string;
  waitBeforeMs: number;
  request: LinkPortalRequestPlan;
  captures: readonly LinkPortalCapturePlan[];
  assertions: readonly LinkPortalAssertionPlan[];
}

export interface LinkPortalSecurityCasePlan {
  id: string;
  label: string;
  category: LinkPortalSecurityCategory;
  authorization: LinkPortalAuthorizationPlan;
  cleanupRequired: boolean;
  steps: readonly LinkPortalStepPlan[];
  comparisonFingerprint: string;
}

export interface LinkPortalSecurityPlan {
  schemaVersion: 1;
  enabled: true;
  targetOrigin: string;
  maxCases: number;
  maxStepsPerCase: number;
  maxRequests: number;
  maxResponseBytes: number;
  actors: readonly LinkPortalActorPlan[];
  resources: readonly LinkPortalResourcePlan[];
  cases: readonly LinkPortalSecurityCasePlan[];
  notes: readonly string[];
}
