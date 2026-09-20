import type { HttpMethod } from "../../core/http/HttpTypes.js";
import type { TotpAlgorithm } from "./AuthenticationFixtures.js";
import type { VirtualWebAuthnOptions } from "../browserCrawler/VirtualWebAuthnManager.js";
import type { TurnkeyAuthAdapterConfig, TurnkeyAuthOperation } from "./TurnkeyAuthProviderAdapters.js";

export const authenticationLifecycleCategories = [
  "LOGIN_ENUMERATION_RESISTANCE",
  "SESSION_ROTATION_AFTER_LOGIN",
  "SESSION_FIXATION",
  "LOGOUT_INVALIDATION",
  "PASSWORD_CHANGE_SESSION_INVALIDATION",
  "SESSION_REVOCATION",
  "IDLE_EXPIRATION",
  "ABSOLUTE_EXPIRATION",
  "REFRESH_TOKEN_ROTATION",
  "PASSWORD_RESET_TOKEN_BINDING",
  "PASSWORD_RESET_TOKEN_REPLAY",
  "PASSWORD_RESET_ACCOUNT_CONFUSION",
  "EMAIL_VERIFICATION_BYPASS",
  "ACCOUNT_LINKING_CONFUSION",
  "OAUTH_OIDC_STATE_REDIRECT_VALIDATION",
  "MFA_ENROLLMENT_REMOVAL",
  "PASSKEY_ENROLLMENT_REMOVAL",
  "RECOVERY_CODE_LIFECYCLE",
  "ADMIN_INVITATION_LIFECYCLE",
  "TENANT_INVITATION_LIFECYCLE",
  "DISABLED_USER_SESSION_BEHAVIOR"
] as const;

export type AuthenticationLifecycleCategory = (typeof authenticationLifecycleCategories)[number];
export type LifecycleAuthSlot = "anonymous" | "primary" | "account_a" | "account_b";
export type LifecycleStepPhase = "SETUP" | "ACTION" | "VERIFY" | "CLEANUP";
export type LifecycleAuthorizationMode = "OBSERVE_ONLY" | "CONTROLLED_LIFECYCLE";

export interface LifecycleActorPlan {
  id: string;
  safeAlias: string;
  authSlot: LifecycleAuthSlot;
  requestAuthentication: "NONE" | "PROFILE";
  relationship: string;
  declaredState: string;
  tenantAlias?: string;
}

export interface LifecycleAuthorizationPlan {
  mode: LifecycleAuthorizationMode;
  environment: "LOCAL" | "TEST" | "STAGING" | "PRODUCTION";
  authorizationIdentityConfirmed: boolean;
  changeTicketConfirmed: boolean;
  authorizedAt?: string;
  expiresAt?: string;
  disposableAccounts: boolean;
  productionAcknowledged: boolean;
  confirmationAccepted: boolean;
}

export interface LifecycleRequestPlan {
  method: HttpMethod;
  url: string;
  stateChanging: boolean;
  headers: Readonly<Record<string, string>>;
  bodyFormat?: "JSON" | "FORM";
  fields?: Readonly<Record<string, unknown>>;
}

export type LifecycleCapturePlan =
  | { name: string; source: "JSON"; path: string }
  | { name: string; source: "HEADER"; header: string }
  | { name: string; source: "COOKIE"; cookie: string };

export type LifecycleAssertionPlan =
  | { kind: "STATUS_IN"; values: readonly number[] }
  | { kind: "STATUS_NOT_IN"; values: readonly number[] }
  | { kind: "HEADER_PRESENT"; header: string }
  | { kind: "HEADER_ABSENT"; header: string }
  | { kind: "JSON_EQUALS"; path: string; expected: string | number | boolean | null }
  | { kind: "JSON_EQUALS_SECRET"; path: string; secretRef: string }
  | { kind: "REDIRECT_LOCATION_ALLOWED"; allowedOrigins: readonly string[]; allowedPathPrefixes: readonly string[] }
  | { kind: "REDIRECT_QUERY_EQUALS_SECRET"; parameter: string; secretRef: string }
  | { kind: "CAPTURE_ROTATED"; capture: string; comparedTo: { source: "SECRET" | "CAPTURE"; ref: string } }
  | { kind: "CAPTURE_UNCHANGED"; capture: string; comparedTo: { source: "SECRET" | "CAPTURE"; ref: string } }
  | { kind: "RESPONSE_SIMILAR"; stepId: string; compareStatus: boolean; compareShape: boolean; compareBodyDigest: boolean; compareTiming: boolean; maxLengthDelta: number; maxResponseTimeDeltaMs: number }
  | { kind: "RESPONSE_DIFFERENT"; stepId: string; compareStatus: boolean; compareShape: boolean; compareBodyDigest: boolean; compareTiming: boolean; maxLengthDelta: number; maxResponseTimeDeltaMs: number };

export interface LifecycleStepPlan {
  id: string;
  phase: LifecycleStepPhase;
  actorId: string;
  waitBeforeMs: number;
  fixtureActions: readonly LifecycleFixtureActionPlan[];
  request: LifecycleRequestPlan;
  captures: readonly LifecycleCapturePlan[];
  assertions: readonly LifecycleAssertionPlan[];
}

export type LifecycleFixtureActionPlan =
  | { kind: "TOTP_GENERATE"; profileId: string; capture: string; seed?: { source: "SECRET" | "CAPTURE"; ref: string } | undefined }
  | { kind: "INBOX_START"; adapterId: string; captureEndpoint: string }
  | { kind: "INBOX_WAIT"; adapterId: string; channel: "EMAIL" | "SMS"; recipientSecretRef: string; capture: string; value: "TEXT" | "HTML" | "SUBJECT" | "CODE" | "LINK"; timeoutMs: number; afterCapture?: string | undefined }
  | { kind: "INBOX_CLEAR"; adapterId: string; channel: "EMAIL" | "SMS"; recipientSecretRef: string }
  | { kind: "WEBAUTHN_CREATE"; authenticatorId: string }
  | { kind: "WEBAUTHN_ADD_CREDENTIAL"; authenticatorId: string; credentialIdSecretRef: string; privateKeySecretRef: string; rpId: string; userHandleSecretRef?: string | undefined; signCount: number }
  | { kind: "WEBAUTHN_CLEAR"; authenticatorId: string }
  | { kind: "WEBAUTHN_REMOVE"; authenticatorId: string }
  | { kind: "OIDC_START"; harnessId: string; captureIssuer: string; captureAuthorizationEndpoint?: string | undefined; captureTokenEndpoint?: string | undefined; captureCallbackEndpoint?: string | undefined }
  | { kind: "OIDC_WAIT_CALLBACK"; harnessId: string; parameter: string; capture: string; timeoutMs: number };

export interface AuthenticationFixturesPlan {
  inboxes: readonly ({ id: string; kind: "LOCAL_HTTP" } | { id: string; kind: "MAILPIT" | "MAILHOG"; baseUrl: string })[];
  totp: readonly { id: string; secretRef?: string | undefined; encoding: "BASE32" | "HEX" | "UTF8"; algorithm: TotpAlgorithm; digits: 6 | 7 | 8; periodSeconds: number; epochSeconds: number }[];
  webauthn: readonly ({ id: string } & VirtualWebAuthnOptions)[];
  oidc: readonly { id: string; clientIdSecretRef: string; clientSecretRef?: string | undefined; redirectUris: readonly string[]; subjectSecretRef: string; port: number; accessTokenLifetimeSeconds: number }[];
  providers: readonly TurnkeyAuthAdapterConfig[];
}

export interface LifecycleProviderCallPlan {
  adapterId: string;
  operation: TurnkeyAuthOperation;
}

export interface AuthenticationLifecycleCasePlan {
  id: string;
  label: string;
  category: AuthenticationLifecycleCategory;
  actors: readonly LifecycleActorPlan[];
  authorization: LifecycleAuthorizationPlan;
  cleanupRequired: boolean;
  steps: readonly LifecycleStepPlan[];
  comparisonFingerprint: string;
}

export interface AuthenticationLifecyclePlan {
  schemaVersion: 1;
  enabled: true;
  source: "EXPLICIT_MANIFEST" | "BROWSER_LEARNED";
  targetOrigin: string;
  maxCases: number;
  maxStepsPerCase: number;
  maxRequests: number;
  maxResponseBytes: number;
  fixtures?: AuthenticationFixturesPlan;
  cases: readonly AuthenticationLifecycleCasePlan[];
  automation?: Readonly<BrowserLearnedLifecycleAutomationPlan>;
  notes: readonly string[];
}

export interface BrowserLearnedLifecycleAutomationPlan {
  categories: readonly AuthenticationLifecycleCategory[];
  actor: LifecycleActorPlan;
  authorization: LifecycleAuthorizationPlan;
  login: {
    fieldSecretRefs: Readonly<Record<string, string>>;
    accountField?: string;
    passwordField?: string;
    unknownAccountSecretRef?: string;
    invalidPasswordSecretRef?: string;
    fixedSessionSecretRef?: string;
    sessionCookieName?: string;
    successStatusCodes: readonly number[];
    failureStatusCodes: readonly number[];
  };
  cleanup: {
    method: HttpMethod;
    url: string;
    headers: Readonly<Record<string, string>>;
    bodyFormat?: "JSON" | "FORM";
    fields?: Readonly<Record<string, unknown>>;
    successStatusCodes: readonly number[];
  };
  recipes: readonly {
    category: AuthenticationLifecycleCategory;
    candidateId: string;
    testCase: import("./AuthenticationLifecyclePlanner.js").AuthenticationLifecycleInput["cases"][number];
  }[];
}
