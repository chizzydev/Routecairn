export const secretBoundarySurfaces = [
  "HTML",
  "JAVASCRIPT_BUNDLE",
  "SOURCE_MAP",
  "RUNTIME_CONFIGURATION",
  "ERROR_RESPONSE",
  "API_RESPONSE",
  "BROWSER_LOCAL_STORAGE",
  "BROWSER_SESSION_STORAGE",
  "COOKIE",
  "BUILD_METADATA",
  "DEBUG_ENDPOINT",
  "GRAPHQL_RESPONSE",
  "PUBLIC_LOG"
] as const;

export type SecretBoundarySurface = (typeof secretBoundarySurfaces)[number];

export const secretMaterialClasses = [
  "SERVER_CREDENTIAL",
  "SUPABASE_SERVICE_ROLE_KEY",
  "DATABASE_CREDENTIAL",
  "PRIVATE_KEY",
  "PAYMENT_PROVIDER_SECRET",
  "USER_SESSION_SECRET",
  "ONE_TIME_OR_RECOVERY_TOKEN",
  "SUPABASE_ANON_KEY",
  "SUPABASE_PUBLISHABLE_KEY",
  "PUBLISHABLE_CLIENT_KEY",
  "PUBLIC_CLIENT_CONFIG",
  "PERSONAL_DATA",
  "INTERNAL_METADATA",
  "UNKNOWN_SECRET_LIKE",
  "NON_SENSITIVE"
] as const;

export type SecretMaterialClass = (typeof secretMaterialClasses)[number];
export type SecretBoundary = "SERVER_ONLY" | "USER_SECRET" | "CLIENT_SAFE" | "PERSONAL_DATA" | "INTERNAL" | "UNKNOWN" | "NONE";
export type SecretImpact = "NONE" | "INFORMATIONAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type SecretExposureOutcome =
  | "CONFIRMED_SENSITIVE_EXPOSURE"
  | "CLIENT_STORAGE_RISK"
  | "COOKIE_TRANSPORT_RISK"
  | "SECURE_COOKIE_STORAGE"
  | "EXPECTED_PUBLIC_CLIENT_MATERIAL"
  | "SENSITIVE_FIELD_EXPOSURE"
  | "METADATA_EXPOSURE"
  | "NEEDS_REVIEW"
  | "NOT_SENSITIVE";
export type SecretConfidence = "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW";
export type SecretActorContext = "PUBLIC" | "AUTHENTICATED" | "BROWSER" | "UNKNOWN";

export interface SecretBoundaryPlan {
  schemaVersion: 1;
  enabled: true;
  maxObservedResponses: number;
  maxAdditionalRequests: number;
  maxSourceMaps: number;
  maxCandidatesPerSource: number;
  maxTotalCandidates: number;
  maxAnalysisBytes: number;
  inspectSourceMaps: boolean;
  probePaths: readonly string[];
  notes: readonly string[];
}

export interface SecretClassification {
  materialClass: SecretMaterialClass;
  boundary: SecretBoundary;
  impact: SecretImpact;
  outcome: SecretExposureOutcome;
  confidence: SecretConfidence;
  reasonCode: string;
  findingEligible: boolean;
  clientSafeNameConflict: boolean;
  tokenFormat: string;
  supabaseRole?: "anon" | "authenticated" | "service_role" | "other";
}

export interface SecretBoundaryObservation {
  surface: SecretBoundarySurface;
  sourceUrl: string;
  actorContext: SecretActorContext;
  publicExposure: boolean;
  candidateName: string;
  valueType: string;
  valueLength: number;
  materialClass: SecretMaterialClass;
  boundary: SecretBoundary;
  impact: SecretImpact;
  outcome: SecretExposureOutcome;
  confidence: SecretConfidence;
  reasonCode: string;
  tokenFormat: string;
  clientSafeNameConflict: boolean;
  correlationFingerprint: string;
  comparisonFingerprint: string;
  method: string;
  statusCode?: number;
  contentType?: string;
  supabaseRole?: "anon" | "authenticated" | "service_role" | "other";
}

export interface TransientSecretCandidate {
  name: string;
  value: string;
  valueType: string;
  cookie?: { httpOnly: boolean; secure: boolean; sameSite?: string };
}
