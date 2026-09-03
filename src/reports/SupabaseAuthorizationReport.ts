import type { SupabaseActor, SupabaseBoundary, SupabaseExpectedDecision, SupabaseOperation, SupabaseSurface } from "../modules/supabaseAuthorization/SupabaseAuthorizationTypes.js";

export type SupabaseObservedDecision =
  | "ACCESS_ALLOWED"
  | "ACCESS_DENIED"
  | "EMPTY_RESULT"
  | "SIGNED_URL_ISSUED"
  | "SIGNED_URL_DOWNLOAD_ALLOWED"
  | "SIGNED_URL_DOWNLOAD_DENIED"
  | "MUTATION_PROVEN"
  | "MUTATION_REJECTED"
  | "MUTATION_INCONCLUSIVE"
  | "IDENTITY_UNVERIFIED"
  | "RESPONSE_UNPARSEABLE"
  | "RATE_LIMITED"
  | "BLOCKED_BY_SAFETY"
  | "CREDENTIAL_UNAVAILABLE"
  | "EXECUTION_ERROR";

export type SupabaseFindingCategory =
  | "RLS_READ_BYPASS"
  | "RLS_INSERT_BYPASS"
  | "RLS_UPDATE_BYPASS"
  | "RLS_DELETE_BYPASS"
  | "CROSS_USER_ACCESS"
  | "CROSS_TENANT_ACCESS"
  | "SENSITIVE_COLUMN_EXPOSURE"
  | "STORAGE_AUTHORIZATION_BYPASS"
  | "SIGNED_URL_BOUNDARY_BYPASS"
  | "RPC_AUTHORIZATION_BYPASS"
  | "RELATIONSHIP_TRAVERSAL_BYPASS"
  | "SERVICE_ROLE_BOUNDARY_BYPASS";

export interface SupabaseAuthorizationObservation {
  cleanupOutcome?: string;
  caseId: string;
  comparisonFingerprint: string;
  surface: SupabaseSurface;
  resource: string;
  operation: SupabaseOperation;
  actor: SupabaseActor;
  boundary: SupabaseBoundary;
  expectedDecision: SupabaseExpectedDecision;
  observedDecision: SupabaseObservedDecision;
  matchedExpectation: boolean;
  identityConfirmed: boolean;
  sensitiveColumnsObserved: string[];
  method: string;
  url: string;
  statusCode?: number;
  contentType?: string;
  contentLength?: number;
  bodyHash?: string;
  findingCategory?: SupabaseFindingCategory;
  confidence: "CONFIRMED" | "HIGH" | "MEDIUM" | "INCONCLUSIVE";
  notes: string[];
}

export type SupabaseStaticRiskCategory =
  | "RLS_DISABLED_EXPOSED_TABLE"
  | "RLS_NOT_FORCED"
  | "ANON_WRITE_GRANT"
  | "SENSITIVE_COLUMN_ANON_EXPOSURE"
  | "PUBLIC_STORAGE_BUCKET"
  | "STORAGE_OWNERSHIP_NOT_ENFORCED"
  | "SECURITY_DEFINER_PUBLIC_EXECUTE"
  | "SECURITY_DEFINER_UNSAFE_SEARCH_PATH"
  | "SECURITY_DEFINER_DYNAMIC_SQL"
  | "UNEXPECTED_EXPOSED_SCHEMA"
  | "RELATIONSHIP_TRAVERSAL_RISK"
  | "ANON_KEY_SERVICE_ROLE_CLAIM"
  | "ANON_KEY_IS_SECRET_KEY"
  | "ANON_SERVICE_KEY_REUSE";

export interface SupabaseStaticRisk {
  id: string;
  comparisonFingerprint: string;
  category: SupabaseStaticRiskCategory;
  severity: "Low" | "Medium" | "High" | "Critical";
  resource: string;
  summary: string;
  evidence: string[];
}

export interface SupabaseAuthorizationReport {
  enabled: boolean;
  projectOrigin?: string;
  plannedCases: number;
  executedCases: number;
  confirmedIssues: number;
  accessMatrix: Record<SupabaseActor, Record<SupabaseOperation, { allowed: number; denied: number; inconclusive: number }>>;
  anonKeyClassification: "UNAVAILABLE" | "ANON_JWT" | "SERVICE_ROLE_JWT" | "OTHER_JWT" | "PUBLISHABLE_KEY" | "SECRET_KEY" | "OPAQUE";
  serviceRoleConfigured: boolean;
  serviceRoleBoundaryVerified: boolean;
  observations: SupabaseAuthorizationObservation[];
  staticRisks: SupabaseStaticRisk[];
  resourceCoverage: Array<{ surface: SupabaseSurface; resource: string; operations: SupabaseOperation[]; actors: SupabaseActor[] }>;
  coverage: {
    tableRead: boolean;
    tableInsert: boolean;
    tableUpdate: boolean;
    tableDelete: boolean;
    crossUser: boolean;
    crossTenant: boolean;
    sensitiveColumns: boolean;
    storage: boolean;
    signedUrls: boolean;
    rpc: boolean;
    securityDefiner: boolean;
    publicSchemas: boolean;
    relationships: boolean;
    accountPair: boolean;
    serviceRole: boolean;
  };
  notes: string[];
}
