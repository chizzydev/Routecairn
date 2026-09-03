export type SupabaseActor = "ANONYMOUS" | "ACCOUNT_A" | "ACCOUNT_B" | "SERVICE_ROLE";
export type SupabaseSurface = "TABLE" | "STORAGE" | "RPC" | "RELATIONSHIP";
export type SupabaseOperation = "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "INVOKE" | "SIGNED_URL";
export type SupabaseExpectedDecision = "ALLOW" | "DENY" | "OBSERVE_ONLY";
export type SupabaseBoundary = "NONE" | "CROSS_USER" | "CROSS_TENANT" | "SERVICE_ROLE";

export interface SupabaseIdentityAssertionPlan {
  path: string;
  expectedValue: string | number | boolean | null;
  expectedValueHash: string;
}

export interface SupabaseSignedUrlPlan {
  responseField: string;
  allowedOrigins: readonly string[];
  expectedPathContains?: string | undefined;
  followOnce: boolean;
}

export interface SupabaseAuthorizationCasePlan {
  id: string;
  surface: SupabaseSurface;
  resource: string;
  operation: SupabaseOperation;
  actor: SupabaseActor;
  expectedDecision: SupabaseExpectedDecision;
  boundary: SupabaseBoundary;
  method: "GET" | "HEAD" | "POST" | "PATCH" | "DELETE";
  url: string;
  headers: Readonly<Record<string, string>>;
  responseShape: "LIST" | "SINGLE" | "VOID";
  identityAssertions: readonly SupabaseIdentityAssertionPlan[];
  forbiddenColumns: readonly string[];
  requireVerifiedIdentity: boolean;
  mutationContractCaseId?: string | undefined;
  signedUrl?: SupabaseSignedUrlPlan | undefined;
  comparisonFingerprint: string;
}

export interface SupabaseCatalogGrantPlan {
  role: "anon" | "authenticated" | "service_role" | string;
  operations: readonly SupabaseOperation[];
}

export interface SupabaseCatalogColumnPlan {
  name: string;
  sensitive: boolean;
  exposedTo: readonly string[];
}

export interface SupabaseCatalogTablePlan {
  schema: string;
  name: string;
  exposed: boolean;
  rlsEnabled: boolean;
  rlsForced: boolean;
  ownerColumn?: string | undefined;
  tenantColumn?: string | undefined;
  grants: readonly SupabaseCatalogGrantPlan[];
  columns: readonly SupabaseCatalogColumnPlan[];
}

export interface SupabaseCatalogFunctionPlan {
  schema: string;
  name: string;
  exposed: boolean;
  securityDefiner: boolean;
  executableBy: readonly string[];
  searchPath: readonly string[];
  usesDynamicSql: boolean;
}

export interface SupabaseCatalogBucketPlan {
  name: string;
  public: boolean;
  ownershipEnforced: boolean;
  allowedOperations: Readonly<Record<string, readonly SupabaseOperation[]>>;
}

export interface SupabaseCatalogRelationshipPlan {
  name: string;
  from: string;
  to: string;
  exposed: boolean;
}

export interface SupabaseCatalogPlan {
  exposedSchemas: readonly string[];
  expectedExposedSchemas: readonly string[];
  tables: readonly SupabaseCatalogTablePlan[];
  functions: readonly SupabaseCatalogFunctionPlan[];
  storageBuckets: readonly SupabaseCatalogBucketPlan[];
  relationships: readonly SupabaseCatalogRelationshipPlan[];
}

export interface SupabaseAuthorizationPlan {
  schemaVersion: 1;
  enabled: true;
  projectOrigin: string;
  anonKeyEnv: string;
  serviceRoleKeyEnv?: string | undefined;
  cases: readonly SupabaseAuthorizationCasePlan[];
  catalog: SupabaseCatalogPlan;
  maxCases: number;
  maxResponseBytes: number;
  maxSignedUrlBytes: number;
  notes: readonly string[];
}
