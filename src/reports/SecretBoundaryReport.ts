import type { SecretBoundaryObservation, SecretBoundarySurface, SecretImpact, SecretMaterialClass } from "../modules/secretBoundary/SecretBoundaryTypes.js";

export interface SecretBoundaryReport {
  enabled: boolean;
  schemaVersion: 1;
  observedResponsesReviewed: number;
  additionalRequestsUsed: number;
  additionalRequestLimit: number;
  sourceMapsReviewed: number;
  sourceMapLimit: number;
  candidatesAnalyzed: number;
  candidateLimit: number;
  classifiedObservations: number;
  confirmedFindings: number;
  clientSafeMaterial: number;
  serverOnlyMaterial: number;
  clientSafeNameConflicts: number;
  supabase: {
    anonKeys: number;
    publishableKeys: number;
    serviceRoleKeys: number;
    distinctionEnforced: true;
  };
  impactCounts: Record<SecretImpact, number>;
  materialCounts: Record<SecretMaterialClass, number>;
  coverage: Record<SecretBoundarySurface, { sourcesObserved: number; candidatesAnalyzed: number; classifiedObservations: number; findings: number }>;
  observations: SecretBoundaryObservation[];
  notes: string[];
}
