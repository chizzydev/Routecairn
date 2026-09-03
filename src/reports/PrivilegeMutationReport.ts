import type { ControlledMutationResult } from "../core/offensive/ControlledMutationTypes.js";
import type { PrivilegeMutationCasePlan } from "../modules/privilegeMutation/PrivilegeMutationPlanner.js";

export type PrivilegeMutationSecurityOutcome = "PRIVILEGE_ESCALATION_PROVEN" | "MASS_ASSIGNMENT_PROVEN" | "CROSS_TENANT_REASSIGNMENT_PROVEN" | "OWNERSHIP_TAKEOVER_PROVEN" | "ADMINISTRATIVE_BOUNDARY_BYPASS_PROVEN" | "MUTATION_REJECTED" | "MUTATION_ACCEPTED_WITHOUT_SECURITY_IMPACT" | "AUTHORITY_CHANGE_NOT_VERIFIED" | "BLOCKED_BY_SAFETY" | "INCONCLUSIVE";
export type PrivilegeMutationCleanupOutcome = "ROLLBACK_VERIFIED" | "CLEANUP_REQUIRED" | "CLEANUP_FAILED" | "MUTATION_STATE_UNCERTAIN" | "NOT_REQUIRED";

export interface PrivilegeMutationObservation {
  caseId: string;
  category: PrivilegeMutationCasePlan["category"];
  actorLabel: string;
  targetAlias: string;
  attackMethod: string;
  attackEndpoint: string;
  authorityField: string;
  securityOutcome: PrivilegeMutationSecurityOutcome;
  cleanupOutcome: PrivilegeMutationCleanupOutcome;
  requestTransmitted: boolean;
  actorIdentityVerified: boolean;
  targetIdentityVerified: boolean;
  originalAuthorityVerified: boolean;
  authorityChangeVerified: boolean;
  protectedActionVerified: boolean;
  comparisonIdentity: string;
  notes: string[];
  result: ControlledMutationResult;
}

export interface PrivilegeMutationReport {
  enabled: boolean;
  plannedCases: number;
  executedCases: number;
  provenFindings: number;
  cleanupRequired: number;
  observations: PrivilegeMutationObservation[];
  notes: string[];
}
