import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import type { CredentialHealthClassification, CredentialProfileSummary, CredentialVault } from "./CredentialVault.js";

export type CredentialActorRole = "single" | "accountA" | "accountB";

export interface CredentialExecutionBinding {
  id: string;
  role: CredentialActorRole;
  secretVersion: number;
  expiresAt?: string;
  healthClassification: CredentialHealthClassification;
}

export interface CredentialReadinessResult {
  ready: boolean;
  checkedAt: string;
  requiredValidThrough: string;
  blockers: Array<{ code: string; role: CredentialActorRole; profileId: string; message: string }>;
  warnings: Array<{ code: string; role?: CredentialActorRole; profileId?: string; message: string }>;
  profiles: Array<{
    id: string;
    role: CredentialActorRole;
    safeAlias: string;
    classification: CredentialHealthClassification;
    reasonCode: string;
    secretVersion: number;
    expiresAt?: string;
  }>;
  bindings: CredentialExecutionBinding[];
}

export function credentialReferences(request: DashboardScanCreateRequest): Array<{ id: string; role: CredentialActorRole }> {
  const result: Array<{ id: string; role: CredentialActorRole }> = [];
  if (request.credentialProfileId) result.push({ id: request.credentialProfileId, role: "single" });
  if (request.credentialProfileAId) result.push({ id: request.credentialProfileAId, role: "accountA" });
  if (request.credentialProfileBId) result.push({ id: request.credentialProfileBId, role: "accountB" });
  const auth = request.studio?.authentication;
  if (auth?.mode === "primary" && auth.primary.source === "saved") result.push({ id: auth.primary.credentialProfileId, role: "single" });
  if (auth?.mode === "account-pair") {
    if (auth.accountA.source === "saved") result.push({ id: auth.accountA.credentialProfileId, role: "accountA" });
    if (auth.accountB.source === "saved") result.push({ id: auth.accountB.credentialProfileId, role: "accountB" });
  }
  return result.filter((item, index) => result.findIndex((candidate) => candidate.id === item.id && candidate.role === item.role) === index);
}

export function evaluateCredentialReadiness(
  vault: CredentialVault,
  request: DashboardScanCreateRequest,
  maximumExecutionMs: number,
  nowMs = Date.now()
): CredentialReadinessResult {
  const checkedAt = new Date(nowMs).toISOString();
  const requiredValidThrough = new Date(nowMs + Math.max(0, maximumExecutionMs)).toISOString();
  const blockers: CredentialReadinessResult["blockers"] = [];
  const warnings: CredentialReadinessResult["warnings"] = [];
  const profiles: CredentialReadinessResult["profiles"] = [];
  const bindings: CredentialExecutionBinding[] = [];
  const summaries = new Map<CredentialActorRole, CredentialProfileSummary>();

  for (const reference of credentialReferences(request)) {
    const summary = vault.getSummary(reference.id);
    if (!summary) {
      blockers.push({ code: "CREDENTIAL_UNAVAILABLE", role: reference.role, profileId: reference.id, message: `Credential profile for ${actorLabel(reference.role)} is unavailable.` });
      continue;
    }
    summaries.set(reference.role, summary);
    profiles.push({ id: summary.id, role: reference.role, safeAlias: summary.safeAlias, classification: summary.health.classification, reasonCode: summary.health.reasonCode, secretVersion: summary.secretVersion, ...(summary.expiresAt ? { expiresAt: summary.expiresAt } : {}) });
    bindings.push({ id: summary.id, role: reference.role, secretVersion: summary.secretVersion, healthClassification: summary.health.classification, ...(summary.expiresAt ? { expiresAt: summary.expiresAt } : {}) });

    if (["DISABLED", "EXPIRED", "INVALID", "IDENTITY_MISMATCH"].includes(summary.health.classification)) {
      blockers.push({ code: `CREDENTIAL_${summary.health.classification}`, role: reference.role, profileId: summary.id, message: `${actorLabel(reference.role)} credential ${summary.safeAlias} is ${summary.health.classification.toLowerCase().replace("_", " ")}.` });
    }
    if (!summary.expiresAt) {
      warnings.push({ code: "CREDENTIAL_EXPIRY_UNSET", role: reference.role, profileId: summary.id, message: `${actorLabel(reference.role)} credential has no declared expiry.` });
    } else if (Date.parse(summary.expiresAt) <= nowMs + maximumExecutionMs) {
      blockers.push({ code: "CREDENTIAL_EXPIRES_DURING_SCAN", role: reference.role, profileId: summary.id, message: `${actorLabel(reference.role)} credential expires before the scan's maximum execution window ends.` });
    } else if (summary.health.classification === "NEAR_EXPIRY") {
      warnings.push({ code: "CREDENTIAL_NEAR_EXPIRY", role: reference.role, profileId: summary.id, message: `${actorLabel(reference.role)} credential is near expiry.` });
    }
    if (summary.health.classification === "UNVERIFIED") {
      warnings.push({ code: "CREDENTIAL_HEALTH_UNVERIFIED", role: reference.role, profileId: summary.id, message: `${actorLabel(reference.role)} credential has not passed its latest health test.` });
    }
  }

  const accountA = summaries.get("accountA");
  const accountB = summaries.get("accountB");
  if (accountA && accountB) {
    const declaredA = scalarIdentity(accountA.safeIdentitySummary, "principalId");
    const declaredB = scalarIdentity(accountB.safeIdentitySummary, "principalId");
    if (declaredA && declaredB && declaredA === declaredB) {
      warnings.push({ code: "ACCOUNT_PAIR_DECLARED_IDENTITY_COLLISION", message: "Account A and Account B declare the same principal. Cross-account results will be blocked by identity verification." });
    }
    if (accountA.health.principalFingerprint && accountA.health.principalFingerprint === accountB.health.principalFingerprint) {
      warnings.push({ code: "ACCOUNT_PAIR_VERIFIED_IDENTITY_COLLISION", message: "Account A and Account B most recently resolved to the same principal fingerprint. Refresh or replace one profile before authorization testing." });
    }
    if (accountA.health.classification === "IDENTITY_MISMATCH" || accountB.health.classification === "IDENTITY_MISMATCH") {
      warnings.push({ code: "ACCOUNT_PAIR_IDENTITY_DRIFT", message: "At least one account-pair profile no longer matches its declared identity metadata." });
    }
  }

  return { ready: blockers.length === 0, checkedAt, requiredValidThrough, blockers, warnings, profiles, bindings };
}

export function assertCredentialBindingsCurrent(vault: CredentialVault, bindings: readonly CredentialExecutionBinding[]): void {
  for (const binding of bindings) {
    const current = vault.getSummary(binding.id);
    if (!current) throw new Error(`CREDENTIAL_UNAVAILABLE: ${actorLabel(binding.role)} credential is unavailable.`);
    if (current.secretVersion !== binding.secretVersion) throw new Error(`CREDENTIAL_CHANGED_AFTER_QUEUE: ${actorLabel(binding.role)} credential was renewed or replaced after plan approval.`);
  }
}

function actorLabel(role: CredentialActorRole): string {
  return role === "single" ? "Primary" : role === "accountA" ? "Account A" : "Account B";
}

function scalarIdentity(value: Record<string, unknown>, key: string): string | undefined {
  const candidate = value[key];
  return typeof candidate === "string" && candidate.trim() ? candidate.trim() : undefined;
}
