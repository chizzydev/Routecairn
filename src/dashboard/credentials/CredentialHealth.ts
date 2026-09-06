import type { IdentityVerificationReport, IdentityVerificationResult } from "../../reports/ReportTypes.js";
import type { CredentialHealthClassification, CredentialProfileSummary } from "./CredentialVault.js";

export interface CredentialHealthAssessment {
  classification: CredentialHealthClassification;
  reasonCode: string;
  safeSummary: string;
  principalFingerprint?: string;
}

const mismatchCategories = new Set(["PRINCIPAL_MISMATCH", "TENANT_MISMATCH", "ROLE_MISMATCH", "ACCOUNT_STATE_MISMATCH"]);
const invalidCategories = new Set(["AUTHENTICATION_FAILED", "ACCESS_DENIED", "LOGIN_PAGE_RESPONSE", "ANONYMOUS_RESPONSE"]);

export function assessCredentialIdentity(
  profile: CredentialProfileSummary,
  report: IdentityVerificationReport,
  slot: "primary" | "accountA" | "accountB" = "primary",
  nowMs = Date.now()
): CredentialHealthAssessment {
  const result = report[slot] as IdentityVerificationResult | undefined;
  if (!result) return { classification: "UNVERIFIED", reasonCode: "IDENTITY_RESULT_MISSING", safeSummary: "The identity health check did not produce a result for the selected actor." };
  const principalFingerprint = result.principalHash;
  if (mismatchCategories.has(result.category)) {
    return { classification: "IDENTITY_MISMATCH", reasonCode: result.category, safeSummary: "Credential identity no longer matches the declared safe identity contract.", ...(principalFingerprint ? { principalFingerprint } : {}) };
  }
  if (invalidCategories.has(result.category)) {
    return { classification: "INVALID", reasonCode: result.category, safeSummary: "The target rejected the credential or resolved it as unauthenticated.", ...(principalFingerprint ? { principalFingerprint } : {}) };
  }
  if (!result.verified) {
    return { classification: "UNVERIFIED", reasonCode: result.category, safeSummary: "Credential validity remains unverified; the bounded identity check was inconclusive.", ...(principalFingerprint ? { principalFingerprint } : {}) };
  }
  if (profile.health.principalFingerprint && principalFingerprint && profile.health.principalFingerprint !== principalFingerprint) {
    return { classification: "IDENTITY_MISMATCH", reasonCode: "OBSERVED_PRINCIPAL_CHANGED", safeSummary: "The verified principal fingerprint changed from the credential's previous healthy observation.", principalFingerprint };
  }
  const expiresInMs = profile.expiresAt ? Date.parse(profile.expiresAt) - nowMs : undefined;
  const nearExpiry = expiresInMs !== undefined && expiresInMs <= 7 * 24 * 60 * 60 * 1000;
  return {
    classification: nearExpiry ? "NEAR_EXPIRY" : "HEALTHY",
    reasonCode: nearExpiry ? "VERIFIED_NEAR_EXPIRY" : result.category,
    safeSummary: nearExpiry ? "Identity verified, but the credential expires within seven days." : "Identity and declared safe metadata were verified by the configured endpoint.",
    ...(principalFingerprint ? { principalFingerprint } : {})
  };
}
