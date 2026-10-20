import type { CredentialVault } from "../credentials/CredentialVault.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import { cleanupDigest } from "./CleanupAttemptLedger.js";
export function cleanupCredentialDigest(
  vault: CredentialVault | undefined,
  request: DashboardScanCreateRequest,
  organizationId: string
) {
  const ids = [request.credentialProfileId, request.credentialProfileAId, request.credentialProfileBId].filter(
    (id): id is string => Boolean(id)
  );
  return cleanupDigest(
    ids.map((id) => {
      const p = vault?.getSummary(id, organizationId);
      if (!p?.enabled) throw Error("RECOVERY_CREDENTIAL_UNAVAILABLE");
      return {
        id,
        identityDigest: cleanupDigest(p.safeIdentitySummary),
        secretVersion: p.secretVersion,
        targetId: p.targetId ?? null,
        expiresAt: p.expiresAt ?? null
      };
    })
  );
}
