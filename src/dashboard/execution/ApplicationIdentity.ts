import { nativeApplicationProofMatches } from "../../core/auth/NativeIdentityAdmission.js";
export { nativeApplicationProofMatches } from "../../core/auth/NativeIdentityAdmission.js";
import { createHash } from "node:crypto";
import { applicationIdentityModel } from "../../core/auth/IdentityModel.js";
import type { IdentityVerificationResult } from "../../reports/ReportTypes.js";
import type { ApiGraphqlActorPlan } from "../../modules/apiGraphql/ApiGraphqlTypes.js";
import type { CredentialProfileSecret } from "../credentials/CredentialVault.js";
const fp = (v: string) =>
  createHash("sha256")
    .update("routecairn-identity-v1\0" + v)
    .digest("hex")
    .slice(0, 16);
export function applicationActorIdentity(m: Record<string, unknown>) {
  const identityModel = applicationIdentityModel(m.identityModel);
  for (const k of identityModel === "TENANT_AWARE" ? ["principalId", "role", "tenantId"] : ["principalId", "role"])
    if (typeof m[k] !== "string" || !(m[k] as string).trim() || (m[k] as string).trim() !== m[k])
      throw Error("WORKBENCH_EXPLICIT_ACTOR_IDENTITY_REQUIRED");
  if (identityModel === "PRINCIPAL_ROLE" && m.tenantId !== undefined)
    throw Error("WORKBENCH_TENANTLESS_METADATA_CONFLICT");
  return {
    identityModel,
    principalId: m.principalId as string,
    role: m.role as string,
    ...(identityModel === "TENANT_AWARE" ? { tenantId: m.tenantId as string } : {})
  };
}
export function assertApplicationIdentityContract(
  m: Record<string, unknown>,
  c: CredentialProfileSecret["identityVerification"]
) {
  const a = applicationActorIdentity(m);
  if (m.identityModel !== undefined && c?.roleFieldPath && c.roleFieldPath === c.principalFieldPath)
    throw Error("WORKBENCH_DISTINCT_PRINCIPAL_ROLE_FIELDS_REQUIRED");
  if (
    !c?.roleFieldPath ||
    (a.identityModel === "TENANT_AWARE" ? !c.tenantFieldPath : !!c.tenantFieldPath || !c.principalFieldPath)
  )
    throw Error("WORKBENCH_MAPPING_VERIFIED_IDENTITY_CONTRACT_REQUIRED");
  return a;
}
export function nativeApplicationActorMatches(
  m: Record<string, unknown>,
  actor: ApiGraphqlActorPlan | undefined,
  proof: IdentityVerificationResult | undefined
): boolean {
  try {
    const a = applicationActorIdentity(m);
    return (
      nativeApplicationProofMatches(actor, proof) &&
      applicationIdentityModel(actor?.identityModel) === a.identityModel &&
      actor?.principalFingerprint === fp(a.principalId) &&
      actor.role === a.role &&
      (a.identityModel === "PRINCIPAL_ROLE" || actor.tenantFingerprint === fp(a.tenantId!))
    );
  } catch {
    return false;
  }
}
