import { createHash } from "node:crypto";
import { applicationIdentityModel } from "./IdentityModel.js";
import type { IdentityVerificationResult } from "../../reports/ReportTypes.js";
import type { ApiGraphqlActorPlan } from "../../modules/apiGraphql/ApiGraphqlTypes.js";
const fp = (v: string) =>
  createHash("sha256")
    .update("routecairn-identity-v1\0" + v)
    .digest("hex")
    .slice(0, 16);
export function nativeApplicationProofMatches(
  actor: ApiGraphqlActorPlan | undefined,
  proof: IdentityVerificationResult | undefined
): boolean {
  try {
    const model = applicationIdentityModel(actor?.identityModel);
    if (
      !actor?.principalFingerprint ||
      !actor.role ||
      !proof?.verified ||
      proof.principalMatched !== true ||
      proof.roleMatched !== true ||
      proof.principalHash !== actor.principalFingerprint ||
      proof.roleHash !== fp(actor.role) ||
      applicationIdentityModel(proof.identityModel) !== model
    )
      return false;
    return model === "TENANT_AWARE"
      ? !!actor.tenantFingerprint && proof.tenantMatched === true && proof.tenantHash === actor.tenantFingerprint
      : actor.identityModel === "PRINCIPAL_ROLE" &&
          proof.identityModel === "PRINCIPAL_ROLE" &&
          proof.tenantVerification === "NOT_APPLICABLE" &&
          proof.tenantMatched === undefined &&
          proof.tenantHash === undefined &&
          actor.tenantFingerprint === undefined;
  } catch {
    return false;
  }
}
