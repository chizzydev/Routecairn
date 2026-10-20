import { it, expect } from "vitest";
import { collectionPrincipalHash as fp } from "../../src/modules/apiGraphql/CollectionOwnership.js";
import { nativeApplicationProofMatches } from "../../src/core/auth/NativeIdentityAdmission.js";
import type { ApiGraphqlActorPlan } from "../../src/modules/apiGraphql/ApiGraphqlTypes.js";
import type { IdentityVerificationResult } from "../../src/reports/ReportTypes.js";
it.each(["TENANT_AWARE", "PRINCIPAL_ROLE"] as const)(
  "constructed-state falsification of %s is separate from reachable CLI RED",
  (model) => {
    const actor: ApiGraphqlActorPlan = {
      id: "primary",
      safeAlias: "owner",
      authSlot: "primary",
      relationship: "OWNER",
      identityModel: model,
      principalFingerprint: fp("person"),
      role: "user",
      ...(model === "TENANT_AWARE" ? { tenantFingerprint: fp("tenant") } : {})
    };
    const proof: IdentityVerificationResult = {
      profileLabel: "owner",
      identityModel: model,
      tenantVerification: model === "TENANT_AWARE" ? "REQUIRED" : "NOT_APPLICABLE",
      mode: "required",
      category: "VERIFIED",
      verified: true,
      required: true,
      principalMatched: true,
      roleMatched: true,
      principalHash: fp("person"),
      roleHash: fp("user"),
      timestamp: new Date().toISOString(),
      notes: [],
      ...(model === "TENANT_AWARE" ? { tenantMatched: true, tenantHash: fp("tenant") } : {})
    };
    expect(nativeApplicationProofMatches(actor, proof)).toBe(true);
    for (const patch of [
      { verified: false },
      { principalMatched: false },
      { principalMatched: undefined },
      { principalHash: undefined },
      { principalHash: fp("foreign") },
      { roleMatched: false },
      { roleMatched: undefined },
      { roleHash: undefined },
      { roleHash: fp("admin") },
      { identityModel: model === "TENANT_AWARE" ? "PRINCIPAL_ROLE" : "TENANT_AWARE" }
    ])
      expect(nativeApplicationProofMatches(actor, { ...proof, ...patch } as IdentityVerificationResult)).toBe(false);
    for (const patch of [
      { principalFingerprint: undefined },
      { principalFingerprint: fp("other") },
      { role: "admin" },
      { role: undefined }
    ])
      expect(nativeApplicationProofMatches({ ...actor, ...patch } as ApiGraphqlActorPlan, proof)).toBe(false);
    if (model === "TENANT_AWARE")
      for (const patch of [
        { tenantMatched: undefined },
        { tenantMatched: false },
        { tenantHash: undefined },
        { tenantHash: fp("other") }
      ])
        expect(nativeApplicationProofMatches(actor, { ...proof, ...patch } as IdentityVerificationResult)).toBe(false);
    else
      for (const patch of [{ tenantMatched: true }, { tenantHash: fp("tenant") }, { tenantVerification: undefined }])
        expect(nativeApplicationProofMatches(actor, { ...proof, ...patch } as IdentityVerificationResult)).toBe(false);
  }
);
