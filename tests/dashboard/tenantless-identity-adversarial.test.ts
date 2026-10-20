import { it, expect } from "vitest";
import { createHash } from "node:crypto";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";
import { applicationOnboardingSchema } from "../../src/dashboard/contracts/ApplicationOnboardingContracts.js";
import { nativeApplicationProofMatches } from "../../src/dashboard/execution/ApplicationIdentity.js";
import { assessApplicationOnboardingCompatibility } from "../../src/dashboard/contracts/ApplicationOnboardingCompatibility.js";
import type { ApiGraphqlActorPlan } from "../../src/modules/apiGraphql/ApiGraphqlTypes.js";
import type { IdentityVerificationResult } from "../../src/reports/ReportTypes.js";
const profile = () => ({
  identityModel: "PRINCIPAL_ROLE",
  principalId: "actor-a",
  role: "user",
  identityVerification: { mode: "required", endpoint: "/identity", principalIdField: "id", roleField: "role" }
});
const hash = (v: string) =>
  createHash("sha256")
    .update("routecairn-identity-v1\0" + v)
    .digest("hex")
    .slice(0, 16);
const actor = (): ApiGraphqlActorPlan => ({
  id: "primary",
  safeAlias: "Generated",
  authSlot: "primary",
  relationship: "DECLARED_PRIMARY",
  identityModel: "PRINCIPAL_ROLE",
  principalFingerprint: hash("actor-a"),
  role: "user"
});
const proof = (): IdentityVerificationResult => ({
  profileLabel: "Generated",
  identityModel: "PRINCIPAL_ROLE",
  tenantVerification: "NOT_APPLICABLE",
  mode: "required",
  category: "VERIFIED",
  verified: true,
  required: true,
  principalMatched: true,
  roleMatched: true,
  principalHash: hash("actor-a"),
  roleHash: hash("user"),
  timestamp: "2026-10-20T00:00:00Z",
  notes: []
});
it("requires exact principal and role contracts without accepting tenant substitutions", () => {
  for (const extra of [
    { principalId: "" },
    { role: "" },
    { identityModel: "GUESSED" },
    { tenantId: "actor-a" },
    { identityVerification: { ...profile().identityVerification, tenantIdField: "id" } },
    { identityVerification: { ...profile().identityVerification, roleField: undefined } }
  ])
    expect(authProfileSchema.safeParse({ ...profile(), ...extra }).success).toBe(false);
  expect(authProfileSchema.safeParse(profile()).success).toBe(true);
});
it("never reinterprets old tenant-aware proofs as tenantless or treats tenant metadata as not applicable", () => {
  expect(nativeApplicationProofMatches(actor(), proof())).toBe(true);
  for (const changed of [
    { identityModel: undefined },
    { identityModel: "TENANT_AWARE" },
    { roleMatched: false },
    { roleHash: hash("admin") },
    { principalHash: hash("other") },
    { principalMatched: false },
    { verified: false },
    { tenantMatched: true },
    { tenantHash: hash("fabricated") },
    { tenantVerification: undefined }
  ])
    expect(nativeApplicationProofMatches(actor(), { ...proof(), ...changed } as IdentityVerificationResult)).toBe(
      false
    );
});
it("preserves legacy and explicit tenant-aware identity requirements", () => {
  const a = actor();
  delete a.identityModel;
  a.tenantFingerprint = hash("tenant-a");
  const p = proof();
  delete p.identityModel;
  delete p.tenantVerification;
  p.tenantMatched = true;
  p.tenantHash = hash("tenant-a");
  expect(nativeApplicationProofMatches(a, p)).toBe(true);
  const missing = { ...p };
  delete missing.tenantMatched;
  expect(nativeApplicationProofMatches(a, missing)).toBe(false);
  expect(
    nativeApplicationProofMatches({ ...a, identityModel: "TENANT_AWARE" }, { ...p, identityModel: "TENANT_AWARE" })
  ).toBe(true);
  expect(authProfileSchema.safeParse({ ...profile(), identityModel: "TENANT_AWARE" }).success).toBe(false);
});
it("tenantless compatibility removes only the tenant requirement, preserving genuine remaining blockers", () => {
  const r = assessApplicationOnboardingCompatibility({
    identityModel: "PRINCIPAL_ROLE",
    tenantIdentity: "ABSENT",
    actorProfiles: "INSUFFICIENT",
    getEffects: "WRITES",
    runtimeIsolation: "UNCONFIRMED",
    resourceShape: "COLLECTION_ONLY"
  });
  expect(r.blockers.map((b) => b.code)).toEqual([
    "THREE_REAL_ACTORS_REQUIRED",
    "GET_SIDE_EFFECT_REVIEW_REQUIRED",
    "RUNTIME_ISOLATION_REQUIRED",
    "SCALAR_OWNERSHIP_EVIDENCE_REQUIRED"
  ]);
  expect(r.executionAuthority).toBe("NONE");
});
it("refuses tenantless onboarding with invented tenant fields", () => {
  const input = { identityModel: "PRINCIPAL_ROLE", tenantField: "id", objectTenantField: "id" };
  expect(applicationOnboardingSchema.safeParse(input).success).toBe(false);
});
