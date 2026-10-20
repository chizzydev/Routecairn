import { it, expect } from "vitest";
import {
  assessApplicationOnboardingCompatibility as assess,
  unknownOnboardingCompatibility as unknown
} from "../../src/dashboard/contracts/ApplicationOnboardingCompatibility.js";
import { applicationOnboardingSchema } from "../../src/dashboard/contracts/ApplicationOnboardingContracts.js";
it("reports all five source-backed incompatibilities without inventing an application identity", () => {
  const result = assess({
    tenantIdentity: "ABSENT",
    actorProfiles: "INSUFFICIENT",
    getEffects: "WRITES",
    runtimeIsolation: "UNCONFIRMED",
    resourceShape: "COLLECTION_ONLY"
  });
  expect(result.status).toBe("BLOCKED");
  expect(result.blockers.map((b) => b.code)).toEqual([
    "TENANTLESS_MAPPING_UNSUPPORTED",
    "THREE_REAL_ACTORS_REQUIRED",
    "GET_SIDE_EFFECT_REVIEW_REQUIRED",
    "RUNTIME_ISOLATION_REQUIRED",
    "SCALAR_OWNERSHIP_EVIDENCE_REQUIRED"
  ]);
  expect(result).toMatchObject({
    executionAuthority: "NONE",
    requestsSent: 0,
    credentialDecryption: false,
    nativeVerified: false
  });
});
it("keeps unknown facts incomplete and known blockers dominant", () => {
  expect(assess(unknown)).toMatchObject({ status: "INCOMPLETE", unknown: Object.keys(unknown) });
  expect(assess({ ...unknown, getEffects: "WRITES" }).status).toBe("BLOCKED");
});
it("compatible declarations still require the existing server and native authorization contract", () => {
  const result = assess({
    tenantIdentity: "PRESENT",
    actorProfiles: "THREE_DISTINCT",
    getEffects: "READ_ONLY",
    runtimeIsolation: "CONFIRMED",
    resourceShape: "SCALAR_MARKERS"
  });
  expect(result.status).toBe("DECLARED_COMPATIBLE_REVIEW_REQUIRED");
  expect(result.executionAuthority).toBe("NONE");
  expect(applicationOnboardingSchema.safeParse({}).success).toBe(false);
  expect(
    applicationOnboardingSchema.safeParse({ ownedReadOnlyConfirmed: true, tenantField: "", actors: {} }).success
  ).toBe(false);
});
it("rejects credentials, free text, unsupported statuses and extra authority fields instead of echoing them", () => {
  for (const extra of [
    { authorizationHeader: "Bearer never-store" },
    { executionAuthority: "APPROVED" },
    { getEffects: "GET_IMPLIES_SAFE" }
  ])
    expect(() => assess({ ...unknown, ...extra })).toThrow();
  expect(() => assess(null)).toThrow();
});
