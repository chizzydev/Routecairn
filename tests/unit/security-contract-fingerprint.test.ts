import { describe, expect, it } from "vitest";
import { securityContractFingerprint, securityContractValueHash } from "../../src/core/comparisons/SecurityContractFingerprint.js";

describe("security contract fingerprints", () => {
  it("is canonical across object key order and operational approval provenance", () => {
    const first = securityContractFingerprint("fixture", { category: "AUTH", assertion: { kind: "JSON_EQUALS", expected: true }, authorization: { authorizedBy: "operator-a", changeTicket: "A-1", expiresAt: "2026-01-01T00:00:00Z" } });
    const second = securityContractFingerprint("fixture", { authorization: { expiresAt: "2027-01-01T00:00:00Z", changeTicket: "B-2", authorizedBy: "operator-b" }, assertion: { expected: true, kind: "JSON_EQUALS" }, category: "AUTH" });
    expect(second).toBe(first);
  });

  it("changes for assertion values, actor semantics, request contracts, bindings, and cleanup verification", () => {
    const base = { actor: { id: "member", relationship: "SELF" }, request: { method: "GET", url: "https://app.test/object" }, resource: { id: "object", ownerActorId: "member" }, assertion: { kind: "JSON_EQUALS", expected: true }, cleanupVerification: { path: "state", expected: "restored" } };
    const fingerprint = securityContractFingerprint("fixture", base);
    for (const changed of [
      { ...base, assertion: { ...base.assertion, expected: false } },
      { ...base, actor: { ...base.actor, relationship: "FOREIGN" } },
      { ...base, request: { ...base.request, method: "HEAD" } },
      { ...base, resource: { ...base.resource, ownerActorId: "other" } },
      { ...base, resource: { ...base.resource, expiresAt: "2027-01-01T00:00:00Z" } },
      { ...base, cleanupVerification: { ...base.cleanupVerification, expected: "pending" } }
    ]) expect(securityContractFingerprint("fixture", changed)).not.toBe(fingerprint);
  });

  it("hashes sensitive values into stable non-reversible contract material", () => {
    const value = securityContractValueHash("fixture-secret", "sensitive-sentinel");
    expect(value).toMatch(/^[a-f0-9]{64}$/);
    expect(value).not.toContain("sensitive-sentinel");
    expect(securityContractValueHash("fixture-secret", "changed-sentinel")).not.toBe(value);
  });
});
