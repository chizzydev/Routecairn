import { describe, expect, it } from "vitest";
import type { AuthProfile } from "../../src/core/auth/AuthProfile.js";
import { exampleScope } from "../../src/config/defaults.js";
import { linkPortalSecurityInputSchema, planLinkPortalSecurity } from "../../src/modules/linkPortalSecurity/LinkPortalSecurityPlanner.js";

const profile = (principalId: string, tenantId: string): AuthProfile => ({ label: principalId, safeAlias: principalId, principalId, tenantId, headers: { Authorization: `Bearer ${principalId}-secret` }, cookies: [], identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: { signed_token: `${principalId}-signed-value`, object_id: `${principalId}-object`, invite_email: `${principalId}@example.test` }, notes: [] });
const context = { target: "https://app.example.test/", scope: { ...exampleScope, allowedDomains: ["app.example.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "DELETE"] as const }, authProfileSet: { accountA: profile("account-a", "tenant-a"), accountB: profile("account-b", "tenant-b") }, now: new Date("2026-08-30T12:00:00.000Z") };

describe("link/portal/export security planner", () => {
  it("builds a bounded structural plan without retaining credentials or secret values", () => {
    const plan = planLinkPortalSecurity(linkPortalSecurityInputSchema.parse(validInput()), context);
    expect(plan).toMatchObject({ enabled: true, actors: [{ authSlot: "anonymous" }, { authSlot: "account_a" }, { authSlot: "account_b" }], resources: [{ kind: "SIGNED_LINK" }], cases: [{ category: "SIGNATURE_TAMPERING" }] });
    expect(plan.cases[0]?.comparisonFingerprint).toHaveLength(64);
    expect(JSON.stringify(plan)).not.toContain("account-a-secret");
    expect(JSON.stringify(plan)).not.toContain("account-a-signed-value");
  });

  it("rejects literal signatures, missing tampering, forward captures, and unapproved mutation", () => {
    const literal: any = validInput(); literal.cases[0].steps[0].request.urlTemplate = "https://app.example.test/signed/object?signature=literal-secret";
    expect(() => planLinkPortalSecurity(linkPortalSecurityInputSchema.parse(literal), context)).toThrow(/must use a secret or capture reference/i);

    const noTamper: any = validInput(); delete noTamper.cases[0].steps[1].request.tamper;
    expect(() => planLinkPortalSecurity(linkPortalSecurityInputSchema.parse(noTamper), context)).toThrow(/automatic tamper request/i);

    const capture: any = validInput(); capture.cases[0].steps[0].request.urlTemplate = "{{CAPTURE:signed_url}}";
    expect(() => planLinkPortalSecurity(linkPortalSecurityInputSchema.parse(capture), context)).toThrow(/earlier step/i);

    const mutation: any = validInput(); mutation.cases[0].category = "SIGNED_LINK_REPLAY"; mutation.cases[0].steps[0].request = { method: "POST", urlTemplate: "https://app.example.test/signed/redeem", stateChanging: true, secretSource: "account_a", fields: { token: "{{SECRET:signed_token}}" } }; mutation.cases[0].steps[1].request = { ...mutation.cases[0].steps[0].request }; mutation.cases[0].authorization = { mode: "OBSERVE_ONLY", environment: "TEST", disposableResource: true };
    expect(() => planLinkPortalSecurity(linkPortalSecurityInputSchema.parse(mutation), context)).toThrow(/controlled authorization/i);
  });

  it("requires distinct tenants and explicit actor matrices for boundary cases", () => {
    const cross: any = validInput(); cross.cases[0].category = "CROSS_TENANT_SIGNED_LINK"; cross.cases[0].steps[1].request.tamper = undefined; cross.cases[0].steps[1].actorId = "owner";
    expect(() => planLinkPortalSecurity(linkPortalSecurityInputSchema.parse(cross), context)).toThrow(/distinct declared tenant/i);

    const ownership: any = validInput(); ownership.cases[0].category = "OBJECT_PATH_OWNERSHIP"; delete ownership.cases[0].steps[1].request.tamper; ownership.cases[0].steps[1].actorId = "owner";
    expect(() => planLinkPortalSecurity(linkPortalSecurityInputSchema.parse(ownership), context)).toThrow(/at least two explicit actors/i);
  });

  it("changes the contract fingerprint when a link decision assertion changes", () => {
    const before = planLinkPortalSecurity(linkPortalSecurityInputSchema.parse(validInput()), context).cases[0]!.comparisonFingerprint;
    const changed: any = validInput(); changed.cases[0].steps[1].assertions[0].expected = "ALLOW";
    const after = planLinkPortalSecurity(linkPortalSecurityInputSchema.parse(changed), context).cases[0]!.comparisonFingerprint;
    expect(after).not.toBe(before);
  });
});

function validInput(): unknown {
  return {
    schemaVersion: 1, maxCases: 10, maxStepsPerCase: 8, maxRequests: 20, maxResponseBytes: 65536,
    actors: [
      { id: "anonymous", safeAlias: "anonymous", authSlot: "anonymous", relationship: "PUBLIC" },
      { id: "owner", safeAlias: "owner", authSlot: "account_a", relationship: "OWNER", principalId: "account-a", tenantId: "tenant-a" },
      { id: "foreign", safeAlias: "foreign", authSlot: "account_b", relationship: "CROSS_TENANT_MEMBER", principalId: "account-b", tenantId: "tenant-b" }
    ],
    resources: [{ id: "signed", safeAlias: "signed", kind: "SIGNED_LINK", pathTemplate: "/signed/{object}", allowedOrigins: ["https://app.example.test"], ownerActorId: "owner", tenantId: "tenant-a" }],
    cases: [{ id: "tamper", label: "tamper", category: "SIGNATURE_TAMPERING", authorization: { mode: "OBSERVE_ONLY", environment: "TEST" }, steps: [
      { id: "control", phase: "CONTROL", actorId: "owner", resourceId: "signed", request: { method: "GET", urlTemplate: "https://app.example.test/signed/{{SECRET:object_id}}?signature={{SECRET:signed_token}}", secretSource: "account_a" }, assertions: [{ kind: "DECISION", expected: "ALLOW" }] },
      { id: "tampered", phase: "VERIFY", actorId: "foreign", resourceId: "signed", request: { method: "GET", urlTemplate: "https://app.example.test/signed/{{SECRET:object_id}}?signature={{SECRET:signed_token}}", secretSource: "account_a", tamper: { kind: "QUERY_PARAMETER", parameter: "signature", strategy: "FLIP_LAST_CHARACTER" } }, assertions: [{ kind: "DECISION", expected: "DENY" }] }
    ] }]
  };
}
