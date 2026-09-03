import { describe, expect, it } from "vitest";
import type { AuthProfile } from "../../src/core/auth/AuthProfile.js";
import { exampleScope } from "../../src/config/defaults.js";
import { billingEntitlementInputSchema, planBillingEntitlement } from "../../src/modules/billingEntitlement/BillingEntitlementPlanner.js";

const profile: AuthProfile = { label: "fixture", safeAlias: "fixture", principalId: "fixture-principal", headers: { Authorization: "Bearer fixture-private" }, cookies: [], identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: { manipulated_price: "1", expected_price: "1250", baseline_price: "0" }, notes: [] };
const context = { target: "https://billing.example.test/", scope: { ...exampleScope, allowedDomains: ["billing.example.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"] as const }, authProfile: profile, now: new Date("2026-08-30T12:00:00.000Z") };

describe("billing entitlement planner", () => {
  it("plans a synthetic fixture workflow without retaining profile secrets", () => {
    const plan = planBillingEntitlement(billingEntitlementInputSchema.parse(validInput()), context);
    expect(plan).toMatchObject({ enabled: true, provider: { kind: "CUSTOM_SYNTHETIC", realPaymentExecution: "FORBIDDEN" }, cases: [{ category: "CLIENT_PRICE_MANIPULATION", cleanupRequired: true }] });
    expect(plan.cases[0]?.comparisonFingerprint).toHaveLength(64);
    expect(JSON.stringify(plan)).not.toContain("fixture-private"); expect(JSON.stringify(plan)).not.toContain("1250");
  });

  it("rejects payment instruments, real checkout paths, and missing cleanup", () => {
    const instrument: any = validInput(); instrument.cases[0].steps[1].request.fields.card_number = "{{SECRET:expected_price}}";
    expect(() => planBillingEntitlement(billingEntitlementInputSchema.parse(instrument), context)).toThrow(/payment instrument/i);
    const realPath: any = validInput(); realPath.cases[0].steps[1].request.urlTemplate = "https://billing.example.test/api/checkout";
    expect(() => planBillingEntitlement(billingEntitlementInputSchema.parse(realPath), context)).toThrow(/fixture path/i);
    const cleanup: any = validInput(); cleanup.cases[0].cleanupRequired = false; cleanup.cases[0].steps = cleanup.cases[0].steps.filter((step: any) => step.phase !== "CLEANUP"); cleanup.cases[0].assertions = cleanup.cases[0].assertions.filter((assertion: any) => assertion.scope !== "CLEANUP");
    expect(() => planBillingEntitlement(billingEntitlementInputSchema.parse(cleanup), context)).toThrow(/requires cleanup/i);
  });

  it("rejects literal commercial terms and race amplification outside the payment-race category", () => {
    const literal: any = validInput(); literal.cases[0].steps[1].request.fields.price = "1";
    expect(() => planBillingEntitlement(billingEntitlementInputSchema.parse(literal), context)).toThrow(/reference-only/i);
    const race: any = validInput(); race.cases[0].steps[1].execution = { mode: "SYNCHRONIZED", attempts: 5, maxDispatchSkewMs: 250 };
    expect(() => planBillingEntitlement(billingEntitlementInputSchema.parse(race), context)).toThrow(/not a bounded payment-event race/i);
  });

  it("changes the contract fingerprint when authoritative verification changes", () => {
    const before = planBillingEntitlement(billingEntitlementInputSchema.parse(validInput()), context).cases[0]!.comparisonFingerprint;
    const changed: any = validInput(); changed.cases[0].assertions[0].secretRef = "baseline_price";
    const after = planBillingEntitlement(billingEntitlementInputSchema.parse(changed), context).cases[0]!.comparisonFingerprint;
    expect(after).not.toBe(before);
  });
});

function validInput(): unknown {
  const controlled = { mode: "CONTROLLED_SYNTHETIC_BILLING", environment: "TEST", confirmation: "I_AUTHORIZE_SYNTHETIC_BILLING_TESTING", authorizedBy: "operator", changeTicket: "BILL-1", authorizedAt: "2026-08-30T11:00:00.000Z", expiresAt: "2026-08-30T13:00:00.000Z", disposableFixtures: true };
  const observe = (id: string, phase: string, capture: string) => ({ id, phase, actorId: "fixture", endpointId: "state", operation: "OBSERVE", request: { method: "GET", urlTemplate: "https://billing.example.test/state", secretSource: "anonymous" }, captures: [{ name: capture, source: "JSON", path: "price" }] });
  return { schemaVersion: 1, provider: { kind: "CUSTOM_SYNTHETIC", mode: "TEST", fixturePathPrefix: "/__routecairn__/billing-fixtures", realPaymentExecution: "FORBIDDEN" }, actors: [{ id: "fixture", safeAlias: "fixture", authSlot: "primary", relationship: "FIXTURE_OWNER", principalId: "fixture-principal" }], endpoints: [{ id: "checkout", safeAlias: "checkout-validation", kind: "CHECKOUT_VALIDATION", pathTemplate: "/__routecairn__/billing-fixtures/checkout", allowedOrigins: ["https://billing.example.test"] }, { id: "state", safeAlias: "billing-state", kind: "ENTITLEMENT_STATE", pathTemplate: "/state", allowedOrigins: ["https://billing.example.test"] }, { id: "control", safeAlias: "fixture-control", kind: "FIXTURE_CONTROL", pathTemplate: "/__routecairn__/billing-fixtures/reset", allowedOrigins: ["https://billing.example.test"] }], cases: [{ id: "price", label: "price manipulation", category: "CLIENT_PRICE_MANIPULATION", authorization: controlled, cleanupRequired: true, steps: [observe("before", "PRE_STATE", "price_before"), { id: "attempt", phase: "ACTION", actorId: "fixture", endpointId: "checkout", operation: "CHECKOUT_VALIDATION", request: { method: "POST", urlTemplate: "https://billing.example.test/__routecairn__/billing-fixtures/checkout", stateChanging: true, secretSource: "primary", bodyFormat: "JSON", fields: { price: "{{SECRET:manipulated_price}}" } }, expectation: { authorization: "ALLOW", businessRule: "REJECT" } }, observe("after", "VERIFY", "price_after"), { id: "reset", phase: "CLEANUP", actorId: "fixture", endpointId: "control", operation: "RESET_FIXTURE", request: { method: "POST", urlTemplate: "https://billing.example.test/__routecairn__/billing-fixtures/reset", stateChanging: true, secretSource: "anonymous", bodyFormat: "JSON", fields: {} } }, observe("restored", "CLEANUP", "price_restored")], assertions: [{ id: "authoritative-price", scope: "MAIN", kind: "VALUE_EQUALS_SECRET", dimension: "PRICE", capture: "price_after", secretSource: "primary", secretRef: "expected_price" }, { id: "restored-price", scope: "CLEANUP", kind: "VALUE_EQUALS_SECRET", dimension: "PRICE", capture: "price_restored", secretSource: "primary", secretRef: "baseline_price" }] }] };
}
