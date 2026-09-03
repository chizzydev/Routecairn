import { describe, expect, it } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import { AppError } from "../../src/core/errors/AppError.js";
import { businessInvariantInputSchema, planBusinessInvariant } from "../../src/modules/businessInvariant/BusinessInvariantPlanner.js";

const target = "https://app.example.test/";
const scope = { ...exampleScope, allowedDomains: ["app.example.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"] as const };
const authorization = { mode: "CONTROLLED_INVARIANT" as const, environment: "TEST" as const, confirmation: "I_AUTHORIZE_CONTROLLED_BUSINESS_INVARIANT_TESTING" as const, authorizedBy: "operator-reference", changeTicket: "BIZ-43", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableEntities: true as const };
const actor = { id: "member", safeAlias: "disposable-member", authSlot: "primary" as const, relationship: "SELF", declaredState: "ACTIVE" };
const authProfile = { label: "member", headers: { Authorization: "Bearer raw-profile-token" }, cookies: [], identityVerification: { mode: "disabled" as const, method: "GET" as const, expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: { amount: "10" }, notes: [] };

function validCase() {
  return {
    id: "withdraw", label: "Withdrawal respects balance", category: "FINANCIAL_LIMIT" as const, actors: [actor], authorization,
    preState: [{ id: "before", actorId: "member", request: { method: "GET" as const, url: `${target}state`, stateChanging: false }, captures: [{ name: "before_balance", source: "JSON" as const, path: "balance" }] }],
    actions: [{ id: "action", actorId: "member", request: { method: "POST" as const, url: `${target}withdraw`, stateChanging: true, bodyFormat: "JSON" as const, fields: { amount: "{{SECRET:amount}}" } }, execution: { mode: "CONCURRENT_DUPLICATE" as const, attempts: 2, maxConcurrency: 2 }, expectation: { authorization: "ALLOW" as const, businessRule: "NOT_EVALUATED" as const }, captures: [], captureFromAttempt: "LAST" as const }],
    postState: [{ id: "after", actorId: "member", request: { method: "GET" as const, url: `${target}state`, stateChanging: false }, captures: [{ name: "after_balance", source: "JSON" as const, path: "balance" }] }],
    invariants: [
      { id: "delta", kind: "NUMERIC_DELTA" as const, before: "before_balance", after: "after_balance", operator: "GTE" as const, expected: -20 },
      { id: "accepted", kind: "ACTION_OUTCOME_COUNT" as const, actionId: "action", outcome: "ACCEPTED" as const, operator: "LTE" as const, expected: 1 },
      { id: "responses", kind: "ACTION_RESPONSE_EQUIVALENCE" as const, actionId: "action", compareStatus: true, compareShape: true, compareBodyDigest: false, expectedEquivalent: true },
      { id: "nonnegative", kind: "VALUE_COMPARE" as const, left: { source: "CAPTURE" as const, ref: "after_balance" }, operator: "GTE" as const, right: { source: "LITERAL" as const, value: 0 } },
      { id: "transition", kind: "STATE_TRANSITION" as const, before: "before_balance", after: "after_balance", allowed: [{ from: "100", to: "80" }] }
    ],
    stateMachine: { beforeCapture: "before_balance", afterCapture: "after_balance", states: ["100", "80"], allowedTransitions: [{ from: "100", to: "80" }] },
    cleanupRequired: true as const,
    cleanup: [{ id: "restore", actorId: "member", request: { method: "POST" as const, url: `${target}restore`, stateChanging: true }, successStatusCodes: [204] }],
    cleanupVerification: [{ id: "restored", actorId: "member", request: { method: "GET" as const, url: `${target}state`, stateChanging: false }, captures: [{ name: "restored_balance", source: "JSON" as const, path: "balance" }] }],
    cleanupInvariants: [{ id: "restored-equals-before", kind: "VALUE_COMPARE" as const, left: { source: "CAPTURE" as const, ref: "restored_balance" }, operator: "EQ" as const, right: { source: "CAPTURE" as const, ref: "before_balance" } }]
  };
}

describe("business invariant planner", () => {
  it("plans bounded multi-step, duplicate, state-machine, and cleanup contracts without persisting authority or secrets", () => {
    const input = businessInvariantInputSchema.parse({ maxConcurrency: 2, maxRequests: 20, cases: [validCase()] });
    const plan = planBusinessInvariant(input, { target, scope, authProfile });
    expect(plan.cases[0]).toMatchObject({ category: "FINANCIAL_LIMIT", cleanupRequired: true, authorization: { mode: "CONTROLLED_INVARIANT", authorizationIdentityConfirmed: true, changeTicketConfirmed: true, disposableEntities: true } });
    expect(plan.cases[0]?.actions[0]?.execution).toEqual({ mode: "CONCURRENT_DUPLICATE", attempts: 2, maxConcurrency: 2 });
    expect(JSON.stringify(plan)).not.toContain("operator-reference");
    expect(JSON.stringify(plan)).not.toContain("BIZ-43");
    expect(JSON.stringify(plan)).not.toContain("raw-profile-token");
  });

  it("rejects forward capture references, literal credentials, unsafe concurrency, and expired authorization", () => {
    const forward = validCase(); forward.actions[0]!.request.fields = { amount: "{{CAPTURE:after_balance}}" };
    expect(() => planBusinessInvariant(businessInvariantInputSchema.parse({ cases: [forward] }), { target, scope, authProfile })).toThrow(/unavailable capture/i);
    const literal = validCase(); literal.actions[0]!.request.headers = { Authorization: "Bearer literal-token" };
    expect(() => planBusinessInvariant(businessInvariantInputSchema.parse({ cases: [literal] }), { target, scope, authProfile })).toThrow(/reference-only/i);
    const concurrency = validCase(); concurrency.actions[0]!.execution.maxConcurrency = 3;
    expect(() => planBusinessInvariant(businessInvariantInputSchema.parse({ maxConcurrency: 2, cases: [concurrency] }), { target, scope, authProfile })).toThrowError(AppError);
    const expired = validCase(); expired.authorization = { ...authorization, expiresAt: "2026-02-01T00:00:00.000Z" };
    expect(() => planBusinessInvariant(businessInvariantInputSchema.parse({ cases: [expired] }), { target, scope, authProfile, now: new Date("2026-08-29T00:00:00.000Z") })).toThrow(/not currently valid/i);
  });

  it("changes the contract fingerprint when an invariant threshold changes", () => {
    const before = planBusinessInvariant(businessInvariantInputSchema.parse({ maxConcurrency: 2, maxRequests: 20, cases: [validCase()] }), { target, scope, authProfile }).cases[0]!.comparisonFingerprint;
    const changed: any = validCase(); changed.invariants[0].expected = -10;
    const after = planBusinessInvariant(businessInvariantInputSchema.parse({ maxConcurrency: 2, maxRequests: 20, cases: [changed] }), { target, scope, authProfile }).cases[0]!.comparisonFingerprint;
    expect(after).not.toBe(before);
  });
});
