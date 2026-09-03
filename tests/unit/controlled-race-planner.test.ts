import { describe, expect, it } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import { AppError } from "../../src/core/errors/AppError.js";
import { controlledRaceInputSchema, planControlledRace } from "../../src/modules/controlledRace/ControlledRacePlanner.js";

const target = "https://app.example.test/";
const scope = { ...exampleScope, allowedDomains: ["app.example.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"] as const };
const actor = { id: "member", safeAlias: "disposable-member", authSlot: "primary" as const, relationship: "SELF", declaredState: "ACTIVE" };
const authorization = { mode: "CONTROLLED_RACE" as const, environment: "TEST" as const, confirmation: "I_AUTHORIZE_CONTROLLED_RACE_TESTING" as const, authorizedBy: "operator-44", changeTicket: "RACE-44", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableEntities: true as const };
const authProfile = { label: "member", headers: { Authorization: "Bearer transport-secret" }, cookies: [], identityVerification: { mode: "disabled" as const, method: "GET" as const, expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: { race_token: "one-time-secret" }, notes: [] };

function raceCase() {
  const observation = (id: string, name: string) => ({ id, actorId: "member", request: { method: "GET" as const, url: `${target}state`, stateChanging: false }, captures: [{ name, source: "JSON" as const, path: "events" }] });
  const member = (id: string) => ({ id, actorId: "member", request: { method: "POST" as const, url: `${target}redeem`, stateChanging: true, bodyFormat: "JSON" as const, fields: { token: "{{SECRET:race_token}}" } }, expectation: { authorization: "ALLOW" as const, businessRule: "NOT_EVALUATED" as const } });
  return { id: "token-race", label: "Token effect happens once", category: "ONE_TIME_TOKEN" as const, target: { type: "one-time-token", safeAlias: "disposable-token", identityFingerprint: "a".repeat(64), disposable: true as const }, actors: [actor], authorization: { ...authorization }, preState: [observation("before", "events_before")], groups: [{ id: "redeem-race", label: "Two synchronized redemptions", synchronization: "READY_BARRIER" as const, maxDispatchSkewMs: 100, requests: [member("redeem-a"), member("redeem-b")] }], postState: [observation("after", "events_after")], invariants: [{ id: "one-event", kind: "EVENT_COUNT_DELTA" as const, before: "events_before", after: "events_after", operator: "LTE" as const, expected: 1 }, { id: "one-accept", kind: "GROUP_OUTCOME_COUNT" as const, groupId: "redeem-race", outcome: "ACCEPTED" as const, operator: "LTE" as const, expected: 1 }], cleanupRequired: true as const, cleanup: [{ id: "reset", actorId: "member", request: { method: "DELETE" as const, url: `${target}redeem`, stateChanging: true }, successStatusCodes: [204] }], cleanupVerification: [observation("restored", "events_restored")], cleanupInvariants: [{ id: "restored-events", kind: "VALUE_COMPARE" as const, left: { source: "CAPTURE" as const, ref: "events_restored" }, operator: "EQ" as const, right: { source: "CAPTURE" as const, ref: "events_before" } }] };
}

describe("controlled race planner", () => {
  it("plans an explicit synchronized group and removes authority and secret material", () => {
    const plan = planControlledRace(controlledRaceInputSchema.parse({ maxConcurrency: 5, cases: [raceCase()] }), { target, scope, authProfile });
    expect(plan.cases[0]).toMatchObject({ category: "ONE_TIME_TOKEN", authorization: { mode: "CONTROLLED_RACE", authorizationIdentityConfirmed: true, changeTicketConfirmed: true }, groups: [{ synchronization: "READY_BARRIER", maxDispatchSkewMs: 100 }] });
    expect(plan.cases[0]?.groups[0]?.requests).toHaveLength(2);
    for (const secret of ["operator-44", "RACE-44", "transport-secret", "one-time-secret"]) expect(JSON.stringify(plan)).not.toContain(secret);
  });

  it("rejects non-mutations, oversized groups, literal tokens, and expired authority", () => {
    const read: any = raceCase(); read.groups[0].requests[0].request = { method: "GET", url: `${target}redeem`, stateChanging: false };
    expect(() => planControlledRace(controlledRaceInputSchema.parse({ cases: [read] }), { target, scope, authProfile })).toThrowError(AppError);
    const oversized: any = raceCase(); oversized.groups[0].requests = Array.from({ length: 6 }, (_, index) => ({ ...oversized.groups[0].requests[0], id: `member-${index}` }));
    expect(() => controlledRaceInputSchema.parse({ cases: [oversized] })).toThrow();
    const literal: any = raceCase(); literal.groups[0].requests[0].request.fields.token = "raw-token";
    expect(() => planControlledRace(controlledRaceInputSchema.parse({ cases: [literal] }), { target, scope, authProfile })).toThrow(/reference-only/i);
    const expired: any = raceCase(); expired.authorization.expiresAt = "2026-02-01T00:00:00.000Z";
    expect(() => planControlledRace(controlledRaceInputSchema.parse({ cases: [expired] }), { target, scope, authProfile, now: new Date("2026-08-30T00:00:00.000Z") })).toThrow(/not currently valid/i);
  });

  it("changes the contract fingerprint when a race invariant is weakened", () => {
    const before = planControlledRace(controlledRaceInputSchema.parse({ maxConcurrency: 5, cases: [raceCase()] }), { target, scope, authProfile }).cases[0]!.comparisonFingerprint;
    const changed: any = raceCase(); changed.invariants[0].expected = 0;
    const after = planControlledRace(controlledRaceInputSchema.parse({ maxConcurrency: 5, cases: [changed] }), { target, scope, authProfile }).cases[0]!.comparisonFingerprint;
    expect(after).not.toBe(before);
  });
});
