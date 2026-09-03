import { describe, expect, it } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import { AppError } from "../../src/core/errors/AppError.js";
import { authenticationLifecycleCategories } from "../../src/modules/authenticationLifecycle/AuthenticationLifecycleTypes.js";
import { authenticationLifecycleInputSchema, planAuthenticationLifecycle } from "../../src/modules/authenticationLifecycle/AuthenticationLifecyclePlanner.js";

const target = "https://app.example.test/";
const scope = { ...exampleScope, allowedDomains: ["app.example.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"] as const };
const anonymousActor = { id: "public", safeAlias: "public-actor", authSlot: "anonymous" as const, relationship: "PUBLIC", declaredState: "ANONYMOUS" };
const observeAuthorization = { mode: "OBSERVE_ONLY" as const, environment: "TEST" as const };

describe("authentication lifecycle planner", () => {
  it("plans every lifecycle category and creates secret-free stable comparison fingerprints", () => {
    const input = authenticationLifecycleInputSchema.parse({
      maxCases: authenticationLifecycleCategories.length,
      maxRequests: authenticationLifecycleCategories.length,
      cases: authenticationLifecycleCategories.map((category, index) => ({
        id: `case-${index}`,
        label: `Lifecycle contract ${index}`,
        category,
        actors: [anonymousActor],
        authorization: observeAuthorization,
        steps: [{ id: `verify-${index}`, phase: "VERIFY", actorId: "public", request: { method: "GET", url: new URL(`/lifecycle/${index}`, target).toString(), stateChanging: false }, assertions: [{ kind: "STATUS_IN", values: [200] }] }]
      }))
    });
    const plan = planAuthenticationLifecycle(input, { target, scope });
    expect(plan.cases.map((item) => item.category)).toEqual(authenticationLifecycleCategories);
    expect(new Set(plan.cases.map((item) => item.comparisonFingerprint)).size).toBe(authenticationLifecycleCategories.length);
    expect(JSON.stringify(plan)).not.toContain("authorizedBy");
    expect(JSON.stringify(plan)).not.toContain("changeTicket\"");
  });

  it("hashes authorization identities and accepts only referenced worker-held secrets", () => {
    const input = authenticationLifecycleInputSchema.parse({ cases: [{
      id: "rotate", label: "Rotate session", category: "SESSION_ROTATION_AFTER_LOGIN", actors: [{ id: "member", safeAlias: "disposable-member", authSlot: "primary", relationship: "SELF", declaredState: "ACTIVE" }],
      authorization: { mode: "CONTROLLED_LIFECYCLE", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING", authorizedBy: "security-operator", changeTicket: "AUTH-42", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableAccounts: true }, cleanupRequired: true,
      steps: [
        { id: "login", phase: "ACTION", actorId: "member", request: { method: "POST", url: new URL("/login", target).toString(), stateChanging: true, fields: { username: "{{SECRET:username}}", password: "{{SECRET:password}}" } }, captures: [{ name: "session", source: "COOKIE", cookie: "session" }], assertions: [{ kind: "STATUS_IN", values: [200] }] },
        { id: "logout", phase: "CLEANUP", actorId: "member", request: { method: "POST", url: new URL("/logout", target).toString(), stateChanging: true, headers: { Cookie: "session={{CAPTURE:session}}" } }, assertions: [{ kind: "STATUS_IN", values: [204] }] }
      ]
    }] });
    const authProfile = { label: "member", headers: {}, cookies: [], identityVerification: { mode: "disabled" as const, method: "GET" as const, expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: { username: "member@example.test", password: "test-password" }, notes: [] };
    const plan = planAuthenticationLifecycle(input, { target, scope, authProfile });
    expect(plan.cases[0]?.authorization.authorizationIdentityConfirmed).toBe(true);
    expect(plan.cases[0]?.authorization.changeTicketConfirmed).toBe(true);
    expect(JSON.stringify(plan)).not.toContain("security-operator");
    expect(JSON.stringify(plan)).not.toContain("AUTH-42");
    expect(JSON.stringify(plan)).not.toContain("member@example.test");
    expect(JSON.stringify(plan)).not.toContain("test-password");
  });

  it("changes the contract fingerprint when an assertion value changes", () => {
    const lifecycleCase = (expected: boolean) => ({ id: "assertion", label: "Assertion binding", category: "DISABLED_USER_SESSION_BEHAVIOR" as const, actors: [anonymousActor], authorization: observeAuthorization, steps: [{ id: "verify", phase: "VERIFY" as const, actorId: "public", request: { method: "GET" as const, url: new URL("/session", target).toString(), stateChanging: false }, assertions: [{ kind: "JSON_EQUALS" as const, path: "active", expected }] }] });
    const before = planAuthenticationLifecycle(authenticationLifecycleInputSchema.parse({ cases: [lifecycleCase(true)] }), { target, scope }).cases[0]!.comparisonFingerprint;
    const weakened = planAuthenticationLifecycle(authenticationLifecycleInputSchema.parse({ cases: [lifecycleCase(false)] }), { target, scope }).cases[0]!.comparisonFingerprint;
    expect(weakened).not.toBe(before);
  });

  it("rejects implicit mutations, literal secrets, missing cleanup, and out-of-scope requests", () => {
    const base = { id: "bad", label: "Bad case", category: "SESSION_REVOCATION", actors: [anonymousActor], authorization: observeAuthorization, steps: [{ id: "action", phase: "ACTION", actorId: "public", request: { method: "POST", url: new URL("/revoke", target).toString(), stateChanging: false } }] };
    expect(() => planAuthenticationLifecycle(authenticationLifecycleInputSchema.parse({ cases: [base] }), { target, scope })).toThrowError(AppError);
    const literal = { ...base, category: "LOGIN_ENUMERATION_RESISTANCE", steps: [{ ...base.steps[0], request: { method: "GET", url: new URL("/login", target).toString(), stateChanging: false, headers: { Authorization: "Bearer raw-secret" } } }] };
    expect(() => planAuthenticationLifecycle(authenticationLifecycleInputSchema.parse({ cases: [literal] }), { target, scope })).toThrow(/SECRET|reference|Credential/i);
    const outside = { ...base, category: "IDLE_EXPIRATION", steps: [{ id: "verify", phase: "VERIFY", actorId: "public", request: { method: "GET", url: "https://outside.example.test/session", stateChanging: false }, assertions: [{ kind: "STATUS_IN", values: [401] }] }] };
    expect(() => planAuthenticationLifecycle(authenticationLifecycleInputSchema.parse({ cases: [outside] }), { target, scope })).toThrow(/origin|scope/i);
  });
});
