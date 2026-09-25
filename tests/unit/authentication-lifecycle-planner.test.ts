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
        { id: "verify", phase: "VERIFY", actorId: "member", request: { method: "GET", url: new URL("/session", target).toString(), stateChanging: false, headers: { Authorization: "Bearer {{CAPTURE:session}}" } }, assertions: [{ kind: "STATUS_IN", values: [200] }] },
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

  it("plans native fixture actions and compiles turnkey provider calls", () => {
    const providerTarget = "https://project.supabase.co/";
    const providerScope = { ...scope, allowedDomains: ["project.supabase.co"] };
    const authProfile = { label: "fixture-member", headers: {}, cookies: [], identityVerification: { mode: "disabled" as const, method: "GET" as const, expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: { totp_seed: "JBSWY3DPEHPK3PXP", recipient: "fixture@example.test", anon_key: "fixture-anon-key" }, notes: [] };
    const input = authenticationLifecycleInputSchema.parse({
      fixtures: {
        inboxes: [{ id: "mail", kind: "LOCAL_HTTP" }],
        totp: [{ id: "mfa", secretRef: "totp_seed" }],
        providers: [{ id: "supabase", provider: "SUPABASE_AUTH", baseUrl: providerTarget, apiKeySecretRef: "anon_key" }]
      },
      cases: [{ id: "fixture-case", label: "Fixture lifecycle", category: "MFA_ENROLLMENT_REMOVAL", actors: [{ id: "member", safeAlias: "fixture-member", authSlot: "primary", relationship: "SELF", declaredState: "ACTIVE" }], authorization: observeAuthorization, steps: [{ id: "authorize", phase: "VERIFY", actorId: "member", fixtureActions: [{ kind: "TOTP_GENERATE", profileId: "mfa", capture: "totp_code" }], providerCall: { adapterId: "supabase", operation: "OAUTH_AUTHORIZE" }, assertions: [{ kind: "STATUS_IN", values: [302] }] }] }]
    });
    const plan = planAuthenticationLifecycle(input, { target: providerTarget, scope: providerScope, authProfile });
    expect(plan.cases[0]?.steps[0]).toMatchObject({ fixtureActions: [{ kind: "TOTP_GENERATE", capture: "totp_code" }], request: { method: "GET", url: "https://project.supabase.co/auth/v1/authorize", headers: { apikey: "{{SECRET:anon_key}}" } } });
    expect(JSON.stringify(plan)).not.toContain("fixture-anon-key");
  });

  it("plans the complete OIDC callback action and exposes only declared transient captures", () => {
    const authProfile = { label: "oidc-member", headers: {}, cookies: [], identityVerification: { mode: "disabled" as const, method: "GET" as const, expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: { client_id: "fixture-client", client_secret: "fixture-secret", subject: "fixture-subject", state: "state-0123456789abcdef", nonce: "nonce-0123456789abcdef", verifier: "v".repeat(64) }, notes: [] };
    const input = authenticationLifecycleInputSchema.parse({
      fixtures: { oidc: [{ id: "local-idp", clientIdSecretRef: "client_id", clientSecretRef: "client_secret", redirectUris: ["http://127.0.0.1/callback"], subjectSecretRef: "subject" }] },
      cases: [{ id: "oidc-flow", label: "Complete OIDC flow", category: "OAUTH_OIDC_STATE_REDIRECT_VALIDATION", actors: [{ id: "member", safeAlias: "oidc-member", authSlot: "primary", relationship: "SELF", declaredState: "ACTIVE" }], authorization: observeAuthorization, steps: [{ id: "verify", phase: "VERIFY", actorId: "member", fixtureActions: [{ kind: "OIDC_AUTHORIZATION_CODE", harnessId: "local-idp", stateSecretRef: "state", nonceSecretRef: "nonce", pkceVerifierSecretRef: "verifier", captureSubject: "verified_subject" }], request: { method: "GET", url: `${target}session?subject={{CAPTURE:verified_subject}}`, stateChanging: false }, assertions: [{ kind: "STATUS_IN", values: [200] }] }] }]
    });
    const plan = planAuthenticationLifecycle(input, { target, scope, authProfile });
    expect(plan.cases[0]?.steps[0]?.fixtureActions).toEqual([{ kind: "OIDC_AUTHORIZATION_CODE", harnessId: "local-idp", stateSecretRef: "state", nonceSecretRef: "nonce", pkceVerifierSecretRef: "verifier", captureSubject: "verified_subject", timeoutMs: 30000 }]);
    expect(JSON.stringify(plan)).not.toContain("fixture-secret");
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
