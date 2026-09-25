import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { generateTotp, LocalTestInboxHarness, MailHogTestInboxAdapter, MailpitTestInboxAdapter, OidcTestHarness, verifyTotp } from "../../src/modules/authenticationLifecycle/AuthenticationFixtures.js";
import { AuthenticationFixtureRuntime } from "../../src/modules/authenticationLifecycle/AuthenticationFixtureRuntime.js";
import { resolveTurnkeyAuthRequest } from "../../src/modules/authenticationLifecycle/TurnkeyAuthProviderAdapters.js";
import { VirtualWebAuthnManager } from "../../src/modules/browserCrawler/VirtualWebAuthnManager.js";

const closeables: Array<{ close(): Promise<void> }> = [];
afterEach(async () => { await Promise.all(closeables.splice(0).map((item) => item.close())); });

describe("authentication fixtures", () => {
  it("implements the RFC 6238 vectors and bounded verification windows", () => {
    const profile = { secret: "12345678901234567890", encoding: "UTF8" as const, algorithm: "SHA1" as const, digits: 8 as const, periodSeconds: 30 };
    expect(generateTotp(profile, new Date(59_000)).code).toBe("94287082");
    expect(generateTotp(profile, new Date(1_111_111_109_000)).code).toBe("07081804");
    expect(verifyTotp("94287082", profile, new Date(59_000), 0)).toEqual({ valid: true, delta: 0 });
    expect(verifyTotp("94287082", profile, new Date(120_000), 0)).toEqual({ valid: false });
  });

  it("receives email and SMS messages through the loopback test inbox", async () => {
    const inbox = new LocalTestInboxHarness(); closeables.push(inbox);
    const { endpoint } = await inbox.start();
    const waiting = inbox.waitForMessage({ channel: "EMAIL", recipient: "fixture@example.test" }, { timeoutMs: 2_000 });
    const response = await fetch(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ channel: "EMAIL", recipient: "fixture@example.test", subject: "Verify", text: "Code 481516" }) });
    expect(response.status).toBe(202);
    await expect(waiting).resolves.toMatchObject({ channel: "EMAIL", subject: "Verify", text: "Code 481516" });
  });

  it("normalizes Mailpit and MailHog messages through one adapter contract", async () => {
    const mailpit = new MailpitTestInboxAdapter("http://127.0.0.1:8025", async (url) => url.includes("/search") ? { messages: [{ ID: "m1", To: [{ Address: "member@example.test" }], Created: "2026-01-01T00:00:00.000Z" }] } : { ID: "m1", To: [{ Address: "member@example.test" }], Subject: "Verify", Text: "Code 123456", Created: "2026-01-01T00:00:00.000Z" });
    await expect(mailpit.waitForMessage({ channel: "EMAIL", recipient: "member@example.test" }, { timeoutMs: 100 })).resolves.toMatchObject({ id: "m1", subject: "Verify", text: "Code 123456" });
    const mailhog = new MailHogTestInboxAdapter("http://127.0.0.1:8025", async () => ({ items: [{ ID: "m2", Created: "2026-01-01T00:00:00.000Z", Content: { Headers: { To: ["member@example.test"], Subject: ["Welcome"] }, Body: "Open the link" } }] }));
    await expect(mailhog.waitForMessage({ channel: "EMAIL", recipient: "member@example.test" }, { timeoutMs: 100 })).resolves.toMatchObject({ id: "m2", subject: "Welcome", text: "Open the link" });
  });

  it("runs a one-use OIDC authorization-code and PKCE flow", async () => {
    const harness = new OidcTestHarness({ clientId: "fixture-client", clientSecret: "fixture-secret", redirectUris: ["http://127.0.0.1/callback"], subject: "fixture-subject" }); closeables.push(harness);
    const endpoints = await harness.start();
    const verifier = "v".repeat(64);
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorize = new URL(endpoints.authorizationEndpoint);
    authorize.search = new URLSearchParams({ response_type: "code", client_id: "fixture-client", redirect_uri: "http://127.0.0.1/callback", state: "opaque-state", nonce: "opaque-nonce", code_challenge: challenge, code_challenge_method: "S256" }).toString();
    const authorization = await fetch(authorize, { redirect: "manual" });
    expect(authorization.status).toBe(302);
    const callback = new URL(authorization.headers.get("location")!);
    expect(callback.searchParams.get("state")).toBe("opaque-state");
    const form = new URLSearchParams({ grant_type: "authorization_code", client_id: "fixture-client", client_secret: "fixture-secret", redirect_uri: "http://127.0.0.1/callback", code: callback.searchParams.get("code")!, code_verifier: verifier });
    const token = await fetch(endpoints.tokenEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form });
    expect(token.status).toBe(200);
    const body = await token.json() as { access_token: string; id_token: string };
    expect(body.access_token).toBeTruthy(); expect(body.id_token.split(".")).toHaveLength(3);
    expect((await fetch(endpoints.tokenEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form })).status).toBe(400);
  });

  it("completes and validates discovery, callback state, PKCE, JWKS, ID token, and replay", async () => {
    const harness = new OidcTestHarness({ clientId: "fixture-client", clientSecret: "fixture-secret", redirectUris: ["http://127.0.0.1/callback"], subject: "fixture-subject" }); closeables.push(harness);
    await expect(harness.completeAuthorizationCodeFlow({ state: "state-0123456789abcdef", nonce: "nonce-0123456789abcdef", codeVerifier: "verifier-0123456789abcdefghijklmnopqrstuvwxyzABCDEFG" })).resolves.toMatchObject({ subject: "fixture-subject", discoveryValidated: true, callbackValidated: true, pkceValidated: true, idTokenValidated: true, replayRejected: true });
  });

  it("runs the complete OIDC callback lifecycle as a case-local fixture action", async () => {
    const runtime = new AuthenticationFixtureRuntime({
      inboxes: [], totp: [], webauthn: [], providers: [],
      oidc: [{ id: "local-idp", clientIdSecretRef: "client_id", clientSecretRef: "client_secret", redirectUris: ["http://127.0.0.1/callback"], subjectSecretRef: "subject", port: 0, accessTokenLifetimeSeconds: 300 }]
    });
    closeables.push(runtime);
    const captures = new Map<string, string>();
    const names = await runtime.execute({ kind: "OIDC_AUTHORIZATION_CODE", harnessId: "local-idp", stateSecretRef: "state", nonceSecretRef: "nonce", pkceVerifierSecretRef: "verifier", captureAccessToken: "access", captureIdToken: "identity", captureSubject: "subject", timeoutMs: 5_000 }, captures, {
      client_id: "fixture-client", client_secret: "fixture-secret", subject: "fixture-subject",
      state: "state-0123456789abcdef", nonce: "nonce-0123456789abcdef", verifier: "v".repeat(64)
    });
    expect(names).toEqual(["access", "identity", "subject"]);
    expect(captures.get("access")).toBeTruthy();
    expect(captures.get("identity")?.split(".")).toHaveLength(3);
    expect(captures.get("subject")).toBe("fixture-subject");
  });

  it("creates, inspects, clears, and removes a Chromium virtual authenticator", async () => {
    const manager = new VirtualWebAuthnManager(); closeables.push(manager);
    await manager.create("platform", { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true });
    await expect(manager.credentials("platform")).resolves.toEqual([]);
    await manager.clear("platform");
    await manager.remove("platform");
    await expect(manager.credentials("platform")).rejects.toThrow("WEBAUTHN_AUTHENTICATOR_MISSING");
  }, 30_000);

  it("resolves turnkey provider operations without embedding credentials", () => {
    const supabase = resolveTurnkeyAuthRequest({ id: "supabase", provider: "SUPABASE_AUTH", baseUrl: "https://project.supabase.co", apiKeySecretRef: "anon_key", serviceKeySecretRef: "service_key" }, "SIGN_UP", { email: "{{SECRET:email}}", password: "{{SECRET:password}}" });
    expect(supabase).toMatchObject({ method: "POST", url: "https://project.supabase.co/auth/v1/signup", stateChanging: true, headers: { apikey: "{{SECRET:anon_key}}", Authorization: "Bearer {{SECRET:anon_key}}" } });
    expect(resolveTurnkeyAuthRequest({ id: "supabase", provider: "SUPABASE_AUTH", baseUrl: "https://project.supabase.co", apiKeySecretRef: "anon_key", serviceKeySecretRef: "service_key" }, "SIGN_OUT", {}).headers.Authorization).toBe("Bearer {{CAPTURE:access_token}}");
    expect(resolveTurnkeyAuthRequest({ id: "supabase", provider: "SUPABASE_AUTH", baseUrl: "https://project.supabase.co", apiKeySecretRef: "anon_key", serviceKeySecretRef: "service_key" }, "DELETE_USER", { userId: "{{CAPTURE:user_id}}" }).headers.Authorization).toBe("Bearer {{SECRET:service_key}}");
    const firebase = resolveTurnkeyAuthRequest({ id: "firebase", provider: "FIREBASE", baseUrl: "https://identitytoolkit.googleapis.com", apiKeySecretRef: "firebase_key" }, "SIGN_IN_PASSWORD", {});
    expect(firebase.url).toBe("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={{SECRET:firebase_key}}");
    expect(resolveTurnkeyAuthRequest({ id: "firebase", provider: "FIREBASE", baseUrl: "https://identitytoolkit.googleapis.com", apiKeySecretRef: "firebase_key" }, "REFRESH_TOKEN", {}).url).toBe("https://securetoken.googleapis.com/v1/token?key={{SECRET:firebase_key}}");
    expect(resolveTurnkeyAuthRequest({ id: "auth0", provider: "AUTH0", baseUrl: "https://tenant.auth0.com" }, "OAUTH_AUTHORIZE", { client_id: "{{SECRET:client_id}}", state: "{{SECRET:state}}" }).url).toContain("/authorize?client_id={{SECRET:client_id}}&state={{SECRET:state}}");
    expect(resolveTurnkeyAuthRequest({ id: "clerk", provider: "CLERK", baseUrl: "https://api.clerk.com", serviceKeySecretRef: "clerk_secret" }, "INVITE", {}).headers.Authorization).toBe("Bearer {{SECRET:clerk_secret}}");
    expect(resolveTurnkeyAuthRequest({ id: "cognito", provider: "COGNITO", baseUrl: "https://fixture.auth.us-east-1.amazoncognito.com" }, "OAUTH_TOKEN", {}).url).toBe("https://fixture.auth.us-east-1.amazoncognito.com/oauth2/token");
    expect(resolveTurnkeyAuthRequest({ id: "cognito-api", provider: "COGNITO", cognitoMode: "USER_POOLS_API", baseUrl: "https://cognito-idp.us-east-1.amazonaws.com" }, "SIGN_UP", { ClientId: "{{SECRET:client_id}}" })).toMatchObject({ method: "POST", url: "https://cognito-idp.us-east-1.amazonaws.com", headers: { "X-Amz-Target": "AWSCognitoIdentityProviderService.SignUp" } });
    expect(() => resolveTurnkeyAuthRequest({ id: "cognito", provider: "COGNITO", baseUrl: "https://fixture.auth.us-east-1.amazoncognito.com" }, "SIGN_UP", {})).toThrow(/COGNITO_USER_POOLS_API/);
  });
});
