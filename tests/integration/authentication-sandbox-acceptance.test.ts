import { createServer } from "node:net";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { OidcTestHarness } from "../../src/modules/authenticationLifecycle/AuthenticationFixtures.js";
import { AuthenticationProviderEmulator } from "../../src/validation/AuthenticationFixtureAcceptance.js";
import { authenticationSandboxAcceptanceSchema, runAuthenticationSandboxAcceptance } from "../../src/validation/AuthenticationSandboxAcceptance.js";

describe("authentication sandbox acceptance", () => {
  it("runs all provider lifecycles, an external OIDC callback, and browser passkey enrollment/login/cleanup", async () => {
    const emulator = new AuthenticationProviderEmulator();
    const { origin } = await emulator.start();
    const callbackPort = await availablePort();
    const callbackUrl = `http://127.0.0.1:${callbackPort}/callback`;
    const oidc = new OidcTestHarness({ clientId: "sandbox-client", clientSecret: "sandbox-client-secret", redirectUris: [callbackUrl], subject: "sandbox-subject" });
    const { issuer } = await oidc.start();
    const environment = {
      AUTH0_MANAGEMENT: "auth0-management-secret", CLERK_SERVICE: "clerk-service-secret", FIREBASE_KEY: "firebase-emulator-key",
      SUPABASE_ANON: "supabase-anon-key", SUPABASE_SERVICE: "supabase-service-key", OIDC_CLIENT: "sandbox-client",
      OIDC_SECRET: "sandbox-client-secret", OIDC_SUBJECT: "sandbox-subject"
    };
    const common = { email: "sandbox-{{RUN_ID}}@example.test", password: "Sandbox-password-42!" };
    const manifest = authenticationSandboxAcceptanceSchema.parse({
      schemaVersion: 1,
      name: "loopback sandbox acceptance",
      providers: [
        {
          id: "auth0", environment: "EMULATOR", authorizationConfirmed: true, disposableAccount: true,
          adapter: { id: "auth0", provider: "AUTH0", baseUrl: `${origin}/auth0`, managementTokenSecretRef: "management" },
          secretEnvironment: { management: "AUTH0_MANAGEMENT" },
          operations: [
            { id: "signup", phase: "SETUP", operation: "SIGN_UP", fields: { ...common, connection: "Username-Password-Authentication" } },
            { id: "signin", phase: "ACTION", operation: "SIGN_IN_PASSWORD", fields: { grant_type: "password", username: common.email, password: common.password } },
            { id: "refresh", phase: "VERIFY", operation: "REFRESH_TOKEN", fields: { grant_type: "refresh_token", refresh_token: "{{CAPTURE:refresh_token}}" } },
            { id: "logout", phase: "VERIFY", operation: "SIGN_OUT" },
            { id: "delete", phase: "CLEANUP", operation: "DELETE_USER", fields: { userId: "{{CAPTURE:user_id}}" } }
          ]
        },
        {
          id: "cognito", environment: "EMULATOR", authorizationConfirmed: true, disposableAccount: true,
          adapter: { id: "cognito", provider: "COGNITO", baseUrl: `${origin}/cognito`, cognitoMode: "USER_POOLS_API" },
          operations: [
            { id: "signup", phase: "SETUP", operation: "SIGN_UP", fields: { Username: common.email, Password: common.password } },
            { id: "signin", phase: "ACTION", operation: "SIGN_IN_PASSWORD", fields: { AuthFlow: "USER_PASSWORD_AUTH", AuthParameters: { USERNAME: common.email, PASSWORD: common.password } } },
            { id: "refresh", phase: "VERIFY", operation: "REFRESH_TOKEN", fields: { AuthFlow: "REFRESH_TOKEN_AUTH", AuthParameters: { REFRESH_TOKEN: "{{CAPTURE:refresh_token}}" } } },
            { id: "logout", phase: "VERIFY", operation: "SIGN_OUT", fields: { AccessToken: "{{CAPTURE:access_token}}" } },
            { id: "delete", phase: "CLEANUP", operation: "DELETE_USER", fields: { AccessToken: "{{CAPTURE:access_token}}" } }
          ]
        },
        {
          id: "clerk", environment: "EMULATOR", authorizationConfirmed: true, disposableAccount: true,
          adapter: { id: "clerk", provider: "CLERK", baseUrl: `${origin}/clerk`, serviceKeySecretRef: "service" },
          secretEnvironment: { service: "CLERK_SERVICE" },
          operations: [
            { id: "signup", phase: "SETUP", operation: "SIGN_UP", fields: { email_address: [common.email], password: common.password } },
            { id: "signin", phase: "ACTION", operation: "SIGN_IN_PASSWORD", fields: { user_id: "{{CAPTURE:user_id}}" } },
            { id: "logout", phase: "VERIFY", operation: "SIGN_OUT", fields: { sessionId: "{{CAPTURE:session_id}}" } },
            { id: "delete", phase: "CLEANUP", operation: "DELETE_USER", fields: { userId: "{{CAPTURE:user_id}}" } }
          ]
        },
        {
          id: "firebase", environment: "EMULATOR", authorizationConfirmed: true, disposableAccount: true,
          adapter: { id: "firebase", provider: "FIREBASE", baseUrl: `${origin}/firebase`, tokenBaseUrl: `${origin}/firebase-token`, apiKeySecretRef: "api_key" },
          secretEnvironment: { api_key: "FIREBASE_KEY" },
          operations: [
            { id: "signup", phase: "SETUP", operation: "SIGN_UP", fields: { ...common, returnSecureToken: true } },
            { id: "signin", phase: "ACTION", operation: "SIGN_IN_PASSWORD", fields: { ...common, returnSecureToken: true } },
            { id: "refresh", phase: "VERIFY", operation: "REFRESH_TOKEN", fields: { grant_type: "refresh_token", refresh_token: "{{CAPTURE:refresh_token}}" } },
            { id: "delete", phase: "CLEANUP", operation: "DELETE_USER", fields: { idToken: "{{CAPTURE:id_token}}" } }
          ]
        },
        {
          id: "supabase", environment: "EMULATOR", authorizationConfirmed: true, disposableAccount: true,
          adapter: { id: "supabase", provider: "SUPABASE_AUTH", baseUrl: `${origin}/supabase`, apiKeySecretRef: "anon", serviceKeySecretRef: "service" },
          secretEnvironment: { anon: "SUPABASE_ANON", service: "SUPABASE_SERVICE" },
          operations: [
            { id: "signup", phase: "SETUP", operation: "SIGN_UP", fields: common },
            { id: "signin", phase: "ACTION", operation: "SIGN_IN_PASSWORD", fields: common },
            { id: "refresh", phase: "VERIFY", operation: "REFRESH_TOKEN", fields: { refresh_token: "{{CAPTURE:refresh_token}}" } },
            { id: "logout", phase: "VERIFY", operation: "SIGN_OUT" },
            { id: "delete", phase: "CLEANUP", operation: "DELETE_USER", fields: { userId: "{{CAPTURE:user_id}}" } }
          ]
        }
      ],
      oidc: [{
        id: "oidc", environment: "EMULATOR", authorizationConfirmed: true, issuer,
        clientIdEnvironment: "OIDC_CLIENT", clientSecretEnvironment: "OIDC_SECRET", expectedSubjectEnvironment: "OIDC_SUBJECT",
        callbackPort, tokenAuthMethod: "CLIENT_SECRET_POST", browserAllowedOrigins: [callbackUrl], browserSteps: []
      }],
      passkeys: [{
        id: "passkey", environment: "EMULATOR", authorizationConfirmed: true, disposableAccount: true, expectedRpId: "localhost",
        enrollment: { startUrl: `${origin}/passkey/enroll`, steps: [{ action: "click", selector: "#enroll" }, { action: "assertVisible", selector: "#enrolled" }] },
        login: { startUrl: `${origin}/passkey/login`, clearCookies: true, steps: [{ action: "click", selector: "#login" }, { action: "waitForUrl", urlPrefix: `${origin}/passkey/account` }, { action: "assertVisible", selector: "#authenticated" }] },
        cleanup: { startUrl: `${origin}/passkey/manage`, steps: [{ action: "click", selector: "#remove" }, { action: "assertVisible", selector: "#removed" }] }
      }]
    });
    const directory = await mkdtemp(join(tmpdir(), "routecairn-auth-sandbox-"));
    try {
      const summary = await runAuthenticationSandboxAcceptance(manifest, directory, environment);
      expect(summary.status).toBe("PASSED");
      expect(summary.providers).toHaveLength(5);
      expect(summary.providers.every((item) => item.status === "PASSED" && item.cleanup === "PASSED")).toBe(true);
      expect(summary.oidc[0]).toMatchObject({ status: "PASSED", discovery: true, browserCallback: true, state: true, pkce: true, idToken: true, callbackReplayRejected: true, codeReplayRejected: true });
      expect(summary.passkeys[0]).toMatchObject({ status: "PASSED", enrollment: true, rpBound: true, login: true, counterAdvanced: true, applicationCleanup: true, authenticatorCleanup: true });
      const artifact = await readFile(join(summary.outputDirectory, "authentication-sandbox-acceptance.json"), "utf8");
      for (const secret of Object.values(environment)) expect(artifact).not.toContain(secret);
    } finally {
      await oidc.close();
      await emulator.close();
    }
  }, 90_000);

  it("rejects production, missing cleanup, and authorization-parameter overrides", () => {
    expect(() => authenticationSandboxAcceptanceSchema.parse({ name: "bad", providers: [{ id: "bad", environment: "PRODUCTION", authorizationConfirmed: true, disposableAccount: true, adapter: { id: "x", provider: "AUTH0", baseUrl: "https://example.test" }, operations: [{ id: "signup", phase: "SETUP", operation: "SIGN_UP" }] }] })).toThrow();
    expect(() => authenticationSandboxAcceptanceSchema.parse({ name: "bad", providers: [{ id: "bad", environment: "SANDBOX", authorizationConfirmed: true, disposableAccount: true, adapter: { id: "x", provider: "AUTH0", baseUrl: "https://example.test" }, operations: [{ id: "signup", phase: "SETUP", operation: "SIGN_UP" }] }] })).toThrow(/DELETE_USER/);
    expect(() => authenticationSandboxAcceptanceSchema.parse({ name: "bad", oidc: [{ id: "bad", environment: "SANDBOX", authorizationConfirmed: true, issuer: "https://example.test", clientIdEnvironment: "CLIENT_ID", extraAuthorizeParameters: { state: "unsafe" } }] })).toThrow(/cannot be overridden/i);
  });
});

async function availablePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); }); });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("PORT_RESERVATION_FAILED");
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}
