import { describe, expect, it } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import type { AuthProfile } from "../../src/core/auth/AuthProfile.js";
import type { BrowserAuthenticationReport, BrowserLearnedTestCase } from "../../src/reports/ReportTypes.js";
import { browserLearnedLifecycleAutomationInputSchema, compileBrowserLearnedLifecycle, planBrowserLearnedLifecycleAutomation } from "../../src/modules/authenticationLifecycle/BrowserLearnedLifecycleCompiler.js";

const origin = "https://app.example.test";
const candidate: BrowserLearnedTestCase = {
  id: "browser-1234567890abcdef",
  source: "browser-learned-traffic",
  method: "POST",
  endpoint: `${origin}/api/session`,
  observedFieldNames: ["credentials.email", "credentials.password"],
  requestBodyFormat: "JSON",
  requestSecretBindings: { "credentials.email": "username", "credentials.password": "password" },
  observedStatusCodes: [302],
  responseCookieNames: ["session"],
  authorizationContext: "EXPLICIT_LOGIN",
  transmitted: true,
  suggestedLifecycleCategories: ["LOGIN_ENUMERATION_RESISTANCE", "SESSION_ROTATION_AFTER_LOGIN", "SESSION_FIXATION"],
  classification: "MUTATION_HYPOTHESIS",
  state: "DRAFT_REQUIRES_OPERATOR_CASE",
  executable: false,
  operatorApprovalRequired: true
};
const browser = { learnedTestCases: [candidate] } as BrowserAuthenticationReport;
const authProfile = {
  label: "member", headers: { Authorization: "Bearer existing-session" }, cookies: [],
  identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] },
  browserBootstrap: { schemaVersion: 1, loginSecrets: { username: "member@example.test", password: "valid-password" }, journeys: [], proofCases: [] },
  lifecycleSecrets: { unknown_username: "absent@example.test", invalid_password: "invalid-password", fixed_session: "fixed-session" }, notes: []
} as AuthProfile;
const input = browserLearnedLifecycleAutomationInputSchema.parse({
  authorization: { mode: "CONTROLLED_LIFECYCLE", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING", authorizedBy: "operator-ref", changeTicket: "AUTH-100", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableAccounts: true },
  login: { unknownAccountSecretRef: "unknown_username", invalidPasswordSecretRef: "invalid_password", fixedSessionSecretRef: "fixed_session" },
  cleanup: { method: "POST", url: `${origin}/api/logout` }
});

describe("browser-learned lifecycle compiler", () => {
  it("promotes a learned login into approved executable lifecycle cases without persisting values", () => {
    const configured = planBrowserLearnedLifecycleAutomation(input, origin);
    const scope = { ...exampleScope, allowedDomains: ["app.example.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"] as const };
    const compiled = compileBrowserLearnedLifecycle(configured, browser, { target: origin, scope, authProfile });
    expect(compiled.generatedCategories).toEqual(["LOGIN_ENUMERATION_RESISTANCE", "SESSION_ROTATION_AFTER_LOGIN", "SESSION_FIXATION"]);
    expect(compiled.blockers).toEqual([]);
    expect(compiled.plan?.cases).toHaveLength(3);
    expect(compiled.plan?.cases.every((testCase) => testCase.actors[0]?.requestAuthentication === "NONE")).toBe(true);
    const fields = compiled.plan?.cases[0]?.steps[0]?.request.fields;
    expect(fields).toEqual({ credentials: { email: "{{SECRET:username}}", password: "{{SECRET:invalid_password}}" } });
    expect(JSON.stringify(compiled)).not.toContain("member@example.test");
    expect(JSON.stringify(compiled)).not.toContain("existing-session");
  });

  it("returns explicit readiness blockers when the learned signal is insufficient", () => {
    const configured = planBrowserLearnedLifecycleAutomation(input, origin);
    const compiled = compileBrowserLearnedLifecycle(configured, { ...browser, learnedTestCases: [] }, { target: origin, scope: { ...exampleScope, allowedDomains: ["app.example.test"], disallowedPaths: [] }, authProfile });
    expect(compiled.plan).toBeUndefined();
    expect(compiled.blockers).toHaveLength(3);
    expect(compiled.blockers[0]?.reasons).toContain("NO_UNAMBIGUOUS_EXPLICIT_LOGIN_CANDIDATE");
  });

  it("fails closed on unsafe learned field paths and unavailable secret references", () => {
    const configured = planBrowserLearnedLifecycleAutomation(input, origin);
    const unsafe = { ...candidate, observedFieldNames: ["__proto__.polluted", "password"], requestSecretBindings: { password: "password" } };
    const compiled = compileBrowserLearnedLifecycle(configured, { ...browser, learnedTestCases: [unsafe] }, { target: origin, scope: { ...exampleScope, allowedDomains: ["app.example.test"], disallowedPaths: [] }, authProfile });
    expect(compiled.plan).toBeUndefined();
    expect(compiled.blockers.flatMap((item) => item.reasons)).toContain("UNSUPPORTED_FIELD_PATH:__proto__.polluted");

    const missingProfile = { ...authProfile, lifecycleSecrets: {} };
    const missing = compileBrowserLearnedLifecycle(configured, browser, { target: origin, scope: { ...exampleScope, allowedDomains: ["app.example.test"], disallowedPaths: [] }, authProfile: missingProfile });
    expect(missing.blockers.flatMap((item) => item.reasons)).toEqual(expect.arrayContaining(["SECRET_REF_UNAVAILABLE:unknown_username", "SECRET_REF_UNAVAILABLE:fixed_session"]));
  });
});
