import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { RequestSafetyBroker } from "../../src/core/http/RequestSafetyBroker.js";
import { ScopeMatcher } from "../../src/core/scope/ScopeMatcher.js";
import { exampleScope } from "../../src/config/defaults.js";
import { activeVulnerabilityInputSchema, planActiveVulnerabilityValidation } from "../../src/modules/activeVulnerability/ActiveVulnerabilityPlanner.js";
import { compileActiveStrategies } from "../../src/modules/activeVulnerability/ActiveVulnerabilityStrategies.js";
import { executeActiveOAuthJourney } from "../../src/modules/activeVulnerability/ActiveOAuthJourney.js";
import type { ActiveProbeRequestObservation } from "../../src/reports/ActiveVulnerabilityReport.js";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { defaultConfig } from "../../src/config/defaults.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { ActiveVulnerabilityModule } from "../../src/modules/activeVulnerability/ActiveVulnerabilityModule.js";

type Lab = { issuer: string; applicationOrigin: string; activeSessions: () => number; cleanup: (canary: string) => Promise<void>; close: () => Promise<void> };
let lab: Lab; const retained: unknown[] = [];
beforeAll(async () => { const modulePath = new URL("../helpers/active-oidc-lab.mjs", import.meta.url).href; lab = await (await import(modulePath)).createActiveOidcLab(); }, 15000);
afterAll(async () => {
  await lab?.close();
  if (process.env.ROUTECAIRN_ACTIVE_LAB_OUTPUT) {
    const directory = resolve(process.env.ROUTECAIRN_ACTIVE_LAB_OUTPUT); await mkdir(directory, { recursive: true });
    const bytes = Buffer.from(`${JSON.stringify({ schemaVersion: 1, implementation: "oidc-provider@9.12.2", generatedAt: new Date().toISOString(), provenance: "SELF_MAINTAINED_LOOPBACK_APPLICATION_REAL_OIDC_SERVER", externalTargetsTested: false, independentlyOperated: false, cleanup: "CONFIRMED", cases: retained }, null, 2)}\n`);
    await writeFile(resolve(directory, "oauth-journeys.json"), bytes); await writeFile(resolve(directory, "oauth-SHA256SUMS"), `${createHash("sha256").update(bytes).digest("hex")}  oauth-journeys.json\n`);
  }
});
describe("native OAuth authorization-server journeys", () => {
  for (const technique of ["OAUTH_STATE", "OAUTH_ISSUER", "OAUTH_MIX_UP", "OAUTH_ACCOUNT_LINK"] as const) for (const mode of ["secure", "vulnerable"] as const) {
    it(`${mode} ${technique} acquires fresh real codes, exchanges them and observes the application identity`, async () => {
      const origin = lab.applicationOrigin; const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], sameOriginOnly: false, allowedMethods: ["GET", "POST", "DELETE"] as typeof exampleScope.allowedMethods };
      const input = activeVulnerabilityInputSchema.parse({ maxRequests: 28, maxCases: 1, discovery: { enabled: false, maxCandidates: 0 }, cases: [{ id: "oauth", label: "Native OAuth", vulnerabilityClass: "OAUTH_VALIDATION", actorId: "anonymous", environment: "LOCAL_FIXTURE", request: { url: `${origin}/${mode}/${technique}/start`, method: "GET", injection: { location: "QUERY", name: "state", originalValue: "fixture" } }, proof: { oauthExpectedIssuer: lab.issuer, oauthExpectedClientId: "routecairn-lab", oauthExpectedAccount: "lab-account-a", marker: "RC-OAUTH-LAB", verificationUrl: `${origin}/${mode}/${technique}/identity`, cleanupUrl: `${origin}/${mode}/${technique}/cleanup`, cleanupMethod: "DELETE", oauthJourney: { discoveryUrl: `${lab.issuer}/.well-known/openid-configuration`, callbackUrl: `${origin}/${mode}/${technique}/callback`, identityJsonPath: "account", linkedAccountJsonPath: "linkedAccount", foreignSessionHeaders: { "X-RouteCairn-Lab-Account": "{{SECRET:foreign-as-session}}" }, foreignAccount: "lab-account-b", expiresAt: new Date(Date.now() + 3600000).toISOString(), confirmation: "I_AUTHORIZE_DISPOSABLE_OAUTH_JOURNEYS" } }, strategy: { techniques: [technique], approvedRisks: ["PASSIVE_DIFFERENTIAL", "STATEFUL_CANARY"] } }] });
      const plan = planActiveVulnerabilityValidation(input, { target: origin, scope }); const testCase = plan.cases[0]!; const nonce = randomBytes(12).toString("hex");
      const broker = new RequestSafetyBroker({ timeoutMs: 3000, concurrency: 1, rateLimitPerSecond: 100, retry: { maxAttempts: 1, baseDelayMs: 0, maxDelayMs: 0, retryStatusCodes: [] }, allowedPrivateOrigins: [lab.issuer], maxRequests: 28, maxResponseBytes: 65536, bodyPreviewBytes: 65536, userAgent: "RouteCairn-native-OAuth-lab", controlledMutationEnabled: true }, new ScopeMatcher(origin, scope), () => undefined);
      const observations: ActiveProbeRequestObservation[] = [];
      try {
        const strategy = compileActiveStrategies(testCase, nonce)[0]!;
        const result = await executeActiveOAuthJourney(testCase, strategy, (request) => broker.send(request), { "X-RouteCairn-Lab-Rp": "a" }, (headers) => Object.fromEntries(Object.keys(headers).map((name) => [name, "b"])), observations, undefined, nonce);
        retained.push({ technique, mode, outcome: result.outcome, reasonCode: result.reasonCode, requests: observations.length, observations });
        expect(result.outcome, result.reasonCode).toBe(mode === "secure" ? "SECURE_FOR_CASE" : "PROVEN"); expect(observations.length).toBeLessThanOrEqual(27);
        expect(JSON.stringify(observations)).not.toContain("code="); expect(result.signals).not.toContain("response-marker");
      } finally { await lab.cleanup(nonce); await broker.close(); }
      expect(lab.activeSessions()).toBe(0);
    }, 30000);
  }
  it("runs the native journey through the scan module, global ledger and cancellation-safe cleanup", async () => {
    const origin = lab.applicationOrigin; const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], sameOriginOnly: false, disallowedPaths: [], allowedMethods: ["GET", "POST", "DELETE"] as const, rateLimitPerSecond: 100, concurrency: 1 };
    const input = activeVulnerabilityInputSchema.parse({ maxRequests: 28, discovery: { enabled: false, maxCandidates: 0 }, cases: [{ id: "native", label: "Native engine", actorId: "anonymous", vulnerabilityClass: "OAUTH_VALIDATION", environment: "LOCAL_FIXTURE", request: { url: `${origin}/vulnerable/OAUTH_STATE/start`, method: "GET", injection: { location: "QUERY", name: "state" } }, proof: { oauthExpectedIssuer: lab.issuer, oauthExpectedClientId: "routecairn-lab", oauthExpectedAccount: "lab-account-a", verificationUrl: `${origin}/vulnerable/OAUTH_STATE/identity`, cleanupUrl: `${origin}/vulnerable/OAUTH_STATE/cleanup`, cleanupMethod: "DELETE", oauthJourney: { discoveryUrl: `${lab.issuer}/.well-known/openid-configuration`, callbackUrl: `${origin}/vulnerable/OAUTH_STATE/callback`, identityJsonPath: "account", expiresAt: new Date(Date.now() + 3600000).toISOString(), confirmation: "I_AUTHORIZE_DISPOSABLE_OAUTH_JOURNEYS" } }, strategy: { techniques: ["OAUTH_STATE"], approvedRisks: ["PASSIVE_DIFFERENTIAL", "STATEFUL_CANARY"] } }] });
    const active = planActiveVulnerabilityValidation(input, { target: origin, scope }); const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "quick", scope, config: defaultConfig, activeVulnerability: active }); const context = new ScanContext({ target: origin, scope, config: defaultConfig, plan, outputDir: ".routecairn-active-lab" });
    try { const result = await new ActiveVulnerabilityModule().run(context); expect(result.activeVulnerability!.cases[0]).toMatchObject({ outcome: "PROVEN", cleanup: "CONFIRMED" }); expect(lab.activeSessions()).toBe(0); expect(context.requestLedger.snapshot().totalTransmitted).toBe(result.activeVulnerability!.cases[0]!.requests.length); const evidence = JSON.stringify({ result, audit: context.state.getRequestAudit() }); expect(evidence).not.toContain("code="); expect(evidence).not.toContain("rca_oidc="); } finally { await context.dispose(); }
  }, 15000);
});
