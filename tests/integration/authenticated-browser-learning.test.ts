import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { BrowserCrawlerModule } from "../../src/modules/browserCrawler/BrowserCrawlerModule.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { testPlan } from "../helpers/plan.js";
import type { AuthProfile } from "../../src/core/auth/AuthProfile.js";

let server: Server | undefined;
let thirdPartyServer: Server | undefined;
const directories: string[] = [];

afterEach(async () => {
  server?.closeAllConnections();
  thirdPartyServer?.closeAllConnections();
  await new Promise<void>((resolve) => server?.close(() => resolve()) ?? resolve());
  await new Promise<void>((resolve) => thirdPartyServer?.close(() => resolve()) ?? resolve());
  server = undefined;
  thirdPartyServer = undefined;
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("authenticated browser bootstrap and traffic learning", () => {
  it("logs in inside an isolated session, records redacted traffic, and never authorizes learned mutations", async () => {
    const received: Array<{ method: string; url: string }> = [];
    let thirdPartyAuthorization: string | undefined;
    thirdPartyServer = createServer((request, response) => {
      thirdPartyAuthorization = request.headers.authorization;
      response.writeHead(200, { "content-type": "application/json", "access-control-allow-origin": "*" });
      response.end('{"asset":true}');
    });
    await new Promise<void>((resolve) => thirdPartyServer!.listen(0, "127.0.0.1", () => resolve()));
    const thirdPartyPort = (thirdPartyServer.address() as AddressInfo).port;
    const thirdPartyOrigin = `http://127.0.0.1:${thirdPartyPort}`;
    server = createServer((request, response) => {
      received.push({ method: request.method ?? "", url: request.url ?? "" });
      if (request.url === "/session" && request.method === "POST") {
        response.writeHead(302, { location: "/app", "set-cookie": "routecairn_session=server-secret-session; HttpOnly; SameSite=Lax" });
        response.end();
        return;
      }
      if (request.url === "/login") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end(`<form action="/session" method="post"><input name="username"><input name="password" type="password"><button type="submit">Sign in</button></form>`);
        return;
      }
      if (request.url === "/api/me") {
        response.writeHead(200, { "content-type": "application/json", "content-length": "32" });
        response.end('{"id":"user-a","role":"member"}');
        return;
      }
      if (request.url === "/app" || request.url === "/admin") {
        if (!request.headers.cookie?.includes("routecairn_session=")) {
          response.writeHead(401); response.end("anonymous"); return;
        }
        response.writeHead(200, { "content-type": "text/html" });
        response.end(`<!doctype html><body>
          <span id="principal">user-a</span>
          <input name="displayName"><input name="immutableId" readonly><input name="systemRole" disabled>
          <a id="admin-link" href="/admin">Administration</a>
          <script>
            localStorage.setItem('auth-token', 'storage-secret-value');
            fetch('/api/me');
            fetch('${thirdPartyOrigin}/asset');
            fetch('/api/unsafe', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({ role: 'admin', privateValue: 'never-store' }) }).catch(() => {});
          </script>
        </body>`);
        return;
      }
      response.writeHead(404); response.end("not found");
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", () => resolve()));
    const port = (server.address() as AddressInfo).port;
    const origin = `http://127.0.0.1:${port}`;
    const outputDir = await mkdtemp(join(tmpdir(), "routecairn-auth-browser-"));
    directories.push(outputDir);
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"] as const, disallowedPaths: [], sameOriginOnly: false, userAgent: "RouteCairn/Auth-Browser-Test" };
    const fullPlan = testPlan("full", { scope });
    const basePlan = { ...fullPlan, authentication: { ...fullPlan.authentication, required: true, level: "single-profile" as const, requireSingleProfile: true, hasSingleProfile: true } };
    const browserPlan = {
      ...basePlan,
      modules: basePlan.modules.map((modulePlan) => modulePlan.id === "browser-crawler" ? { ...modulePlan, settings: { ...modulePlan.settings, browserAllowPrivateNetwork: true, browserAllowedPrivateOrigins: [origin, thirdPartyOrigin], browserAllowedThirdPartyOrigins: [thirdPartyOrigin], browserCaptureScreenshot: false } } : modulePlan)
    };
    const authProfile: AuthProfile = {
      label: "Account A",
      safeAlias: "Account A",
      principalId: "user-a",
      headers: { Authorization: "Bearer browser-header-secret" },
      cookies: [],
      identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] },
      browserBootstrap: {
        schemaVersion: 1,
        loginSecrets: { username: "alice@example.test", password: "super-secret-password" },
        login: {
          startUrl: `${origin}/login`,
          allowedWritePaths: ["/session"],
          successUrlPrefix: `${origin}/app`,
          steps: [
            { action: "fill", selector: "input[name=username]", valueRef: "username" },
            { action: "fill", selector: "input[name=password]", valueRef: "password" },
            { action: "click", selector: "button[type=submit]" },
            { action: "waitForUrl", urlPrefix: `${origin}/app` }
          ]
        },
        journeys: [{ id: "admin-navigation", label: "Open admin navigation", steps: [{ action: "clickLink", selector: "#admin-link" }] }],
        identitySelectors: { principal: "#principal" }
      },
      notes: []
    };
    const context = new ScanContext({ target: `${origin}/app`, scope, config: defaultConfig, plan: browserPlan, outputDir, authProfile });

    const result = await new BrowserCrawlerModule().run(context);
    const report = result.browserCrawl!;
    expect(report.authentication).toMatchObject({ mode: "learned-login-flow", bootstrapSucceeded: true, sessionIsolated: true, sessionSecretsPersisted: false, loginStepsExecuted: 4, loginWriteRequestsAllowed: 1, identityCorrelation: { principal: "MATCHED", rawIdentityStored: false } });
    expect(report.formsSubmitted).toBe(1);
    expect(report.authentication?.adminRoutes).toContain(`${origin}/admin`);
    expect(report.authentication?.fields).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "displayName", access: "writable" }),
      expect.objectContaining({ name: "immutableId", access: "read-only" }),
      expect.objectContaining({ name: "systemRole", access: "disabled" })
    ]));
    expect(report.authentication?.storage).toEqual(expect.arrayContaining([expect.objectContaining({ name: "auth-token", classification: "authentication", valueLength: 20, secretBoundary: expect.objectContaining({ materialClass: "USER_SESSION_SECRET", outcome: "CLIENT_STORAGE_RISK", findingEligible: true }) })]));
    expect(JSON.stringify(report)).not.toContain("super-secret-password");
    expect(JSON.stringify(report)).not.toContain("storage-secret-value");
    expect(JSON.stringify(report)).not.toContain("server-secret-session");
    expect(report.authentication?.learnedTestCases.find((item) => item.method === "POST")).toMatchObject({ classification: "MUTATION_HYPOTHESIS", state: "DRAFT_REQUIRES_OPERATOR_CASE", executable: false, operatorApprovalRequired: true });
    expect(report.authentication?.lifecycleLearningBundle).toMatchObject({ schemaVersion: 1, loginCandidateCount: 1, mutationHypothesisCount: 2, secretsStored: false });
    expect(received.some((item) => item.url === "/api/unsafe")).toBe(false);
    expect(thirdPartyAuthorization).toBeUndefined();
    expect(report.policyEvents).toEqual(expect.arrayContaining([expect.objectContaining({ reason: "browser-write-requires-explicit-operator-case", transmitted: false })]));

    const har = await readFile(report.authentication!.redactedHarPath!, "utf8");
    expect(har).toContain('"secretsStored": false');
    expect(har).not.toContain("super-secret-password");
    expect(har).not.toContain("storage-secret-value");
    expect(har).not.toContain("server-secret-session");
    expect(har).not.toContain("never-store");
    expect(har).not.toContain("browser-header-secret");
    const learningBundle = await readFile(report.authentication!.lifecycleLearningBundle.artifactPath, "utf8");
    expect(learningBundle).toContain('"BLOCKED_MUTATION_HYPOTHESIS"');
    expect(learningBundle).not.toContain("super-secret-password");
    expect(learningBundle).not.toContain("never-store");
  }, 30_000);
});
