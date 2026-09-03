import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";
import { defaultConfig } from "../../src/config/defaults.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { RouteCairnEngine } from "../../src/core/engine/RouteCairnEngine.js";
import { authenticationLifecycleInputSchema, planAuthenticationLifecycle } from "../../src/modules/authenticationLifecycle/AuthenticationLifecyclePlanner.js";
import { browserLearnedLifecycleAutomationInputSchema, planBrowserLearnedLifecycleAutomation } from "../../src/modules/authenticationLifecycle/BrowserLearnedLifecycleCompiler.js";
import type { AuthProfile } from "../../src/core/auth/AuthProfile.js";

let server: Server | undefined;
const directories: string[] = [];

afterEach(async () => {
  if (server) await new Promise<void>((resolve, reject) => server?.close((error) => error ? reject(error) : resolve()));
  server = undefined;
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("authentication lifecycle integration", () => {
  it("learns a browser login and automatically executes compiled lifecycle cases", async () => {
    server = createServer(async (request, response) => {
      if (request.url === "/login") return void response.writeHead(200, { "content-type": "text/html" }).end('<form action="/api/session" method="post"><input name="username"><input name="password" type="password"><button type="submit">Sign in</button></form>');
      if (request.url === "/app") return void response.writeHead(200, { "content-type": "text/html" }).end("<h1>Application</h1>");
      if (request.url === "/api/session" && request.method === "POST") {
        const body = new URLSearchParams(await requestBody(request));
        if (body.get("username") === "member@example.test" && body.get("password") === "valid-password") {
          response.writeHead(302, { location: "/app", "set-cookie": "session=rotated-session; HttpOnly; SameSite=Lax" }); response.end(); return;
        }
        response.writeHead(401, { "content-type": "application/json" }); response.end('{"error":"invalid credentials"}'); return;
      }
      if (request.url === "/api/logout" && request.method === "POST") return void response.writeHead(204).end();
      return void response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const target = `${origin}/app`;
    const directory = await mkdtemp(join(tmpdir(), "routecairn-learned-lifecycle-")); directories.push(directory);
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"] as const, rateLimitPerSecond: 50, concurrency: 2 };
    const authProfile: AuthProfile = {
      label: "member", safeAlias: "disposable-member", headers: {}, cookies: [], lifecycleSecrets: { unknown_username: "absent@example.test", invalid_password: "invalid-password-raw-8675309", fixed_session: "fixed-session-raw-8675309" }, notes: [],
      identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] },
      browserBootstrap: { schemaVersion: 1, loginSecrets: { username: "member@example.test", password: "valid-password" }, login: { startUrl: `${origin}/login`, allowedWritePaths: ["/api/session"], successUrlPrefix: `${origin}/app`, steps: [{ action: "fill", selector: "input[name=username]", valueRef: "username" }, { action: "fill", selector: "input[name=password]", valueRef: "password" }, { action: "click", selector: "button[type=submit]" }, { action: "waitForUrl", urlPrefix: `${origin}/app` }] }, journeys: [], proofCases: [] }
    };
    const automationInput = browserLearnedLifecycleAutomationInputSchema.parse({
      authorization: { mode: "CONTROLLED_LIFECYCLE", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING", authorizedBy: "operator", changeTicket: "AUTH-AUTO", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableAccounts: true },
      login: { unknownAccountSecretRef: "unknown_username", invalidPasswordSecretRef: "invalid_password", fixedSessionSecretRef: "fixed_session" },
      cleanup: { method: "POST", url: `${origin}/api/logout`, successStatusCodes: [204] }
    });
    const lifecycle = planBrowserLearnedLifecycleAutomation(automationInput, target);
    const resolved = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "quick", scope, config: defaultConfig, authProfile, authenticationLifecycle: lifecycle, overrides: { includeModules: ["baseline", "browser-crawler", "authentication-lifecycle"], moduleSettings: { "browser-crawler": { browserAllowPrivateNetwork: true, browserAllowedPrivateOrigins: [origin], browserCaptureScreenshot: false } } } });
    const result = await new RouteCairnEngine().scan({ target, scope, config: defaultConfig, plan: resolved, outputDir: join(directory, "reports"), authProfile });
    const reportText = await readFile(result.reportPath, "utf8");
    const report = JSON.parse(reportText) as { authenticationLifecycle: import("../../src/reports/AuthenticationLifecycleReport.js").AuthenticationLifecycleReport; browserCrawl: import("../../src/reports/ReportTypes.js").BrowserCrawlReport };
    expect(report.authenticationLifecycle.learningAutomation).toMatchObject({ source: "BROWSER_LEARNED", generatedCategories: ["LOGIN_ENUMERATION_RESISTANCE", "SESSION_ROTATION_AFTER_LOGIN", "SESSION_FIXATION"], blockers: [], secretsStored: false });
    expect(report.authenticationLifecycle).toMatchObject({ plannedCases: 3, executedCases: 3, passedCases: 3, blockedCases: 0, cleanupFailed: 0 });
    expect(report.browserCrawl.authentication?.lifecycleLearningBundle).toMatchObject({ schemaVersion: 1, loginCandidateCount: 1, secretsStored: false });
    for (const secret of ["member@example.test", "valid-password", "absent@example.test", "invalid-password-raw-8675309", "fixed-session-raw-8675309", "rotated-session"]) expect(reportText).not.toContain(secret);
    expect(await readFile(join(directory, "reports", "authentication-lifecycle.learning.json"), "utf8")).not.toContain("valid-password");
    expect(await readFile(join(directory, "reports", "authentication-lifecycle.automation.json"), "utf8")).not.toContain("operator");
  }, 45_000);

  it("executes rotation, enumeration, replay, and cleanup through the safety broker without secret persistence", async () => {
    const seenBodies: string[] = [];
    server = createServer(async (request, response) => {
      const path = request.url ?? "/";
      if (path === "/") return void response.writeHead(200, { "content-type": "text/html" }).end("ok");
      const body = await requestBody(request); seenBodies.push(body);
      response.setHeader("content-type", "application/json");
      if (path === "/login-enumeration") return void response.writeHead(401).end('{"error":"invalid credentials"}');
      if (path === "/login") { response.setHeader("set-cookie", "session=rotated-session-secret; HttpOnly; Secure; SameSite=Lax"); return void response.writeHead(200).end('{"authenticated":true}'); }
      if (path === "/refresh") {
        const parsed = JSON.parse(body) as { refresh_token?: string };
        if (parsed.refresh_token === "initial-refresh-secret") return void response.writeHead(200).end('{"access_token":"new-access-secret","refresh_token":"new-refresh-secret"}');
        return void response.writeHead(401).end('{"error":"invalid refresh"}');
      }
      if (path === "/cleanup" || path === "/logout" || path === "/revoke") return void response.writeHead(204).end();
      return void response.writeHead(404).end("{}");
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const target = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    const directory = await mkdtemp(join(tmpdir(), "routecairn-auth-lifecycle-")); directories.push(directory);
    const result = await runScanCommand(target, {
      scope: await writeJson(directory, "scope.json", { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"], rateLimitPerSecond: 50, concurrency: 2 }),
      output: join(directory, "reports"),
      auth: await writeJson(directory, "auth.json", { label: "disposable", safeAlias: "disposable-member", headers: {}, lifecycleSecrets: { known_username: "known@example.test", unknown_username: "unknown@example.test", password: "test-password-secret", fixed_session: "fixed-session-secret", initial_refresh: "initial-refresh-secret" } }),
      authenticationLifecycle: await writeJson(directory, "lifecycle.json", manifest(target))
    });
    const json = await readFile(result.reportPath, "utf8");
    const markdown = await readFile(result.markdownReportPath, "utf8");
    const html = await readFile(result.htmlReportPath, "utf8");
    const journal = await readFile(join(process.env.ROUTECAIRN_MUTATION_DIR!, "mutation-journal.json"), "utf8");
    const report = JSON.parse(json) as { authenticationLifecycle: import("../../src/reports/AuthenticationLifecycleReport.js").AuthenticationLifecycleReport; findings: Array<{ type: string }>; requestAudit: Array<{ requestHeaders: Record<string, string>; requestBodyHash?: string }>; scanPlan: { authenticationLifecycle: { cases: Array<{ authorization: Record<string, unknown> }> } } };
    expect(report.authenticationLifecycle).toMatchObject({ plannedCases: 3, executedCases: 3, passedCases: 2, failedCases: 1, cleanupRequired: 3, cleanupFailed: 0 });
    expect(report.authenticationLifecycle.observations.find((item) => item.caseId === "refresh-replay")?.outcome).toBe("FAIL");
    expect(report.authenticationLifecycle.observations.every((item) => item.cleanupOutcome === "ROLLBACK_VERIFIED")).toBe(true);
    expect(report.findings.some((item) => item.type === "Authentication Lifecycle Issue")).toBe(true);
    expect(seenBodies.some((body) => body.includes("initial-refresh-secret"))).toBe(true);
    expect(report.requestAudit.some((entry) => typeof entry.requestBodyHash === "string")).toBe(true);
    for (const output of [json, markdown, html, journal]) for (const secret of ["known@example.test", "unknown@example.test", "test-password-secret", "fixed-session-secret", "initial-refresh-secret", "rotated-session-secret", "new-access-secret", "new-refresh-secret", "security-operator", "AUTH-101"]) expect(output).not.toContain(secret);
    expect(JSON.parse(journal).filter((entry: { stage: string }) => entry.stage === "ROLLBACK_VERIFIED")).toHaveLength(3);
    expect(report.scanPlan.authenticationLifecycle.cases[0]?.authorization).not.toHaveProperty("authorizedBy");
  });

  it("durably marks failed cleanup and blocks later state-changing cases", async () => {
    let laterRequests = 0;
    server = createServer(async (request, response) => {
      if (request.url === "/") return void response.writeHead(200).end("ok");
      if (request.url === "/action") return void response.writeHead(200, { "content-type": "application/json" }).end('{"ok":true}');
      if (request.url === "/cleanup-fails") return void response.writeHead(500, { "content-type": "application/json" }).end('{"ok":false}');
      if (request.url === "/later") { laterRequests += 1; return void response.writeHead(200).end(); }
      return void response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const target = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    const directory = await mkdtemp(join(tmpdir(), "routecairn-auth-cleanup-")); directories.push(directory);
    const actor = { id: "public", safeAlias: "disposable-public", authSlot: "anonymous", relationship: "PUBLIC", declaredState: "ANONYMOUS" };
    const authorization = { mode: "CONTROLLED_LIFECYCLE", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING", authorizedBy: "operator", changeTicket: "AUTH-CLEANUP", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableAccounts: true };
    const step = (id: string, phase: string, path: string, expected: number) => ({ id, phase, actorId: "public", request: { method: "POST", url: new URL(path, target).toString(), stateChanging: true }, assertions: [{ kind: "STATUS_IN", values: [expected] }] });
    const cases = [
      { id: "cleanup-failure", label: "Failed cleanup", category: "SESSION_REVOCATION", actors: [actor], authorization, cleanupRequired: true, steps: [step("action", "ACTION", "/action", 200), step("cleanup", "CLEANUP", "/cleanup-fails", 204)] },
      { id: "must-block", label: "Blocked after cleanup", category: "LOGOUT_INVALIDATION", actors: [actor], authorization, cleanupRequired: true, steps: [step("later", "ACTION", "/later", 200), step("later-cleanup", "CLEANUP", "/later", 204)] }
    ];
    const result = await runScanCommand(target, { scope: await writeJson(directory, "scope.json", { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"], rateLimitPerSecond: 50 }), output: join(directory, "reports"), authenticationLifecycle: await writeJson(directory, "lifecycle.json", { schemaVersion: 1, cases }) });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { authenticationLifecycle: import("../../src/reports/AuthenticationLifecycleReport.js").AuthenticationLifecycleReport };
    expect(report.authenticationLifecycle.observations[0]?.cleanupOutcome).toBe("CLEANUP_FAILED");
    expect(report.authenticationLifecycle.observations[1]?.outcome).toBe("BLOCKED");
    expect(report.authenticationLifecycle.observations[1]?.notes).toContain("UNRESOLVED_PRIOR_CLEANUP");
    expect(laterRequests).toBe(0);
  });

  it("enforces the plan-wide scan deadline and retains abort-aware lifecycle evidence", async () => {
    server = createServer((_request, response) => response.writeHead(200, { "content-type": "application/json" }).end('{"active":true}'));
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const target = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
    const directory = await mkdtemp(join(tmpdir(), "routecairn-auth-deadline-")); directories.push(directory);
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"] as const, rateLimitPerSecond: 50 };
    const lifecycle = planAuthenticationLifecycle(authenticationLifecycleInputSchema.parse({ cases: [{ id: "idle-deadline", label: "Idle deadline", category: "IDLE_EXPIRATION", actors: [{ id: "public", safeAlias: "public-actor", authSlot: "anonymous", relationship: "PUBLIC", declaredState: "ANONYMOUS" }], authorization: { mode: "OBSERVE_ONLY", environment: "TEST" }, steps: [{ id: "after-idle", phase: "VERIFY", actorId: "public", waitBeforeMs: 2000, request: { method: "GET", url: new URL("/session", target).toString(), stateChanging: false }, assertions: [{ kind: "STATUS_IN", values: [401] }] }] }] }), { target, scope });
    const resolved = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "quick", scope, config: defaultConfig, overrides: { includeModules: ["authentication-lifecycle"] }, authenticationLifecycle: lifecycle });
    const plan = { ...resolved, limits: { ...resolved.limits, maxScanDurationMs: 250 } };
    const events: string[] = [];
    const started = Date.now();
    const result = await new RouteCairnEngine().scan({ target, scope, config: defaultConfig, plan, outputDir: join(directory, "reports"), eventSink: { async emit(event) { events.push(event.message); } } });
    expect(Date.now() - started).toBeLessThan(1500);
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { authenticationLifecycle?: import("../../src/reports/AuthenticationLifecycleReport.js").AuthenticationLifecycleReport };
    expect(report.authenticationLifecycle?.observations[0]?.outcome).toBe("INCONCLUSIVE");
    expect(events.some((message) => message.includes("duration limit"))).toBe(true);
  });
});

function manifest(target: string) {
  const url = (path: string) => new URL(path, target).toString();
  const authorization = { mode: "CONTROLLED_LIFECYCLE", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING", authorizedBy: "security-operator", changeTicket: "AUTH-101", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableAccounts: true };
  const actor = { id: "member", safeAlias: "disposable-member", authSlot: "primary", relationship: "SELF", declaredState: "ACTIVE" };
  const cleanup = (id: string, path = "/cleanup") => ({ id, phase: "CLEANUP", actorId: "member", request: { method: "POST", url: url(path), stateChanging: true }, assertions: [{ kind: "STATUS_IN", values: [204] }] });
  return { schemaVersion: 1, maxRequests: 20, cases: [
    { id: "enumeration", label: "Login enumeration resistance", category: "LOGIN_ENUMERATION_RESISTANCE", actors: [actor], authorization, cleanupRequired: true, steps: [
      { id: "known", phase: "ACTION", actorId: "member", request: { method: "POST", url: url("/login-enumeration"), stateChanging: true, fields: { username: "{{SECRET:known_username}}", password: "{{SECRET:password}}" } }, assertions: [{ kind: "STATUS_IN", values: [401] }] },
      { id: "unknown", phase: "VERIFY", actorId: "member", request: { method: "POST", url: url("/login-enumeration"), stateChanging: true, fields: { username: "{{SECRET:unknown_username}}", password: "{{SECRET:password}}" } }, assertions: [{ kind: "RESPONSE_SIMILAR", stepId: "known", compareStatus: true, compareShape: true, maxLengthDelta: 0 }] }, cleanup("enumeration-cleanup") ] },
    { id: "rotation", label: "Session rotates after login", category: "SESSION_ROTATION_AFTER_LOGIN", actors: [actor], authorization, cleanupRequired: true, steps: [
      { id: "login", phase: "ACTION", actorId: "member", request: { method: "POST", url: url("/login"), stateChanging: true, fields: { username: "{{SECRET:known_username}}", password: "{{SECRET:password}}" }, headers: { Cookie: "session={{SECRET:fixed_session}}" } }, captures: [{ name: "rotated_session", source: "COOKIE", cookie: "session" }], assertions: [{ kind: "CAPTURE_ROTATED", capture: "rotated_session", comparedTo: { source: "SECRET", ref: "fixed_session" } }] },
      { ...cleanup("rotation-cleanup", "/logout"), request: { method: "POST", url: url("/logout"), stateChanging: true, headers: { Cookie: "session={{CAPTURE:rotated_session}}" } } } ] },
    { id: "refresh-replay", label: "Refresh token replay rejection", category: "REFRESH_TOKEN_ROTATION", actors: [actor], authorization, cleanupRequired: true, steps: [
      { id: "rotate-refresh", phase: "ACTION", actorId: "member", request: { method: "POST", url: url("/refresh"), stateChanging: true, fields: { refresh_token: "{{SECRET:initial_refresh}}" } }, captures: [{ name: "new_refresh", source: "JSON", path: "refresh_token" }], assertions: [{ kind: "CAPTURE_ROTATED", capture: "new_refresh", comparedTo: { source: "SECRET", ref: "initial_refresh" } }] },
      { id: "replay-old", phase: "VERIFY", actorId: "member", request: { method: "POST", url: url("/refresh"), stateChanging: true, fields: { refresh_token: "{{SECRET:initial_refresh}}" } }, assertions: [{ kind: "STATUS_IN", values: [401] }] },
      { id: "revoke-new", phase: "CLEANUP", actorId: "member", request: { method: "POST", url: url("/revoke"), stateChanging: true, fields: { refresh_token: "{{CAPTURE:new_refresh}}" } }, assertions: [{ kind: "STATUS_IN", values: [204] }] } ] }
  ] };
}

async function writeJson(directory: string, name: string, value: unknown): Promise<string> { const path = join(directory, name); await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8"); return path; }
function requestBody(request: import("node:http").IncomingMessage): Promise<string> { return new Promise((resolve, reject) => { const chunks: Buffer[] = []; request.on("data", (chunk: Buffer) => chunks.push(chunk)); request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8"))); request.on("error", reject); }); }
