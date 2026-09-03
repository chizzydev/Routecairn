import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { exampleScope, defaultConfig } from "../../src/config/defaults.js";
import { RouteCairnEngine } from "../../src/core/engine/RouteCairnEngine.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import type { AuthProfile } from "../../src/core/auth/AuthProfile.js";
import { businessInvariantInputSchema, planBusinessInvariant } from "../../src/modules/businessInvariant/BusinessInvariantPlanner.js";
import { runScanCommand } from "../../src/cli/commands/scan.js";

let server: Server | undefined; const directories: string[] = [];
afterEach(async () => { if (server) await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve())); server = undefined; await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });

describe("business invariant integration", () => {
  it("proves a concurrent one-time-action violation, verifies cleanup, and persists only redacted structural evidence", async () => {
    let balance = 100; let redemptions = 0; const bodies: string[] = [];
    server = createServer(async (request, response) => {
      if (request.url === "/") return void response.writeHead(200).end("ok");
      if (request.url === "/wallet" && request.method === "GET") return json(response, 200, { balance });
      if (request.url === "/withdraw" && request.method === "POST") { bodies.push(await body(request)); balance -= 10; return json(response, 200, { accepted: true }); }
      if (request.url === "/restore-wallet" && request.method === "POST") { balance = 100; return void response.writeHead(204).end(); }
      if (request.url === "/coupon" && request.method === "GET") return json(response, 200, { redemptions });
      if (request.url === "/redeem" && request.method === "POST") { bodies.push(await body(request)); redemptions += 1; return json(response, 200, { accepted: true }); }
      if (request.url === "/reset-coupon" && request.method === "DELETE") { redemptions = 0; return void response.writeHead(204).end(); }
      return void response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; const target = `${origin}/`;
    const directory = await mkdtemp(join(tmpdir(), "routecairn-business-invariant-")); directories.push(directory);
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"] as const, rateLimitPerSecond: 50, concurrency: 4 };
    const authProfile: AuthProfile = { label: "member", safeAlias: "disposable-member", headers: { Authorization: "Bearer transport-secret-43" }, cookies: [], identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: { coupon_code: "coupon-secret-43" }, notes: [] };
    const businessInvariant = planBusinessInvariant(businessInvariantInputSchema.parse({ maxConcurrency: 2, maxRequests: 20, cases: [walletCase(origin), couponCase(origin)] }), { target, scope, authProfile });
    const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "quick", scope, config: defaultConfig, authProfile, businessInvariant, overrides: { includeModules: ["business-invariant"] } });
    const result = await new RouteCairnEngine().scan({ target, scope, config: defaultConfig, plan, outputDir: join(directory, "reports"), authProfile });
    const jsonText = await readFile(result.reportPath, "utf8"); const markdown = await readFile(result.markdownReportPath, "utf8"); const html = await readFile(result.htmlReportPath, "utf8"); const journal = await readFile(join(process.env.ROUTECAIRN_MUTATION_DIR!, "mutation-journal.json"), "utf8");
    const report = JSON.parse(jsonText) as { businessInvariant: import("../../src/reports/BusinessInvariantReport.js").BusinessInvariantReport; findings: Array<{ type: string }>; requestAudit: Array<{ requestHeaders: Record<string, string>; requestBodyHash?: string }> };
    expect(report.businessInvariant).toMatchObject({ plannedCases: 2, executedCases: 2, passedCases: 1, failedCases: 1, cleanupRequired: 2, cleanupFailed: 0, duplicateAttempts: 1, concurrentActions: 1 });
    expect(report.businessInvariant.observations.find((item) => item.caseId === "coupon-once")).toMatchObject({ outcome: "FAIL", cleanupOutcome: "ROLLBACK_VERIFIED", preStateVerified: true, postStateVerified: true });
    expect(report.businessInvariant.observations.find((item) => item.caseId === "coupon-once")?.actions[0]).toMatchObject({ attemptsTransmitted: 2, acceptedCount: 2 });
    expect(report.findings.some((finding) => finding.type === "Business Logic Invariant Issue")).toBe(true);
    expect(markdown).toContain("## Business Invariant Validation"); expect(html).toContain("businessInvariant");
    expect(balance).toBe(100); expect(redemptions).toBe(0); expect(bodies.some((value) => value.includes("coupon-secret-43"))).toBe(true);
    for (const output of [jsonText, markdown, html, journal]) for (const secret of ["coupon-secret-43", "transport-secret-43", "operator-43", "BIZ-43"]) expect(output).not.toContain(secret);
    expect(report.requestAudit.some((entry) => typeof entry.requestBodyHash === "string")).toBe(true);
    expect(JSON.parse(journal).filter((entry: { stage: string }) => entry.stage === "ROLLBACK_VERIFIED")).toHaveLength(2);
  });

  it("runs the explicit manifest through the public CLI path", async () => {
    let balance = 100;
    server = createServer(async (request, response) => {
      if (request.url === "/") return void response.writeHead(200).end("ok");
      if (request.url === "/wallet" && request.method === "GET") return json(response, 200, { balance });
      if (request.url === "/withdraw" && request.method === "POST") { await body(request); balance -= 10; return json(response, 200, { accepted: true }); }
      if (request.url === "/restore-wallet" && request.method === "POST") { balance = 100; return void response.writeHead(204).end(); }
      return void response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; const directory = await mkdtemp(join(tmpdir(), "routecairn-business-cli-")); directories.push(directory);
    const scopePath = await writeJson(directory, "scope.json", { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"], rateLimitPerSecond: 50, concurrency: 2 });
    const authPath = await writeJson(directory, "auth.json", { label: "member", safeAlias: "disposable-member", headers: { Authorization: "Bearer cli-secret-43" }, lifecycleSecrets: { coupon_code: "unused" } });
    const manifestPath = await writeJson(directory, "invariant.json", { schemaVersion: 1, maxRequests: 10, cases: [walletCase(origin)] });
    const result = await runScanCommand(`${origin}/`, { scope: scopePath, auth: authPath, businessInvariants: manifestPath, output: join(directory, "reports") });
    const text = await readFile(result.reportPath, "utf8"); const report = JSON.parse(text) as { businessInvariant: import("../../src/reports/BusinessInvariantReport.js").BusinessInvariantReport };
    expect(report.businessInvariant).toMatchObject({ plannedCases: 1, passedCases: 1, cleanupFailed: 0 }); expect(balance).toBe(100); expect(text).not.toContain("cli-secret-43");
  });

  it("marks failed cleanup durably and blocks every later invariant mutation", async () => {
    let balance = 100; let laterActions = 0;
    server = createServer(async (request, response) => {
      if (request.url === "/") return void response.writeHead(200).end("ok");
      if (request.url === "/wallet" && request.method === "GET") return json(response, 200, { balance });
      if (request.url === "/withdraw" && request.method === "POST") { balance -= 10; return json(response, 200, { accepted: true }); }
      if (request.url === "/later" && request.method === "POST") { laterActions += 1; balance -= 10; return json(response, 200, { accepted: true }); }
      if (request.url === "/cleanup-fails" && request.method === "POST") return void response.writeHead(500).end();
      if (request.url === "/restore-wallet" && request.method === "POST") { balance = 100; return void response.writeHead(204).end(); }
      return void response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; const directory = await mkdtemp(join(tmpdir(), "routecairn-business-cleanup-")); directories.push(directory);
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"] as const, rateLimitPerSecond: 50, concurrency: 2 };
    const authProfile: AuthProfile = { label: "member", headers: {}, cookies: [], identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: {}, notes: [] };
    const first: any = walletCase(origin); first.id = "cleanup-failure"; first.cleanup[0].request.url = `${origin}/cleanup-fails`; const second: any = walletCase(origin); second.id = "must-block"; second.actions[0].request.url = `${origin}/later`;
    const businessInvariant = planBusinessInvariant(businessInvariantInputSchema.parse({ maxRequests: 20, cases: [first, second] }), { target: `${origin}/`, scope, authProfile });
    const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "quick", scope, config: defaultConfig, authProfile, businessInvariant, overrides: { includeModules: ["business-invariant"] } });
    const result = await new RouteCairnEngine().scan({ target: `${origin}/`, scope, config: defaultConfig, plan, outputDir: join(directory, "reports"), authProfile });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { businessInvariant: import("../../src/reports/BusinessInvariantReport.js").BusinessInvariantReport };
    expect(report.businessInvariant).toMatchObject({ cleanupFailed: 1, blockedCases: 1 });
    expect(report.businessInvariant.observations[0]?.cleanupOutcome).toBe("CLEANUP_FAILED"); expect(report.businessInvariant.observations[1]?.notes).toContain("UNRESOLVED_PRIOR_CLEANUP"); expect(laterActions).toBe(0);
  });
});

const authorization = { mode: "CONTROLLED_INVARIANT" as const, environment: "TEST" as const, confirmation: "I_AUTHORIZE_CONTROLLED_BUSINESS_INVARIANT_TESTING" as const, authorizedBy: "operator-43", changeTicket: "BIZ-43", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableEntities: true as const };
const actor = { id: "member", safeAlias: "disposable-member", authSlot: "primary" as const, relationship: "SELF", declaredState: "ACTIVE" };
function walletCase(origin: string) { return { id: "wallet-limit", label: "Wallet remains nonnegative", category: "FINANCIAL_LIMIT" as const, actors: [actor], authorization, preState: [observation("wallet-before", `${origin}/wallet`, "balance_before", "balance")], actions: [action("withdraw", `${origin}/withdraw`, { amount: 10 }, "ONCE", 1, 1)], postState: [observation("wallet-after", `${origin}/wallet`, "balance_after", "balance")], invariants: [{ id: "nonnegative", kind: "VALUE_COMPARE" as const, left: { source: "CAPTURE" as const, ref: "balance_after" }, operator: "GTE" as const, right: { source: "LITERAL" as const, value: 0 } }, { id: "one-withdrawal", kind: "NUMERIC_DELTA" as const, before: "balance_before", after: "balance_after", operator: "EQ" as const, expected: -10 }], cleanupRequired: true as const, cleanup: [cleanup("restore", `${origin}/restore-wallet`, "POST")], cleanupVerification: [observation("wallet-restored", `${origin}/wallet`, "balance_restored", "balance")], cleanupInvariants: [{ id: "wallet-reset", kind: "VALUE_COMPARE" as const, left: { source: "CAPTURE" as const, ref: "balance_restored" }, operator: "EQ" as const, right: { source: "CAPTURE" as const, ref: "balance_before" } }] }; }
function couponCase(origin: string) { return { id: "coupon-once", label: "Coupon applies once", category: "ONE_TIME_ACTION" as const, actors: [actor], authorization, preState: [observation("coupon-before", `${origin}/coupon`, "redemptions_before", "redemptions")], actions: [action("redeem", `${origin}/redeem`, { couponCode: "{{SECRET:coupon_code}}" }, "CONCURRENT_DUPLICATE", 2, 2)], postState: [observation("coupon-after", `${origin}/coupon`, "redemptions_after", "redemptions")], invariants: [{ id: "accepted-once", kind: "ACTION_OUTCOME_COUNT" as const, actionId: "redeem", outcome: "ACCEPTED" as const, operator: "LTE" as const, expected: 1 }, { id: "effect-once", kind: "NUMERIC_DELTA" as const, before: "redemptions_before", after: "redemptions_after", operator: "LTE" as const, expected: 1 }], cleanupRequired: true as const, cleanup: [cleanup("reset", `${origin}/reset-coupon`, "DELETE")], cleanupVerification: [observation("coupon-restored", `${origin}/coupon`, "redemptions_restored", "redemptions")], cleanupInvariants: [{ id: "coupon-reset", kind: "VALUE_COMPARE" as const, left: { source: "CAPTURE" as const, ref: "redemptions_restored" }, operator: "EQ" as const, right: { source: "CAPTURE" as const, ref: "redemptions_before" } }] }; }
function observation(id: string, url: string, name: string, path: string) { return { id, actorId: "member", request: { method: "GET" as const, url, stateChanging: false }, captures: [{ name, source: "JSON" as const, path }] }; }
function action(id: string, url: string, fields: Record<string, unknown>, mode: "ONCE" | "CONCURRENT_DUPLICATE", attempts: number, maxConcurrency: number) { return { id, actorId: "member", request: { method: "POST" as const, url, stateChanging: true, bodyFormat: "JSON" as const, fields }, execution: { mode, attempts, maxConcurrency }, expectation: { authorization: "ALLOW" as const, businessRule: "NOT_EVALUATED" as const } }; }
function cleanup(id: string, url: string, method: "POST" | "DELETE") { return { id, actorId: "member", request: { method, url, stateChanging: true }, successStatusCodes: [204] }; }
function json(response: import("node:http").ServerResponse, status: number, value: unknown): void { response.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(value)); }
async function body(request: import("node:http").IncomingMessage): Promise<string> { const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk)); return Buffer.concat(chunks).toString("utf8"); }
async function writeJson(directory: string, name: string, value: unknown): Promise<string> { const path = join(directory, name); await writeFile(path, JSON.stringify(value)); return path; }
