import { afterEach, describe, expect, it } from "vitest";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AuthProfile } from "../../src/core/auth/AuthProfile.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { RouteCairnEngine } from "../../src/core/engine/RouteCairnEngine.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { controlledRaceInputSchema, planControlledRace } from "../../src/modules/controlledRace/ControlledRacePlanner.js";
import { runScanCommand } from "../../src/cli/commands/scan.js";

let server: Server | undefined; const directories: string[] = [];
afterEach(async () => { if (server) await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve())); server = undefined; await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });

describe("controlled race integration", () => {
  it("synchronizes bounded groups, proves a duplicate effect, distinguishes a secure case, and verifies cleanup", async () => {
    const state = { vulnerable: { used: false, events: 0 }, secure: { used: false, events: 0 } }; const bodies: string[] = [];
    server = createServer(async (request, response) => {
      if (request.url === "/") return void response.writeHead(200).end("ok");
      const kind = request.url?.includes("secure") ? "secure" : "vulnerable"; const selected = state[kind];
      if (request.url === `/${kind}/state` && request.method === "GET") return json(response, 200, selected);
      if (request.url === `/${kind}/redeem` && request.method === "POST") {
        bodies.push(await requestBody(request));
        if (kind === "secure") { if (selected.used) return json(response, 409, { accepted: false }); selected.used = true; await delay(35); selected.events += 1; return json(response, 200, { accepted: true }); }
        if (selected.used) return json(response, 409, { accepted: false }); await delay(35); selected.used = true; selected.events += 1; return json(response, 200, { accepted: true });
      }
      if (request.url === `/${kind}/reset` && request.method === "DELETE") { selected.used = false; selected.events = 0; return void response.writeHead(204).end(); }
      return void response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; const directory = await mkdtemp(join(tmpdir(), "routecairn-race-")); directories.push(directory);
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PATCH", "PUT", "DELETE"] as const, rateLimitPerSecond: 1, concurrency: 5 };
    const authProfile: AuthProfile = { label: "member", safeAlias: "disposable-member", headers: { Authorization: "Bearer race-auth-secret" }, cookies: [], identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: { race_token: "one-time-race-secret" }, notes: [] };
    const controlledRace = planControlledRace(controlledRaceInputSchema.parse({ maxRequests: 30, maxConcurrency: 5, cases: [raceCase(origin, "vulnerable", "a"), raceCase(origin, "secure", "b")] }), { target: `${origin}/`, scope, authProfile });
    const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "quick", scope, config: defaultConfig, authProfile, controlledRace, overrides: { includeModules: ["controlled-race"] } });
    const result = await new RouteCairnEngine().scan({ target: `${origin}/`, scope, config: defaultConfig, plan, outputDir: join(directory, "reports"), authProfile });
    const jsonText = await readFile(result.reportPath, "utf8"); const markdown = await readFile(result.markdownReportPath, "utf8"); const html = await readFile(result.htmlReportPath, "utf8"); const journal = await readFile(join(process.env.ROUTECAIRN_MUTATION_DIR!, "mutation-journal.json"), "utf8");
    const report = JSON.parse(jsonText) as { controlledRace: import("../../src/reports/ControlledRaceReport.js").ControlledRaceReport; findings: Array<{ type: string }> };
    expect(report.controlledRace).toMatchObject({ plannedCases: 2, executedCases: 2, passedCases: 1, failedCases: 1, plannedGroups: 2, synchronizedGroups: 2, plannedRaceRequests: 4, transmittedRaceRequests: 4, cleanupFailed: 0 });
    expect(report.controlledRace.observations.find((item) => item.caseId === "vulnerable-race")).toMatchObject({ outcome: "FAIL", cleanupOutcome: "ROLLBACK_VERIFIED", preStateVerified: true, postStateVerified: true, groups: [{ synchronized: true, acceptedCount: 2 }] });
    expect(report.controlledRace.observations.find((item) => item.caseId === "secure-race")).toMatchObject({ outcome: "PASS", cleanupOutcome: "ROLLBACK_VERIFIED", groups: [{ synchronized: true, acceptedCount: 1, rejectedCount: 1 }] });
    expect(report.findings.some((finding) => finding.type === "Controlled Race Condition")).toBe(true); expect(markdown).toContain("## Controlled Race Testing"); expect(html).toContain("controlledRace");
    expect(state.vulnerable.events).toBe(0); expect(state.secure.events).toBe(0); expect(bodies.filter((value) => value.includes("one-time-race-secret"))).toHaveLength(4);
    for (const output of [jsonText, markdown, html, journal]) for (const secret of ["race-auth-secret", "one-time-race-secret", "operator-44", "RACE-44"]) expect(output).not.toContain(secret);
    expect(JSON.parse(journal).filter((entry: { stage: string }) => entry.stage === "ROLLBACK_VERIFIED")).toHaveLength(2);
  }, 30_000);

  it("runs a synchronized race manifest through the public CLI path", async () => {
    const state = { used: false, events: 0 };
    server = createServer(async (request, response) => {
      if (request.url === "/") return void response.writeHead(200).end("ok");
      if (request.url === "/secure/state" && request.method === "GET") return json(response, 200, state);
      if (request.url === "/secure/redeem" && request.method === "POST") {
        await requestBody(request);
        if (state.used) return json(response, 409, { accepted: false });
        state.used = true;
        await delay(25);
        state.events += 1;
        return json(response, 200, { accepted: true });
      }
      if (request.url === "/secure/reset" && request.method === "DELETE") { state.used = false; state.events = 0; return void response.writeHead(204).end(); }
      return void response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; const directory = await mkdtemp(join(tmpdir(), "routecairn-race-cli-")); directories.push(directory);
    const scopePath = await writeJson(directory, "scope.json", { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "DELETE"], rateLimitPerSecond: 1, concurrency: 5 });
    const authPath = await writeJson(directory, "auth.json", { label: "member", safeAlias: "disposable-member", headers: { Authorization: "Bearer cli-race-secret" }, lifecycleSecrets: { race_token: "cli-one-time-secret" } });
    const manifestPath = await writeJson(directory, "controlled-races.json", { schemaVersion: 1, maxRequests: 15, maxConcurrency: 5, cases: [raceCase(origin, "secure", "d")] });
    const result = await runScanCommand(`${origin}/`, { scope: scopePath, auth: authPath, controlledRaces: manifestPath, output: join(directory, "reports") });
    const text = await readFile(result.reportPath, "utf8"); const report = JSON.parse(text) as { controlledRace: import("../../src/reports/ControlledRaceReport.js").ControlledRaceReport };
    expect(report.controlledRace).toMatchObject({ enabled: true, plannedCases: 1, passedCases: 1, synchronizedGroups: 1, transmittedRaceRequests: 2, cleanupFailed: 0 });
    expect(state).toEqual({ used: false, events: 0 });
    expect(text).not.toContain("cli-race-secret"); expect(text).not.toContain("cli-one-time-secret");
  }, 30_000);

  it("records failed cleanup durably and blocks every later race group", async () => {
    const state = { used: false, events: 0 }; let laterRaceRequests = 0;
    server = createServer(async (request, response) => {
      if (request.url === "/") return void response.writeHead(200).end("ok");
      if (request.url === "/vulnerable/state" && request.method === "GET") return json(response, 200, state);
      if (request.url === "/vulnerable/redeem" && request.method === "POST") { if (state.used) return json(response, 409, { accepted: false }); await delay(25); state.used = true; state.events += 1; return json(response, 200, { accepted: true }); }
      if (request.url === "/later" && request.method === "POST") { laterRaceRequests += 1; return json(response, 200, { accepted: true }); }
      if (request.url === "/cleanup-fails" && request.method === "DELETE") return void response.writeHead(500).end();
      return void response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`; const directory = await mkdtemp(join(tmpdir(), "routecairn-race-cleanup-")); directories.push(directory);
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "DELETE"] as const, rateLimitPerSecond: 50, concurrency: 5 };
    const authProfile: AuthProfile = { label: "member", safeAlias: "disposable-member", headers: {}, cookies: [], identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: { race_token: "cleanup-race-secret" }, notes: [] };
    const first: any = raceCase(origin, "vulnerable", "e"); first.id = "cleanup-failure"; first.cleanup[0].request.url = `${origin}/cleanup-fails`;
    const second: any = raceCase(origin, "vulnerable", "f"); second.id = "must-block"; second.target.safeAlias = "later-target"; for (const request of second.groups[0].requests) request.request.url = `${origin}/later`;
    const controlledRace = planControlledRace(controlledRaceInputSchema.parse({ maxRequests: 30, maxConcurrency: 5, cases: [first, second] }), { target: `${origin}/`, scope, authProfile });
    const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "quick", scope, config: defaultConfig, authProfile, controlledRace, overrides: { includeModules: ["controlled-race"] } });
    const result = await new RouteCairnEngine().scan({ target: `${origin}/`, scope, config: defaultConfig, plan, outputDir: join(directory, "reports"), authProfile });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { controlledRace: import("../../src/reports/ControlledRaceReport.js").ControlledRaceReport };
    expect(report.controlledRace).toMatchObject({ cleanupFailed: 1, blockedCases: 1, transmittedRaceRequests: 2 });
    expect(report.controlledRace.observations[0]?.cleanupOutcome).toBe("CLEANUP_FAILED");
    expect(report.controlledRace.observations[1]?.notes).toContain("UNRESOLVED_PRIOR_CLEANUP");
    expect(laterRaceRequests).toBe(0);
    const journal = JSON.parse(await readFile(join(process.env.ROUTECAIRN_MUTATION_DIR!, "mutation-journal.json"), "utf8")) as Array<{ stage: string }>;
    expect(journal.some((entry) => entry.stage === "CLEANUP_FAILED")).toBe(true);
  }, 30_000);
});

const authorization = { mode: "CONTROLLED_RACE" as const, environment: "TEST" as const, confirmation: "I_AUTHORIZE_CONTROLLED_RACE_TESTING" as const, authorizedBy: "operator-44", changeTicket: "RACE-44", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableEntities: true as const };
const actor = { id: "member", safeAlias: "disposable-member", authSlot: "primary" as const, relationship: "SELF", declaredState: "ACTIVE" };
function raceCase(origin: string, kind: "vulnerable" | "secure", fingerprint: string) { const observation = (id: string, name: string) => ({ id, actorId: "member", request: { method: "GET" as const, url: `${origin}/${kind}/state`, stateChanging: false }, captures: [{ name, source: "JSON" as const, path: "events" }] }); const member = (id: string) => ({ id, actorId: "member", request: { method: "POST" as const, url: `${origin}/${kind}/redeem`, stateChanging: true, bodyFormat: "JSON" as const, fields: { token: "{{SECRET:race_token}}" } }, expectation: { authorization: "ALLOW" as const, businessRule: "NOT_EVALUATED" as const } }); return { id: `${kind}-race`, label: `${kind} one-time token race`, category: "ONE_TIME_TOKEN" as const, target: { type: "one-time-token", safeAlias: `${kind}-token`, identityFingerprint: fingerprint.repeat(64), disposable: true as const }, actors: [actor], authorization, preState: [observation(`${kind}-before`, `${kind}_events_before`)], groups: [{ id: `${kind}-group`, label: "Two synchronized redemptions", synchronization: "READY_BARRIER" as const, maxDispatchSkewMs: 100, requests: [member(`${kind}-a`), member(`${kind}-b`)] }], postState: [observation(`${kind}-after`, `${kind}_events_after`)], invariants: [{ id: `${kind}-one-event`, kind: "EVENT_COUNT_DELTA" as const, before: `${kind}_events_before`, after: `${kind}_events_after`, operator: "LTE" as const, expected: 1 }, { id: `${kind}-one-accept`, kind: "GROUP_OUTCOME_COUNT" as const, groupId: `${kind}-group`, outcome: "ACCEPTED" as const, operator: "LTE" as const, expected: 1 }], cleanupRequired: true as const, cleanup: [{ id: `${kind}-reset`, actorId: "member", request: { method: "DELETE" as const, url: `${origin}/${kind}/reset`, stateChanging: true }, successStatusCodes: [204] }], cleanupVerification: [observation(`${kind}-restored`, `${kind}_events_restored`)], cleanupInvariants: [{ id: `${kind}-cleanup`, kind: "VALUE_COMPARE" as const, left: { source: "CAPTURE" as const, ref: `${kind}_events_restored` }, operator: "EQ" as const, right: { source: "CAPTURE" as const, ref: `${kind}_events_before` } }] }; }
function json(response: ServerResponse, status: number, value: unknown): void { response.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(value)); }
async function requestBody(request: IncomingMessage): Promise<string> { const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk)); return Buffer.concat(chunks).toString("utf8"); }
async function writeJson(directory: string, name: string, value: unknown): Promise<string> { const path = join(directory, name); await writeFile(path, JSON.stringify(value)); return path; }
function delay(ms: number): Promise<void> { return new Promise((resolve) => setTimeout(resolve, ms)); }
