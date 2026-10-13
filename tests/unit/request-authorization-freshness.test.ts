import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ScanRequestLedger } from "../../src/core/http/ScanRequestLedger.js";
import { RequestSafetyBroker } from "../../src/core/http/RequestSafetyBroker.js";
import { ScopeMatcher } from "../../src/core/scope/ScopeMatcher.js";
import { TargetAuthorizationGuard, targetAuthorizationSchema } from "../../src/core/authorization/TargetAuthorization.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import type { RequestAuditEntry } from "../../src/core/http/HttpTypes.js";

afterEach(() => vi.restoreAllMocks());
function authorization(origin: string, expiry: number, mode = "BUG_BOUNTY_AUTHORIZED") {
  const now = Date.now();
  return targetAuthorizationSchema.parse({ schemaVersion: 1, mode, targetOrigin: origin, proof: { reference: "Owned public constant-response loopback fixture", sha256: "a".repeat(64) }, ...(mode === "BUG_BOUNTY_AUTHORIZED" ? { bugBounty: {
    program: "Owned loopback freshness fixture", platform: "LOCAL", scopeDocumentSha256: "b".repeat(64), inScope: [{ origin, pathPrefix: "/" }], outOfScope: [], rules: ["Only owned non-mutating fixture requests"], prohibitedActions: ["No external targets or credentials"], startsAt: new Date(now - 1000).toISOString(), expiresAt: new Date(expiry).toISOString(), maxRequests: 10, rateLimitPerSecond: 50, authenticationPermitted: false, mutationPermitted: false, destructivePermitted: false, racePermitted: false, disposableAccountsSupplied: false, requests: [], reportMode: "BUG_BOUNTY_SAFE"
  } } : {}) });
}
async function fixture(handler?: (ordinal: number, response: import("node:http").ServerResponse) => void) {
  let receipts = 0;
  const server = createServer((_request, response) => { receipts++; if (handler) handler(receipts, response); else { response.writeHead(200); response.end("constant-public-fixture"); } });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address(); if (!address || typeof address === "string") throw new Error("Fixture failed");
  return { origin: `http://127.0.0.1:${address.port}`, server, get receipts() { return receipts; } };
}
async function close(server: Server) { server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
function setup(origin: string, options: { window?: number; coordinated?: boolean; rate?: number; max?: number; reserve?: number; mode?: string; signal?: AbortSignal; retries?: boolean } = {}) {
  const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"] as const, disallowedPaths: [] as string[], rateLimitPerSecond: options.rate ?? 1, concurrency: 1 };
  const guard = new TargetAuthorizationGuard(authorization(origin, Date.now() + (options.window ?? 500), options.mode));
  const matcher = new ScopeMatcher(origin, scope, guard); const ledger = new ScanRequestLedger(options.max ?? 3, options.reserve ?? 1, options.rate ?? 1, 1); const audits: RequestAuditEntry[] = [];
  const broker = new RequestSafetyBroker({ userAgent: "RouteCairn-owned-freshness-fixture", timeoutMs: 3000, bodyPreviewBytes: 1024, maxResponseBytes: 4096, rateLimitPerSecond: options.rate ?? 1, concurrency: 1, maxRequests: options.max ?? 3, retry: { maxAttempts: options.retries ? 3 : 1, baseDelayMs: 700, maxDelayMs: 700, retryStatusCodes: [500] }, ...(options.signal ? { abortSignal: options.signal } : {}) }, matcher, (value) => audits.push(value), options.coordinated === false ? undefined : { ledger, lane: "SCAN" });
  return { broker, ledger, audits, guard, matcher, scope };
}
describe("P0 final broker/ledger authorization freshness", () => {
  it.each(["SCAN", "CLEANUP"] as const)("denies final %s guard without reserving or operating", async (lane) => {
    const ledger = new ScanRequestLedger(3, 1, 50, 1); const operation = vi.fn(async () => 1); const before = ledger.snapshot();
    const result = await ledger.transmit(lane, undefined, operation, { beforeTransmit: () => false });
    expect(result).toEqual({ accepted: false, reason: "POLICY_DENIED" }); expect(operation).not.toHaveBeenCalled(); expect(ledger.snapshot()).toEqual(before);
  });
  it.each(["SCAN", "CLEANUP"] as const)("contains thrown %s predicates and releases concurrency", async (lane) => {
    const ledger = new ScanRequestLedger(3, 1, 50, 1);
    expect(await ledger.transmit(lane, undefined, async () => 1, { beforeTransmit: () => { throw new Error("private-predicate-secret"); } })).toEqual({ accepted: false, reason: "POLICY_DENIED" });
    expect(ledger.snapshot()).toMatchObject({ inFlight: 0, queued: 0, scanTransmitted: 0, cleanupTransmitted: 0 });
    expect(await ledger.transmit(lane, undefined, async () => 1)).toEqual({ accepted: true, value: 1 });
  });
  it("has no await between final synchronous predicate and operation", async () => {
    const ledger = new ScanRequestLedger(3, 1, 50, 1); let microtaskRan = false; const predicate = vi.fn(() => { queueMicrotask(() => { microtaskRan = true; }); return true; });
    expect(await ledger.transmit("SCAN", undefined, async () => { expect(microtaskRan).toBe(false); return 1; }, { beforeTransmit: predicate })).toEqual({ accepted: true, value: 1 }); expect(predicate).toHaveBeenCalledOnce();
  });
  it("rechecks after concurrency acquisition and retains cleanup reserve", async () => {
    const ledger = new ScanRequestLedger(3, 1, 50, 1); let release!: () => void; let permitted = true;
    const hold = ledger.transmit("SCAN", undefined, () => new Promise<void>((resolve) => { release = resolve; }));
    await vi.waitFor(() => expect(release).toBeTypeOf("function"));
    const queued = ledger.transmit("SCAN", undefined, async () => { throw new Error("No dispatch"); }, { beforeTransmit: () => permitted });
    await vi.waitFor(() => expect(ledger.snapshot().queued).toBe(1)); permitted = false; release(); await hold;
    expect(await queued).toEqual({ accepted: false, reason: "POLICY_DENIED" }); expect(ledger.snapshot()).toMatchObject({ scanTransmitted: 1, cleanupRemaining: 1, inFlight: 0, queued: 0 });
  });
  it.each([0, -1])("rejects time at/after expiry (%s offset) without authorization accounting", async (offset) => {
    const origin = "http://127.0.0.1:1"; const plan = authorization(origin, Date.now() + 1000); const expiry = Date.parse(plan.bugBounty!.expiresAt); const guard = new TargetAuthorizationGuard(plan, () => expiry - offset);
    const ledger = new ScanRequestLedger(3, 1, 50, 1); expect(await ledger.transmit("SCAN", undefined, async () => 1, { beforeTransmit: () => !guard.reserve(`${origin}/health`, "GET") })).toEqual({ accepted: false, reason: "POLICY_DENIED" }); expect(guard.snapshot().transmittedRequests).toBe(0);
  });
  it("preserves budget-exhausted result and never evaluates a guard without capacity", async () => {
    const ledger = new ScanRequestLedger(1, 1, 50, 1); const predicate = vi.fn(() => true);
    expect(await ledger.transmit("SCAN", undefined, async () => 1, { beforeTransmit: predicate })).toEqual({ accepted: false }); expect(predicate).not.toHaveBeenCalled(); expect(ledger.snapshot().cleanupRemaining).toBe(1);
  });
  it("preserves cancellation before final predicate", async () => {
    const ledger = new ScanRequestLedger(3, 1, 50, 1); const controller = new AbortController(); controller.abort(); const guard = vi.fn(() => false);
    await expect(ledger.transmit("SCAN", controller.signal, async () => 1, { beforeTransmit: guard })).rejects.toThrow(/cancel/i); expect(guard).not.toHaveBeenCalled();
  });
  it.each([true, false])("naturally expired queued broker dispatch sends no second receipt (coordinated=%s)", async (coordinated) => {
    const owned = await fixture(); const state = setup(owned.origin, { coordinated }); const reserve = vi.spyOn(state.guard, "reserve");
    try { expect((await state.broker.send({ url: `${owned.origin}/health`, method: "GET", skipCache: true, disableRetries: true, disableRedirects: true })).statusCode).toBe(200); expect(owned.receipts).toBe(1);
      const response = await state.broker.send({ url: `${owned.origin}/status`, method: "GET", skipCache: true, disableRetries: true, disableRedirects: true });
      expect(owned.receipts).toBe(1); expect(response.error?.name).toBe("TargetAuthorizationDenied"); expect(state.audits.at(-1)?.outcome).toBe("scope-skipped"); expect(state.guard.snapshot().transmittedRequests).toBe(1); expect(reserve).toHaveBeenCalledTimes(1); expect(state.broker.budgetSnapshot().transmittedRequests).toBe(1); if (coordinated) expect(state.ledger.snapshot()).toMatchObject({ scanTransmitted: 1, cleanupRemaining: 1, inFlight: 0, queued: 0 });
    } finally { await state.broker.close(); await close(owned.server); }
  });
  it.each([true, false])("open-window control retains two real receipts and exactly two reservations (%s)", async (coordinated) => {
    const owned = await fixture(); const state = setup(owned.origin, { coordinated, window: 60_000 }); const reserve = vi.spyOn(state.guard, "reserve");
    try { for (const path of ["/health", "/status"]) expect((await state.broker.send({ url: owned.origin + path, method: "GET", skipCache: true })).statusCode).toBe(200); expect(owned.receipts).toBe(2); expect(reserve).toHaveBeenCalledTimes(2); expect(state.guard.snapshot().transmittedRequests).toBe(2); }
    finally { await state.broker.close(); await close(owned.server); }
  });
  it("fixes the exact original ScanContext path with cleanup capacity unchanged", async () => {
    const owned = await fixture(); const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], allowedMethods: ["GET"] as const, disallowedPaths: [], rateLimitPerSecond: 1, concurrency: 1 };
    const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "quick", scope, config: defaultConfig, targetAuthorization: authorization(owned.origin, Date.now() + 500), overrides: { includeModules: ["api-mapper"], maxRequests: 3, cleanupReservedRequests: 1 } });
    const context = new ScanContext({ target: owned.origin, scope, config: defaultConfig, plan, outputDir: process.env.ROUTECAIRN_MUTATION_DIR! });
    try { await context.httpClient.send({ url: `${owned.origin}/health`, method: "GET", skipCache: true }); const denied = await context.httpClient.send({ url: `${owned.origin}/status`, method: "GET", skipCache: true }); expect(denied.error?.name).toBe("TargetAuthorizationDenied"); expect(owned.receipts).toBe(1); expect(context.requestLedger.snapshot()).toMatchObject({ scanTransmitted: 1, cleanupTransmitted: 0, cleanupRemaining: 1 }); }
    finally { await context.dispose(); await close(owned.server); }
  });
  it("rejects a delayed retry without another transport or reservation", async () => {
    const owned = await fixture((_ordinal, response) => { response.writeHead(500); response.end("fixture-failure"); }); const state = setup(owned.origin, { retries: true, rate: 50 });
    try { const response = await state.broker.send({ url: `${owned.origin}/health`, method: "GET", skipCache: true }); expect(response.error?.name).toBe("TargetAuthorizationDenied"); expect(owned.receipts).toBe(1); expect(state.guard.snapshot().transmittedRequests).toBe(1); }
    finally { await state.broker.close(); await close(owned.server); }
  });
  it("does not transmit a same-origin redirected hop after expiry", async () => {
    const owned = await fixture((_ordinal, response) => { response.writeHead(302, { location: "/status" }); response.end(); }); const state = setup(owned.origin);
    try { const response = await state.broker.send({ url: `${owned.origin}/health`, method: "GET", skipCache: true }); expect(owned.receipts).toBe(1); expect(response.error?.name).toBe("TargetAuthorizationDenied"); expect(state.ledger.snapshot().scanTransmitted).toBe(1); }
    finally { await state.broker.close(); await close(owned.server); }
  });
  it("preserves cross-origin redirect blocking", async () => {
    const owned = await fixture((_ordinal, response) => { response.writeHead(302, { location: "http://127.0.0.1:1/private" }); response.end(); }); const state = setup(owned.origin, { window: 60_000 });
    try { expect((await state.broker.send({ url: `${owned.origin}/health`, method: "GET", skipCache: true })).error?.name).toBe("OutOfScopeRedirect"); expect(owned.receipts).toBe(1); }
    finally { await state.broker.close(); await close(owned.server); }
  });
  it("fails a changed method scope at dispatch without late transmission", async () => {
    const owned = await fixture(); const state = setup(owned.origin, { window: 60_000 });
    try { await state.broker.send({ url: `${owned.origin}/health`, method: "GET", skipCache: true }); const queued = state.broker.send({ url: `${owned.origin}/status`, method: "GET", skipCache: true }); await new Promise((resolve) => setTimeout(resolve, 50)); state.scope.disallowedPaths.push("/status"); expect((await queued).error?.name).toBe("TargetAuthorizationDenied"); expect(owned.receipts).toBe(1); }
    finally { await state.broker.close(); await close(owned.server); }
  });
  it("contains a throwing scope predicate without private error leakage", async () => {
    const owned = await fixture(); const state = setup(owned.origin, { window: 60_000 });
    try { await state.broker.send({ url: `${owned.origin}/health`, method: "GET", skipCache: true }); const queued = state.broker.send({ url: `${owned.origin}/status?token=private-canary`, method: "GET", skipCache: true }); await new Promise((resolve) => setTimeout(resolve, 50)); vi.spyOn(state.matcher, "decide").mockImplementation(() => { throw new Error("private-predicate-secret"); }); const response = await queued; expect(response.error?.name).toBe("TargetAuthorizationDenied"); expect(JSON.stringify(response)).not.toContain("private"); expect(JSON.stringify(state.audits.at(-1))).not.toContain("private"); expect(owned.receipts).toBe(1); }
    finally { await state.broker.close(); await close(owned.server); }
  });
  it("cancels during rate wait without extra receipt or stale-policy conversion", async () => {
    const controller = new AbortController(); const owned = await fixture(); const state = setup(owned.origin, { window: 60_000, signal: controller.signal });
    try { await state.broker.send({ url: `${owned.origin}/health`, method: "GET", skipCache: true }); const queued = state.broker.send({ url: `${owned.origin}/status`, method: "GET", skipCache: true }); const assertion = expect(queued).rejects.toThrow(); await new Promise((resolve) => setTimeout(resolve, 50)); controller.abort(); await assertion; expect(owned.receipts).toBe(1); expect(state.ledger.snapshot()).toMatchObject({ inFlight: 0, queued: 0, cleanupRemaining: 1 }); }
    finally { await state.broker.close(); await close(owned.server); }
  });
  it.each(["OWNED_PRODUCTION", "INTERNAL_STAGING", "PRE_HANDOVER_ASSAULT"])("retains %s permitted ordinary behavior", async (mode) => {
    const owned = await fixture(); const state = setup(owned.origin, { mode, rate: 50 });
    try { expect((await state.broker.send({ url: `${owned.origin}/health`, method: "GET" })).statusCode).toBe(200); expect(owned.receipts).toBe(1); expect(state.guard.snapshot().transmittedRequests).toBe(0); }
    finally { await state.broker.close(); await close(owned.server); }
  });
  it("preserves the fixed authorization-cap diagnostic without extra receipt or reservation", async () => {
    const owned = await fixture(); const state = setup(owned.origin, { window: 60_000, rate: 50, max: 20 });
    try { for (let n = 0; n < 10; n++) expect((await state.broker.send({ url: owned.origin + "/health", method: "GET", skipCache: true })).statusCode).toBe(200);
      const denied = await state.broker.send({ url: owned.origin + "/private?token=private-canary", method: "GET", skipCache: true });
      expect(denied.error?.message).toBe("authorization-budget-exhausted"); expect(owned.receipts).toBe(10); expect(state.guard.snapshot().transmittedRequests).toBe(10); expect(state.ledger.snapshot().scanTransmitted).toBe(10); expect(state.audits.at(-1)?.outcome).toBe("scope-skipped"); expect(JSON.stringify(denied)).not.toContain("private");
    } finally { await state.broker.close(); await close(owned.server); }
  });
  it("does not count cached duplicates as network requests", async () => {
    const owned = await fixture(); const state = setup(owned.origin, { window: 60_000 });
    try { await state.broker.send({ url: `${owned.origin}/health`, method: "GET" }); await state.broker.send({ url: `${owned.origin}/health`, method: "GET" }); expect(owned.receipts).toBe(1); expect(state.audits.at(-1)?.outcome).toBe("duplicate-skipped"); expect(state.guard.snapshot().transmittedRequests).toBe(1); }
    finally { await state.broker.close(); await close(owned.server); }
  });
});
