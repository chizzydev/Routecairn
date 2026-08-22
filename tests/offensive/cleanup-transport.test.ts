import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ControlledMutationExecutor } from "../../src/core/offensive/ControlledMutationExecutor.js";
import type { HttpRequest, HttpResponse } from "../../src/core/http/HttpTypes.js";
import type { MutationTransport } from "../../src/core/offensive/ControlledMutationTypes.js";
import { controlledMutationContractSchema } from "../../src/core/offensive/ControlledMutationTypes.js";

describe("mutation cleanup transport", () => {
  it("uses the dedicated cleanup transport after the attack transport aborts", async () => {
    const cleanupRequests: HttpRequest[] = [];
    const attack: MutationTransport = { send: async (request) => { if (request.method !== "GET") throw new Error("scan abort"); return response(request, { id: "target", role: "user" }); } };
    const cleanup: MutationTransport = { send: async (request) => { cleanupRequests.push(request); return response(request, request.method === "GET" ? { id: "target", role: "user" } : { accepted: true }); } };
    const result = await new ControlledMutationExecutor(attack, { journalDirectory: await tempDirectory(), cleanupTransport: cleanup, sleep: async () => undefined }).execute(contract());
    expect(result.cleanupOutcome).toBe("ROLLBACK_VERIFIED");
    expect(cleanupRequests.some((request) => request.method !== "GET")).toBe(true);
  });
});

function contract() {
  return controlledMutationContractSchema.parse({
    schemaVersion: 1, caseId: "cleanup-case", targetOrigin: "https://example.test", mode: "CONTROLLED_MUTATION", environment: "STAGING", productionAcknowledged: false,
    authorization: { authorizedBy: "owner", changeTicket: "SEC-2", confirmation: "I_CONFIRM_EXPLICIT_AUTHORIZATION_AND_CLEANUP_DUTY", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z" },
    target: { disposable: true, type: "user", alias: "target", identityFingerprint: createHash("sha256").update(JSON.stringify("target")).digest("hex"), identityAssertion: { path: "id", operator: "EQUALS", expectedValue: "target" } },
    attack: { request: { url: "https://example.test/user/target", method: "PATCH", body: "{\"role\":\"admin\"}" }, allowedFields: ["role"], allowedValues: { role: ["admin"] }, semanticEffect: "UPDATE_EXISTING" },
    precondition: { request: { url: "https://example.test/user/target", method: "GET" }, assertions: [{ path: "id", operator: "EQUALS", expectedValue: "target" }, { path: "role", operator: "EQUALS", expectedValue: "user" }], attempts: 1, delayMs: 0 },
    impact: { request: { url: "https://example.test/user/target", method: "GET" }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "admin" }], attempts: 1, delayMs: 0 },
    rollback: { request: { url: "https://example.test/user/target", method: "PATCH", body: "{\"role\":\"user\"}" }, verification: { request: { url: "https://example.test/user/target", method: "GET" }, assertions: [{ path: "role", operator: "EQUALS", expectedValue: "user" }], attempts: 1, delayMs: 0 } }
  });
}
function response(request: HttpRequest, body: unknown): HttpResponse { const serialized = JSON.stringify(body); return { requestedUrl: request.url, finalUrl: request.url, method: request.method, statusCode: 200, headers: { "content-type": "application/json" }, contentType: "application/json", contentLength: serialized.length, bodyPreview: serialized, bodyHash: "c".repeat(64), responseTimeMs: 1, redirectChain: [] }; }
async function tempDirectory(): Promise<string> { return mkdtemp(join(tmpdir(), "routecairn-cleanup-")); }
