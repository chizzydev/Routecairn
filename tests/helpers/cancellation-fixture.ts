import { createServer } from "node:http";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { exampleScope } from "../../src/config/defaults.js";
import type { DashboardScanCreateRequest } from "../../src/dashboard/types/DashboardTypes.js";

export async function cancellationFixture(directory: string, options: { cleanupDelayMs?: number; cleanupFails?: boolean; holdCleanup?: boolean } = {}) {
  const received: string[] = [];
  let restored = false;
  const timers: ReturnType<typeof setTimeout>[] = [];
  const server = createServer(async (request, response) => {
    const path = request.url!;
    received.push(path);
    response.setHeader("content-type", "application/json");
    if (path === "/") return void response.end("{}");
    if (path === "/exposure") return void response.end('{"visible":true}');
    if (path === "/fixture/action") return void response.end('{"refresh_token":"cancel-cleanup-secret"}');
    if (path === "/hold") return; // cancelled by the scan's attack signal
    if (path === "/fixture/cleanup") {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      if (!Buffer.concat(chunks).toString().includes("cancel-cleanup-secret")) return void response.writeHead(400).end("{}");
      if (options.holdCleanup) return;
      timers.push(setTimeout(() => {
        restored = !options.cleanupFails;
        response.writeHead(options.cleanupFails ? 500 : 204).end();
      }, options.cleanupDelayMs ?? 10));
      return;
    }
    if (path === "/state") return void response.end(JSON.stringify({ restored }));
    response.writeHead(404).end("{}");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const target = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
  await mkdir(directory, { recursive: true });
  const scopeFile = join(directory, "scope.json");
  const authenticationLifecycleFile = join(directory, "lifecycle.json");
  await writeFile(scopeFile, JSON.stringify({ ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"], rateLimitPerSecond: 50, concurrency: 2 }));
  const actor = { id: "public", safeAlias: "disposable-actor", authSlot: "anonymous", relationship: "PUBLIC", declaredState: "ANONYMOUS" };
  const step = (id: string, phase: string, path: string, method: string, status: number) => ({ id, phase, actorId: "public", request: { method, url: new URL(path, target).href, stateChanging: method === "POST" }, assertions: [{ kind: "STATUS_IN", values: [status] }] });
  const cleanup = step("restore", "CLEANUP", "/fixture/cleanup", "POST", 204);
  await writeFile(authenticationLifecycleFile, JSON.stringify({ schemaVersion: 1, cases: [
    { id: "retained-evidence", label: "Retained contradiction", category: "SESSION_REVOCATION", actors: [actor], authorization: { mode: "OBSERVE_ONLY", environment: "TEST" }, steps: [step("read", "VERIFY", "/exposure", "GET", 401)] },
    { id: "cancelled-case", label: "Cancellation restoration", category: "SESSION_REVOCATION", actors: [actor], cleanupRequired: true,
      authorization: { mode: "CONTROLLED_LIFECYCLE", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING", authorizedBy: "fixture-operator", changeTicket: "LOCAL-CANCEL", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableAccounts: true },
      steps: [{ ...step("action", "ACTION", "/fixture/action", "POST", 200), captures: [{ name: "restore", source: "JSON", path: "refresh_token" }] }, step("hold", "VERIFY", "/hold", "GET", 401), { ...cleanup, request: { ...cleanup.request, fields: { refresh_token: "{{CAPTURE:restore}}" } } }]
    }
  ] }));
  const scanRequest: DashboardScanCreateRequest = { target, scopeFile, authenticationLifecycleFile, profile: "quick", includeModules: ["authentication-lifecycle"], authorizationDeclaration: "Authorized disposable local cancellation fixture." };
  return { target, scanRequest, received, get restored() { return restored; }, close: async () => { for (const timer of timers) clearTimeout(timer); server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); } };
}
