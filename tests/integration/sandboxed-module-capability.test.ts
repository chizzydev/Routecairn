import { createServer, type Server } from "node:http";
import { createHash } from "node:crypto";
import type { AddressInfo } from "node:net";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SandboxedModuleHost } from "../../src/core/plugins/SandboxedModuleHost.js";
import { thirdPartyModuleBrokerBindingSchema, thirdPartyModuleManifestSchema } from "../../src/dashboard/contracts/OperationalScaleSchemas.js";

const directories: string[] = [];
let server: Server | undefined;
afterEach(async () => { if (server) await new Promise<void>((resolve) => server!.close(() => resolve())); server = undefined; await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("sandboxed module capability broker", () => {
  it("mediates declared proposals through scope, DNS, budgets, and redacted responses", async () => {
    let transmitted = 0;
    server = createServer(async (request, response) => {
      transmitted += 1;
      if (request.url?.startsWith("/fixture")) { response.setHeader("content-type", "application/json"); response.setHeader("set-cookie", "session=private"); response.end(JSON.stringify({ token: "private-value", framework: "nextjs" })); return; }
      if (request.url === "/inspect" && request.method === "POST") { let body = ""; for await (const chunk of request) body += String(chunk); response.setHeader("content-type", "application/json"); response.end(JSON.stringify({ accepted: body === '{"probe":true}' })); return; }
      response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const directory = await modulePackage(`
export async function analyze(_input, sdk) {
  let directDenied = false; try { await fetch(${JSON.stringify(origin)} + "/fixture"); } catch { directDenied = true; }
  const read = await sdk.request({ url: "/fixture?token=module-canary", method: "GET", purpose: "framework signature" });
  const post = await sdk.capabilities.request({ url: "/inspect", method: "POST", headers: { "content-type": "application/json" }, body: '{"probe":true}', nonMutating: true, purpose: "read-only parser adapter" });
  const blockedPost = await sdk.request({ url: "/inspect", method: "POST", headers: { "content-type": "application/json" }, body: '{"probe":false}', nonMutating: true, purpose: "unapproved body" });
  const blockedPath = await sdk.request({ url: "/admin", method: "GET", purpose: "undeclared path" });
  const blockedHeader = await sdk.request({ url: "/fixture", method: "GET", headers: { authorization: "Bearer fabricated" }, purpose: "forbidden credential header" });
  return { observations: [{ kind: "broker", summary: "mediated", data: { directDenied, readStatus: read.statusCode, preview: read.bodyPreview, safeUrl: read.safeUrl, postStatus: post.statusCode, blockedPost: blockedPost.errorCode, blockedPath: blockedPath.errorCode, blockedHeader: blockedHeader.errorCode } }], findings: [], notes: [] };
}`);
    const host = new SandboxedModuleHost(); const manifest = manifestValue(); const digest = host.validatePackage(directory, manifest).digest; const now = Date.now();
    const binding = thirdPartyModuleBrokerBindingSchema.parse({ target: origin, scope: { program: "module-test", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "POST"], rateLimitPerSecond: 10, concurrency: 2, maxDepth: 0, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn-Module-Test" }, approval: { targetOrigin: origin, packageDigest: digest, authorizedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), operator: "test-operator", reference: "test-approval", nonMutatingPosts: [{ path: "/inspect", bodySha256: createHash("sha256").update('{"probe":true}').digest("hex"), headersSha256: createHash("sha256").update(JSON.stringify([["content-type", "application/json"]])).digest("hex") }], confirmation: "I_AUTHORIZE_BROKERED_MODULE_REQUESTS" } });
    const result = await host.execute(directory, manifest, {}, binding);
    expect(transmitted).toBe(2);
    expect(result.capabilitySummary).toMatchObject({ enabled: true, riskClass: "MODERATE", proposedRequests: 5, transmittedRequests: 2, policyBlockedRequests: 3, budgetBlockedRequests: 0, maxRequests: 5 });
    expect(result.capabilitySummary.auditDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(result.observations[0]?.data).toMatchObject({ directDenied: true, readStatus: 200, postStatus: 200, blockedPost: "SDK_BROKER_POST_APPROVAL_MISMATCH", blockedPath: "SDK_BROKER_PATH_NOT_DECLARED", blockedHeader: "SDK_BROKER_HEADER_FORBIDDEN" });
    expect(String(result.observations[0]?.data.preview)).toContain("<redacted>");
    expect(String(result.observations[0]?.data.preview)).not.toContain("private-value");
    expect(String(result.observations[0]?.data.safeUrl)).toContain("token=%3Credacted%3E");
  });

  it("binds broker approval to the exact package digest and active target origin", async () => {
    const directory = await modulePackage("export async function analyze(){ return { observations: [], findings: [], notes: [] }; }"); const host = new SandboxedModuleHost(); const manifest = manifestValue(); const now = Date.now();
    const binding = thirdPartyModuleBrokerBindingSchema.parse({ target: "https://app.example.test", scope: { program: "module-test", allowedDomains: ["app.example.test"], disallowedPaths: [], allowedMethods: ["GET", "POST"], rateLimitPerSecond: 1, concurrency: 1, maxDepth: 0, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn-Module-Test" }, approval: { targetOrigin: "https://app.example.test", packageDigest: "0".repeat(64), authorizedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), operator: "test-operator", reference: "test-approval", confirmation: "I_AUTHORIZE_BROKERED_MODULE_REQUESTS" } });
    await expect(host.execute(directory, manifest, {}, binding)).rejects.toThrow("SDK_BROKER_APPROVAL_DIGEST_MISMATCH");
  });

  it("rejects undeclared moderate actions and long-lived execution approvals", () => {
    expect(() => thirdPartyModuleManifestSchema.parse({ ...manifestValue(), capabilities: { requestBroker: { ...manifestValue().capabilities.requestBroker!, riskClass: "LOW" } } })).toThrow(/MODERATE/);
    const now = Date.now(); expect(() => thirdPartyModuleBrokerBindingSchema.parse({ target: "https://app.example.test", scope: { program: "module-test", allowedDomains: ["app.example.test"] }, approval: { targetOrigin: "https://app.example.test", packageDigest: "a".repeat(64), authorizedAt: new Date(now).toISOString(), expiresAt: new Date(now + 2 * 60 * 60 * 1000).toISOString(), operator: "operator", reference: "approval", confirmation: "I_AUTHORIZE_BROKERED_MODULE_REQUESTS" } })).toThrow(/one hour/i);
  });
});

async function modulePackage(source: string): Promise<string> { const directory = await mkdtemp(join(tmpdir(), "routecairn-module-rpc-")); directories.push(directory); await mkdir(directory, { recursive: true }); await writeFile(join(directory, "routecairn.module.json"), JSON.stringify(manifestValue()), "utf8"); await writeFile(join(directory, "index.mjs"), `${source.trim()}\n`, "utf8"); return directory; }
function manifestValue() { return thirdPartyModuleManifestSchema.parse({ schemaVersion: 1, moduleId: "capability-module", version: "1.0.0", entrypoint: "index.mjs", description: "Capability broker fixture", permissions: { network: false, childProcess: false, filesystem: "PACKAGE_READ_ONLY", maxRuntimeMs: 10000, maxMemoryMb: 32 }, capabilities: { requestBroker: { maxRequests: 5, riskClass: "MODERATE", methods: ["GET", "POST"], pathPrefixes: ["/fixture", "/inspect"], allowNonMutatingPost: true, maxRequestBytes: 4096, maxResponseBytes: 65536, bodyPreviewBytes: 4096, timeoutMs: 3000, concurrency: 2 } }, inputSchema: { type: "object", additionalProperties: false }, outputLimit: 10 }); }
