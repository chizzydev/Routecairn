import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { request as tlsRequest } from "node:https";
import { generate } from "selfsigned";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { spawn, type ChildProcess } from "node:child_process";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildModulePayload, installModuleEnvelope, readModuleJson, signModulePayload, verifyModuleEnvelope } from "../../src/core/plugins/ModuleDistribution.js";
import { ModuleRegistry, moduleRegistryConfigSchema, moduleRegistryRequest } from "../../src/core/plugins/ModuleRegistry.js";
import { ModuleCapabilityBroker } from "../../src/core/plugins/ModuleCapabilityBroker.js";
import { SandboxedModuleHost } from "../../src/core/plugins/SandboxedModuleHost.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ThirdPartyModuleService } from "../../src/dashboard/operations/ThirdPartyModuleService.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { thirdPartyModuleBrokerBindingSchema, thirdPartyModuleManifestSchema } from "../../src/dashboard/contracts/OperationalScaleSchemas.js";
import { moduleSigningFixture, writeModuleFixture } from "../helpers/module-distribution.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";

const roots: string[] = [], registries: ModuleRegistry[] = [], servers: Server[] = [], databases: DashboardDatabase[] = [];
const children = new Set<ChildProcess>();
let pendingProof: Record<string, unknown> | undefined;
afterEach(async () => { await Promise.all([...children].map((child) => new Promise<void>((done) => { if (child.exitCode !== null || child.signalCode !== null) { done(); return; } child.once("exit", () => done()); child.kill("SIGKILL"); }))); children.clear(); for (const database of databases.splice(0)) database.close(); for (const registry of registries.splice(0)) await registry.close(); for (const server of servers.splice(0)) { server.closeAllConnections(); await new Promise<void>((done) => server.close(() => done())); } for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); if (pendingProof && process.env.ROUTECAIRN_MODULE_LAB_OUTPUT) writeFileSync(join(process.env.ROUTECAIRN_MODULE_LAB_OUTPUT, "runtime-proof.json"), JSON.stringify({ ...pendingProof, cleanup: "CONFIRMED" }, null, 2), { flag: "wx" }); pendingProof = undefined; });
const publishToken = "publication-fixture-".repeat(3), signingToken = "signing-fixture-".repeat(3);
function fixture() { const root = mkdtempSync(join(tmpdir(), "routecairn-ecosystem-")); roots.push(root); const signer = moduleSigningFixture(); const trustPath = join(root, "trust.json"); writeFileSync(trustPath, JSON.stringify(signer.trust)); return { root, signer, trustPath }; }
async function listen(server: Server) { await new Promise<void>((done) => server.listen(0, "127.0.0.1", done)); return `http://127.0.0.1:${(server.address() as AddressInfo).port}`; }
function binding(origin: string, digest: string, methods = ["GET", "HEAD"] as string[]) { const now = Date.now(); return thirdPartyModuleBrokerBindingSchema.parse({ target: origin, scope: { program: "owned-module-lab", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: methods, rateLimitPerSecond: 10, concurrency: 1, maxDepth: 0, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn-Module-Lab" }, approval: { targetOrigin: origin, packageDigest: digest, authorizedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), operator: "fixture-owner", reference: "owned-loopback-approval", confirmation: "I_AUTHORIZE_BROKERED_MODULE_REQUESTS" } }); }

describe("module ecosystem runtime", () => {
  it("runs the authoring CLI through keys, build, signing, review and digest-pinned installation", async () => {
    const f = fixture(), directory = join(f.root, "cli-source"); writeModuleFixture(directory);
    const cli = async (...args: string[]) => new Promise<string>((done, reject) => { const child = spawn(process.execPath, ["--import", "tsx", "src/cli/index.ts", "modules", ...args], { cwd: process.cwd(), windowsHide: true }); children.add(child); const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("CLI child runtime exceeded 20 seconds")); }, 20_000); let output = "", errors = ""; child.stdout.on("data", (chunk) => output += String(chunk)); child.stderr.on("data", (chunk) => errors += String(chunk)); child.once("error", (error) => { clearTimeout(timer); children.delete(child); reject(error); }); child.once("exit", (code) => { clearTimeout(timer); children.delete(child); code === 0 ? done(output) : reject(new Error(errors)); }); });
    const keyPath = join(f.root, "publisher.key"), publicPath = join(f.root, "publisher.pub"), payloadPath = join(f.root, "payload.json"), bundlePath = join(f.root, "bundle.json");
    const generated = JSON.parse(await cli("keygen", "--private-key", keyPath, "--public-key", publicPath));
    const trust = { ...f.signer.trust, publishers: [{ ...f.signer.trust.publishers[0]!, keyId: generated.keyId, publicKeyPem: readFileSync(publicPath, "utf8") }] }; writeFileSync(f.trustPath, JSON.stringify(trust));
    const built = JSON.parse(await cli("build", "--directory", directory, "--publisher", f.signer.publisher, "--expires-at", f.signer.expiresAt, "--output", payloadPath));
    await cli("sign", "--payload", payloadPath, "--private-key", keyPath, "--output", bundlePath);
    expect(JSON.parse(await cli("review", "--bundle", bundlePath, "--trust", f.trustPath))).toMatchObject({ packageDigest: built.packageDigest, packageApproval: "REQUIRED" });
    expect(JSON.parse(await cli("install", "--bundle", bundlePath, "--trust", f.trustPath, "--root", join(f.root, "installed"), "--digest", built.packageDigest))).toMatchObject({ approved: false, packageDigest: built.packageDigest });
  }, 120_000);
  it("denies raw listeners, sockets, DNS, inspector, child processes, outside files and inherited secrets", async () => {
    const f = fixture(), directory = join(f.root, "denials"); const outside = join(f.root, "outside.txt"); writeFileSync(outside, "fixture-private-value");
    const source = `import net from 'node:net'; import dns from 'node:dns'; import http from 'node:http'; import dgram from 'node:dgram'; import cp from 'node:child_process'; import fs from 'node:fs'; import inspector from 'node:inspector';
export async function analyze(){ const data={}; const check=(name, action)=>{try{action();data[name]=false;}catch(error){data[name]=error.message==='SDK_DIRECT_CAPABILITY_DENIED'||error.code==='ERR_ACCESS_DENIED';}};
check('socketDenied',()=>net.connect(1,'127.0.0.1')); check('listenerDenied',()=>net.createServer().listen(0)); check('httpDenied',()=>http.get('http://127.0.0.1/')); check('dnsDenied',()=>dns.lookup('localhost',()=>{})); check('udpDenied',()=>dgram.createSocket('udp4')); check('childDenied',()=>cp.spawn(process.execPath,['--version'])); check('inspectorDenied',()=>inspector.open(0)); check('outsideFileDenied',()=>fs.readFileSync(${JSON.stringify(outside)})); data.inheritedCanaryAbsent=process.env.ROUTECAIRN_PRIVATE_CANARY===undefined; return { observations:[{kind:'authority',summary:'Denied raw capabilities',data}],findings:[],notes:[]};}`;
    const manifest = writeModuleFixture(directory, source), previous = process.env.ROUTECAIRN_PRIVATE_CANARY; process.env.ROUTECAIRN_PRIVATE_CANARY = "fixture-private-value";
    try { const result = await new SandboxedModuleHost().execute(directory, manifest, {}); expect(result.observations[0]!.data).toEqual({ socketDenied: true, listenerDenied: true, httpDenied: true, dnsDenied: true, udpDenied: true, childDenied: true, inspectorDenied: true, outsideFileDenied: true, inheritedCanaryAbsent: true }); } finally { if (previous === undefined) delete process.env.ROUTECAIRN_PRIVATE_CANARY; else process.env.ROUTECAIRN_PRIVATE_CANARY = previous; }
  });
  it("operates signed registration, review, execution and disable through authenticated dashboard APIs", async () => {
    const f = fixture(), paths = resolveDashboardPaths(join(f.root, "dashboard")); mkdirSync(paths.thirdPartyModulesDir, { recursive: true });
    const previous = process.env.ROUTECAIRN_MODULE_TRUST_PATH, previousStrict = process.env.ROUTECAIRN_REQUIRE_SIGNED_MODULES;
    process.env.ROUTECAIRN_MODULE_TRUST_PATH = f.trustPath; process.env.ROUTECAIRN_REQUIRE_SIGNED_MODULES = "true";
    const dashboard = await startDashboardServer({ dataDir: paths.dataDir, uiDistDir: join(f.root, "ui") });
    try {
      const token = new URL(dashboard.bootstrapUrl!).hash.replace("#bootstrap=", ""); const session = await fetch(`${dashboard.url}/api/session/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) }); const { csrfToken } = await session.json() as { csrfToken: string }; const cookie = session.headers.get("set-cookie")!.split(";")[0]!;
      const headers = { cookie, origin: dashboard.url, "x-csrf-token": csrfToken, "content-type": "application/json" };
      const organizations = await fetch(`${dashboard.url}/api/operations/organizations`, { headers: { cookie } }).then((response) => response.json()) as { organizations: Array<{ id: string }> }; const organizationId = organizations.organizations[0]!.id;
      const directory = join(paths.thirdPartyModulesDir, "fixture"); writeModuleFixture(directory); const bundlePath = join(paths.thirdPartyModulesDir, "bundle.json"); writeFileSync(bundlePath, JSON.stringify(signModulePayload(buildModulePayload(directory, f.signer.publisher, f.signer.expiresAt), f.signer.privateKeyPem)));
      const post = (path: string, body: unknown) => fetch(`${dashboard.url}${path}`, { method: "POST", headers, body: JSON.stringify(body) });
      const registered = await post("/api/operations/modules", { organizationId, packageDirectory: directory, bundlePath }); expect(registered.status).toBe(201); const { moduleId } = await registered.json() as { moduleId: string };
      expect((await post(`/api/operations/modules/${moduleId}/execute`, { input: {} })).ok).toBe(false);
      expect((await post(`/api/operations/modules/${moduleId}/approve`, {})).status).toBe(200);
      const executed = await post(`/api/operations/modules/${moduleId}/execute`, { input: {} }); expect(executed.status).toBe(200); expect(await executed.json()).toMatchObject({ result: { observations: [], capabilitySummary: { enabled: false } } });
      const listed = await fetch(`${dashboard.url}/api/operations/modules?organizationId=${organizationId}`, { headers: { cookie } }).then((response) => response.json()) as { modules: Array<{ signature: { signed: boolean; publisher: string } }> }; expect(listed.modules[0]!.signature).toMatchObject({ signed: true, publisher: f.signer.publisher });
      expect((await post(`/api/operations/modules/${moduleId}/disable`, {})).status).toBe(200); expect((await post(`/api/operations/modules/${moduleId}/execute`, { input: {} })).ok).toBe(false);
    } finally { await dashboard.close(); if (previous === undefined) delete process.env.ROUTECAIRN_MODULE_TRUST_PATH; else process.env.ROUTECAIRN_MODULE_TRUST_PATH = previous; if (previousStrict === undefined) delete process.env.ROUTECAIRN_REQUIRE_SIGNED_MODULES; else process.env.ROUTECAIRN_REQUIRE_SIGNED_MODULES = previousStrict; }
  });
  it("serves native HTTPS and requires a trusted certificate", async () => {
    const f = fixture(); const certificate = await generate([{ name: "commonName", value: "localhost" }], { keySize: 2048, days: 1, extensions: [{ name: "basicConstraints", cA: true }, { name: "keyUsage", digitalSignature: true, keyCertSign: true, keyEncipherment: true }, { name: "subjectAltName", altNames: [{ type: 7, ip: "127.0.0.1" }] }] });
    const registry = new ModuleRegistry({ directory: join(f.root, "tls-registry"), trustPath: f.trustPath, publishToken, tls: { cert: certificate.cert, key: certificate.private, minVersion: "TLSv1.2" } }); registries.push(registry); const origin = (await listen(registry.server)).replace("http:", "https:");
    const result = await new Promise<{ status: number; data: string }>((done, reject) => { const request = tlsRequest(`${origin}/v1/index`, { ca: certificate.cert }, (response) => { let data = ""; response.on("data", (chunk) => data += String(chunk)); response.on("end", () => done({ status: response.statusCode!, data })); }); request.on("error", reject); request.end(); });
    expect(result.status).toBe(200); expect(JSON.parse(result.data)).toEqual({ schemaVersion: 1, packages: [] });
    await expect(moduleRegistryRequest(origin, "/v1/index")).rejects.toThrow();
  });
  it("executes all signed reference packs through registry, installation, separate review and bounded broker requests", async () => {
    const f = fixture(); const paths = resolveDashboardPaths(join(f.root, "dashboard")); mkdirSync(paths.thirdPartyModulesDir, { recursive: true });
    const database = new DashboardDatabase(paths.databasePath); database.migrate(); databases.push(database);
    const organizationId = (database.db.prepare("SELECT value FROM dashboard_meta WHERE key='default_organization_id'").get() as { value: string }).value;
    const packages = ["security-headers", "framework-fingerprint", "graphql-response"].map((name) => ({ name, payload: buildModulePayload(join(process.cwd(), "examples/modules", name), f.signer.publisher, f.signer.expiresAt) }));
    const registry = new ModuleRegistry({ directory: join(f.root, "registry"), trustPath: f.trustPath, publishToken, signing: { token: signingToken, privateKeyPem: f.signer.privateKeyPem, publisher: f.signer.publisher, approvedDigests: packages.map(({ payload }) => payload.packageDigest) } }); registries.push(registry); const registryOrigin = await listen(registry.server);
    let transmitted = 0;
    const target = createServer((request, response) => { transmitted++; if (request.url?.startsWith("/graphql")) { response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ data: { __typename: "Query" }, token: "fixture-private-value" })); return; } response.writeHead(200, { "x-powered-by": "FixtureFramework", "content-type": "text/html", "set-cookie": "session=fixture-private-value" }).end("<html>owned fixture</html>"); }); servers.push(target); const targetOrigin = await listen(target);
    let service = new ThirdPartyModuleService(database, paths, f.trustPath, true); const runtime = [];
    for (const { name, payload } of packages) {
      const signed = await moduleRegistryRequest(registryOrigin, "/v1/sign", payload, signingToken);
      expect(verifyModuleEnvelope(signed, f.signer.trust)).toEqual(payload);
      await moduleRegistryRequest(registryOrigin, "/v1/publish", signed, publishToken);
      const bundle = await moduleRegistryRequest(registryOrigin, `/v1/packages/${payload.moduleId}/${payload.version}/${payload.packageDigest}`);
      const installed = installModuleEnvelope(bundle, f.signer.trust, paths.thirdPartyModulesDir);
      const bundlePath = join(paths.thirdPartyModulesDir, `${name}.bundle.json`); writeFileSync(bundlePath, JSON.stringify(bundle));
      const id = service.register(organizationId, installed.directory, "fixture-installer", bundlePath);
      await expect(service.execute(id, {})).rejects.toThrow("SDK_MODULE_NOT_APPROVED"); service.approve(id, "fixture-reviewer");
      const result = await service.execute(id, {}, binding(targetOrigin, payload.packageDigest)) as { observations: unknown[]; findings: unknown[]; capabilitySummary: { transmittedRequests: number } };
      expect(result.capabilitySummary.transmittedRequests).toBe(1); expect(result.observations).toHaveLength(1); expect(JSON.stringify(result)).not.toContain("fixture-private-value");
      if (name === "security-headers") expect(result.findings).toHaveLength(1);
      runtime.push({ moduleId: payload.moduleId, packageDigest: payload.packageDigest, transmittedRequests: 1, observations: result.observations.length, findings: result.findings.length, separatelyApproved: true });
    }
    expect(transmitted).toBe(3);
    const index = await moduleRegistryRequest(registryOrigin, "/v1/index") as { packages: unknown[] }; expect(index.packages).toHaveLength(3);
    expect(readFileSync(join(f.root, "registry/audit.jsonl"), "utf8")).not.toMatch(/fixture-private-value|publication-fixture|signing-fixture|PRIVATE KEY/);
    expect(() => service.register(organizationId, join(process.cwd(), "examples/modules/security-headers"), "fixture-owner")).toThrow("SDK_PACKAGE_OUTSIDE_MODULE_ROOT");
    const id = (service.list(organizationId)[0] as { id: string }).id;
    databases.splice(databases.indexOf(database), 1); database.close();
    const reopened = new DashboardDatabase(paths.databasePath); reopened.migrate(); databases.push(reopened); service = new ThirdPartyModuleService(reopened, paths, f.trustPath, true);
    writeFileSync(f.trustPath, JSON.stringify({ ...f.signer.trust, revokedKeyIds: [f.signer.trust.publishers[0]!.keyId] }));
    await expect(service.execute(id, {})).rejects.toThrow("MODULE_KEY_UNTRUSTED_OR_REVOKED"); expect(service.list(organizationId)).toContainEqual(expect.objectContaining({ id, status: "QUARANTINED" }));
    const revoked = await moduleRegistryRequest(registryOrigin, "/v1/index") as { packages: unknown[] }; expect(revoked.packages).toHaveLength(0); expect(transmitted).toBe(3);
    pendingProof = { schemaVersion: 1, status: "VERIFIED", provenance: "SELF_MAINTAINED_LOOPBACK", publicDeployment: false, independentlyOperated: false, communityAdoption: false, isolation: process.env.ROUTECAIRN_MODULE_CONTAINER_IMAGE ? "NETWORK_ISOLATED_CONTAINER" : "REVIEWED_PROCESS", runtime, checks: ["authenticated-signing", "digest-review-policy", "publisher-namespace", "immutable-publication", "anonymous-discovery", "signed-download", "safe-installation", "separate-package-approval", "target-digest-approval", "bounded-broker", "response-redaction", "database-reopen", "revocation-quarantine", "revoked-registry-filter", "secret-free-audit"] };
  });
  it("rejects unauthorized signing, unreviewed digest, token role confusion and immutable replacement", async () => {
    const f = fixture(); const directory = join(f.root, "package"); writeModuleFixture(directory); const payload = buildModulePayload(directory, f.signer.publisher, f.signer.expiresAt);
    const registry = new ModuleRegistry({ directory: join(f.root, "registry"), trustPath: f.trustPath, publishToken, signing: { token: signingToken, privateKeyPem: f.signer.privateKeyPem, publisher: f.signer.publisher, approvedDigests: ["0".repeat(64)] } }); registries.push(registry); const origin = await listen(registry.server);
    await expect(moduleRegistryRequest(origin, "/v1/sign", payload, publishToken)).rejects.toThrow("MODULE_REGISTRY_HTTP_401");
    await expect(moduleRegistryRequest(origin, "/v1/sign", payload, signingToken)).rejects.toThrow("MODULE_REGISTRY_HTTP_400");
    const envelope = signModulePayload(payload, f.signer.privateKeyPem);
    await expect(moduleRegistryRequest(origin, "/v1/publish", envelope, signingToken)).rejects.toThrow("MODULE_REGISTRY_HTTP_401");
    await moduleRegistryRequest(origin, "/v1/publish", envelope, publishToken);
    await expect(moduleRegistryRequest(origin, "/v1/publish", envelope, publishToken)).rejects.toThrow("MODULE_REGISTRY_HTTP_409");
    await expect(moduleRegistryRequest(origin, `/v1/packages/${payload.moduleId}/${payload.version}/${"0".repeat(64)}`)).rejects.toThrow("MODULE_REGISTRY_HTTP_400");
    expect(() => new ModuleRegistry({ directory: join(f.root, "other"), trustPath: f.trustPath, publishToken, signing: { token: publishToken, privateKeyPem: f.signer.privateKeyPem, publisher: f.signer.publisher, approvedDigests: [payload.packageDigest] } })).toThrow("DISTINCT_TOKENS");
    expect(() => moduleRegistryConfigSchema.parse({ directory: "store", trustPath: "trust.json", host: "0.0.0.0", publishTokenEnv: "PUBLISH_TOKEN" })).toThrow(/TLS/);
  });
  it("bounds registry storage and rejects compressed or oversize publication bodies", async () => {
    const f = fixture(); const directory = join(f.root, "package"); writeModuleFixture(directory); const envelope = signModulePayload(buildModulePayload(directory, f.signer.publisher, f.signer.expiresAt), f.signer.privateKeyPem);
    const registry = new ModuleRegistry({ directory: join(f.root, "registry"), trustPath: f.trustPath, publishToken, maxStoredBytes: 100 }); registries.push(registry); const origin = await listen(registry.server);
    await expect(moduleRegistryRequest(origin, "/v1/publish", envelope, publishToken)).rejects.toThrow("MODULE_REGISTRY_HTTP_400");
    const response = await fetch(`${origin}/v1/publish`, { method: "POST", headers: { "content-type": "application/json", "content-encoding": "gzip", authorization: `Bearer ${publishToken}` }, body: "{}" }); expect(response.status).toBe(400);
  });
  it("fails before publication when the audit retention ceiling is reached", async () => {
    const f = fixture(), directory = join(f.root, "audit-source"); writeModuleFixture(directory); const envelope = signModulePayload(buildModulePayload(directory, f.signer.publisher, f.signer.expiresAt), f.signer.privateKeyPem);
    const registry = new ModuleRegistry({ directory: join(f.root, "registry"), trustPath: f.trustPath, publishToken }); registries.push(registry); const origin = await listen(registry.server); writeFileSync(join(f.root, "registry/audit.jsonl"), Buffer.alloc(4 * 1024 * 1024));
    await expect(moduleRegistryRequest(origin, "/v1/publish", envelope, publishToken)).rejects.toThrow("MODULE_REGISTRY_HTTP_400");
    expect(await moduleRegistryRequest(origin, "/v1/index")).toEqual({ schemaVersion: 1, packages: [] });
  });
  it("limits broker approvals to the exact origin, canonical paths and active lifetime", async () => {
    const f = fixture(); const directory = join(f.root, "source"); cpSync(join(process.cwd(), "examples/modules/graphql-response"), directory, { recursive: true }); const manifest = thirdPartyModuleManifestSchema.parse(readModuleJson(join(directory, "routecairn.module.json"))); const digest = new SandboxedModuleHost().validatePackage(directory, manifest).digest;
    const approved = binding("http://127.0.0.1:9999", digest); approved.scope.sameOriginOnly = false;
    const broker = new ModuleCapabilityBroker({ ...manifest.capabilities.requestBroker!, maxRequests: 4 }, approved, digest);
    try {
      expect(await broker.execute({ url: "http://127.0.0.1:8888/graphql", purpose: "origin control" })).toMatchObject({ outcome: "POLICY_BLOCKED", errorCode: "SDK_BROKER_APPROVAL_ORIGIN_MISMATCH" });
      expect(await broker.execute({ url: "/graphql/%2fadmin", purpose: "encoded path control" })).toMatchObject({ outcome: "POLICY_BLOCKED", errorCode: "SDK_BROKER_PATH_NOT_CANONICAL" });
      broker.cancel(); expect(await broker.execute({ url: "/graphql", purpose: "cancel control" })).toMatchObject({ outcome: "POLICY_BLOCKED", errorCode: "SDK_BROKER_CANCELLED" }); expect(broker.summary().transmittedRequests).toBe(0);
    } finally { await broker.close(); }
  });
  it("expires approval while requests wait for the rate limiter", async () => {
    const f = fixture(), directory = join(f.root, "queued"); cpSync(join(process.cwd(), "examples/modules/graphql-response"), directory, { recursive: true }); const manifest = thirdPartyModuleManifestSchema.parse(readModuleJson(join(directory, "routecairn.module.json"))); const digest = new SandboxedModuleHost().validatePackage(directory, manifest).digest;
    let transmitted = 0; const target = createServer((_request, response) => { transmitted++; response.writeHead(200).end("fixture"); }); servers.push(target); const origin = await listen(target), approval = binding(origin, digest, ["GET"]); approval.scope.rateLimitPerSecond = 1; approval.approval.expiresAt = new Date(Date.now() + 500).toISOString();
    const broker = new ModuleCapabilityBroker({ ...manifest.capabilities.requestBroker!, maxRequests: 2 }, approval, digest);
    try { const results = await Promise.all([broker.execute({ url: "/graphql", purpose: "first bounded request" }), broker.execute({ url: "/graphql", purpose: "queued request expires" })]); expect(results[1]).toMatchObject({ outcome: "INCONCLUSIVE", errorCode: "SDK_BROKER_CANCELLED" }); expect(transmitted).toBe(1); expect(broker.summary().transmittedRequests).toBe(1); } finally { await broker.close(); }
  });
  it("rejects package edits after approval and does not allow unsigned imports under strict policy", async () => {
    const f = fixture(), paths = resolveDashboardPaths(join(f.root, "dashboard")); mkdirSync(paths.thirdPartyModulesDir, { recursive: true }); const database = new DashboardDatabase(paths.databasePath); database.migrate(); databases.push(database);
    const service = new ThirdPartyModuleService(database, paths, f.trustPath, true), organizationId = (database.db.prepare("SELECT value FROM dashboard_meta WHERE key='default_organization_id'").get() as { value: string }).value;
    const directory = join(paths.thirdPartyModulesDir, "fixture"); writeModuleFixture(directory); expect(() => service.register(organizationId, directory, "owner")).toThrow("MODULE_SIGNATURE_REQUIRED");
    const envelope = signModulePayload(buildModulePayload(directory, f.signer.publisher, f.signer.expiresAt), f.signer.privateKeyPem), bundlePath = join(paths.thirdPartyModulesDir, "fixture.bundle.json"); writeFileSync(bundlePath, JSON.stringify(envelope)); const id = service.register(organizationId, directory, "owner", bundlePath); service.approve(id, "reviewer");
    writeFileSync(join(directory, "index.mjs"), "export async function analyze(){ throw new Error('changed'); }"); await expect(service.execute(id, {})).rejects.toThrow("SDK_PACKAGE_DIGEST_CHANGED"); expect(service.list(organizationId)).toContainEqual(expect.objectContaining({ id, status: "QUARANTINED" }));
  });
});
