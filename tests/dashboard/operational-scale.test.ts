import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { OrganizationService } from "../../src/dashboard/operations/OrganizationService.js";
import { RemoteWorkerService } from "../../src/dashboard/operations/RemoteWorkerService.js";
import { CloudSyncService } from "../../src/dashboard/operations/CloudSyncService.js";
import { BackupRestoreService } from "../../src/dashboard/operations/BackupRestoreService.js";
import { ThirdPartyModuleService } from "../../src/dashboard/operations/ThirdPartyModuleService.js";
import { NotificationService } from "../../src/dashboard/operations/NotificationService.js";
import { writePdfProofPack } from "../../src/dashboard/proofPacks/PdfProofPackWriter.js";
import { IntegrationExportService } from "../../src/dashboard/operations/IntegrationExportService.js";
import { ScanRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { FindingFingerprintService } from "../../src/dashboard/findings/FindingFingerprintService.js";
import { FindingNormalizer } from "../../src/dashboard/findings/FindingNormalizer.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("operational scale services", () => {
  it("creates the default organization and enforces organization roles and final-owner safety", () => {
    const { database } = fixture();
    const organizations = new OrganizationService(database);
    const ownerId = createUser(database, "owner@example.test", "OWNER");
    const analystId = createUser(database, "analyst@example.test", "ANALYST");
    database.migrate();

    const defaultId = organizations.defaultOrganizationId();
    expect(organizations.list(ownerId)).toEqual(expect.arrayContaining([expect.objectContaining({ id: defaultId, role: "OWNER" })]));
    organizations.setMember(defaultId, { userId: analystId, role: "ADMIN" }, ownerId);
    expect(organizations.require(defaultId, analystId, "workers.manage")).toBe("ADMIN");
    organizations.removeMember(defaultId, analystId, ownerId);
    expect(() => organizations.setMember(defaultId, { userId: ownerId, role: "ADMIN" }, ownerId)).toThrow("ORGANIZATION_FINAL_OWNER_REQUIRED");
    expect(() => organizations.removeMember(defaultId, ownerId, ownerId)).toThrow("ORGANIZATION_FINAL_OWNER_REQUIRED");
    database.close();
  });

  it("enrolls an Ed25519 worker once, rejects signed replay, and completes a capability-bound job", () => {
    const { database } = fixture(); const service = new RemoteWorkerService(database); const organizationId = defaultOrganization(database);
    const enrollment = service.createEnrollment({ organizationId, expiresInMinutes: 60 }, "operator");
    const keys = generateKeyPairSync("ed25519");
    const publicKeyPem = keys.publicKey.export({ format: "pem", type: "spki" }).toString();
    const worker = service.enroll({ token: enrollment.token, name: "worker-1", publicKeyPem, capabilities: ["ping"], labels: { region: "test" } });
    expect(() => service.enroll({ token: enrollment.token, name: "worker-2", publicKeyPem, capabilities: ["ping"], labels: {} })).toThrow("REMOTE_ENROLLMENT_REJECTED");

    const path = "/api/remote-agents/worker/heartbeat"; const body = { status: "ONLINE", resources: { cpuPercent: 1, memoryBytes: 2, activeJobs: 0 } };
    const headers = signedHeaders(worker.workerId, keys.privateKey.export({ format: "pem", type: "pkcs8" }).toString(), path, body);
    expect(service.authenticate("POST", path, body, headers).id).toBe(worker.workerId);
    expect(() => service.authenticate("POST", path, body, headers)).toThrow("REMOTE_WORKER_REPLAY_REJECTED");

    const jobId = service.enqueue({ organizationId, kind: "PING", payload: { message: "health" }, requiredCapabilities: ["ping"], priority: 5, maxAttempts: 2 }, "operator");
    const workerRow = database.db.prepare("SELECT * FROM remote_workers WHERE id=?").get(worker.workerId) as Parameters<RemoteWorkerService["claim"]>[0];
    const claimed = service.claim(workerRow) as { job: { id: string; leaseToken: string } };
    expect(claimed.job.id).toBe(jobId);
    expect(service.renew(workerRow,jobId,claimed.job.leaseToken).leaseExpiresAt).toBeTruthy();
    service.complete(workerRow, jobId, { leaseToken: claimed.job.leaseToken, status: "COMPLETED", result: { pong: true } });
    expect(service.list(organizationId)).toEqual(expect.objectContaining({ jobs: [expect.objectContaining({ status: "COMPLETED" })] }));
    database.close();
  });

  it("signs, verifies, and deduplicates cloud synchronization batches", () => {
    const { database } = fixture(); const organizationId = defaultOrganization(database); const service = new CloudSyncService(database);
    const env = `ROUTECAIRN_TEST_SYNC_${randomUUID().replaceAll("-", "_")}`; process.env[env] = "x".repeat(48);
    try {
      const peerId = service.createPeer({ organizationId, name: "peer-a", endpoint: "https://sync.example.test", sharedSecretEnv: env, enabled: true }, "operator");
      service.record(organizationId, "finding", "finding-1", "UPSERT", { title: "Safe event" });
      const batch = service.batch(peerId);
      const body = { organizationId, cursor: batch.cursor, events: batch.events } as Parameters<CloudSyncService["receive"]>[1];
      expect(service.receive(peerId, body, batch.signature)).toEqual({ accepted: 0, cursor: batch.cursor });
      expect(service.receive(peerId, body, batch.signature)).toEqual({ accepted: 0, cursor: batch.cursor });
      expect(() => service.receive(peerId, { ...body, cursor: body.cursor + 1 }, batch.signature)).toThrow("CLOUD_SYNC_AUTH_REJECTED");
    } finally { delete process.env[env]; database.close(); }
  });

  it("creates, verifies, stages, and atomically applies an encrypted backup", async () => {
    const { database, paths } = fixture(); const key = { bytes: randomBytes(32), version: "test-key" };
    database.db.prepare("INSERT INTO dashboard_meta (key,value,updated_at) VALUES ('backup_sentinel','before',?)").run(new Date().toISOString());
    const service = new BackupRestoreService(database, paths, key);
    const id = await service.create(true, "operator");
    expect(service.verify(id)).toEqual(expect.objectContaining({ valid: true, encrypted: true }));
    database.db.prepare("UPDATE dashboard_meta SET value='after' WHERE key='backup_sentinel'").run();
    service.stageRestore(id); database.close();

    expect(BackupRestoreService.applyStagedRestore(paths, key)).toBe(true);
    const restored = new DashboardDatabase(paths.databasePath);
    expect((restored.db.prepare("SELECT value FROM dashboard_meta WHERE key='backup_sentinel'").get() as { value: string }).value).toBe("before");
    expect((restored.db.prepare("SELECT status FROM operational_backups WHERE id=?").get(id) as {status:string}).status).toBe("VERIFIED");
    restored.close();
  });

  it("runs only approved immutable third-party packages and validates declared input", async () => {
    const { database, paths } = fixture(); const organizationId = defaultOrganization(database); const packageDirectory = join(paths.thirdPartyModulesDir, "sample"); mkdirSync(packageDirectory, { recursive: true });
    writeFileSync(join(packageDirectory, "routecairn.module.json"), JSON.stringify({ schemaVersion: 1, moduleId: "sample-module", version: "1.0.0", entrypoint: "index.mjs", description: "test", permissions: { network: false, childProcess: false, filesystem: "PACKAGE_READ_ONLY", maxRuntimeMs: 5000, maxMemoryMb: 32 }, inputSchema: { type: "object", properties: { label: { type: "string", minLength: 1 } }, required: ["label"], additionalProperties: false }, outputLimit: 10 }));
    writeFileSync(join(packageDirectory, "index.mjs"), "export async function analyze(input, sdk) { return { observations: [{ kind: 'sample', summary: input.label, data: { digest: await sdk.hash(input.label) } }], findings: [], notes: [] }; }\n");
    const service = new ThirdPartyModuleService(database, paths); const id = service.register(organizationId, packageDirectory, "operator");
    await expect(service.execute(id, { label: "hello" })).rejects.toThrow("SDK_MODULE_NOT_APPROVED");
    service.approve(id, "reviewer");
    await expect(service.execute(id, {})).rejects.toThrow("SDK_INPUT_SCHEMA_MISMATCH");
    await expect(service.execute(id, { label: "hello" })).resolves.toEqual(expect.objectContaining({ observations: [expect.objectContaining({ summary: "hello" })] }));
    writeFileSync(join(packageDirectory, "index.mjs"), "export async function analyze() { return { observations: [], findings: [], notes: ['changed'] }; }\n");
    await expect(service.execute(id, { label: "hello" })).rejects.toThrow("SDK_PACKAGE_DIGEST_CHANGED");
    expect(service.list(organizationId)).toEqual([expect.objectContaining({ status: "QUARANTINED" })]);
    database.close();
  });

  it("keeps notification idempotency stable and emits scriptless PDF proof bytes", async () => {
    const { database } = fixture(); const organizationId = defaultOrganization(database); const notifications = new NotificationService(database);
    const channel = notifications.create({ organizationId, name: "audit", kind: "WEBHOOK", endpoint: "https://alerts.example.test", configuration: {}, enabled: true }, "operator");
    const input = { channelIds: [channel], eventType: "SCAN_COMPLETED", resourceType: "SCAN", resourceId: randomUUID(), idempotencyKey: "stable-key-1", payload: { title: "Scan completed", summary: "No secret evidence included.", severity: "INFO" as const } };
    expect(notifications.enqueue(input)).toEqual(notifications.enqueue(input));
    expect((database.db.prepare("SELECT COUNT(*) AS count FROM notification_deliveries").get() as { count: number }).count).toBe(1);
    const pdfPath = join(temporaryDirectories.at(-1)!, "proof.pdf"); writePdfProofPack(pdfPath, "# Proof pack\n\n## Summary\nSafe finding evidence"); const pdf = readFileSync(pdfPath);
    expect(pdf.subarray(0, 8).toString()).toBe("%PDF-1.7");
    expect(pdf.toString("latin1")).not.toContain("/JavaScript");
    await notifications.shutdown(); database.close();
  });

  it("exports interoperable SARIF, JUnit, Burp, and JSON artifacts", () => {
    const { database, paths } = fixture(); const organizationId = defaultOrganization(database); const scanId = randomUUID();
    new ScanRepository(database).create({ id: scanId, source: "DASHBOARD", status: "COMPLETED", targetOrigin: "https://app.example.test", safeTargetLabel: "app.example.test", profile: "quick", evidenceLevel: "minimal", safeConfigurationSummary: {} });
    new FindingNormalizer(database.db, new FindingFingerprintService(paths.fingerprintKeyPath)).normalizeReport(scanId, {
      routeCairnVersion: "0.1.0", target: "https://app.example.test", mode: "quick", program: "fixture",
      scope: { allowedDomains: ["app.example.test"], disallowedPaths: [], allowedMethods: ["GET"], rateLimitPerSecond: 1, concurrency: 1, sameOriginOnly: true, includeSubdomains: false },
      metadata: { startedAt: new Date(0).toISOString(), completedAt: new Date(1).toISOString(), durationMs: 1, totalRequests: 1, failedRequests: 0 },
      scopeDecisions: [], requestAudit: [], responses: [], technologies: [], discoveredUrls: [],
      findings: [{ id: "finding-1", title: "Authorization boundary missing", type: "Authorization", severity: "High", confidence: "High", url: "https://app.example.test/api/orders/123?token=redacted", method: "GET", evidence: { url: "https://app.example.test/api/orders/123", method: "GET", source: "fixture", title: "Observed" }, sourceModule: "authorization-matrix-testing", tags: ["authorization"] }]
    });
    const exports = new IntegrationExportService(database, paths);
    for (const format of ["SARIF", "JUNIT", "BURP_XML", "JSON"] as const) {
      const result = exports.create({ organizationId, scanId, format }, "operator");
      const artifact = database.db.prepare("SELECT canonical_path,content_type FROM artifacts WHERE id=?").get(result.artifactId) as { canonical_path: string; content_type: string };
      const content = readFileSync(artifact.canonical_path, "utf8");
      expect(content).toContain(format === "SARIF" ? '"version": "2.1.0"' : format === "JUNIT" ? "<testsuites>" : format === "BURP_XML" ? "<issues " : '"schemaVersion": 1');
      expect(content).not.toContain("token=redacted");
    }
    expect(exports.list(organizationId)).toHaveLength(4); database.close();
  });

  it("operates the organization and signed-agent control plane through authenticated APIs", async () => {
    const directory = mkdtempSync(join(tmpdir(), "routecairn-operations-api-")); temporaryDirectories.push(directory);
    const server = await startDashboardServer({ dataDir: directory, uiDistDir: join(directory, "ui") });
    try {
      const auth = await bootstrap(server.url, server.bootstrapUrl!);
      const organizations = await apiGet<{ organizations: Array<{ id: string }> }>(server.url, "/api/operations/organizations", auth.cookie); const organizationId = organizations.organizations[0]!.id;
      const enrollment = await apiPost<{ token: string }>(server.url, "/api/operations/remote-workers/enrollments", auth, { organizationId, expiresInMinutes: 60 });
      const keys = generateKeyPairSync("ed25519"); const publicKeyPem = keys.publicKey.export({ format: "pem", type: "spki" }).toString(); const privateKeyPem = keys.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
      const enrolledResponse = await fetch(`${server.url}/api/remote-agents/enroll`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: enrollment.token, name: "api-worker", publicKeyPem, capabilities: ["ping"], labels: { environment: "test" } }) });
      expect(enrolledResponse.status).toBe(201); const enrolled = await enrolledResponse.json() as { workerId: string };
      await apiPost(server.url, "/api/operations/remote-jobs", auth, { organizationId, kind: "PING", payload: { message: "api-check" }, requiredCapabilities: ["ping"], priority: 0, maxAttempts: 2 });
      const claimPath = "/api/remote-agents/worker/claim"; const claimBody = {}; const claimResponse = await fetch(`${server.url}${claimPath}`, { method: "POST", headers: { "content-type": "application/json", ...signedHeaders(enrolled.workerId, privateKeyPem, claimPath, claimBody) } as Record<string, string>, body: canonical(claimBody) });
      expect(claimResponse.status).toBe(200); const claimed = await claimResponse.json() as { job: { id: string; leaseToken: string } };
      const renewPath=`/api/remote-agents/worker/jobs/${claimed.job.id}/renew`;const renewBody={leaseToken:claimed.job.leaseToken};const renewResponse=await fetch(`${server.url}${renewPath}`,{method:"POST",headers:{"content-type":"application/json",...signedHeaders(enrolled.workerId,privateKeyPem,renewPath,renewBody)},body:canonical(renewBody)});expect(renewResponse.status).toBe(200);
      const completePath = `/api/remote-agents/worker/jobs/${claimed.job.id}/complete`; const completeBody = { leaseToken: claimed.job.leaseToken, status: "COMPLETED", result: { pong: true } }; const completeResponse = await fetch(`${server.url}${completePath}`, { method: "POST", headers: { "content-type": "application/json", ...signedHeaders(enrolled.workerId, privateKeyPem, completePath, completeBody) } as Record<string, string>, body: canonical(completeBody) });
      expect(completeResponse.status).toBe(200);
      const state = await apiGet<{ workers: unknown[]; jobs: Array<{ status: string }> }>(server.url, `/api/operations/remote-workers?organizationId=${organizationId}`, auth.cookie);
      expect(state.workers).toHaveLength(1); expect(state.jobs[0]?.status).toBe("COMPLETED");
    } finally { await server.close(); }
  });
});

function fixture(): { database: DashboardDatabase; paths: ReturnType<typeof resolveDashboardPaths> } {
  const directory = mkdtempSync(join(tmpdir(), "routecairn-operations-")); temporaryDirectories.push(directory);
  const paths = resolveDashboardPaths(directory); const database = new DashboardDatabase(paths.databasePath); database.migrate();
  mkdirSync(paths.thirdPartyModulesDir, { recursive: true }); mkdirSync(paths.backupsDir, { recursive: true });
  return { database, paths };
}

function defaultOrganization(database: DashboardDatabase): string { return (database.db.prepare("SELECT value FROM dashboard_meta WHERE key='default_organization_id'").get() as { value: string }).value; }
function createUser(database: DashboardDatabase, login: string, role: string): string { const id = randomUUID(); const now = new Date().toISOString(); database.db.prepare("INSERT INTO dashboard_users (id,login,normalized_login,password_hash,role,enabled,created_at,updated_at,password_changed_at) VALUES (?, ?, ?, 'unused', ?, 1, ?, ?, ?)").run(id, login, login, role, now, now, now); return id; }
function canonical(value: unknown): string { const sort = (item: unknown): unknown => Array.isArray(item) ? item.map(sort) : item && typeof item === "object" ? Object.fromEntries(Object.entries(item as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => [key, sort(child)])) : item; return JSON.stringify(sort(value)); }
function signedHeaders(workerId: string, privateKey: string, path: string, body: unknown): Record<string, string> { const timestamp = new Date().toISOString(); const nonce = randomBytes(24).toString("base64url"); const digest = createHash("sha256").update(canonical(body)).digest("hex"); const message = ["routecairn-agent-ed25519-v1", "POST", path, timestamp, nonce, digest].join("\n"); return { "x-routecairn-worker-id": workerId, "x-routecairn-timestamp": timestamp, "x-routecairn-nonce": nonce, "x-routecairn-signature": sign(null, Buffer.from(message), privateKey).toString("base64url") }; }
async function bootstrap(baseUrl: string, bootstrapUrl: string): Promise<{ cookie: string; csrf: string }> { const token=new URL(bootstrapUrl).hash.replace("#bootstrap=","");const response=await fetch(`${baseUrl}/api/session/bootstrap`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({token})});const body=await response.json() as {csrfToken:string};return{cookie:response.headers.get("set-cookie")?.split(";")[0]??"",csrf:body.csrfToken}; }
async function apiGet<T>(baseUrl:string,path:string,cookie:string):Promise<T>{const response=await fetch(`${baseUrl}${path}`,{headers:{cookie}});if(!response.ok)throw new Error(`${path}:${response.status}:${await response.text()}`);return response.json() as Promise<T>;}
async function apiPost<T=unknown>(baseUrl:string,path:string,auth:{cookie:string;csrf:string},body:unknown):Promise<T>{const response=await fetch(`${baseUrl}${path}`,{method:"POST",headers:{cookie:auth.cookie,"x-csrf-token":auth.csrf,"content-type":"application/json",origin:baseUrl},body:JSON.stringify(body)});if(!response.ok)throw new Error(`${path}:${response.status}:${await response.text()}`);return response.json() as Promise<T>;}
