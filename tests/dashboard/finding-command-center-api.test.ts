import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { DashboardDatabase, nowIso } from "../../src/dashboard/db/DashboardDatabase.js";
import { ArtifactRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { FindingFingerprintService } from "../../src/dashboard/findings/FindingFingerprintService.js";
import { FindingNormalizer } from "../../src/dashboard/findings/FindingNormalizer.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";

describe("finding command center API", () => {
  it("supports paged review, conflict protection, notes, bulk actions, saved views, and safe audit", async () => {
    const dir = tempDir();
    try {
      seedNativeFinding(dir);
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const auth = await localAuth(handle.url, handle.bootstrapUrl!);
        const page = await getJson<any>(handle.url, "/api/findings?page=1&pageSize=1&sort=severity_desc&review=UNREVIEWED", auth.cookie);
        expect(page).toMatchObject({ total: 1, page: 1, pageSize: 1 });
        const finding = page.findings[0];
        const reviewed = await mutate(handle.url, `/api/findings/${finding.id}/review`, "PATCH", auth, { newStatus: "IN_REVIEW", expectedVersion: finding.rowVersion });
        expect(reviewed.status).toBe(200);
        const stale = await mutate(handle.url, `/api/findings/${finding.id}/review`, "PATCH", auth, { newStatus: "CONFIRMED", expectedVersion: finding.rowVersion });
        expect(stale.status).toBe(409);
        expect(await stale.json()).toMatchObject({ code: "FINDING_VERSION_CONFLICT" });
        const current = (await getJson<any>(handle.url, `/api/findings/${finding.id}`, auth.cookie)).finding;
        const confirmed = await mutate(handle.url, `/api/findings/${finding.id}/review`, "PATCH", auth, { newStatus: "CONFIRMED", expectedVersion: current.rowVersion });
        expect(confirmed.status).toBe(200);
        const note = await mutate(handle.url, `/api/findings/${finding.id}/notes`, "POST", auth, { text: "Checked against the controlled fixture." });
        expect(note.status).toBe(201);
        const secretNote = await mutate(handle.url, `/api/findings/${finding.id}/notes`, "POST", auth, { text: "Authorization: Bearer hidden-secret-value" });
        expect(secretNote.status).toBe(400);
        const view = await mutate(handle.url, "/api/finding-views", "POST", auth, { name: "Confirmed", query: { reviewStatus: "CONFIRMED" }, columns: ["severity", "title"], isDefault: true, shared: false });
        expect(view.status).toBe(201);
        const views = await getJson<any>(handle.url, "/api/finding-views", auth.cookie);
        expect(views.views).toHaveLength(1);
        const saved = views.views[0];
        expect((await mutate(handle.url, "/api/finding-views", "PATCH", auth, { id: saved.id, name: "Confirmed renamed", query: { reviewStatus: "CONFIRMED" }, columns: ["title", "severity"], isDefault: false, shared: true, expectedVersion: saved.row_version })).status).toBe(200);
        expect((await mutate(handle.url, "/api/finding-views/default", "POST", auth, { id: saved.id })).status).toBe(200);
        const renamed = await getJson<any>(handle.url, "/api/finding-views", auth.cookie);
        expect(renamed.views[0]).toMatchObject({ safe_name: "Confirmed renamed", is_default: 1, shared_installation_wide: 1 });
        expect((await mutate(handle.url, "/api/finding-views/default", "POST", auth, { id: null })).status).toBe(200);
        expect((await mutate(handle.url, "/api/finding-views", "PATCH", auth, { id: saved.id, name: "Stale", query: {}, columns: ["title"], isDefault: false, shared: true, expectedVersion: saved.row_version })).status).toBe(409);
        expect((await mutate(handle.url, "/api/finding-views", "POST", auth, { name: "Invalid", query: {}, columns: ["title", "raw_sql"], isDefault: false, shared: false })).status).toBe(400);
        const audits = await getJson<any>(handle.url, "/api/audit-events", auth.cookie);
        const persisted = JSON.stringify(audits);
        expect(persisted).toContain("FINDING_CONFIRMED");
        expect(persisted).not.toContain("hidden-secret-value");
      } finally { await handle.close(); }
    } finally { cleanup(dir); }
  });

  it("integrates imported reports without fabricating unavailable evidence", async () => {
    const dir = tempDir();
    try {
      const paths = resolveDashboardPaths(dir);
      mkdirSync(paths.reportsDir, { recursive: true });
      const reportPath = resolve(paths.reportsDir, "historical-report.json");
      writeFileSync(reportPath, JSON.stringify(report()), "utf8");
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const auth = await localAuth(handle.url, handle.bootstrapUrl!);
        expect((await mutate(handle.url, "/api/import/report", "POST", auth, { reportPath })).status).toBe(201);
        const page = await getJson<any>(handle.url, "/api/findings?source=IMPORTED&evidence=HAS_EVIDENCE", auth.cookie);
        expect(page.total).toBe(1);
        const detail = await getJson<any>(handle.url, `/api/findings/${page.findings[0].id}`, auth.cookie);
        expect(detail.occurrences[0].source_kind).toBe("IMPORTED");
        expect(detail.evidence).toHaveLength(1);
        expect(JSON.stringify(detail)).not.toContain("historical-secret");
      } finally { await handle.close(); }
    } finally { cleanup(dir); }
  });

  it("keeps viewers read-only in server mode", async () => {
    const dir = tempDir();
    const publicOrigin = "https://findings.routecairn.test";
    const secret = "finding-command-center-server-session-secret";
    try {
      const paths = resolveDashboardPaths(dir);
      const database = new DashboardDatabase(paths.databasePath);
      database.migrate();
      const sessions = new ServerSessionManager(database, { publicOrigin, sessionSecret: secret, trustProxy: true, developmentInsecureHttp: false });
      await sessions.createFirstOwner("owner@example.test", "correct horse battery staple");
      await sessions.createUser({ login: "viewer@example.test", password: "viewer password value", role: "VIEWER" });
      seedFinding(database, paths);
      database.close();
      const handle = await startDashboardServer({ mode: "server", host: "127.0.0.1", dataDir: dir, publicOrigin, sessionSecret: secret, trustProxy: true, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const auth = await serverLogin(handle.url, publicOrigin, "viewer@example.test", "viewer password value");
        const page = await getJson<any>(handle.url, "/api/findings", auth.cookie);
        expect(page.total).toBe(1);
        const response = await mutate(handle.url, `/api/findings/${page.findings[0].id}/review`, "PATCH", { ...auth, origin: publicOrigin, forwarded: true }, { newStatus: "IN_REVIEW", expectedVersion: page.findings[0].rowVersion });
        expect(response.status).toBe(403);
      } finally { await handle.close(); }
    } finally { cleanup(dir); }
  });

  it("previews only bounded contained image artifacts", async () => {
    const dir = tempDir();
    const outsideDir = tempDir();
    try {
      const paths = resolveDashboardPaths(dir);
      mkdirSync(paths.artifactsDir, { recursive: true });
      const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "base64");
      const imagePath = resolve(paths.artifactsDir, "preview.png"); writeFileSync(imagePath, png);
      const textPath = resolve(paths.artifactsDir, "not-image.txt"); writeFileSync(textPath, "not an image");
      const outsidePath = resolve(outsideDir, "outside.png"); writeFileSync(outsidePath, png);
      const missingPath = resolve(paths.artifactsDir, "missing.png");
      const oversizedDimensions = Buffer.from(png); oversizedDimensions.writeUInt32BE(20_000, 16);
      const oversizedPath = resolve(paths.artifactsDir, "oversized.png"); writeFileSync(oversizedPath, oversizedDimensions);
      const mislabeledPath = resolve(paths.artifactsDir, "mislabeled.jpg"); writeFileSync(mislabeledPath, png);
      const database = new DashboardDatabase(paths.databasePath); database.migrate();
      const artifacts = new ArtifactRepository(database);
      const imageId = artifacts.create({ type: "SCREENSHOT", name: "preview.png", path: imagePath, size: png.length, contentType: "image/png", hash: "image" });
      const textId = artifacts.create({ type: "TEXT", name: "not-image.txt", path: textPath, size: 12, contentType: "text/plain", hash: "text" });
      const outsideId = artifacts.create({ type: "SCREENSHOT", name: "outside.png", path: outsidePath, size: png.length, contentType: "image/png", hash: "outside" });
      const missingId = artifacts.create({ type: "SCREENSHOT", name: "missing.png", path: missingPath, size: 1, contentType: "image/png", hash: "missing" });
      const oversizedId = artifacts.create({ type: "SCREENSHOT", name: "oversized.png", path: oversizedPath, size: oversizedDimensions.length, contentType: "image/png", hash: "oversized" });
      const mislabeledId = artifacts.create({ type: "SCREENSHOT", name: "mislabeled.jpg", path: mislabeledPath, size: png.length, contentType: "image/jpeg", hash: "mislabeled" });
      database.close();
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const auth = await localAuth(handle.url, handle.bootstrapUrl!);
        const preview = await fetch(`${handle.url}/api/artifacts/${imageId}/preview`, { headers: { cookie: auth.cookie } });
        expect(preview.status).toBe(200); expect(preview.headers.get("content-type")).toBe("image/png"); expect(preview.headers.get("x-content-type-options")).toBe("nosniff"); expect(preview.headers.get("content-disposition")).toContain("inline"); expect(preview.headers.get("x-routecairn-image-dimensions")).toBe("1x1");
        expect((await preview.arrayBuffer()).byteLength).toBe(png.length);
        expect((await fetch(`${handle.url}/api/artifacts/${textId}/preview`, { headers: { cookie: auth.cookie } })).status).toBe(415);
        expect((await fetch(`${handle.url}/api/artifacts/${outsideId}/preview`, { headers: { cookie: auth.cookie } })).status).toBe(403);
        expect((await fetch(`${handle.url}/api/artifacts/${missingId}/preview`, { headers: { cookie: auth.cookie } })).status).toBe(404);
        expect((await fetch(`${handle.url}/api/artifacts/${oversizedId}/preview`, { headers: { cookie: auth.cookie } })).status).toBe(415);
        expect((await fetch(`${handle.url}/api/artifacts/${mislabeledId}/preview`, { headers: { cookie: auth.cookie } })).status).toBe(415);
      } finally { await handle.close(); }
    } finally { cleanup(dir); cleanup(outsideDir); }
  });
});

function seedNativeFinding(dir: string): void {
  const paths = resolveDashboardPaths(dir);
  const database = new DashboardDatabase(paths.databasePath);
  database.migrate();
  seedFinding(database, paths);
  database.close();
}

function seedFinding(database: DashboardDatabase, paths: ReturnType<typeof resolveDashboardPaths>): void {
  const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  database.db.prepare(`INSERT INTO scans (id, source, status, target_origin, safe_target_label, profile, evidence_level, created_at, completed_at, safe_configuration_summary) VALUES (?, 'DASHBOARD', 'COMPLETED', 'https://app.test', 'https://app.test', 'authenticated', 'normal', ?, ?, '{}')`).run(id, nowIso(), nowIso());
  database.db.prepare(`INSERT INTO scan_module_executions (id, scan_id, module_id, module_label, planned_order, status) VALUES ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', ?, 'authorization-matrix-testing', 'Authorization Matrix', 1, 'COMPLETED')`).run(id);
  new FindingNormalizer(database.db, new FindingFingerprintService(paths.fingerprintKeyPath)).normalizeReport(id, report());
}

function report(): RouteCairnReport {
  return { routeCairnVersion: "0.1.0", target: "https://app.test", mode: "authenticated", program: "fixture", scope: { allowedDomains: ["app.test"], disallowedPaths: [], allowedMethods: ["GET"], rateLimitPerSecond: 1, concurrency: 1, sameOriginOnly: true, includeSubdomains: false }, metadata: { startedAt: new Date(0).toISOString(), completedAt: new Date(1).toISOString(), durationMs: 1, totalRequests: 1, failedRequests: 0 }, scopeDecisions: [], requestAudit: [], responses: [], technologies: [], discoveredUrls: [], findings: [{ id: "finding", title: "Controlled authorization finding", type: "Authorization", severity: "High", confidence: "High", url: "https://app.test/api/orders/123?token=historical-secret", method: "GET", sourceModule: "authorization-matrix-testing", tags: ["authorization", "role:user"], evidence: { url: "https://app.test/api/orders/:id?token=<redacted>", method: "GET", source: "fixture", title: "Controlled evidence", bodyHash: "safe-hash" } }] };
}

async function localAuth(baseUrl: string, bootstrapUrl: string): Promise<Auth> {
  const token = new URL(bootstrapUrl).hash.replace("#bootstrap=", "");
  const response = await fetch(`${baseUrl}/api/session/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });
  const body = await response.json() as { csrfToken: string };
  return { cookie: response.headers.get("set-cookie")?.split(";")[0] ?? "", csrf: body.csrfToken, origin: baseUrl };
}

async function serverLogin(baseUrl: string, origin: string, login: string, password: string): Promise<Auth> {
  const response = await fetch(`${baseUrl}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json", origin, "x-forwarded-proto": "https" }, body: JSON.stringify({ login, password }) });
  const body = await response.json() as { csrfToken: string };
  return { cookie: response.headers.get("set-cookie")?.split(";")[0] ?? "", csrf: body.csrfToken, origin };
}

interface Auth { cookie: string; csrf: string; origin: string; forwarded?: boolean }

async function mutate(baseUrl: string, path: string, method: "POST" | "PATCH", auth: Auth, body: unknown): Promise<Response> {
  return fetch(`${baseUrl}${path}`, { method, headers: { "content-type": "application/json", "x-csrf-token": auth.csrf, cookie: auth.cookie, origin: auth.origin, ...(auth.forwarded ? { "x-forwarded-proto": "https" } : {}) }, body: JSON.stringify(body) });
}

async function getJson<T>(baseUrl: string, path: string, cookie: string): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, { headers: { cookie } });
  if (!response.ok) throw new Error(await response.text());
  return await response.json() as T;
}

function tempDir(): string { return mkdtempSync(resolve(tmpdir(), "routecairn-finding-api-")); }
function cleanup(dir: string): void { try { rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 30 }); } catch { /* Windows SQLite cleanup is best effort. */ } }
