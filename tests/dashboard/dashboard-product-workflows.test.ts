import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

describe("dashboard product workflows", () => {
  it("exposes a shared capability registry with explicit parity status", async () => {
    const dir = tempDir("routecairn-dashboard-capabilities-");
    try {
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const auth = await authenticate(handle.url, handle.bootstrapUrl);
        const capabilities = await apiGet<any>(handle.url, "/api/capabilities", auth.cookie);
        expect(capabilities.schemaVersion).toBe(1);
        expect(capabilities.generatedFrom).toBe("scanner-core");
        expect(capabilities.profiles.map((profile: any) => profile.name)).toEqual(["pre-handover", "quick", "full", "authenticated", "monitor", "proof"]);
        expect(capabilities.modules.some((module: any) => module.id === "browser-crawler")).toBe(true);
        expect(capabilities.controlledWorkflows.map((workflow: any) => workflow.id)).toEqual([
          "object-pair",
          "field-exposure",
          "authorization-matrix",
          "equivalent-route",
          "collection-authorization",
          "bulk-authorization",
          "file-authorization"
        ]);
        expect(capabilities.parity["server-mode-rbac"].status).toBe("FULL_DASHBOARD_PARITY");
        expect(capabilities.parity["isolated-workers"].status).toBe("FULL_DASHBOARD_PARITY");
        expect(capabilities.parity["credential-vault"].status).toBe("FULL_DASHBOARD_PARITY");
        for (const workflow of capabilities.controlledWorkflows) {
          expect(workflow.moduleId).toMatch(/testing$/);
          expect(workflow.schemaSource).toContain("ScanPlanner");
          expect(workflow.parity.status).toBe("FULL_DASHBOARD_PARITY");
          expect(workflow.guidedEditorSupport).toBe(true);
          expect(workflow.advancedJsonSupport).toBe(true);
        }
      } finally {
        await handle.close();
      }
    } finally {
      cleanup(dir);
    }
  });

  it("supports project and target CRUD with audit events and no secret metadata", async () => {
    const dir = tempDir("routecairn-dashboard-projects-");
    try {
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const auth = await authenticate(handle.url, handle.bootstrapUrl);
        const createdProject = await apiMutation<any>(handle.url, "/api/projects", auth, {
          name: "Client Portal",
          description: "Authorized assessment workspace",
          tags: ["client"],
          defaultProfile: "quick",
          defaultScope: { sameOriginOnly: true }
        });
        expect(createdProject.projectId).toMatch(/[0-9a-f-]{36}/);
        const createdTarget = await apiMutation<any>(handle.url, "/api/targets", auth, {
          projectId: createdProject.projectId,
          displayName: "Portal production",
          baseOrigin: "https://portal.example.com/app",
          authorizationType: "CLIENT_AUTHORIZED",
          authorizationSummary: "Written authorization for RouteCairn defensive testing only.",
          classification: "PUBLIC",
          defaultProfile: "monitor",
          tags: ["prod"],
          approvedScope: { origins: ["https://portal.example.com"] }
        });
        expect(createdTarget.targetId).toMatch(/[0-9a-f-]{36}/);
        const targets = await apiGet<any>(handle.url, "/api/targets", auth.cookie);
        expect(targets.targets[0].baseOrigin).toBe("https://portal.example.com");
        expect(targets.targets[0].authorizationSummary).toContain("defensive testing");
        const audit = await apiGet<any>(handle.url, "/api/audit-events", auth.cookie);
        expect(audit.events.map((event: any) => event.action)).toEqual(expect.arrayContaining(["TARGET_CREATED", "PROJECT_CREATED", "LOGIN_SUCCESS"]));
        expect(JSON.stringify(audit)).not.toMatch(/Bearer|Cookie|secret-token|sid=/i);
      } finally {
        await handle.close();
      }
    } finally {
      cleanup(dir);
    }
  });

  it("persists target authorization metadata on dashboard-created scans", async () => {
    const dir = tempDir("routecairn-dashboard-scan-metadata-");
    const fixture = await startFixtureServer();
    try {
      const paths = resolveDashboardPaths(dir);
      const scopePath = resolve(dir, "scope.json");
      const approvedScope = {
        program: "dashboard metadata fixture",
        allowedDomains: ["127.0.0.1"],
        disallowedPaths: [],
        allowedMethods: ["GET", "HEAD", "OPTIONS"],
        rateLimitPerSecond: 50,
        concurrency: 1,
        maxDepth: 1,
        sameOriginOnly: true,
        includeSubdomains: false,
        respectRobotsTxt: false,
        userAgent: "RouteCairn-Test/1.0"
      };
      writeFileSync(scopePath, JSON.stringify(approvedScope), "utf8");
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const auth = await authenticate(handle.url, handle.bootstrapUrl);
        const project = await apiMutation<any>(handle.url, "/api/projects", auth, { name: "Metadata", tags: [], defaultProfile: "quick", defaultScope: {} });
        const target = await apiMutation<any>(handle.url, "/api/targets", auth, {
          projectId: project.projectId,
          displayName: "Example",
          baseOrigin: fixture.url,
          authorizationType: "OWNED",
          authorizationSummary: "Owned target used for metadata persistence verification.",
          classification: "PUBLIC",
          tags: [],
          approvedScope,
          defaultProfile: "quick"
        });
        const queued = await apiMutation<any>(handle.url, "/api/scans", auth, {
          target: fixture.url,
          scopeFile: scopePath,
          profile: "quick",
          projectId: project.projectId,
          targetId: target.targetId,
          authorizationDeclaration: "OWNED: Owned target used for metadata persistence verification."
        });
        expect(queued.scanId).toMatch(/[0-9a-f-]{36}/);
        await waitForScan(handle.url, auth.cookie, queued.scanId);
      } finally {
        await handle.close();
      }
      const database = new DashboardDatabase(paths.databasePath);
      const row = database.db.prepare("SELECT project_id, target_id, authorization_declaration FROM scans LIMIT 1").get() as { project_id: string; target_id: string; authorization_declaration: string };
      expect(row.project_id).toBeTruthy();
      expect(row.target_id).toBeTruthy();
      expect(row.authorization_declaration).toContain("OWNED");
      database.close();
    } finally {
      await fixture.close();
      cleanup(dir);
    }
  });

  it("fails closed when server mode is requested before the first owner exists", async () => {
    await expect(startDashboardServer({
      mode: "server",
      host: "127.0.0.1",
      publicOrigin: "https://routecairn.example.com",
      sessionSecret: "x".repeat(40),
      trustProxy: true
    })).rejects.toThrow(/first owner/);
  });

  it("starts server mode after first-owner bootstrap and enforces viewer RBAC", async () => {
    const dir = tempDir("routecairn-dashboard-server-mode-");
    const secret = "server-mode-test-secret-value-with-entropy";
    try {
      const database = new DashboardDatabase(resolveDashboardPaths(dir).databasePath);
      database.migrate();
      const manager = new ServerSessionManager(database, { publicOrigin: "https://routecairn.example.com", sessionSecret: secret, trustProxy: true, developmentInsecureHttp: false });
      await manager.createFirstOwner("owner@example.com", "correct horse battery staple");
      await manager.createUser({ login: "viewer@example.com", password: "viewer password value", role: "VIEWER" });
      const passwordRows = database.db.prepare("SELECT password_hash FROM dashboard_users").all() as Array<{ password_hash: string }>;
      expect(passwordRows.every((row) => row.password_hash.startsWith("$argon2id$"))).toBe(true);
      expect(JSON.stringify(passwordRows)).not.toContain("correct horse battery staple");
      database.close();

      const handle = await startDashboardServer({ mode: "server", host: "127.0.0.1", dataDir: dir, publicOrigin: "https://routecairn.example.com", sessionSecret: secret, trustProxy: true, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const owner = await login(handle.url, "owner@example.com", "correct horse battery staple");
        const session = await apiGet<any>(handle.url, "/api/auth/session", owner.cookie);
        expect(session.principal.role).toBe("OWNER");
        const viewer = await login(handle.url, "viewer@example.com", "viewer password value");
        const denied = await fetch(`${handle.url}/api/scans`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-csrf-token": viewer.csrf, cookie: viewer.cookie, origin: "https://routecairn.example.com" },
          body: JSON.stringify({})
        });
        expect(denied.status).toBe(403);
        const sessions = new DashboardDatabase(resolveDashboardPaths(dir).databasePath);
        const tokenRows = sessions.db.prepare("SELECT token_hash FROM dashboard_sessions").all() as Array<{ token_hash: string }>;
        expect(tokenRows.every((row) => /^[a-f0-9]{64}$/.test(row.token_hash))).toBe(true);
        sessions.close();
      } finally {
        await handle.close();
      }
    } finally {
      cleanup(dir);
    }
  });
});

function tempDir(prefix: string): string {
  return mkdtempSync(resolve(tmpdir(), prefix));
}

function cleanup(path: string): void {
  rmSync(path, { recursive: true, force: true });
}

async function authenticate(baseUrl: string, bootstrapUrl: string): Promise<{ cookie: string; csrf: string }> {
  const token = new URL(bootstrapUrl).hash.replace("#bootstrap=", "");
  const response = await fetch(`${baseUrl}/api/session/bootstrap`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token })
  });
  if (!response.ok) throw new Error(`Bootstrap failed: ${response.status}`);
  return {
    cookie: response.headers.get("set-cookie")?.split(";")[0] ?? "",
    csrf: (await response.json() as { csrfToken: string }).csrfToken
  };
}

async function login(baseUrl: string, loginName: string, password: string): Promise<{ cookie: string; csrf: string }> {
  const response = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ login: loginName, password })
  });
  if (!response.ok) throw new Error(`Login failed: ${response.status} ${await response.text()}`);
  return {
    cookie: response.headers.get("set-cookie")?.split(";")[0] ?? "",
    csrf: (await response.json() as { csrfToken: string }).csrfToken
  };
}

async function apiGet<T>(baseUrl: string, path: string, cookie: string): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, { headers: { cookie } });
  if (!response.ok) throw new Error(`GET ${path} failed: ${response.status}`);
  return (await response.json()) as T;
}

async function apiMutation<T>(baseUrl: string, path: string, auth: { cookie: string; csrf: string }, body: unknown): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-csrf-token": auth.csrf, cookie: auth.cookie, origin: baseUrl },
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error(`POST ${path} failed: ${response.status} ${await response.text()}`);
  return (await response.json()) as T;
}

async function waitForScan(baseUrl: string, cookie: string, scanId: string): Promise<void> {
  // A real child worker, browser-network boundary, report writers, and cleanup
  // all run before terminal ingestion. Windows can legitimately exceed 15s.
  const deadline = Date.now() + 25000;
  while (Date.now() < deadline) {
    const body = await apiGet<any>(baseUrl, `/api/scans/${scanId}`, cookie);
    if (["COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"].includes(body.scan.status)) return;
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error("Timed out waiting for dashboard scan.");
}

async function startFixtureServer(): Promise<{ url: string; close(): Promise<void> }> {
  const server = createServer((request, response) => {
    response.setHeader("content-type", "text/html; charset=utf-8");
    if (request.url === "/robots.txt") {
      response.end("User-agent: *\nAllow: /\n");
      return;
    }
    response.end("<!doctype html><title>RouteCairn Dashboard Fixture</title><main>stable dashboard metadata fixture</main>");
  });
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Fixture server did not bind.");
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: async () => {
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    }
  };
}
