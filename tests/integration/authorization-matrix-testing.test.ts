import { afterEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";

let server: Server | undefined;
const tempDirs: string[] = [];

afterEach(async () => {
  if (server) {
    await new Promise<void>((resolve, reject) => {
      server?.close((error) => (error ? reject(error) : resolve()));
    });
    server = undefined;
  }
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("authorization matrix testing integration", () => {
  it("executes only the fixed GET matrix, confirms bypasses after object/state confirmation, and redacts evidence", async () => {
    const seen: string[] = [];
    let publicRequestHadAuthMaterial = false;
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end("ok");
        return;
      }
      const match = request.url?.match(/^\/api\/documents\/([^/?]+)/);
      if (!match) {
        response.writeHead(404).end();
        return;
      }
      const cookie = String(request.headers.cookie ?? "");
      const actor = cookie.includes("account-a") ? "owner" : cookie.includes("account-b") ? "viewer" : "public";
      if (actor === "public") {
        publicRequestHadAuthMaterial = Boolean(request.headers.cookie || request.headers.authorization || request.headers["x-csrf-token"] || request.headers["x-tenant-id"]);
        response.writeHead(401, { "content-type": "application/json" });
        response.end('{"error":"login required"}');
        return;
      }
      seen.push(`${actor}:${request.method}:${request.url}`);
      const objectId = decodeURIComponent(match[1] ?? "");
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ id: objectId, state: "published", owner: "principal-a-secret", tenantId: "tenant-one", privateNote: "never serialize matrix secret" }));
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-authz-matrix-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a-secret", "tenant-one", "member", "active")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b-secret", "tenant-two", "viewer", "active")),
      authorizationMatrix: await writeJson(tempDir, "authorization-matrix.json", authorizationMatrixInput(target, false))
    });

    const jsonText = await readFile(result.reportPath, "utf8");
    const markdownText = await readFile(result.markdownReportPath, "utf8");
    const report = JSON.parse(jsonText) as {
      scanPlan: { modules: Array<{ id: string }>; authorizationMatrixTesting?: { requestMatrix: Array<{ objectId: string; url: string }> } };
      authorizationMatrix?: {
        plannedRequests: number;
        executedRequests: number;
        confirmedIssues: number;
        cases: Array<{ caseId: string; actorId: string; authSlot?: string; observedDecision: string; matchedExpectation: boolean; objectIdentityConfirmed: boolean; objectStateConfirmed?: boolean; findingCategory?: string }>;
      };
      findings: Array<{ type: string; sourceModule: string; evidence: { curlCommand: string; source: string } }>;
      requestAudit: Array<{ requestedUrl: string; outcome: string; requestHeaders: Record<string, string> }>;
    };

    expect(report.scanPlan.modules.map((module) => module.id)).toEqual(["authorization-matrix-testing"]);
    expect(report.authorizationMatrix?.plannedRequests).toBe(3);
    expect(report.authorizationMatrix?.executedRequests).toBe(3);
    expect(seen).toEqual(["owner:GET:/api/documents/doc-a-001", "viewer:GET:/api/documents/doc-a-001"]);
    expect(publicRequestHadAuthMaterial).toBe(false);

    const viewer = report.authorizationMatrix?.cases.find((testCase) => testCase.caseId === "viewer-deny");
    const owner = report.authorizationMatrix?.cases.find((testCase) => testCase.caseId === "owner-allow");
    const publicCase = report.authorizationMatrix?.cases.find((testCase) => testCase.caseId === "public-auth");
    expect(owner?.observedDecision).toBe("ACCESS_ALLOWED_CONFIRMED");
    expect(owner?.matchedExpectation).toBe(true);
    expect(viewer?.observedDecision).toBe("ACCESS_ALLOWED_CONFIRMED");
    expect(viewer?.objectIdentityConfirmed).toBe(true);
    expect(viewer?.objectStateConfirmed).toBe(true);
    expect(viewer?.findingCategory).toBe("CROSS_TENANT_ACCESS_CONFIRMED");
    expect(publicCase?.observedDecision).toBe("AUTHENTICATION_REQUIRED");
    expect(report.authorizationMatrix?.confirmedIssues).toBe(1);
    expect(report.findings.filter((finding) => finding.type === "Authorization Matrix Issue")).toHaveLength(1);
    expect(report.findings[0]?.sourceModule).toBe("authorization-matrix-testing");
    expect(report.findings[0]?.evidence.curlCommand).toContain("Cookie: <redacted>");

    for (const serialized of [jsonText, markdownText]) {
      expect(serialized).not.toContain("doc-a-001");
      expect(serialized).not.toContain("session=account-a");
      expect(serialized).not.toContain("session=account-b");
      expect(serialized).not.toContain("principal-a-secret");
      expect(serialized).not.toContain("principal-b-secret");
      expect(serialized).not.toContain("never serialize matrix secret");
    }
    expect(JSON.stringify(report.scanPlan.authorizationMatrixTesting)).toContain("<object:");
    expect(report.requestAudit.every((entry) => Object.values(entry.requestHeaders).every((value) => value !== "session=account-a" && value !== "session=account-b"))).toBe(true);
  });

  it("does not create a finding when object state is not confirmed", async () => {
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200).end("ok");
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ id: "doc-a-001", state: "archived" }));
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-authz-matrix-state-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a-secret", "tenant-one", "member", "active")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b-secret", "tenant-two", "viewer", "active")),
      authorizationMatrix: await writeJson(tempDir, "authorization-matrix.json", authorizationMatrixInput(target, false))
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { authorizationMatrix?: { confirmedIssues: number; cases: Array<{ caseId: string; observedDecision: string }> }; findings: Array<{ type: string }> };
    const viewer = report.authorizationMatrix?.cases.find((testCase) => testCase.caseId === "viewer-deny");
    expect(viewer?.observedDecision).toBe("OBJECT_STATE_MISMATCH");
    expect(report.authorizationMatrix?.confirmedIssues).toBe(0);
    expect(report.findings.some((finding) => finding.type === "Authorization Matrix Issue")).toBe(false);
  });

  it("blocks verified-identity-required cases before matrix requests when verification is missing", async () => {
    const seen: string[] = [];
    server = createServer((request, response) => {
      seen.push(request.url ?? "");
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"id":"doc-a-001","state":"published"}');
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-authz-matrix-gate-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const matrixInput = authorizationMatrixInput(target, true);
    matrixInput.matrices[0].actors = matrixInput.matrices[0].actors.filter((actor) => actor.id !== "public");
    matrixInput.matrices[0].cases = matrixInput.matrices[0].cases.filter((testCase) => testCase.actorId !== "public");
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a-secret", "tenant-one", "member", "active")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b-secret", "tenant-two", "viewer", "active")),
      authorizationMatrix: await writeJson(tempDir, "authorization-matrix.json", matrixInput)
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { authorizationMatrix?: { executedRequests: number; cases: Array<{ observedDecision: string; notes: string[] }> } };
    expect(report.authorizationMatrix?.executedRequests).toBe(0);
    expect(report.authorizationMatrix?.cases.every((testCase) => testCase.observedDecision === "IDENTITY_REQUIREMENT_UNSATISFIED")).toBe(true);
    expect(seen).toEqual(["/"]);
  });
});

function authorizationMatrixInput(target: string, requireVerifiedIdentity: boolean) {
  return {
    schemaVersion: 1,
    maxMatrices: 1,
    maxCasesPerMatrix: 5,
    maxResponseBytes: 65536,
    maxPreviewLength: 80,
    matrices: [
      {
        id: "document-access",
        name: "Document access",
        objectType: "document",
        template: { id: "document-read", method: "GET", url: new URL("/api/documents/{{OBJECT_ID}}", target).toString(), headers: {} },
        objectIdentityField: "id",
        objectStateField: "state",
        actors: [
          { id: "owner", relationship: "OWNER", authProfile: "account_a", safeAlias: "Owner", principalId: "principal-a-secret", tenantId: "tenant-one", role: "member", accountState: "active" },
          { id: "viewer", relationship: "CROSS_TENANT_MEMBER", authProfile: "account_b", safeAlias: "Viewer", principalId: "principal-b-secret", tenantId: "tenant-two", role: "viewer", accountState: "active" },
          { id: "public", relationship: "PUBLIC", safeAlias: "Public" }
        ],
        cases: [
          { id: "owner-allow", actorId: "owner", objectId: "doc-a-001", expectedObjectState: "published", expectedDecision: "MUST_ALLOW", requireVerifiedIdentity },
          { id: "viewer-deny", actorId: "viewer", objectId: "doc-a-001", expectedObjectState: "published", expectedDecision: "MUST_DENY", expectedTenantId: "tenant-two", expectedRole: "viewer", expectedAccountState: "active", requireVerifiedIdentity },
          { id: "public-auth", actorId: "public", objectId: "doc-a-001", expectedDecision: "MUST_REQUIRE_AUTHENTICATION", requireVerifiedIdentity: false }
        ]
      }
    ]
  };
}

function authProfile(label: string, principalId: string, tenantId: string, role: string, accountState: string) {
  return {
    label,
    safeAlias: label,
    principalId,
    tenantId,
    role,
    accountState,
    headers: { Cookie: `session=${label}` }
  };
}

async function writeScope(tempDir: string): Promise<string> {
  return writeJson(tempDir, "scope.json", {
    ...exampleScope,
    allowedDomains: ["127.0.0.1"],
    disallowedPaths: [],
    rateLimitPerSecond: 50,
    concurrency: 2,
    userAgent: "RouteCairn/Test"
  });
}

async function writeJson(tempDir: string, name: string, value: unknown): Promise<string> {
  const path = join(tempDir, name);
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  return path;
}

function listen(targetServer: Server): Promise<void> {
  return new Promise((resolve) => {
    targetServer.listen(0, "127.0.0.1", resolve);
  });
}
