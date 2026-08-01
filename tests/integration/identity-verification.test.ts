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
    await new Promise<void>((resolve, reject) => server?.close((error) => (error ? reject(error) : resolve())));
    server = undefined;
  }
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("identity verification integration", () => {
  it("verifies Account A and Account B independently before object-pair execution", async () => {
    const identityRequests: string[] = [];
    const objectRequests: string[] = [];
    server = createServer((request, response) => {
      const cookie = String(request.headers.cookie ?? "");
      const principal = cookie.includes("account-a") ? "principal-a-secret" : cookie.includes("account-b") ? "principal-b-secret" : "anonymous";

      if (request.url === "/") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end("ok");
        return;
      }

      if (request.url === "/api/me") {
        identityRequests.push(cookie);
        response.writeHead(200, { "content-type": "application/json" });
        response.end(
          JSON.stringify({
            authenticated: principal !== "anonymous",
            user: { id: principal, role: "member", username: principal === "principal-a-secret" ? "Account A" : "Account B" },
            organization: { id: principal === "principal-a-secret" ? "tenant-a-secret" : "tenant-b-secret" }
          })
        );
        return;
      }

      const match = request.url?.match(/^\/objects\/([^/?]+)/);
      if (match) {
        const objectId = decodeURIComponent(match[1]);
        objectRequests.push(`${principal}:${objectId}`);
        const owner = objectId === "doc-a-001" ? "principal-a-secret" : "principal-b-secret";
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ id: objectId, owner, tenant: owner === "principal-a-secret" ? "tenant-a-secret" : "tenant-b-secret", privateNote: "private-field-fixture" }));
        return;
      }

      response.writeHead(404).end();
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-identity-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a-secret", "tenant-a-secret", "member", "required")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b-secret", "tenant-b-secret", "member", "required")),
      objectPairs: await writeJson(tempDir, "object-pairs.json", objectPairs(target))
    });

    const jsonReport = await readFile(result.reportPath, "utf8");
    const markdownReport = await readFile(result.markdownReportPath, "utf8");
    const report = JSON.parse(jsonReport) as {
      identityVerification?: { accountA: { category: string; verified: boolean }; accountB: { category: string; verified: boolean }; distinctVerifiedPrincipals: boolean };
      objectPairTesting?: { executedRequests: number; confirmedIssues: number };
      requestAudit: Array<{ requestedUrl: string; requestHeaders: Record<string, string> }>;
    };

    expect(identityRequests).toEqual(["session=account-a", "session=account-b"]);
    expect(objectRequests).toHaveLength(4);
    expect(report.identityVerification?.accountA.category).toBe("VERIFIED");
    expect(report.identityVerification?.accountB.category).toBe("VERIFIED");
    expect(report.identityVerification?.distinctVerifiedPrincipals).toBe(true);
    expect(report.objectPairTesting?.executedRequests).toBe(4);
    expect(report.objectPairTesting?.confirmedIssues).toBe(2);
    expect(report.requestAudit.filter((entry) => entry.requestedUrl.endsWith("/api/me"))).toHaveLength(2);
    for (const serialized of [jsonReport, markdownReport]) {
      expect(serialized).not.toContain("principal-a-secret");
      expect(serialized).not.toContain("principal-b-secret");
      expect(serialized).not.toContain("tenant-a-secret");
      expect(serialized).not.toContain("tenant-b-secret");
      expect(serialized).not.toContain("session=account-a");
      expect(serialized).not.toContain("session=account-b");
    }
  });

  it("blocks required verification on principal, tenant, role, login, and anonymous failures", async () => {
    const objectRequests: string[] = [];
    server = createServer((request, response) => {
      if (request.url === "/") return response.writeHead(200, { "content-type": "text/html" }).end("ok");
      if (request.url === "/login-me") return response.writeHead(200, { "content-type": "text/html" }).end("<html>sign in required</html>");
      if (request.url === "/anonymous-me") return response.writeHead(200, { "content-type": "application/json" }).end('{"authenticated":false,"user":null}');
      if (request.url === "/api/me") {
        response.writeHead(200, { "content-type": "application/json" });
        response.end('{"authenticated":true,"user":{"id":"same-server-principal","role":"wrong-role"},"organization":{"id":"wrong-tenant"}}');
        return;
      }
      if (request.url?.startsWith("/objects/")) {
        objectRequests.push(request.url);
        return response.writeHead(200, { "content-type": "application/json" }).end("{}");
      }
      response.writeHead(404).end();
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-identity-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const baseOptions = {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      objectPairs: await writeJson(tempDir, "object-pairs.json", objectPairs(target))
    };

    const mismatchResult = await runScanCommand(target, {
        ...baseOptions,
        mode: "headers",
        authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "principal-a", "tenant-a", "member", "required")),
        authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "principal-b", "tenant-b", "member", "required"))
      });
    const mismatchReport = JSON.parse(await readFile(mismatchResult.reportPath, "utf8")) as {
      identityVerification?: { accountA: { category: string } };
      objectPairTesting?: { enabled: boolean; executedRequests: number; notes: string[] };
      technologies: unknown[];
    };
    expect(mismatchReport.identityVerification?.accountA.category).toBe("PRINCIPAL_MISMATCH");
    expect(mismatchReport.objectPairTesting?.enabled).toBe(false);
    expect(mismatchReport.objectPairTesting?.executedRequests).toBe(0);
    expect(mismatchReport.objectPairTesting?.notes.join(" ")).toContain("required verified principal identity");
    expect(mismatchReport.technologies).toBeDefined();
    expect(objectRequests).toEqual([]);

    const loginResult = await runScanCommand(target, {
        ...baseOptions,
        mode: "headers",
        authA: await writeJson(tempDir, "auth-login-a.json", authProfile("account-a", "principal-a", "tenant-a", "member", "required", "/login-me")),
        authB: await writeJson(tempDir, "auth-login-b.json", authProfile("account-b", "principal-b", "tenant-b", "member", "required", "/login-me"))
      });
    const loginReport = JSON.parse(await readFile(loginResult.reportPath, "utf8")) as { identityVerification?: { accountA: { category: string } }; objectPairTesting?: { enabled: boolean; executedRequests: number } };
    expect(loginReport.identityVerification?.accountA.category).toBe("LOGIN_PAGE_RESPONSE");
    expect(loginReport.objectPairTesting?.enabled).toBe(false);
    expect(loginReport.objectPairTesting?.executedRequests).toBe(0);

    const anonymousResult = await runScanCommand(target, {
        ...baseOptions,
        mode: "headers",
        authA: await writeJson(tempDir, "auth-anon-a.json", authProfile("account-a", "principal-a", "tenant-a", "member", "required", "/anonymous-me")),
        authB: await writeJson(tempDir, "auth-anon-b.json", authProfile("account-b", "principal-b", "tenant-b", "member", "required", "/anonymous-me"))
      });
    const anonymousReport = JSON.parse(await readFile(anonymousResult.reportPath, "utf8")) as { identityVerification?: { accountA: { category: string } }; objectPairTesting?: { enabled: boolean; executedRequests: number } };
    expect(anonymousReport.identityVerification?.accountA.category).toBe("ANONYMOUS_RESPONSE");
    expect(anonymousReport.objectPairTesting?.enabled).toBe(false);
    expect(anonymousReport.objectPairTesting?.executedRequests).toBe(0);
  });

  it("records optional verification failure without blocking modules that do not require verified identity", async () => {
    server = createServer((request, response) => {
      if (request.url === "/") return response.writeHead(200, { "content-type": "text/html" }).end("ok");
      if (request.url === "/api/me") return response.writeHead(200, { "content-type": "application/json" }).end('{"authenticated":true}');
      response.writeHead(404).end();
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-identity-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      profile: "quick",
      output: join(tempDir, "reports"),
      auth: await writeJson(tempDir, "auth.json", authProfile("account-a", "principal-a-secret", "tenant-a-secret", "member", "optional"))
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { identityVerification?: { primary: { category: string; verified: boolean } }; technologies: unknown[] };
    expect(report.identityVerification?.primary.category).toBe("IDENTITY_FIELD_MISSING");
    expect(report.identityVerification?.primary.verified).toBe(false);
    expect(report.technologies).toBeDefined();
  });

  it("supports explicit array paths and reports missing configured metadata separately", async () => {
    server = createServer((request, response) => {
      if (request.url === "/") return response.writeHead(200, { "content-type": "text/html" }).end("ok");
      if (request.url === "/api/me") {
        response.writeHead(200, { "content-type": "application/json" });
        response.end('{"authenticated":true,"users":[{"id":12345}],"organization":{}}');
        return;
      }
      response.writeHead(404).end();
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-identity-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const profile = authProfile("account-a", "12345", "tenant-a-secret", "member", "optional");
    profile.identityVerification.principalIdField = "users[0].id";
    profile.identityVerification.tenantIdField = "organization.id";

    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      profile: "quick",
      output: join(tempDir, "reports"),
      auth: await writeJson(tempDir, "auth.json", profile)
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as { identityVerification?: { primary: { category: string; principalMatched: boolean; verified: boolean } } };
    expect(report.identityVerification?.primary.principalMatched).toBe(true);
    expect(report.identityVerification?.primary.category).toBe("REQUIRED_METADATA_MISSING");
    expect(report.identityVerification?.primary.verified).toBe(false);
  });
});

function authProfile(label: string, principalId: string, tenantId: string, role: string, mode: "optional" | "required", endpoint = "/api/me") {
  return {
    label,
    safeAlias: label,
    principalId,
    tenantId,
    role,
    headers: { Cookie: `session=${label}` },
    identityVerification: {
      mode,
      endpoint,
      method: "GET",
      principalIdField: "user.id",
      tenantIdField: "organization.id",
      roleField: "user.role",
      safeAliasField: "user.username",
      anonymousMarkers: [{ field: "authenticated", value: false }]
    }
  };
}

function objectPairs(target: string) {
  return {
    schemaVersion: 1,
    maxPairs: 1,
    cases: [
      {
        id: "documents",
        objectType: "document",
        expectedVisibility: "PRIVATE_TO_OWNER",
        template: { id: "doc-read", method: "GET", url: new URL("/objects/{{OBJECT_ID}}", target).toString() },
        accountAObject: {
          id: "doc-a-001",
          source: "fixture",
          confirmedSafeToTest: true,
          readOnly: true,
          expectedObjectIdField: "id",
          expectedOwnerField: "owner",
          expectedTenantField: "tenant",
          expectedPrivateFields: ["privateNote"]
        },
        accountBObject: {
          id: "doc-b-002",
          source: "fixture",
          confirmedSafeToTest: true,
          readOnly: true,
          expectedObjectIdField: "id",
          expectedOwnerField: "owner",
          expectedTenantField: "tenant",
          expectedPrivateFields: ["privateNote"]
        }
      }
    ]
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
  return new Promise((resolve) => targetServer.listen(0, "127.0.0.1", resolve));
}
