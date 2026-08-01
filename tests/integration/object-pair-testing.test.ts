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

describe("object pair testing integration", () => {
  it("executes fixed object-pair matrices, confirms vulnerable access, and avoids public/shared false positives", async () => {
    const requestedObjectUrls: string[] = [];
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end("<!doctype html><html><body>RouteCairn object-pair fixture</body></html>");
        return;
      }

      const cookie = String(request.headers.cookie ?? "");
      const principal = cookie.includes("account-a") ? "account-a" : cookie.includes("account-b") ? "account-b" : "anonymous";
      const match = request.url?.match(/^\/(vuln|secure|public|shared)\/([^/?]+)/);
      if (!match) {
        response.writeHead(404, { "content-type": "text/plain" });
        response.end("not found");
        return;
      }

      requestedObjectUrls.push(request.url ?? "");
      const [, kind, objectId] = match;
      const owner = objectId === "doc-a-001" ? "account-a" : objectId === "doc-b-002" ? "account-b" : "unknown";
      const body = JSON.stringify({
        id: objectId,
        owner,
        marker: owner === "account-a" ? "owner-a-marker" : "owner-b-marker",
        privateNote: kind === "public" ? undefined : "private-field-fixture",
        publicTitle: "safe title"
      });

      if (kind === "secure" && principal !== owner) {
        response.writeHead(403, { "content-type": "application/json" });
        response.end('{"error":"forbidden"}');
        return;
      }

      response.writeHead(200, { "content-type": "application/json" });
      response.end(body);
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-object-pair-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const scopePath = await writeScope(tempDir);
    const authAPath = await writeJson(tempDir, "auth-a.json", authProfile("account-a", "tenant-one", "member"));
    const authBPath = await writeJson(tempDir, "auth-b.json", authProfile("account-b", "tenant-two", "member"));
    const objectPairsPath = await writeJson(tempDir, "object-pairs.json", objectPairInput(target));
    const outputDir = join(tempDir, "reports");

    const result = await runScanCommand(target, {
      scope: scopePath,
      output: outputDir,
      authA: authAPath,
      authB: authBPath,
      objectPairs: objectPairsPath
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as {
      scanPlan: { modules: Array<{ id: string }>; objectPairTesting?: { requestMatrix: Array<{ targetObjectId: string; targetObjectIdHash: string }> } };
      objectPairTesting?: {
        plannedCases: number;
        plannedRequests: number;
        executedRequests: number;
        confirmedIssues: number;
        cases: Array<{
          caseId: string;
          baselineA: { category: string };
          baselineB: { category: string };
          aToB: { category: string; objectIdHash: string; finalClassification: string; technicalAccessResult: string; businessPolicyReviewStatus: string; response: { containsPrivateFieldEvidence: boolean } };
          bToA: { category: string };
        }>;
      };
      findings: Array<{ type: string; title: string; sourceModule: string; evidence: { source: string; curlCommand: string } }>;
      requestAudit: Array<{ requestHeaders: Record<string, string>; outcome: string }>;
    };

    expect(report.scanPlan.modules.map((module) => module.id)).toEqual(["object-pair-testing"]);
    expect(report.objectPairTesting?.plannedCases).toBe(4);
    expect(report.objectPairTesting?.plannedRequests).toBe(16);
    expect(report.objectPairTesting?.executedRequests).toBe(16);
    expect(requestedObjectUrls).toHaveLength(16);
    expect(new Set(requestedObjectUrls.map((url) => url.split("/").pop()))).toEqual(new Set(["doc-a-001", "doc-b-002"]));

    const vuln = report.objectPairTesting?.cases.find((testCase) => testCase.caseId === "vulnerable-documents");
    const secure = report.objectPairTesting?.cases.find((testCase) => testCase.caseId === "secure-documents");
    const publicCase = report.objectPairTesting?.cases.find((testCase) => testCase.caseId === "public-documents");
    const shared = report.objectPairTesting?.cases.find((testCase) => testCase.caseId === "shared-documents");

    expect(vuln?.baselineA.category).toBe("AUTHORIZED_BASELINE_CONFIRMED");
    expect(vuln?.baselineB.category).toBe("AUTHORIZED_BASELINE_CONFIRMED");
    expect(vuln?.aToB.category).toBe("CROSS_ACCOUNT_ACCESS_CONFIRMED");
    expect(vuln?.aToB.technicalAccessResult).toBe("FOREIGN_PRIVATE_ACCESS_CONFIRMED");
    expect(vuln?.aToB.businessPolicyReviewStatus).toBe("DECLARED_PRIVATE_CONFIRMED");
    expect(vuln?.aToB.finalClassification).toBe("CONFIRMED_VULNERABILITY");
    expect(vuln?.aToB.response.containsPrivateFieldEvidence).toBe(true);
    expect(secure?.aToB.category).toBe("CROSS_ACCOUNT_ACCESS_DENIED");
    expect(secure?.bToA.category).toBe("CROSS_ACCOUNT_ACCESS_DENIED");
    expect(publicCase?.aToB.category).toBe("PUBLIC_OBJECT_ACCESS");
    expect(shared?.aToB.category).toBe("PUBLIC_OBJECT_ACCESS");
    expect(report.findings.filter((finding) => finding.type === "Object Authorization Issue")).toHaveLength(2);
    expect(report.findings.every((finding) => finding.sourceModule === "object-pair-testing")).toBe(true);
    expect(JSON.stringify(report)).not.toContain("session=account-a");
    expect(JSON.stringify(report)).not.toContain("session=account-b");
    expect(JSON.stringify(report.scanPlan.objectPairTesting)).not.toContain("doc-a-001");
    expect(JSON.stringify(report.scanPlan.objectPairTesting)).not.toContain("doc-b-002");
    expect(
      report.requestAudit.every((entry) =>
        Object.entries(entry.requestHeaders).every(([name, value]) => name.toLowerCase() !== "cookie" || value === "<redacted>")
      )
    ).toBe(true);
  });

  it("marks cross-account results inconclusive when ownership baselines are not confirmed", async () => {
    const requestedObjectUrls: string[] = [];
    server = createServer((request, response) => {
      if (request.url?.startsWith("/generic/")) {
        requestedObjectUrls.push(request.url);
      }
      response.writeHead(200, { "content-type": "text/html" });
      response.end("<!doctype html><html><body>generic login page</body></html>");
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-object-pair-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "tenant-one", "member")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "tenant-two", "member")),
      objectPairs: await writeJson(tempDir, "object-pairs.json", {
        schemaVersion: 1,
        maxPairs: 1,
        cases: [caseInput("generic-documents", "generic", "PRIVATE_TO_OWNER", target)]
      })
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as {
      objectPairTesting?: { plannedRequests: number; executedRequests: number; confirmedIssues: number; cases: Array<{ baselineA: { category: string }; aToB: { category: string }; inconclusive: boolean }> };
      findings: Array<{ type: string }>;
    };

    expect(report.objectPairTesting?.plannedRequests).toBe(4);
    expect(report.objectPairTesting?.executedRequests).toBe(2);
    expect(requestedObjectUrls).toEqual(["/generic/doc-a-001", "/generic/doc-b-002"]);
    expect(report.objectPairTesting?.confirmedIssues).toBe(0);
    expect(report.objectPairTesting?.cases[0]?.baselineA.category).toBe("OWNERSHIP_NOT_CONFIRMED");
    expect(report.objectPairTesting?.cases[0]?.aToB.category).toBe("OWNERSHIP_NOT_CONFIRMED");
    expect(report.objectPairTesting?.cases[0]?.inconclusive).toBe(true);
    expect(report.findings.some((finding) => finding.type === "Object Authorization Issue")).toBe(false);
  });

  it("keeps confirmed technical access with unknown visibility in policy review instead of confirmed vulnerability", async () => {
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end("ok");
        return;
      }
      const match = request.url?.match(/^\/unknown\/([^/?]+)/);
      if (!match) {
        response.writeHead(404).end();
        return;
      }
      const objectId = match[1];
      const owner = objectId === "doc-a-001" ? "account-a" : "account-b";
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ id: objectId, owner, privateNote: "private-field-fixture" }));
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-object-pair-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "tenant-one", "member")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "tenant-two", "member")),
      objectPairs: await writeJson(tempDir, "object-pairs.json", {
        schemaVersion: 1,
        maxPairs: 1,
        principals: { accountA: { expectedAccountId: "account-a" }, accountB: { expectedAccountId: "account-b" } },
        cases: [caseInput("unknown-documents", "unknown", "UNKNOWN_REQUIRES_REVIEW", target)]
      })
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as {
      objectPairTesting?: { confirmedIssues: number; cases: Array<{ aToB: { category: string; technicalAccessResult: string; finalClassification: string; businessPolicyReviewStatus: string } }> };
      findings: Array<{ type: string }>;
    };

    expect(report.objectPairTesting?.cases[0]?.aToB.category).toBe("CROSS_ACCOUNT_ACCESS_CONFIRMED");
    expect(report.objectPairTesting?.cases[0]?.aToB.technicalAccessResult).toBe("FOREIGN_PRIVATE_ACCESS_CONFIRMED");
    expect(report.objectPairTesting?.cases[0]?.aToB.businessPolicyReviewStatus).toBe("POLICY_REVIEW_REQUIRED");
    expect(report.objectPairTesting?.cases[0]?.aToB.finalClassification).toBe("TECHNICAL_ACCESS_REQUIRES_POLICY_REVIEW");
    expect(report.objectPairTesting?.confirmedIssues).toBe(0);
    expect(report.findings.some((finding) => finding.type === "Object Authorization Issue")).toBe(false);
  });

  it("does not confirm HEAD exposure without explicit header evidence and supports explicit safe header evidence", async () => {
    const requested: string[] = [];
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end("ok");
        return;
      }
      const match = request.url?.match(/^\/(head-plain|head-explicit)\/([^/?]+)/);
      if (!match) {
        response.writeHead(404).end();
        return;
      }
      requested.push(`${request.method} ${request.url}`);
      const [, kind, objectId] = match;
      const owner = objectId === "doc-a-001" ? "account-a" : "account-b";
      const headers = kind === "head-explicit" ? { "x-object-id": objectId, "x-owner": owner, "x-private-signal": "present" } : { etag: `"${objectId}"`, "content-length": "100" };
      response.writeHead(200, headers);
      response.end(request.method === "HEAD" ? undefined : JSON.stringify({ id: objectId, owner, privateNote: "private-field-fixture" }));
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-object-pair-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", authProfile("account-a", "tenant-one", "member")),
      authB: await writeJson(tempDir, "auth-b.json", authProfile("account-b", "tenant-two", "member")),
      objectPairs: await writeJson(tempDir, "object-pairs.json", {
        schemaVersion: 1,
        maxPairs: 2,
        principals: { accountA: { expectedAccountId: "account-a" }, accountB: { expectedAccountId: "account-b" } },
        cases: [
          { ...caseInput("head-plain-documents", "head-plain", "PRIVATE_TO_OWNER", target), template: { id: "head-plain-read", method: "HEAD", url: new URL("/head-plain/{{OBJECT_ID}}", target).toString() } },
          {
            ...caseInput("head-explicit-documents", "head-explicit", "PRIVATE_TO_OWNER", target),
            template: { id: "head-explicit-read", method: "HEAD", url: new URL("/head-explicit/{{OBJECT_ID}}", target).toString() },
            accountAObject: { ...caseInput("x", "x", "PRIVATE_TO_OWNER", target).accountAObject, expectedObjectIdHeader: "x-object-id", expectedOwnerHeader: "x-owner", expectedPrivateHeaders: ["x-private-signal"] },
            accountBObject: { ...caseInput("x", "x", "PRIVATE_TO_OWNER", target).accountBObject, expectedObjectIdHeader: "x-object-id", expectedOwnerHeader: "x-owner", expectedPrivateHeaders: ["x-private-signal"] }
          }
        ]
      })
    });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as {
      objectPairTesting?: { cases: Array<{ caseId: string; executedRequests?: number; baselineA: { category: string }; aToB: { category: string; finalClassification: string } }> };
      findings: Array<{ type: string }>;
    };
    const plain = report.objectPairTesting?.cases.find((testCase) => testCase.caseId === "head-plain-documents");
    const explicit = report.objectPairTesting?.cases.find((testCase) => testCase.caseId === "head-explicit-documents");

    expect(plain?.baselineA.category).toBe("OWNERSHIP_NOT_CONFIRMED");
    expect(plain?.aToB.finalClassification).toBe("INCONCLUSIVE");
    expect(explicit?.baselineA.category).toBe("AUTHORIZED_BASELINE_CONFIRMED");
    expect(explicit?.aToB.category).toBe("CROSS_ACCOUNT_ACCESS_CONFIRMED");
    expect(explicit?.aToB.finalClassification).toBe("CONFIRMED_VULNERABILITY");
    expect(requested.filter((entry) => entry.includes("/head-plain/"))).toHaveLength(2);
    expect(requested.filter((entry) => entry.includes("/head-explicit/"))).toHaveLength(4);
  });

  it("redacts token-like object identifiers and sensitive response evidence from JSON, Markdown, and audit output", async () => {
    const objectA = "reset_token_OBJECT_A_SECRET_123456";
    const objectB = "reset_token_OBJECT_B_SECRET_654321";
    server = createServer((request, response) => {
      if (request.url === "/") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end("ok");
        return;
      }
      const match = request.url?.match(/^\/tokens\/([^/?]+)/);
      if (!match) {
        response.writeHead(404).end();
        return;
      }
      const objectId = decodeURIComponent(match[1]);
      const owner = objectId === objectA ? "principal-secret-A" : "principal-secret-B";
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ id: objectId, owner, privateNote: "password=SuperSecretFixture api_key=AKIA1234567890123456" }));
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-object-pair-"));
    tempDirs.push(tempDir);
    const target = `http://127.0.0.1:${port}/`;
    const result = await runScanCommand(target, {
      scope: await writeScope(tempDir),
      output: join(tempDir, "reports"),
      authA: await writeJson(tempDir, "auth-a.json", { ...authProfile("account-a", "tenant-one", "member"), principalId: "principal-secret-A" }),
      authB: await writeJson(tempDir, "auth-b.json", { ...authProfile("account-b", "tenant-two", "member"), principalId: "principal-secret-B" }),
      objectPairs: await writeJson(tempDir, "object-pairs.json", {
        ...objectPairInput(target),
        schemaVersion: 1,
        maxPairs: 1,
        principals: { accountA: { expectedAccountId: "principal-secret-A" }, accountB: { expectedAccountId: "principal-secret-B" } },
        cases: [
          {
            ...caseInput("token-documents", "tokens", "PRIVATE_TO_OWNER", target),
            accountAObject: { ...caseInput("x", "x", "PRIVATE_TO_OWNER", target).accountAObject, id: objectA },
            accountBObject: { ...caseInput("x", "x", "PRIVATE_TO_OWNER", target).accountBObject, id: objectB }
          }
        ]
      })
    });

    const jsonReport = await readFile(result.reportPath, "utf8");
    const markdownReport = await readFile(result.markdownReportPath, "utf8");
    for (const serialized of [jsonReport, markdownReport]) {
      expect(serialized).not.toContain(objectA);
      expect(serialized).not.toContain(objectB);
      expect(serialized).not.toContain("principal-secret-A");
      expect(serialized).not.toContain("principal-secret-B");
      expect(serialized).not.toContain("SuperSecretFixture");
      expect(serialized).not.toContain("AKIA1234567890123456");
      expect(serialized).not.toContain("session=account-a");
      expect(serialized).not.toContain("session=account-b");
    }
  });
});

function objectPairInput(target: string) {
  return {
    schemaVersion: 1,
    principals: { accountA: { expectedAccountId: "account-a" }, accountB: { expectedAccountId: "account-b" } },
    maxPairs: 5,
    cases: [
      caseInput("vulnerable-documents", "vuln", "PRIVATE_TO_OWNER", target),
      caseInput("secure-documents", "secure", "PRIVATE_TO_OWNER", target),
      caseInput("public-documents", "public", "PUBLIC", target),
      caseInput("shared-documents", "shared", "SHARED_WITH_SPECIFIC_PRINCIPALS", target)
    ]
  };
}

function caseInput(id: string, path: string, expectedVisibility: string, target: string) {
  return {
    id,
    objectType: "document",
    expectedVisibility,
    template: { id: `${id}-read`, method: "GET", url: new URL(`/${path}/{{OBJECT_ID}}`, target).toString() },
    accountAObject: {
      id: "doc-a-001",
      source: "integration fixture",
      confirmedSafeToTest: true,
      readOnly: true,
      expectedSafeMarkers: ["owner-a-marker"],
      expectedObjectIdField: "id",
      expectedOwnerField: "owner",
      expectedPrivateFields: ["privateNote"]
    },
    accountBObject: {
      id: "doc-b-002",
      source: "integration fixture",
      confirmedSafeToTest: true,
      readOnly: true,
      expectedSafeMarkers: ["owner-b-marker"],
      expectedObjectIdField: "id",
      expectedOwnerField: "owner",
      expectedPrivateFields: ["privateNote"]
    }
  };
}

function authProfile(principalId: string, tenantId: string, role: string) {
  return {
    label: principalId,
    safeAlias: principalId === "account-a" ? "Account A" : "Account B",
    principalId,
    tenantId,
    role,
    headers: { Cookie: `session=${principalId}` }
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
