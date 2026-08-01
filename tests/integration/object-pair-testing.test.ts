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
    const authAPath = await writeJson(tempDir, "auth-a.json", { label: "account-a", headers: { Cookie: "session=account-a" } });
    const authBPath = await writeJson(tempDir, "auth-b.json", { label: "account-b", headers: { Cookie: "session=account-b" } });
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
          aToB: { category: string; objectIdHash: string; response: { containsPrivateFieldEvidence: boolean } };
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
      authA: await writeJson(tempDir, "auth-a.json", { label: "account-a", headers: { Cookie: "session=account-a" } }),
      authB: await writeJson(tempDir, "auth-b.json", { label: "account-b", headers: { Cookie: "session=account-b" } }),
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
});

function objectPairInput(target: string) {
  return {
    schemaVersion: 1,
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
      expectedPrivateFields: ["privateNote"]
    },
    accountBObject: {
      id: "doc-b-002",
      source: "integration fixture",
      confirmedSafeToTest: true,
      readOnly: true,
      expectedSafeMarkers: ["owner-b-marker"],
      expectedPrivateFields: ["privateNote"]
    }
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
