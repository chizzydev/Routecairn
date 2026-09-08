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
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })));
});

describe("monitor profile determinism", () => {
  it("produces equivalent stable comparison output across repeated unchanged scans", async () => {
    server = createServer((request, response) => {
      if (request.url === "/api/health") {
        response.writeHead(200, { "content-type": "application/json", date: new Date().toUTCString() });
        response.end('{"ok":true}');
        return;
      }
      response.writeHead(200, { "content-type": "text/html; charset=utf-8", date: new Date().toUTCString() });
      response.end('<!doctype html><html><head><title>Monitor Fixture</title></head><body><a href="/api/health">health</a></body></html>');
    });
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    const target = `http://127.0.0.1:${port}/`;
    const tempDir = await mkdtemp(join(tmpdir(), "routecairn-monitor-"));
    tempDirs.push(tempDir);
    const scopePath = join(tempDir, "scope.json");
    await writeFile(scopePath, JSON.stringify({ ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], rateLimitPerSecond: 50, concurrency: 10 }, null, 2));

    const first = await runScanCommand(target, { scope: scopePath, output: join(tempDir, "one"), profile: "monitor", rate: "50", concurrency: "10" });
    const second = await runScanCommand(target, { scope: scopePath, output: join(tempDir, "two"), profile: "monitor", rate: "50", concurrency: "10" });

    const firstReport = JSON.parse(await readFile(first.reportPath, "utf8"));
    const secondReport = JSON.parse(await readFile(second.reportPath, "utf8"));
    expect(stableProjection(firstReport)).toEqual(stableProjection(secondReport));
  }, 120_000);
});

function stableProjection(report: {
  scanPlan: { profile: string; modules: Array<{ id: string }> };
  technologies: Array<{ name: string; confidence: string }>;
  apiMapper?: { endpoints: Array<{ endpoint: string; routeType: string; riskTags: string[] }> };
  discoveredUrls: Array<{ url: string; falsePositiveStatus: string; statusCode?: number }>;
  findings: Array<{ type: string; url: string; severity: string; sourceModule: string }>;
}) {
  return {
    profile: report.scanPlan.profile,
    modules: report.scanPlan.modules.map((module) => module.id),
    technologies: report.technologies.map((technology) => `${technology.name}:${technology.confidence}`).sort(),
    endpoints: (report.apiMapper?.endpoints ?? []).map((endpoint) => `${endpoint.routeType}:${normalizeUrl(endpoint.endpoint)}:${endpoint.riskTags.join(",")}`).sort(),
    urls: report.discoveredUrls
      .filter((url) => !url.url.includes(".routecairn-nonexistent"))
      .map((url) => `${normalizeUrl(url.url)}:${url.statusCode ?? "error"}:${url.falsePositiveStatus}`)
      .sort(),
    findings: report.findings.map((finding) => `${finding.type}:${normalizeUrl(finding.url)}:${finding.severity}:${finding.sourceModule}`).sort()
  };
}

function normalizeUrl(value: string): string {
  const parsed = new URL(value);
  return `${parsed.protocol}//${parsed.hostname}${parsed.pathname}${parsed.search}`;
}
