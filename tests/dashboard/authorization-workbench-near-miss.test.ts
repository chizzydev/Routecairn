import { it, expect } from "vitest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";
it("does not confirm object authorization bypass when a 200 returns a different object", async () => {
  const root = createOwnedTestDirectory("workbench-near-miss-"),
    wire: string[] = [];
  const server = createServer((req, res) => {
    wire.push(req.url!);
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(req.url === "/object/foreign" ? { id: "own-object", tenant: "own-tenant" } : {}));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = "http://127.0.0.1:" + (server.address() as AddressInfo).port;
  try {
    const scope = join(root, "s.json"),
      manifest = join(root, "m.json");
    writeFileSync(
      scope,
      JSON.stringify({
        ...exampleScope,
        allowedDomains: ["127.0.0.1"],
        disallowedPaths: [],
        allowedMethods: ["GET"],
        rateLimitPerSecond: 20,
        concurrency: 1
      })
    );
    writeFileSync(
      manifest,
      JSON.stringify({
        schemaVersion: 1,
        maxRequests: 2,
        actors: [{ id: "anonymous", safeAlias: "anonymous", authSlot: "anonymous", relationship: "PUBLIC" }],
        routes: [
          {
            id: "object",
            safeAlias: "foreign-object",
            protocol: "REST",
            kind: "OBJECT",
            objectType: "document",
            url: origin + "/object/foreign",
            pathTemplate: "/object/:id"
          }
        ],
        checks: [
          {
            id: "near-miss",
            matrixId: "object-boundary",
            label: "Wrong object is not proof",
            kind: "OBJECT_AUTHORIZATION",
            routeId: "object",
            actorId: "anonymous",
            request: { method: "GET" },
            response: {
              expectedDecision: "DENY",
              identity: { path: "id", expectedValue: "foreign-object" },
              tenant: { path: "tenant", expectedValue: "foreign-tenant" }
            }
          }
        ]
      })
    );
    const result = await runScanCommand(origin, {
      scope,
      apiGraphql: manifest,
      includeModules: ["api-graphql-authorization"],
      replaceProfileModules: true,
      output: join(root, "reports"),
      maxRequests: "6"
    });
    const report = JSON.parse(readFileSync(result.reportPath, "utf8"));
    writeFileSync(
      join(root, "NEAR_MISS_HTTP_RECEIPT.json"),
      JSON.stringify(
        { wire, checks: report.apiGraphql.checks, findings: report.findings, integrity: "REAL_LOOPBACK_HTTP" },
        null,
        2
      )
    );
    expect(wire).toContain("/object/foreign");
    expect(report.apiGraphql.checks[0]).toMatchObject({ outcome: "INCONCLUSIVE", objectIdentityConfirmed: false });
    expect(
      report.findings.filter((v: { sourceModule: string }) => v.sourceModule === "api-graphql-authorization")
    ).toEqual([]);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    retainOwnedTestDirectory(root);
  }
});

it("requires a working ALLOW control before confirming a denied actor bypass", async () => {
  const root = createOwnedTestDirectory("workbench-control-"),
    wire: string[] = [];
  const server = createServer((req, res) => {
    wire.push(String(req.headers["x-fixture-mode"]));
    res.writeHead(req.headers["x-fixture-mode"] === "control" ? 403 : 200, { "content-type": "application/json" });
    res.end(JSON.stringify(req.headers["x-fixture-mode"] === "control" ? {} : { id: "foreign-object" }));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = "http://127.0.0.1:" + (server.address() as AddressInfo).port;
  try {
    const scope = join(root, "s.json"),
      manifest = join(root, "m.json");
    writeFileSync(
      scope,
      JSON.stringify({
        ...exampleScope,
        allowedDomains: ["127.0.0.1"],
        disallowedPaths: [],
        allowedMethods: ["GET"],
        rateLimitPerSecond: 20,
        concurrency: 1
      })
    );
    writeFileSync(
      manifest,
      JSON.stringify({
        schemaVersion: 1,
        maxRequests: 3,
        actors: ["control", "candidate"].map((id) => ({
          id,
          safeAlias: id,
          authSlot: "anonymous",
          relationship: "EXPLICIT_CONTROL_FIXTURE"
        })),
        routes: [
          {
            id: "object",
            safeAlias: "object",
            protocol: "REST",
            kind: "OBJECT",
            objectType: "document",
            url: origin + "/object/foreign",
            pathTemplate: "/object/:id"
          }
        ],
        checks: ["control", "candidate"].map((id) => ({
          id,
          matrixId: "pair",
          label: "Unavailable allowed control",
          kind: "OBJECT_AUTHORIZATION",
          routeId: "object",
          actorId: id,
          request: { method: "GET", headers: { "X-Fixture-Mode": id } },
          response: {
            expectedDecision: id === "control" ? "ALLOW" : "DENY",
            identity: { path: "id", expectedValue: "foreign-object" }
          }
        }))
      })
    );
    const result = await runScanCommand(origin, {
      scope,
      apiGraphql: manifest,
      includeModules: ["api-graphql-authorization"],
      replaceProfileModules: true,
      output: join(root, "reports"),
      maxRequests: "6"
    });
    const report = JSON.parse(readFileSync(result.reportPath, "utf8"));
    writeFileSync(
      join(root, "CONTROL_HTTP_RECEIPT.json"),
      JSON.stringify({ wire, checks: report.apiGraphql.checks, findings: report.findings }, null, 2)
    );
    expect(wire).toContain("control");
    expect(wire).toContain("candidate");
    expect(report.apiGraphql.checks.every((c: { outcome: string }) => c.outcome === "INCONCLUSIVE")).toBe(true);
    expect(
      report.findings.filter((f: { sourceModule: string }) => f.sourceModule === "api-graphql-authorization")
    ).toEqual([]);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((r) => server.close(() => r()));
    retainOwnedTestDirectory(root);
  }
});
