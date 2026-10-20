import { it, expect } from "vitest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "../helpers/owned-test-directory.js";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";
import { nativeApplicationProofMatches } from "../../src/dashboard/execution/ApplicationIdentity.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
it.each([
  "legacy-incomplete",
  "TENANT_AWARE",
  "PRINCIPAL_ROLE",
  "TENANT_AWARE:principal",
  "TENANT_AWARE:role",
  "TENANT_AWARE:tenant",
  "TENANT_AWARE:missing-role",
  "PRINCIPAL_ROLE:principal",
  "PRINCIPAL_ROLE:role",
  "PRINCIPAL_ROLE:missing-role"
])("native admission: %s", async (caseName) => {
  const [modelRaw, fault] = caseName.split(":");
  const model = modelRaw as "legacy-incomplete" | "TENANT_AWARE" | "PRINCIPAL_ROLE";
  const root = createOwnedTestDirectory("collection22-admission");
  const wire: string[] = [];
  const server = createServer((req, res) => {
    wire.push(req.url ?? "");
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify(
        req.url === "/identity"
          ? {
              id: fault === "principal" ? "foreign" : "generated-person",
              role: fault === "missing-role" ? undefined : fault === "role" ? "admin" : "user",
              tenant: fault === "tenant" ? "foreign-tenant" : "generated-tenant"
            }
          : { id: "generated-object" }
      )
    );
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  try {
    const origin = "http://127.0.0.1:" + (server.address() as AddressInfo).port;
    const save = (name: string, value: unknown) => {
      const p = join(root, name + ".json");
      writeFileSync(p, JSON.stringify(value), { flag: "wx" });
      return p;
    };
    const explicit = model !== "legacy-incomplete";
    const scope = save("scope", {
      ...exampleScope,
      allowedDomains: ["127.0.0.1"],
      disallowedPaths: [],
      allowedMethods: ["GET"],
      rateLimitPerSecond: 50,
      concurrency: 1
    });
    const auth = save("profile", {
      label: "generated",
      principalId: "generated-person",
      ...(explicit
        ? { identityModel: model, role: "user", ...(model === "TENANT_AWARE" ? { tenantId: "generated-tenant" } : {}) }
        : {}),
      headers: { Authorization: "Bearer synthetic-owned" },
      identityVerification: {
        mode: "required",
        endpoint: origin + "/identity",
        principalIdField: "id",
        ...(explicit ? { roleField: "role", ...(model === "TENANT_AWARE" ? { tenantIdField: "tenant" } : {}) } : {})
      }
    });
    const apiGraphql = save("manifest", {
      actors: [
        {
          id: "actor",
          safeAlias: "actor",
          authSlot: "primary",
          relationship: "OWNER",
          principalId: "generated-person",
          role: "user",
          ...(model !== "PRINCIPAL_ROLE" ? { tenantId: "generated-tenant" } : {}),
          ...(explicit ? { identityModel: model } : {})
        }
      ],
      routes: [
        {
          id: "object",
          safeAlias: "object",
          protocol: "REST",
          kind: "OBJECT",
          objectType: "fixture",
          url: origin + "/object",
          pathTemplate: "/object"
        }
      ],
      checks: [
        {
          id: "check",
          matrixId: "matrix",
          label: "owned bounded check",
          kind: "OBJECT_AUTHORIZATION",
          actorId: "actor",
          routeId: "object",
          requireVerifiedIdentity: true,
          request: { method: "GET" },
          response: { expectedDecision: "OBSERVE" }
        }
      ]
    });
    const result = await runScanCommand(origin + "/", {
      scope,
      auth,
      apiGraphql,
      includeModules: ["api-graphql-authorization"],
      replaceProfileModules: true,
      output: join(root, "reports"),
      historyDirectory: join(root, "history"),
      suppressProcessExitCode: true
    });
    const report = JSON.parse(readFileSync(result.reportPath, "utf8")) as RouteCairnReport;
    const actor = report.scanPlan?.apiGraphql?.actors[0];
    const proof = report.identityVerification?.primary;
    const strict = nativeApplicationProofMatches(actor, proof);
    save("receipt", { wire, report, strict, root });
    if (fault) {
      expect(proof?.verified).toBe(false);
      expect(strict).toBe(false);
      expect(wire).not.toContain("/object");
      expect(report.apiGraphql?.checks[0]?.outcome).toBe("BLOCKED");
    } else if (!explicit) {
      expect(proof?.verified).toBe(true);
      expect(strict).toBe(false);
      expect(wire).not.toContain("/object");
      expect(report.apiGraphql?.checks[0]?.outcome).toBe("BLOCKED");
    } else {
      expect(strict).toBe(true);
      expect(wire).toContain("/object");
    }
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
    retainOwnedTestDirectory(root);
  }
});
