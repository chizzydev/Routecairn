import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { exampleScope } from "../../src/config/defaults.js";
import type { SecretBoundaryReport } from "../../src/reports/SecretBoundaryReport.js";
import { classifyTransientSecret } from "../../src/modules/secretBoundary/SecretBoundaryClassifier.js";

let server: Server | undefined;
const directories: string[] = [];

afterEach(async () => {
  if (server) await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve()));
  server = undefined;
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("secret-boundary integration", () => {
  it("uses field-token boundaries when classifying personal data", () => {
    expect(classifyTransientSecret({
      name: "className",
      value: "rounded-lg border border-slate-200",
      surface: "JAVASCRIPT_BUNDLE",
      publicExposure: true
    })).toMatchObject({ materialClass: "NON_SENSITIVE", findingEligible: false });

    expect(classifyTransientSecret({
      name: "socialSecurityNumber",
      value: "000-00-0000",
      surface: "API_RESPONSE",
      publicExposure: true
    })).toMatchObject({
      materialClass: "PERSONAL_DATA",
      findingEligible: true,
      reasonCode: "HIGH_SENSITIVITY_FIELD_NAME"
    });
  });

  it("correlates every server/client exposure surface without retaining values or misclassifying public keys", async () => {
    const secrets = {
      service: jwt({ role: "service_role", ref: "project-ref" }),
      anon: jwt({ role: "anon", ref: "project-ref" }),
      database: "postgres://routecairn:private-password@db.internal/app",
      github: "ghp_abcdefghijklmnopqrstuvwxyz123456",
      jwtSecret: "jwt-secret-private-887711",
      access: "access-token-private-771188",
      dbPassword: "db-password-private-551199",
      session: "session-cookie-private-991144",
      ssn: "123-45-6789",
      privateEmail: "private-person@example.test"
    };
    server = createServer((request, response) => {
      const path = new URL(request.url ?? "/", "http://localhost").pathname;
      if (path === "/") return send(response, 200, "text/html", `<!doctype html><script>window.__ENV__={"NEXT_PUBLIC_SUPABASE_ANON_KEY":"${secrets.anon}","NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY":"${secrets.service}"}</script><script src="/app.js"></script>`, { "set-cookie": `session_id=${secrets.session}; Secure; SameSite=Lax` });
      if (path === "/app.js") return send(response, 200, "application/javascript", `VITE_SUPABASE_ANON_KEY="${secrets.anon}"; PUBLIC_STRIPE_KEY="pk_test_publishable123"; DATABASE_URL="${secrets.database}"; //# sourceMappingURL=/app.js.map`);
      if (path === "/app.js.map") return send(response, 200, "application/json", JSON.stringify({ version: 3, sources: ["src/app.ts"], sourcesContent: [`const GITHUB_TOKEN="${secrets.github}";`], names: [], mappings: "" }));
      if (path === "/config.json" || path === "/runtime-config.js" || path === "/env.js") return send(response, 200, "application/json", JSON.stringify({ SUPABASE_PUBLISHABLE_KEY: "sb_publishable_example12345", apiBaseUrl: "/api" }));
      if (path === "/asset-manifest.json" || path === "/build-info.json") return send(response, 200, "application/json", JSON.stringify({ BUILD_ID: "build-991", COMMIT_SHA: "abcdef123456" }));
      if (path === "/api/config") return send(response, 200, "application/json", JSON.stringify({ ssn: secrets.ssn }));
      if (path === "/debug") return send(response, 200, "application/json", JSON.stringify({ BUILD_NUMBER: "552" }));
      if (path === "/debug/config") return send(response, 500, "application/json", JSON.stringify({ JWT_SECRET: secrets.jwtSecret }));
      if (path === "/debug.log") return send(response, 200, "text/plain", `ACCESS_TOKEN=${secrets.access}`);
      if (path === "/error.log") return send(response, 200, "text/plain", `DB_PASSWORD=${secrets.dbPassword}`);
      if (path === "/server.log") return send(response, 200, "text/plain", "BUILD_ID=build-991");
      if (path === "/graphql") return send(response, 200, "application/json", JSON.stringify({ data: { viewer: { privateEmail: secrets.privateEmail } } }));
      response.writeHead(404, { "content-type": "text/plain" }); response.end("not found");
    });
    await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const directory = await mkdtemp(join(tmpdir(), "routecairn-secret-boundary-")); directories.push(directory);
    const scopePath = join(directory, "scope.json");
    await writeFile(scopePath, JSON.stringify({ ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 50, concurrency: 4 }), "utf8");
    const result = await runScanCommand(`${origin}/`, { scope: scopePath, profile: "quick", secretBoundary: true, output: join(directory, "report") });
    const raw = await readFile(result.reportPath, "utf8"); const markdown = await readFile(result.markdownReportPath, "utf8"); const html = await readFile(result.htmlReportPath, "utf8");
    const report = JSON.parse(raw) as { secretBoundary: SecretBoundaryReport; findings: Array<{ type: string; sourceModule: string }> };
    expect(report.secretBoundary).toMatchObject({ enabled: true, schemaVersion: 1, additionalRequestsUsed: 12, sourceMapsReviewed: 1, confirmedFindings: expect.any(Number), supabase: { anonKeys: expect.any(Number), publishableKeys: expect.any(Number), serviceRoleKeys: expect.any(Number), distinctionEnforced: true } });
    expect(report.secretBoundary.confirmedFindings).toBeGreaterThanOrEqual(7);
    expect(report.secretBoundary.supabase.anonKeys).toBeGreaterThan(0); expect(report.secretBoundary.supabase.publishableKeys).toBeGreaterThan(0); expect(report.secretBoundary.supabase.serviceRoleKeys).toBeGreaterThan(0);
    expect(report.secretBoundary.clientSafeNameConflicts).toBeGreaterThan(0);
    for (const surface of ["HTML", "JAVASCRIPT_BUNDLE", "SOURCE_MAP", "RUNTIME_CONFIGURATION", "ERROR_RESPONSE", "API_RESPONSE", "COOKIE", "BUILD_METADATA", "DEBUG_ENDPOINT", "GRAPHQL_RESPONSE", "PUBLIC_LOG"] as const) expect(report.secretBoundary.coverage[surface].sourcesObserved).toBeGreaterThan(0);
    expect(report.secretBoundary.observations).toEqual(expect.arrayContaining([
      expect.objectContaining({ materialClass: "SUPABASE_ANON_KEY", outcome: "EXPECTED_PUBLIC_CLIENT_MATERIAL" }),
      expect.objectContaining({ materialClass: "SUPABASE_SERVICE_ROLE_KEY", outcome: "CONFIRMED_SENSITIVE_EXPOSURE", clientSafeNameConflict: true }),
      expect.objectContaining({ materialClass: "PUBLISHABLE_CLIENT_KEY", boundary: "CLIENT_SAFE" }),
      expect.objectContaining({ materialClass: "DATABASE_CREDENTIAL", impact: "CRITICAL" }),
      expect.objectContaining({ materialClass: "USER_SESSION_SECRET", surface: "COOKIE", outcome: "CLIENT_STORAGE_RISK" }),
      expect.objectContaining({ materialClass: "PERSONAL_DATA", surface: "GRAPHQL_RESPONSE", outcome: "SENSITIVE_FIELD_EXPOSURE" }),
      expect.objectContaining({ materialClass: "INTERNAL_METADATA", impact: "INFORMATIONAL" })
    ]));
    expect(report.findings.filter((finding) => finding.sourceModule === "secret-boundary").map((finding) => finding.type)).toEqual(expect.arrayContaining(["Server Credential Exposure", "Session Secret Exposure", "Client-Side Session Secret Exposure", "Sensitive Response Exposure"]));
    const serialized = `${raw}\n${markdown}\n${html}`;
    for (const secret of Object.values(secrets)) expect(serialized).not.toContain(secret);
    expect(markdown).toContain("## Secret Boundary and Sensitive Exposure"); expect(html).toContain("Secret Boundary and Sensitive Exposure");
  }, 30000);
});

function send(response: Parameters<Parameters<typeof createServer>[0]>[1], status: number, contentType: string, body: string, headers: Record<string, string> = {}): void { response.writeHead(status, { "content-type": contentType, ...headers }); response.end(body); }
function jwt(payload: Record<string, unknown>): string { return `${Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.signatureplaceholder`; }
