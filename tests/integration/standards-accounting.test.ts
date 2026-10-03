import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { RouteCairnEngine } from "../../src/core/engine/RouteCairnEngine.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { activeVulnerabilityInputSchema, planActiveVulnerabilityValidation } from "../../src/modules/activeVulnerability/ActiveVulnerabilityPlanner.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { validateStandardsCoverage } from "../../src/standards/StandardsCoverageValidation.js";

let server: Server | undefined; let directory: string | undefined;
afterEach(async () => { if (server) { server.closeAllConnections(); await new Promise<void>((done) => server!.close(() => done())); server = undefined; } if (directory) { await rm(directory, { recursive: true, force: true }); directory = undefined; } });

describe("operational strict standards accounting", () => {
  it("executes real HTTP cases, writes validated reports, verifies the installed CLI contract and rejects edited exports", async () => {
    let requests = 0;
    server = createServer((request, response) => {
      requests++; const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (url.pathname === "/vulnerable" && url.searchParams.get("q")?.includes("'")) return void response.writeHead(500, { "content-type": "text/plain" }).end("SQL syntax error");
      response.writeHead(200, { "content-type": "text/plain" }).end("bounded-fixture-result");
    });
    await new Promise<void>((done) => server!.listen(0, "127.0.0.1", done));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    directory = await mkdtemp(join(tmpdir(), "routecairn-standards-runtime-"));
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"] as const, rateLimitPerSecond: 100, concurrency: 1 };
    const input = activeVulnerabilityInputSchema.parse({ schemaVersion: 1, maxRequests: 16, maxCases: 2, actors: [{ id: "public", safeAlias: "Public", authSlot: "anonymous", relationship: "PUBLIC" }], discovery: { enabled: false, classes: [], maxCandidates: 0, queryParametersOnly: true, includeAuthenticated: false }, cases: ["vulnerable", "secure"].map((id) => ({ id, label: `${id} SQL control`, vulnerabilityClass: "SQL_INJECTION", actorId: "public", environment: "LOCAL_FIXTURE", request: { url: `${origin}/${id}?q=control`, method: "GET", headers: {}, injection: { location: "QUERY", name: "q", originalValue: "control" }, operatorConfirmedNonMutating: false }, proof: { allowedRedirectOrigins: [], secureStatuses: [], vulnerableStatuses: [] } })) });
    const activeVulnerability = planActiveVulnerabilityValidation(input, { target: `${origin}/`, scope });
    const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "quick", scope, config: defaultConfig, activeVulnerability, overrides: { includeModules: ["baseline", "api-mapper", "parameter-analysis", "active-vulnerability-validation"] } });
    const result = await new RouteCairnEngine().scan({ target: `${origin}/`, scope, config: defaultConfig, plan, outputDir: join(directory, "scan") });
    const report = JSON.parse(await readFile(result.reportPath, "utf8")) as RouteCairnReport;
    expect(report.activeVulnerability?.cases.find((item) => item.caseId === "vulnerable")?.outcome).toBe("PROVEN");
    expect(report.activeVulnerability?.cases.find((item) => item.caseId === "secure")?.outcome).toBe("SECURE_FOR_CASE");
    expect(requests).toBeGreaterThan(3);
    expect(() => validateStandardsCoverage(report.standardsCoverage)).not.toThrow();
    const coveragePath = join(directory, "scan/standards-coverage.json");
    const cli = ["--import", "tsx", "src/cli/index.ts"];
    const verification = await run([...cli, "standards", "verify", "--output", join(directory, "verification.json")]);
    expect(verification.code).toBe(0); expect(verification.stdout).toContain('"builtInMappings":111');
    const valid = await run([...cli, "standards", "validate-report", "--input", result.reportPath, "--output-dir", join(directory, "validated")]);
    expect(valid.code).toBe(0); expect(valid.stdout).toContain('"unmappedCases":0');
    const edited = JSON.parse(await readFile(coveragePath, "utf8")); edited.accounting.unmappedCases = 1;
    const editedPath = join(directory, "edited.json"); await writeFile(editedPath, JSON.stringify(edited));
    const rejected = await run([...cli, "standards", "validate-report", "--input", editedPath]);
    expect(rejected.code).toBe(1);
    const markdown = await readFile(result.markdownReportPath, "utf8"); const html = await readFile(result.htmlReportPath, "utf8");
    expect(markdown).toContain("Catalog Denominators"); expect(html).toContain("Catalog denominators");
    if (process.env.ROUTECAIRN_STANDARDS_PROOF) {
      const output = resolve(process.env.ROUTECAIRN_STANDARDS_PROOF); await mkdir(output, { recursive: true });
      const files: Record<string, string> = {};
      for (const [name, path] of [["report.json", result.reportPath], ["report.md", result.markdownReportPath], ["report.html", result.htmlReportPath], ["standards-coverage.json", coveragePath], ["standards-coverage.csv", join(directory, "scan/standards-coverage.csv")], ["standards-verification.json", join(directory, "verification.json")]]) {
        const bytes = await readFile(path!); await writeFile(join(output, name!), bytes, { flag: "wx" }); files[name!] = createHash("sha256").update(bytes).digest("hex");
      }
      await writeFile(join(output, "runtime-proof.json"), `${JSON.stringify({ schemaVersion: 1, provenance: "SELF_MAINTAINED_LOOPBACK", realHttpRequests: requests, vulnerableOutcome: "PROVEN", secureOutcome: "SECURE_FOR_CASE", cliVerify: verification.code, cliValidate: valid.code, cliRejectEdited: rejected.code, catalogSha256: report.standardsCoverage!.catalog.sha256, mappingsSha256: report.standardsCoverage!.validation.mappingSha256, files }, null, 2)}\n`, { flag: "wx" });
    }
  }, 60_000);
});
async function run(args: string[]): Promise<{ code: number; stdout: string }> {
  return new Promise((done, reject) => { const child = spawn(process.execPath, args, { cwd: process.cwd(), windowsHide: true, stdio: ["ignore", "pipe", "pipe"] }); let stdout = ""; child.stdout.on("data", (chunk) => { stdout += String(chunk); }); child.stderr.resume(); child.on("error", reject); child.on("exit", (code) => done({ code: code ?? 1, stdout })); });
}
