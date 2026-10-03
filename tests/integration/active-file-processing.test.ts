import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { ActiveVulnerabilityModule } from "../../src/modules/activeVulnerability/ActiveVulnerabilityModule.js";
import { activeVulnerabilityInputSchema, planActiveVulnerabilityValidation } from "../../src/modules/activeVulnerability/ActiveVulnerabilityPlanner.js";

const formats = ["ZIP", "TAR", "TAR_GZIP", "XML", "SVG", "CSV", "JSON", "PDF"] as const;
const retained: unknown[] = []; let server: Server; let origin: string; const receipts = new Map<string, unknown>();
const parse = async (value: unknown): Promise<Record<string, unknown>> => await new Promise((done, reject) => {
  const child = spawn(process.env.ROUTECAIRN_PYTHON ?? "python", [resolve("tests/helpers/active-file-parser.py")], { windowsHide: true, env: { ...process.env, ...(process.env.ROUTECAIRN_PYPDF_PATH ? { PYTHONPATH: process.env.ROUTECAIRN_PYPDF_PATH } : {}) }, stdio: ["pipe", "pipe", "pipe"] }); let output = "", size = 0;
  const timer = setTimeout(() => { child.kill(); reject(new Error("PARSER_TIMEOUT")); }, 3000);
  child.stdout.on("data", (chunk) => { size += chunk.length; if (size > 8192) { child.kill(); reject(new Error("PARSER_OUTPUT_LIMIT")); } else output += chunk; }); child.stderr.resume(); child.on("error", reject);
  child.on("close", (code) => { clearTimeout(timer); try { if (code !== 0) throw new Error("PARSER_FAILED"); done(JSON.parse(output)); } catch (error) { reject(error); } }); child.stdin.end(JSON.stringify(value));
});
beforeAll(async () => {
  server = createServer(async (req, res) => { const url = new URL(req.url ?? "/", origin); const key = url.pathname.split("/")[1]!;
    try {
      if (url.pathname.endsWith("/upload")) { let body = ""; for await (const chunk of req) { body += chunk; if (body.length > 131072) throw new Error("BODY_LIMIT"); } const value = JSON.parse(body); const receipt = await parse(value); receipts.set(key, receipt); res.writeHead(200).end("accepted"); return; }
      if (url.pathname.endsWith("/verify")) { res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ receipt: receipts.get(key) ?? { observed: false } })); return; }
      if (url.pathname.endsWith("/cleanup")) { const receipt = receipts.get(key) as { canary?: string } | undefined; if (receipt?.canary && receipt.canary !== url.searchParams.get("routecairn_canary")) { res.writeHead(409).end(); return; } receipts.delete(key); res.writeHead(204).end(); return; }
      res.writeHead(404).end();
    } catch { res.writeHead(400).end("parser-rejected"); }
  }); await new Promise<void>((done) => server.listen(0, "127.0.0.1", done)); origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(async () => { server.closeAllConnections(); await new Promise<void>((done) => server.close(() => done())); if (process.env.ROUTECAIRN_ACTIVE_LAB_OUTPUT) { const directory = resolve(process.env.ROUTECAIRN_ACTIVE_LAB_OUTPUT); await mkdir(directory, { recursive: true }); const bytes = Buffer.from(`${JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString(), provenance: "SELF_MAINTAINED_LOOPBACK_POLICIES_INDEPENDENT_PARSERS", externalTargetsTested: false, independentlyOperated: false, parserImplementations: ["Python zipfile", "Python tarfile", "Python ElementTree", "Python csv", "Python json", "pypdf@6.19.0", "Playwright Chromium"], policySimulation: true, cleanup: receipts.size === 0 ? "CONFIRMED" : "FAILED", cases: retained }, null, 2)}\n`); await writeFile(resolve(directory, "file-processing.json"), bytes); await writeFile(resolve(directory, "file-SHA256SUMS"), `${createHash("sha256").update(bytes).digest("hex")}  file-processing.json\n`); } });
describe("file-processing engine with independent parsers", () => {
  for (const format of formats) for (const technique of (["ZIP", "TAR", "TAR_GZIP"].includes(format) ? ["ARCHIVE_CANARY", "ARCHIVE_SYMLINK", "ARCHIVE_DUPLICATE_ENTRY"] : ["PARSER_CANARY"])) for (const secure of [true, false]) {
    it.skipIf(format === "PDF" && !process.env.ROUTECAIRN_PYPDF_PATH)(`${format} ${technique} ${secure ? "secure" : "vulnerable"} validates effects and cleanup`, async () => {
      const effect = technique === "ARCHIVE_CANARY" ? "PATH_ESCAPE" : technique === "ARCHIVE_SYMLINK" ? "SYMLINK_ESCAPE" : technique === "ARCHIVE_DUPLICATE_ENTRY" ? "DUPLICATE_ENTRY_POLICY_BYPASS" : ({ XML: "ENTITY_EXPANSION", SVG: "SCRIPT_EXECUTION", CSV: "FORMULA_INTERPRETATION", JSON: "DUPLICATE_KEY_POLICY_BYPASS", PDF: "DUPLICATE_KEY_POLICY_BYPASS" } as Record<string, string>)[format];
      const id = `${format}-${technique}-${secure}`; const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "POST", "DELETE"] as const, rateLimitPerSecond: 100, concurrency: 1 };
      const input = activeVulnerabilityInputSchema.parse({ maxRequests: 6, discovery: { enabled: false, maxCandidates: 0 }, cases: [{ id, label: id, vulnerabilityClass: "FILE_PROCESSING", actorId: "anonymous", environment: "LOCAL_FIXTURE", request: { url: `${origin}/${id}/upload`, method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ format, effect, secure, data: "safe" }), injection: { location: "JSON_FIELD", name: "data", originalValue: "safe" } }, proof: { fileFormat: format, fileEffect: { jsonPath: "receipt", effect }, marker: "RC-FILE-PROOF", archiveEntry: "fixture.txt", maxExpandedBytes: 4096, verificationUrl: `${origin}/${id}/verify`, cleanupUrl: `${origin}/${id}/cleanup`, cleanupMethod: "DELETE" }, strategy: { techniques: [technique], approvedRisks: ["PASSIVE_DIFFERENTIAL", "STATEFUL_CANARY"] } }] });
      const active = planActiveVulnerabilityValidation(input, { target: origin, scope }); const base = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "quick", scope, config: defaultConfig, activeVulnerability: active }); const context = new ScanContext({ target: origin, scope, config: defaultConfig, plan: { ...base, activeVulnerability: active }, outputDir: ".routecairn-active-lab" });
      try { const result = await new ActiveVulnerabilityModule().run(context); const observation = result.activeVulnerability!.cases[0]!; retained.push({ format, technique, secure, outcome: observation.outcome, reasonCode: observation.reasonCode, cleanup: observation.cleanup, requests: observation.requests.length }); expect(observation.cleanup).toBe("CONFIRMED"); expect(observation.outcome, observation.reasonCode).toBe(secure ? "INCONCLUSIVE" : "PROVEN"); expect(receipts.size).toBe(0); expect(JSON.stringify(result)).not.toContain("renderedHtml"); } finally { await context.dispose(); }
    }, 15000);
  }
});
