import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { exampleScope, defaultConfig } from "../../src/config/defaults.js";
import { RouteCairnEngine } from "../../src/core/engine/RouteCairnEngine.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import { activeVulnerabilityInputSchema, planActiveVulnerabilityValidation } from "../../src/modules/activeVulnerability/ActiveVulnerabilityPlanner.js";
import { createOastLab } from "../helpers/oast-lab.js";

const pythonPath = process.env.ROUTECAIRN_OAST_PYTHON_PATH;
const cells = (["SSRF", "XXE", "COMMAND_INJECTION", "TEMPLATE_INJECTION"] as const).flatMap((kind) => (kind === "COMMAND_INJECTION" && process.platform === "win32" ? ["HTTP"] as const : ["HTTP", "HTTPS"] as const).flatMap((protocol) => [false, true].map((secure) => ({ kind, protocol, secure }))));
const retained: unknown[] = [];
let lab: Awaited<ReturnType<typeof createOastLab>>;
let target: ReturnType<typeof createServer>; let origin = "";
const receiptFailures: string[] = []; const receipts: { runtime: string; executions: number }[] = [];

describe.skipIf(!pythonPath)("active OAST real parser, shell and template runtime proof", () => {
  beforeAll(async () => {
    lab = await createOastLab(); process.env.RC_OAST_RUNTIME_TOKEN = lab.token; process.env.RC_OAST_RUNTIME_CA = lab.ca;
    target = createServer(async (request, response) => {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (url.pathname !== "/execute") { response.writeHead(200).end("owned runtime fixture"); return; }
      const kind = url.searchParams.get("kind"), secure = url.searchParams.get("secure") === "true", protocol = url.searchParams.get("protocol");
      if (!["SSRF", "XXE", "COMMAND_INJECTION", "TEMPLATE_INJECTION"].includes(kind ?? "") || !["HTTP", "HTTPS"].includes(protocol ?? "")) { response.writeHead(400).end(); return; }
      const input = { kind, secure, payload: url.searchParams.get("value") ?? "", origin: protocol === "HTTPS" ? lab.httpsOrigin : lab.httpOrigin, caPath: protocol === "HTTPS" ? lab.caPath : null };
      try {
        // Delayed execution forces polling to correlate after the target response.
        await new Promise((done) => setTimeout(done, 120));
        const receipt = await executePython(input); receipts.push(receipt);
        response.writeHead(200).end("accepted");
      } catch { receiptFailures.push(`${kind}:${protocol}`); response.writeHead(500).end("runtime failed"); }
    });
    await new Promise<void>((done) => target.listen(0, "127.0.0.1", done)); origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`;
  }, 15000);
  afterAll(async () => {
    if (target) { target.closeAllConnections(); await new Promise<void>((done) => target.close(() => done())); }
    if (lab) await lab.stop(); delete process.env.RC_OAST_RUNTIME_TOKEN; delete process.env.RC_OAST_RUNTIME_CA;
    if (process.env.ROUTECAIRN_OAST_LAB_OUTPUT) {
      const output = resolve(process.env.ROUTECAIRN_OAST_LAB_OUTPUT); await mkdir(output, { recursive: true });
      await writeFile(join(output, "runtime-proof.json"), `${JSON.stringify({ schemaVersion: 1, generatedAt: new Date().toISOString(), provenance: "SELF_MAINTAINED_LOOPBACK", externalTargetsTested: false, independentlyOperated: false, cleanup: "CONFIRMED", runtimeFailures: receiptFailures, cases: retained }, null, 2)}\n`);
    }
  });
  it.each(cells)("$kind / $protocol / secure=$secure", async ({ kind, protocol, secure }) => {
    const before = receipts.length;
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"] as const, rateLimitPerSecond: 50, concurrency: 2 };
    const input = activeVulnerabilityInputSchema.parse({ schemaVersion: 1, maxRequests: 3, maxCases: 1, discovery: { enabled: false, classes: [], maxCandidates: 0, queryParametersOnly: true, includeAuthenticated: false },
      oast: { mode: "SELF_HOSTED", apiBaseUrl: lab.httpsOrigin, apiTokenEnv: "RC_OAST_RUNTIME_TOKEN", tlsCaEnv: "RC_OAST_RUNTIME_CA", tenantId: lab.tenantId, workerId: "runtime-worker", jobId: "runtime-job", leaseSeconds: 60, pollIntervalMs: 100, maxPolls: 3, protocols: [protocol] },
      cases: [{ id: `runtime-${kind.toLowerCase()}-${protocol.toLowerCase()}-${secure ? "secure" : "vulnerable"}`, label: "Owned runtime proof", vulnerabilityClass: kind, actorId: "anonymous", environment: "LOCAL_FIXTURE", request: { url: `${origin}/execute?kind=${kind}&protocol=${protocol}&secure=${secure}&value=fixture`, method: "GET", headers: {}, injection: { location: "QUERY", name: "value", originalValue: "fixture" }, operatorConfirmedNonMutating: false }, proof: { oastProtocol: protocol, ...(kind === "COMMAND_INJECTION" ? { commandDialect: process.platform === "win32" ? "POWERSHELL" : "POSIX_SH" } : {}), ...(kind === "TEMPLATE_INJECTION" ? { templateDialect: "JINJA2" } : {}) }, strategy: { profile: "DEEP", techniques: ["OAST_CALLBACK"], encodings: ["PLAIN"], maxStrategies: 1, approvedRisks: ["OUT_OF_BAND_CALLBACK"] } }] });
    const activeVulnerability = planActiveVulnerabilityValidation(input, { target: `${origin}/`, scope });
    const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({ requestedProfile: "quick", scope, config: defaultConfig, activeVulnerability, overrides: { includeModules: ["api-mapper", "parameter-analysis", "active-vulnerability-validation"] } });
    const result = await new RouteCairnEngine().scan({ target: `${origin}/`, scope, config: defaultConfig, plan, outputDir: join(lab.directory, input.cases[0]!.id) });
    const bytes = await readFile(result.reportPath, "utf8"); const report = JSON.parse(bytes); const observation = report.activeVulnerability.cases[0];
    expect(receiptFailures).toEqual([]); expect(receipts.slice(before)).toHaveLength(3); expect(receipts.slice(before).reduce((sum, receipt) => sum + receipt.executions, 0)).toBe(secure ? 0 : 1);
    expect(observation.outcome).toBe(secure ? "INCONCLUSIVE" : "PROVEN"); expect(observation.cleanup).toBe("CONFIRMED");
    if (!secure) { expect(observation.reasonCode).toBe("SIGNED_OAST_CALLBACK_CONFIRMED"); expect(observation.oastEvidence.protocol).toBe(protocol); expect(observation.oastEvidence.delayMs).toBeGreaterThanOrEqual(100); }
    for (const secret of [lab.token, lab.tenantId, "runtime-worker", "runtime-job", "/c/", "pollToken"]) expect(bytes).not.toContain(secret);
    retained.push({ kind, protocol, fixture: secure ? "SECURE_CONTROL" : "VULNERABLE", runtime: receipts.at(-1)!.runtime, outcome: observation.outcome, reasonCode: observation.reasonCode, cleanup: observation.cleanup, ...(observation.oastEvidence ? { evidence: observation.oastEvidence } : {}), reportSha256: createHash("sha256").update(bytes).digest("hex") });
  }, 30000);
});

function executePython(input: unknown): Promise<{ runtime: string; executions: number }> {
  return new Promise((done, reject) => {
    const child = spawn(process.env.ROUTECAIRN_PYTHON ?? "python", [resolve("tests/helpers/oast-runtime.py")], { windowsHide: true, env: { ...process.env, PYTHONPATH: resolve(pythonPath!) }, stdio: ["pipe", "pipe", "pipe"] }); let output = "", errors = "";
    const timer = setTimeout(() => { child.kill(); reject(new Error("OAST_RUNTIME_TIMEOUT")); }, 8000);
    child.stdout.on("data", (value) => { output += String(value); if (output.length > 4096) child.kill(); }); child.stderr.on("data", (value) => { errors += String(value); if (errors.length > 4096) child.kill(); });
    child.once("error", (error) => { clearTimeout(timer); reject(error); }); child.once("exit", (code) => { clearTimeout(timer); if (code !== 0) { reject(new Error("OAST_RUNTIME_FAILED")); return; } try { done(JSON.parse(output)); } catch { reject(new Error("OAST_RUNTIME_RECEIPT_INVALID")); } }); child.stdin.end(JSON.stringify(input));
  });
}
