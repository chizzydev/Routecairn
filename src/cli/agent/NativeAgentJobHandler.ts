import { createHash } from "node:crypto";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { z } from "zod";
import { scanModeSchema } from "../../config/ConfigSchema.js";
import { scanProfileNameSchema } from "../../config/ScanProfiles.js";
import { moduleCatalog } from "../../core/planning/ModuleCatalog.js";
import type { ModuleId } from "../../core/planning/ScanPlan.js";
import { loadReport } from "../../reports/ReportSummary.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { HtmlReportWriter } from "../../reports/HtmlReportWriter.js";
import { JsonReportWriter } from "../../reports/JsonReportWriter.js";
import { MarkdownReportWriter } from "../../reports/MarkdownReportWriter.js";
import { runScanCommand, type ScanCommandOptions } from "../commands/scan.js";

export interface NativeAgentJob { id: string; kind: string; payload: Record<string, unknown> }
export interface NativeAgentContext { signal: AbortSignal; workspace: string }

const localPath = z.string().trim().min(1).max(2000).refine((value) => !isAbsolute(value), "Agent paths must be relative to the workspace.");
const moduleIds = Object.keys(moduleCatalog) as [ModuleId, ...ModuleId[]];
const moduleIdSchema = z.enum(moduleIds);

const scanPayloadObject = z.object({
  schemaVersion: z.literal(1).default(1),
  target: z.string().url().refine((value) => ["http:", "https:"].includes(new URL(value).protocol), "HTTP(S) target required."),
  scopePath: localPath,
  outputPath: localPath.optional(),
  configPath: localPath.optional(),
  profile: scanProfileNameSchema.optional(),
  mode: scanModeSchema.optional(),
  rate: z.number().positive().max(10_000).optional(),
  concurrency: z.number().int().positive().max(100).optional(),
  maxRequests: z.number().int().positive().max(1_000_000).optional(),
  cleanupReservedRequests: z.number().int().nonnegative().max(1_000_000).optional(),
  authPath: localPath.optional(), authAPath: localPath.optional(), authBPath: localPath.optional(),
  objectPairsPath: localPath.optional(), fieldExposurePath: localPath.optional(), authorizationMatrixPath: localPath.optional(),
  collectionAuthorizationPath: localPath.optional(), bulkAuthorizationPath: localPath.optional(), fileAuthorizationPath: localPath.optional(), equivalentRoutesPath: localPath.optional(),
  privilegeMutationPath: localPath.optional(), mutationContractsPath: localPath.optional(), supabaseAuthorizationPath: localPath.optional(),
  authenticationLifecyclePath: localPath.optional(), authenticationLifecycleAutoPath: localPath.optional(), businessInvariantsPath: localPath.optional(), controlledRacesPath: localPath.optional(),
  apiGraphqlPath: localPath.optional(), protocolSecurityPath: localPath.optional(), linkPortalSecurityPath: localPath.optional(), operationalEndpointsPath: localPath.optional(), billingEntitlementPath: localPath.optional(),
  assistedReviewPath: localPath.optional(), preHandoverPath: localPath.optional(), grantPath: localPath.optional(), activeVulnerabilityPath: localPath.optional(), inventoryImportPath: localPath.optional(),
  secretBoundary: z.boolean().default(false),
  modules: z.array(moduleIdSchema).min(1).max(moduleIds.length).optional()
}).strict();
const validateScanPayload = (value: z.infer<typeof scanPayloadObject>, context: z.RefinementCtx): void => {
  if ((value.authAPath && !value.authBPath) || (!value.authAPath && value.authBPath)) context.addIssue({ code: z.ZodIssueCode.custom, path: ["authAPath"], message: "Account-pair jobs require both authAPath and authBPath." });
  if (value.cleanupReservedRequests !== undefined && value.maxRequests !== undefined && value.cleanupReservedRequests > value.maxRequests) context.addIssue({ code: z.ZodIssueCode.custom, path: ["cleanupReservedRequests"], message: "Cleanup reserve cannot exceed the request budget." });
};
const scanPayloadSchema = scanPayloadObject.superRefine(validateScanPayload);

const modulePayloadSchema = scanPayloadObject.extend({ modules: z.array(moduleIdSchema).min(1).max(moduleIds.length) }).strict().superRefine(validateScanPayload);
const exportPayloadSchema = z.object({ schemaVersion: z.literal(1).default(1), reportPath: localPath, outputPath: localPath.optional(), format: z.enum(["JSON", "MARKDOWN", "HTML", "SARIF", "JUNIT", "BURP_XML"]) }).strict();

export const nativeAgentCapabilities = ["ping", "scan", "module", "export"] as const;

export async function handleNativeAgentJob(job: NativeAgentJob, context: NativeAgentContext): Promise<Record<string, unknown>> {
  const workspace = await ensureWorkspace(context.workspace);
  if (job.kind === "PING") return { pong: true, at: new Date().toISOString(), runtime: `node-${process.version}`, platform: process.platform, architecture: process.arch };
  if (job.kind === "SCAN") return runNativeScan(job.id, scanPayloadSchema.parse(job.payload), workspace, context.signal, false);
  if (job.kind === "MODULE") return runNativeScan(job.id, modulePayloadSchema.parse(job.payload), workspace, context.signal, true);
  if (job.kind === "EXPORT") return runNativeExport(job.id, exportPayloadSchema.parse(job.payload), workspace);
  throw new Error(`Unsupported native agent job kind: ${job.kind.slice(0, 80)}`);
}

async function runNativeScan(jobId: string, payload: z.infer<typeof scanPayloadSchema>, workspace: string, signal: AbortSignal, moduleOnly: boolean): Promise<Record<string, unknown>> {
  const path = (value: string): Promise<string> => existingWorkspacePath(workspace, value);
  const outputDir = await prepareOutput(workspace, payload.outputPath ?? `jobs/${jobId}/scan`);
  const options: ScanCommandOptions = {
    scope: await path(payload.scopePath), output: outputDir,
    config: payload.configPath ? await path(payload.configPath) : resolveWorkspacePath(workspace, "routecairn.config.json"),
    historyDirectory: resolveWorkspacePath(workspace, ".routecairn"),
    suppressProcessExitCode: true,
    ...(payload.profile ? { profile: payload.profile } : {}), ...(payload.mode ? { mode: payload.mode } : {}),
    ...(payload.rate !== undefined ? { rate: String(payload.rate) } : {}), ...(payload.concurrency !== undefined ? { concurrency: String(payload.concurrency) } : {}),
    ...(payload.maxRequests !== undefined ? { maxRequests: String(payload.maxRequests) } : {}), ...(payload.cleanupReservedRequests !== undefined ? { cleanupReservedRequests: String(payload.cleanupReservedRequests) } : {}),
    ...(await mapInputPaths(payload, path)), ...(payload.secretBoundary ? { secretBoundary: true } : {}),
    ...(payload.modules ? { includeModules: [...new Set(payload.modules)], ...(moduleOnly ? { replaceProfileModules: true } : {}) } : {})
  };
  const result = await runScanCommand(payload.target, options, signal);
  const report = await loadReport(result.reportPath);
  return {
    jobType: moduleOnly ? "MODULE" : "SCAN", status: result.status,
    reportPath: relativeResult(workspace, result.reportPath), markdownReportPath: relativeResult(workspace, result.markdownReportPath), htmlReportPath: relativeResult(workspace, result.htmlReportPath),
    findingCount: report.findings.length, requestCount: report.metadata.totalRequests,
    ...(payload.modules ? { modules: payload.modules } : {})
  };
}

async function runNativeExport(jobId: string, payload: z.infer<typeof exportPayloadSchema>, workspace: string): Promise<Record<string, unknown>> {
  const reportPath = await existingWorkspacePath(workspace, payload.reportPath);
  const report = await loadReport(reportPath);
  const outputDir = await prepareOutput(workspace, payload.outputPath ?? `jobs/${jobId}/export`);
  let outputFile: string;
  if (payload.format === "JSON") outputFile = await new JsonReportWriter().write(outputDir, report);
  else if (payload.format === "MARKDOWN") outputFile = await new MarkdownReportWriter().write(outputDir, report);
  else if (payload.format === "HTML") outputFile = await new HtmlReportWriter().write(outputDir, report);
  else {
    const rendered = portable(report, payload.format); outputFile = resolve(outputDir, rendered.name);
    await writeFile(outputFile, rendered.content, { encoding: "utf8", mode: 0o600 });
  }
  return { jobType: "EXPORT", format: payload.format, outputPath: relativeResult(workspace, outputFile), findingCount: report.findings.length, sha256: createHash("sha256").update(await readFile(outputFile)).digest("hex") };
}

async function mapInputPaths(payload: z.infer<typeof scanPayloadSchema>, path: (value: string) => Promise<string>): Promise<Partial<ScanCommandOptions>> {
  const pairs: Array<[keyof typeof payload, keyof ScanCommandOptions]> = [
    ["authPath","auth"],["authAPath","authA"],["authBPath","authB"],["objectPairsPath","objectPairs"],["fieldExposurePath","fieldExposure"],["authorizationMatrixPath","authorizationMatrix"],
    ["collectionAuthorizationPath","collectionAuthorization"],["bulkAuthorizationPath","bulkAuthorization"],["fileAuthorizationPath","fileAuthorization"],["equivalentRoutesPath","equivalentRoutes"],
    ["privilegeMutationPath","privilegeMutation"],["mutationContractsPath","mutationContracts"],["supabaseAuthorizationPath","supabaseAuthorization"],["authenticationLifecyclePath","authenticationLifecycle"],
    ["authenticationLifecycleAutoPath","authenticationLifecycleAuto"],["businessInvariantsPath","businessInvariants"],["controlledRacesPath","controlledRaces"],["apiGraphqlPath","apiGraphql"],
    ["protocolSecurityPath","protocolSecurity"],["linkPortalSecurityPath","linkPortalSecurity"],["operationalEndpointsPath","operationalEndpoints"],["billingEntitlementPath","billingEntitlement"],
    ["assistedReviewPath","assistedReview"],["preHandoverPath","preHandover"],["grantPath","targetAuthorization"],["activeVulnerabilityPath","activeVulnerability"],["inventoryImportPath","inventoryImport"]
  ];
  const entries:Array<[string,string]>=[];for(const[source,target]of pairs){const value=payload[source];if(typeof value==="string")entries.push([target,await path(value)]);}return Object.fromEntries(entries) as Partial<ScanCommandOptions>;
}

async function ensureWorkspace(value: string): Promise<string> { await mkdir(resolve(value), { recursive: true }); return realpath(resolve(value)); }
function resolveWorkspacePath(workspace: string, value: string): string { const candidate = resolve(workspace, value); assertContained(workspace, candidate); return candidate; }
async function existingWorkspacePath(workspace: string, value: string): Promise<string> { const candidate = await realpath(resolveWorkspacePath(workspace, value)); assertContained(workspace, candidate); return candidate; }
async function prepareOutput(workspace: string, value: string): Promise<string> {
  const candidate = resolveWorkspacePath(workspace, value);
  const child = relative(workspace, candidate);
  let current = workspace;
  for (const segment of child.split(sep).filter(Boolean)) {
    const next = resolve(current, segment);
    await mkdir(next).catch((error: unknown) => {
      if (!isAlreadyExists(error)) throw error;
    });
    current = await realpath(next);
    assertContained(workspace, current);
  }
  return current;
}
function assertContained(workspace: string, candidate: string): void { const child = relative(workspace, candidate); if (child.startsWith("..") || isAbsolute(child)) throw new Error("AGENT_WORKSPACE_PATH_REJECTED"); }
function relativeResult(workspace: string, value: string): string { const child = relative(workspace, resolve(value)); assertContained(workspace, resolve(value)); return child.replaceAll("\\", "/"); }
function isAlreadyExists(error: unknown): boolean { return Boolean(error && typeof error === "object" && "code" in error && (error as { code?: unknown }).code === "EEXIST"); }

function portable(report: RouteCairnReport, format: "SARIF" | "JUNIT" | "BURP_XML"): { name: string; content: string } {
  if (format === "SARIF") return { name: "routecairn.sarif.json", content: `${JSON.stringify({ version: "2.1.0", $schema: "https://json.schemastore.org/sarif-2.1.0.json", runs: [{ tool: { driver: { name: "RouteCairn", version: report.routeCairnVersion } }, results: report.findings.map((finding) => ({ ruleId: `${finding.sourceModule}/${finding.type}`.replace(/[^A-Za-z0-9_./-]/g, "-"), level: ["Critical","High"].includes(finding.severity) ? "error" : finding.severity === "Medium" ? "warning" : "note", message: { text: finding.title }, locations: [{ physicalLocation: { artifactLocation: { uri: safeUri(finding.url) } } }], partialFingerprints: { routeCairnFindingId: finding.id } })) }] }, null, 2)}\n` };
  if (format === "JUNIT") return { name: "routecairn.junit.xml", content: `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites><testsuite name="RouteCairn" tests="${report.findings.length}" failures="${report.findings.filter((finding) => finding.severity !== "Informational").length}">${report.findings.map((finding) => `<testcase classname="${xml(finding.sourceModule)}" name="${xml(finding.title)}">${finding.severity === "Informational" ? `<system-out>${xml(finding.evidence.severityReason ?? finding.title)}</system-out>` : `<failure type="${xml(finding.type)}" message="${xml(finding.severity)}">${xml(finding.evidence.severityReason ?? finding.title)}</failure>`}</testcase>`).join("")}</testsuite></testsuites>\n` };
  return { name: "routecairn.burp.xml", content: `<?xml version="1.0" encoding="UTF-8"?>\n<issues burpVersion="RouteCairn ${xml(report.routeCairnVersion)}">${report.findings.map((finding) => `<issue><serialNumber>${xml(finding.id)}</serialNumber><type>0</type><name>${xml(finding.title)}</name><host ip="">${xml(safeUri(finding.url))}</host><path>${xml(safePath(finding.url))}</path><location>${xml(finding.method)} ${xml(safePath(finding.url))}</location><severity>${xml(finding.severity === "Critical" ? "High" : finding.severity === "Informational" ? "Information" : finding.severity)}</severity><confidence>${xml(finding.confidence)}</confidence><issueDetail>${xml(finding.evidence.severityReason ?? finding.title)}</issueDetail></issue>`).join("")}</issues>\n` };
}
function safeUri(value: string): string { try { const url = new URL(value); url.search = ""; url.hash = ""; return url.toString(); } catch { return "redacted://routecairn-target"; } }
function safePath(value: string): string { try { return new URL(value).pathname; } catch { return "/"; } }
function xml(value: unknown): string { return String(value ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/\"/g,"&quot;").replace(/'/g,"&apos;").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g,""); }
