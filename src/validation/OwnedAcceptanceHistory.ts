import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { z } from "zod";
import { runBoundedHttp } from "../modules/protocolSecurity/ProtocolTransports.js";
import { acceptanceCanonical, acceptanceDigest, assertAcceptanceExternalOrigin } from "./ExternalAcceptanceReadiness.js";

const historySchema = z.object({
  schemaVersion: z.literal(1), generatedAt: z.string().datetime({ offset: true }), product: z.literal("Decide"),
  targets: z.object({ web: z.string().url(), api: z.string().url() }),
  assessment: z.record(z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,99}$/), z.object({ outcome: z.string().regex(/^[A-Z][A-Z0-9_]{0,99}$/), scanId: z.string().uuid().optional(), findingCount: z.number().int().nonnegative().optional() }).passthrough()),
  cleanup: z.object({ allDisposableUsersDeleted: z.boolean(), sessionsRemaining: z.number().int().nonnegative(), controlledMutationStateRestored: z.boolean(), credentialsRemovedAfterRuns: z.boolean() })
}).passthrough();

/** Preserve actual owned-target evidence without upgrading it to independent grid acceptance. */
export async function retainOwnedDecideAcceptance(options: { sourceDirectory: string; outputDirectory: string; probeApprovedOrigins?: string[] }) {
  const source = resolve(options.sourceDirectory); const output = resolve(options.outputDirectory);
  const summaryBytes = await boundedRead(resolve(source, "decide-acceptance-summary.json"));
  const history = historySchema.parse(JSON.parse(summaryBytes.toString("utf8")));
  for (const origin of Object.values(history.targets)) assertAcceptanceExternalOrigin(origin);
  const assessments = [];
  for (const [name, assessment] of Object.entries(history.assessment)) {
    if (!assessment.scanId) { assessments.push({ name, historicalOutcome: assessment.outcome, reportAvailable: false }); continue; }
    try {
      const bytes = await boundedRead(resolve(source, "reports", assessment.scanId, "report.json"));
      const report = JSON.parse(bytes.toString("utf8")) as Record<string, unknown>;
      const execution = z.object({ status: z.enum(["COMPLETED", "INTERRUPTED", "FAILED", "CANCELLED"]), partial: z.boolean(), cleanup: z.object({ state: z.string().max(100) }).passthrough().optional() }).passthrough().parse(report.execution);
      const findings = z.array(z.object({ type: z.string().max(200), severity: z.string().max(100) }).passthrough()).parse(report.findings);
      const matches = assessment.findingCount === undefined || assessment.findingCount === findings.length;
      assessments.push({ name, historicalOutcome: assessment.outcome, reportAvailable: true, scanId: assessment.scanId, rawReportSha256: acceptanceDigest(bytes), routeCairnVersion: typeof report.routeCairnVersion === "string" ? report.routeCairnVersion : "UNKNOWN", executionStatus: execution.status, partial: execution.partial, reportCleanupState: execution.cleanup?.state ?? "UNKNOWN", findingCount: findings.length, findings: findings.map(({ type, severity }) => ({ type, severity })), summaryCountMatchesReport: matches, assessment: execution.partial || !matches ? "REVIEW_REQUIRED" : "HISTORICAL_EXECUTION_RETAINED" });
    } catch { assessments.push({ name, historicalOutcome: assessment.outcome, reportAvailable: false, scanId: assessment.scanId, assessment: "SOURCE_REPORT_UNAVAILABLE_OR_INVALID" }); }
  }
  let journal: { rawSha256: string; latestStages: Array<{ caseIdSha256: string; stage: string; timestamp: string }> } | undefined;
  try {
    const bytes = await boundedRead(resolve(source, "controlled-mutations", "mutation-journal.json"));
    const entries = z.array(z.object({ caseId: z.string().max(200), stage: z.string().max(100), timestamp: z.string().datetime({ offset: true }) }).passthrough()).parse(JSON.parse(bytes.toString("utf8")));
    const latest = new Map<string, typeof entries[number]>();
    for (const entry of entries) {
      const previous = latest.get(entry.caseId);
      if (!previous || Date.parse(entry.timestamp) >= Date.parse(previous.timestamp)) latest.set(entry.caseId, entry);
    }
    journal = { rawSha256: acceptanceDigest(bytes), latestStages: [...latest.values()].map((entry) => ({ caseIdSha256: acceptanceDigest(entry.caseId), stage: entry.stage, timestamp: entry.timestamp })) };
  } catch { /* Missing recovery evidence remains visible as a limitation. */ }
  const availability = [];
  if (options.probeApprovedOrigins) {
    const origins = [...new Set(Object.values(history.targets).map((value) => new URL(value).origin))];
    const approved = new Set(options.probeApprovedOrigins.map((value) => new URL(value).origin));
    if (origins.length !== 2 || origins.some((origin) => !approved.has(origin)) || approved.size !== 2) throw new Error("OWNED_HISTORY_PUBLIC_PROBE_APPROVAL_MISMATCH");
    for (const origin of origins) assertAcceptanceExternalOrigin(origin);
    for (const [kind, raw] of Object.entries(history.targets)) {
      const url = new URL(kind === "web" ? "/" : "/health", new URL(raw).origin).toString();
      try {
        const result = await runBoundedHttp(url, kind === "web" ? "HEAD" : "GET", { "user-agent": "RouteCairn-owned-readiness/0.1", accept: kind === "api" ? "application/json" : "text/html" }, undefined, { allowedPrivateOrigins: [], maxBytes: 16384, timeoutMs: 10000 });
        availability.push({ kind, url, method: kind === "web" ? "HEAD" : "GET", statusCode: result.statusCode, responseBodySha256: acceptanceDigest(result.body), responseBytes: result.body.length, checkedAt: new Date().toISOString(), assessment: result.statusCode >= 200 && result.statusCode < 400 ? "PUBLIC_ENDPOINT_REACHABLE" : "PUBLIC_ENDPOINT_RESPONSE_REQUIRES_REVIEW" });
      } catch { availability.push({ kind, url, method: kind === "web" ? "HEAD" : "GET", checkedAt: new Date().toISOString(), assessment: "PUBLIC_ENDPOINT_UNAVAILABLE" }); }
    }
  }
  const result = { schemaVersion: 1, standard: "ROUTECAIRN_OWNED_TARGET_HISTORY_V1", product: "Decide", status: "PARTIAL_EXTERNAL_EVIDENCE", historicalSummaryAt: history.generatedAt, retainedAt: new Date().toISOString(), sourceSummarySha256: acceptanceDigest(summaryBytes), targets: history.targets, assessments, ...(journal ? { recoveryJournal: journal } : {}), reportedHistoricalCleanup: history.cleanup, publicAvailability: availability, independentOperatorVerified: false, releaseArtifactVerified: false, fullEightLaneAcceptance: false, limitations: ["Historical owned-target reports are unsigned; their integrity hashes are newly retained, not historical attestations.", "The interrupted recovery report remains partial. The later journal and historical cleanup declaration are separate evidence.", "No tenant model was assessed. Supabase, GraphQL, Auth0/Cognito, signed portals and independent operator evidence are not supplied by these reports.", "Historical webhook/billing and post-remediation assessments were NOT_ASSESSED.", "Public endpoint availability is read-only and cannot establish authenticated authorization, provider or remediation acceptance.", "Historical disposable accounts and credentials were removed; fresh approved credentials are required for authenticated reruns."] };
  await mkdir(output, { recursive: true });
  const path = resolve(output, "owned-decide-evidence.json"); await writeFile(path, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
  await writeFile(resolve(output, "SHA256SUMS"), `${acceptanceDigest(`${JSON.stringify(result, null, 2)}\n`)}  owned-decide-evidence.json\n`, { mode: 0o600 });
  await writeFile(resolve(output, "owned-decide-report.md"), renderOwnedAcceptanceHistory(result), { mode: 0o600 });
  return { outputPath: path, status: result.status, referencedReports: assessments.filter((item) => item.reportAvailable).length, publicChecks: availability.length, independentOperatorVerified: false, fullEightLaneAcceptance: false, evidenceSha256: acceptanceDigest(acceptanceCanonical(result)) };
}

export function renderOwnedAcceptanceHistory(result: {
  historicalSummaryAt: string;
  assessments: Array<{ name: string; historicalOutcome: string; reportAvailable: boolean; executionStatus?: string; partial?: boolean; reportCleanupState?: string; assessment?: string }>;
  publicAvailability: Array<{ kind: string; method: string; statusCode?: number; checkedAt: string; assessment: string }>;
  limitations: string[];
}): string {
  const assessments = result.assessments.map((item) => item.reportAvailable
    ? `- ${item.name}: ${item.executionStatus}; partial: ${item.partial ? "yes" : "no"}; report cleanup: ${item.reportCleanupState}; ${item.assessment}. Historical declaration: ${item.historicalOutcome}. Source report retained by digest.`
    : `- ${item.name}: ${item.historicalOutcome}; source report unavailable or not supplied.`).join("\n");
  const checks = result.publicAvailability.map((item) => `- ${item.kind}: ${item.method}, ${item.statusCode === undefined ? item.assessment : `HTTP ${item.statusCode}`}, checked ${item.checkedAt}.`).join("\n") || "No new public checks performed.";
  return `# Decide owned-target evidence\n\nStatus: **PARTIAL_EXTERNAL_EVIDENCE**\n\nHistorical summary: ${result.historicalSummaryAt}\n\n${assessments}\n\n## Public availability\n\n${checks}\n\nThese checks establish endpoint availability only.\n\n## Limits\n\n${result.limitations.map((item) => `- ${item}`).join("\n")}\n`;
}

async function boundedRead(path: string): Promise<Buffer> { const info = await stat(path); if (!info.isFile() || info.size > 32 * 1024 * 1024) throw new Error("OWNED_HISTORY_SOURCE_FILE_INVALID"); return readFile(path); }
