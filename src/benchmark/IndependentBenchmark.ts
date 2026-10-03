import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFile, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { isIP } from "node:net";
import { lookup } from "node:dns/promises";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { z } from "zod";
import { runScanCommand } from "../cli/commands/scan.js";
import type { RouteCairnReport } from "../reports/ReportTypes.js";
import type { ModuleId } from "../core/planning/ScanPlan.js";
import { canonicalJson, blindBenchmarkPackSchema, openBenchmarkPack, verifyBenchmarkManifest } from "./BenchmarkCorpus.js";
import { benchmarkTelemetrySchema, type BenchmarkTelemetry } from "./BenchmarkSchemas.js";
import { evaluateBenchmark, type BenchmarkResult } from "./BenchmarkEvaluator.js";
import { writeBenchmarkArtifacts } from "./BenchmarkArtifacts.js";

const hash = z.string().regex(/^[a-f0-9]{64}$/);
const identity = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$/);
const signature = z.object({ algorithm: z.literal("Ed25519"), keyId: identity, value: z.string().min(40).max(512) }).strict();
const binding = z.object({ path: z.string().min(1).max(4096), sha256: hash }).strict();

export const independentTrustSchema = z.object({
  schemaVersion: z.literal(1),
  keys: z.array(z.object({ id: identity, organization: z.string().min(1).max(240), role: z.enum(["PUBLISHER", "OPERATOR"]), publicKeyPem: z.string().min(40).max(4096), validFrom: z.string().datetime(), validUntil: z.string().datetime(), revoked: z.boolean(), independence: z.literal("INDEPENDENT_THIRD_PARTY") }).strict()).max(100)
}).strict().superRefine((value, context) => {
  if (new Set(value.keys.map((key) => key.id)).size !== value.keys.length) context.addIssue({ code: "custom", message: "Duplicate key IDs." });
  const materials = new Set<string>();
  for (const key of value.keys) {
    try {
      const publicKey = createPublicKey(key.publicKeyPem);
      if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Wrong key type");
      const material = publicKey.export({ type: "spki", format: "der" }).toString("hex");
      if (materials.has(material)) context.addIssue({ code: "custom", message: "Duplicate signing key material across identities." });
      materials.add(material);
    } catch { context.addIssue({ code: "custom", message: "Trust keys must be valid Ed25519 public keys." }); }
  }
  for (const key of value.keys) if (Date.parse(key.validFrom) >= Date.parse(key.validUntil)) context.addIssue({ code: "custom", message: "Invalid key validity interval." });
});
type Trust = z.infer<typeof independentTrustSchema>;

export const independentSubmissionSchema = z.object({
  schemaVersion: z.literal(1), kind: z.literal("ROUTECAIRN_INDEPENDENT_BENCHMARK_SUBMISSION"),
  createdAt: z.string().datetime(), benchmarkId: identity, packSha256: hash,
  operatorOrganization: z.string().min(1).max(240),
  release: z.object({ version: z.string().min(1).max(80), sourceCommit: z.string().regex(/^[a-f0-9]{40}$/), artifactSha256: hash }).strict(),
  runs: z.array(z.object({ report: binding, telemetry: benchmarkTelemetrySchema }).strict()).min(3).max(20),
  signature
}).strict();
type Submission = z.infer<typeof independentSubmissionSchema>;

export const independentExecutionSchema = z.object({
  schemaVersion: z.literal(1), operatorKeyId: identity, repetitions: z.number().int().min(3).max(10),
  releaseVersion: z.string().min(1).max(80), sourceCommit: z.string().regex(/^[a-f0-9]{40}$/),
  targets: z.array(z.object({
    id: identity, url: z.string().url().max(2048), scope: binding, targetAuthorization: binding,
    inputs: z.object({ auth: binding.optional(), authA: binding.optional(), authB: binding.optional(), apiGraphql: binding.optional(), activeVulnerability: binding.optional(), authenticationLifecycle: binding.optional(), protocolSecurity: binding.optional(), supabaseAuthorization: binding.optional(), businessInvariants: binding.optional() }).strict(),
    maxRequests: z.number().int().min(1).max(5000), cleanupReservedRequests: z.number().int().min(0).max(1000)
  }).strict()).min(1).max(20)
}).strict().superRefine((value, context) => {
  if (new Set(value.targets.map((target) => target.id)).size !== value.targets.length) context.addIssue({ code: "custom", message: "Duplicate target IDs." });
  for (const target of value.targets) if (target.cleanupReservedRequests > target.maxRequests) context.addIssue({ code: "custom", message: "Cleanup budget exceeds request budget." });
  for (const target of value.targets) if (!Object.entries(target.inputs).some(([name, input]) => input && !["auth", "authA", "authB"].includes(name))) context.addIssue({ code: "custom", message: "Each target requires an execution contract." });
});

/** Only explicitly trusted, currently valid third-party keys can make independence claims. */
export function trustedBenchmarkKey(raw: unknown, keyId: string, role: "PUBLISHER" | "OPERATOR", at: string) {
  const trust = independentTrustSchema.parse(raw);
  const key = trust.keys.find((item) => item.id === keyId && item.role === role);
  const time = Date.parse(at);
  if (!Number.isFinite(time) || !key || key.revoked || time < Date.parse(key.validFrom) || time >= Date.parse(key.validUntil)) throw new Error("BENCHMARK_INDEPENDENT_KEY_UNTRUSTED");
  if (createPublicKey(key.publicKeyPem).asymmetricKeyType !== "ed25519") throw new Error("BENCHMARK_INDEPENDENT_KEY_TYPE_INVALID");
  return key;
}

export function signIndependentSubmission(raw: Omit<Submission, "signature">, privateKeyPem: string, keyId: string): Submission {
  const key = createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("BENCHMARK_INDEPENDENT_KEY_TYPE_INVALID");
  const parsed = independentSubmissionSchema.parse({ ...raw, signature: { algorithm: "Ed25519", keyId, value: "0".repeat(88) } });
  const { signature: _signature, ...unsigned } = parsed;
  return { ...unsigned, signature: { algorithm: "Ed25519", keyId, value: sign(null, Buffer.from(canonicalJson(unsigned)), key).toString("base64") } };
}

export function verifyIndependentSubmission(raw: unknown, trust: Trust, now = new Date().toISOString()): Submission {
  const submission = independentSubmissionSchema.parse(raw);
  if (Date.parse(submission.createdAt) > Date.parse(now) + 30_000) throw new Error("BENCHMARK_SUBMISSION_FROM_FUTURE");
  const key = trustedBenchmarkKey(trust, submission.signature.keyId, "OPERATOR", submission.createdAt);
  trustedBenchmarkKey(trust, submission.signature.keyId, "OPERATOR", now);
  if (key.organization !== submission.operatorOrganization) throw new Error("BENCHMARK_OPERATOR_ORGANIZATION_MISMATCH");
  const { signature: supplied, ...unsigned } = submission;
  if (!verify(null, Buffer.from(canonicalJson(unsigned)), key.publicKeyPem, Buffer.from(supplied.value, "base64"))) throw new Error("BENCHMARK_SUBMISSION_SIGNATURE_INVALID");
  if (new Set(submission.runs.map((run) => run.report.sha256)).size !== submission.runs.length) throw new Error("BENCHMARK_REPETITION_REPLAY");
  return submission;
}

/** Execute approved scanner contracts before truth is released. This process has no decryption key. */
export async function runIndependentBenchmark(options: { plan: string; pack: string; trust: string; releaseArtifact: string; signingKey: string; output: string }) {
  const plan = independentExecutionSchema.parse(JSON.parse(await readFile(resolve(options.plan), "utf8")));
  const packBytes = await readFile(resolve(options.pack));
  const pack = blindBenchmarkPackSchema.parse(JSON.parse(packBytes.toString("utf8")));
  const trust = independentTrustSchema.parse(JSON.parse(await readFile(resolve(options.trust), "utf8")));
  const operator = trustedBenchmarkKey(trust, plan.operatorKeyId, "OPERATOR", new Date().toISOString());
  const privatePem = await readFile(resolve(options.signingKey), "utf8");
  if (createPublicKey(privatePem).export({ type: "spki", format: "pem" }) !== createPublicKey(operator.publicKeyPem).export({ type: "spki", format: "pem" })) throw new Error("BENCHMARK_OPERATOR_SIGNER_MISMATCH");
  const parent = resolve(options.output); await mkdir(parent, { recursive: true, mode: 0o700 });
  const directory = await mkdtemp(join(parent, "independent-execution-"));
  // Verify every input digest and origin before transmitting the first request.
  const inputs = await Promise.all(plan.targets.map(async (target) => {
    assertExternalOrigin(target.url);
    const addresses = await lookup(new URL(target.url).hostname.replace(/^\[|\]$/g, ""), { all: true });
    if (!addresses.length) throw new Error("BENCHMARK_EXTERNAL_TARGET_REQUIRED");
    for (const address of addresses) assertExternalOrigin(`http://${address.family === 6 ? `[${address.address}]` : address.address}`);
    const paths: Record<string, string> = {};
    const snapshotDirectory = join(directory, "private-inputs", target.id); await mkdir(snapshotDirectory, { recursive: true, mode: 0o700 });
    for (const [name, file] of Object.entries({ scope: target.scope, targetAuthorization: target.targetAuthorization, ...target.inputs })) if (file) { const bytes = await readBoundFile(file); const snapshot = join(snapshotDirectory, `${name}.json`); await writeFile(snapshot, bytes, { mode: 0o600 }); paths[name] = snapshot; }
    return { target, paths };
  }));
  const artifact = await readFile(resolve(options.releaseArtifact));
  const runs: Submission["runs"] = [];
  for (let repetition = 0; repetition < plan.repetitions; repetition += 1) {
    const reports: RouteCairnReport[] = []; let requests = 0; let rss = process.memoryUsage().rss;
    const start = performance.now(); const cpuStart = process.cpuUsage();
    const sampler = setInterval(() => { rss = Math.max(rss, process.memoryUsage().rss); }, 10); sampler.unref();
    try {
      for (const { target, paths } of inputs) {
        const modules: ModuleId[] = Object.entries({ apiGraphql: "api-graphql-authorization", activeVulnerability: "active-vulnerability-validation", authenticationLifecycle: "authentication-lifecycle", protocolSecurity: "protocol-security", supabaseAuthorization: "supabase-authorization", businessInvariants: "business-invariant" } as const).filter(([input]) => paths[input]).map(([, module]) => module);
        if (!modules.length) throw new Error("BENCHMARK_EXECUTION_CONTRACT_REQUIRED");
        const result = await runScanCommand(target.url, { ...paths, profile: "quick", includeModules: modules, replaceProfileModules: true, output: join(directory, `run-${repetition + 1}`, target.id), maxRequests: String(target.maxRequests), cleanupReservedRequests: String(target.cleanupReservedRequests) });
        const report = JSON.parse(await readFile(result.reportPath, "utf8")) as RouteCairnReport;
        if (report.routeCairnVersion !== plan.releaseVersion || report.execution?.status !== "COMPLETED" || report.execution.partial) throw new Error("BENCHMARK_SUBMISSION_EXECUTION_INCOMPLETE");
        requests += report.requestAudit.reduce((sum, item) => sum + (item.transmittedRequests ?? (item.outcome === "sent" ? 1 : 0)), 0); reports.push(report);
      }
      const report = mergeBenchmarkReports(reports);
      const path = join(directory, `run-${repetition + 1}`, "report.json");
      await mkdir(join(directory, `run-${repetition + 1}`), { recursive: true, mode: 0o700 });
      const bytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`); await writeFile(path, bytes, { mode: 0o600 });
      const cpu = process.cpuUsage(cpuStart);
      const telemetry: BenchmarkTelemetry = { runtimeMs: performance.now() - start, peakRssBytes: rss, requestCount: requests, transmittedRequestCount: requests, cpuUserMicros: cpu.user, cpuSystemMicros: cpu.system };
      runs.push({ report: { path, sha256: sha256(bytes) }, telemetry });
    } finally { clearInterval(sampler); }
  }
  const submission = signIndependentSubmission({ schemaVersion: 1, kind: "ROUTECAIRN_INDEPENDENT_BENCHMARK_SUBMISSION", createdAt: new Date().toISOString(), benchmarkId: pack.public.benchmarkId, packSha256: sha256(packBytes), operatorOrganization: operator.organization, release: { version: plan.releaseVersion, sourceCommit: plan.sourceCommit, artifactSha256: sha256(artifact) }, runs }, privatePem, plan.operatorKeyId);
  verifyIndependentSubmission(submission, trust);
  const path = join(directory, "independent-submission.json"); await writeFile(path, `${JSON.stringify(submission, null, 2)}\n`, { mode: 0o600 });
  return { submissionPath: path, repetitions: runs.length, status: "AWAITING_INDEPENDENT_TRUTH" };
}

export async function evaluateIndependentBenchmark(options: { submission: string; pack: string; secret: string; trust: string; releaseArtifact: string; output: string; baseline?: string }) {
  const trust = independentTrustSchema.parse(JSON.parse(await readFile(resolve(options.trust), "utf8")));
  const submission = verifyIndependentSubmission(JSON.parse(await readFile(resolve(options.submission), "utf8")), trust);
  const packBytes = await readFile(resolve(options.pack));
  if (sha256(packBytes) !== submission.packSha256) throw new Error("BENCHMARK_PACK_COMMITMENT_MISMATCH");
  if (sha256(await readFile(resolve(options.releaseArtifact))) !== submission.release.artifactSha256) throw new Error("BENCHMARK_RELEASE_COMMITMENT_MISMATCH");
  const truth = openBenchmarkPack(JSON.parse(packBytes.toString("utf8")), options.secret);
  const publisherId = truth.corpus?.signature?.keyId;
  if (!publisherId || truth.corpus?.independence !== "EXTERNAL" || !truth.corpus.blinded || !truth.corpus.source || !truth.corpus.commit) throw new Error("BENCHMARK_INDEPENDENT_SIGNED_BLIND_PROVENANCE_REQUIRED");
  const publisher = trustedBenchmarkKey(trust, publisherId, "PUBLISHER", new Date().toISOString());
  if (publisher.organization !== truth.corpus.publisher || publisherId === submission.signature.keyId) throw new Error("BENCHMARK_PUBLISHER_IDENTITY_MISMATCH");
  const operator = trustedBenchmarkKey(trust, submission.signature.keyId, "OPERATOR", submission.createdAt);
  if (createPublicKey(publisher.publicKeyPem).export({ type: "spki", format: "der" }).equals(createPublicKey(operator.publicKeyPem).export({ type: "spki", format: "der" }))) throw new Error("BENCHMARK_PUBLISHER_IDENTITY_MISMATCH");
  if (truth.id !== submission.benchmarkId) throw new Error("BENCHMARK_SUBMISSION_CORPUS_MISMATCH");
  const manifest = verifyBenchmarkManifest(truth, publisher.publicKeyPem, publisherId);
  const runs = [];
  for (const run of submission.runs) {
    const report = JSON.parse((await readBoundFile(run.report)).toString("utf8")) as RouteCairnReport;
    if (report.routeCairnVersion !== submission.release.version || report.execution?.status !== "COMPLETED" || report.execution.partial) throw new Error("BENCHMARK_SUBMISSION_EXECUTION_INCOMPLETE");
    assertExternalOrigin(report.target);
    const sent = report.requestAudit.filter((item) => item.outcome === "sent");
    if (!sent.length || !run.telemetry.transmittedRequestCount || run.telemetry.peakRssBytes === 0) throw new Error("BENCHMARK_INDEPENDENT_TELEMETRY_REQUIRED");
    const transmitted = report.requestAudit.reduce((sum, entry) => sum + (entry.transmittedRequests ?? (entry.outcome === "sent" ? 1 : 0)), 0);
    if (transmitted !== run.telemetry.transmittedRequestCount || run.telemetry.requestCount !== transmitted) throw new Error("BENCHMARK_INDEPENDENT_TELEMETRY_MISMATCH");
    for (const entry of sent) assertExternalOrigin(entry.requestedUrl);
    runs.push({ report, telemetry: run.telemetry });
  }
  if (manifest.thresholds.minRepetitions < 3 || (manifest.thresholds.minLanguages ?? 0) < 3 || (manifest.thresholds.minFrameworks ?? 0) < 4 || (manifest.thresholds.minCorpusCases ?? 0) < 500 || (manifest.thresholds.minCategories ?? 0) < 12 || !manifest.thresholds.requireBalancedCategories || (manifest.thresholds.minStabilityRate ?? 0) < 0.95 || (manifest.thresholds.minCategoryRecall ?? 0) < 0.95 || (manifest.thresholds.maxCategoryFalsePositiveRate ?? 1) > 0.01 || (manifest.thresholds.maxCategoryInconclusiveRate ?? 1) > 0.01) throw new Error("BENCHMARK_INDEPENDENT_POLICY_TOO_WEAK");
  const baseline = options.baseline ? JSON.parse(await readFile(resolve(options.baseline), "utf8")) as BenchmarkResult : undefined;
  const result = evaluateBenchmark(manifest, runs, { release: submission.release.version, build: submission.release.sourceCommit, ...(baseline ? { baseline } : {}) });
  const artifacts = await writeBenchmarkArtifacts(options.output, result);
  const verification = { schemaVersion: 1, kind: "ROUTECAIRN_INDEPENDENT_BENCHMARK_VERIFICATION", status: result.status, verifiedAt: new Date().toISOString(), publisherKeyId: publisherId, operatorKeyId: submission.signature.keyId, publisherOrganization: publisher.organization, operatorOrganization: submission.operatorOrganization, independence: "EXTERNAL", blinded: true, externalTargetsTested: true, packSha256: submission.packSha256, resultSha256: sha256(await readFile(artifacts.jsonPath)), release: submission.release, limitations: ["Operator signatures attest execution; independence is established by the separately administered trust registry.", "Encryption does not establish that an operator never accessed truth; preserve organizational separation and submission timing evidence."] };
  const verificationPath = join(resolve(options.output), "independent-verification.json"); await writeFile(verificationPath, `${JSON.stringify(verification, null, 2)}\n`, { mode: 0o600 });
  return { result, artifacts, verificationPath };
}

export function mergeBenchmarkReports(reports: readonly RouteCairnReport[]): RouteCairnReport {
  const first = reports[0]; if (!first) throw new Error("BENCHMARK_REPORTS_REQUIRED");
  const merged = { ...first } as unknown as Record<string, unknown>;
  for (const name of ["findings", "requestAudit", "responses", "discoveredUrls", "scopeDecisions"]) merged[name] = reports.flatMap((report) => (report as unknown as Record<string, unknown[]>)[name] ?? []);
  for (const name of ["apiGraphql", "activeVulnerability", "authenticationLifecycle", "protocolSecurity", "supabaseAuthorization", "businessInvariant"]) {
    const sections = reports.map((report) => (report as unknown as Record<string, unknown>)[name]).filter((section): section is Record<string, unknown> => Boolean(section && typeof section === "object"));
    if (!sections.length) continue;
    const section = { ...sections[0] };
    for (const key of Object.keys(section)) if (Array.isArray(section[key])) section[key] = sections.flatMap((item) => Array.isArray(item[key]) ? item[key] as unknown[] : []);
    merged[name] = section;
  }
  merged.execution = { ...first.execution, status: reports.every((report) => report.execution?.status === "COMPLETED") ? "COMPLETED" : "FAILED", partial: reports.some((report) => report.execution?.partial) };
  return merged as unknown as RouteCairnReport;
}

async function readBoundFile(file: z.infer<typeof binding>): Promise<Buffer> { const bytes = await readFile(resolve(file.path)); if (sha256(bytes) !== file.sha256) throw new Error("BENCHMARK_INPUT_COMMITMENT_MISMATCH"); return bytes; }
export function assertExternalOrigin(raw: string): void {
  const url = new URL(raw); const hostname = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  const mapped = isIP(hostname) === 6 && /^::ffff:(?:7f[0-9a-f]{2}:|0:0$)/i.test(hostname);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".test") || hostname.endsWith(".invalid") || hostname === "0.0.0.0" || hostname === "::" || hostname === "::1" || hostname.startsWith("127.") || mapped) throw new Error("BENCHMARK_EXTERNAL_TARGET_REQUIRED");
}
function sha256(bytes: Buffer): string { return createHash("sha256").update(bytes).digest("hex"); }
