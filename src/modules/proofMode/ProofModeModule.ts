import { authHeadersForProfile, redactedCurlCommand } from "../../core/auth/AuthProfile.js";
import type { AuthProfile } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { Finding } from "../../core/findings/Finding.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { ProofModeBlock, ProofModeComparison, ProofModeReport } from "../../reports/ReportTypes.js";

interface ProofTarget {
  id: string;
  source: "finding" | "endpoint";
  title: string;
  url: string;
  severity: string;
  severityReason: string;
  whySelected: string[];
}

export class ProofModeModule implements RouteCairnPlugin {
  public readonly name = "proof-mode";
  public readonly description = "Re-tests selected high-signal targets and creates stable proof-first evidence blocks.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    if (!context.moduleSettings(this.name).enabled) {
      return { pluginName: this.name, notes: ["Proof mode skipped because the active scan profile does not request proof-first evidence."] };
    }

    const report = await buildProofModeReport(context);
    return { pluginName: this.name, proofMode: report, notes: report.notes };
  }
}

async function buildProofModeReport(context: ScanContext): Promise<ProofModeReport> {
  const targets = selectProofTargets(context);
  const client = context.createHttpClient();
  const blocks: ProofModeBlock[] = [];

  for (const target of targets) {
    const decision = context.scopeMatcher.decide(target.url, "GET");
    context.state.recordScopeDecision(decision);
    if (!decision.allowed || !decision.normalizedUrl) continue;

    const comparisons: ProofModeComparison[] = [];
    const anonymous = await client.send({ url: decision.normalizedUrl, method: "GET" });
    context.state.recordResponse(anonymous);
    comparisons.push(toComparison("anonymous", decision.normalizedUrl, anonymous));

    if (context.options.authProfile) {
      const authenticated = await client.send({ url: decision.normalizedUrl, method: "GET", headers: authHeadersForProfile(context.options.authProfile) });
      comparisons.push(toComparison("authenticated", decision.normalizedUrl, authenticated, context.options.authProfile));
    }

    if (context.options.authProfileSet) {
      const accountA = await client.send({ url: decision.normalizedUrl, method: "GET", headers: authHeadersForProfile(context.options.authProfileSet.accountA) });
      const accountB = await client.send({ url: decision.normalizedUrl, method: "GET", headers: authHeadersForProfile(context.options.authProfileSet.accountB) });
      comparisons.push(toComparison("account-a", decision.normalizedUrl, accountA, context.options.authProfileSet.accountA));
      comparisons.push(toComparison("account-b", decision.normalizedUrl, accountB, context.options.authProfileSet.accountB));
    }

    blocks.push(toProofBlock(target, comparisons));
  }

  return {
    enabled: true,
    retestedTargets: blocks.length,
    blocks,
    notes: [
      "Proof Mode re-tested selected targets with safe GET requests only.",
      "Auth and Account A/B proof requests redact auth material and store response summaries, not private body dumps.",
      "Proof blocks are submission aids and still require tester judgment before claiming a vulnerability."
    ]
  };
}

function selectProofTargets(context: ScanContext): ProofTarget[] {
  const selected = new Map<string, ProofTarget>();
  const maxTargets = context.moduleSettings("proof-mode").maxProofTargets ?? 12;
  const rankedFindings = context.state
    .getFindings()
    .filter((finding) => finding.falsePositiveStatus !== "likely-false-positive")
    .sort((left, right) => right.riskScore - left.riskScore || severityRank(right.severity) - severityRank(left.severity));

  for (const finding of rankedFindings) {
    addTarget(selected, fromFinding(finding));
    if (selected.size >= maxTargets) return [...selected.values()];
  }

  for (const endpoint of context.state.getStateAwareApi()?.bolaIdorCandidates ?? []) {
    addTarget(selected, {
      id: `endpoint:${endpoint.endpoint}`,
      source: "endpoint",
      title: "State-aware API candidate needs proof review",
      url: endpoint.endpoint,
      severity: endpoint.priority === "high" ? "High" : endpoint.priority === "medium" ? "Medium" : "Low",
      severityReason: `Selected from state-aware API review with signal ${endpoint.accessComparison.signal}.`,
      whySelected: endpoint.candidateReasons
    });
    if (selected.size >= maxTargets) return [...selected.values()];
  }

  for (const endpoint of context.state.getApiMapper()?.endpoints ?? []) {
    if (!endpoint.hasObjectId && endpoint.privilegeSensitivity !== "high" && endpoint.dataExposureSensitivity !== "high") continue;
    addTarget(selected, {
      id: `endpoint:${endpoint.endpoint}`,
      source: "endpoint",
      title: "API endpoint needs proof review",
      url: endpoint.endpoint,
      severity: endpoint.dataExposureSensitivity === "high" || endpoint.privilegeSensitivity === "high" ? "Medium" : "Low",
      severityReason: `Selected because API mapper tagged this endpoint with ${endpoint.riskTags.join(", ")}.`,
      whySelected: endpoint.riskTags
    });
    if (selected.size >= maxTargets) return [...selected.values()];
  }

  return [...selected.values()];
}

function fromFinding(finding: Finding): ProofTarget {
  return {
    id: finding.id,
    source: "finding",
    title: finding.title,
    url: finding.url,
    severity: finding.severity,
    severityReason: finding.evidence.severityReason ?? `${finding.severity} severity from ${finding.sourceModule} with risk score ${finding.riskScore}.`,
    whySelected: [`${finding.type}`, `risk score ${finding.riskScore}`, ...finding.tags.slice(0, 5)]
  };
}

function addTarget(targets: Map<string, ProofTarget>, target: ProofTarget): void {
  if (!targets.has(target.url)) targets.set(target.url, target);
}

function toComparison(label: ProofModeComparison["label"], url: string, response: HttpResponse, profile?: AuthProfile): ProofModeComparison {
  return {
    label,
    request: {
      method: "GET",
      url,
      curlCommand: redactedCurlCommand(url, profile),
      authMaterialRedacted: Boolean(profile)
    },
    response: summarizeResponse(response)
  };
}

function summarizeResponse(response: HttpResponse): ProofModeComparison["response"] {
  return {
    finalUrl: response.finalUrl,
    ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(response.contentType ? { contentType: response.contentType } : {}),
    ...(typeof response.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(response.title ? { title: response.title } : {}),
    ...(response.bodyHash ? { bodyHash: response.bodyHash } : {}),
    responseTimeMs: response.responseTimeMs,
    redirectChain: response.redirectChain,
    ...(response.error ? { error: response.error.message } : {})
  };
}

function toProofBlock(target: ProofTarget, comparisons: ProofModeComparison[]): ProofModeBlock {
  const stableEvidence = comparisons.map((comparison) => {
    const response = comparison.response;
    return `${comparison.label}: status=${response.statusCode ?? "error"}, length=${response.contentLength ?? "unknown"}, type=${response.contentType ?? "unknown"}, hash=${response.bodyHash ?? "none"}`;
  });

  return {
    id: `proof-${target.id}`,
    source: target.source,
    title: target.title,
    target: target.url,
    severity: target.severity,
    severityReason: target.severityReason,
    whySelected: target.whySelected,
    comparisons,
    stableEvidence,
    bountySubmissionSummary: `${target.title} at ${target.url}. Evidence: ${stableEvidence.join("; ")}. Severity rationale: ${target.severityReason}`,
    needsManualVerification: true
  };
}

function severityRank(severity: string): number {
  return { Critical: 5, High: 4, Medium: 3, Low: 2, Informational: 1 }[severity] ?? 0;
}
