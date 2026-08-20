import { createHash } from "node:crypto";
import type { Confidence } from "../../core/findings/Confidence.js";
import type { Finding, FindingType } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { Severity } from "../../core/findings/Severity.js";
import type { HttpMethod, HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";
import { RecommendationEngine } from "../../intelligence/recommendations/RecommendationEngine.js";
import { evidenceFromResponse } from "../../core/evidence/EvidenceBuilder.js";
import type { ResponseObservation } from "../../reports/ReportTypes.js";
import { hasBackupResponseEvidence } from "./BackupExposureDetector.js";
import { isConfigPath } from "./ConfigExposureDetector.js";
import { isDirectoryListing } from "./DirectoryListingDetector.js";
import { SecretPatternDetector } from "./SecretPatternDetector.js";

const exposurePaths = [
  "/.env",
  "/.env.local",
  "/config.json",
  "/config.js",
  "/settings.json",
  "/backup.zip",
  "/backup.tar.gz",
  "/database.sql",
  "/dump.sql",
  "/debug.log",
  "/error.log",
  "/server.log",
  "/.git/config",
  "/phpinfo.php",
  "/_debugbar",
  "/telescope",
  "/.well-known/security.txt"
];

export class ExposureReviewModule implements RouteCairnPlugin {
  public readonly name = "exposure-review";
  public readonly description = "Detects sensitive file, backup, config, debug, source map, and directory listing exposures using safe previews.";
  public readonly phase = "analysis";
  private readonly secretDetector = new SecretPatternDetector();
  private readonly recommendationEngine = new RecommendationEngine();
  private readonly riskScorer = new RiskScorer();

  public async run(context: ScanContext): Promise<ModuleResult> {
    const responses = [...context.state.getResponses()];
    const observations: ResponseObservation[] = [];

    for (const path of this.pathsToCheck(context)) {
      const target = normalizeUrl(path, context.options.target);
      const method: HttpMethod = "GET";
      const decision = context.scopeMatcher.decide(target, method);
      context.state.recordScopeDecision(decision);

      if (!decision.allowed || !decision.normalizedUrl) {
        continue;
      }

      const response = await context.httpClient.send({ url: decision.normalizedUrl, method });
      context.state.recordResponse(response);
      responses.push(response);
      observations.push(toObservation(response));
    }

    const findings = responses.flatMap((response) => this.findingsForResponse(response));

    return {
      pluginName: this.name,
      discoveredUrls: observations,
      findings,
      notes: [`Exposure findings: ${findings.length}.`]
    };
  }

  private pathsToCheck(context: ScanContext): string[] {
    const sourceMaps = context.state.getJsIntelligence()?.sourceMaps ?? [];
    const sourceMapPaths = sourceMaps.map((url) => `${new URL(url).pathname}${new URL(url).search}`);
    return [...new Set([...exposurePaths, ...sourceMapPaths])];
  }

  private findingsForResponse(response: HttpResponse): Finding[] {
    if (response.error || !response.statusCode || response.statusCode >= 400) {
      return [];
    }

    const url = new URL(response.finalUrl);
    const pathname = url.pathname;
    const findings: Finding[] = [];
    const analysisBody = bodyPreviewForAnalysis(response);
    const secretMatches = this.secretDetector.detect(analysisBody);

    if (secretMatches.length > 0) {
      findings.push(
        this.exposureFinding(response, "Sensitive File Exposure", "Sensitive file exposure detected", "High", [
          "exposure",
          "secret-like",
          ...secretMatches.map((match) => match.name.toLowerCase())
        ], secretPatternSummary(secretMatches))
      );
    }

    // Source-map availability alone is expected deployment intelligence. The
    // Next.js deep review (or the generic secret exposure rule above) only
    // creates a finding when sensitive security material is demonstrated.

    if (hasBackupResponseEvidence({ pathname, contentType: response.contentType, bodyPreview: analysisBody })) {
      findings.push(this.exposureFinding(response, "Backup File Exposure", "Backup or archive file is publicly reachable", "High", ["exposure", "backup"], "Backup-like path and response content indicate a reachable backup/archive."));
    }

    if (isConfigPath(pathname)) {
      findings.push(this.exposureFinding(response, "Config Exposure", "Configuration file is publicly reachable", secretMatches.length > 0 ? "High" : "Medium", ["exposure", "config"], "Config-like path returned a successful response."));
    }

    if (/debug|telescope|_debugbar|phpinfo|\.log$/i.test(pathname)) {
      findings.push(this.exposureFinding(response, "Debug/Dev Path", "Debug or log path is publicly reachable", "Medium", ["exposure", "debug"], "Debug/log path returned a successful response."));
    }

    if (isDirectoryListing(analysisBody)) {
      findings.push(this.exposureFinding(response, "Directory Listing", "Directory listing is enabled", "Medium", ["exposure", "directory-listing"], "Response resembles an auto-generated directory index."));
    }

    return dedupeFindings(findings);
  }

  private exposureFinding(response: HttpResponse, type: FindingType, title: string, severity: Severity, tags: string[], evidence: string): Finding {
    const confidence: Confidence = severity === "High" ? "High" : "Medium";
    const falsePositiveStatus = "likely-valid" as const;
    const findingBase = {
      severity,
      confidence,
      falsePositiveStatus,
      tags
    };

    return {
      id: `finding-${createHash("sha1").update(`${type}:${response.finalUrl}:${evidence}`).digest("hex").slice(0, 12)}`,
      title,
      type,
      severity,
      confidence,
      url: response.finalUrl,
      method: response.method,
      ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
      evidence: evidenceFromResponse(response, {
        source: evidence,
        severity,
        confidence,
        tags
      }),
      impact: impactForType(type),
      recommendation: this.recommendationEngine.recommendationFor(type),
      manualTestingSuggestions: manualSuggestionsForType(type),
      tags,
      riskScore: this.riskScorer.score(findingBase),
      sourceModule: this.name,
      falsePositiveStatus,
      timestamp: new Date().toISOString()
    };
  }
}

function secretPatternSummary(matches: readonly { name: string; count: number }[]): string {
  const total = matches.reduce((sum, match) => sum + match.count, 0);
  const names = matches.map((match) => match.name.replaceAll("_", " ").toLowerCase()).join(", ");
  return `Detected ${total} secret-like pattern${total === 1 ? "" : "s"}: ${names}. Raw values were excluded.`;
}

function toObservation(response: HttpResponse): ResponseObservation {
  return {
    url: response.finalUrl,
    method: response.method,
    source: "exposure-review",
    responseTimeMs: response.responseTimeMs,
    falsePositiveStatus: response.statusCode && response.statusCode < 400 ? "likely-valid" : "likely-false-positive",
    classificationReason: response.statusCode && response.statusCode < 400 ? `status ${response.statusCode}` : `status ${response.statusCode ?? "error"}`,
    ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(response.title ? { title: response.title } : {}),
    ...(response.contentType ? { contentType: response.contentType } : {}),
    ...(typeof response.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(response.bodyHash ? { bodyHash: response.bodyHash } : {}),
    responseHeaders: response.headers,
    ...(response.bodyPreview ? { bodyPreview: response.bodyPreview } : {})
  };
}

function impactForType(type: FindingType): string {
  if (type === "Sensitive File Exposure") {
    return "Exposed sensitive files can leak credentials, service endpoints, or deployment secrets.";
  }

  if (type === "Backup File Exposure") {
    return "Public backups may expose source code, data, credentials, or internal structure.";
  }

  if (type === "Source Map Exposure") {
    return "Public source maps can expose original frontend source and internal route or API references.";
  }

  if (type === "Directory Listing") {
    return "Directory listings can reveal files and paths that were not meant to be indexed.";
  }

  return "Public debug or configuration artifacts can expose implementation details and increase attack surface.";
}

function manualSuggestionsForType(type: FindingType): string[] {
  if (type === "Sensitive File Exposure") {
    return ["Capture minimal proof only", "Verify whether exposed values are active", "Recommend secret rotation if real secrets are present"];
  }

  if (type === "Source Map Exposure") {
    return ["Review source map content for sensitive comments, endpoints, or source disclosure impact"];
  }

  return ["Verify the file is intended to be public", "Capture only minimal evidence required for reporting"];
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.type}:${finding.url}`;
    if (seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
}
