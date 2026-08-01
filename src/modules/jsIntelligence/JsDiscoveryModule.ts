import type { HttpMethod } from "../../core/http/HttpTypes.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { JsIntelligenceReport, JsScriptAnalysis, PathCandidate } from "../../reports/ReportTypes.js";
import { JsEndpointExtractor } from "./JsEndpointExtractor.js";
import { PublicConfigAnalyzer } from "./PublicConfigAnalyzer.js";
import { ScriptExtractor } from "./ScriptExtractor.js";
import { SourceMapDetector } from "./SourceMapDetector.js";

export class JsDiscoveryModule implements RouteCairnPlugin {
  public readonly name = "js-intelligence";
  public readonly description = "Extracts script URLs, downloads same-origin JavaScript, mines endpoints and config-looking values, and detects source maps.";
  public readonly phase = "intelligence";
  private readonly scriptExtractor = new ScriptExtractor();
  private readonly endpointExtractor = new JsEndpointExtractor();
  private readonly configAnalyzer = new PublicConfigAnalyzer();
  private readonly sourceMapDetector = new SourceMapDetector();

  public async run(context: ScanContext): Promise<ModuleResult> {
    const htmlResponses = context.state
      .getResponses()
      .filter((response) => isHtmlResponse(response.contentType, response.bodyPreview));
    const targetOrigin = new URL(normalizeUrl(context.options.target)).origin;
    const scriptUrls = new Set<string>();

    for (const response of htmlResponses) {
      for (const scriptUrl of this.scriptExtractor.extract(response.bodyPreview ?? "", response.finalUrl)) {
        scriptUrls.add(scriptUrl);
      }
    }

    const scripts: JsScriptAnalysis[] = [];
    const queuedEndpoints = new Map<string, PathCandidate>();
    const sourceMaps = new Set<string>();

    for (const scriptUrl of scriptUrls) {
      const sameOrigin = new URL(scriptUrl).origin === targetOrigin;

      if (!sameOrigin) {
        scripts.push({
          scriptUrl,
          sameOrigin,
          downloaded: false,
          endpoints: [],
          absoluteUrls: [],
          websocketUrls: [],
          cloudReferences: [],
          configValues: [],
          sourceMapUrls: []
        });
        continue;
      }

      const decision = context.scopeMatcher.decide(scriptUrl, "GET");
      context.state.recordScopeDecision(decision);

      if (!decision.allowed || !decision.normalizedUrl) {
        scripts.push({
          scriptUrl,
          sameOrigin,
          downloaded: false,
          endpoints: [],
          absoluteUrls: [],
          websocketUrls: [],
          cloudReferences: [],
          configValues: [],
          sourceMapUrls: [],
          error: `script skipped: ${decision.reason}`
        });
        continue;
      }

      const response = await context.httpClient.send({
        url: decision.normalizedUrl,
        method: "GET"
      });
      context.state.recordResponse(response);

      if (response.error || !response.bodyPreview) {
        scripts.push({
          scriptUrl,
          sameOrigin,
          downloaded: false,
          endpoints: [],
          absoluteUrls: [],
          websocketUrls: [],
          cloudReferences: [],
          configValues: [],
          sourceMapUrls: [],
          error: response.error?.message ?? "empty JavaScript response"
        });
        continue;
      }

      const extraction = this.endpointExtractor.extract(response.bodyPreview);
      const configValues = this.configAnalyzer.analyze(response.bodyPreview);
      const sourceMapUrls = this.sourceMapDetector.detect(response.bodyPreview, response.finalUrl);

      for (const sourceMapUrl of sourceMapUrls) {
        sourceMaps.add(sourceMapUrl);
      }

      for (const endpoint of [...extraction.endpoints, ...extraction.absoluteUrls]) {
        const candidate = this.toScopedCandidate(endpoint, response.finalUrl, context);

        if (candidate) {
          queuedEndpoints.set(candidate.path, candidate);
        }
      }

      scripts.push({
        scriptUrl,
        sameOrigin,
        downloaded: true,
        endpoints: extraction.endpoints,
        absoluteUrls: extraction.absoluteUrls,
        websocketUrls: extraction.websocketUrls,
        cloudReferences: extraction.cloudReferences,
        configValues,
        sourceMapUrls
      });
    }

    const report: JsIntelligenceReport = {
      scripts,
      queuedEndpoints: [...queuedEndpoints.values()],
      sourceMaps: [...sourceMaps],
      notes: notesForScripts(scripts)
    };

    return {
      pluginName: this.name,
      jsIntelligence: report,
      notes: report.notes
    };
  }

  private toScopedCandidate(rawEndpoint: string, baseUrl: string, context: ScanContext): PathCandidate | undefined {
    let normalized: string;

    try {
      normalized = normalizeUrl(rawEndpoint, baseUrl);
    } catch {
      return undefined;
    }

    const method: HttpMethod = "GET";
    const decision = context.scopeMatcher.decide(normalized, method);
    context.state.recordScopeDecision(decision);

    if (!decision.allowed || !decision.normalizedUrl) {
      return undefined;
    }

    const url = new URL(decision.normalizedUrl);
    return {
      path: `${url.pathname}${url.search}`,
      source: "js:endpoint"
    };
  }
}

function isHtmlResponse(contentType: string | undefined, bodyPreview: string | undefined): boolean {
  return contentType?.includes("text/html") === true || bodyPreview?.toLowerCase().includes("<script") === true;
}

function notesForScripts(scripts: JsScriptAnalysis[]): string[] {
  const notes: string[] = [];
  const downloaded = scripts.filter((script) => script.downloaded).length;
  const sourceMapCount = scripts.reduce((total, script) => total + script.sourceMapUrls.length, 0);
  const publicConfigCount = scripts.reduce(
    (total, script) => total + script.configValues.filter((value) => value.classification === "public-frontend-config").length,
    0
  );

  notes.push(`Scripts discovered: ${scripts.length}.`);
  notes.push(`Same-origin scripts downloaded: ${downloaded}.`);

  if (sourceMapCount > 0) {
    notes.push(`Source map references detected: ${sourceMapCount}.`);
  }

  if (publicConfigCount > 0) {
    notes.push(`Public frontend config values detected: ${publicConfigCount}; these are not treated as secrets by default.`);
  }

  return notes;
}
