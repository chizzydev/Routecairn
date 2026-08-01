import type { HttpMethod } from "../../core/http/HttpTypes.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";
import type { ResponseObservation } from "../../reports/ReportTypes.js";
import { FindingFactory } from "../../core/findings/FindingFactory.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { InterestingResponseDetector } from "../responseAnalysis/InterestingResponseDetector.js";
import { TechAwarePathGenerator } from "./TechAwarePathGenerator.js";
import { WordlistLoader } from "./WordlistLoader.js";

export class PathDiscoveryModule implements RouteCairnPlugin {
  public readonly name = "path-discovery";
  public readonly description = "Tests scoped wordlist paths and classifies responses against baseline behavior.";
  public readonly phase = "discovery";
  private readonly wordlistLoader = new WordlistLoader();
  private readonly techAwarePathGenerator = new TechAwarePathGenerator();
  private readonly responseDetector = new InterestingResponseDetector();
  private readonly findingFactory = new FindingFactory();

  public async run(context: ScanContext): Promise<ModuleResult> {
    const baseline = context.state.getBaseline();
    const sources = context.moduleSettings(this.name).pathSources ?? ["wordlist:common", "wordlist:admin", "wordlist:api"];
    const entries = [
      ...(await this.wordlistLoader.load([...sources])),
      ...this.techAwarePathGenerator.generate(context.state.getTechnologies()),
      ...context.state.getQueuedPathCandidates()
    ];
    const target = normalizeUrl(context.options.target);
    const seen = new Set<string>();
    const observations: ResponseObservation[] = [];

    for (const entry of entries) {
      const candidateUrl = normalizeUrl(entry.path, target);
      if (seen.has(candidateUrl)) {
        continue;
      }

      seen.add(candidateUrl);

      const method: HttpMethod = "GET";
      const decision = context.scopeMatcher.decide(candidateUrl, method);
      context.state.recordScopeDecision(decision);

      if (!decision.allowed || !decision.normalizedUrl) {
        continue;
      }

      const response = await context.httpClient.send({
        url: decision.normalizedUrl,
        method
      });
      const classification = this.responseDetector.classify(response, baseline);

      context.state.recordResponse(response);
      observations.push({
        url: response.finalUrl,
        method,
        source: entry.source,
        responseTimeMs: response.responseTimeMs,
        falsePositiveStatus: classification.falsePositiveStatus,
        classificationReason: classification.reason,
        ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
        ...(response.title ? { title: response.title } : {}),
        ...(response.contentType ? { contentType: response.contentType } : {}),
        ...(typeof response.contentLength === "number" ? { contentLength: response.contentLength } : {}),
        ...(response.bodyHash ? { bodyHash: response.bodyHash } : {}),
        responseHeaders: response.headers,
        ...(response.bodyPreview ? { bodyPreview: response.bodyPreview } : {})
      });
    }

    return {
      pluginName: this.name,
      discoveredUrls: observations,
      findings: observations
        .map((observation) => this.findingFactory.fromResponseObservation(observation, this.name))
        .filter((finding) => typeof finding !== "undefined")
    };
  }
}
