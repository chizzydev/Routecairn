import type { HttpMethod } from "../../core/http/HttpTypes.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import { Soft404Detector } from "./Soft404Detector.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";

export class BaselineDetector implements RouteCairnPlugin {
  public readonly name = "baseline";
  public readonly description = "Probes random non-existing paths to identify soft-404 and wildcard response behavior.";
  public readonly phase = "baseline";
  private readonly soft404Detector = new Soft404Detector();

  public async run(context: ScanContext): Promise<ModuleResult> {
    const target = normalizeUrl(context.options.target);
    const probes = await Promise.all(
      this.probePaths().map(async (path) => {
        const url = normalizeUrl(path, target);
        const method: HttpMethod = "GET";
        const decision = context.scopeMatcher.decide(url, method);
        context.state.recordScopeDecision(decision);

        if (!decision.allowed || !decision.normalizedUrl) {
          return undefined;
        }

        const response = await context.httpClient.send({
          url: decision.normalizedUrl,
          method
        });
        context.state.recordResponse(response);
        return response;
      })
    );

    const baseline = this.soft404Detector.analyze(probes.filter((probe) => typeof probe !== "undefined"));

    return {
      pluginName: this.name,
      baseline,
      notes: baseline.notes
    };
  }

  private probePaths(): string[] {
    return Array.from({ length: 3 }, (_item, index) => {
      const token = `${Date.now().toString(36)}-${index}-${Math.random().toString(36).slice(2, 10)}`;
      return `/.routecairn-nonexistent-${token}`;
    });
  }
}
