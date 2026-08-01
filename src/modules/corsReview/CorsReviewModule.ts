import type { HttpMethod } from "../../core/http/HttpTypes.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";
import { corsFinding } from "./CorsRules.js";

export class CorsReviewModule implements RouteCairnPlugin {
  public readonly name = "cors-review";
  public readonly description = "Performs controlled CORS Origin probes with conservative severity.";
  public readonly phase = "analysis";

  public async run(context: ScanContext): Promise<ModuleResult> {
    const targetUrl = normalizeUrl(context.options.target);
    const findings = [];
    const method: HttpMethod = "GET";

    for (const origin of ["https://example-attacker.invalid", "null"]) {
      const decision = context.scopeMatcher.decide(targetUrl, method);
      context.state.recordScopeDecision(decision);

      if (!decision.allowed || !decision.normalizedUrl) {
        continue;
      }

      const response = await context.httpClient.send({
        url: decision.normalizedUrl,
        method,
        headers: {
          Origin: origin
        }
      });
      context.state.recordResponse(response);

      const finding = corsFinding(response, origin);
      if (finding) {
        findings.push(finding);
      }
    }

    return {
      pluginName: this.name,
      findings,
      notes: [`CORS findings: ${findings.length}.`]
    };
  }
}
