import type { HttpMethod } from "../../core/http/HttpTypes.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";
import { methodFindings } from "./MethodRules.js";

export class MethodReviewModule implements RouteCairnPlugin {
  public readonly name = "method-review";
  public readonly description = "Reviews OPTIONS responses for advertised dangerous HTTP methods.";
  public readonly phase = "analysis";

  public async run(context: ScanContext): Promise<ModuleResult> {
    const targetUrl = normalizeUrl(context.options.target);
    const method: HttpMethod = "OPTIONS";
    const decision = context.scopeMatcher.decide(targetUrl, method);
    context.state.recordScopeDecision(decision);

    if (!decision.allowed || !decision.normalizedUrl) {
      return {
        pluginName: this.name,
        findings: [],
        notes: [`Method review skipped: ${decision.reason}.`]
      };
    }

    const response = await context.httpClient.send({
      url: decision.normalizedUrl,
      method
    });
    context.state.recordResponse(response);
    const findings = methodFindings(response);

    return {
      pluginName: this.name,
      findings,
      notes: [`Method findings: ${findings.length}.`]
    };
  }
}
