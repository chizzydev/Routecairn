import { ScanContext } from "../../core/engine/ScanContext.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { headerFindings } from "./HeaderRules.js";

export class HeaderReviewModule implements RouteCairnPlugin {
  public readonly name = "header-review";
  public readonly description = "Reviews security-relevant response headers with conservative severity.";
  public readonly phase = "analysis";

  public async run(context: ScanContext): Promise<ModuleResult> {
    const firstResponse = context.state.getResponses()[0];
    const findings = firstResponse ? headerFindings(firstResponse) : [];

    return {
      pluginName: this.name,
      findings,
      notes: [`Header findings: ${findings.length}.`]
    };
  }
}
