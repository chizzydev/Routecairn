import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import type { ApiMapperReport } from "../../reports/ReportTypes.js";
import { ApiRouteClassifier } from "./ApiRouteClassifier.js";
import { apiMapperNotes } from "./ApiRiskHints.js";

export class ApiMapperModule implements RouteCairnPlugin {
  public readonly name = "api-mapper";
  public readonly description = "Classifies API endpoints and adds manual testing guidance.";
  public readonly phase = "analysis";
  private readonly classifier = new ApiRouteClassifier();

  public async run(context: ScanContext): Promise<ModuleResult> {
    const endpoints = context.state
      .getDiscoveredUrls()
      .filter((observation) => observation.falsePositiveStatus !== "likely-false-positive")
      .map((observation) => this.classifier.classify(observation))
      .filter((endpoint) => typeof endpoint !== "undefined");
    const report: ApiMapperReport = {
      endpoints,
      graphQlEndpoints: endpoints.filter((endpoint) => endpoint.routeType === "graphql").map((endpoint) => endpoint.endpoint),
      notes: apiMapperNotes(endpoints)
    };

    return {
      pluginName: this.name,
      apiMapper: report,
      notes: report.notes
    };
  }
}
