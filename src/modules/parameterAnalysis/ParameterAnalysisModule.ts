import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { analyzePathSegment, analyzeQueryParameter } from "../../intelligence/parameters/ParameterClassifier.js";
import type { ParameterAnalysisReport, ParameterizedUrlAnalysis, ParameterRiskTag, ParameterSignal } from "../../reports/ReportTypes.js";

export class ParameterAnalysisModule implements RouteCairnPlugin {
  public readonly name = "parameter-analysis";
  public readonly description = "Classifies URL and API parameters for access-control and business-logic review.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = analyzeParameters(context);

    return {
      pluginName: this.name,
      parameterAnalysis: report,
      notes: report.notes
    };
  }
}

function analyzeParameters(context: ScanContext): ParameterAnalysisReport {
  const urls = candidateUrls(context);
  const analyzedUrls = urls.map((url) => analyzeUrl(url)).filter((analysis) => analysis.parameters.length > 0);
  const allParameters = analyzedUrls.flatMap((analysis) => analysis.parameters);
  const highRiskParameters = allParameters.filter((parameter) => isHighRisk(parameter));

  return {
    analyzedUrls,
    totalParameters: allParameters.length,
    highRiskParameters,
    riskSummary: {
      objectId: countRisk(allParameters, "object-id"),
      authorizationSensitive: countRisk(allParameters, "authorization-sensitive"),
      businessLogic: countRisk(allParameters, "business-logic"),
      harmlessNavigation: countRisk(allParameters, "harmless-navigation")
    },
    workflowTargets: analyzedUrls
      .filter((analysis) => analysis.parameters.some((parameter) => isHighRisk(parameter)))
      .map((analysis) => ({
        url: analysis.url,
        reasons: [...new Set(analysis.parameters.flatMap((parameter) => parameter.riskTags).filter((tag) => tag !== "harmless-navigation"))],
        suggestedWorkflow: analysis.parameters.some((parameter) => parameter.riskTags.includes("authorization-sensitive"))
          ? "IDOR/BOLA authorization review"
          : "Business-logic parameter review"
      })),
    notes:
      allParameters.length === 0
        ? ["No URL or API parameters were identified in the current scan evidence."]
        : [
            `Analyzed ${analyzedUrls.length} URL(s) with ${allParameters.length} parameter signal(s).`,
            "High-risk parameter signals feed manual workflows as hypotheses, not confirmed vulnerabilities.",
            "Token-like values are previewed only and should not be collected beyond minimal proof."
          ]
  };
}

function candidateUrls(context: ScanContext): string[] {
  const urls = new Set<string>();

  for (const observation of context.state.getDiscoveredUrls()) {
    if (observation.falsePositiveStatus !== "likely-false-positive") {
      urls.add(observation.url);
    }
  }

  for (const endpoint of context.state.getApiMapper()?.endpoints ?? []) {
    urls.add(endpoint.endpoint);
  }

  for (const review of context.state.getStateAwareApi()?.reviewedEndpoints ?? []) {
    urls.add(review.endpoint);
  }

  for (const candidate of context.state.getQueuedPathCandidates()) {
    try {
      const base = context.scopeMatcher.decide(context.options.target, "GET").normalizedUrl ?? context.options.target;
      urls.add(new URL(candidate.path, base).toString());
    } catch {
      // Ignore malformed candidates already handled elsewhere.
    }
  }

  return [...urls].filter((url) => context.scopeMatcher.decide(url, "GET").allowed).sort();
}

function analyzeUrl(url: string): ParameterizedUrlAnalysis {
  const parsed = new URL(url);
  const parameters: ParameterSignal[] = [];

  for (const [name, value] of parsed.searchParams.entries()) {
    parameters.push(analyzeQueryParameter(name, value));
  }

  const segments = parsed.pathname.split("/").filter(Boolean);
  for (let index = 0; index < segments.length; index += 1) {
    const signal = analyzePathSegment(segments[index]!, index, segments[index - 1]);
    if (signal) {
      parameters.push(signal);
    }
  }

  return {
    url,
    path: parsed.pathname,
    parameters,
    highRisk: parameters.some((parameter) => isHighRisk(parameter))
  };
}

function isHighRisk(parameter: ParameterSignal): boolean {
  return parameter.riskTags.includes("authorization-sensitive") || parameter.riskTags.includes("business-logic");
}

function countRisk(parameters: ParameterSignal[], tag: ParameterRiskTag): number {
  return parameters.filter((parameter) => parameter.riskTags.includes(tag)).length;
}
