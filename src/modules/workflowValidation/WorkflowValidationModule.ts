import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { buildEvidenceTemplates } from "../../intelligence/evidenceTemplates/EvidenceTemplateFactory.js";
import type { WorkflowValidationReport } from "../../reports/ReportTypes.js";

export class WorkflowValidationModule implements RouteCairnPlugin {
  public readonly name = "workflow-validation";
  public readonly description = "Builds structured manual proof templates for safe vulnerability validation.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const templates = buildEvidenceTemplates({
      workflows: context.state.getVulnerabilityWorkflows()?.workflows ?? [],
      authSurface: context.state.getAuthSurface(),
      roleComparison: context.state.getRoleComparison(),
      stateAwareApi: context.state.getStateAwareApi(),
      parameterAnalysis: context.state.getParameterAnalysis()
    });
    const report: WorkflowValidationReport = {
      templates,
      notes:
        templates.length === 0
          ? ["No manual evidence templates were generated from current scan evidence."]
          : [
              `Generated ${templates.length} manual evidence template(s).`,
              "Manual Test Pack templates are safe proof-collection guides, not confirmed vulnerabilities.",
              "Follow program rules and use only accounts/resources you are authorized to test."
            ]
    };

    return {
      pluginName: this.name,
      workflowValidation: report,
      notes: report.notes
    };
  }
}
