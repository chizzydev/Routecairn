import type { ScanContext } from "../engine/ScanContext.js";
import { ScanCancelledError, throwIfScanAborted } from "../engine/ScanEvents.js";
import type { ResolvedScanPlan } from "../planning/ScanPlan.js";
import type { ModuleResult } from "./Plugin.js";
import { PluginRegistry } from "./PluginRegistry.js";
import { acceptAssistedWorkflowFindings } from "../findings/AssistedWorkflowFindingAcceptance.js";
import { collectAssistedCases } from "../../modules/assistedReview/AssistedCaseCollector.js";

export class ModuleRunner {
  public constructor(private readonly registry: PluginRegistry) {}

  public async runPlan(context: ScanContext, plan: ResolvedScanPlan): Promise<ModuleResult[]> {
    const results: ModuleResult[] = [];

    for (const [index, modulePlan] of plan.modules.entries()) {
      throwIfScanAborted(context.options.abortSignal);
      if (plan.preHandover && modulePlan.id !== "assisted-review" && results.flatMap((result) => collectAssistedCases(result, context.state.getFindings())).some((item) => item.cleanupFailed)) {
        await context.eventSink.emit({ type: "OBSERVATION_RECORDED", moduleId: modulePlan.id, message: "Pre-handover sequence stopped: prior cleanup is unresolved." });
        continue;
      }
      const registration = this.registry.get(modulePlan.id);
      if (!registration) {
        throw new Error(`Planned module is not registered: ${modulePlan.id}`);
      }

      await context.eventSink.emit({
        type: "MODULE_STARTED",
        moduleId: modulePlan.id,
        message: `Module ${modulePlan.id} started.`,
        metadata: { plannedOrder: index + 1, plannedModuleCount: plan.modules.length }
      });

      try {
        const rawResult = await registration.plugin.run(context);
        let result: ModuleResult;
        try {
          result = acceptAssistedWorkflowFindings(rawResult);
        } catch (error) {
          context.state.recordModuleResult({ ...rawResult, findings: [], notes: [...(rawResult.notes ?? []), "FINDING_ACCEPTANCE_REJECTED: case evidence and cleanup results retained."] });
          throw error;
        }
        context.state.recordModuleResult(result);
        context.partialModules.delete(result.pluginName);
        await context.options.checkpointReport?.();
        results.push(result);
        // Modules with abort-aware cleanup may return a valuable partial result
        // after the deadline/cancellation signal. Persist it before propagating
        // cancellation so cleanup failures and safe evidence reach the report.
        throwIfScanAborted(context.options.abortSignal);
        await context.eventSink.emit({
          type: "MODULE_COMPLETED",
          moduleId: modulePlan.id,
          message: `Module ${modulePlan.id} completed.`,
          metadata: { findings: result.findings?.length ?? 0 }
        });
      } catch (error) {
        if (error instanceof ScanCancelledError || context.options.abortSignal?.aborted) {
          await context.eventSink.emit({ type: "MODULE_CANCELLED", moduleId: modulePlan.id, message: `Module ${modulePlan.id} cancelled.` });
          throw new ScanCancelledError();
        }

        await context.eventSink.emit({ type: "MODULE_FAILED", moduleId: modulePlan.id, message: safeErrorMessage(error) });
        throw error;
      }
    }

    return results;
  }
}

function safeErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Module failed with an unknown error.";
}
