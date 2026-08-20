import type { ScanContext } from "../engine/ScanContext.js";
import { ScanCancelledError, throwIfScanAborted } from "../engine/ScanEvents.js";
import type { ResolvedScanPlan } from "../planning/ScanPlan.js";
import type { ModuleResult } from "./Plugin.js";
import { PluginRegistry } from "./PluginRegistry.js";

export class ModuleRunner {
  public constructor(private readonly registry: PluginRegistry) {}

  public async runPlan(context: ScanContext, plan: ResolvedScanPlan): Promise<ModuleResult[]> {
    const results: ModuleResult[] = [];

    for (const [index, modulePlan] of plan.modules.entries()) {
      throwIfScanAborted(context.options.abortSignal);
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
        const result = await registration.plugin.run(context);
        throwIfScanAborted(context.options.abortSignal);
        context.state.recordModuleResult(result);
        results.push(result);
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
