import type { ScanContext } from "../engine/ScanContext.js";
import type { ResolvedScanPlan } from "../planning/ScanPlan.js";
import type { ModuleResult } from "./Plugin.js";
import { PluginRegistry } from "./PluginRegistry.js";

export class ModuleRunner {
  public constructor(private readonly registry: PluginRegistry) {}

  public async runPlan(context: ScanContext, plan: ResolvedScanPlan): Promise<ModuleResult[]> {
    const results: ModuleResult[] = [];

    for (const modulePlan of plan.modules) {
      const registration = this.registry.get(modulePlan.id);
      if (!registration) {
        throw new Error(`Planned module is not registered: ${modulePlan.id}`);
      }

      const result = await registration.plugin.run(context);
      context.state.recordModuleResult(result);
      results.push(result);
    }

    return results;
  }
}
