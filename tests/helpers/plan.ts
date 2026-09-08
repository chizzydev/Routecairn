import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import type { RouteCairnConfig, RouteCairnScope } from "../../src/config/ConfigSchema.js";
import type { ScanProfileName } from "../../src/config/ScanProfiles.js";
import { createDefaultPluginRegistry } from "../../src/core/engine/ScanOrchestrator.js";
import { ScanPlanner } from "../../src/core/planning/ScanPlanner.js";
import type { ResolvedScanPlan, ScanPlannerInput } from "../../src/core/planning/ScanPlan.js";

export function testPlan(
  profile: ScanProfileName,
  options: { scope?: RouteCairnScope; config?: RouteCairnConfig; overrides?: ScanPlannerInput["overrides"] } = {}
): ResolvedScanPlan {
  const scope = options.scope ?? exampleScope;
  const config = options.config ?? defaultConfig;
  return new ScanPlanner(createDefaultPluginRegistry()).resolve({
    requestedProfile: profile,
    scope,
    config,
    ...(options.overrides ? { overrides: options.overrides } : {})
  });
}
