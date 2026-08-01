import { describe, expect, it, vi } from "vitest";
import type { ModuleMetadata } from "../../src/core/planning/ScanPlan.js";
import type { RouteCairnPlugin } from "../../src/core/plugins/Plugin.js";
import { PluginRegistry } from "../../src/core/plugins/PluginRegistry.js";
import { ModuleRunner } from "../../src/core/plugins/ModuleRunner.js";
import { testPlan } from "../helpers/plan.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";

describe("PluginRegistry", () => {
  it("registers plugins with metadata and returns deterministic phase order", () => {
    const registry = new PluginRegistry();
    registry.register(plugin("api-mapper", "analysis"), metadata("api-mapper", "analysis"));
    registry.register(plugin("baseline", "baseline"), metadata("baseline", "baseline"));
    registry.register(plugin("path-discovery", "discovery"), metadata("path-discovery", "discovery"));

    expect(registry.list().map((item) => item.metadata.id)).toEqual(["baseline", "path-discovery", "api-mapper"]);
  });

  it("rejects mismatched plugin and metadata identifiers", () => {
    const registry = new PluginRegistry();

    expect(() => registry.register(plugin("baseline", "baseline"), metadata("api-mapper", "analysis"))).toThrow(/does not match/);
  });

  it("executes the resolved plan instead of independently interpreting profile or mode", async () => {
    const registry = new PluginRegistry();
    const baseline = plugin("baseline", "baseline");
    const apiMapper = plugin("api-mapper", "analysis");
    registry.register(baseline, metadata("baseline", "baseline"));
    registry.register(apiMapper, metadata("api-mapper", "analysis"));
    const baselineRun = vi.spyOn(baseline, "run");
    const apiRun = vi.spyOn(apiMapper, "run");
    const plan = { ...testPlan("quick"), modules: [{ id: "baseline", phase: "baseline", settings: {}, limits: {}, includedBecause: ["test"] }] };
    const context = new ScanContext({
      target: "https://example.com",
      scope: exampleScope,
      config: defaultConfig,
      plan,
      outputDir: "."
    });

    await new ModuleRunner(registry).runPlan(context, plan);

    expect(baselineRun).toHaveBeenCalledTimes(1);
    expect(apiRun).not.toHaveBeenCalled();
  });
});

function plugin(name: RouteCairnPlugin["name"], phase: RouteCairnPlugin["phase"]): RouteCairnPlugin {
  return {
    name,
    description: name,
    phase,
    async run() {
      return { pluginName: name };
    }
  };
}

function metadata(id: ModuleMetadata["id"], phase: ModuleMetadata["phase"]): ModuleMetadata {
  return {
    id,
    displayName: id,
    description: id,
    phase,
    capabilities: [],
    requiresAuthentication: "none",
    monitoringCompatible: true,
    supportsEvidence: true,
    dependencies: [],
    orderAfter: [],
    cost: "low",
    readiness: "production",
    defaultSettings: {},
    supportedSettings: []
  };
}
