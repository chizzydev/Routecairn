import type { RouteCairnPlugin } from "./Plugin.js";
import type { ModuleId, ModuleMetadata } from "../planning/ScanPlan.js";

export interface RegisteredPlugin {
  plugin: RouteCairnPlugin;
  metadata: ModuleMetadata;
}

export class PluginRegistry {
  private readonly plugins = new Map<ModuleId, RegisteredPlugin>();

  public register(plugin: RouteCairnPlugin, metadata: ModuleMetadata): void {
    if (plugin.name !== metadata.id) {
      throw new Error(`Plugin name ${plugin.name} does not match metadata id ${metadata.id}`);
    }

    if (this.plugins.has(metadata.id)) {
      throw new Error(`Plugin already registered: ${plugin.name}`);
    }

    this.plugins.set(metadata.id, { plugin, metadata });
  }

  public get(id: ModuleId): RegisteredPlugin | undefined {
    return this.plugins.get(id);
  }

  public list(): RegisteredPlugin[] {
    return [...this.plugins.values()].sort((left, right) => compareMetadata(left.metadata, right.metadata));
  }
}

export function compareMetadata(left: ModuleMetadata, right: ModuleMetadata): number {
  const phaseDelta = phaseOrder(left.phase) - phaseOrder(right.phase);
  if (phaseDelta !== 0) {
    return phaseDelta;
  }

  return left.id.localeCompare(right.id);
}

export function phaseOrder(phase: RouteCairnPlugin["phase"]): number {
  if (phase === "baseline") {
    return 0;
  }

  if (phase === "fingerprint") {
    return 1;
  }

  if (phase === "intelligence") {
    return 2;
  }

  if (phase === "discovery") {
    return 3;
  }

  return 4;
}
