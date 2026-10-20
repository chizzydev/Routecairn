import type { RouteCairnPlugin, ModuleResult } from "./Plugin.js";
import type { ModuleMetadata } from "../planning/ScanPlan.js";
import type { ScanContext } from "../engine/ScanContext.js";
import { throwIfScanAborted } from "../engine/ScanEvents.js";
/** Built-in, static allowlisted imports only. Planning reads metadata without loading detectors.
 * A rejected load stays rejected; cancellation is rechecked before execution. */
export class DeferredPlugin implements RouteCairnPlugin {
  public readonly name;
  public readonly phase;
  public readonly description;
  private loading: Promise<RouteCairnPlugin> | undefined;
  constructor(
    metadata: ModuleMetadata,
    private readonly load: () => Promise<RouteCairnPlugin>
  ) {
    this.name = metadata.id;
    this.phase = metadata.phase;
    this.description = metadata.description;
  }
  public async run(context: ScanContext): Promise<ModuleResult> {
    throwIfScanAborted(context.options.abortSignal);
    this.loading ??= Promise.resolve()
      .then(this.load)
      .then((plugin) => {
        if (plugin.name !== this.name || plugin.phase !== this.phase) throw Error("BUILTIN_MODULE_IDENTITY_MISMATCH");
        return plugin;
      });
    const plugin = await this.loading;
    throwIfScanAborted(context.options.abortSignal);
    return plugin.run(context);
  }
}
