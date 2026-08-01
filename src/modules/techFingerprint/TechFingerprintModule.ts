import type { RouteCairnPlugin, ModuleResult } from "../../core/plugins/Plugin.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import { TechnologyClassifier } from "./TechnologyClassifier.js";

export class TechFingerprintModule implements RouteCairnPlugin {
  public readonly name = "tech-fingerprint";
  public readonly description = "Detects common frameworks, platforms, servers, CMSs, commerce stacks, and cloud references.";
  public readonly phase = "fingerprint";
  private readonly classifier = new TechnologyClassifier();

  public async run(context: ScanContext): Promise<ModuleResult> {
    const technologies = this.classifier.classify(context.state.getResponses());

    return {
      pluginName: this.name,
      technologies,
      notes: technologies.map((technology) => `Detected ${technology.name} (${technology.confidence})`)
    };
  }
}
