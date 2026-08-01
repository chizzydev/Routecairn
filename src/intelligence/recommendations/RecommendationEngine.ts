import type { FindingType } from "../../core/findings/Finding.js";
import { recommendationRules } from "./recommendationRules.js";

export class RecommendationEngine {
  public recommendationFor(type: FindingType): string {
    return recommendationRules[type];
  }
}
