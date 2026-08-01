import type { Finding } from "./Finding.js";
import type { Confidence } from "./Confidence.js";
import type { Severity } from "./Severity.js";

const severityScores: Record<Severity, number> = {
  Informational: 10,
  Low: 25,
  Medium: 50,
  High: 75,
  Critical: 95
};

const confidenceMultipliers: Record<Confidence, number> = {
  Low: 0.65,
  Medium: 0.85,
  High: 1
};

export class RiskScorer {
  public score(input: Pick<Finding, "severity" | "confidence" | "falsePositiveStatus" | "tags">): number {
    let score = severityScores[input.severity] * confidenceMultipliers[input.confidence];

    if (input.falsePositiveStatus === "maybe-false-positive") {
      score *= 0.75;
    }

    if (input.tags.includes("secret-like") || input.tags.includes("exposure")) {
      score += 10;
    }

    if (input.tags.includes("source-map")) {
      score += 5;
    }

    return Math.max(0, Math.min(100, Math.round(score)));
  }
}
