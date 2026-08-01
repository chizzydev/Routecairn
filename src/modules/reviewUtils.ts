import { createHash } from "node:crypto";
import type { Finding, FindingType } from "../core/findings/Finding.js";
import type { Confidence } from "../core/findings/Confidence.js";
import type { Severity } from "../core/findings/Severity.js";
import type { HttpResponse } from "../core/http/HttpTypes.js";
import { RiskScorer } from "../core/findings/RiskScorer.js";
import { evidenceFromResponse } from "../core/evidence/EvidenceBuilder.js";

export interface ReviewFindingInput {
  title: string;
  type: FindingType;
  severity: Severity;
  confidence: Confidence;
  response: HttpResponse;
  sourceModule: string;
  evidence: string;
  impact: string;
  recommendation: string;
  tags: string[];
  manualTestingSuggestions?: string[];
}

export function createReviewFinding(input: ReviewFindingInput): Finding {
  const riskScorer = new RiskScorer();
  const findingBase = {
    severity: input.severity,
    confidence: input.confidence,
    falsePositiveStatus: "likely-valid" as const,
    tags: input.tags
  };

  const id = createHash("sha1")
    .update(`${input.sourceModule}:${input.type}:${input.title}:${input.response.finalUrl}:${input.evidence}`)
    .digest("hex")
    .slice(0, 12);

  return {
    id: `finding-${id}`,
    title: input.title,
    type: input.type,
    severity: input.severity,
    confidence: input.confidence,
    url: input.response.finalUrl,
    method: input.response.method,
    ...(typeof input.response.statusCode === "number" ? { statusCode: input.response.statusCode } : {}),
    evidence: evidenceFromResponse(input.response, {
      source: input.evidence,
      severity: input.severity,
      confidence: input.confidence,
      tags: input.tags
    }),
    impact: input.impact,
    recommendation: input.recommendation,
    manualTestingSuggestions: input.manualTestingSuggestions ?? ["Review manually in the authorized testing context."],
    tags: input.tags,
    riskScore: riskScorer.score(findingBase),
    sourceModule: input.sourceModule,
    falsePositiveStatus: findingBase.falsePositiveStatus,
    timestamp: new Date().toISOString()
  };
}

export function headerValue(headers: Record<string, string | string[]>, name: string): string | undefined {
  const value = headers[name.toLowerCase()];

  if (Array.isArray(value)) {
    return value.join(", ");
  }

  return value;
}

export function headerValues(headers: Record<string, string | string[]>, name: string): string[] {
  const value = headers[name.toLowerCase()];

  if (Array.isArray(value)) {
    return value;
  }

  return value ? [value] : [];
}
