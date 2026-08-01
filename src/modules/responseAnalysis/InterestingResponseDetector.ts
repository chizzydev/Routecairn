import type { HttpResponse } from "../../core/http/HttpTypes.js";
import type { BaselineReport, FalsePositiveStatus } from "../../reports/ReportTypes.js";
import { hasSimilarLength } from "./BodyFingerprint.js";

export interface ResponseClassification {
  falsePositiveStatus: FalsePositiveStatus;
  reason: string;
}

export class InterestingResponseDetector {
  public classify(response: HttpResponse, baseline: BaselineReport | undefined): ResponseClassification {
    if (response.error) {
      return {
        falsePositiveStatus: "likely-false-positive",
        reason: `request error: ${response.error.message}`
      };
    }

    if (response.statusCode === 404 || response.statusCode === 410) {
      return {
        falsePositiveStatus: "likely-false-positive",
        reason: `status ${response.statusCode}`
      };
    }

    if (baseline && this.matchesBaseline(response, baseline)) {
      return {
        falsePositiveStatus: "maybe-false-positive",
        reason: "response resembles non-existing baseline behavior"
      };
    }

    if (typeof response.statusCode === "number" && response.statusCode >= 200 && response.statusCode < 400) {
      return {
        falsePositiveStatus: "likely-valid",
        reason: `status ${response.statusCode}`
      };
    }

    return {
      falsePositiveStatus: "maybe-false-positive",
      reason: `unusual status ${response.statusCode ?? "unknown"}`
    };
  }

  private matchesBaseline(response: HttpResponse, baseline: BaselineReport): boolean {
    if (baseline.repeatedBodyHash && response.bodyHash === baseline.repeatedBodyHash) {
      return true;
    }

    const statusMatchesWildcard =
      typeof baseline.wildcardStatusCode === "number" &&
      typeof response.statusCode === "number" &&
      baseline.wildcardStatusCode === response.statusCode &&
      response.statusCode >= 200 &&
      response.statusCode < 400;
    const titleMatches = Boolean(baseline.repeatedTitle && response.title === baseline.repeatedTitle);
    const lengthMatches = hasSimilarLength(response.contentLength, baseline.repeatedContentLength);

    // SPA and ecommerce apps often reuse titles across real pages, so title or
    // length alone is too weak. Treat it as soft-404 only when multiple baseline
    // signals agree on the same wildcard status behavior.
    if (statusMatchesWildcard && titleMatches && lengthMatches) {
      return true;
    }

    return false;
  }
}
