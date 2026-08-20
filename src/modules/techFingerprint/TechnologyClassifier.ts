import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { DetectedTechnology } from "../../reports/ReportTypes.js";
import { fingerprintRules } from "./fingerprints.js";

export class TechnologyClassifier {
  public classify(responses: HttpResponse[]): DetectedTechnology[] {
    const input = {
      headersText: responses.map((response) => headersToText(headersForAnalysis(response))).join("\n"),
      cookiesText: responses.map((response) => headerValues(headersForAnalysis(response), "set-cookie")).join("\n"),
      bodyText: responses.map((response) => bodyPreviewForAnalysis(response) ?? "").join("\n"),
      urlText: responses.flatMap((response) => [response.requestedUrl, response.finalUrl]).join("\n")
    };
    const technologies = new Map<string, DetectedTechnology>();

    for (const rule of fingerprintRules) {
      const signals = rule.match(input);

      if (signals.length === 0) {
        continue;
      }

      technologies.set(rule.name, {
        name: rule.name,
        category: rule.category,
        confidence: rule.confidence,
        signals: [...new Set(signals)]
      });
    }

    return [...technologies.values()];
  }
}

function headersToText(headers: Readonly<Record<string, string | readonly string[]>>): string {
  return Object.entries(headers)
    .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : value}`)
    .join("\n");
}

function headerValues(headers: Readonly<Record<string, string | readonly string[]>>, name: string): string {
  const value = headers[name];

  return typeof value === "string" ? value : value?.join("\n") ?? "";
}
