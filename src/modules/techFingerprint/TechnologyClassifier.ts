import type { HttpResponse } from "../../core/http/HttpTypes.js";
import type { DetectedTechnology } from "../../reports/ReportTypes.js";
import { fingerprintRules } from "./fingerprints.js";

export class TechnologyClassifier {
  public classify(responses: HttpResponse[]): DetectedTechnology[] {
    const input = {
      headersText: responses.map((response) => headersToText(response.headers)).join("\n"),
      cookiesText: responses.map((response) => headerValues(response.headers, "set-cookie")).join("\n"),
      bodyText: responses.map((response) => response.bodyPreview ?? "").join("\n"),
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

function headersToText(headers: Record<string, string | string[]>): string {
  return Object.entries(headers)
    .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : value}`)
    .join("\n");
}

function headerValues(headers: Record<string, string | string[]>, name: string): string {
  const value = headers[name];

  if (Array.isArray(value)) {
    return value.join("\n");
  }

  return value ?? "";
}
