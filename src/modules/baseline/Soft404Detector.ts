import type { HttpResponse } from "../../core/http/HttpTypes.js";
import type { BaselineProbe, BaselineReport } from "../../reports/ReportTypes.js";

export class Soft404Detector {
  public analyze(probes: HttpResponse[]): BaselineReport {
    const baselineProbes = probes.map(toProbe);
    const notes: string[] = [];
    const wildcardStatusCode = repeatedValue(probes.map((probe) => probe.statusCode));
    const repeatedTitle = repeatedValue(probes.map((probe) => probe.title));
    const repeatedBodyHash = repeatedValue(probes.map((probe) => probe.bodyHash));
    const repeatedContentLength = repeatedNumber(probes.map((probe) => probe.contentLength));

    if (wildcardStatusCode && wildcardStatusCode >= 200 && wildcardStatusCode < 300) {
      notes.push(`Non-existing paths repeatedly returned HTTP ${wildcardStatusCode}.`);
    }

    if (repeatedBodyHash) {
      notes.push("Non-existing paths shared the same body hash.");
    }

    if (repeatedTitle) {
      notes.push(`Non-existing paths shared the title "${repeatedTitle}".`);
    }

    if (notes.length === 0) {
      notes.push("No strong soft-404 pattern detected.");
    }

    return {
      probes: baselineProbes,
      notes,
      ...(wildcardStatusCode ? { wildcardStatusCode } : {}),
      ...(repeatedTitle ? { repeatedTitle } : {}),
      ...(repeatedBodyHash ? { repeatedBodyHash } : {}),
      ...(typeof repeatedContentLength === "number" ? { repeatedContentLength } : {})
    };
  }
}

function toProbe(response: HttpResponse): BaselineProbe {
  return {
    url: response.requestedUrl,
    ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(response.title ? { title: response.title } : {}),
    ...(typeof response.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(response.bodyHash ? { bodyHash: response.bodyHash } : {}),
    ...(response.error ? { error: response.error.message } : {})
  };
}

function repeatedValue<T extends string | number>(values: Array<T | undefined>): T | undefined {
  const counts = new Map<T, number>();

  for (const value of values) {
    if (typeof value === "undefined") {
      continue;
    }

    counts.set(value, (counts.get(value) ?? 0) + 1);
  }

  for (const [value, count] of counts) {
    if (count >= 2) {
      return value;
    }
  }

  return undefined;
}

function repeatedNumber(values: Array<number | undefined>): number | undefined {
  const numbers = values.filter((value): value is number => typeof value === "number");

  if (numbers.length < 2) {
    return undefined;
  }

  const first = numbers[0];
  if (typeof first !== "number") {
    return undefined;
  }

  return numbers.every((value) => Math.abs(value - first) <= Math.max(50, first * 0.08)) ? first : undefined;
}
