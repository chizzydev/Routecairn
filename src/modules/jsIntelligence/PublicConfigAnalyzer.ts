import type { JsConfigValue } from "../../reports/ReportTypes.js";

const assignmentPattern =
  /\b(?<name>NEXT_PUBLIC_[A-Z0-9_]+|VITE_[A-Z0-9_]+|PUBLIC_[A-Z0-9_]+|apiBaseUrl|baseURL|graphqlEndpoint)\b\s*[:=]\s*["'`](?<value>[^"'`]{1,300})["'`]/gi;

export class PublicConfigAnalyzer {
  public analyze(jsSource: string): JsConfigValue[] {
    const values = new Map<string, JsConfigValue>();

    for (const match of jsSource.matchAll(assignmentPattern)) {
      const name = match.groups?.name;
      const value = match.groups?.value;

      if (!name || !value) {
        continue;
      }

      values.set(name, {
        name,
        valuePreview: preview(value),
        classification: isPublicFrontendName(name) ? "public-frontend-config" : "config-looking-value"
      });
    }

    return [...values.values()];
  }
}

function isPublicFrontendName(name: string): boolean {
  return /^(NEXT_PUBLIC_|VITE_|PUBLIC_)/i.test(name);
}

function preview(value: string): string {
  return value.length > 120 ? `${value.slice(0, 117)}...` : value;
}
