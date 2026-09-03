import type { JsConfigValue } from "../../reports/ReportTypes.js";
import { classifyTransientSecret } from "../secretBoundary/SecretBoundaryClassifier.js";

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

      const secret = classifyTransientSecret({ name, value, surface: "JAVASCRIPT_BUNDLE", publicExposure: true });
      const sensitive = !["NON_SENSITIVE", "PUBLIC_CLIENT_CONFIG", "PUBLISHABLE_CLIENT_KEY", "SUPABASE_ANON_KEY", "SUPABASE_PUBLISHABLE_KEY"].includes(secret.materialClass);
      const clientCredential = ["PUBLISHABLE_CLIENT_KEY", "SUPABASE_ANON_KEY", "SUPABASE_PUBLISHABLE_KEY"].includes(secret.materialClass);
      values.set(name, {
        name,
        valuePreview: sensitive ? "<redacted-sensitive-config>" : clientCredential ? "<redacted-client-material>" : preview(value),
        classification: sensitive ? "redacted-sensitive-config" : isPublicFrontendName(name) ? "public-frontend-config" : "config-looking-value",
        ...(!["NON_SENSITIVE", "PUBLIC_CLIENT_CONFIG"].includes(secret.materialClass) ? { secretMaterialClass: secret.materialClass, secretImpact: secret.impact } : {})
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
