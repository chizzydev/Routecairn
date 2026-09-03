import { classifyTransientSecret } from "../secretBoundary/SecretBoundaryClassifier.js";

export interface SecretPatternMatch {
  name: string;
  count: number;
}

/** Module-private callers must discard `value` immediately after producing redacted evidence. */
export interface TransientSecretPatternMatch extends SecretPatternMatch {
  value: string;
}

const secretPatterns: Array<{ name: string; pattern: RegExp; valueGroup: number }> = [
  { name: "DATABASE_URL", pattern: /\bDATABASE_URL["']?\s*[:=]\s*["']?([^\s"'`,;]+)/i, valueGroup: 1 },
  { name: "DB_PASSWORD", pattern: /\bDB_PASSWORD["']?\s*[:=]\s*["']?([^\s"'`,;]+)/i, valueGroup: 1 },
  { name: "SECRET_KEY", pattern: /\bSECRET_KEY["']?\s*[:=]\s*["']?([^\s"'`,;]+)/i, valueGroup: 1 },
  { name: "API_KEY", pattern: /\bAPI_KEY["']?\s*[:=]\s*["']?([^\s"'`,;]+)/i, valueGroup: 1 },
  { name: "AWS_ACCESS_KEY_ID", pattern: /\bAWS_ACCESS_KEY_ID["']?\s*[:=]\s*["']?(AKIA[0-9A-Z]{12,})/i, valueGroup: 1 },
  { name: "AWS_SECRET_ACCESS_KEY", pattern: /\bAWS_SECRET_ACCESS_KEY["']?\s*[:=]\s*["']?([A-Za-z0-9/+]{20,})/i, valueGroup: 1 },
  { name: "PRIVATE_KEY", pattern: /(-----BEGIN [A-Z ]*PRIVATE KEY-----)/, valueGroup: 1 },
  { name: "JWT_SECRET", pattern: /\bJWT_SECRET["']?\s*[:=]\s*["']?([^\s"'`,;]+)/i, valueGroup: 1 },
  { name: "SUPABASE_SERVICE_ROLE_KEY", pattern: /\bSUPABASE_SERVICE_ROLE_KEY["']?\s*[:=]\s*["']?([^\s"'`,;]+)/i, valueGroup: 1 },
  { name: "STRIPE_SECRET_KEY", pattern: /\bSTRIPE_SECRET_KEY["']?\s*[:=]\s*["']?(sk_(?:live|test)_[A-Za-z0-9]+)/i, valueGroup: 1 }
];

export class SecretPatternDetector {
  public detect(bodyPreview: string | undefined): SecretPatternMatch[] {
    const counts = new Map<string, number>();
    for (const match of this.detectForTransientAnalysis(bodyPreview, 256)) counts.set(match.name, (counts.get(match.name) ?? 0) + 1);
    return [...counts].map(([name, count]) => ({ name, count }));
  }

  public detectForTransientAnalysis(bodyPreview: string | undefined, maximumMatches = 32): TransientSecretPatternMatch[] {
    if (!bodyPreview || maximumMatches <= 0) return [];
    const matches: TransientSecretPatternMatch[] = [];
    for (const rule of secretPatterns) {
      const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`;
      for (const match of bodyPreview.matchAll(new RegExp(rule.pattern.source, flags))) {
        const value = match[rule.valueGroup];
        if (!value || isPlaceholder(value)) continue;
        const classification = classifyTransientSecret({ name: rule.name, value, surface: "HTML", publicExposure: true });
        if (["NON_SENSITIVE", "PUBLIC_CLIENT_CONFIG", "PUBLISHABLE_CLIENT_KEY", "SUPABASE_ANON_KEY", "SUPABASE_PUBLISHABLE_KEY"].includes(classification.materialClass)) continue;
        matches.push({ name: rule.name, count: 1, value });
        if (matches.length >= maximumMatches) return matches;
      }
    }
    return matches;
  }
}

function isPlaceholder(value: string): boolean {
  return /^(?:example|sample|placeholder|changeme|replace[_-]?me|your[_-].*|xxx+|test)$/i.test(value) || value.length < 8;
}
