export interface SecretPatternMatch {
  name: string;
  count: number;
}

const secretPatterns: Array<{ name: string; pattern: RegExp }> = [
  { name: "DATABASE_URL", pattern: /\bDATABASE_URL\s*=\s*[^\s]+/i },
  { name: "DB_PASSWORD", pattern: /\bDB_PASSWORD\s*=\s*[^\s]+/i },
  { name: "SECRET_KEY", pattern: /\bSECRET_KEY\s*=\s*[^\s]+/i },
  { name: "API_KEY", pattern: /\bAPI_KEY\s*=\s*[^\s]+/i },
  { name: "AWS_ACCESS_KEY_ID", pattern: /\bAWS_ACCESS_KEY_ID\s*=\s*AKIA[0-9A-Z]{12,}/i },
  { name: "AWS_SECRET_ACCESS_KEY", pattern: /\bAWS_SECRET_ACCESS_KEY\s*=\s*[A-Za-z0-9/+]{20,}/i },
  { name: "PRIVATE_KEY", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: "JWT_SECRET", pattern: /\bJWT_SECRET\s*=\s*[^\s]+/i },
  { name: "SUPABASE_SERVICE_ROLE_KEY", pattern: /\bSUPABASE_SERVICE_ROLE_KEY\s*=\s*[^\s]+/i },
  { name: "STRIPE_SECRET_KEY", pattern: /\bSTRIPE_SECRET_KEY\s*=\s*sk_(?:live|test)_[A-Za-z0-9]+/i }
];

export class SecretPatternDetector {
  public detect(bodyPreview: string | undefined): SecretPatternMatch[] {
    if (!bodyPreview) {
      return [];
    }

    return secretPatterns.flatMap((rule) => {
      const count = countMatches(bodyPreview, rule.pattern);
      if (count === 0) {
        return [];
      }

      return [
        {
          name: rule.name,
          count
        }
      ];
    });
  }
}

function countMatches(value: string, pattern: RegExp): number {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  return [...value.matchAll(new RegExp(pattern.source, flags))].length;
}
