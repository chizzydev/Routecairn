import { createHash } from "node:crypto";

const sensitivePattern = /(?:authorization|cookie|token|secret|password|passwd|api[_-]?key|session|jwt|signature|signed|credential|set-cookie)/i;

export function redactDashboardValue(value: unknown): unknown {
  if (typeof value === "string") {
    return redactString(value);
  }
  if (Array.isArray(value)) {
    return value.map(redactDashboardValue);
  }
  if (value && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      result[key] = sensitivePattern.test(key) ? "<redacted>" : redactDashboardValue(child);
    }
    return result;
  }
  return value;
}

export function redactString(value: string): string {
  return value
    .replace(/(authorization\s*[:=]\s*)(bearer\s+)?[^\s"']+/gi, "$1<redacted>")
    .replace(/(cookie\s*[:=]\s*)[^"'\n\r]+/gi, "$1<redacted>")
    .replace(/([?&][^=]*(?:token|secret|session|cookie|auth|password|pass|key|jwt|sig|signature|credential)[^=]*=)[^&\s]+/gi, "$1<redacted>");
}

export function safeJson(value: unknown): string {
  return JSON.stringify(redactDashboardValue(value));
}

export function safeHash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => {
    switch (character) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case "\"":
        return "&quot;";
      case "'":
        return "&#39;";
      default:
        return character;
    }
  });
}
