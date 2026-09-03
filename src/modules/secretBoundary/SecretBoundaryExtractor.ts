import type { TransientSecretCandidate } from "./SecretBoundaryTypes.js";

const assignmentPattern = /(?:^|[,{;\s])(?:["'`])?([A-Za-z_$][A-Za-z0-9_$.-]{1,159})(?:["'`])?\s*[:=]\s*["'`]([^"'`\r\n]{1,8192})["'`]/gm;
const bareAssignmentPattern = /\b([A-Z][A-Z0-9_]{2,159})\s*=\s*([^\s,;<>]{1,8192})/g;
const directTokenPatterns: Array<{ name: string; pattern: RegExp }> = [
  { name: "detected.private_key", pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{0,16000}?-----END [A-Z0-9 ]*PRIVATE KEY-----/g },
  { name: "detected.supabase_key", pattern: /\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{8,}\b/g },
  { name: "detected.payment_key", pattern: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9_-]{8,}\b/g },
  { name: "detected.vendor_token", pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b/g },
  { name: "detected.connection_url", pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis):\/\/[^\s"'<>]{8,}/gi }
];

export function extractTransientSecretCandidates(body: string | undefined, maximum: number): TransientSecretCandidate[] {
  if (!body || maximum <= 0) return [];
  const output: TransientSecretCandidate[] = [];
  const seen = new Set<string>();
  const add = (candidate: TransientSecretCandidate): boolean => {
    const value = candidate.value.trim();
    if (!value || value.length > 16384) return false;
    const key = `${candidate.name}\0${value}`;
    if (seen.has(key)) return false;
    seen.add(key); output.push({ ...candidate, value });
    return output.length >= maximum;
  };

  const parsed = parseJson(body);
  if (parsed !== undefined) {
    walkJson(parsed, "", 0, (name, value, valueType) => add({ name, value, valueType }), maximum, output);
    if (output.length >= maximum) return output;
  }
  for (const match of body.matchAll(assignmentPattern)) {
    if (add({ name: safeName(match[1]!), value: match[2]!, valueType: "string" })) return output;
  }
  for (const match of body.matchAll(bareAssignmentPattern)) {
    if (add({ name: safeName(match[1]!), value: match[2]!, valueType: "string" })) return output;
  }
  for (const rule of directTokenPatterns) {
    for (const match of body.matchAll(rule.pattern)) if (add({ name: rule.name, value: match[0], valueType: "string" })) return output;
  }
  return output;
}

export function extractSetCookieCandidates(headers: Readonly<Record<string, string | readonly string[]>>, maximum: number): TransientSecretCandidate[] {
  const raw = Object.entries(headers).find(([name]) => name.toLowerCase() === "set-cookie")?.[1];
  const values = Array.isArray(raw) ? raw : typeof raw === "string" ? splitSetCookie(raw) : [];
  return values.slice(0, maximum).flatMap((line) => {
    const [pair, ...attributes] = line.split(";");
    const equals = pair?.indexOf("=") ?? -1;
    if (!pair || equals <= 0) return [];
    const attributeSet = new Set(attributes.map((value: string) => value.trim().toLowerCase()));
    const sameSite = attributes.map((value: string) => /^samesite=(.+)$/i.exec(value.trim())?.[1]).find(Boolean);
    return [{ name: safeName(pair.slice(0, equals)), value: pair.slice(equals + 1), valueType: "string", cookie: { httpOnly: attributeSet.has("httponly"), secure: attributeSet.has("secure"), ...(sameSite ? { sameSite } : {}) } }];
  });
}

function parseJson(body: string): unknown | undefined { try { return JSON.parse(body); } catch { return undefined; } }
function walkJson(value: unknown, path: string, depth: number, add: (name: string, value: string, valueType: string) => boolean, maximum: number, output: TransientSecretCandidate[]): void {
  if (depth > 8 || output.length >= maximum) return;
  if (Array.isArray(value)) { for (const child of value.slice(0, 50)) walkJson(child, path ? `${path}[]` : "[]", depth + 1, add, maximum, output); return; }
  if (value && typeof value === "object") { for (const [key, child] of Object.entries(value as Record<string, unknown>).slice(0, 300)) walkJson(child, path ? `${path}.${safeName(key)}` : safeName(key), depth + 1, add, maximum, output); return; }
  if (!path || value === null || value === undefined) return;
  const valueType = typeof value;
  if (["string", "number", "boolean"].includes(valueType)) add(path, String(value), valueType);
}
function safeName(value: string): string { return value.replace(/[\r\n\0|]/g, "_").slice(0, 200); }
function splitSetCookie(value: string): string[] { return value.split(/,(?=\s*[!#$%&'*+.^_`|~0-9A-Za-z-]+=)/g); }
