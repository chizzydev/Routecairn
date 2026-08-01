import { readFile } from "node:fs/promises";
import { z } from "zod";
import { AppError } from "../errors/AppError.js";

const forbiddenAuthHeaderNames = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "upgrade",
  "expect",
  "te",
  "trailer"
]);

const authCookieSchema = z.object({
  name: z.string().min(1),
  value: z.string().min(1),
  domain: z.string().optional(),
  path: z.string().optional()
});

export const authProfileSchema = z.object({
  label: z.string().min(1).default("authenticated"),
  principalId: z.string().min(1).optional(),
  tenantId: z.string().min(1).optional(),
  role: z.string().min(1).optional(),
  safeAlias: z.string().min(1).optional(),
  headers: z.record(z.string()).default({}),
  cookies: z.array(authCookieSchema).default([]),
  notes: z.array(z.string()).default([])
});

export type AuthProfile = z.infer<typeof authProfileSchema>;

export interface AuthProfileSummary {
  enabled: boolean;
  label?: string;
  principalIdDeclared?: boolean;
  tenantIdDeclared?: boolean;
  role?: string;
  safeAlias?: string;
  headerNames: string[];
  cookieNames: string[];
  redactionApplied: boolean;
  notes: string[];
}

export async function loadAuthProfile(filePath: string): Promise<AuthProfile> {
  const raw = (await readFile(filePath, "utf8")).replace(/^\uFEFF/, "");
  const parsed = authProfileSchema.safeParse(JSON.parse(raw));

  if (!parsed.success) {
    throw new AppError(parsed.error.message, "AUTH_PROFILE_INVALID");
  }

  validateAuthHeaders(parsed.data.headers);
  for (const cookie of parsed.data.cookies) {
    validateHeaderValue(cookie.value, `cookie ${cookie.name}`);
  }

  return parsed.data;
}

export function authHeadersForProfile(profile: AuthProfile): Record<string, string> {
  validateAuthHeaders(profile.headers);
  const headers: Record<string, string> = { ...profile.headers };
  const cookieHeaderName = Object.keys(headers).find((name) => name.toLowerCase() === "cookie") ?? "Cookie";
  const profileCookieHeader = profile.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; ");

  if (profileCookieHeader) {
    headers[cookieHeaderName] = headers[cookieHeaderName] ? `${headers[cookieHeaderName]}; ${profileCookieHeader}` : profileCookieHeader;
  }

  return headers;
}

export function summarizeAuthProfile(profile: AuthProfile | undefined): AuthProfileSummary {
  if (!profile) {
    return {
      enabled: false,
      headerNames: [],
      cookieNames: [],
      redactionApplied: true,
      notes: ["No auth profile supplied. Authenticated comparison was skipped."]
    };
  }

  return {
    enabled: true,
    label: profile.safeAlias ?? profile.label,
    ...(profile.principalId ? { principalIdDeclared: true } : {}),
    ...(profile.tenantId ? { tenantIdDeclared: true } : {}),
    ...(profile.role ? { role: profile.role } : {}),
    ...(profile.safeAlias ? { safeAlias: profile.safeAlias } : {}),
    headerNames: Object.keys(profile.headers).sort(),
    cookieNames: profile.cookies.map((cookie) => cookie.name).sort(),
    redactionApplied: true,
    notes: [
      ...profile.notes,
      "Auth material was used only for requests and redacted from reports.",
      "This foundation is ready for future account A vs account B comparison using separate profiles."
    ]
  };
}

export function redactedAuthHeaders(profile: AuthProfile): Record<string, string> {
  const headers = authHeadersForProfile(profile);
  return Object.fromEntries(Object.entries(headers).map(([name]) => [name, "<redacted>"]));
}

export function redactAuthMaterial(value: string, profile: AuthProfile | undefined): string {
  if (!profile) {
    return value;
  }

  let redacted = value;
  for (const secret of authSecretValues(profile)) {
    if (secret) {
      redacted = redacted.split(secret).join("<redacted>");
    }
  }

  return redacted;
}

export function redactedCurlCommand(url: string, profile?: AuthProfile): string {
  const headerParts = profile
    ? Object.keys(authHeadersForProfile(profile))
        .sort()
        .map((name) => `-H "${escapeShell(name)}: <redacted>"`)
    : [];

  return ["curl -i", ...headerParts, `"${escapeShell(url)}"`].join(" ");
}

function authSecretValues(profile: AuthProfile): string[] {
  return [...Object.values(profile.headers), ...profile.cookies.map((cookie) => cookie.value)].filter((value) => value.length >= 4);
}

function validateAuthHeaders(headers: Record<string, string>): void {
  for (const [name, value] of Object.entries(headers)) {
    const normalizedName = name.trim().toLowerCase();

    if (!normalizedName || forbiddenAuthHeaderNames.has(normalizedName)) {
      throw new AppError(`Auth profile header "${name}" is not allowed.`, "AUTH_HEADER_FORBIDDEN");
    }

    if (/[^a-z0-9!#$%&'*+.^_`|~-]/i.test(name)) {
      throw new AppError(`Auth profile header "${name}" is invalid.`, "AUTH_HEADER_INVALID");
    }

    validateHeaderValue(value, `header ${name}`);
  }
}

function validateHeaderValue(value: string, label: string): void {
  if (/[\r\n]/.test(value)) {
    throw new AppError(`Auth profile ${label} contains a newline and was rejected.`, "AUTH_HEADER_INVALID");
  }
}

function escapeShell(value: string): string {
  return value.replace(/"/g, "\\\"");
}
