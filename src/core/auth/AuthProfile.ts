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

export const identityVerificationModeSchema = z.enum(["disabled", "optional", "required"]);
export const identityVerificationMethodSchema = z.enum(["GET", "HEAD"]);
const identityFieldPathPattern = /^[A-Za-z_$][A-Za-z0-9_$]*(?:\[(?:0|[1-9][0-9]{0,2})\]|\.[A-Za-z_$][A-Za-z0-9_$]*){0,8}$/;
const forbiddenIdentityPathSegments = new Set(["__proto__", "prototype", "constructor"]);

const identityVerificationSchema = z
  .object({
    mode: identityVerificationModeSchema.default("disabled"),
    endpoint: z.string().min(1).max(2048).optional(),
    method: identityVerificationMethodSchema.default("GET"),
    principalIdField: z.string().min(1).max(160).optional(),
    tenantIdField: z.string().min(1).max(160).optional(),
    roleField: z.string().min(1).max(160).optional(),
    accountStateField: z.string().min(1).max(160).optional(),
    safeAliasField: z.string().min(1).max(160).optional(),
    expectedContentType: z.string().min(1).max(120).default("application/json"),
    successStatusCodes: z.array(z.number().int().min(100).max(599)).max(10).default([200]),
    maxResponseBytes: z.number().int().positive().max(65536).default(8192),
    anonymousMarkers: z.array(z.object({ field: z.string().min(1).max(160), value: z.union([z.string(), z.number(), z.boolean(), z.null()]) }).strict()).max(10).default([])
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.mode !== "disabled") {
      if (!value.endpoint) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["endpoint"], message: "identityVerification.endpoint is required when verification is enabled." });
      }
      if (!value.principalIdField) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["principalIdField"], message: "identityVerification.principalIdField is required when verification is enabled." });
      }
    }
    for (const [fieldName, path] of Object.entries({
      principalIdField: value.principalIdField,
      tenantIdField: value.tenantIdField,
      roleField: value.roleField,
      accountStateField: value.accountStateField,
      safeAliasField: value.safeAliasField
    })) {
      if (path && !identityFieldPathPattern.test(path)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: [fieldName], message: "identityVerification field mapping uses an unsupported path." });
      }
      if (path && hasForbiddenIdentityPathSegment(path)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: [fieldName], message: "identityVerification field mapping uses a forbidden path segment." });
      }
    }
    for (const [index, marker] of value.anonymousMarkers.entries()) {
      if (!identityFieldPathPattern.test(marker.field)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["anonymousMarkers", index, "field"], message: "anonymous marker field uses an unsupported path." });
      }
      if (hasForbiddenIdentityPathSegment(marker.field)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["anonymousMarkers", index, "field"], message: "anonymous marker field uses a forbidden path segment." });
      }
    }
  });

export const authProfileSchema = z.object({
  label: z.string().min(1).default("authenticated"),
  principalId: z.string().min(1).optional(),
  tenantId: z.string().min(1).optional(),
  role: z.string().min(1).optional(),
  accountState: z.string().min(1).optional(),
  safeAlias: z.string().min(1).optional(),
  headers: z.record(z.string()).default({}),
  cookies: z.array(authCookieSchema).default([]),
  identityVerification: identityVerificationSchema.default({ mode: "disabled" }),
  notes: z.array(z.string()).default([])
});

export type AuthProfile = z.infer<typeof authProfileSchema>;

export interface AuthProfileSummary {
  enabled: boolean;
  label?: string;
  principalIdDeclared?: boolean;
  tenantIdDeclared?: boolean;
  role?: string;
  accountStateDeclared?: boolean;
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
    ...(profile.accountState ? { accountStateDeclared: true } : {}),
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

function hasForbiddenIdentityPathSegment(path: string): boolean {
  return path.split(".").some((part) => forbiddenIdentityPathSegments.has(part.replace(/\[\d+\]$/, "")));
}
