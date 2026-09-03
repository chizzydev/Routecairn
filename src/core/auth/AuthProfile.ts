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

const browserSelectorSchema = z.string().min(1).max(500).refine((value) => !/[\r\n\0]/.test(value), "Browser selector contains invalid characters.");
const browserUrlSchema = z.string().url().max(2048);
const browserLoginStepSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("navigate"), url: browserUrlSchema }).strict(),
  z.object({ action: z.literal("fill"), selector: browserSelectorSchema, valueRef: z.string().regex(/^[A-Za-z0-9._-]{1,80}$/) }).strict(),
  z.object({ action: z.literal("click"), selector: browserSelectorSchema }).strict(),
  z.object({ action: z.literal("waitForUrl"), urlPrefix: browserUrlSchema }).strict(),
  z.object({ action: z.literal("assertVisible"), selector: browserSelectorSchema }).strict()
]);
const browserJourneyStepSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("navigate"), url: browserUrlSchema }).strict(),
  z.object({ action: z.literal("clickLink"), selector: browserSelectorSchema }).strict(),
  z.object({ action: z.literal("assertVisible"), selector: browserSelectorSchema }).strict()
]);
const lifecycleSecretsSchema = z.record(z.string().regex(/^[A-Za-z0-9._-]{1,100}$/), z.string().min(1).max(8192)).superRefine((value, ctx) => {
  if (Object.keys(value).length > 64) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "lifecycleSecrets supports at most 64 named values." });
  if (Buffer.byteLength(JSON.stringify(value), "utf8") > 32 * 1024) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "lifecycleSecrets exceeds the 32 KiB secret budget." });
});

export const browserBootstrapSchema = z.object({
  schemaVersion: z.literal(1).default(1),
  loginSecrets: z.record(z.string().min(1).max(8192)).default({}),
  login: z.object({
    startUrl: browserUrlSchema,
    allowedWritePaths: z.array(z.string().startsWith("/").max(500)).min(1).max(12),
    successUrlPrefix: browserUrlSchema,
    steps: z.array(browserLoginStepSchema).min(1).max(24)
  }).strict().optional(),
  journeys: z.array(z.object({
    id: z.string().regex(/^[A-Za-z0-9._-]{1,80}$/),
    label: z.string().min(1).max(160),
    steps: z.array(browserJourneyStepSchema).min(1).max(30)
  }).strict()).max(12).default([]),
  identitySelectors: z.object({
    principal: browserSelectorSchema.optional(),
    tenant: browserSelectorSchema.optional(),
    role: browserSelectorSchema.optional()
  }).strict().optional(),
  proofCases: z.array(z.object({
    caseId: z.string().regex(/^[A-Za-z0-9._-]{1,120}$/),
    protectedAction: z.object({ url: browserUrlSchema, selector: browserSelectorSchema, readySelector: browserSelectorSchema.optional(), expected: z.enum(["visible", "hidden"]) }).strict(),
    rollback: z.object({ url: browserUrlSchema, selector: browserSelectorSchema, readySelector: browserSelectorSchema.optional(), expected: z.enum(["visible", "hidden"]) }).strict()
  }).strict()).max(10).default([])
}).strict().superRefine((value, ctx) => {
  if (!value.login && Object.keys(value.loginSecrets).length > 0) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["loginSecrets"], message: "Browser login secrets require a login workflow." });
  }
  const referenced = new Set(value.login?.steps.filter((step) => step.action === "fill").map((step) => step.valueRef) ?? []);
  for (const name of referenced) {
    if (!Object.prototype.hasOwnProperty.call(value.loginSecrets, name)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["loginSecrets", name], message: `Missing browser login secret reference ${name}.` });
    }
  }
  for (const name of Object.keys(value.loginSecrets)) {
    if (!referenced.has(name)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["loginSecrets", name], message: `Unused browser login secret ${name} was rejected.` });
    }
  }
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
  browserBootstrap: browserBootstrapSchema.optional(),
  lifecycleSecrets: lifecycleSecretsSchema.default({}),
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

/** Worker-only secret namespace used by authentication lifecycle contracts. */
export function authenticationLifecycleSecrets(profile: AuthProfile): Record<string, string> {
  const loginSecrets = profile.browserBootstrap?.loginSecrets ?? {};
  for (const name of Object.keys(loginSecrets)) {
    if (Object.prototype.hasOwnProperty.call(profile.lifecycleSecrets, name) && profile.lifecycleSecrets[name] !== loginSecrets[name]) {
      throw new AppError(`Authentication secret reference ${name} is ambiguous across browserBootstrap.loginSecrets and lifecycleSecrets.`, "AUTH_LIFECYCLE_SECRET_AMBIGUOUS");
    }
  }
  return { ...loginSecrets, ...profile.lifecycleSecrets };
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
  return [
    ...Object.values(profile.headers),
    ...profile.cookies.map((cookie) => cookie.value),
    ...Object.values(profile.browserBootstrap?.loginSecrets ?? {}),
    ...Object.values(profile.lifecycleSecrets ?? {})
  ].filter((value) => value.length >= 4);
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
