import { createHash } from "node:crypto";
import { authHeadersForProfile, type AuthProfile } from "./AuthProfile.js";
import type { ScanContext } from "../engine/ScanContext.js";
import { AppError } from "../errors/AppError.js";
import type { HttpResponse } from "../http/HttpTypes.js";
import type { IdentityVerificationCategory, IdentityVerificationReport, IdentityVerificationResult } from "../../reports/ReportTypes.js";

type IdentityProfileSlot = "primary" | "accountA" | "accountB";

interface IdentityVerificationInput {
  slot: IdentityProfileSlot;
  profile: AuthProfile;
}

interface ExtractedIdentity {
  principalId?: string;
  tenantId?: string;
  role?: string;
  safeAlias?: string;
}

const identityHashScope = "routecairn-identity-v1";
const forbiddenPathSegments = new Set(["__proto__", "prototype", "constructor"]);

export async function verifyScanIdentities(context: ScanContext): Promise<IdentityVerificationReport | undefined> {
  const inputs: IdentityVerificationInput[] = [
    ...(context.options.authProfile ? [{ slot: "primary" as const, profile: context.options.authProfile }] : []),
    ...(context.options.authProfileSet
      ? [
          { slot: "accountA" as const, profile: context.options.authProfileSet.accountA },
          { slot: "accountB" as const, profile: context.options.authProfileSet.accountB }
        ]
      : [])
  ];

  if (inputs.length === 0 || inputs.every((input) => identityMode(input.profile) === "disabled")) {
    return undefined;
  }

  const entries = await Promise.all(inputs.map((input) => verifyIdentity(context, input)));
  const report: IdentityVerificationReport = {
    enabled: true,
    notes: [
      "Identity verification used only configured identity endpoints and explicit field mappings.",
      "Raw identity values and authentication material are redacted from reports."
    ]
  };

  for (const entry of entries) {
    if (entry.slot === "primary") report.primary = entry.result;
    if (entry.slot === "accountA") report.accountA = entry.result;
    if (entry.slot === "accountB") report.accountB = entry.result;
  }

  if (report.accountA && report.accountB && report.accountA.verified && report.accountB.verified) {
    report.distinctVerifiedPrincipals = report.accountA.principalHash !== report.accountB.principalHash;
  }

  return report;
}

export function objectPairIdentityBlockReason(report: IdentityVerificationReport | undefined): string | undefined {
  if (!report?.accountA?.required && !report?.accountB?.required) return undefined;
  if (!report.accountA?.verified) return `Account A required verified principal identity but verification result was ${report.accountA?.category ?? "missing"}.`;
  if (!report.accountB?.verified) return `Account B required verified principal identity but verification result was ${report.accountB?.category ?? "missing"}.`;
  if (report.accountA.principalHash === report.accountB.principalHash) return "Account A and Account B resolved to the same verified principal.";
  return undefined;
}

async function verifyIdentity(context: ScanContext, input: IdentityVerificationInput): Promise<{ slot: IdentityProfileSlot; result: IdentityVerificationResult }> {
  const config = input.profile.identityVerification;
  if (!config || config.mode === "disabled") {
    return { slot: input.slot, result: declaredOnly(input.profile) };
  }

  const endpoint = config.endpoint;
  if (!endpoint || !config.principalIdField) {
    return { slot: input.slot, result: failure(input.profile, "IDENTITY_FIELD_MISSING", "Identity verification endpoint or principal field mapping is missing.") };
  }

  const url = resolveIdentityEndpoint(context.options.target, endpoint);
  const response = await context.createHttpClient().send({
    url,
    method: config.method,
    headers: authHeadersForProfile(input.profile)
  });

  return { slot: input.slot, result: classifyIdentityResponse(input.profile, response) };
}

function classifyIdentityResponse(profile: AuthProfile, response: HttpResponse): IdentityVerificationResult {
  const config = profile.identityVerification;
  const base = resultBase(profile, response);
  if (!config || config.mode === "disabled") return declaredOnly(profile);

  if (response.error?.name === "OutOfScopeRequest" || response.error?.name === "OutOfScopeRedirect") {
    return { ...base, category: "OUT_OF_SCOPE", notes: ["Identity endpoint was blocked by scope policy."] };
  }
  if (response.error?.name === "RequestBudgetExceeded") {
    return { ...base, category: "BUDGET_EXHAUSTED", notes: ["Identity endpoint could not run because the request budget was exhausted."] };
  }
  if (response.error) {
    return { ...base, category: "EXECUTION_ERROR", notes: [response.error.message] };
  }
  if (response.statusCode === 429) return { ...base, category: "RATE_LIMITED", notes: ["Identity endpoint was rate limited."] };
  if (response.statusCode === 401) return { ...base, category: "AUTHENTICATION_FAILED", notes: ["Identity endpoint returned 401."] };
  if (response.statusCode === 403) return { ...base, category: "ACCESS_DENIED", notes: ["Identity endpoint returned 403."] };
  if (response.redirectLocation && /login|signin|auth/i.test(response.redirectLocation)) return { ...base, category: "LOGIN_PAGE_RESPONSE", notes: ["Identity endpoint redirected toward login."] };
  if (!config.successStatusCodes.includes(response.statusCode ?? 0)) return { ...base, category: "INCONCLUSIVE", notes: ["Identity endpoint returned an unexpected status code."] };
  if ((response.contentLength ?? 0) > config.maxResponseBytes) return { ...base, category: "RESPONSE_TOO_LARGE", notes: ["Identity response exceeded configured size."] };
  if (/login|sign in|required to log in/i.test(response.bodyPreview ?? "")) return { ...base, category: "LOGIN_PAGE_RESPONSE", notes: ["Identity endpoint returned a login-like response."] };
  if (!matchesContentType(response.contentType, config.expectedContentType)) return { ...base, category: "UNSUPPORTED_CONTENT_TYPE", notes: ["Identity endpoint returned an unsupported content type."] };

  const parsed = parseJsonObject(response.bodyPreview ?? "");
  if (!parsed) {
    return { ...base, category: "UNSUPPORTED_CONTENT_TYPE", notes: ["Identity endpoint did not return a supported JSON object."] };
  }
  if (isAnonymousResponse(parsed, config.anonymousMarkers)) return { ...base, category: "ANONYMOUS_RESPONSE", notes: ["Identity endpoint matched configured anonymous markers."] };

  const extracted = extractIdentity(config, parsed);
  if (!extracted.principalId) return { ...base, category: "IDENTITY_FIELD_MISSING", notes: ["Configured principal identity field was missing or invalid."] };

  const principalMatched = extracted.principalId === profile.principalId;
  if (!principalMatched) return withIdentity(base, extracted, "PRINCIPAL_MISMATCH", false, "Verified principal did not match declared principalId.");
  if (config.tenantIdField && profile.tenantId && !extracted.tenantId) return withIdentity(base, extracted, "REQUIRED_METADATA_MISSING", true, "Configured tenant metadata was missing or invalid.");
  if (config.roleField && profile.role && !extracted.role) return withIdentity(base, extracted, "REQUIRED_METADATA_MISSING", true, "Configured role metadata was missing or invalid.");
  if (config.tenantIdField && profile.tenantId && extracted.tenantId !== profile.tenantId) return withIdentity(base, extracted, "TENANT_MISMATCH", true, "Verified tenant did not match declared tenantId.");
  if (config.roleField && profile.role && extracted.role !== profile.role) return withIdentity(base, extracted, "ROLE_MISMATCH", true, "Verified role did not match declared role.");

  const partial = (config.tenantIdField && !extracted.tenantId) || (config.roleField && !extracted.role);
  return withIdentity(base, extracted, partial ? "VERIFIED_WITH_PARTIAL_METADATA" : "VERIFIED", true, "Configured identity endpoint matched declared profile metadata.");
}

function extractIdentity(config: NonNullable<AuthProfile["identityVerification"]>, source: Record<string, unknown>): ExtractedIdentity {
  const principalId = scalarAtPath(source, config.principalIdField);
  const tenantId = config.tenantIdField ? scalarAtPath(source, config.tenantIdField) : undefined;
  const role = config.roleField ? scalarAtPath(source, config.roleField) : undefined;
  const safeAlias = config.safeAliasField ? scalarAtPath(source, config.safeAliasField) : undefined;
  return {
    ...(principalId ? { principalId } : {}),
    ...(tenantId ? { tenantId } : {}),
    ...(role ? { role } : {}),
    ...(safeAlias ? { safeAlias } : {})
  };
}

function withIdentity(
  base: IdentityVerificationResult,
  identity: ExtractedIdentity,
  category: IdentityVerificationCategory,
  principalMatched: boolean,
  note: string
): IdentityVerificationResult {
  return {
    ...base,
    category,
    verified: category === "VERIFIED" || category === "VERIFIED_WITH_PARTIAL_METADATA",
    principalMatched,
    ...(identity.principalId ? { principalHash: hashValue(identity.principalId) } : {}),
    ...(identity.tenantId ? { tenantHash: hashValue(identity.tenantId), tenantMatched: true } : {}),
    ...(identity.role ? { roleHash: hashValue(identity.role), roleMatched: true } : {}),
    ...(identity.safeAlias ? { safeAliasHash: hashValue(identity.safeAlias) } : {}),
    notes: [note]
  };
}

function declaredOnly(profile: AuthProfile): IdentityVerificationResult {
  return {
    profileLabel: profile.safeAlias ?? profile.label,
    mode: "disabled",
    category: "DECLARED_ONLY",
    verified: false,
    required: false,
    principalMatched: false,
    ...(profile.principalId ? { principalHash: hashValue(profile.principalId) } : {}),
    ...(profile.tenantId ? { tenantHash: hashValue(profile.tenantId) } : {}),
    ...(profile.role ? { roleHash: hashValue(profile.role) } : {}),
    timestamp: new Date().toISOString(),
    notes: ["Principal identity was supplied by the operator and was not independently verified through the target application."]
  };
}

function failure(profile: AuthProfile, category: IdentityVerificationCategory, note: string): IdentityVerificationResult {
  return { ...resultBase(profile), category, notes: [note] };
}

function resultBase(profile: AuthProfile, response?: HttpResponse): IdentityVerificationResult {
  const config = profile.identityVerification;
  return {
    profileLabel: profile.safeAlias ?? profile.label,
    mode: config?.mode ?? "disabled",
    ...(config?.endpoint ? { endpoint: redactIdentityEndpoint(config.endpoint) } : {}),
    ...(config?.method ? { method: config.method } : {}),
    category: "INCONCLUSIVE",
    verified: false,
    required: config?.mode === "required",
    principalMatched: false,
    ...(typeof response?.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(response?.contentType ? { contentType: response.contentType } : {}),
    ...(typeof response?.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(response?.bodyHash ? { bodyHash: response.bodyHash } : {}),
    timestamp: new Date().toISOString(),
    notes: []
  };
}

function identityMode(profile: AuthProfile): "disabled" | "optional" | "required" {
  return profile.identityVerification?.mode ?? "disabled";
}

function resolveIdentityEndpoint(target: string, endpoint: string): string {
  const url = new URL(endpoint, target);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new AppError("Identity verification endpoint must use http or https.", "IDENTITY_ENDPOINT_PROTOCOL_INVALID");
  }
  return url.toString();
}

function parseJsonObject(body: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(body) as unknown;
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

function scalarAtPath(source: Record<string, unknown>, path: string | undefined): string | undefined {
  if (!path) return undefined;
  let value: unknown = source;
  for (const part of path.split(".")) {
    if (isForbiddenPathPart(part)) return undefined;
    const arrayMatch = part.match(/^([A-Za-z_$][A-Za-z0-9_$]*)\[(\d+)\]$/);
    if (arrayMatch) {
      if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
      const key = arrayMatch[1];
      if (!key) return undefined;
      if (forbiddenPathSegments.has(key)) return undefined;
      const next = (value as Record<string, unknown>)[key];
      if (!Array.isArray(next)) return undefined;
      value = next[Number(arrayMatch[2])];
      continue;
    }
    if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
    value = (value as Record<string, unknown>)[part];
  }
  if (typeof value === "string" || typeof value === "number") {
    const normalized = String(value).trim();
    return normalized && normalized.length <= 256 && !/[\r\n\0]/.test(normalized) ? normalized : undefined;
  }
  return undefined;
}

function isAnonymousResponse(source: Record<string, unknown>, markers: NonNullable<AuthProfile["identityVerification"]>["anonymousMarkers"]): boolean {
  return markers.some((marker) => scalarOrNullAtPath(source, marker.field) === marker.value);
}

function scalarOrNullAtPath(source: Record<string, unknown>, path: string): string | number | boolean | null | undefined {
  const value = scalarAtPath(source, path);
  if (value !== undefined) return value;
  let current: unknown = source;
  for (const part of path.split(".")) {
    if (isForbiddenPathPart(part)) return undefined;
    if (typeof current !== "object" || current === null || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current === null || typeof current === "boolean" ? current : undefined;
}

function matchesContentType(actual: string | undefined, expected: string): boolean {
  return Boolean(actual?.toLowerCase().includes(expected.toLowerCase()));
}

function redactIdentityEndpoint(endpoint: string): string {
  try {
    const parsed = new URL(endpoint, "https://routecairn.local");
    for (const key of [...parsed.searchParams.keys()]) {
      if (/token|secret|session|cookie|auth|password|pass|key|jwt/i.test(key)) parsed.searchParams.set(key, "<redacted>");
    }
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return endpoint.replace(/([?&][^=]*(?:token|secret|session|cookie|auth|password|pass|key|jwt)[^=]*=)[^&\s]+/gi, "$1<redacted>");
  }
}

function hashValue(value: string): string {
  return createHash("sha256").update(identityHashScope).update("\0").update(value).digest("hex").slice(0, 16);
}

function isForbiddenPathPart(part: string): boolean {
  const key = part.replace(/\[\d+\]$/, "");
  return forbiddenPathSegments.has(key);
}
