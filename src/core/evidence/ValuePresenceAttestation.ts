import { createHmac, randomBytes, randomUUID } from "node:crypto";

export type ValuePresenceLocation = "query" | "header" | "cookie" | "body" | "source-map";
export type ValuePresenceClassification =
  | "bearer-token"
  | "api-key"
  | "session-token"
  | "csrf-token"
  | "signed-request"
  | "tenant-context"
  | "cookie-value"
  | "secret-material"
  | "private-data"
  | "opaque-auth-value";

export interface ValuePresenceAttestation {
  readonly schemaVersion: 1;
  readonly location: ValuePresenceLocation;
  readonly name: string;
  readonly classification: ValuePresenceClassification;
  readonly valueLength: number;
  readonly fingerprintAlgorithm: "HMAC-SHA-256";
  readonly fingerprintScope: "scan";
  readonly correlationFingerprint: string;
  readonly observedAt: string;
  readonly requestId: string;
  readonly statusCode?: number;
  readonly responseHash?: string;
  readonly transportOutcome: "transmitted" | "cache-reused" | "policy-blocked" | "network-approved";
  readonly reproductionSteps: readonly string[];
}

interface ObservedValue {
  readonly location: ValuePresenceLocation;
  readonly name: string;
  readonly classification: ValuePresenceClassification;
  readonly rawValue: string;
}

export interface TransientValueObservation {
  readonly requestId: string;
  readonly observedAt: string;
  readonly values: readonly ObservedValue[];
}

const sensitiveNamePattern = /(?:token|cursor|continuation|secret|session|cookie|auth|password|pass|key|jwt|sig|signature|credential|csrf|tenant|org|organization|workspace|policy|expires|expiry|email|username|user_?id|account|principal|identity|invite|verification|recovery|code|x-amz-|x-goog-)/i;
const authenticationCookiePattern = /(?:session|sess|sid|auth|token|jwt|csrf|xsrf|identity|principal|tenant|org|organization|workspace)/i;

export class ValuePresenceAttestor {
  readonly #key = randomBytes(32);

  public observe(url: string, headers: Readonly<Record<string, string>> = {}): TransientValueObservation {
    const values = [...observeQuery(url), ...observeHeaders(headers)];
    return Object.freeze({
      requestId: randomUUID(),
      observedAt: new Date().toISOString(),
      values: Object.freeze(values)
    });
  }

  public finalize(
    observation: TransientValueObservation,
    input: {
      readonly safeUrl: string;
      readonly transportOutcome: ValuePresenceAttestation["transportOutcome"];
      readonly statusCode?: number;
      readonly responseHash?: string;
    }
  ): readonly ValuePresenceAttestation[] {
    return Object.freeze(
      observation.values.map((value) =>
        Object.freeze({
          schemaVersion: 1 as const,
          location: value.location,
          name: safeName(value.name),
          classification: value.classification,
          valueLength: Buffer.byteLength(value.rawValue, "utf8"),
          fingerprintAlgorithm: "HMAC-SHA-256" as const,
          fingerprintScope: "scan" as const,
          correlationFingerprint: `hmac-sha256:${createHmac("sha256", this.#key).update(value.rawValue).digest("hex")}`,
          observedAt: observation.observedAt,
          requestId: observation.requestId,
          ...(typeof input.statusCode === "number" ? { statusCode: input.statusCode } : {}),
          ...(input.responseHash ? { responseHash: input.responseHash } : {}),
          transportOutcome: input.transportOutcome,
          reproductionSteps: Object.freeze([
            `Repeat the authorized request identified by request ID ${observation.requestId} using the separately retained redacted endpoint.`,
            `Confirm a ${value.classification} value is present in the ${value.location} location named ${safeName(value.name)}.`,
            "Compare the scan-scoped correlation fingerprint; do not copy the raw value into evidence."
          ])
        })
      )
    );
  }

  public attestTransientValue(input: {
    readonly rawValue: string;
    readonly location: "body" | "source-map";
    readonly name: string;
    readonly classification: "secret-material" | "private-data";
    readonly safeUrl: string;
    readonly requestId: string;
    readonly observedAt?: string;
    readonly statusCode?: number;
    readonly responseHash?: string;
  }): ValuePresenceAttestation {
    const observedAt = input.observedAt ?? new Date().toISOString();
    return Object.freeze({
      schemaVersion: 1 as const,
      location: input.location,
      name: safeName(input.name),
      classification: input.classification,
      valueLength: Buffer.byteLength(input.rawValue, "utf8"),
      fingerprintAlgorithm: "HMAC-SHA-256" as const,
      fingerprintScope: "scan" as const,
      correlationFingerprint: `hmac-sha256:${createHmac("sha256", this.#key).update(input.rawValue).digest("hex")}`,
      observedAt,
      requestId: input.requestId,
      ...(typeof input.statusCode === "number" ? { statusCode: input.statusCode } : {}),
      ...(input.responseHash ? { responseHash: input.responseHash } : {}),
      transportOutcome: "transmitted" as const,
      reproductionSteps: Object.freeze([
        `Repeat the authorized read-only request identified by request ID ${input.requestId} using the separately retained redacted endpoint.`,
        `Confirm a ${input.classification} value is present at the safe field or pattern label ${safeName(input.name)}.`,
        "Compare the scan-scoped correlation fingerprint; do not copy the raw value into evidence."
      ])
    });
  }
}

export function redactSensitiveUrl(url: string): string {
  try {
    const parsed = new URL(url);
    parsed.username = "";
    parsed.password = "";
    const queryIndex = url.indexOf("?");
    if (queryIndex < 0) return parsed.toString();
    const hashIndex = url.indexOf("#", queryIndex);
    const rawQuery = url.slice(queryIndex + 1, hashIndex < 0 ? undefined : hashIndex);
    const redactedQuery = rawQuery
      .split("&")
      .map((part) => {
        const separator = part.indexOf("=");
        const rawName = separator < 0 ? part : part.slice(0, separator);
        const decodedName = decodeComponent(rawName.replace(/\+/g, " "));
        if (!sensitiveNamePattern.test(decodedName)) return part;
        return separator < 0 ? rawName : `${rawName}=%3Credacted%3E`;
      })
      .join("&");
    const base = parsed.toString().split("?")[0] ?? parsed.toString();
    return `${base}?${redactedQuery}${parsed.hash}`;
  } catch {
    return url.replace(/([?&][^=]*(?:token|secret|session|cookie|auth|password|pass|key|jwt|sig|signature|credential|csrf|tenant|org|workspace|policy|email|username|user_?id|account|principal|identity|invite|verification|recovery|code|x-amz-|x-goog-)[^=]*=)[^&\s]+/gi, "$1<redacted>");
  }
}

export function scrubObservedValues(value: string, observation: TransientValueObservation): string;
export function scrubObservedValues(value: undefined, observation: TransientValueObservation): undefined;
export function scrubObservedValues(value: string | undefined, observation: TransientValueObservation): string | undefined {
  if (!value) return value;
  let scrubbed = value;
  const distinctValues = [...new Set(observation.values.map((item) => item.rawValue).filter(Boolean))].sort((left, right) => right.length - left.length);
  for (const rawValue of distinctValues) {
    scrubbed = scrubbed.split(rawValue).join("<redacted>");
  }
  return scrubbed;
}

function observeQuery(url: string): ObservedValue[] {
  try {
    const parsed = new URL(url);
    const values: ObservedValue[] = [];
    for (const [name, value] of parsed.searchParams.entries()) {
      if (value && sensitiveNamePattern.test(name)) {
        values.push({ location: "query", name, classification: classifyName(name), rawValue: value });
      }
    }
    return values;
  } catch {
    return [];
  }
}

function observeHeaders(headers: Readonly<Record<string, string>>): ObservedValue[] {
  const values: ObservedValue[] = [];
  for (const [name, rawValue] of Object.entries(headers)) {
    if (!rawValue) continue;
    if (name.toLowerCase() === "cookie") {
      for (const cookie of rawValue.split(";")) {
        const separator = cookie.indexOf("=");
        if (separator <= 0) continue;
        const cookieName = cookie.slice(0, separator).trim();
        const cookieValue = cookie.slice(separator + 1).trim();
        if (cookieValue && authenticationCookiePattern.test(cookieName)) {
          values.push({ location: "cookie", name: cookieName, classification: classifyName(cookieName, "cookie-value"), rawValue: cookieValue });
        }
      }
      continue;
    }
    if (!sensitiveNamePattern.test(name)) continue;
    const bearerMatch = /^Bearer\s+(.+)$/i.exec(rawValue.trim());
    values.push({
      location: "header",
      name,
      classification: bearerMatch ? "bearer-token" : classifyName(name),
      rawValue: bearerMatch?.[1] ?? rawValue
    });
  }
  return values;
}

function classifyName(name: string, fallback: ValuePresenceClassification = "opaque-auth-value"): ValuePresenceClassification {
  if (/csrf/i.test(name)) return "csrf-token";
  if (/(?:api[-_]?key|x-api-key)/i.test(name)) return "api-key";
  if (/(?:sig|signature|policy|expires|expiry|x-amz-|x-goog-)/i.test(name)) return "signed-request";
  if (/(?:tenant|org|organization|workspace)/i.test(name)) return "tenant-context";
  if (/(?:session|cookie)/i.test(name)) return "session-token";
  if (/(?:token|jwt|auth|credential)/i.test(name)) return "opaque-auth-value";
  return fallback;
}

function safeName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_.-]/g, "_").slice(0, 128) || "unnamed";
}

function decodeComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
