export interface SafeValuePresenceAttestation {
  readonly schemaVersion: 1;
  readonly location: "query" | "header" | "cookie";
  readonly name: string;
  readonly classification:
    | "bearer-token"
    | "api-key"
    | "session-token"
    | "csrf-token"
    | "signed-request"
    | "tenant-context"
    | "cookie-value"
    | "opaque-auth-value";
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

const locations = new Set(["query", "header", "cookie"]);
const classifications = new Set([
  "bearer-token",
  "api-key",
  "session-token",
  "csrf-token",
  "signed-request",
  "tenant-context",
  "cookie-value",
  "opaque-auth-value"
]);
const outcomes = new Set(["transmitted", "cache-reused", "policy-blocked", "network-approved"]);

export function extractSafeValuePresenceAttestations(value: unknown): SafeValuePresenceAttestation[] {
  if (!isRecord(value) || !Array.isArray(value.valueAttestations)) return [];
  const result: SafeValuePresenceAttestation[] = [];
  for (const candidate of value.valueAttestations.slice(0, 32)) {
    const parsed = parseAttestation(candidate);
    if (parsed) result.push(parsed);
  }
  return result;
}

function parseAttestation(value: unknown): SafeValuePresenceAttestation | undefined {
  if (!isRecord(value)) return undefined;
  if (value.schemaVersion !== 1 || !locations.has(value.location as string)) return undefined;
  if (!classifications.has(value.classification as string) || !outcomes.has(value.transportOutcome as string)) return undefined;
  if (value.fingerprintAlgorithm !== "HMAC-SHA-256" || value.fingerprintScope !== "scan") return undefined;
  if (!isBoundedText(value.name, 128) || !/^[a-zA-Z0-9_.:[\]-]+$/.test(value.name)) return undefined;
  if (!Number.isInteger(value.valueLength) || (value.valueLength as number) < 0 || (value.valueLength as number) > 65_536) return undefined;
  if (typeof value.correlationFingerprint !== "string" || !/^hmac-sha256:[a-f0-9]{64}$/.test(value.correlationFingerprint)) return undefined;
  if (!isBoundedText(value.observedAt, 64) || !Number.isFinite(Date.parse(value.observedAt))) return undefined;
  if (!isBoundedText(value.requestId, 128)) return undefined;
  if (value.statusCode !== undefined && (!Number.isInteger(value.statusCode) || (value.statusCode as number) < 100 || (value.statusCode as number) > 599)) return undefined;
  if (value.responseHash !== undefined && (!isBoundedText(value.responseHash, 160) || !/^[a-zA-Z0-9:_-]+$/.test(value.responseHash))) return undefined;
  if (!Array.isArray(value.reproductionSteps)) return undefined;
  const steps = value.reproductionSteps.slice(0, 8);
  if (!steps.every((step) => isBoundedText(step, 300))) return undefined;

  return {
    schemaVersion: 1,
    location: value.location as SafeValuePresenceAttestation["location"],
    name: value.name,
    classification: value.classification as SafeValuePresenceAttestation["classification"],
    valueLength: value.valueLength as number,
    fingerprintAlgorithm: "HMAC-SHA-256",
    fingerprintScope: "scan",
    correlationFingerprint: value.correlationFingerprint,
    observedAt: value.observedAt,
    requestId: value.requestId,
    ...(value.statusCode === undefined ? {} : { statusCode: value.statusCode as number }),
    ...(value.responseHash === undefined ? {} : { responseHash: value.responseHash }),
    transportOutcome: value.transportOutcome as SafeValuePresenceAttestation["transportOutcome"],
    reproductionSteps: steps as string[]
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isBoundedText(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}
