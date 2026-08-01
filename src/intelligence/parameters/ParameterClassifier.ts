export type ParameterLocation = "query" | "path";
export type ParameterKind =
  | "object-id"
  | "uuid"
  | "numeric-id"
  | "slug"
  | "pagination"
  | "search"
  | "filter"
  | "sort"
  | "price"
  | "user-account"
  | "token"
  | "unknown";
export type ParameterRiskTag = "object-id" | "authorization-sensitive" | "business-logic" | "harmless-navigation";

export interface ParameterSignal {
  name: string;
  valuePreview: string;
  location: ParameterLocation;
  kind: ParameterKind;
  riskTags: ParameterRiskTag[];
  confidence: "Low" | "Medium" | "High";
  evidence: string;
}

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const numericPattern = /^\d+$/;
const slugPattern = /^[a-z0-9]+(?:-[a-z0-9]+){1,}$/i;
const tokenPattern = /^[a-z0-9_-]{20,}$/i;
const userAccountNamePattern = /(?:user|account|customer|member|tenant|org|organization|owner|profile)/i;
const objectIdNamePattern = /(?:id|uuid|guid|object|resource|order|invoice|receipt|booking|product|variant|cart|checkout|subscription)/i;
const paginationNamePattern = /^(?:page|p|offset|limit|cursor|per_page|perPage|size)$/i;
const searchNamePattern = /^(?:q|query|search|keyword|keywords|term)$/i;
const filterNamePattern = /(?:filter|category|brand|status|type|tag|color|size|rating|availability)/i;
const sortNamePattern = /^(?:sort|sortBy|order|orderBy|direction)$/i;
const priceNamePattern = /(?:price|amount|total|subtotal|min|max|discount|coupon|currency)/i;
const tokenNamePattern = /(?:token|jwt|session|csrf|xsrf|auth|signature|sig|key|secret|code|otp|nonce)/i;

export function analyzeQueryParameter(name: string, value: string): ParameterSignal {
  const normalizedName = name.trim();
  const valuePreview = previewValue(value);
  const kind = classifyKind(normalizedName, value, "query");

  return {
    name: normalizedName || "<empty>",
    valuePreview,
    location: "query",
    kind,
    riskTags: riskTagsFor(kind, normalizedName),
    confidence: confidenceFor(kind, normalizedName, value),
    evidence: evidenceFor(kind, normalizedName, valuePreview, "query")
  };
}

export function analyzePathSegment(segment: string, index: number, previousSegment?: string): ParameterSignal | undefined {
  const decoded = safeDecode(segment);
  if (!decoded || decoded.length < 2) {
    return undefined;
  }

  const kind = classifyKind(previousSegment ?? `segment-${index}`, decoded, "path");
  if (kind === "unknown") {
    return undefined;
  }

  const name = previousSegment ? `${previousSegment}:segment-${index}` : `segment-${index}`;
  return {
    name,
    valuePreview: previewValue(decoded),
    location: "path",
    kind,
    riskTags: riskTagsFor(kind, previousSegment ?? name),
    confidence: confidenceFor(kind, previousSegment ?? name, decoded),
    evidence: evidenceFor(kind, previousSegment ?? name, previewValue(decoded), "path")
  };
}

function classifyKind(name: string, value: string, location: ParameterLocation): ParameterKind {
  if (uuidPattern.test(value)) {
    return "uuid";
  }

  if (tokenNamePattern.test(name) || tokenPattern.test(value)) {
    return "token";
  }

  if (userAccountNamePattern.test(name)) {
    return "user-account";
  }

  if (objectIdNamePattern.test(name)) {
    return numericPattern.test(value) ? "numeric-id" : "object-id";
  }

  if (paginationNamePattern.test(name)) {
    return "pagination";
  }

  if (searchNamePattern.test(name)) {
    return "search";
  }

  if (filterNamePattern.test(name)) {
    return "filter";
  }

  if (sortNamePattern.test(name)) {
    return "sort";
  }

  if (priceNamePattern.test(name)) {
    return "price";
  }

  if (numericPattern.test(value)) {
    return location === "path" ? "numeric-id" : "object-id";
  }

  if (slugPattern.test(value)) {
    return "slug";
  }

  return "unknown";
}

function riskTagsFor(kind: ParameterKind, name: string): ParameterRiskTag[] {
  const tags = new Set<ParameterRiskTag>();

  if (["object-id", "uuid", "numeric-id", "slug", "user-account"].includes(kind)) {
    tags.add("object-id");
  }

  if (["object-id", "uuid", "numeric-id", "user-account", "token"].includes(kind) || userAccountNamePattern.test(name)) {
    tags.add("authorization-sensitive");
  }

  if (["price", "filter", "sort"].includes(kind)) {
    tags.add("business-logic");
  }

  if (["pagination", "search", "filter", "sort"].includes(kind)) {
    tags.add("harmless-navigation");
  }

  if (tags.size === 0) {
    tags.add("harmless-navigation");
  }

  return [...tags];
}

function confidenceFor(kind: ParameterKind, name: string, value: string): ParameterSignal["confidence"] {
  if (kind === "uuid" || kind === "token" || userAccountNamePattern.test(name) || objectIdNamePattern.test(name)) {
    return "High";
  }

  if (kind === "numeric-id" || numericPattern.test(value) || ["price", "pagination", "search", "filter", "sort"].includes(kind)) {
    return "Medium";
  }

  return "Low";
}

function evidenceFor(kind: ParameterKind, name: string, valuePreview: string, location: ParameterLocation): string {
  return `${location} parameter ${name} looked like ${kind} from value ${valuePreview}.`;
}

function previewValue(value: string): string {
  const decoded = safeDecode(value);
  if (decoded.length <= 80) {
    return decoded;
  }

  return `${decoded.slice(0, 77)}...`;
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
