import type { Confidence } from "../findings/Confidence.js";
import type { FindingEvidence } from "../findings/Finding.js";
import type { Severity } from "../findings/Severity.js";
import type { HttpResponse } from "../http/HttpTypes.js";
import type { ResponseObservation } from "../../reports/ReportTypes.js";

const sensitiveHeaderPattern = /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-csrf-token|x-tenant-id|x-org-id|x-organization-id|x-workspace-id)$/i;
const sensitiveBodyPatterns: Array<[RegExp, string]> = [
  [/(\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|signing[_-]?secret|session[_-]?secret|password|passwd|pwd|database_url|db_password|private[_-]?key)\b["']?\s*[:=]\s*)["']?[^"'\s,;<>]+/gi, "$1<redacted>"],
  [/("(?:ssn|socialSecurityNumber|taxId|privateEmail|privatePhone|privateAddress|passwordHash)"\s*:\s*")[^"]+("?)/gi, "$1<redacted>$2"],
  [/AKIA[0-9A-Z]{16}/g, "AKIA<redacted>"],
  [/(?:postgres|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'<>]+/gi, "<redacted-connection-url>"],
  [/-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/g, "<redacted-private-key>"]
];

export interface EvidenceInput {
  source: string;
  severity: Severity;
  confidence: Confidence;
  tags: string[];
}

export function evidenceFromResponse(response: HttpResponse, input: EvidenceInput): FindingEvidence {
  return {
    url: response.finalUrl,
    method: response.method,
    ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    ...(response.title ? { title: response.title } : {}),
    source: input.source,
    ...(response.bodyHash ? { bodyHash: response.bodyHash } : {}),
    ...(typeof response.contentLength === "number" ? { contentLength: response.contentLength } : {}),
    ...(response.contentType ? { contentType: response.contentType } : {}),
    responseHeaders: redactHeaders(response.headers),
    ...(response.bodyPreview ? { bodyPreview: redactBodyPreview(response.bodyPreview) } : {}),
    curlCommand: curlCommand(response.method, response.finalUrl),
    severityReason: severityReason(input),
    reproductionNotes: reproductionNotes(response),
    ...(response.valueAttestations?.length
      ? { valueAttestations: response.valueAttestations.map((attestation) => ({ ...attestation, reproductionSteps: [...attestation.reproductionSteps] })) }
      : {})
  };
}

export function evidenceFromObservation(observation: ResponseObservation, input: EvidenceInput): FindingEvidence {
  return {
    url: observation.url,
    method: observation.method,
    ...(typeof observation.statusCode === "number" ? { statusCode: observation.statusCode } : {}),
    ...(observation.title ? { title: observation.title } : {}),
    source: input.source,
    ...(observation.bodyHash ? { bodyHash: observation.bodyHash } : {}),
    ...(typeof observation.contentLength === "number" ? { contentLength: observation.contentLength } : {}),
    ...(observation.contentType ? { contentType: observation.contentType } : {}),
    ...(observation.responseHeaders ? { responseHeaders: redactHeaders(observation.responseHeaders) } : {}),
    ...(observation.bodyPreview ? { bodyPreview: redactBodyPreview(observation.bodyPreview) } : {}),
    curlCommand: curlCommand(observation.method, observation.url),
    severityReason: severityReason(input),
    reproductionNotes: [
      `RouteCairn classified this observation as ${observation.falsePositiveStatus}: ${observation.classificationReason}.`,
      "Re-run the curl command from an authorized network context and compare status, headers, and page behavior."
    ]
  };
}

export function redactHeaders(headers: Record<string, string | string[]>): Record<string, string | string[]> {
  const redacted: Record<string, string | string[]> = {};

  for (const [name, value] of Object.entries(headers)) {
    redacted[name] = sensitiveHeaderPattern.test(name) ? redactHeaderValue(value) : value;
  }

  return redacted;
}

export function redactBodyPreview(bodyPreview: string, maxLength = 1200): string {
  const normalized = bodyPreview.slice(0, maxLength);
  return sensitiveBodyPatterns.reduce((preview, [pattern, replacement]) => preview.replace(pattern, replacement), normalized);
}

function redactHeaderValue(value: string | string[]): string | string[] {
  if (Array.isArray(value)) {
    return value.map(() => "<redacted>");
  }

  return "<redacted>";
}

function curlCommand(method: string, url: string): string {
  const escapedUrl = url.replace(/"/g, '\\"');
  return `curl -i -X ${method} "${escapedUrl}"`;
}

function severityReason(input: EvidenceInput): string {
  const tagSummary = input.tags.length > 0 ? ` Tags: ${input.tags.join(", ")}.` : "";
  return `${input.severity} severity with ${input.confidence} confidence assigned by RouteCairn rule evidence: ${input.source}.${tagSummary}`;
}

function reproductionNotes(response: HttpResponse): string[] {
  const notes = [
    "Re-run the curl command from an authorized network context and compare status, headers, content length, and body hash/preview.",
    "Body preview and sensitive headers are redacted to avoid storing secrets unnecessarily."
  ];

  if (response.redirectChain.length > 0) {
    notes.push(`Response followed ${response.redirectChain.length} redirect(s).`);
  }

  return notes;
}
