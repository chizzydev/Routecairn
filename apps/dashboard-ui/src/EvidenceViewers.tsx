import React, { useState } from "react";
import type { FindingDetailData } from "./api";

export type EvidenceRecord = FindingDetailData["evidence"][number];
export interface EvidenceViewerContext { evidence: EvidenceRecord; data: Record<string, unknown>; }
export type EvidenceViewer = (context: EvidenceViewerContext) => React.ReactElement;

const viewers: ReadonlyArray<{ matches: RegExp; render: EvidenceViewer }> = [
  { matches: /object.?pair|bola|idor/i, render: ObjectPairViewer },
  { matches: /field.?exposure/i, render: FieldExposureViewer },
  { matches: /matrix|role.?state/i, render: MatrixViewer },
  { matches: /equivalent.?route/i, render: EquivalentRouteViewer },
  { matches: /collection|listing/i, render: CollectionViewer },
  { matches: /bulk/i, render: BulkViewer },
  { matches: /file|download/i, render: FileViewer },
  { matches: /identity|principal/i, render: IdentityViewer },
  { matches: /browser|playwright|screenshot/i, render: BrowserViewer },
  { matches: /http|request|response/i, render: HttpViewer }
];

export function EvidenceViewerRegistry({ evidence }: { evidence: EvidenceRecord }): React.ReactElement {
  const data = parseSafeData(evidence.safe_structured_data_json);
  const viewer = viewers.find((item) => item.matches.test(evidence.evidence_type))?.render ?? GenericViewer;
  const attestations = parseValuePresenceAttestations(data.valueAttestations);
  return <>{viewer({ evidence, data })}{attestations.length > 0 ? <ValuePresenceAttestations attestations={attestations} /> : null}</>;
}

function HttpViewer(context: EvidenceViewerContext): React.ReactElement {
  return <Semantic title="HTTP evidence" data={context.data} fields={["method", "url", "normalizedUrl", "status", "safeHeaders", "redirects", "responseType", "contentType", "contentLength", "timing", "bodyHash", "fingerprint", "case"]} />;
}
function ObjectPairViewer(context: EvidenceViewerContext): React.ReactElement {
  return <><Semantic title="Object ownership relationship" data={context.data} fields={["actor", "account", "object", "owner", "relationship", "expected", "observed", "decision", "result", "mismatch"]} /><Callout>Baseline and cross-owner rows are shown only when retained in executed evidence.</Callout></>;
}
function FieldExposureViewer(context: EvidenceViewerContext): React.ReactElement {
  return <Semantic title="Field exposure" data={context.data} fields={["fieldPath", "actor", "expected", "actual", "exposure", "baseline", "fingerprint", "result"]} />;
}
function MatrixViewer(context: EvidenceViewerContext): React.ReactElement {
  return <><Semantic title="Executed authorization matrix" data={context.data} fields={["rows", "actor", "tenant", "role", "accountState", "objectState", "action", "expected", "observed", "result"]} /><Callout>Only executed rows are displayed; missing permutations are not inferred.</Callout></>;
}
function EquivalentRouteViewer(context: EvidenceViewerContext): React.ReactElement {
  return <Semantic title="Equivalent route comparison" data={context.data} fields={["referenceRoute", "candidateRoute", "actor", "expectedRelationship", "referenceResult", "candidateResult", "identityBoundary", "result"]} />;
}
function CollectionViewer(context: EvidenceViewerContext): React.ReactElement {
  return <><Semantic title="Collection authorization" data={context.data} fields={["endpoint", "actor", "knownObject", "expectedMembership", "observedMembership", "completeness", "reference", "count", "conclusion", "limitation"]} /><Callout>Absence is not conclusive unless the retained completeness model proves that the result set was complete.</Callout></>;
}
function BulkViewer(context: EvidenceViewerContext): React.ReactElement {
  return <><Semantic title="Bulk authorization" data={context.data} fields={["safetyMode", "actor", "objectSet", "baseline", "bulkResult", "perObject", "precondition", "postcondition", "stateFields", "mutationContract", "result"]} /><Callout>Only explicitly configured state fields were checked. This does not prove absence of all possible side effects.</Callout></>;
}
function FileViewer(context: EvidenceViewerContext): React.ReactElement {
  return <><Semantic title="File and download authorization" data={context.data} fields={["proofMode", "actor", "metadataAccess", "contentAccess", "bytesRead", "prefix", "complete", "fingerprint", "signedUrlIssued", "signedUrlFollowed", "approvedOrigin", "redirectCount", "result", "limitation"]} /><Callout>HEAD is not body proof, a prefix is not complete-file proof, and signed URL issuance is distinct from a successful download.</Callout></>;
}
function IdentityViewer(context: EvidenceViewerContext): React.ReactElement {
  return <Semantic title="Verified identity" data={context.data} fields={["actor", "verificationState", "principalComparison", "tenantComparison", "roleComparison", "accountStateComparison", "failureCategory"]} />;
}
function BrowserViewer(context: EvidenceViewerContext): React.ReactElement {
  return <><Semantic title="Browser observation" data={context.data} fields={["source", "title", "method", "url", "bodyHash", "pageUrl", "navigationState", "event", "scopeStatus", "policyStatus", "screenshotAvailable", "metadata"]} />{context.evidence.artifact_id ? <ScreenshotPreview evidence={context.evidence} /> : null}</>;
}
function GenericViewer(context: EvidenceViewerContext): React.ReactElement {
  return <><Callout>No specialized viewer is available for this evidence type.</Callout><pre className="safe-evidence-json">{JSON.stringify(boundValue(context.data), null, 2)}</pre></>;
}

function Semantic({ title, data, fields }: { title: string; data: Record<string, unknown>; fields: string[] }): React.ReactElement {
  const entries = collect(data, new Set(fields.map(normalizeKey))).slice(0, 80);
  if (!entries.length) return <GenericViewer evidence={{} as EvidenceRecord} data={data} />;
  return <section className="semantic-evidence"><h4>{title}</h4><dl className="dense-dl">{entries.map(([key, value], index) => <React.Fragment key={`${key}-${index}`}><dt>{label(key)}</dt><dd>{renderValue(value)}</dd></React.Fragment>)}</dl></section>;
}

function ScreenshotPreview({ evidence }: { evidence: EvidenceRecord }): React.ReactElement {
  const [large, setLarge] = useState(false);
  const [dimensions, setDimensions] = useState<string>();
  const id = evidence.artifact_id!;
  if (evidence.missing_file_flag) return <p className="muted">Screenshot artifact is unavailable.</p>;
  const recordDimensions = (image: HTMLImageElement): void => setDimensions(`${image.naturalWidth} × ${image.naturalHeight}`);
  return <div className="screenshot-evidence"><button className="screenshot-thumb" onClick={() => setLarge(true)} aria-label="Open larger screenshot preview"><img src={`/api/artifacts/${id}/preview`} alt="Retained scan screenshot" loading="lazy" onLoad={(event) => recordDimensions(event.currentTarget)} /></button>{dimensions && <small className="muted">Validated preview: {dimensions}</small>}<a href={`/api/artifacts/${id}/download`}>Download screenshot</a>{large && <div className="screenshot-modal" role="dialog" aria-modal="true" aria-label="Screenshot preview"><button onClick={() => setLarge(false)}>Close</button><img src={`/api/artifacts/${id}/preview`} alt="Retained scan screenshot enlarged" /></div>}</div>;
}

function Callout({ children }: { children: React.ReactNode }): React.ReactElement { return <p className="evidence-callout">{children}</p>; }

interface SafeValuePresenceAttestation {
  schemaVersion: 1;
  location: "query" | "header" | "cookie";
  name: string;
  classification: string;
  valueLength: number;
  fingerprintAlgorithm: "HMAC-SHA-256";
  fingerprintScope: "scan";
  correlationFingerprint: string;
  observedAt: string;
  requestId: string;
  statusCode?: number;
  responseHash?: string;
  transportOutcome: "transmitted" | "cache-reused" | "policy-blocked" | "network-approved";
  reproductionSteps: string[];
}

function ValuePresenceAttestations({ attestations }: { attestations: readonly SafeValuePresenceAttestation[] }): React.ReactElement {
  return (
    <section className="semantic-evidence value-presence-attestations">
      <h4>Sensitive value presence attestations</h4>
      <Callout>
        Raw values are intentionally excluded. Matching scan-scoped fingerprints show that the same value was observed during this scan.
      </Callout>
      {attestations.map((attestation) => (
        <article
          className="value-presence-attestation"
          key={`${attestation.requestId}-${attestation.location}-${attestation.name}-${attestation.correlationFingerprint}`}
        >
          <dl className="dense-dl">
            <dt>Location</dt><dd>{label(attestation.location)}</dd>
            <dt>Name</dt><dd><code>{attestation.name}</code></dd>
            <dt>Classification</dt><dd>{label(attestation.classification)}</dd>
            <dt>Length</dt><dd>{attestation.valueLength} characters</dd>
            <dt>Correlation fingerprint</dt><dd><code>{attestation.correlationFingerprint}</code></dd>
            <dt>Observed</dt><dd>{attestation.observedAt}</dd>
            <dt>Request ID</dt><dd><code>{attestation.requestId}</code></dd>
            <dt>Transport</dt><dd>{label(attestation.transportOutcome)}</dd>
            {attestation.statusCode !== undefined ? <><dt>Status</dt><dd>{attestation.statusCode}</dd></> : null}
            {attestation.responseHash ? <><dt>Response hash</dt><dd><code>{attestation.responseHash}</code></dd></> : null}
          </dl>
          {attestation.reproductionSteps.length > 0 ? (
            <>
              <h5>Reproduction steps</h5>
              <ol>
                {attestation.reproductionSteps.map((step, index) => <li key={`${index}-${step}`}>{step}</li>)}
              </ol>
            </>
          ) : null}
        </article>
      ))}
    </section>
  );
}

function parseValuePresenceAttestations(value: unknown): SafeValuePresenceAttestation[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, 32).flatMap((candidate) => {
    if (!isObject(candidate)) return [];
    const classifications = new Set(["bearer-token", "api-key", "session-token", "csrf-token", "signed-request", "tenant-context", "cookie-value", "opaque-auth-value"]);
    const outcomes = new Set(["transmitted", "cache-reused", "policy-blocked", "network-approved"]);
    if (candidate.schemaVersion !== 1 || !["query", "header", "cookie"].includes(String(candidate.location))) return [];
    if (!classifications.has(String(candidate.classification)) || !outcomes.has(String(candidate.transportOutcome))) return [];
    if (candidate.fingerprintAlgorithm !== "HMAC-SHA-256" || candidate.fingerprintScope !== "scan") return [];
    if (!boundedString(candidate.name, 128) || !/^[a-zA-Z0-9_.:[\]-]+$/.test(candidate.name)) return [];
    if (!Number.isInteger(candidate.valueLength) || Number(candidate.valueLength) < 0 || Number(candidate.valueLength) > 65_536) return [];
    if (typeof candidate.correlationFingerprint !== "string" || !/^hmac-sha256:[a-f0-9]{64}$/.test(candidate.correlationFingerprint)) return [];
    if (!boundedString(candidate.observedAt, 64) || !Number.isFinite(Date.parse(candidate.observedAt))) return [];
    if (!boundedString(candidate.requestId, 128)) return [];
    if (candidate.statusCode !== undefined && (!Number.isInteger(candidate.statusCode) || Number(candidate.statusCode) < 100 || Number(candidate.statusCode) > 599)) return [];
    if (candidate.responseHash !== undefined && (!boundedString(candidate.responseHash, 160) || !/^[a-zA-Z0-9:_-]+$/.test(candidate.responseHash))) return [];
    if (!Array.isArray(candidate.reproductionSteps)) return [];
    const reproductionSteps = candidate.reproductionSteps.slice(0, 8);
    if (!reproductionSteps.every((step) => boundedString(step, 300))) return [];
    return [{
      schemaVersion: 1,
      location: candidate.location as SafeValuePresenceAttestation["location"],
      name: candidate.name,
      classification: String(candidate.classification),
      valueLength: Number(candidate.valueLength),
      fingerprintAlgorithm: "HMAC-SHA-256",
      fingerprintScope: "scan",
      correlationFingerprint: candidate.correlationFingerprint,
      observedAt: candidate.observedAt,
      requestId: candidate.requestId,
      ...(candidate.statusCode === undefined ? {} : { statusCode: Number(candidate.statusCode) }),
      ...(candidate.responseHash === undefined ? {} : { responseHash: candidate.responseHash }),
      transportOutcome: candidate.transportOutcome as SafeValuePresenceAttestation["transportOutcome"],
      reproductionSteps: reproductionSteps as string[]
    }];
  });
}

function boundedString(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

function parseSafeData(value: string): Record<string, unknown> { try { const parsed = JSON.parse(value) as unknown; return isObject(parsed) ? parsed : { value: parsed }; } catch { return { value }; } }
function collect(value: unknown, wanted: Set<string>, prefix = ""): Array<[string, unknown]> {
  if (!isObject(value)) return [];
  const result: Array<[string, unknown]> = [];
  for (const [key, child] of Object.entries(value)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (wanted.has(normalizeKey(key))) result.push([path, child]);
    if (isObject(child)) result.push(...collect(child, wanted, path));
    if (Array.isArray(child)) child.slice(0, 50).forEach((item, index) => { if (isObject(item)) result.push(...collect(item, wanted, `${path}[${index}]`)); });
  }
  return result;
}
function renderValue(value: unknown): React.ReactNode { return typeof value === "string" || typeof value === "number" || typeof value === "boolean" ? String(value) : <pre className="safe-evidence-json compact">{JSON.stringify(boundValue(value), null, 2)}</pre>; }
function boundValue(value: unknown): unknown { const text = JSON.stringify(value); if (!text || text.length <= 20_000) return value; return { boundedPreview: text.slice(0, 20_000), truncated: true }; }
function normalizeKey(value: string): string { return value.replace(/[^a-z0-9]/gi, "").toLowerCase(); }
function label(value: string): string { return value.replace(/\[(\d+)\]/g, " $1").replaceAll(".", " / ").replace(/([a-z])([A-Z])/g, "$1 $2").replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase()); }
function isObject(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
