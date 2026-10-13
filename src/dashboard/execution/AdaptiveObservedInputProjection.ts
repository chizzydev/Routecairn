import type { HttpResponse, RequestAuditEntry } from "../../core/http/HttpTypes.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { adaptiveHttpUrl, createAdaptiveResponseMatcher } from "./AdaptiveEvidenceSafety.js";
import { adaptiveObservedInputV1Schema, observedInputBounds as bounds, observedInputId, observedInputIdentityPreimage, observedInputMethodSchema, observedInputSkippedOutcomeSchema, type AdaptiveObservedInputV1, type ObservedInputDiagnostic, type ObservedInputIdentity } from "./AdaptiveObservedInputIR.js";

export interface ObservedInputProjection {
  observations: AdaptiveObservedInputV1[];
  diagnostics: ObservedInputDiagnostic[];
  sourceCounts: { brokerAudit: number; browserNetwork: number; apiMapper: number; responses: number };
}
type RecordValue = Record<string, unknown>;
function record(value: unknown): value is RecordValue { return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype; }
/** Bounded JSON data inspection, without invoking getters, toJSON, or serializing private data.
 * Repeated references are permitted; ancestor cycles, accessors and non-data objects fail closed. */
function inspect(input: unknown): "INVALID_INPUT" | "INPUT_LIMIT" | undefined {
  let nodes = 0; let strings = 0; const ancestors = new Set<object>();
  const walk = (value: unknown, depth: number): "INVALID_INPUT" | "INPUT_LIMIT" | undefined => {
    if (++nodes > bounds.nodes || depth > bounds.depth) return "INPUT_LIMIT";
    if (typeof value === "string") { strings += value.length * 2; return value.length > bounds.string || strings > bounds.stringBytes ? "INPUT_LIMIT" : undefined; }
    if (value === null || value === undefined || typeof value === "boolean") return;
    if (typeof value === "number") return Number.isFinite(value) ? undefined : "INVALID_INPUT";
    if (typeof value !== "object" || (!Array.isArray(value) && !record(value)) || ancestors.has(value)) return "INVALID_INPUT";
    if (Array.isArray(value) && value.length > bounds.records) return "INPUT_LIMIT";
    const keys = Reflect.ownKeys(value);
    if (keys.length > (Array.isArray(value) ? bounds.records + 1 : bounds.keys)) return "INPUT_LIMIT";
    ancestors.add(value);
    for (const key of keys) {
      if (typeof key !== "string" || key.length > bounds.urls) return "INVALID_INPUT";
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor)) return "INVALID_INPUT";
      const failure = walk(descriptor.value, depth + 1); if (failure) return failure;
    }
    ancestors.delete(value);
  };
  try { return walk(input, 0); } catch { return "INVALID_INPUT"; }
}
function url(value: unknown, base: string): URL | undefined { return typeof value === "string" && value.length > 0 && value.length <= bounds.urls ? adaptiveHttpUrl(value, base) : undefined; }
function validStatus(value: unknown): boolean { return value === undefined || typeof value === "number" && Number.isInteger(value) && value >= 100 && value <= 599; }
function exchange(value: unknown, base: string): value is RequestAuditEntry & HttpResponse {
  return record(value) && Boolean(url(value.requestedUrl, base)) && typeof value.method === "string" && value.method.length <= 32 &&
    (value.finalUrl === undefined || Boolean(url(value.finalUrl, base))) && (value.requestId === undefined || typeof value.requestId === "string" && value.requestId.length > 0 && value.requestId.length <= 512) &&
    validStatus(value.statusCode) && Array.isArray(value.redirectChain) &&
    value.redirectChain.every((hop) => record(hop) && validStatus(hop.statusCode) && typeof hop.location === "string" && hop.location.length <= bounds.urls);
}

/** Offline shadow projection. Matching transiently uses raw identities only inside the frozen matcher.
 * Input records are never deduplicated; route ordinals use first-seen origin/method/path, without query.
 * An exact pair is correlation, not complete body, principal, scope, cleanup or exploit proof. */
export function projectAdaptiveObservedInputs(report: RouteCairnReport): ObservedInputProjection {
  try { return project(report); }
  catch { return { observations: [], diagnostics: [{ code: "INVALID_INPUT" }], sourceCounts: { brokerAudit: 0, browserNetwork: 0, apiMapper: 0, responses: 0 } }; }
}
function project(report: RouteCairnReport): ObservedInputProjection {
  const result: ObservedInputProjection = { observations: [], diagnostics: [], sourceCounts: { brokerAudit: 0, browserNetwork: 0, apiMapper: 0, responses: 0 } };
  const fail = (code: ObservedInputDiagnostic["code"]) => { result.observations = []; result.diagnostics = [{ code }]; return result; };
  const inspected = inspect(report); if (inspected) return fail(inspected);
  if (!record(report)) return fail("INVALID_INPUT");
  if (!Array.isArray(report.requestAudit) || !Array.isArray(report.responses)) return fail("INVALID_INPUT");
  const target = url(report.target, report.target); if (!target || target.origin.length > 300) return fail("INVALID_TARGET");
  if (report.browserCrawl !== undefined && (!record(report.browserCrawl) || !Array.isArray(report.browserCrawl.networkRequests))) return fail("INVALID_INPUT");
  if (report.apiMapper !== undefined && (!record(report.apiMapper) || !Array.isArray(report.apiMapper.endpoints))) return fail("INVALID_INPUT");
  const browser = report.browserCrawl?.networkRequests ?? []; const mapper = report.apiMapper?.endpoints ?? [];
  result.sourceCounts = { brokerAudit: report.requestAudit.length, browserNetwork: browser.length, apiMapper: mapper.length, responses: report.responses.length };
  if (Object.values(result.sourceCounts).reduce((sum, count) => sum + count, 0) > bounds.records) return fail("INPUT_LIMIT");
  // Never remove a malformed exchange and thereby turn an ambiguous legacy corpus into an exact match.
  // A malformed response taints pairing for the batch; independent metadata still gets accounted.
  const validResponses = Array.from(report.responses).every((value) => exchange(value, report.target) &&
    (value.error === undefined || record(value.error)) && (value.streamTruncated === undefined || typeof value.streamTruncated === "boolean"));
  const validAudits = Array.from(report.requestAudit).every((value) => exchange(value, report.target) &&
    (value.error === undefined || typeof value.error === "string") && (value.outcome === "sent" || observedInputSkippedOutcomeSchema.safeParse(value.outcome).success));
  const match = validResponses && validAudits ? createAdaptiveResponseMatcher(report.requestAudit, report.responses, report.target) : () => undefined;
  const routes = new Map<string, number>();
  const completeness: ObservedInputIdentity["reportCompleteness"] = record(report.execution) && report.execution.status === "COMPLETED" && report.execution.partial === false ? "COMPLETED_REPORTED" : "INCOMPLETE_OR_UNKNOWN";
  const sources = [["BROKER_AUDIT", report.requestAudit], ["BROWSER_NETWORK", browser], ["API_MAPPER", mapper]] as const;
  for (const [producer, items] of sources) for (let sourceIndex = 0; sourceIndex < items.length; sourceIndex++) {
    const item: unknown = items[sourceIndex];
    const diagnostic = (code: ObservedInputDiagnostic["code"]) => result.diagnostics.push({ producer, sourceIndex, code });
    if (!record(item) || typeof item.method !== "string" || item.method.length > 32) { diagnostic("INVALID_RECORD"); continue; }
    const location = url(producer === "BROKER_AUDIT" ? item.requestedUrl : producer === "BROWSER_NETWORK" ? item.url : item.endpoint, report.target);
    if (!location) { diagnostic("INVALID_URL"); continue; }
    const parsedMethod = observedInputMethodSchema.safeParse(item.method.toUpperCase()); const method = parsedMethod.success ? parsedMethod.data : "UNKNOWN";
    const routeKey = JSON.stringify([location.origin, method, location.pathname]);
    const routeOrdinal = routes.get(routeKey) ?? routes.size;
    if (routeOrdinal >= bounds.routes) return fail("INPUT_LIMIT");
    const common = { schemaVersion: 1 as const, targetOrigin: target.origin, sourceIndex, routeOrdinal, method, originRelation: location.origin === target.origin ? "PRIMARY_TARGET" as const : "OTHER_ORIGIN" as const,
      reportCompleteness: completeness, actorAttribution: "UNKNOWN" as const, vulnerabilityConclusion: "NOT_ASSESSED" as const, authorizationDecision: "UNKNOWN" as const,
      executable: false as const, executionAuthority: "NONE" as const, operatorApproval: "NOT_GRANTED" as const, credentialsResolved: false as const, cleanup: "NOT_ASSESSED" as const };
    let identity: ObservedInputIdentity;
    if (producer === "BROKER_AUDIT") {
      if (item.outcome !== "sent" && !observedInputSkippedOutcomeSchema.safeParse(item.outcome).success) { diagnostic("UNKNOWN_OUTCOME"); continue; }
      if (!exchange(item, report.target) || item.error !== undefined && typeof item.error !== "string") { diagnostic("INVALID_RECORD"); continue; }
      if (item.outcome === "sent") {
        const response = method === "UNKNOWN" ? undefined : match(item);
        identity = response ? { ...common, producer, disposition: "BROKER_SENT_EXACT_PAIR", auditOutcome: "sent", statusCode: response.statusCode!, responseError: false, ...(response.streamTruncated === undefined ? {} : { responseTruncated: response.streamTruncated }) } :
          { ...common, producer, disposition: "BROKER_SENT_UNPAIRED", auditOutcome: "sent", ...(item.statusCode === undefined ? {} : { auditReportedStatus: item.statusCode }) };
      } else identity = { ...common, producer, disposition: "BROKER_SKIPPED_OR_BLOCKED", auditOutcome: observedInputSkippedOutcomeSchema.parse(item.outcome) };
    } else if (producer === "BROWSER_NETWORK") {
      if (item.decision !== undefined && item.decision !== "allowed" && item.decision !== "blocked" || item.transmitted !== undefined && typeof item.transmitted !== "boolean") { diagnostic("INVALID_RECORD"); continue; }
      if (item.decision === "blocked" && item.transmitted === true) { diagnostic("CONTRADICTORY_BROWSER"); continue; }
      identity = item.transmitted === true ? { ...common, producer, disposition: "BROWSER_REPORTED_TRANSMITTED", browserTransmitted: true, ...(item.decision === undefined ? {} : { browserDecision: "allowed" as const }) } :
        item.decision === "blocked" ? { ...common, producer, disposition: "BROWSER_REPORTED_BLOCKED", browserDecision: "blocked", ...(item.transmitted === undefined ? {} : { browserTransmitted: false as const }) } :
          { ...common, producer, disposition: "BROWSER_REPORTED_UNKNOWN", ...(item.decision === undefined ? {} : { browserDecision: "allowed" as const }), ...(item.transmitted === undefined ? {} : { browserTransmitted: false as const }) };
    } else identity = { ...common, producer, disposition: "API_DISCOVERY_CANDIDATE" };
    const observation = { ...identity, observationId: observedInputId(identity) };
    if (!adaptiveObservedInputV1Schema.safeParse(observation).success) { diagnostic("INVALID_RECORD"); continue; }
    routes.set(routeKey, routeOrdinal); result.observations.push(observation);
  }
  return result;
}

/** Hash validity only proves internal consistency. Re-derive against the supplied evidence to bind facts. */
export function validateAdaptiveObservedInput(input: unknown, report: RouteCairnReport): boolean {
  try {
    if (inspect(input)) return false;
    const parsed = adaptiveObservedInputV1Schema.safeParse(input); if (!parsed.success) return false;
    const value = parsed.data as AdaptiveObservedInputV1;
    const expected = projectAdaptiveObservedInputs(report).observations.find((candidate) => candidate.producer === value.producer && candidate.sourceIndex === value.sourceIndex);
    if (!expected) return false;
    const { observationId: expectedId, ...expectedIdentity } = expected; const { observationId, ...identity } = value;
    return observationId === expectedId && observedInputIdentityPreimage(identity) === observedInputIdentityPreimage(expectedIdentity);
  } catch { return false; }
}
