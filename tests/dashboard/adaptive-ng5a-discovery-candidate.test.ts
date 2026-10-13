import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { discoveryCandidateId, discoveryCandidateIdentityPreimage, discoveryCandidateV1Schema, discoveryAccountingEntrySchema, discoveryPlannerDiagnosticSchema, compareDiscoveryCandidates, discoveryBinaryCompare, parseAdaptiveDiscoveryCandidate, type DiscoveryCandidateV1 } from "../../src/dashboard/execution/AdaptiveDiscoveryCandidateIR.js";
import { planAdaptiveDiscoveryCandidates, validateAdaptiveDiscoveryCandidate } from "../../src/dashboard/execution/AdaptiveDiscoveryCandidatePlanner.js";
import { projectAdaptiveObservedInputs } from "../../src/dashboard/execution/AdaptiveObservedInputProjection.js";
import { observedInputSkippedOutcomeSchema } from "../../src/dashboard/execution/AdaptiveObservedInputIR.js";
import { ng2Origin, ng2Report } from "../helpers/adaptive-ng2-fixture.js";
function fixture() { return structuredClone(ng2Report()); }
function one() { const report = fixture(); report.requestAudit = [report.requestAudit[0]!]; report.responses = [report.responses[0]!]; report.browserCrawl = undefined; report.apiMapper = undefined; return report; }
function corpus() {
  const report = fixture(); report.requestAudit.forEach((audit, index) => { audit.requestId = `ng4-private-request-${index}`; report.responses[index]!.requestId = audit.requestId; });
  report.requestAudit.push({ ...structuredClone(report.requestAudit[0]!), requestId: "ng4-private-unpaired" }, { ...structuredClone(report.requestAudit[0]!), outcome: "scope-skipped" });
  report.browserCrawl!.networkRequests = [
    { url: report.requestAudit[0]!.requestedUrl, method: "GET", resourceType: "fetch", decision: "allowed", transmitted: true },
    { url: report.requestAudit[0]!.requestedUrl, method: "GET", resourceType: "fetch", decision: "blocked", transmitted: false },
    { url: report.requestAudit[0]!.requestedUrl, method: "GET", resourceType: "fetch", decision: "allowed" }
  ];
  report.apiMapper!.endpoints.push(structuredClone(report.apiMapper!.endpoints[0]!));
  report.execution = { status: "COMPLETED", partial: false, reason: "fixture", checkpointAt: "2026-10-13T08:00:00Z", cleanup: { state: "UNKNOWN", cases: [] } };
  return report;
}
function candidate(report = one()) { return planAdaptiveDiscoveryCandidates(report).candidates[0]!; }
function idInput(value: DiscoveryCandidateV1) { return { targetOrigin: value.targetOrigin, originRelation: value.originRelation, routeOrdinal: value.routeOrdinal, method: value.method }; }
function mappingOnly() { const report = fixture(); report.requestAudit = []; report.responses = []; report.browserCrawl = undefined; return report; }
function browserOnly(decision?: "allowed" | "blocked", transmitted?: boolean) { const report = fixture(); report.requestAudit = []; report.responses = []; report.apiMapper = undefined; report.browserCrawl!.networkRequests = [{ url: `${ng2Origin}/health`, method: "GET", resourceType: "fetch", ...(decision === undefined ? {} : { decision }), ...(transmitted === undefined ? {} : { transmitted }) }]; return report; }
function digest(value: unknown) { return createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
afterEach(() => vi.restoreAllMocks());
describe("RC-NG5A report-local discovery review planner", () => {
  it("accounts every observation from the real 18-event NG4 corpus", () => {
    const report = corpus(); const upstream = projectAdaptiveObservedInputs(report); const result = planAdaptiveDiscoveryCandidates(report);
    expect(upstream.observations).toHaveLength(18); expect(result.candidates).toHaveLength(8); expect(result.accountedObservations).toBe(18); expect(result.sourceCounts).toEqual({ brokerAudit: 6, browserNetwork: 3, apiMapper: 9, responses: 4 });
    expect(result.diagnostics).toEqual([]); expect(result.upstreamDiagnostics).toEqual([]);
    expect(result.accountingLedger.map((value) => value.observationId)).toEqual(upstream.observations.map((value) => value.observationId));
    expect(result.candidates.flatMap((value) => value.sourceReferences)).toHaveLength(18);
    for (const value of result.accountingLedger) expect(discoveryAccountingEntrySchema.safeParse(value).success).toBe(true);
  });
  it("retains conflicting blocked and exact memberships instead of best-of promotion", () => {
    const value = candidate(corpus()); expect(value).toMatchObject({ routeOrdinal: 0, readiness: "BLOCKED_OR_CONTRADICTORY", alreadyObservedExchange: true, mixedEvidence: true, nextStep: "RESOLVE_CONTRADICTION", producerCoverage: 3 });
    expect(value.sourceReferences).toHaveLength(8); expect(value.evidenceSummary).toEqual({ BROKER_SENT_EXACT_PAIR: 1, BROKER_SENT_UNPAIRED: 1, BROKER_SKIPPED_OR_BLOCKED: 1, BROWSER_REPORTED_TRANSMITTED: 1, BROWSER_REPORTED_BLOCKED: 1, BROWSER_REPORTED_UNKNOWN: 1, API_DISCOVERY_CANDIDATE: 2 });
  });
  it("marks exact grouped with browser transmission and mapper as already observed", () => {
    const report = corpus(); report.requestAudit.splice(4); report.browserCrawl!.networkRequests.splice(1);
    const value = planAdaptiveDiscoveryCandidates(report).candidates.find((item) => item.routeOrdinal === 0)!;
    expect(value).toMatchObject({ readiness: "EXACT_EXCHANGE_ALREADY_OBSERVED", alreadyObservedExchange: true, mixedEvidence: true, nextStep: "REVIEW_EXISTING_EVIDENCE" }); expect(value.sourceReferences).toHaveLength(4);
  });
  it("makes mapper-only gaps review signals without requests", () => { const value = candidate(mappingOnly()); expect(value).toMatchObject({ readiness: "DISCOVERED_NOT_CONFIRMED_TRANSMITTED", nextStep: "REVIEW_FOR_POTENTIAL_PROBE", alreadyObservedExchange: false }); expect(value.requirements).toContain("VERIFY_NON_MUTATING_EFFECT"); });
  it.each([["allowed", true, "BROWSER_TRANSMISSION_REPORTED_ONLY"], ["allowed", undefined, "BROWSER_OBSERVATION_UNCONFIRMED"], [undefined, false, "BROWSER_OBSERVATION_UNCONFIRMED"], ["blocked", false, "BLOCKED_OR_CONTRADICTORY"]] as const)("preserves browser %s/%s uncertainty", (decision, transmitted, readiness) => {
    const value = candidate(browserOnly(decision, transmitted)); expect(value.readiness).toBe(readiness); expect(value.alreadyObservedExchange).toBe(false); expect(value.evidenceSummary.BROKER_SENT_EXACT_PAIR).toBe(0);
  });
  it("propagates contradictory upstream browser diagnostic with a conservative global barrier", () => {
    const report = corpus(); report.browserCrawl!.networkRequests[0]!.decision = "blocked"; const result = planAdaptiveDiscoveryCandidates(report);
    expect(result.upstreamDiagnostics).toEqual([{ producer: "BROWSER_NETWORK", sourceIndex: 0, code: "CONTRADICTORY_BROWSER" }]); expect(result.accountedObservations).toBe(17);
    for (const value of result.candidates) { expect(value.upstreamEvidenceIncomplete).toBe(true); expect(value.nextStep).toBe("RESOLVE_CONTRADICTION"); expect(value.readiness).toBe("BLOCKED_OR_CONTRADICTORY"); }
  });
  it.each(["missing", "duplicate ID", "duplicate response", "wrong query", "wrong status", "redirect", "error"])("inherits NG4 downgrade for %s", (kind) => {
    const report = one(); if (kind === "missing") report.responses = [];
    if (kind === "duplicate ID") { report.requestAudit[0]!.requestId = "same"; report.responses[0]!.requestId = "same"; report.requestAudit.push(structuredClone(report.requestAudit[0]!)); }
    if (kind === "duplicate response") report.responses.push(structuredClone(report.responses[0]!));
    if (kind === "wrong query") { report.responses[0]!.requestedUrl += "?private=wrong"; report.responses[0]!.finalUrl = report.responses[0]!.requestedUrl; }
    if (kind === "wrong status") report.responses[0]!.statusCode = 403;
    if (kind === "redirect") report.responses[0]!.redirectChain.push({ statusCode: 302, location: "/private" });
    if (kind === "error") report.responses[0]!.error = { name: "Private", message: "private-error" };
    expect(candidate(report)).toMatchObject({ readiness: "SENT_BUT_RESPONSE_UNCONFIRMED", alreadyObservedExchange: false }); expect(candidate(report).evidenceSummary.BROKER_SENT_EXACT_PAIR).toBe(0);
  });
  it("retains exact evidence but highlights an additional unconfirmed sent exchange", () => { const report = corpus(); report.requestAudit.pop(); report.browserCrawl!.networkRequests = []; expect(candidate(report)).toMatchObject({ readiness: "SENT_BUT_RESPONSE_UNCONFIRMED", alreadyObservedExchange: true }); });
  it("does not confer same-origin or ownership on cross-origin grouped evidence", () => {
    const report = one(); for (const item of [report.requestAudit[0]!, report.responses[0]!]) { item.requestedUrl = "https://other.test/health"; item.finalUrl = item.requestedUrl; }
    const value = candidate(report); expect(value).toMatchObject({ targetOrigin: ng2Origin, originRelation: "OTHER_ORIGIN", readiness: "UNKNOWN_OR_CROSS_ORIGIN", nextStep: "NO_PROBE_PROPOSAL", alreadyObservedExchange: true });
  });
  it.each(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT", "weird"])("never auto-probes or infers read-only for %s", (method) => {
    const report = mappingOnly(); report.apiMapper!.endpoints = [{ ...report.apiMapper!.endpoints[0]!, method }]; const value = candidate(report);
    expect(value).toMatchObject({ executable: false, executionAuthority: "NONE", approval: "NOT_GRANTED", credentialsResolved: false, authorizationDecision: "UNKNOWN", vulnerabilityConclusion: "NOT_ASSESSED", cleanup: "NOT_ASSESSED", status: "REQUIRES_OPERATOR_REVIEW" });
    expect(value.method).toBe(method === "weird" ? "UNKNOWN" : method); expect(value).not.toHaveProperty("request"); expect(value).not.toHaveProperty("readOnly");
  });
  it("keeps different methods and origins on the same pathname separate", () => {
    const report = mappingOnly(); const endpoint = report.apiMapper!.endpoints[0]!; report.apiMapper!.endpoints = [endpoint, { ...endpoint, method: "POST" }, { ...endpoint, endpoint: endpoint.endpoint.replace("app.test", "other.test") }];
    const values = planAdaptiveDiscoveryCandidates(report).candidates; expect(values).toHaveLength(3); expect(new Set(values.map((value) => value.routeOrdinal)).size).toBe(3); expect(new Set(values.map((value) => value.candidateId)).size).toBe(3);
  });
  it.each(observedInputSkippedOutcomeSchema.options)("does not override broker %s with a favorable discovery", (outcome) => {
    const report = one(); report.requestAudit[0]!.outcome = outcome; expect(candidate(report)).toMatchObject({ readiness: "BLOCKED_OR_CONTRADICTORY", nextStep: "RESOLVE_CONTRADICTION" });
  });
  it("keeps source-order ledger independent of deterministic triage sorting", () => {
    const result = planAdaptiveDiscoveryCandidates(corpus()); expect(result.candidates).toEqual([...result.candidates].sort(compareDiscoveryCandidates)); expect(result.candidates[0]!.triageRank).toBe(0);
    expect(result.accountingLedger.map((value) => value.observationIndex)).toEqual(Array.from({ length: 18 }, (_, index) => index));
    const discovered = result.candidates.filter((value) => value.readiness === "DISCOVERED_NOT_CONFIRMED_TRANSMITTED"); expect(discovered.map((value) => value.candidateId)).toEqual(discovered.map((value) => value.candidateId).sort(discoveryBinaryCompare));
  });
  it("retains duplicate source entries without duplicate suppression", () => {
    const report = mappingOnly(); const entry = report.apiMapper!.endpoints[0]!; report.apiMapper!.endpoints = [entry, structuredClone(entry)];
    const value = candidate(report); expect(value.sourceReferences.map((ref) => ref.sourceIndex)).toEqual([0, 1]); expect(value.evidenceSummary.API_DISCOVERY_CANDIDATE).toBe(2);
  });
  it("keeps first-appearance ordinals report-local and intentionally order dependent", () => {
    const report = mappingOnly(); const values = planAdaptiveDiscoveryCandidates(report).candidates; report.apiMapper!.endpoints.reverse(); expect(planAdaptiveDiscoveryCandidates(report).candidates).not.toEqual(values);
    expect(discoveryCandidateIdentityPreimage(idInput(values[0]!))).not.toContain("/api/");
  });
  it("preserves candidate IDs for coherent private queries and degrades incoherent pairing", () => {
    const report = one(); const before = candidate(report); const privateUrl = report.requestAudit[0]!.requestedUrl + "?token=private-one#private-fragment";
    for (const item of [report.requestAudit[0]!, report.responses[0]!]) { item.requestedUrl = privateUrl; item.finalUrl = privateUrl; }
    expect(candidate(report)).toEqual(before); report.responses[0]!.requestedUrl = privateUrl.replace("private-one", "private-two"); report.responses[0]!.finalUrl = report.responses[0]!.requestedUrl;
    expect(candidate(report).candidateId).toBe(before.candidateId); expect(candidate(report).readiness).toBe("SENT_BUT_RESPONSE_UNCONFIRMED");
  });
  it("excludes raw route, query, request, credential, object and metadata canaries everywhere", () => {
    const report = corpus(); const secrets = ["tiny43", "reset-secret-token", "signed-private-link", "private-query", "request-secret-id", "Bearer-private-JWT", "private-cookie", "private-body-hash", "profile-private", "tenant-private", "browser-private", "free-private-error"];
    const privateUrl = `${ng2Origin}/reset/tiny43/reset-secret-token?token=private-query#signed-private-link`;
    const audit = report.requestAudit[0]!; const response = report.responses[0]!; for (const item of [audit, response]) { item.requestedUrl = privateUrl; item.finalUrl = privateUrl; item.requestId = "request-secret-id"; }
    audit.requestHeaders = { authorization: "Bearer-private-JWT", cookie: "private-cookie" }; audit.requestBodyHash = "private-body-hash"; response.headers = { "set-cookie": "private-cookie" }; response.bodyPreview = "tenant-private"; response.bodyHash = "private-body-hash";
    report.browserCrawl!.notes = ["browser-private"]; (report as unknown as Record<string, unknown>).profileId = "profile-private"; report.requestAudit[5]!.scopeReason = "free-private-error";
    const result = planAdaptiveDiscoveryCandidates(report); const serialized = JSON.stringify(result) + result.candidates.map((value) => discoveryCandidateIdentityPreimage(idInput(value))).join(""); for (const secret of secrets) expect(serialized).not.toContain(secret); expect(result.candidates.some((value) => value.alreadyObservedExchange)).toBe(true);
  });
  it("has strict binary-sorted identity preimages and ignores property insertion order", () => {
    const input = idInput(candidate()); const text = discoveryCandidateIdentityPreimage(input); const parsed = JSON.parse(text); expect(Object.keys(parsed)).toEqual(Object.keys(parsed).sort(discoveryBinaryCompare)); expect(parsed.purpose).toBe("routecairn-discovery-candidate-v1");
    expect(discoveryCandidateIdentityPreimage(Object.fromEntries(Object.entries(input).reverse()) as typeof input)).toBe(text);
    expect(() => discoveryCandidateIdentityPreimage({ ...input, path: "/private" } as typeof input)).toThrow("INVALID_DISCOVERY_CANDIDATE_IDENTITY");
  });
  it.each(["schemaVersion", "executable", "approval", "status", "candidateId", "targetOrigin", "request", "rationale", "requirements", "triageRank", "evidenceSummary", "sourceReferences"])("rejects forged %s", (field) => {
    const value: Record<string, unknown> = structuredClone(candidate());
    value[field] = field === "schemaVersion" ? 2 : field === "executable" ? true : field === "triageRank" ? 0 : field === "requirements" || field === "rationale" ? [] : field === "sourceReferences" ? [] : field === "evidenceSummary" ? {} : "private-forged";
    expect(parseAdaptiveDiscoveryCandidate(value)).toBeUndefined();
  });
  it("rejects duplicate references, forged producer grade, bad order and inconsistent summary", () => {
    const value = candidate(corpus());
    expect(parseAdaptiveDiscoveryCandidate({ ...value, sourceReferences: [...value.sourceReferences, value.sourceReferences[0]] })).toBeUndefined();
    expect(parseAdaptiveDiscoveryCandidate({ ...value, sourceReferences: [...value.sourceReferences].reverse() })).toBeUndefined();
    expect(parseAdaptiveDiscoveryCandidate({ ...value, evidenceSummary: { ...value.evidenceSummary, BROKER_SENT_EXACT_PAIR: 2 } })).toBeUndefined();
    const forged = structuredClone(value); forged.sourceReferences[0]!.producer = "API_MAPPER"; expect(parseAdaptiveDiscoveryCandidate(forged)).toBeUndefined();
  });
  it("rejects internally valid swapped evidence members against the real report", () => {
    const report = one(); const value = candidate(report); const forged = structuredClone(value); forged.sourceReferences[0]!.observationId = "b".repeat(64);
    expect(discoveryCandidateV1Schema.safeParse(forged).success).toBe(true); expect(validateAdaptiveDiscoveryCandidate(forged, report)).toBe(false);
    forged.sourceReferences[0]!.sourceIndex = 1; expect(validateAdaptiveDiscoveryCandidate(forged, report)).toBe(false);
  });
  it("rejects internally valid forged grade and wrong-origin candidates through context", () => {
    const report = one(); const exact = candidate(report); const altered = one(); altered.responses = []; const unpaired = candidate(altered);
    expect(unpaired.candidateId).toBe(exact.candidateId); expect(discoveryCandidateV1Schema.safeParse(unpaired).success).toBe(true); expect(validateAdaptiveDiscoveryCandidate(unpaired, report)).toBe(false);
    const wrong = { ...idInput(exact), targetOrigin: "https://other.test" }; const forged = { ...exact, ...wrong, candidateId: discoveryCandidateId(wrong) }; expect(discoveryCandidateV1Schema.safeParse(forged).success).toBe(true); expect(validateAdaptiveDiscoveryCandidate(forged, report)).toBe(false);
    expect(validateAdaptiveDiscoveryCandidate({ ...exact, nextStep: "REVIEW_FOR_POTENTIAL_PROBE" }, report)).toBe(false); expect(validateAdaptiveDiscoveryCandidate({ ...exact, requirements: [] }, report)).toBe(false);
  });
  it("accepts full original candidate equality from the same report", () => { const report = corpus(); for (const value of planAdaptiveDiscoveryCandidates(report).candidates) expect(validateAdaptiveDiscoveryCandidate(value, report)).toBe(true); });
  it("fails an overflowing group atomically with all 65 observations explicitly omitted", () => {
    const report = mappingOnly(); const entry = report.apiMapper!.endpoints[0]!; report.apiMapper!.endpoints = Array.from({ length: 65 }, () => structuredClone(entry)); const result = planAdaptiveDiscoveryCandidates(report);
    expect(result.candidates).toEqual([]); expect(result.accountedObservations).toBe(65); expect(result.diagnostics).toHaveLength(65); expect(result.accountingLedger).toHaveLength(65);
    for (const row of result.accountingLedger) expect(row).toMatchObject({ state: "OMITTED", code: "SOURCE_REFERENCE_LIMIT" });
  });
  it("preserves an independent group while rejecting all members of an overflowing group", () => {
    const report = mappingOnly(); const [first, second] = report.apiMapper!.endpoints; report.apiMapper!.endpoints = [...Array.from({ length: 65 }, () => structuredClone(first!)), second!]; const result = planAdaptiveDiscoveryCandidates(report);
    expect(result.candidates).toHaveLength(1); expect(result.accountingLedger[65]).toMatchObject({ state: "CANDIDATE", sourceIndex: 65 }); expect(result.diagnostics).toHaveLength(65);
  });
  it("accepts the exact 64-ref boundary without lost memberships", () => {
    const report = mappingOnly(); const entry = report.apiMapper!.endpoints[0]!; report.apiMapper!.endpoints = Array.from({ length: 64 }, () => structuredClone(entry)); expect(candidate(report).sourceReferences).toHaveLength(64);
  });
  it("handles 2000 distinct source-built mapper records and bounded grouping", () => {
    const report = mappingOnly(); const entry = report.apiMapper!.endpoints[0]!; report.apiMapper!.endpoints = Array.from({ length: 2000 }, (_, index) => ({ ...entry, endpoint: `${ng2Origin}/fixture/${index}` })); const result = planAdaptiveDiscoveryCandidates(report);
    expect(result.accountedObservations).toBe(2000); expect(result.candidates).toHaveLength(2000); expect(result.accountingLedger).toHaveLength(2000); expect(result.diagnostics).toEqual([]);
  });
  it("handles 2000 duplicates without silently keeping the best or first 64", () => {
    const report = mappingOnly(); const entry = report.apiMapper!.endpoints[0]!; report.apiMapper!.endpoints = Array.from({ length: 2000 }, () => structuredClone(entry)); const result = planAdaptiveDiscoveryCandidates(report); expect(result.candidates).toEqual([]); expect(result.accountingLedger).toHaveLength(2000); expect(result.diagnostics).toHaveLength(2000);
  });
  it("retains an upstream batch budget failure instead of an empty success", () => {
    const report = mappingOnly(); report.apiMapper!.endpoints = new Array(2001); const result = planAdaptiveDiscoveryCandidates(report); expect(result.candidates).toEqual([]); expect(result.upstreamDiagnostics).toEqual([{ code: "INPUT_LIMIT" }]); expect(result.diagnostics).toEqual([{ code: "UPSTREAM_FAILED" }]);
  });
  it("preserves original upstream sparse and invalid indexes separately from its observation ledger", () => {
    const report = corpus(); delete report.apiMapper!.endpoints[1]; const result = planAdaptiveDiscoveryCandidates(report); expect(result.upstreamDiagnostics).toEqual([{ producer: "API_MAPPER", sourceIndex: 1, code: "INVALID_RECORD" }]); expect(result.accountedObservations).toBe(17); expect(result.accountingLedger).toHaveLength(17); expect(result.candidates.every((value) => value.upstreamEvidenceIncomplete)).toBe(true);
  });
  it.each(["cycle", "accessor", "proxy", "function", "non-JSON"])("fails poisoned %s safely through NG4 first", (kind) => {
    let report = one(); const raw = report as unknown as Record<string, unknown>;
    if (kind === "cycle") raw.private = raw; if (kind === "function") raw.private = () => "private"; if (kind === "non-JSON") raw.private = new Date();
    if (kind === "accessor") Object.defineProperty(raw, "private", { get() { throw new Error("private-getter"); }, enumerable: true });
    if (kind === "proxy") report = new Proxy(report, { get() { throw new Error("private-proxy"); } });
    const result = planAdaptiveDiscoveryCandidates(report); expect(result.candidates).toEqual([]); expect(result.diagnostics).toEqual([{ code: "UPSTREAM_FAILED" }]); expect(result.upstreamDiagnostics).toEqual([{ code: "INVALID_INPUT" }]); expect(JSON.stringify(result)).not.toContain("private");
  });
  it("rejects poisoned candidate input without invoking getters or echoing parser errors", () => {
    const value = candidate(); Object.defineProperty(value, "private", { get() { throw new Error("private-parser"); }, enumerable: true }); expect(parseAdaptiveDiscoveryCandidate(value)).toBeUndefined(); expect(validateAdaptiveDiscoveryCandidate(value, one())).toBe(false);
    expect(parseAdaptiveDiscoveryCandidate({ ...candidate(), requirements: new Array(2001) })).toBeUndefined(); const cyclic: Record<string, unknown> = {}; cyclic.self = cyclic; expect(parseAdaptiveDiscoveryCandidate(cyclic)).toBeUndefined();
  });
  it("fails unknown future audit/browser outcomes closed", () => {
    const report = one(); report.requestAudit[0]!.outcome = "future" as never; const result = planAdaptiveDiscoveryCandidates(report); expect(result.candidates).toEqual([]); expect(result.upstreamDiagnostics[0]).toMatchObject({ code: "UNKNOWN_OUTCOME", sourceIndex: 0 });
    const browser = browserOnly(); browser.browserCrawl!.networkRequests[0]!.decision = "future" as never; expect(planAdaptiveDiscoveryCandidates(browser).candidates).toEqual([]);
  });
  it("does not invent discovery or scan completion for an empty report", () => { const report = one(); report.requestAudit = []; report.responses = []; const result = planAdaptiveDiscoveryCandidates(report); expect(result.candidates).toEqual([]); expect(result.accountedObservations).toBe(0); expect(result.accountingLedger).toEqual([]); });
  it.each(["FAILED", "INTERRUPTED", "RUNNING", "CANCELLED"] as const)("preserves %s completeness uncertainty", (status) => {
    const report = corpus(); report.execution!.status = status; for (const value of planAdaptiveDiscoveryCandidates(report).candidates) { expect(value.reportCompleteness).toBe("INCOMPLETE_OR_UNKNOWN"); expect(value.requirements).toContain("CONFIRM_REPORT_COMPLETENESS"); }
  });
  it("keeps absent and partial execution incomplete", () => { expect(candidate().reportCompleteness).toBe("INCOMPLETE_OR_UNKNOWN"); const report = corpus(); report.execution!.partial = true; expect(candidate(report).reportCompleteness).toBe("INCOMPLETE_OR_UNKNOWN"); });
  it("does not mutate inputs or rely on DB IDs/times/profiles", () => { const report = corpus(); const original = structuredClone(report); const result = planAdaptiveDiscoveryCandidates(report); expect(report).toEqual(original); expect(planAdaptiveDiscoveryCandidates(structuredClone(report))).toEqual(result); report.metadata.startedAt = "2050-private-time"; (report as unknown as Record<string, unknown>).databaseId = "private-profile"; expect(planAdaptiveDiscoveryCandidates(report)).toEqual(result); });
  it("has no clock, random or global fetch path", () => { const report = corpus(); const forbidden = () => { throw new Error("forbidden"); }; vi.spyOn(Date, "now").mockImplementation(forbidden); vi.spyOn(Math, "random").mockImplementation(forbidden); vi.spyOn(globalThis, "fetch").mockImplementation(forbidden); expect(planAdaptiveDiscoveryCandidates(report).candidates).toHaveLength(8); expect(validateAdaptiveDiscoveryCandidate(candidate(report), report)).toBe(true); });
  it("has fixed diagnostics with strict complete indexed bindings", () => { expect(discoveryPlannerDiagnosticSchema.safeParse({ code: "UPSTREAM_FAILED", rawUrl: "private" }).success).toBe(false); expect(discoveryPlannerDiagnosticSchema.safeParse({ code: "INVALID_CANDIDATE", observationIndex: 0 }).success).toBe(false); });
  it("locks the first production-assembled NG5A full-plan golden", () => {
    // ng2Report source-built 18-event NG4 corpus, full plan including sorted candidates + original-order ledger.
    // HEAD 705b4592ae5e73f602d1ed955ca675fe19863961. Ordinals/indices intentionally remain report-local and order-sensitive.
    expect(digest(planAdaptiveDiscoveryCandidates(corpus()))).toBe("9451efb5110a0efeb542377f14979a8cc39d26b3e11a1558c4aef9c47058dd2f");
  });
});
