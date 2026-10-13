import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { HttpResponse, RequestAuditEntry } from "../../src/core/http/HttpTypes.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { adaptiveObservedInputV1Schema, observedInputDiagnosticSchema, observedInputId, observedInputIdentityPreimage, observedInputSkippedOutcomeSchema, type AdaptiveObservedInputV1, type ObservedInputIdentity } from "../../src/dashboard/execution/AdaptiveObservedInputIR.js";
import { projectAdaptiveObservedInputs, validateAdaptiveObservedInput } from "../../src/dashboard/execution/AdaptiveObservedInputProjection.js";
import { ng2Origin, ng2Report } from "../helpers/adaptive-ng2-fixture.js";

function fixture(): RouteCairnReport { return structuredClone(ng2Report()); }
function one(): RouteCairnReport { const report = fixture(); report.requestAudit = [report.requestAudit[0]!]; report.responses = [report.responses[0]!]; report.apiMapper = undefined; report.browserCrawl = undefined; return report; }
/** Cloned genuine planner fixture exchanges only; no server, transmission or credential lookup. */
function corpus(): RouteCairnReport {
  const report = fixture();
  report.requestAudit.forEach((audit, index) => { audit.requestId = `ng4-private-request-${index}`; report.responses[index]!.requestId = audit.requestId; });
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
function identity(value: AdaptiveObservedInputV1): ObservedInputIdentity { const { observationId: _id, ...rest } = value; return rest; }
function first(report = one()): AdaptiveObservedInputV1 { return projectAdaptiveObservedInputs(report).observations[0]!; }
function assertUnpaired(report: RouteCairnReport) { expect(first(report).disposition).toBe("BROKER_SENT_UNPAIRED"); expect(first(report)).not.toHaveProperty("statusCode"); }
function digest(value: unknown) { return createHash("sha256").update(JSON.stringify(value), "utf8").digest("hex"); }
afterEach(() => vi.restoreAllMocks());

describe("RC-NG4 offline observed-input IR", () => {
  it("correlates the genuine unique legacy response without disclosing a route", () => {
    const report = one(); const value = first(report);
    expect(value).toMatchObject({ producer: "BROKER_AUDIT", disposition: "BROKER_SENT_EXACT_PAIR", targetOrigin: ng2Origin, sourceIndex: 0, routeOrdinal: 0, statusCode: 200, responseError: false });
    expect(adaptiveObservedInputV1Schema.safeParse(value).success).toBe(true);
    expect(validateAdaptiveObservedInput(value, report)).toBe(true);
    expect(observedInputIdentityPreimage(identity(value))).not.toContain("/api/public-profile");
  });
  it("uses unique modern IDs even with duplicate route identities", () => {
    const report = one(); report.requestAudit[0]!.requestId = "a"; report.responses[0]!.requestId = "a";
    report.requestAudit.push({ ...report.requestAudit[0]!, requestId: "b" }); report.responses.push({ ...report.responses[0]!, requestId: "b" });
    expect(projectAdaptiveObservedInputs(report).observations.map((value) => value.disposition)).toEqual(["BROKER_SENT_EXACT_PAIR", "BROKER_SENT_EXACT_PAIR"]);
  });
  it.each(["audit identity", "response identity", "audit ID", "response ID"])("rejects duplicate %s pairing", (variant) => {
    const report = one();
    if (variant.includes("ID")) { report.requestAudit[0]!.requestId = "duplicate"; report.responses[0]!.requestId = "duplicate"; }
    if (variant.startsWith("audit")) report.requestAudit.push(structuredClone(report.requestAudit[0]!)); else report.responses.push(structuredClone(report.responses[0]!));
    assertUnpaired(report);
  });
  it.each(["status", "method", "audit final URL", "response final URL", "response redirect", "audit redirect", "response error", "audit error", "absent status", "modern versus legacy"])("keeps %s mismatch unpaired", (variant) => {
    const report = one(); const audit = report.requestAudit[0]!; const response = report.responses[0]!;
    if (variant === "status") response.statusCode = 403;
    if (variant === "method") response.method = "POST";
    if (variant === "audit final URL") audit.finalUrl = `${ng2Origin}/health`;
    if (variant === "response final URL") response.finalUrl = `${ng2Origin}/health`;
    if (variant === "response redirect") response.redirectChain = [{ statusCode: 302, location: "/private-canary" }];
    if (variant === "audit redirect") audit.redirectChain = [{ statusCode: 302, location: "/private-canary" }];
    if (variant === "response error") response.error = { name: "Error", message: "private error" };
    if (variant === "audit error") audit.error = "private error";
    if (variant === "absent status") audit.statusCode = undefined;
    if (variant === "modern versus legacy") response.requestId = "only-response-has-id";
    assertUnpaired(report);
  });
  it("never promotes an audit status without a response", () => { const report = one(); report.responses = []; assertUnpaired(report); expect(first(report)).toHaveProperty("auditReportedStatus", 200); });
  it.each(observedInputSkippedOutcomeSchema.options)("preserves %s as non-sent metadata", (outcome) => {
    const report = one(); report.requestAudit[0]!.outcome = outcome;
    expect(first(report)).toMatchObject({ disposition: "BROKER_SKIPPED_OR_BLOCKED", auditOutcome: outcome });
    expect(first(report)).not.toHaveProperty("statusCode");
  });
  it.each([
    ["allowed", undefined, "BROWSER_REPORTED_UNKNOWN"], ["allowed", false, "BROWSER_REPORTED_UNKNOWN"], ["allowed", true, "BROWSER_REPORTED_TRANSMITTED"],
    ["blocked", false, "BROWSER_REPORTED_BLOCKED"], ["blocked", undefined, "BROWSER_REPORTED_BLOCKED"], [undefined, undefined, "BROWSER_REPORTED_UNKNOWN"], [undefined, true, "BROWSER_REPORTED_TRANSMITTED"]
  ] as const)("keeps browser decision=%s and transmission=%s separate", (decision, transmitted, disposition) => {
    const report = fixture(); report.requestAudit = []; report.responses = []; report.apiMapper = undefined;
    report.browserCrawl!.networkRequests = [{ url: `${ng2Origin}/health`, method: "GET", resourceType: "fetch", ...(decision === undefined ? {} : { decision }), ...(transmitted === undefined ? {} : { transmitted }) }];
    expect(first(report)).toMatchObject({ producer: "BROWSER_NETWORK", disposition }); expect(first(report)).not.toHaveProperty("statusCode");
  });
  it("diagnoses contradictory browser evidence without guessing", () => {
    const report = corpus(); report.browserCrawl!.networkRequests[0]!.decision = "blocked";
    expect(projectAdaptiveObservedInputs(report).diagnostics).toEqual([{ producer: "BROWSER_NETWORK", sourceIndex: 0, code: "CONTRADICTORY_BROWSER" }]);
  });
  it("retains a discovery candidate separately from broker and browser records", () => {
    const values = projectAdaptiveObservedInputs(corpus()).observations;
    expect(values).toHaveLength(18); expect(new Set(values.map((value) => value.observationId)).size).toBe(18);
    for (const value of values.filter((item) => item.producer === "API_MAPPER")) { expect(value.disposition).toBe("API_DISCOVERY_CANDIDATE"); expect(value).not.toHaveProperty("statusCode"); }
    expect(values[0]!.routeOrdinal).toBe(values[6]!.routeOrdinal); expect(values[0]!.routeOrdinal).toBe(values[9]!.routeOrdinal);
  });
  it("preserves primary origin for cross-origin metadata and relative URLs", () => {
    const report = one(); report.requestAudit[0]!.requestedUrl = "https://other.test/health"; report.requestAudit[0]!.finalUrl = undefined; report.responses = [];
    expect(first(report)).toMatchObject({ targetOrigin: ng2Origin, originRelation: "OTHER_ORIGIN" });
    report.requestAudit[0]!.requestedUrl = "/health"; expect(first(report).originRelation).toBe("PRIMARY_TARGET");
  });
  it.each(["ftp://private.test/x", "https://private:user@app.test/x", "http://[", "", "x".repeat(8193)])("rejects invalid or oversized URL", (value) => {
    const report = one(); report.requestAudit[0]!.requestedUrl = value;
    expect(projectAdaptiveObservedInputs(report).observations).toEqual([]); expect(projectAdaptiveObservedInputs(report).diagnostics).toEqual([{ producer: "BROKER_AUDIT", sourceIndex: 0, code: "INVALID_URL" }]);
  });
  it.each(["ftp://app.test", "https://user:pass@app.test", "", "x".repeat(8193)])("rejects invalid primary target", (target) => {
    const report = one(); report.target = target; expect(projectAdaptiveObservedInputs(report).diagnostics).toEqual([{ code: "INVALID_TARGET" }]);
  });
  it.each(["GET", "POST"])("never infers safety or authorization for %s", (method) => {
    const report = one(); report.requestAudit[0]!.method = method; report.responses[0]!.method = method as HttpResponse["method"];
    expect(first(report)).toMatchObject({ executable: false, executionAuthority: "NONE", operatorApproval: "NOT_GRANTED", actorAttribution: "UNKNOWN", vulnerabilityConclusion: "NOT_ASSESSED", authorizationDecision: "UNKNOWN", cleanup: "NOT_ASSESSED", credentialsResolved: false });
    expect(first(report)).not.toHaveProperty("protocol"); expect(first(report)).not.toHaveProperty("readOnly");
  });
  it("retains truncated response correlation without complete-body proof", () => {
    const report = one(); report.responses[0]!.streamTruncated = true;
    expect(first(report)).toMatchObject({ disposition: "BROKER_SENT_EXACT_PAIR", responseTruncated: true });
    expect(first(report)).not.toHaveProperty("bodyComplete");
  });
  it("does not invent absent truncation flags", () => { expect(first()).not.toHaveProperty("responseTruncated"); });
  it("removes every private canary from observations, diagnostics and identity preimages", () => {
    const report = corpus(); const secrets = ["secret-query-value", "tiny42", "reset-private-token", "Bearer-private-jwt", "request-private-id", "Cookie-private-session", "payment-private-link", "browser-private-storage", "private-body-hash", "private-error-detail"];
    const audit = report.requestAudit[0]!; const response = report.responses[0]!;
    const privateUrl = `${ng2Origin}/reset/tiny42?token=reset-private-token&value=secret-query-value#payment-private-link`;
    audit.requestedUrl = privateUrl; audit.finalUrl = privateUrl; response.requestedUrl = privateUrl; response.finalUrl = privateUrl;
    audit.requestId = "request-private-id"; response.requestId = audit.requestId; audit.requestHeaders = { authorization: "Bearer-private-jwt", cookie: "Cookie-private-session" }; audit.requestBodyHash = "private-body-hash";
    response.bodyPreview = "Bearer-private-jwt"; response.bodyHash = "private-body-hash"; response.headers = { "set-cookie": "Cookie-private-session" };
    report.browserCrawl!.notes = ["browser-private-storage"]; report.requestAudit[5]!.scopeReason = "private-error-detail";
    const projected = projectAdaptiveObservedInputs(report); const publicData = JSON.stringify(projected) + projected.observations.map((value) => observedInputIdentityPreimage(identity(value))).join("");
    for (const secret of secrets) expect(publicData).not.toContain(secret);
    expect(projected.observations[0]!.disposition).toBe("BROKER_SENT_EXACT_PAIR");
  });
  it("preserves public identity when query values and fragments change coherently", () => {
    const report = one(); const before = first(report);
    const privateUrl = `${ng2Origin}/api/public-profile?token=private-query-1#private-fragment`;
    report.requestAudit[0]!.requestedUrl = privateUrl; report.requestAudit[0]!.finalUrl = privateUrl; report.responses[0]!.requestedUrl = privateUrl; report.responses[0]!.finalUrl = privateUrl;
    expect(first(report)).toEqual(before);
    for (const item of [report.requestAudit[0]!, report.responses[0]!]) { item.requestedUrl = item.requestedUrl.replace("private-query-1", "private-query-2"); item.finalUrl = item.requestedUrl; }
    expect(first(report)).toEqual(before);
  });
  it("retains original query equality exclusively inside exact pairing", () => {
    const report = one(); report.requestAudit[0]!.requestedUrl += "?token=private-a"; report.requestAudit[0]!.finalUrl = report.requestAudit[0]!.requestedUrl;
    report.responses[0]!.requestedUrl += "?token=private-b"; report.responses[0]!.finalUrl = report.responses[0]!.requestedUrl; assertUnpaired(report);
  });
  it("uses first appearance route ordinals without raw route fingerprints", () => {
    const report = one(); report.responses = []; report.requestAudit.push({ ...report.requestAudit[0]!, requestedUrl: `${ng2Origin}/short43`, finalUrl: undefined }, { ...report.requestAudit[0]!, requestedUrl: `${ng2Origin}/api/public-profile?secret=value`, finalUrl: undefined });
    expect(projectAdaptiveObservedInputs(report).observations.map((value) => value.routeOrdinal)).toEqual([0, 1, 0]);
    const before = first(report); report.requestAudit[0]!.requestedUrl = `${ng2Origin}/tiny44`; report.requestAudit[0]!.finalUrl = undefined;
    expect(first(report)).toEqual(before); // Opaque ordinal is local; context matching, not a raw-path hash.
  });
  it("preserves duplicates, input order and distinct local indices", () => {
    const report = one(); report.responses = []; report.requestAudit.push(structuredClone(report.requestAudit[0]!));
    const values = projectAdaptiveObservedInputs(report).observations; expect(values.map((value) => value.sourceIndex)).toEqual([0, 1]); expect(values[0]!.observationId).not.toBe(values[1]!.observationId);
    expect(values.map((value) => value.routeOrdinal)).toEqual([0, 0]);
    const ordered = corpus(); const original = projectAdaptiveObservedInputs(ordered); ordered.requestAudit.reverse(); expect(projectAdaptiveObservedInputs(ordered)).not.toEqual(original);
  });
  it("is deterministic and does not mutate sources", () => { const report = corpus(); const clone = structuredClone(report); expect(projectAdaptiveObservedInputs(report)).toEqual(projectAdaptiveObservedInputs(clone)); expect(report).toEqual(clone); });
  it("ignores DB IDs, timestamps and profile metadata", () => {
    const report = corpus(); const before = projectAdaptiveObservedInputs(report);
    report.metadata.startedAt = "2050-01-01"; report.metadata.completedAt = "2051-01-01"; (report as unknown as Record<string, unknown>).databaseId = "saved-profile-private-id";
    (report as unknown as Record<string, unknown>).profileId = "saved-profile-other-private-id"; report.execution!.checkpointAt = "2040-01-01";
    expect(projectAdaptiveObservedInputs(report)).toEqual(before);
  });
  it.each(["RUNNING", "FAILED", "CANCELLED", "INTERRUPTED", "FUTURE"])("keeps %s execution incomplete", (status) => {
    const report = corpus(); report.execution!.status = status as NonNullable<RouteCairnReport["execution"]>["status"]; expect(first(report).reportCompleteness).toBe("INCOMPLETE_OR_UNKNOWN");
  });
  it("distinguishes completed, partial and absent execution without changing correlation", () => {
    const report = corpus(); expect(first(report).reportCompleteness).toBe("COMPLETED_REPORTED"); report.execution!.partial = true; expect(first(report).reportCompleteness).toBe("INCOMPLETE_OR_UNKNOWN"); report.execution = undefined;
    expect(first(report)).toMatchObject({ reportCompleteness: "INCOMPLETE_OR_UNKNOWN", disposition: "BROKER_SENT_EXACT_PAIR" });
  });
  it.each([null, {}, [], "private-input", { target: ng2Origin, requestAudit: {}, responses: [] }])("fails malformed report safely", (input) => {
    expect(projectAdaptiveObservedInputs(input as RouteCairnReport).diagnostics).toEqual([{ code: "INVALID_INPUT" }]);
  });
  it("accounts for sparse broker/browser/mapper slots by original index", () => {
    const report = corpus(); delete report.requestAudit[1]; delete report.browserCrawl!.networkRequests[1]; delete report.apiMapper!.endpoints[1];
    const result = projectAdaptiveObservedInputs(report); expect(result.observations.length + result.diagnostics.length).toBe(18);
    expect(result.diagnostics).toEqual(["BROKER_AUDIT", "BROWSER_NETWORK", "API_MAPPER"].map((producer) => ({ producer, sourceIndex: 1, code: "INVALID_RECORD" })));
    expect(result.observations.find((value) => value.producer === "BROKER_AUDIT" && value.sourceIndex === 0)!.disposition).toBe("BROKER_SENT_UNPAIRED");
  });
  it("does not manufacture legacy uniqueness by dropping malformed auxiliary responses", () => {
    const report = one(); report.responses.push({ ...report.responses[0]!, method: null as unknown as HttpResponse["method"] }); assertUnpaired(report);
  });
  it("fails total input budget atomically, including auxiliary responses", () => {
    const report = one(); report.requestAudit = Array.from({ length: 2000 }, () => structuredClone(report.requestAudit[0]!));
    expect(projectAdaptiveObservedInputs(report)).toMatchObject({ observations: [], diagnostics: [{ code: "INPUT_LIMIT" }], sourceCounts: { brokerAudit: 2000, responses: 1 } });
  });
  it("accepts exactly the 2000-record boundary without clipping", () => {
    const report = one(); const audit = report.requestAudit[0]!; report.responses = []; report.requestAudit = Array.from({ length: 2000 }, () => structuredClone(audit));
    const result = projectAdaptiveObservedInputs(report); expect(result.observations).toHaveLength(2000); expect(result.diagnostics).toEqual([]);
  });
  it.each(["cycle", "depth", "keys", "array", "string", "accessor", "toJSON"])("rejects hostile %s without serialization", (kind) => {
    const report = one() as unknown as Record<string, unknown>;
    if (kind === "cycle") report.private = report;
    if (kind === "depth") { let cursor = report; for (let index = 0; index < 40; index++) { const next = {}; cursor.private = next; cursor = next; } }
    if (kind === "keys") report.private = Object.fromEntries(Array.from({ length: 129 }, (_, index) => [`private${index}`, true]));
    if (kind === "array") report.private = new Array(2001);
    if (kind === "string") report.private = "secret".repeat(50_000);
    if (kind === "accessor") Object.defineProperty(report, "private", { get: () => { throw new Error("private getter invoked"); }, enumerable: true });
    if (kind === "toJSON") report.toJSON = () => { throw new Error("private serialization invoked"); };
    const result = projectAdaptiveObservedInputs(report as unknown as RouteCairnReport); expect(result.observations).toEqual([]); expect(result.diagnostics[0]!.code).toMatch(/^(INVALID_INPUT|INPUT_LIMIT)$/); expect(JSON.stringify(result)).not.toContain("private");
  });
  it("catches hostile proxy reads without exposing exception text", () => {
    const report = new Proxy(one(), { get() { throw new Error("private-proxy-canary"); } });
    expect(projectAdaptiveObservedInputs(report)).toMatchObject({ observations: [], diagnostics: [{ code: "INVALID_INPUT" }] });
  });
  it("never falls back from a future outcome to sent", () => {
    const report = one(); report.requestAudit[0]!.outcome = "future-sent" as RequestAuditEntry["outcome"]; expect(projectAdaptiveObservedInputs(report).diagnostics).toEqual([{ producer: "BROKER_AUDIT", sourceIndex: 0, code: "UNKNOWN_OUTCOME" }]);
  });
  it.each(["", "G ET", "get\n", "ZZZ"])("never defaults malformed method %s to GET or exact", (method) => {
    const report = one(); report.requestAudit[0]!.method = method; report.responses[0]!.method = method as HttpResponse["method"];
    expect(first(report)).toMatchObject({ method: "UNKNOWN", disposition: "BROKER_SENT_UNPAIRED" });
  });
  it("normalizes known method casing without changing semantics", () => { const report = one(); report.requestAudit[0]!.method = "get"; expect(first(report)).toMatchObject({ method: "GET", disposition: "BROKER_SENT_EXACT_PAIR" }); });
  it.each(["executable", "operatorApproval", "statusCode", "observationId", "rawUrl", "routeOrdinal", "producer"])("rejects forged schema field %s", (field) => {
    const value: Record<string, unknown> = { ...first() };
    value[field] = field === "executable" ? true : field === "operatorApproval" ? "GRANTED" : field === "statusCode" ? 201 : field === "routeOrdinal" ? -1 : "private-forged";
    expect(adaptiveObservedInputV1Schema.safeParse(value).success).toBe(false);
  });
  it("rejects response status on browser or mapper and inconsistent disposition fields", () => {
    const values = projectAdaptiveObservedInputs(corpus()).observations;
    for (const value of values.filter((item) => item.producer !== "BROKER_AUDIT")) expect(adaptiveObservedInputV1Schema.safeParse({ ...value, statusCode: 200 }).success).toBe(false);
    expect(adaptiveObservedInputV1Schema.safeParse({ ...first(), disposition: "BROKER_SENT_UNPAIRED" }).success).toBe(false);
  });
  it("validates sorted strict preimages, rejects unsupported duplicate inputs and unsafe origins", () => {
    const value = identity(first()); const preimage = observedInputIdentityPreimage(value);
    const keys = Object.keys(JSON.parse(preimage)); expect(keys).toEqual([...keys].sort()); expect(JSON.parse(preimage).purpose).toBe("routecairn-observed-input-v1");
    const reverse = Object.fromEntries(Object.entries(value).reverse()); expect(observedInputIdentityPreimage(reverse as ObservedInputIdentity)).toBe(preimage);
    expect(() => observedInputIdentityPreimage({ ...value, extra: "private-canary" } as ObservedInputIdentity)).toThrow("INVALID_OBSERVED_INPUT_IDENTITY");
    expect(() => observedInputIdentityPreimage([value, value] as unknown as ObservedInputIdentity)).toThrow("INVALID_OBSERVED_INPUT_IDENTITY");
    expect(() => observedInputIdentityPreimage({ ...value, targetOrigin: `${ng2Origin}/private` })).toThrow("INVALID_OBSERVED_INPUT_IDENTITY");
  });
  it("rejects rehashed forged observations against original context", () => {
    const report = one(); const value = first(report); const forged = { ...identity(value), statusCode: 201 } as ObservedInputIdentity; const resigned = { ...forged, observationId: observedInputId(forged) };
    expect(adaptiveObservedInputV1Schema.safeParse(resigned).success).toBe(true); expect(validateAdaptiveObservedInput(resigned, report)).toBe(false);
    const mismatched = one(); mismatched.responses = []; expect(validateAdaptiveObservedInput(value, mismatched)).toBe(false);
    const crossOrigin = one(); crossOrigin.target = "https://other.test"; expect(validateAdaptiveObservedInput(value, crossOrigin)).toBe(false);
  });
  it("validates only matching producer and original source index", () => {
    const report = corpus(); const value = first(report); const forged = { ...identity(value), sourceIndex: 5 };
    expect(validateAdaptiveObservedInput({ ...forged, observationId: observedInputId(forged) }, report)).toBe(false);
  });
  it("keeps diagnostics strict and free of raw parser messages", () => {
    expect(observedInputDiagnosticSchema.safeParse({ code: "INVALID_URL", reason: "private" }).success).toBe(false);
    expect(observedInputDiagnosticSchema.safeParse({ code: "INVALID_RECORD", producer: "BROKER_AUDIT" }).success).toBe(false);
  });
  it("performs no clock, randomness or global network access", () => {
    const report = corpus(); const forbidden = () => { throw new Error("forbidden side effect"); };
    vi.spyOn(Date, "now").mockImplementation(forbidden); vi.spyOn(Math, "random").mockImplementation(forbidden); vi.spyOn(globalThis, "fetch").mockImplementation(forbidden);
    expect(projectAdaptiveObservedInputs(report).observations).toHaveLength(18); expect(validateAdaptiveObservedInput(first(report), report)).toBe(true);
  });
  it("accounts for the entire source-backed corpus by producer and grade", () => {
    const result = projectAdaptiveObservedInputs(corpus()); expect(result.sourceCounts).toEqual({ brokerAudit: 6, browserNetwork: 3, apiMapper: 9, responses: 4 }); expect(result.diagnostics).toEqual([]);
    const counts: Record<string, number> = {}; for (const value of result.observations) counts[value.disposition] = (counts[value.disposition] ?? 0) + 1;
    expect(counts).toEqual({ BROKER_SENT_EXACT_PAIR: 4, BROKER_SENT_UNPAIRED: 1, BROKER_SKIPPED_OR_BLOCKED: 1, BROWSER_REPORTED_TRANSMITTED: 1, BROWSER_REPORTED_BLOCKED: 1, BROWSER_REPORTED_UNKNOWN: 1, API_DISCOVERY_CANDIDATE: 9 });
  });
  it("locks the first production-assembled NG4 corpus golden", () => {
    // ng2Report cloned exchanges, all three producers, full ordered projection; HEAD 616c5872e387bb118649dd3a21abbc4758b91812.
    // New NG4 baseline only. Original producer indices and first-appearance ordinals intentionally affect identity.
    expect(digest(projectAdaptiveObservedInputs(corpus()))).toBe("ecd525b0befe89955cffa22e588d672394c2b499cd4f801bbb2c7aaa96488535");
  });
});
