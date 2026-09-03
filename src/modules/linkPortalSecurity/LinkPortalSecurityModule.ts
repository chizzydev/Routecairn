import { createHash } from "node:crypto";
import { authenticationLifecycleSecrets, authHeadersForProfile, type AuthProfile } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import type { Finding, FindingType } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import type { RequestSafetyBroker } from "../../core/http/RequestSafetyBroker.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import { GlobalMutationLock, MutationJournal } from "../../core/offensive/MutationJournal.js";
import type { MutationJournalStage, MutationOutcome } from "../../core/offensive/ControlledMutationTypes.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { LinkPortalAssertionObservation, LinkPortalCaseObservation, LinkPortalOutcome, LinkPortalSecurityReport, LinkPortalStepObservation } from "../../reports/LinkPortalSecurityReport.js";
import { parseSafeFieldPath, valueAtSafePath } from "../fieldExposureTesting/SafeFieldPath.js";
import { linkPortalSecurityCategories, type LinkPortalActorPlan, type LinkPortalAssertionPlan, type LinkPortalAuthSlot, type LinkPortalResourcePlan, type LinkPortalSecurityCasePlan, type LinkPortalStepPlan } from "./LinkPortalSecurityTypes.js";

interface Snapshot { statusCode?: number; contentType?: string; bodyLength: number; bodyFingerprint: string; shapeFingerprint: string; json?: unknown }

export class LinkPortalSecurityModule implements RouteCairnPlugin {
  public readonly name = "link-portal-export-security";
  public readonly description = "Verifies signed-link, invitation, portal, export, evidence-artifact, and object-path security contracts.";
  public readonly phase = "analysis" as const;
  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await executeLinkPortalSecurity(context);
    return { pluginName: this.name, linkPortalSecurity: report, findings: findingsFromReport(report), notes: report.notes };
  }
}

export async function executeLinkPortalSecurity(context: ScanContext): Promise<LinkPortalSecurityReport> {
  const plan = context.options.plan.linkPortalSecurity;
  if (!plan) return disabledReport();
  const transport = context.createLinkPortalSecurityHttpClient(plan.maxRequests, plan.maxResponseBytes);
  const journal = context.mutations.journal;
  const lock = context.mutations.lock();
  const observations: LinkPortalCaseObservation[] = [];
  const snapshot = (): LinkPortalSecurityReport => {
  const coverage = Object.fromEntries(linkPortalSecurityCategories.map((category) => {
    const items = observations.filter((item) => item.category === category);
    return [category, { planned: plan.cases.filter((item) => item.category === category).length, executed: items.filter((item) => item.outcome !== "BLOCKED").length, passed: items.filter((item) => item.outcome === "PASS").length, failed: items.filter((item) => item.outcome === "FAIL").length }];
  })) as LinkPortalSecurityReport["coverage"];
  return {
    enabled: true, plannedCases: plan.cases.length, executedCases: observations.filter((item) => item.outcome !== "BLOCKED").length,
    passedCases: observations.filter((item) => item.outcome === "PASS").length, failedCases: observations.filter((item) => item.outcome === "FAIL").length,
    inconclusiveCases: observations.filter((item) => item.outcome === "INCONCLUSIVE").length, blockedCases: observations.filter((item) => item.outcome === "BLOCKED").length,
    requestsTransmitted: observations.flatMap((item) => item.steps).filter((step) => step.transmitted).length, requestBudget: plan.maxRequests,
    cleanupRequired: plan.cases.filter((item) => item.cleanupRequired).length, cleanupFailed: observations.filter((item) => item.cleanupOutcome === "CLEANUP_FAILED").length,
    resourceInventory: plan.resources.map((resource) => ({ safeAlias: resource.safeAlias, kind: resource.kind, pathTemplate: resource.pathTemplate, allowedOriginCount: resource.allowedOrigins.length, ownerDeclared: Boolean(resource.ownerActorId), tenantDeclared: Boolean(resource.tenantFingerprint), ...(resource.declaredState ? { declaredState: resource.declaredState } : {}), expiryDeclared: Boolean(resource.expiresAt) })),
    observations, coverage, notes: [...plan.notes, "Requests never retry or follow redirects. Mutations share RouteCairn's global lock and durable cleanup journal.", "FAIL requires a contradicted explicit assertion; unavailable secrets, transport ambiguity, or safety-policy blocks do not become confirmed findings."]
  };
  };
  context.partialModules.set("link-portal-security", () => { const report = snapshot(); return { pluginName: "link-portal-security", linkPortalSecurity: report, findings: findingsFromReport(report) }; });
  for (const testCase of plan.cases) {
    if (context.options.abortSignal?.aborted && !context.options.workflowRecovery) break;
    if (changesState(testCase) && (context.options.workflowRecovery ? [] : await journal.unresolvedCaseIds()).length > 0) { observations.push(blockedCase(plan, testCase, "UNRESOLVED_PRIOR_CLEANUP")); continue; }
    try { observations.push(await executeCase(context, transport, journal, lock, testCase)); } finally { await lock.release(); context.finishCaseCleanup(); await context.options.checkpointReport?.(); }
  }
  return snapshot();
}

async function executeCase(context: ScanContext, transport: RequestSafetyBroker, journal: MutationJournal, lock: GlobalMutationLock, testCase: LinkPortalSecurityCasePlan): Promise<LinkPortalCaseObservation> {
  const plan = context.options.plan.linkPortalSecurity!; const actorById = new Map(plan.actors.map((value) => [value.id, value])); const resourceById = new Map(plan.resources.map((value) => [value.id, value]));
  const captures = new Map<string, string>(); const snapshots = new Map<string, Snapshot>(); const steps: LinkPortalStepObservation[] = [];
  const mainSteps = testCase.steps.filter((step) => step.phase !== "CLEANUP"); const cleanupSteps = testCase.steps.filter((step) => step.phase === "CLEANUP");
  const caseId = `link-portal-${testCase.id}`; let stateChangeTransmitted = Boolean(context.options.workflowRecovery); let lockHeld = false; const notes: string[] = [];
  const recovering = context.mutations.register("linkPortalSecurity", caseId, testCase, { captures, snapshots });
  const cleanupTransport = context.createWorkflowCleanupHttpClient(300, context.options.plan.linkPortalSecurity!.maxResponseBytes);
  if (changesState(testCase)) {
    try { await lock.acquire(caseId); lockHeld = true; await journal.append(journalEntry(plan.targetOrigin, testCase, caseId, "AUTHORIZED")); }
    catch { if (lockHeld) await lock.release().catch(() => undefined); return blockedCase(plan, testCase, "DURABLE_MUTATION_LOCK_OR_JOURNAL_UNAVAILABLE"); }
  }
  let stop = false;
  try {
    for (const step of recovering ? [] : mainSteps) {
      if (stop) break;
      const result = await executeStep(context, transport, journal, caseId, testCase, actorById.get(step.actorId)!, resourceById.get(step.resourceId)!, step, captures, snapshots, false);
      steps.push(result); if (step.request.stateChanging && result.transmitted) stateChangeTransmitted = true; await context.mutations.checkpoint(caseId);
      if (result.outcome === "BLOCKED" || result.outcome === "INCONCLUSIVE") stop = true;
    }
  } finally {
    if (stateChangeTransmitted && cleanupSteps.length > 0) for (const step of cleanupSteps) steps.push(await executeStep(context, cleanupTransport, journal, caseId, testCase, actorById.get(step.actorId)!, resourceById.get(step.resourceId)!, step, captures, snapshots, true));
  }
  const cleanup = steps.filter((step) => step.phase === "CLEANUP");
  let cleanupOutcome = !testCase.cleanupRequired ? "NOT_REQUIRED" as const : !stateChangeTransmitted ? "CLEANUP_NOT_REACHED" as const : cleanup.length === cleanupSteps.length && cleanup.every((step) => step.outcome === "PASS") ? "ROLLBACK_VERIFIED" as const : "CLEANUP_FAILED" as const;
  if (changesState(testCase)) {
    try {
      const disposableComplete = stateChangeTransmitted && !testCase.cleanupRequired && testCase.authorization.disposableResource;
      const stage: MutationJournalStage = !stateChangeTransmitted || disposableComplete ? "SEALED" : cleanupOutcome === "ROLLBACK_VERIFIED" ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED";
      const outcome: MutationOutcome = !stateChangeTransmitted ? "BLOCKED_BY_SAFETY" : disposableComplete ? "SECURE_FOR_CASE" : cleanupOutcome === "ROLLBACK_VERIFIED" ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED";
      await journal.append(journalEntry(plan.targetOrigin, testCase, caseId, stage, outcome));
    } catch { cleanupOutcome = "CLEANUP_FAILED"; notes.push("RouteCairn could not durably seal the cleanup journal."); }
    finally { await lock.release().catch(() => notes.push("The global mutation lock could not be removed automatically.")); }
  }
  for (const key of captures.keys()) captures.set(key, "<cleared>"); captures.clear(); snapshots.clear();
  const main = steps.filter((step) => step.phase !== "CLEANUP");
  const outcome: LinkPortalOutcome = main.some((step) => step.outcome === "BLOCKED") ? "BLOCKED" : main.some((step) => step.outcome === "INCONCLUSIVE") ? "INCONCLUSIVE" : main.some((step) => step.outcome === "FAIL") ? "FAIL" : "PASS";
  return { caseId: testCase.id, label: testCase.label, category: testCase.category, outcome, cleanupOutcome, comparisonFingerprint: testCase.comparisonFingerprint, actorAliases: [...new Set(testCase.steps.map((step) => actorById.get(step.actorId)!.safeAlias))], resourceAliases: [...new Set(testCase.steps.map((step) => resourceById.get(step.resourceId)!.safeAlias))], steps, notes: [...notes, ...(cleanupOutcome === "CLEANUP_FAILED" ? ["Cleanup verification failed; the disposable resource must not be reused until inspected."] : [])] };
}

async function executeStep(context: ScanContext, transport: RequestSafetyBroker, journal: MutationJournal, journalCaseId: string, testCase: LinkPortalSecurityCasePlan, actor: LinkPortalActorPlan, resource: LinkPortalResourcePlan, step: LinkPortalStepPlan, captures: Map<string, string>, snapshots: Map<string, Snapshot>, cleanupDuty: boolean): Promise<LinkPortalStepObservation> {
  if (step.request.stateChanging && !cleanupDuty && !authorizationValid(testCase)) return emptyStep(step, actor, resource, false, "BLOCKED", "AUTHORIZATION_EXPIRED_AT_EXECUTION");
  const actorProfile = profileFor(context, actor.authSlot); const secretProfile = profileFor(context, step.request.secretSource);
  if (actor.authSlot !== "anonymous" && !actorProfile) return emptyStep(step, actor, resource, false, "BLOCKED", "ACTOR_CREDENTIAL_UNAVAILABLE");
  if (step.request.secretSource !== "anonymous" && !secretProfile) return emptyStep(step, actor, resource, false, "BLOCKED", "SECRET_SOURCE_UNAVAILABLE");
  if (step.waitBeforeMs > 0) try { await abortableDelay(step.waitBeforeMs, cleanupDuty ? context.cleanupSignal(transport) : context.options.abortSignal); } catch { return emptyStep(step, actor, resource, false, "INCONCLUSIVE", "WAIT_ABORTED"); }
  let url: string; let headers: Record<string, string>; let body: string | undefined;
  try {
    const secrets = secretProfile ? authenticationLifecycleSecrets(secretProfile) : {};
    url = expand(step.request.urlTemplate, secrets, captures); if (step.request.tamper) url = tamperQuery(url, step.request.tamper.parameter);
    const parsed = new URL(url); if (!resource.allowedOrigins.includes(parsed.origin)) throw new Error("origin");
    const scope = context.scopeMatcher.decide(url, step.request.method); if (!scope.allowed) throw new Error("scope");
    headers = { ...(actor.sendAuthentication && actorProfile ? authHeadersForProfile(actorProfile) : {}), ...Object.fromEntries(Object.entries(step.request.headers).map(([key, value]) => [key, expand(value, secrets, captures)])) };
    if (step.request.fields) {
      const fields = expandValue(step.request.fields, secrets, captures) as Record<string, unknown>;
      if (step.request.bodyFormat === "FORM") { body = new URLSearchParams(Object.entries(fields).map(([key, value]) => [key, String(value)] as [string, string])).toString(); headers[headerName(headers, "content-type") ?? "Content-Type"] = "application/x-www-form-urlencoded"; }
      else { body = JSON.stringify(fields); headers[headerName(headers, "content-type") ?? "Content-Type"] = "application/json"; }
    }
  } catch { return emptyStep(step, actor, resource, false, "BLOCKED", "SECRET_CAPTURE_OR_SCOPE_VALIDATION_FAILED"); }
  if (step.request.stateChanging) try { await journal.append({ ...journalEntry(new URL(url).origin, testCase, journalCaseId, cleanupDuty ? "ROLLBACK_SENT" : "MUTATION_ARMED"), requestMethod: step.request.method, requestUrl: safeResourceUrl(resource), ...(body ? { requestBodyAttestation: journal.attestBody(body) } : {}) }); } catch { return emptyStep(step, actor, resource, false, "BLOCKED", "MUTATION_INTENT_JOURNAL_FAILED"); }
  let response: HttpResponse;
  try { response = await transport.send({ url, method: step.request.method, headers, ...(body !== undefined ? { body } : {}), streamLimitBytes: context.options.plan.linkPortalSecurity!.maxResponseBytes, maxStreamContentLength: context.options.plan.linkPortalSecurity!.maxResponseBytes, retainBodyPreview: true, disableRetries: true, disableRedirects: true, skipCache: true }); }
  catch { if (step.request.stateChanging) await journal.append({ ...journalEntry(new URL(url).origin, testCase, journalCaseId, cleanupDuty ? "ROLLBACK_SENT" : "MUTATION_SENT"), requestMethod: step.request.method, requestUrl: safeResourceUrl(resource), note: "Transport threw after mutation intent; target state is uncertain and raw link material was omitted." }).catch(() => undefined); return emptyStep(step, actor, resource, step.request.stateChanging, "INCONCLUSIVE", "TRANSPORT_ERROR"); }
  const transmitted = requestPotentiallyTransmitted(response);
  if (step.request.stateChanging) try { await journal.append({ ...journalEntry(new URL(url).origin, testCase, journalCaseId, transmitted ? (cleanupDuty ? "ROLLBACK_SENT" : "MUTATION_SENT") : "SEALED"), requestMethod: step.request.method, requestUrl: safeResourceUrl(resource), ...(response.statusCode ? { responseStatus: response.statusCode } : {}), ...(!transmitted ? { outcome: "BLOCKED_BY_SAFETY" as const } : {}) }); } catch { return emptyStep(step, actor, resource, transmitted, "INCONCLUSIVE", "POST_REQUEST_JOURNAL_FAILED"); }
  if (response.error) return emptyStep(step, actor, resource, transmitted, transmitted ? "INCONCLUSIVE" : "BLOCKED", response.error.name === "DeclaredContentLengthExceeded" ? "RESPONSE_LIMIT_EXCEEDED" : "TRANSPORT_ERROR");
  const snapshot = snapshotFor(response); snapshots.set(step.id, snapshot); const captured: string[] = [];
  for (const capture of step.captures) { const value = captureValue(capture, response, snapshot.json); if (value !== undefined) { captures.set(capture.name, value); captured.push(capture.name); } }
  const assertions = step.assertions.map((assertion) => evaluate(assertion, response, snapshot, snapshots, context)); const outcome: LinkPortalOutcome = assertions.some((item) => !item.matched) ? "FAIL" : "PASS";
  return { stepId: step.id, phase: step.phase, actorAlias: actor.safeAlias, resourceAlias: resource.safeAlias, resourceKind: resource.kind, pathTemplate: resource.pathTemplate, method: step.request.method, stateChanging: step.request.stateChanging, tampered: Boolean(step.request.tamper), transmitted, ...(response.statusCode ? { statusCode: response.statusCode } : {}), ...(response.contentType ? { contentType: response.contentType } : {}), responseLengthBand: lengthBand(snapshot.bodyLength), responseShapeFingerprint: snapshot.shapeFingerprint, responseBodyFingerprint: snapshot.bodyFingerprint, capturesRecorded: captured, assertions, outcome };
}

function evaluate(assertion: LinkPortalAssertionPlan, response: HttpResponse, snapshot: Snapshot, snapshots: ReadonlyMap<string, Snapshot>, context: ScanContext): LinkPortalAssertionObservation {
  let matched = false;
  if (assertion.kind === "STATUS_IN") matched = response.statusCode !== undefined && assertion.values.includes(response.statusCode);
  else if (assertion.kind === "STATUS_NOT_IN") matched = response.statusCode !== undefined && !assertion.values.includes(response.statusCode);
  else if (assertion.kind === "DECISION") { const decision = assertion.deniedStatuses.includes(response.statusCode ?? 0) ? "DENY" : assertion.allowedStatuses.includes(response.statusCode ?? 0) ? "ALLOW" : "UNKNOWN"; matched = decision === assertion.expected; }
  else if (assertion.kind === "HEADER_PRESENT") matched = header(response, assertion.header) !== undefined;
  else if (assertion.kind === "HEADER_ABSENT") matched = header(response, assertion.header) === undefined;
  else if (assertion.kind === "BODY_FINGERPRINT") matched = snapshot.bodyFingerprint === assertion.expectedSha256.toLowerCase();
  else if (assertion.kind === "RESPONSE_FINGERPRINT_MATCH") matched = snapshots.get(assertion.stepId)?.bodyFingerprint === snapshot.bodyFingerprint;
  else if (assertion.kind === "RESPONSE_FINGERPRINT_DIFFERENT") matched = snapshots.has(assertion.stepId) && snapshots.get(assertion.stepId)?.bodyFingerprint !== snapshot.bodyFingerprint;
  else {
    const profile = profileFor(context, assertion.secretSource); const expected = profile ? authenticationLifecycleSecrets(profile)[assertion.secretRef] : undefined;
    const json = snapshot.json && typeof snapshot.json === "object" && !Array.isArray(snapshot.json) ? snapshot.json as Record<string, unknown> : undefined;
    const observed = valueAtSafePath(json, parseSafeFieldPath(assertion.path, { maxDepth: 8, maxArrayIndex: 50, code: "LINK_PORTAL_FIELD_PATH_INVALID" })).value;
    matched = expected !== undefined && observed !== undefined && observed !== null && typeof observed !== "object" && (assertion.kind === "JSON_EQUALS_SECRET" ? String(observed) === expected : String(observed) !== expected);
  }
  return { kind: assertion.kind, matched, reasonCode: matched ? "EXPECTATION_MATCHED" : "SECURITY_EXPECTATION_CONTRADICTED" };
}

function snapshotFor(response: HttpResponse): Snapshot { const body = bodyPreviewForAnalysis(response) ?? ""; let json: unknown; try { json = JSON.parse(body); } catch { json = undefined; } const shape = json === undefined ? `text:${response.contentType ?? "unknown"}` : JSON.stringify(jsonShape(json)); return { ...(response.statusCode ? { statusCode: response.statusCode } : {}), ...(response.contentType ? { contentType: response.contentType } : {}), bodyLength: response.contentLength ?? body.length, bodyFingerprint: (response.bodyHash ?? createHash("sha256").update(body).digest("hex")).toLowerCase(), shapeFingerprint: createHash("sha256").update(shape).digest("hex"), ...(json !== undefined ? { json } : {}) }; }
function jsonShape(value: unknown): unknown { if (Array.isArray(value)) return [value.length ? jsonShape(value[0]) : "empty"]; if (value && typeof value === "object") return Object.fromEntries(Object.keys(value as Record<string, unknown>).sort().map((key) => [key, jsonShape((value as Record<string, unknown>)[key])])); return value === null ? "null" : typeof value; }
function captureValue(capture: LinkPortalStepPlan["captures"][number], response: HttpResponse, json: unknown): string | undefined { if (capture.source === "HEADER") return header(response, capture.header); const record = json && typeof json === "object" && !Array.isArray(json) ? json as Record<string, unknown> : undefined; const value = valueAtSafePath(record, parseSafeFieldPath(capture.path, { maxDepth: 8, maxArrayIndex: 50, code: "LINK_PORTAL_FIELD_PATH_INVALID" })).value; return value === undefined || value === null || typeof value === "object" ? undefined : String(value); }
function expand(value: string, secrets: Readonly<Record<string, string>>, captures: ReadonlyMap<string, string>): string { return value.replace(/\{\{(SECRET|CAPTURE):([A-Za-z0-9._-]+)\}\}/g, (_match, kind: string, name: string) => { const result = kind === "SECRET" ? secrets[name] : captures.get(name); if (result === undefined) throw new Error("missing"); return result; }); }
function expandValue(value: unknown, secrets: Readonly<Record<string, string>>, captures: ReadonlyMap<string, string>): unknown { if (Array.isArray(value)) return value.map((entry) => expandValue(entry, secrets, captures)); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, expandValue(entry, secrets, captures)])); return typeof value === "string" ? expand(value, secrets, captures) : value; }
function tamperQuery(raw: string, parameter: string): string {
  new URL(raw);
  const hashIndex = raw.indexOf("#"); const withoutHash = hashIndex >= 0 ? raw.slice(0, hashIndex) : raw; const hash = hashIndex >= 0 ? raw.slice(hashIndex) : ""; const queryIndex = withoutHash.indexOf("?");
  if (queryIndex < 0) throw new Error("missing query");
  const prefix = withoutHash.slice(0, queryIndex + 1); const parts = withoutHash.slice(queryIndex + 1).split("&"); let changed = false;
  const next = parts.map((part) => { const equals = part.indexOf("="); const rawKey = equals < 0 ? part : part.slice(0, equals); if (decodeQueryComponent(rawKey) !== parameter || changed) return part; const rawValue = equals < 0 ? "" : part.slice(equals + 1); const current = decodeQueryComponent(rawValue); if (!current) throw new Error("missing tamper value"); const last = current.at(-1)!; changed = true; return `${rawKey}=${encodeURIComponent(`${current.slice(0, -1)}${last === "a" ? "b" : "a"}`)}`; });
  if (!changed) throw new Error("missing tamper parameter"); return `${prefix}${next.join("&")}${hash}`;
}
function decodeQueryComponent(value: string): string { return decodeURIComponent(value.replace(/\+/g, " ")); }
function profileFor(context: ScanContext, slot: LinkPortalAuthSlot): AuthProfile | undefined { if (slot === "anonymous") return undefined; if (slot === "primary") return context.options.authProfile; return slot === "account_a" ? context.options.authProfileSet?.accountA : context.options.authProfileSet?.accountB; }
function authorizationValid(testCase: LinkPortalSecurityCasePlan): boolean { const auth = testCase.authorization; return auth.mode === "CONTROLLED_LINK_FLOW" && auth.authorizationIdentityConfirmed && auth.changeTicketConfirmed && auth.confirmationAccepted && Boolean(auth.authorizedAt && auth.expiresAt) && Date.parse(auth.authorizedAt!) <= Date.now() && Date.parse(auth.expiresAt!) > Date.now() && (auth.environment !== "PRODUCTION" || auth.productionAcknowledged); }
function header(response: HttpResponse, name: string): string | undefined { const value = Object.entries(headersForAnalysis(response)).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1]; return typeof value === "string" ? value : value?.join(", "); }
function headerName(headers: Readonly<Record<string, string>>, name: string): string | undefined { return Object.keys(headers).find((key) => key.toLowerCase() === name); }
function safeResourceUrl(resource: LinkPortalResourcePlan): string { return new URL(resource.pathTemplate, resource.allowedOrigins[0]!).toString(); }
function emptyStep(step: LinkPortalStepPlan, actor: LinkPortalActorPlan, resource: LinkPortalResourcePlan, transmitted: boolean, outcome: LinkPortalOutcome, reasonCode: string): LinkPortalStepObservation { return { stepId: step.id, phase: step.phase, actorAlias: actor.safeAlias, resourceAlias: resource.safeAlias, resourceKind: resource.kind, pathTemplate: resource.pathTemplate, method: step.request.method, stateChanging: step.request.stateChanging, tampered: Boolean(step.request.tamper), transmitted, capturesRecorded: [], assertions: [], outcome, reasonCode }; }
function requestPotentiallyTransmitted(response: HttpResponse): boolean { return !["RequestBudgetExceeded", "OutOfScopeRequest", "ControlledMutationBlocked", "ControlledDeletionBlocked"].includes(response.error?.name ?? ""); }
function abortableDelay(ms: number, signal?: AbortSignal): Promise<void> { return new Promise((resolve, reject) => { if (signal?.aborted) return reject(new Error("aborted")); const timer = setTimeout(resolve, ms); signal?.addEventListener("abort", () => { clearTimeout(timer); reject(new Error("aborted")); }, { once: true }); }); }
function lengthBand(length: number): string { if (length === 0) return "0"; if (length <= 64) return "1-64"; if (length <= 256) return "65-256"; if (length <= 1024) return "257-1024"; if (length <= 8192) return "1025-8192"; return ">8192"; }
function changesState(testCase: LinkPortalSecurityCasePlan): boolean { return testCase.steps.some((step) => step.request.stateChanging); }
function journalEntry(targetOrigin: string, testCase: LinkPortalSecurityCasePlan, caseId: string, stage: MutationJournalStage, outcome?: MutationOutcome) { return { caseId, stage, mode: "CONTROLLED_MUTATION" as const, targetOrigin, targetIdentityFingerprint: testCase.comparisonFingerprint, ...(outcome ? { outcome } : {}), note: "Link/portal security entry; signed values, captures, invite data, object identifiers, and response bodies omitted." }; }
function blockedCase(plan: NonNullable<ScanContext["options"]["plan"]["linkPortalSecurity"]>, testCase: LinkPortalSecurityCasePlan, reason: string): LinkPortalCaseObservation { const actorById = new Map(plan.actors.map((value) => [value.id, value])); const resourceById = new Map(plan.resources.map((value) => [value.id, value])); return { caseId: testCase.id, label: testCase.label, category: testCase.category, outcome: "BLOCKED", cleanupOutcome: testCase.cleanupRequired ? "CLEANUP_NOT_REACHED" : "NOT_REQUIRED", comparisonFingerprint: testCase.comparisonFingerprint, actorAliases: [...new Set(testCase.steps.map((step) => actorById.get(step.actorId)!.safeAlias))], resourceAliases: [...new Set(testCase.steps.map((step) => resourceById.get(step.resourceId)!.safeAlias))], steps: [], notes: [reason] }; }

function findingsFromReport(report: LinkPortalSecurityReport): Finding[] { const scorer = new RiskScorer(); return report.observations.filter((item) => item.outcome === "FAIL").map((item) => { const first = item.steps.find((step) => step.outcome === "FAIL"); const type = findingType(item.category); const severity = ["SIGNED_LINK_REPLAY", "INVITE_REPLAY", "PORTAL_TENANT_BINDING", "EXPORT_AUTHORIZATION", "EVIDENCE_ARTIFACT_AUTHORIZATION", "OBJECT_PATH_OWNERSHIP"].includes(item.category) ? "High" as const : "Medium" as const; const base = { id: `finding-${createHash("sha1").update(`link-portal:${item.comparisonFingerprint}`).digest("hex").slice(0, 12)}`, title: titleFor(item.category), type, severity, confidence: "High" as const, url: first ? `redacted://link-portal${first.pathTemplate}` : "redacted://link-portal", method: first?.method ?? "N/A", ...(first?.statusCode ? { statusCode: first.statusCode } : {}), evidence: { url: first ? `redacted://link-portal${first.pathTemplate}` : "redacted://link-portal", method: first?.method ?? "N/A", ...(first?.statusCode ? { statusCode: first.statusCode } : {}), ...(first?.responseBodyFingerprint ? { bodyHash: first.responseBodyFingerprint } : {}), source: `link-portal-export-security:${item.caseId}`, severityReason: `Explicit ${item.category} expectation was contradicted.`, reproductionNotes: [`Comparison fingerprint ${item.comparisonFingerprint}.`, "Signed values, invites, emails, object identifiers, captures, and response bodies are intentionally absent."] }, impact: impactFor(item.category), recommendation: recommendationFor(item.category), manualTestingSuggestions: ["Confirm the declared actor/resource relationship and intended policy.", "Re-run only the same explicit bounded case after remediation."], tags: ["link-portal-security", item.category.toLowerCase()], falsePositiveStatus: "likely-valid" as const, workflowCase: { id: item.caseId, comparisonFingerprint: item.comparisonFingerprint, cleanupOutcome: item.cleanupOutcome }, sourceModule: "link-portal-export-security", timestamp: new Date().toISOString() }; return { ...base, riskScore: scorer.score(base) }; }); }
function findingType(category: LinkPortalSecurityCasePlan["category"]): FindingType { if (category.startsWith("INVITE_")) return "Invitation Security Issue"; if (category === "PORTAL_TENANT_BINDING") return "Portal Tenant Isolation Issue"; if (category === "EXPORT_AUTHORIZATION") return "Export Authorization Issue"; if (category === "EVIDENCE_ARTIFACT_AUTHORIZATION") return "Evidence Artifact Authorization Issue"; if (category === "OBJECT_PATH_OWNERSHIP" || category === "ID_SUBSTITUTION") return "Object Path Authorization Issue"; return "Signed Link Security Issue"; }
function titleFor(category: LinkPortalSecurityCasePlan["category"]): string { return `${category.toLowerCase().replace(/_/g, " ")} contract was contradicted`; }
function impactFor(category: LinkPortalSecurityCasePlan["category"]): string { if (category.startsWith("INVITE_")) return "An invitation may be accepted by the wrong identity, after expiry, or more than once."; if (category === "PORTAL_TENANT_BINDING") return "A portal session or link may expose another tenant's data."; if (category.includes("EXPORT") || category.includes("ARTIFACT")) return "A protected export or evidence artifact may be retrievable without its required authorization boundary."; if (category.includes("OBJECT") || category === "ID_SUBSTITUTION") return "Changing an object path may cross an ownership boundary."; return "A signed capability may remain usable after tampering, expiry, replay, revocation, or across tenants."; }
function recommendationFor(category: LinkPortalSecurityCasePlan["category"]): string { if (category.startsWith("INVITE_")) return "Bind invitations to the intended identity and tenant, store one-way token digests, enforce atomic one-time use and expiry, and invalidate them after acceptance or revocation."; if (category === "PORTAL_TENANT_BINDING") return "Resolve tenant identity server-side and authorize every portal object independently of link or route parameters."; if (category.includes("EXPORT") || category.includes("ARTIFACT")) return "Authorize export and artifact retrieval at download time, bind it to the intended principal and tenant, and use short-lived revocable capabilities."; return "Cryptographically bind the signature to the complete canonical resource, tenant, audience, and expiry; enforce one-time or revocation state atomically where declared."; }
function disabledReport(): LinkPortalSecurityReport { return { enabled: false, plannedCases: 0, executedCases: 0, passedCases: 0, failedCases: 0, inconclusiveCases: 0, blockedCases: 0, requestsTransmitted: 0, requestBudget: 0, cleanupRequired: 0, cleanupFailed: 0, resourceInventory: [], observations: [], coverage: Object.fromEntries(linkPortalSecurityCategories.map((category) => [category, { planned: 0, executed: 0, passed: 0, failed: 0 }])) as LinkPortalSecurityReport["coverage"], notes: ["No link/portal/export security manifest was supplied."] }; }
