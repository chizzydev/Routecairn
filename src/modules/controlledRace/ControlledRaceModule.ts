import { createHash } from "node:crypto";
import { authenticationLifecycleSecrets, authHeadersForProfile, type AuthProfile } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import { redactSensitiveUrl } from "../../core/evidence/ValuePresenceAttestation.js";
import type { Finding } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { HttpRequest, HttpResponse } from "../../core/http/HttpTypes.js";
import type { RequestSafetyBroker } from "../../core/http/RequestSafetyBroker.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import { GlobalMutationLock, MutationJournal, safeRequestUrl } from "../../core/offensive/MutationJournal.js";
import type { MutationJournalStage, MutationOutcome } from "../../core/offensive/ControlledMutationTypes.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { RaceAssertionObservation, RaceGroupObservation, RaceRequestObservation, ControlledRaceCaseObservation, ControlledRaceReport } from "../../reports/ControlledRaceReport.js";
import type { LifecycleActorPlan } from "../authenticationLifecycle/AuthenticationLifecycleTypes.js";
import type { InvariantCapturePlan, InvariantRequestPlan, StateObservationPlan } from "../businessInvariant/BusinessInvariantTypes.js";
import { controlledRaceCategories, type ControlledRaceAssertionPlan, type ControlledRaceCasePlan, type ControlledRaceOutcome, type SynchronizedRaceGroupPlan, type SynchronizedRaceRequestPlan } from "./ControlledRaceTypes.js";

interface Snapshot { response: HttpResponse; statusCode?: number; json?: unknown; shapeFingerprint: string }
interface GroupRuntime { observation: RaceGroupObservation }

export class ControlledRaceModule implements RouteCairnPlugin {
  public readonly name = "controlled-race";
  public readonly description = "Tests explicit bounded application race conditions with synchronized mutation groups and authoritative state verification.";
  public readonly phase = "analysis" as const;
  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await executeControlledRace(context);
    return { pluginName: this.name, controlledRace: report, findings: findingsFromReport(report), notes: report.notes };
  }
}

export async function executeControlledRace(context: ScanContext): Promise<ControlledRaceReport> {
  const plan = context.options.plan.controlledRace;
  if (!plan) return disabledReport();
  const transport = context.createControlledRaceHttpClient(plan.maxRequests, plan.maxResponseBytes, plan.maxConcurrency);
  const journal = context.mutations.journal;
  const lock = context.mutations.lock();
  const observations: ControlledRaceCaseObservation[] = [];
  const snapshot = (): ControlledRaceReport => {
  const coverage = Object.fromEntries(controlledRaceCategories.map((category) => {
    const values = observations.filter((item) => item.category === category);
    return [category, { planned: plan.cases.filter((item) => item.category === category).length, executed: values.filter((item) => item.outcome !== "BLOCKED").length, passed: values.filter((item) => item.outcome === "PASS").length, failed: values.filter((item) => item.outcome === "FAIL").length }];
  })) as ControlledRaceReport["coverage"];
  return {
    enabled: true,
    plannedCases: plan.cases.length,
    executedCases: observations.filter((item) => item.outcome !== "BLOCKED").length,
    passedCases: count(observations, "PASS"), failedCases: count(observations, "FAIL"), inconclusiveCases: count(observations, "INCONCLUSIVE"), blockedCases: count(observations, "BLOCKED"),
    plannedGroups: plan.cases.flatMap((item) => item.groups).length,
    synchronizedGroups: observations.flatMap((item) => item.groups).filter((item) => item.synchronized).length,
    plannedRaceRequests: plan.cases.flatMap((item) => item.groups).flatMap((item) => item.requests).length,
    transmittedRaceRequests: observations.flatMap((item) => item.groups).reduce((total, group) => total + group.transmittedCount, 0),
    cleanupRequired: plan.cases.length,
    cleanupFailed: observations.filter((item) => item.cleanupOutcome === "CLEANUP_FAILED").length,
    observations,
    coverage,
    notes: [...plan.notes, "Race findings require both a synchronized group within its configured dispatch-skew bound and an explicit invariant contradiction from authoritative post-state or event counts.", "Supplied credentials stay worker-local. Case state is encrypted for crash recovery and removed after verified cleanup; reports omit raw restoration values."]
  };
  };
  context.partialModules.set("controlled-race", () => { const report = snapshot(); return { pluginName: "controlled-race", controlledRace: report, findings: findingsFromReport(report) }; });
  for (const testCase of plan.cases) {
    if (context.options.abortSignal?.aborted && !context.options.workflowRecovery) break;
    if ((context.options.workflowRecovery ? [] : await journal.unresolvedCaseIds()).length > 0) { observations.push(blockedCase(testCase, "UNRESOLVED_PRIOR_CLEANUP")); continue; }
    try { observations.push(await executeCase(context, transport, journal, lock, testCase)); } finally { await lock.release(); context.finishCaseCleanup(); await context.options.checkpointReport?.(); }
  }
  return snapshot();
}

async function executeCase(context: ScanContext, transport: RequestSafetyBroker, journal: MutationJournal, lock: GlobalMutationLock, testCase: ControlledRaceCasePlan): Promise<ControlledRaceCaseObservation> {
  const captures = new Map<string, unknown>(); const groups = new Map<string, GroupRuntime>(); const groupObservations: RaceGroupObservation[] = []; const notes: string[] = [];
  const journalCaseId = `controlled-race-${testCase.id}`;
  const recovering = context.mutations.register("controlledRace", journalCaseId, testCase, { captures, groups });
  const cleanupTransport = context.createWorkflowCleanupHttpClient(300, context.options.plan.controlledRace!.maxResponseBytes);
  let lockHeld = false; let potentiallyTransmitted = Boolean(context.options.workflowRecovery); let preStateVerified = false; let postStateVerified = false; let outcome: ControlledRaceOutcome = "PASS"; let cleanupOutcome: ControlledRaceCaseObservation["cleanupOutcome"] = "CLEANUP_NOT_REACHED"; let invariants: RaceAssertionObservation[] = []; let cleanupInvariants: RaceAssertionObservation[] = [];
  try {
    try { await lock.acquire(journalCaseId); lockHeld = true; await journal.append(journalEntry(testCase, journalCaseId, "AUTHORIZED")); }
    catch { return blockedCase(testCase, "DURABLE_MUTATION_LOCK_OR_JOURNAL_UNAVAILABLE"); }
    if (!recovering && !authorizationValid(testCase)) outcome = "BLOCKED";
    if (!recovering && outcome === "PASS") {
      const pre = await executeObservations(context, transport, testCase, testCase.preState, captures); preStateVerified = pre === "PASS"; outcome = merge(outcome, pre);
      if (preStateVerified) await journal.append(journalEntry(testCase, journalCaseId, "PRE_STATE_CAPTURED"));
    }
    if (!recovering && outcome === "PASS") {
      for (const group of testCase.groups) {
        const runtime = await executeGroup(context, transport, journal, journalCaseId, testCase, group, captures);
        groups.set(group.id, runtime); groupObservations.push(runtime.observation);
        if (runtime.observation.transmittedCount > 0) potentiallyTransmitted = true;
        await context.mutations.checkpoint(journalCaseId);
        outcome = merge(outcome, runtime.observation.outcome);
        if (runtime.observation.outcome === "BLOCKED" || runtime.observation.outcome === "INCONCLUSIVE") break;
      }
    }
    if (!recovering && outcome !== "BLOCKED" && outcome !== "INCONCLUSIVE") {
      const post = await executeObservations(context, transport, testCase, testCase.postState, captures); postStateVerified = post === "PASS"; outcome = merge(outcome, post);
      if (postStateVerified) {
        invariants = testCase.invariants.map((value) => evaluateInvariant(value, captures, groups));
        outcome = invariants.reduce((current, value) => merge(current, value.outcome), outcome);
        await journal.append(journalEntry(testCase, journalCaseId, "IMPACT_VERIFIED", outcome === "FAIL" ? "EXPLOIT_PROVEN" : "SECURE_FOR_CASE"));
      }
    }
  } catch {
    outcome = potentiallyTransmitted ? "INCONCLUSIVE" : "BLOCKED";
    notes.push(potentiallyTransmitted ? "Execution failed after a race request may have been transmitted; cleanup was forced." : "Execution stopped before the race group was transmitted.");
  } finally {
    if (potentiallyTransmitted && lockHeld) {
      const cleanupActionsPassed = await executeCleanup(context, cleanupTransport, journal, journalCaseId, testCase, captures);
      const verification = cleanupActionsPassed ? await executeObservations(context, cleanupTransport, testCase, testCase.cleanupVerification, captures) : "INCONCLUSIVE";
      if (verification === "PASS") cleanupInvariants = testCase.cleanupInvariants.map((value) => evaluateInvariant(value, captures, groups));
      cleanupOutcome = cleanupActionsPassed && verification === "PASS" && cleanupInvariants.every((value) => value.outcome === "PASS") ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED";
    }
    if (lockHeld) {
      try { await journal.append(journalEntry(testCase, journalCaseId, !potentiallyTransmitted ? "SEALED" : cleanupOutcome === "ROLLBACK_VERIFIED" ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED", !potentiallyTransmitted ? "BLOCKED_BY_SAFETY" : cleanupOutcome === "ROLLBACK_VERIFIED" ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED")); }
      catch { if (potentiallyTransmitted) cleanupOutcome = "CLEANUP_FAILED"; notes.push("The durable race journal could not be sealed."); }
      await lock.release().catch(() => notes.push("The global mutation lock could not be removed automatically."));
    }
    captures.clear(); groups.clear();
  }
  if (cleanupOutcome === "CLEANUP_FAILED") notes.push("Cleanup verification failed; the disposable race target must not be reused until reconciled.");
  return { caseId: testCase.id, label: testCase.label, category: testCase.category, targetType: testCase.target.type, targetIdentityFingerprint: testCase.target.identityFingerprint, outcome, cleanupOutcome, preStateVerified, postStateVerified, comparisonFingerprint: testCase.comparisonFingerprint, groups: groupObservations, invariants, cleanupInvariants, notes };
}

async function executeGroup(context: ScanContext, transport: RequestSafetyBroker, journal: MutationJournal, journalCaseId: string, testCase: ControlledRaceCasePlan, group: SynchronizedRaceGroupPlan, captures: Map<string, unknown>): Promise<GroupRuntime> {
  const prepared: Array<{ plan: SynchronizedRaceRequestPlan; actor: LifecycleActorPlan; request: HttpRequest }> = [];
  for (const raceRequest of group.requests) {
    const actor = testCase.actors.find((value) => value.id === raceRequest.actorId)!;
    const request = prepareRequest(context, actor, raceRequest.request, captures);
    if (!request || !authorizationValid(testCase)) return { observation: blockedGroup(group, "AUTHORIZATION_OR_REFERENCE_UNAVAILABLE") };
    prepared.push({ plan: raceRequest, actor, request });
  }
  try {
    for (const member of prepared) await journal.append({ ...journalEntry(testCase, journalCaseId, "MUTATION_ARMED"), requestMethod: member.request.method, requestUrl: safeRequestUrl(member.request.url), requestBodyAttestation: journal.attestBody(member.request.body), note: `Controlled race group ${group.id}; request ${member.plan.id}; body and identity omitted.` });
  } catch { return { observation: blockedGroup(group, "MUTATION_INTENT_NOT_DURABLE") }; }
  let result: Awaited<ReturnType<RequestSafetyBroker["sendSynchronizedMutations"]>>;
  try { result = await transport.sendSynchronizedMutations(prepared.map((value) => ({ ...value.request, retainBodyPreview: true }))); }
  catch { return { observation: { ...blockedGroup(group, "TRANSPORT_EXCEPTION_AFTER_BARRIER_RELEASE"), transmittedCount: group.requests.length, outcome: "INCONCLUSIVE" } }; }
  const snapshots = result.responses.map(snapshotFor);
  try {
    for (let index = 0; index < snapshots.length; index += 1) { const snapshot = snapshots[index]!; const member = prepared[index]!; await journal.append({ ...journalEntry(testCase, journalCaseId, "MUTATION_SENT"), requestMethod: member.request.method, requestUrl: safeRequestUrl(member.request.url), ...(snapshot.statusCode ? { responseStatus: snapshot.statusCode } : {}), responseHash: snapshot.response.bodyHash, note: `Controlled race group ${group.id}; request ${member.plan.id}; response body omitted.` }); }
  } catch { return { observation: { ...groupObservation(group, prepared, snapshots, result.dispatchSkewMs), outcome: "INCONCLUSIVE", reasonCode: "POST_TRANSMISSION_JOURNAL_FAILURE" } }; }
  return { observation: groupObservation(group, prepared, snapshots, result.dispatchSkewMs) };
}

function groupObservation(group: SynchronizedRaceGroupPlan, prepared: Array<{ plan: SynchronizedRaceRequestPlan; actor: LifecycleActorPlan }>, snapshots: Snapshot[], dispatchSkewMs: number): RaceGroupObservation {
  const requests = snapshots.map((snapshot, index) => classifyRequest(prepared[index]!.plan, prepared[index]!.actor, snapshot));
  const transmittedCount = snapshots.filter((value) => potentiallyTransmitted(value.response)).length;
  const synchronized = dispatchSkewMs <= group.maxDispatchSkewMs && snapshots.length === group.requests.length;
  const requestOutcome = requests.reduce<ControlledRaceOutcome>((current, value) => merge(current, value.outcome), "PASS");
  const outcome = synchronized ? requestOutcome : "INCONCLUSIVE";
  return { groupId: group.id, label: group.label, synchronized, requestCount: group.requests.length, transmittedCount, dispatchSkewMs: Math.round(dispatchSkewMs * 1000) / 1000, maxDispatchSkewMs: group.maxDispatchSkewMs, acceptedCount: requests.filter((value) => value.businessRuleDecision === "ACCEPTED").length, rejectedCount: requests.filter((value) => value.businessRuleDecision === "REJECTED").length, authorizedCount: requests.filter((value) => value.authorizationDecision === "ALLOWED").length, deniedCount: requests.filter((value) => value.authorizationDecision === "DENIED").length, outcome, reasonCode: !synchronized ? "DISPATCH_SKEW_EXCEEDED" : outcome === "PASS" ? "GROUP_EXPECTATIONS_MATCHED" : outcome === "FAIL" ? "GROUP_EXPECTATION_CONTRADICTED" : "GROUP_RESPONSE_UNCLASSIFIED", requests };
}

function classifyRequest(plan: SynchronizedRaceRequestPlan, actor: LifecycleActorPlan, snapshot: Snapshot): RaceRequestObservation {
  const status = snapshot.statusCode;
  const authorizationDecision = status === undefined ? "UNCLASSIFIED" : plan.expectation.authorizationAllowedStatuses.includes(status) ? "ALLOWED" : plan.expectation.authorizationDeniedStatuses.includes(status) ? "DENIED" : "UNCLASSIFIED";
  const businessRuleDecision = status === undefined ? "UNCLASSIFIED" : plan.expectation.businessAcceptedStatuses.includes(status) ? "ACCEPTED" : plan.expectation.businessRejectedStatuses.includes(status) ? "REJECTED" : plan.expectation.businessRule === "NOT_EVALUATED" ? "NOT_EVALUATED" : "UNCLASSIFIED";
  const authorizationMatched = plan.expectation.authorization === "ALLOW" ? authorizationDecision === "ALLOWED" : authorizationDecision === "DENIED";
  const businessMatched = plan.expectation.businessRule === "NOT_EVALUATED" || (plan.expectation.businessRule === "ACCEPT" ? businessRuleDecision === "ACCEPTED" : businessRuleDecision === "REJECTED");
  const unclassified = authorizationDecision === "UNCLASSIFIED" || (plan.expectation.businessRule !== "NOT_EVALUATED" && businessRuleDecision === "UNCLASSIFIED");
  const outcome: ControlledRaceOutcome = unclassified ? "INCONCLUSIVE" : authorizationMatched && businessMatched ? "PASS" : "FAIL";
  return { requestId: plan.id, actorAlias: actor.safeAlias, method: plan.request.method, url: redactSensitiveUrl(plan.request.url), transmitted: potentiallyTransmitted(snapshot.response), ...(status !== undefined ? { statusCode: status } : {}), authorizationDecision, businessRuleDecision, expectationMatched: authorizationMatched && businessMatched, responseShapeFingerprint: snapshot.shapeFingerprint, outcome, reasonCode: unclassified ? "RESPONSE_UNCLASSIFIED" : authorizationMatched && businessMatched ? "EXPECTATION_MATCHED" : !authorizationMatched ? "AUTHORIZATION_EXPECTATION_CONTRADICTED" : "BUSINESS_RULE_EXPECTATION_CONTRADICTED" };
}

async function executeObservations(context: ScanContext, transport: RequestSafetyBroker, testCase: ControlledRaceCasePlan, observations: readonly StateObservationPlan[], captures: Map<string, unknown>): Promise<ControlledRaceOutcome> {
  for (const observation of observations) {
    const actor = testCase.actors.find((value) => value.id === observation.actorId)!; const request = prepareRequest(context, actor, observation.request, captures); if (!request) return "BLOCKED";
    let response: HttpResponse; try { response = await transport.send(request); } catch { return "INCONCLUSIVE"; }
    if (response.error || response.statusCode === undefined || response.statusCode < 200 || response.statusCode >= 300) return "INCONCLUSIVE";
    if (!captureAll(observation.captures, snapshotFor(response), captures)) return "INCONCLUSIVE";
  }
  return "PASS";
}

async function executeCleanup(context: ScanContext, transport: RequestSafetyBroker, journal: MutationJournal, journalCaseId: string, testCase: ControlledRaceCasePlan, captures: Map<string, unknown>): Promise<boolean> {
  let passed = true;
  for (const cleanup of testCase.cleanup) {
    const actor = testCase.actors.find((value) => value.id === cleanup.actorId)!; const request = prepareRequest(context, actor, cleanup.request, captures); if (!request) { passed = false; continue; }
    try { await journal.append({ ...journalEntry(testCase, journalCaseId, "ROLLBACK_SENT"), requestMethod: request.method, requestUrl: safeRequestUrl(request.url), requestBodyAttestation: journal.attestBody(request.body) }); }
    catch { passed = false; continue; }
    try { const response = await transport.send(request); if (!cleanup.successStatusCodes.includes(response.statusCode ?? 0)) passed = false; } catch { passed = false; }
  }
  return passed;
}

function evaluateInvariant(value: ControlledRaceAssertionPlan, captures: Map<string, unknown>, groups: Map<string, GroupRuntime>): RaceAssertionObservation {
  try {
    let matched: boolean;
    if (value.kind === "VALUE_COMPARE") matched = compare(operand(value.left, captures), value.operator, operand(value.right, captures));
    else if (value.kind === "NUMERIC_DELTA" || value.kind === "EVENT_COUNT_DELTA") matched = compare(numberCapture(captures, value.after) - numberCapture(captures, value.before), value.operator, value.expected);
    else if (value.kind === "STATE_TRANSITION") matched = value.allowed.some((edge) => edge.from === String(required(captures, value.before)) && edge.to === String(required(captures, value.after)));
    else { const group = groups.get(value.groupId); if (!group) throw new Error("missing group"); const count = value.outcome === "ACCEPTED" ? group.observation.acceptedCount : value.outcome === "REJECTED" ? group.observation.rejectedCount : value.outcome === "AUTHORIZED" ? group.observation.authorizedCount : group.observation.deniedCount; matched = compare(count, value.operator, value.expected); }
    return { invariantId: value.id, kind: value.kind, outcome: matched ? "PASS" : "FAIL", reasonCode: matched ? "INVARIANT_SATISFIED" : "INVARIANT_CONTRADICTED" };
  } catch { return { invariantId: value.id, kind: value.kind, outcome: "INCONCLUSIVE", reasonCode: "INVARIANT_INPUT_UNAVAILABLE" }; }
}

function prepareRequest(context: ScanContext, actor: LifecycleActorPlan, plan: InvariantRequestPlan, captures: Map<string, unknown>): HttpRequest | undefined {
  try {
    const profile = profileFor(context, actor); if (actor.authSlot !== "anonymous" && !profile) return undefined; const secrets = profile ? authenticationLifecycleSecrets(profile) : {};
    const url = expandString(plan.url, secrets, captures); if (!context.scopeMatcher.decide(url, plan.method).allowed || new URL(url).origin !== new URL(context.options.target).origin) return undefined;
    const headers = { ...(profile && actor.requestAuthentication === "PROFILE" ? authHeadersForProfile(profile) : {}) }; for (const [name, value] of Object.entries(expandValue(plan.headers, secrets, captures) as Record<string, string>)) setHeader(headers, name, value);
    let body: string | undefined;
    if (plan.fields) { const fields = expandValue(plan.fields, secrets, captures) as Record<string, unknown>; if (plan.bodyFormat === "FORM") { body = new URLSearchParams(Object.entries(fields).map(([key, value]) => [key, String(value)] as [string, string])).toString(); setHeader(headers, "Content-Type", "application/x-www-form-urlencoded"); } else { body = JSON.stringify(fields); setHeader(headers, "Content-Type", "application/json"); } }
    return { url, method: plan.method, headers, ...(body !== undefined ? { body } : {}), skipCache: true, disableRetries: true, disableRedirects: true, retainBodyPreview: true };
  } catch { return undefined; }
}

function snapshotFor(response: HttpResponse): Snapshot { const body = bodyPreviewForAnalysis(response) ?? ""; let json: unknown; try { json = JSON.parse(body); } catch { json = undefined; } const shape = json === undefined ? `text:${response.contentType ?? "unknown"}` : JSON.stringify(jsonShape(json)); return { response, ...(response.statusCode !== undefined ? { statusCode: response.statusCode } : {}), ...(json !== undefined ? { json } : {}), shapeFingerprint: createHash("sha256").update(shape).digest("hex") }; }
function captureAll(plans: readonly InvariantCapturePlan[], snapshot: Snapshot, captures: Map<string, unknown>): boolean { for (const capture of plans) { let value: unknown; if (capture.source === "JSON") value = at(snapshot.json, capture.path); else if (capture.source === "HEADER") value = header(snapshot.response, capture.header); else value = header(snapshot.response, "set-cookie")?.match(new RegExp(`(?:^|,\\s*)${escapeRegex(capture.cookie)}=([^;]*)`, "i"))?.[1]; if (value === undefined) return false; captures.set(capture.name, value); } return true; }
function profileFor(context: ScanContext, actor: LifecycleActorPlan): AuthProfile | undefined { if (actor.authSlot === "anonymous") return undefined; if (actor.authSlot === "primary") return context.options.authProfile; return actor.authSlot === "account_a" ? context.options.authProfileSet?.accountA : context.options.authProfileSet?.accountB; }
function authorizationValid(testCase: ControlledRaceCasePlan): boolean { const value = testCase.authorization; const now = Date.now(); return value.mode === "CONTROLLED_RACE" && value.authorizationIdentityConfirmed && value.changeTicketConfirmed && value.confirmationAccepted && value.disposableEntities && new Date(value.authorizedAt).getTime() <= now && new Date(value.expiresAt).getTime() > now && (value.environment !== "PRODUCTION" || value.productionAcknowledged); }
function expandValue(value: unknown, secrets: Record<string, string>, captures: Map<string, unknown>): unknown { if (Array.isArray(value)) return value.map((entry) => expandValue(entry, secrets, captures)); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, expandValue(child, secrets, captures)])); return typeof value === "string" ? expandString(value, secrets, captures) : value; }
function expandString(value: string, secrets: Record<string, string>, captures: Map<string, unknown>): string { return value.replace(/\{\{(SECRET|CAPTURE):([A-Za-z0-9._-]+)\}\}/g, (_match, kind: string, name: string) => { const resolved = kind === "SECRET" ? secrets[name] : captures.get(name); if (resolved === undefined || resolved === null || typeof resolved === "object") throw new Error("reference unavailable"); return String(resolved); }); }
function operand(value: { source: "CAPTURE"; ref: string } | { source: "LITERAL"; value: unknown }, captures: Map<string, unknown>): unknown { return value.source === "CAPTURE" ? required(captures, value.ref) : value.value; }
function required(captures: Map<string, unknown>, name: string): unknown { if (!captures.has(name)) throw new Error("capture unavailable"); return captures.get(name); }
function numberCapture(captures: Map<string, unknown>, name: string): number { const value = Number(required(captures, name)); if (!Number.isFinite(value)) throw new Error("capture is not numeric"); return value; }
function compare(left: unknown, operator: "EQ" | "NEQ" | "LT" | "LTE" | "GT" | "GTE", right: unknown): boolean { if (operator === "EQ") return JSON.stringify(left) === JSON.stringify(right); if (operator === "NEQ") return JSON.stringify(left) !== JSON.stringify(right); const a = Number(left); const b = Number(right); if (!Number.isFinite(a) || !Number.isFinite(b)) throw new Error("not comparable"); return operator === "LT" ? a < b : operator === "LTE" ? a <= b : operator === "GT" ? a > b : a >= b; }
function at(value: unknown, path: string): unknown { let current = value; for (const part of path.replace(/\[(\d+)\]/g, ".$1").split(".")) { if (!current || typeof current !== "object") return undefined; current = (current as Record<string, unknown>)[part]; } return current; }
function header(response: HttpResponse, name: string): string | undefined { const value = Object.entries(headersForAnalysis(response)).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1]; return typeof value === "string" ? value : value?.join(", "); }
function setHeader(headers: Record<string, string>, name: string, value: string): void { const existing = Object.keys(headers).find((key) => key.toLowerCase() === name.toLowerCase()); headers[existing ?? name] = value; }
function jsonShape(value: unknown): unknown { if (Array.isArray(value)) return [value.length ? jsonShape(value[0]) : "empty"]; if (value && typeof value === "object") return Object.fromEntries(Object.keys(value as Record<string, unknown>).sort().map((key) => [key, jsonShape((value as Record<string, unknown>)[key])])); return value === null ? "null" : typeof value; }
function potentiallyTransmitted(response: HttpResponse): boolean { return !["RequestBudgetExceeded", "OutOfScopeRequest", "ControlledMutationBlocked"].includes(response.error?.name ?? ""); }
function merge(left: ControlledRaceOutcome, right: ControlledRaceOutcome): ControlledRaceOutcome { const rank: Record<ControlledRaceOutcome, number> = { PASS: 0, FAIL: 1, INCONCLUSIVE: 2, BLOCKED: 3 }; return rank[right] > rank[left] ? right : left; }
function count(values: ControlledRaceCaseObservation[], outcome: ControlledRaceOutcome): number { return values.filter((value) => value.outcome === outcome).length; }
function escapeRegex(value: string): string { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function journalEntry(testCase: ControlledRaceCasePlan, caseId: string, stage: MutationJournalStage, outcome?: MutationOutcome) { return { caseId, stage, mode: "CONTROLLED_MUTATION" as const, targetOrigin: new URL(testCase.preState[0]!.request.url).origin, targetIdentityFingerprint: testCase.target.identityFingerprint, ...(outcome ? { outcome } : {}), note: "Controlled race entry; credentials, raw state, request bodies, response bodies, identities, and tickets omitted." }; }
function blockedGroup(group: SynchronizedRaceGroupPlan, reasonCode: string): RaceGroupObservation { return { groupId: group.id, label: group.label, synchronized: false, requestCount: group.requests.length, transmittedCount: 0, dispatchSkewMs: 0, maxDispatchSkewMs: group.maxDispatchSkewMs, acceptedCount: 0, rejectedCount: 0, authorizedCount: 0, deniedCount: 0, outcome: "BLOCKED", reasonCode, requests: [] }; }
function blockedCase(testCase: ControlledRaceCasePlan, reason: string): ControlledRaceCaseObservation { return { caseId: testCase.id, label: testCase.label, category: testCase.category, targetType: testCase.target.type, targetIdentityFingerprint: testCase.target.identityFingerprint, outcome: "BLOCKED", cleanupOutcome: "CLEANUP_NOT_REACHED", preStateVerified: false, postStateVerified: false, comparisonFingerprint: testCase.comparisonFingerprint, groups: [], invariants: [], cleanupInvariants: [], notes: [reason] }; }

function findingsFromReport(report: ControlledRaceReport): Finding[] {
  const scorer = new RiskScorer();
  return report.observations.filter((item) => item.outcome === "FAIL").map((item) => {
    const group = item.groups.find((value) => value.outcome === "FAIL") ?? item.groups[0]; const request = group?.requests[0];
    const base = { id: `finding-${createHash("sha1").update(`controlled-race:${item.comparisonFingerprint}`).digest("hex").slice(0, 12)}`, title: `Controlled race invariant failed: ${item.label}`, type: "Controlled Race Condition" as const, severity: "High" as const, confidence: "High" as const, url: request?.url ?? "redacted://controlled-race", method: request?.method ?? "N/A", ...(request?.statusCode ? { statusCode: request.statusCode } : {}), evidence: { url: request?.url ?? "redacted://controlled-race", method: request?.method ?? "N/A", ...(request?.statusCode ? { statusCode: request.statusCode } : {}), source: "controlled-race", severityReason: `A synchronized ${item.category} group contradicted an explicit authoritative invariant.`, reproductionNotes: [`Case ${item.caseId}; fingerprint ${item.comparisonFingerprint}.`, `Synchronized groups: ${item.groups.filter((value) => value.synchronized).length}/${item.groups.length}.`, "Credentials, raw state, request/response bodies, and target identifiers are omitted."] }, impact: "Concurrent requests may bypass one-time, inventory, payment, entitlement, invitation, token, or same-object transaction guarantees and create duplicate or unauthorized effects.", recommendation: "Enforce the invariant atomically at the authoritative data layer using transactions, row or advisory locks, compare-and-swap state transitions, idempotency keys, and uniqueness constraints appropriate to the workflow.", manualTestingSuggestions: ["Reconcile the disposable target and review authoritative event/state counts.", "Re-run the exact synchronized group after adding an atomic server-side control."], tags: ["race-condition", "business-logic", item.category.toLowerCase()], falsePositiveStatus: "likely-valid" as const, workflowCase: { id: item.caseId, comparisonFingerprint: item.comparisonFingerprint, cleanupOutcome: item.cleanupOutcome }, sourceModule: "controlled-race", timestamp: new Date().toISOString() };
    return { ...base, riskScore: scorer.score(base) };
  });
}
function disabledReport(): ControlledRaceReport { return { enabled: false, plannedCases: 0, executedCases: 0, passedCases: 0, failedCases: 0, inconclusiveCases: 0, blockedCases: 0, plannedGroups: 0, synchronizedGroups: 0, plannedRaceRequests: 0, transmittedRaceRequests: 0, cleanupRequired: 0, cleanupFailed: 0, observations: [], coverage: Object.fromEntries(controlledRaceCategories.map((category) => [category, { planned: 0, executed: 0, passed: 0, failed: 0 }])) as ControlledRaceReport["coverage"], notes: ["Controlled race testing was not configured."] }; }
