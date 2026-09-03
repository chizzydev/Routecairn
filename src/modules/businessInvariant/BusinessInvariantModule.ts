import { createHash } from "node:crypto";
import { authenticationLifecycleSecrets, authHeadersForProfile, type AuthProfile } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import { redactSensitiveUrl } from "../../core/evidence/ValuePresenceAttestation.js";
import type { Finding } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { HttpRequest, HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { RequestSafetyBroker } from "../../core/http/RequestSafetyBroker.js";
import { GlobalMutationLock, MutationJournal, safeRequestUrl } from "../../core/offensive/MutationJournal.js";
import type { MutationJournalStage, MutationOutcome } from "../../core/offensive/ControlledMutationTypes.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import type { BusinessInvariantActionObservation, BusinessInvariantAssertionObservation, BusinessInvariantCaseObservation, BusinessInvariantReport } from "../../reports/BusinessInvariantReport.js";
import type { LifecycleActorPlan } from "../authenticationLifecycle/AuthenticationLifecycleTypes.js";
import { businessInvariantCategories, type BusinessActionPlan, type BusinessInvariantAssertionPlan, type BusinessInvariantCasePlan, type InvariantCapturePlan, type InvariantOutcome, type InvariantRequestPlan } from "./BusinessInvariantTypes.js";

interface Snapshot { statusCode?: number; shapeFingerprint: string; bodyDigest: string; json?: unknown; response: HttpResponse }
interface ActionRuntime { observation: BusinessInvariantActionObservation; snapshots: Snapshot[] }

export class BusinessInvariantModule implements RouteCairnPlugin {
  public readonly name = "business-invariant";
  public readonly description = "Verifies controlled multi-step business invariants with authoritative state and cleanup.";
  public readonly phase = "analysis" as const;
  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await executeBusinessInvariant(context);
    return { pluginName: this.name, businessInvariant: report, findings: findingsFromReport(report), notes: report.notes };
  }
}

export async function executeBusinessInvariant(context: ScanContext): Promise<BusinessInvariantReport> {
  const plan = context.options.plan.businessInvariant;
  if (!plan) return disabledReport();
  const transport = context.createBusinessInvariantHttpClient(plan.maxRequests, plan.maxResponseBytes, plan.maxConcurrency);
  const journal = context.mutations.journal;
  const lock = context.mutations.lock();
  const observations: BusinessInvariantCaseObservation[] = [];
  const snapshot = (): BusinessInvariantReport => {
  const coverage = Object.fromEntries(businessInvariantCategories.map((category) => {
    const entries = observations.filter((item) => item.category === category);
    return [category, { planned: plan.cases.filter((item) => item.category === category).length, executed: entries.filter((item) => item.outcome !== "BLOCKED").length, passed: entries.filter((item) => item.outcome === "PASS").length, failed: entries.filter((item) => item.outcome === "FAIL").length }];
  })) as BusinessInvariantReport["coverage"];
  return { enabled: true, plannedCases: plan.cases.length, executedCases: observations.filter((item) => item.outcome !== "BLOCKED").length, passedCases: count(observations, "PASS"), failedCases: count(observations, "FAIL"), inconclusiveCases: count(observations, "INCONCLUSIVE"), blockedCases: count(observations, "BLOCKED"), cleanupRequired: plan.cases.length, cleanupFailed: observations.filter((item) => item.cleanupOutcome === "CLEANUP_FAILED").length, duplicateAttempts: plan.cases.flatMap((item) => item.actions).reduce((total, action) => total + Math.max(0, action.execution.attempts - 1), 0), concurrentActions: plan.cases.flatMap((item) => item.actions).filter((action) => action.execution.mode === "CONCURRENT_DUPLICATE").length, observations, coverage, notes: [...plan.notes, "Supplied credentials stay worker-local. Case state is encrypted in recovery checkpoints until verified cleanup; reports never contain raw restoration values. Reports retain status, structure fingerprints, counters, and invariant outcomes.", "A finding requires a configured invariant or expectation to be contradicted; transport uncertainty is never promoted to a finding."] };
  };
  context.partialModules.set("business-invariant", () => { const report = snapshot(); return { pluginName: "business-invariant", businessInvariant: report, findings: findingsFromReport(report) }; });
  for (const testCase of plan.cases) {
    if (context.options.abortSignal?.aborted && !context.options.workflowRecovery) break;
    if ((context.options.workflowRecovery ? [] : await journal.unresolvedCaseIds()).length > 0) { observations.push(blockedCase(testCase, "UNRESOLVED_PRIOR_CLEANUP")); continue; }
    try { observations.push(await executeCase(context, transport, journal, lock, testCase)); } finally { await lock.release(); context.finishCaseCleanup(); await context.options.checkpointReport?.(); }
  }
  return snapshot();
}

async function executeCase(context: ScanContext, transport: RequestSafetyBroker, journal: MutationJournal, lock: GlobalMutationLock, testCase: BusinessInvariantCasePlan): Promise<BusinessInvariantCaseObservation> {
  const captures = new Map<string, unknown>();
  const actionRuntime = new Map<string, ActionRuntime>();
  const actions: BusinessInvariantActionObservation[] = [];
  const notes: string[] = [];
  const journalCaseId = `business-invariant-${testCase.id}`;
  const recovering = context.mutations.register("businessInvariant", journalCaseId, testCase, { captures, actionRuntime });
  const cleanupTransport = context.createWorkflowCleanupHttpClient(300, context.options.plan.businessInvariant!.maxResponseBytes);
  let lockHeld = false; let anyPotentialTransmission = Boolean(context.options.workflowRecovery); let preStateVerified = false; let postStateVerified = false;
  let mainOutcome: InvariantOutcome = "PASS";
  let cleanupOutcome: BusinessInvariantCaseObservation["cleanupOutcome"] = "CLEANUP_NOT_REACHED";
  let invariantResults: BusinessInvariantAssertionObservation[] = [];
  let cleanupInvariantResults: BusinessInvariantAssertionObservation[] = [];
  let stateMachineResult: BusinessInvariantAssertionObservation | undefined;
  try {
    try { await lock.acquire(journalCaseId); lockHeld = true; await journal.append(journalEntry(testCase, journalCaseId, "AUTHORIZED")); }
    catch { return blockedCase(testCase, "DURABLE_MUTATION_LOCK_OR_JOURNAL_UNAVAILABLE"); }
    if (!recovering && !authorizationValid(testCase)) mainOutcome = "BLOCKED";
    if (!recovering && mainOutcome === "PASS") {
      const pre = await executeObservations(context, transport, testCase, testCase.preState, captures);
      preStateVerified = pre === "PASS";
      mainOutcome = mergeOutcome(mainOutcome, pre);
      if (preStateVerified) await journal.append(journalEntry(testCase, journalCaseId, "PRE_STATE_CAPTURED"));
    }
    if (!recovering && mainOutcome === "PASS") {
      for (const action of testCase.actions) {
        const runtime = await executeAction(context, transport, journal, journalCaseId, testCase, action, captures);
        actionRuntime.set(action.id, runtime); actions.push(runtime.observation);
        if (runtime.observation.attemptsTransmitted > 0) anyPotentialTransmission = true;
        await context.mutations.checkpoint(journalCaseId);
        mainOutcome = mergeOutcome(mainOutcome, runtime.observation.outcome);
        if (runtime.observation.outcome === "BLOCKED" || runtime.observation.outcome === "INCONCLUSIVE") break;
      }
    }
    if (!recovering && mainOutcome !== "BLOCKED" && mainOutcome !== "INCONCLUSIVE") {
      const post = await executeObservations(context, transport, testCase, testCase.postState, captures);
      postStateVerified = post === "PASS";
      mainOutcome = mergeOutcome(mainOutcome, post);
      if (postStateVerified) {
        invariantResults = testCase.invariants.map((item) => evaluateInvariant(item, captures, actionRuntime));
        mainOutcome = invariantResults.reduce((outcome, item) => mergeOutcome(outcome, item.outcome), mainOutcome);
        if (testCase.stateMachine) {
          stateMachineResult = evaluateStateMachine(testCase.stateMachine.beforeCapture, testCase.stateMachine.afterCapture, testCase.stateMachine.allowedTransitions, captures);
          mainOutcome = mergeOutcome(mainOutcome, stateMachineResult.outcome);
        }
        await journal.append(journalEntry(testCase, journalCaseId, "IMPACT_VERIFIED", mainOutcome === "FAIL" ? "EXPLOIT_PROVEN" : "SECURE_FOR_CASE"));
      }
    }
  } catch {
    mainOutcome = anyPotentialTransmission ? "INCONCLUSIVE" : "BLOCKED";
    notes.push(anyPotentialTransmission ? "Execution failed after a request may have been transmitted; cleanup was forced." : "Execution stopped before any mutation was transmitted.");
  } finally {
    if (anyPotentialTransmission && lockHeld) {
      const cleanupActionsPassed = await executeCleanup(context, cleanupTransport, journal, journalCaseId, testCase, captures);
      const cleanupVerification = cleanupActionsPassed ? await executeObservations(context, cleanupTransport, testCase, testCase.cleanupVerification, captures) : "INCONCLUSIVE";
      if (cleanupVerification === "PASS") cleanupInvariantResults = testCase.cleanupInvariants.map((item) => evaluateInvariant(item, captures, actionRuntime));
      cleanupOutcome = cleanupActionsPassed && cleanupVerification === "PASS" && cleanupInvariantResults.every((item) => item.outcome === "PASS") ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED";
    }
    if (lockHeld) {
      try { await journal.append(journalEntry(testCase, journalCaseId, !anyPotentialTransmission ? "SEALED" : cleanupOutcome === "ROLLBACK_VERIFIED" ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED", !anyPotentialTransmission ? "BLOCKED_BY_SAFETY" : cleanupOutcome === "ROLLBACK_VERIFIED" ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED")); }
      catch { cleanupOutcome = anyPotentialTransmission ? "CLEANUP_FAILED" : cleanupOutcome; notes.push("The durable journal could not be sealed; inspect the disposable entity before reuse."); }
      await lock.release().catch(() => notes.push("The global mutation lock could not be removed automatically."));
    }
    captures.clear(); actionRuntime.clear();
  }
  if (cleanupOutcome === "CLEANUP_FAILED") notes.push("Cleanup verification failed; the disposable entity must not be reused until manually reconciled.");
  return { caseId: testCase.id, label: testCase.label, category: testCase.category, actorModel: actorModel(testCase), outcome: mainOutcome, cleanupOutcome, comparisonFingerprint: testCase.comparisonFingerprint, preStateVerified, postStateVerified, actions, invariants: invariantResults, cleanupInvariants: cleanupInvariantResults, ...(stateMachineResult ? { stateMachine: stateMachineResult } : {}), notes };
}

async function executeObservations(context: ScanContext, transport: RequestSafetyBroker, testCase: BusinessInvariantCasePlan, observations: BusinessInvariantCasePlan["preState"], captures: Map<string, unknown>): Promise<InvariantOutcome> {
  for (const observation of observations) {
    const actor = testCase.actors.find((item) => item.id === observation.actorId)!;
    const prepared = prepareRequest(context, actor, observation.request, captures);
    if (!prepared) return "BLOCKED";
    let response: HttpResponse;
    try { response = await transport.send(prepared); } catch { return "INCONCLUSIVE"; }
    if (response.error || typeof response.statusCode !== "number") return "INCONCLUSIVE";
    if (response.statusCode < 200 || response.statusCode >= 300) return "INCONCLUSIVE";
    const snapshot = snapshotFor(response);
    if (!captureAll(observation.captures, snapshot, captures)) return "INCONCLUSIVE";
  }
  return "PASS";
}

async function executeAction(context: ScanContext, transport: RequestSafetyBroker, journal: MutationJournal, journalCaseId: string, testCase: BusinessInvariantCasePlan, action: BusinessActionPlan, captures: Map<string, unknown>): Promise<ActionRuntime> {
  const actor = testCase.actors.find((item) => item.id === action.actorId)!;
  const request = prepareRequest(context, actor, action.request, captures);
  if (!request || !authorizationValid(testCase)) return { observation: actionObservation(action, actor.safeAlias, [], 0, "BLOCKED", "AUTHORIZATION_OR_REFERENCE_UNAVAILABLE"), snapshots: [] };
  try {
    for (let index = 0; index < action.execution.attempts; index += 1) await journal.append({ ...journalEntry(testCase, journalCaseId, "MUTATION_ARMED"), requestMethod: request.method, requestUrl: safeRequestUrl(request.url), requestBodyAttestation: journal.attestBody(request.body), note: `Business invariant action ${action.id}; attempt ${index + 1}; raw request and identity omitted.` });
  } catch { return { observation: actionObservation(action, actor.safeAlias, [], 0, "BLOCKED", "MUTATION_INTENT_NOT_DURABLE"), snapshots: [] }; }
  const snapshots: Snapshot[] = [];
  const run = async (): Promise<Snapshot> => snapshotFor(await transport.send({ ...request, skipCache: true, disableRetries: true, disableRedirects: true, retainBodyPreview: true }));
  try {
    if (action.execution.mode === "CONCURRENT_DUPLICATE") {
      for (let offset = 0; offset < action.execution.attempts; offset += action.execution.maxConcurrency) snapshots.push(...await Promise.all(Array.from({ length: Math.min(action.execution.maxConcurrency, action.execution.attempts - offset) }, run)));
    } else {
      for (let index = 0; index < action.execution.attempts; index += 1) snapshots.push(await run());
    }
  } catch {
    return { observation: actionObservation(action, actor.safeAlias, snapshots, action.execution.attempts, "INCONCLUSIVE", "TRANSPORT_EXCEPTION_AFTER_MUTATION_INTENT"), snapshots };
  }
  const transmitted = snapshots.filter((item) => requestPotentiallyTransmitted(item.response)).length;
  try { for (const current of snapshots) await journal.append({ ...journalEntry(testCase, journalCaseId, "MUTATION_SENT"), requestMethod: request.method, requestUrl: safeRequestUrl(request.url), ...(current.statusCode ? { responseStatus: current.statusCode } : {}), responseHash: current.response.bodyHash, note: `Business invariant action ${action.id}; response body and headers omitted.` }); }
  catch { return { observation: actionObservation(action, actor.safeAlias, snapshots, Math.max(transmitted, action.execution.attempts), "INCONCLUSIVE", "POST_TRANSMISSION_JOURNAL_FAILURE"), snapshots }; }
  const selected = action.captureFromAttempt === "FIRST" ? snapshots[0] : snapshots.at(-1);
  if (action.captures.length > 0 && (!selected || !captureAll(action.captures, selected, captures))) return { observation: actionObservation(action, actor.safeAlias, snapshots, transmitted, "INCONCLUSIVE", "ACTION_CAPTURE_UNAVAILABLE"), snapshots };
  const observation = classifyAction(action, actor.safeAlias, snapshots, transmitted);
  return { observation, snapshots };
}

async function executeCleanup(context: ScanContext, transport: RequestSafetyBroker, journal: MutationJournal, journalCaseId: string, testCase: BusinessInvariantCasePlan, captures: Map<string, unknown>): Promise<boolean> {
  let passed = true;
  for (const cleanup of testCase.cleanup) {
    const actor = testCase.actors.find((item) => item.id === cleanup.actorId)!;
    const request = prepareRequest(context, actor, cleanup.request, captures);
    if (!request) { passed = false; continue; }
    try { await journal.append({ ...journalEntry(testCase, journalCaseId, "ROLLBACK_SENT"), requestMethod: request.method, requestUrl: safeRequestUrl(request.url), requestBodyAttestation: journal.attestBody(request.body) }); }
    catch { passed = false; continue; }
    try {
      const response = await transport.send({ ...request, skipCache: true, disableRetries: true, disableRedirects: true, retainBodyPreview: true });
      if (!cleanup.successStatusCodes.includes(response.statusCode ?? 0)) passed = false;
    } catch { passed = false; }
  }
  return passed;
}

function classifyAction(action: BusinessActionPlan, alias: string, snapshots: Snapshot[], transmitted: number): BusinessInvariantActionObservation {
  const statuses = snapshots.flatMap((item) => typeof item.statusCode === "number" ? [item.statusCode] : []);
  const allowed = statuses.filter((status) => action.expectation.authorizationAllowedStatuses.includes(status)).length;
  const denied = statuses.filter((status) => action.expectation.authorizationDeniedStatuses.includes(status)).length;
  const accepted = statuses.filter((status) => action.expectation.businessAcceptedStatuses.includes(status)).length;
  const rejected = statuses.filter((status) => action.expectation.businessRejectedStatuses.includes(status)).length;
  const authMatched = statuses.length === snapshots.length && (action.expectation.authorization === "ALLOW" ? allowed === statuses.length : denied === statuses.length);
  const businessMatched = action.expectation.businessRule === "NOT_EVALUATED" || (statuses.length === snapshots.length && (action.expectation.businessRule === "ACCEPT" ? accepted === statuses.length : rejected === statuses.length));
  const unclassified = statuses.length !== snapshots.length || allowed + denied < statuses.length || (action.expectation.businessRule !== "NOT_EVALUATED" && accepted + rejected < statuses.length);
  const outcome: InvariantOutcome = unclassified ? "INCONCLUSIVE" : authMatched && businessMatched ? "PASS" : "FAIL";
  return actionObservation(action, alias, snapshots, transmitted, outcome, unclassified ? "ACTION_RESPONSE_UNCLASSIFIED" : authMatched && businessMatched ? "EXPECTATIONS_MATCHED" : !authMatched ? "AUTHORIZATION_EXPECTATION_CONTRADICTED" : "BUSINESS_RULE_EXPECTATION_CONTRADICTED", { accepted, rejected, allowed, denied, authMatched, businessMatched });
}

function actionObservation(action: BusinessActionPlan, alias: string, snapshots: Snapshot[], transmitted: number, outcome: InvariantOutcome, reasonCode: string, counts = { accepted: 0, rejected: 0, allowed: 0, denied: 0, authMatched: false, businessMatched: false }): BusinessInvariantActionObservation {
  return { actionId: action.id, actorAlias: alias, method: action.request.method, url: redactSensitiveUrl(action.request.url), executionMode: action.execution.mode, attemptsPlanned: action.execution.attempts, attemptsTransmitted: transmitted, statusCodes: snapshots.flatMap((item) => typeof item.statusCode === "number" ? [item.statusCode] : []), acceptedCount: counts.accepted, rejectedCount: counts.rejected, authorizedCount: counts.allowed, deniedCount: counts.denied, authorizationExpectationMatched: counts.authMatched, businessRuleExpectationMatched: counts.businessMatched, responseShapeFingerprints: snapshots.map((item) => item.shapeFingerprint), outcome, reasonCode };
}

function evaluateInvariant(invariant: BusinessInvariantAssertionPlan, captures: Map<string, unknown>, actions: Map<string, ActionRuntime>): BusinessInvariantAssertionObservation {
  try {
    let matched = false;
    if (invariant.kind === "VALUE_COMPARE") matched = compare(operand(invariant.left, captures), invariant.operator, operand(invariant.right, captures));
    else if (invariant.kind === "NUMERIC_DELTA") matched = compare(numberCapture(captures, invariant.after) - numberCapture(captures, invariant.before), invariant.operator, invariant.expected);
    else if (invariant.kind === "STATE_TRANSITION") matched = invariant.allowed.some((edge) => edge.from === String(requiredCapture(captures, invariant.before)) && edge.to === String(requiredCapture(captures, invariant.after)));
    else if (invariant.kind === "ACTION_OUTCOME_COUNT") {
      const action = actions.get(invariant.actionId); if (!action) throw new Error("missing action");
      const value = invariant.outcome === "ACCEPTED" ? action.observation.acceptedCount : invariant.outcome === "REJECTED" ? action.observation.rejectedCount : invariant.outcome === "AUTHORIZED" ? action.observation.authorizedCount : action.observation.deniedCount;
      matched = compare(value, invariant.operator, invariant.expected);
    } else {
      const action = actions.get(invariant.actionId); if (!action || action.snapshots.length < 2) throw new Error("missing duplicate responses");
      const first = action.snapshots[0]!; const equivalent = action.snapshots.slice(1).every((item) => (!invariant.compareStatus || item.statusCode === first.statusCode) && (!invariant.compareShape || item.shapeFingerprint === first.shapeFingerprint) && (!invariant.compareBodyDigest || item.bodyDigest === first.bodyDigest)); matched = equivalent === invariant.expectedEquivalent;
    }
    return { invariantId: invariant.id, kind: invariant.kind, outcome: matched ? "PASS" : "FAIL", reasonCode: matched ? "INVARIANT_SATISFIED" : "INVARIANT_CONTRADICTED" };
  } catch { return { invariantId: invariant.id, kind: invariant.kind, outcome: "INCONCLUSIVE", reasonCode: "INVARIANT_INPUT_UNAVAILABLE" }; }
}

function evaluateStateMachine(before: string, after: string, allowed: readonly { from: string; to: string }[], captures: Map<string, unknown>): BusinessInvariantAssertionObservation {
  try { const matched = allowed.some((edge) => edge.from === String(requiredCapture(captures, before)) && edge.to === String(requiredCapture(captures, after))); return { invariantId: "state-machine", kind: "STATE_MACHINE", outcome: matched ? "PASS" : "FAIL", reasonCode: matched ? "ALLOWED_TRANSITION" : "FORBIDDEN_TRANSITION" }; }
  catch { return { invariantId: "state-machine", kind: "STATE_MACHINE", outcome: "INCONCLUSIVE", reasonCode: "STATE_CAPTURE_UNAVAILABLE" }; }
}

function prepareRequest(context: ScanContext, actor: LifecycleActorPlan, plan: InvariantRequestPlan, captures: Map<string, unknown>): HttpRequest | undefined {
  try {
    const profile = profileForActor(context, actor); if (actor.authSlot !== "anonymous" && !profile) return undefined;
    const secrets = profile ? authenticationLifecycleSecrets(profile) : {};
    const url = expandString(plan.url, secrets, captures);
    if (!context.scopeMatcher.decide(url, plan.method).allowed || new URL(url).origin !== new URL(context.options.target).origin) return undefined;
    const headers = { ...(profile && actor.requestAuthentication === "PROFILE" ? authHeadersForProfile(profile) : {}) };
    for (const [name, value] of Object.entries(expandValue(plan.headers, secrets, captures) as Record<string, string>)) setHeader(headers, name, value);
    let body: string | undefined;
    if (plan.fields) {
      const fields = expandValue(plan.fields, secrets, captures) as Record<string, unknown>;
      if (plan.bodyFormat === "FORM") { body = new URLSearchParams(Object.entries(fields).map(([key, value]) => [key, String(value)] as [string, string])).toString(); setHeader(headers, "Content-Type", "application/x-www-form-urlencoded"); }
      else { body = JSON.stringify(fields); setHeader(headers, "Content-Type", "application/json"); }
    }
    return { url, method: plan.method, headers, ...(body !== undefined ? { body } : {}), skipCache: true, disableRetries: true, disableRedirects: true, retainBodyPreview: true };
  } catch { return undefined; }
}

function snapshotFor(response: HttpResponse): Snapshot {
  const body = bodyPreviewForAnalysis(response) ?? ""; let json: unknown;
  try { json = JSON.parse(body); } catch { json = undefined; }
  const shape = json === undefined ? `text:${response.contentType ?? "unknown"}` : JSON.stringify(jsonShape(json));
  return { ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}), shapeFingerprint: createHash("sha256").update(shape).digest("hex"), bodyDigest: createHash("sha256").update(body).digest("hex"), ...(json !== undefined ? { json } : {}), response };
}

function captureAll(plans: readonly InvariantCapturePlan[], snapshot: Snapshot, captures: Map<string, unknown>): boolean {
  for (const capture of plans) {
    let value: unknown;
    if (capture.source === "JSON") value = valueAt(snapshot.json, capture.path);
    else if (capture.source === "HEADER") value = header(snapshot.response, capture.header);
    else { const cookie = header(snapshot.response, "set-cookie"); value = cookie?.match(new RegExp(`(?:^|,\\s*)${escapeRegex(capture.cookie)}=([^;]*)`, "i"))?.[1]; }
    if (value === undefined) return false;
    captures.set(capture.name, value);
  }
  return true;
}

function authorizationValid(testCase: BusinessInvariantCasePlan): boolean { const value = testCase.authorization; const now = Date.now(); return value.mode === "CONTROLLED_INVARIANT" && value.authorizationIdentityConfirmed && value.changeTicketConfirmed && value.confirmationAccepted && value.disposableEntities && new Date(value.authorizedAt).getTime() <= now && new Date(value.expiresAt).getTime() > now && (value.environment !== "PRODUCTION" || value.productionAcknowledged); }
function profileForActor(context: ScanContext, actor: LifecycleActorPlan): AuthProfile | undefined { if (actor.authSlot === "anonymous") return undefined; if (actor.authSlot === "primary") return context.options.authProfile; return actor.authSlot === "account_a" ? context.options.authProfileSet?.accountA : context.options.authProfileSet?.accountB; }
function expandValue(value: unknown, secrets: Record<string, string>, captures: Map<string, unknown>): unknown { if (Array.isArray(value)) return value.map((entry) => expandValue(entry, secrets, captures)); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, expandValue(child, secrets, captures)])); return typeof value === "string" ? expandString(value, secrets, captures) : value; }
function expandString(value: string, secrets: Record<string, string>, captures: Map<string, unknown>): string { return value.replace(/\{\{(SECRET|CAPTURE):([A-Za-z0-9._-]+)\}\}/g, (_match, kind: string, name: string) => { const result = kind === "SECRET" ? secrets[name] : captures.get(name); if (result === undefined || result === null || typeof result === "object") throw new Error("reference unavailable"); return String(result); }); }
function setHeader(headers: Record<string, string>, name: string, value: string): void { const existing = Object.keys(headers).find((key) => key.toLowerCase() === name.toLowerCase()); headers[existing ?? name] = value; }
function header(response: HttpResponse, name: string): string | undefined { const value = Object.entries(headersForAnalysis(response)).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1]; return typeof value === "string" ? value : value?.join(", "); }
function valueAt(value: unknown, path: string): unknown { let current = value; for (const part of path.replace(/\[(\d+)\]/g, ".$1").split(".")) { if (!current || typeof current !== "object") return undefined; current = (current as Record<string, unknown>)[part]; } return current; }
function requiredCapture(captures: Map<string, unknown>, name: string): unknown { if (!captures.has(name)) throw new Error("capture unavailable"); return captures.get(name); }
function numberCapture(captures: Map<string, unknown>, name: string): number { const value = requiredCapture(captures, name); const parsed = typeof value === "number" ? value : Number(value); if (!Number.isFinite(parsed)) throw new Error("not numeric"); return parsed; }
function operand(value: { source: "CAPTURE"; ref: string } | { source: "LITERAL"; value: unknown }, captures: Map<string, unknown>): unknown { return value.source === "CAPTURE" ? requiredCapture(captures, value.ref) : value.value; }
function compare(left: unknown, operator: "EQ" | "NEQ" | "LT" | "LTE" | "GT" | "GTE", right: unknown): boolean { if (operator === "EQ") return JSON.stringify(left) === JSON.stringify(right); if (operator === "NEQ") return JSON.stringify(left) !== JSON.stringify(right); const a = typeof left === "number" ? left : Number(left); const b = typeof right === "number" ? right : Number(right); if (!Number.isFinite(a) || !Number.isFinite(b)) throw new Error("not comparable"); return operator === "LT" ? a < b : operator === "LTE" ? a <= b : operator === "GT" ? a > b : a >= b; }
function jsonShape(value: unknown): unknown { if (Array.isArray(value)) return [value.length ? jsonShape(value[0]) : "empty"]; if (value && typeof value === "object") return Object.fromEntries(Object.keys(value as Record<string, unknown>).sort().map((key) => [key, jsonShape((value as Record<string, unknown>)[key])])); return value === null ? "null" : typeof value; }
function mergeOutcome(left: InvariantOutcome, right: InvariantOutcome): InvariantOutcome { const rank: Record<InvariantOutcome, number> = { PASS: 0, FAIL: 1, INCONCLUSIVE: 2, BLOCKED: 3 }; return rank[right] > rank[left] ? right : left; }
function count(values: BusinessInvariantCaseObservation[], outcome: InvariantOutcome): number { return values.filter((item) => item.outcome === outcome).length; }
function requestPotentiallyTransmitted(response: HttpResponse): boolean { return !["RequestBudgetExceeded", "OutOfScopeRequest", "ControlledMutationBlocked"].includes(response.error?.name ?? ""); }
function journalEntry(testCase: BusinessInvariantCasePlan, caseId: string, stage: MutationJournalStage, outcome?: MutationOutcome) { return { caseId, stage, mode: "CONTROLLED_MUTATION" as const, targetOrigin: new URL(testCase.preState[0]!.request.url).origin, targetIdentityFingerprint: testCase.comparisonFingerprint, ...(outcome ? { outcome } : {}), note: "Business invariant entry; credentials, identities, raw captures, and response bodies omitted." }; }
function actorModel(testCase: BusinessInvariantCasePlan): BusinessInvariantCaseObservation["actorModel"] { return testCase.actors.map((actor) => ({ safeAlias: actor.safeAlias, authSlot: actor.authSlot, requestAuthentication: actor.requestAuthentication, relationship: actor.relationship, declaredState: actor.declaredState, ...(actor.tenantAlias ? { tenantAlias: actor.tenantAlias } : {}) })); }
function blockedCase(testCase: BusinessInvariantCasePlan, reason: string): BusinessInvariantCaseObservation { return { caseId: testCase.id, label: testCase.label, category: testCase.category, actorModel: actorModel(testCase), outcome: "BLOCKED", cleanupOutcome: "CLEANUP_NOT_REACHED", comparisonFingerprint: testCase.comparisonFingerprint, preStateVerified: false, postStateVerified: false, actions: [], invariants: [], cleanupInvariants: [], notes: [reason] }; }
function escapeRegex(value: string): string { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

function findingsFromReport(report: BusinessInvariantReport): Finding[] {
  const scorer = new RiskScorer();
  return report.observations.filter((item) => item.outcome === "FAIL").map((item) => {
    const action = item.actions.find((entry) => entry.outcome === "FAIL") ?? item.actions[0];
    const base = { id: `finding-${createHash("sha1").update(`business-invariant:${item.comparisonFingerprint}`).digest("hex").slice(0, 12)}`, title: `Business invariant failed: ${item.label}`, type: "Business Logic Invariant Issue" as const, severity: "High" as const, confidence: "High" as const, url: action?.url ?? "redacted://business-invariant", method: action?.method ?? "N/A", ...(action?.statusCodes[0] ? { statusCode: action.statusCodes[0] } : {}), evidence: { url: action?.url ?? "redacted://business-invariant", method: action?.method ?? "N/A", ...(action?.statusCodes[0] ? { statusCode: action.statusCodes[0] } : {}), source: "business-invariant", severityReason: `An explicitly configured ${item.category} invariant was contradicted by authoritative post-state.`, reproductionNotes: [`Case ${item.caseId}; comparison fingerprint ${item.comparisonFingerprint}.`, "Raw business state, account identifiers, credentials, and response bodies are intentionally absent."] }, impact: "An attacker may violate an application-level transaction, entitlement, ordering, separation-of-duties, or one-time-action rule even when endpoint authorization is otherwise functioning.", recommendation: "Enforce the invariant atomically in the authoritative data layer, use idempotency/uniqueness controls where applicable, separate authorization from business-rule validation, and retain this case as a regression test.", manualTestingSuggestions: ["Reconcile the disposable entity and inspect the redacted action/invariant outcomes.", "Re-run the exact case after implementing an atomic server-side guard."], tags: ["business-logic", "invariant", item.category.toLowerCase()], falsePositiveStatus: "likely-valid" as const, workflowCase: { id: item.caseId, comparisonFingerprint: item.comparisonFingerprint, cleanupOutcome: item.cleanupOutcome }, sourceModule: "business-invariant", timestamp: new Date().toISOString() };
    return { ...base, riskScore: scorer.score(base) };
  });
}
function disabledReport(): BusinessInvariantReport { return { enabled: false, plannedCases: 0, executedCases: 0, passedCases: 0, failedCases: 0, inconclusiveCases: 0, blockedCases: 0, cleanupRequired: 0, cleanupFailed: 0, duplicateAttempts: 0, concurrentActions: 0, observations: [], coverage: Object.fromEntries(businessInvariantCategories.map((category) => [category, { planned: 0, executed: 0, passed: 0, failed: 0 }])) as BusinessInvariantReport["coverage"], notes: ["Business invariant testing was not configured."] }; }
