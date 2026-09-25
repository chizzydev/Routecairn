import { createHash } from "node:crypto";
import { join } from "node:path";
import { writeFile } from "node:fs/promises";
import { authenticationLifecycleSecrets, authHeadersForProfile, type AuthProfile } from "../../core/auth/AuthProfile.js";
import type { ScanContext } from "../../core/engine/ScanContext.js";
import { redactSensitiveUrl } from "../../core/evidence/ValuePresenceAttestation.js";
import type { Finding } from "../../core/findings/Finding.js";
import { RiskScorer } from "../../core/findings/RiskScorer.js";
import type { HttpResponse } from "../../core/http/HttpTypes.js";
import { bodyPreviewForAnalysis, headersForAnalysis } from "../../core/http/TransientResponseAnalysis.js";
import type { RequestSafetyBroker } from "../../core/http/RequestSafetyBroker.js";
import type { ModuleResult, RouteCairnPlugin } from "../../core/plugins/Plugin.js";
import { GlobalMutationLock, MutationJournal, safeRequestUrl } from "../../core/offensive/MutationJournal.js";
import type { MutationJournalStage, MutationOutcome } from "../../core/offensive/ControlledMutationTypes.js";
import type { AuthenticationLifecycleCaseObservation, AuthenticationLifecycleReport, LifecycleAssertionObservation, LifecycleStepObservation } from "../../reports/AuthenticationLifecycleReport.js";
import { authenticationLifecycleCategories, type AuthenticationLifecycleCasePlan, type AuthenticationLifecycleCategory, type LifecycleActorPlan, type LifecycleAssertionPlan, type LifecycleStepPlan } from "./AuthenticationLifecycleTypes.js";
import { compileBrowserLearnedLifecycle } from "./BrowserLearnedLifecycleCompiler.js";
import { AuthenticationFixtureRuntime } from "./AuthenticationFixtureRuntime.js";

interface TransientSnapshot {
  statusCode?: number;
  bodyLength: number;
  bodyDigest: string;
  responseTimeMs: number;
  shape: string;
  json?: unknown;
}

export class AuthenticationLifecycleModule implements RouteCairnPlugin {
  public readonly name = "authentication-lifecycle";
  public readonly description = "Verifies explicitly authorized authentication and session lifecycle contracts.";
  public readonly phase = "analysis" as const;

  public async run(context: ScanContext): Promise<ModuleResult> {
    const report = await executeAuthenticationLifecycle(context);
    return { pluginName: this.name, authenticationLifecycle: report, findings: findingsFromReport(report), notes: report.notes };
  }
}

export async function executeAuthenticationLifecycle(context: ScanContext): Promise<AuthenticationLifecycleReport> {
  const configuredPlan = context.options.plan.authenticationLifecycle;
  if (!configuredPlan) return disabledReport();
  let plan = configuredPlan;
  let automation: AuthenticationLifecycleReport["learningAutomation"];
  const observations = [] as AuthenticationLifecycleCaseObservation[];
  if (configuredPlan.automation) {
    const compilation = compileBrowserLearnedLifecycle(configuredPlan, context.state.getBrowserCrawl()?.authentication, { target: context.options.target, scope: context.options.scope, ...(context.options.authProfile ? { authProfile: context.options.authProfile } : {}), ...(context.options.authProfileSet ? { authProfileSet: context.options.authProfileSet } : {}) });
    const artifactPath = join(context.options.outputDir, "authentication-lifecycle.automation.json");
    const artifact = { schemaVersion: 1, source: "BROWSER_LEARNED", sourceCandidateId: compilation.sourceCandidateId, requestedCategories: configuredPlan.automation.categories, generatedCategories: compilation.generatedCategories, blockers: compilation.blockers, redaction: { applied: true, secretsStored: false, authorizationIdentityStored: false }, executableCasesCompiledInMemory: compilation.generatedCategories.length };
    await writeFile(artifactPath, `${JSON.stringify(artifact, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    automation = { source: "BROWSER_LEARNED", ...(compilation.sourceCandidateId ? { sourceCandidateId: compilation.sourceCandidateId } : {}), requestedCategories: [...configuredPlan.automation.categories], generatedCategories: compilation.generatedCategories, blockers: compilation.blockers, artifactPath, secretsStored: false };
    for (const blocker of compilation.blockers) observations.push(automationBlockedObservation(blocker.category, blocker.reasons));
    if (!compilation.plan) return reportFor(configuredPlan, observations, automation);
    plan = compilation.plan;
  }
  const transport = context.createAuthenticationLifecycleHttpClient(plan.maxRequests, plan.maxResponseBytes);
  const journal = context.mutations.journal;
  const lock = context.mutations.lock();
  context.partialModules.set("authentication-lifecycle", () => { const report = reportFor(plan, observations, automation); return { pluginName: "authentication-lifecycle", authenticationLifecycle: report, findings: findingsFromReport(report) }; });
  for (const testCase of plan.cases) {
    if (context.options.abortSignal?.aborted && !context.options.workflowRecovery) break;
    if (caseChangesState(testCase) && (context.options.workflowRecovery ? [] : await journal.unresolvedCaseIds()).length > 0) {
      observations.push(blockedObservation(testCase, "UNRESOLVED_PRIOR_CLEANUP"));
      continue;
    }
    try { observations.push(await executeCase(context, transport, journal, lock, testCase, plan.maxResponseBytes)); }
    finally { await lock.release(); context.finishCaseCleanup(); await context.options.checkpointReport?.(); }
  }
  return reportFor(plan, observations, automation);
}

function reportFor(plan: NonNullable<ScanContext["options"]["plan"]["authenticationLifecycle"]>, observations: AuthenticationLifecycleCaseObservation[], automation?: AuthenticationLifecycleReport["learningAutomation"]): AuthenticationLifecycleReport {
  const fixtures = plan.fixtures ?? emptyFixtures();
  const coverage = Object.fromEntries(authenticationLifecycleCategories.map((category) => {
    const categoryItems = observations.filter((item) => item.category === category);
    return [category, {
      planned: plan.cases.filter((item) => item.category === category).length + observations.filter((item) => item.category === category && item.caseId.startsWith("automation-blocked-")).length,
      executed: categoryItems.filter((item) => item.outcome !== "BLOCKED").length,
      passed: categoryItems.filter((item) => item.outcome === "PASS").length,
      failed: categoryItems.filter((item) => item.outcome === "FAIL").length
    }];
  })) as AuthenticationLifecycleReport["coverage"];
  return {
    enabled: true,
    plannedCases: plan.cases.length + observations.filter((item) => item.caseId.startsWith("automation-blocked-")).length,
    executedCases: observations.filter((item) => item.outcome !== "BLOCKED").length,
    passedCases: observations.filter((item) => item.outcome === "PASS").length,
    failedCases: observations.filter((item) => item.outcome === "FAIL").length,
    inconclusiveCases: observations.filter((item) => item.outcome === "INCONCLUSIVE").length,
    blockedCases: observations.filter((item) => item.outcome === "BLOCKED").length,
    cleanupRequired: plan.cases.filter((item) => item.cleanupRequired).length,
    cleanupFailed: observations.filter((item) => item.cleanupOutcome === "CLEANUP_FAILED").length,
    fixtures: { inboxAdapters: fixtures.inboxes.length, totpProfiles: fixtures.totp.length, webauthnAuthenticators: fixtures.webauthn.length, oidcHarnesses: fixtures.oidc.length, providerAdapters: fixtures.providers.map((item) => item.provider), secretsStored: false },
    ...(automation ? { learningAutomation: automation } : {}),
    observations,
    coverage,
    notes: [...plan.notes, "Authentication fixtures are isolated per case; generated codes, inbox contents, WebAuthn credentials, OAuth codes, and tokens are cleared without report persistence.", "State-changing cases join the durable mutation journal and global lock; unresolved cleanup blocks later state changes.", "A FAIL means a configured security expectation was contradicted. Network errors and unavailable credentials remain inconclusive or blocked, never confirmed findings."]
  };
}

function automationBlockedObservation(category: AuthenticationLifecycleCategory, reasons: string[]): AuthenticationLifecycleCaseObservation {
  return { caseId: `automation-blocked-${category.toLowerCase()}`, label: `Browser-learned ${category.toLowerCase().replace(/_/g, " ")}`, category, actorModel: [], outcome: "BLOCKED", cleanupOutcome: "CLEANUP_NOT_REACHED", comparisonFingerprint: createHash("sha256").update(`browser-learned:${category}`).digest("hex"), steps: [], notes: reasons };
}

async function executeCase(context: ScanContext, transport: RequestSafetyBroker, journal: MutationJournal, lock: GlobalMutationLock, testCase: AuthenticationLifecycleCasePlan, maxResponseBytes: number): Promise<AuthenticationLifecycleCaseObservation> {
  const captures = new Map<string, string>();
  const snapshots = new Map<string, TransientSnapshot>();
  const observations: LifecycleStepObservation[] = [];
  let stateChangeTransmitted = false;
  let mainBlocked = false;
  let mainInconclusive = false;
  let mainFailed = false;
  const actionSteps = testCase.steps.filter((step) => step.phase !== "CLEANUP");
  const cleanupSteps = testCase.steps.filter((step) => step.phase === "CLEANUP");
  const journalCaseId = `auth-lifecycle-${testCase.id}`;
  const recovering = context.mutations.register("authenticationLifecycle", journalCaseId, testCase, { captures, snapshots });
  const fixturePlan = context.options.plan.authenticationLifecycle!.fixtures ?? emptyFixtures();
  const fixtureNetworkOrigins = [...fixturePlan.providers.flatMap((provider) => [new URL(provider.baseUrl).origin, ...(provider.tokenBaseUrl ? [new URL(provider.tokenBaseUrl).origin] : provider.provider === "FIREBASE" && new URL(provider.baseUrl).hostname === "identitytoolkit.googleapis.com" ? ["https://securetoken.googleapis.com"] : [])]), ...fixturePlan.inboxes.flatMap((inbox) => inbox.kind === "LOCAL_HTTP" ? [] : [new URL(inbox.baseUrl).origin])];
  const cleanupTransport = context.createWorkflowCleanupHttpClient(300, context.options.plan.authenticationLifecycle!.maxResponseBytes, fixtureNetworkOrigins);
  stateChangeTransmitted = recovering;
  const lifecycleNotes: string[] = [];
  const fixtureRuntime = new AuthenticationFixtureRuntime(fixturePlan, context.options.abortSignal, async (url) => {
    const response = await transport.send({ url, method: "GET", headers: { Accept: "application/json" }, streamLimitBytes: maxResponseBytes, maxStreamContentLength: maxResponseBytes, retainBodyPreview: true, disableRetries: true, disableRedirects: true, skipCache: true });
    if (response.error || response.statusCode === undefined || response.statusCode < 200 || response.statusCode >= 300) throw new Error("TEST_INBOX_TRANSPORT_ERROR");
    const body = bodyPreviewForAnalysis(response);
    if (body === undefined) throw new Error("TEST_INBOX_BODY_UNAVAILABLE");
    return JSON.parse(body);
  });
  let lockHeld = false;
  if (caseChangesState(testCase)) {
    try {
      await lock.acquire(journalCaseId); lockHeld = true;
      await journal.append(journalEntry(testCase, journalCaseId, "AUTHORIZED"));
    } catch {
      if (lockHeld) await lock.release().catch(() => undefined);
      return blockedObservation(testCase, "DURABLE_MUTATION_LOCK_OR_JOURNAL_UNAVAILABLE");
    }
  }
  try {
    for (const step of recovering ? [] : actionSteps) {
      if (mainBlocked || mainInconclusive) break;
      const result = await executeStep(context, transport, journal, journalCaseId, testCase, step, captures, snapshots, fixtureRuntime, maxResponseBytes, false);
      observations.push(result);
      if (result.transmitted && step.request.stateChanging) stateChangeTransmitted = true;
      await context.mutations.checkpoint(journalCaseId);
      if (result.outcome === "BLOCKED") mainBlocked = true;
      else if (result.outcome === "INCONCLUSIVE") mainInconclusive = true;
      else if (result.outcome === "FAIL") mainFailed = true;
    }
  } finally {
    if ((testCase.cleanupRequired && stateChangeTransmitted) || (!testCase.cleanupRequired && cleanupSteps.length > 0 && stateChangeTransmitted)) {
      for (const step of cleanupSteps) observations.push(await executeStep(context, cleanupTransport, journal, journalCaseId, testCase, step, captures, snapshots, fixtureRuntime, maxResponseBytes, true));
    }
    await fixtureRuntime.close();
  }
  const cleanupObservations = observations.filter((step) => step.phase === "CLEANUP");
  let cleanupOutcome = !testCase.cleanupRequired
    ? "NOT_REQUIRED" as const
    : !stateChangeTransmitted
      ? "CLEANUP_NOT_REACHED" as const
      : cleanupObservations.length === cleanupSteps.length && cleanupObservations.every((step) => step.outcome === "PASS")
        ? "ROLLBACK_VERIFIED" as const
        : "CLEANUP_FAILED" as const;
  if (caseChangesState(testCase)) {
    try {
      const finalStage: MutationJournalStage = !stateChangeTransmitted ? "SEALED" : cleanupOutcome === "ROLLBACK_VERIFIED" ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED";
      const finalOutcome: MutationOutcome = !stateChangeTransmitted ? "BLOCKED_BY_SAFETY" : cleanupOutcome === "ROLLBACK_VERIFIED" ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED";
      await journal.append(journalEntry(testCase, journalCaseId, finalStage, finalOutcome));
    } catch {
      cleanupOutcome = "CLEANUP_FAILED";
      lifecycleNotes.push("Cleanup may have succeeded, but RouteCairn could not durably seal the cleanup journal.");
    } finally {
      await lock.release().catch(() => lifecycleNotes.push("The global mutation lock could not be removed automatically."));
    }
  }
  for (const [key] of captures) captures.set(key, "<cleared>");
  captures.clear();
  snapshots.clear();
  return {
    caseId: testCase.id,
    label: testCase.label,
    category: testCase.category,
    actorModel: testCase.actors.map((actor) => ({ safeAlias: actor.safeAlias, authSlot: actor.authSlot, requestAuthentication: actor.requestAuthentication, relationship: actor.relationship, declaredState: actor.declaredState, ...(actor.tenantAlias ? { tenantAlias: actor.tenantAlias } : {}) })),
    outcome: mainBlocked ? "BLOCKED" : mainInconclusive ? "INCONCLUSIVE" : mainFailed ? "FAIL" : "PASS",
    cleanupOutcome,
    comparisonFingerprint: testCase.comparisonFingerprint,
    steps: observations,
    notes: [...(cleanupOutcome === "CLEANUP_FAILED" ? ["Cleanup verification failed; the operator must inspect the disposable account before reuse."] : []), ...lifecycleNotes]
  };
}

async function executeStep(context: ScanContext, transport: RequestSafetyBroker, journal: MutationJournal, journalCaseId: string, testCase: AuthenticationLifecycleCasePlan, step: LifecycleStepPlan, captures: Map<string, string>, snapshots: Map<string, TransientSnapshot>, fixtureRuntime: AuthenticationFixtureRuntime, maxResponseBytes: number, cleanupDuty: boolean): Promise<LifecycleStepObservation> {
  const actor = testCase.actors.find((item) => item.id === step.actorId)!;
  if (step.request.stateChanging && !cleanupDuty && !authorizationValid(testCase)) return stepObservation(step, actor, false, "BLOCKED", "AUTHORIZATION_EXPIRED_AT_EXECUTION");
  const profile = profileForActor(context, actor);
  if (actor.authSlot !== "anonymous" && !profile) return stepObservation(step, actor, false, "BLOCKED", "ACTOR_CREDENTIAL_UNAVAILABLE");
  const secrets = profile ? authenticationLifecycleSecrets(profile) : {};
  const capturedNames: string[] = [];
  if (step.waitBeforeMs > 0) {
    try { await abortableDelay(step.waitBeforeMs, cleanupDuty ? context.cleanupSignal(transport) : context.options.abortSignal); }
    catch { return stepObservation(step, actor, false, "INCONCLUSIVE", "WAIT_ABORTED"); }
  }
  try {
    for (const action of step.fixtureActions ?? []) capturedNames.push(...await fixtureRuntime.execute(action, captures, secrets));
  } catch (error) {
    const reason = error instanceof Error && /TIMEOUT|ABORTED/.test(error.message) ? "AUTH_FIXTURE_TIMEOUT_OR_ABORT" : "AUTH_FIXTURE_EXECUTION_ERROR";
    return { ...stepObservation(step, actor, false, "INCONCLUSIVE", reason), capturesRecorded: capturedNames };
  }
  let url: string;
  let headers: Record<string, string>;
  let body: string | undefined;
  try {
    url = expandUrlString(step.request.url, secrets, captures);
    headers = { ...(profile && actor.requestAuthentication === "PROFILE" ? authHeadersForProfile(profile) : {}), ...expandRecord(step.request.headers, secrets, captures) };
    if (step.request.fields) {
      const expanded = expandValue(step.request.fields, secrets, captures) as Record<string, unknown>;
      if (step.request.bodyFormat === "FORM") {
        body = new URLSearchParams(Object.entries(expanded).map(([key, value]) => [key, String(value)] as [string, string])).toString();
        headers[findHeader(headers, "content-type") ?? "Content-Type"] = "application/x-www-form-urlencoded";
      } else {
        body = JSON.stringify(expanded);
        headers[findHeader(headers, "content-type") ?? "Content-Type"] = "application/json";
      }
    }
  } catch {
    return stepObservation(step, actor, false, "BLOCKED", "SECRET_OR_CAPTURE_REFERENCE_UNAVAILABLE");
  }
  const scope = context.scopeMatcher.decide(url, step.request.method);
  const fixtureOrigins = new Set(context.options.plan.authenticationLifecycle?.fixtures?.providers.flatMap((provider) => [new URL(provider.baseUrl).origin, ...(provider.tokenBaseUrl ? [new URL(provider.tokenBaseUrl).origin] : provider.provider === "FIREBASE" && new URL(provider.baseUrl).hostname === "identitytoolkit.googleapis.com" ? ["https://securetoken.googleapis.com"] : [])]) ?? []);
  if (!scope.allowed || (new URL(url).origin !== context.options.plan.authenticationLifecycle?.targetOrigin && !fixtureOrigins.has(new URL(url).origin))) return stepObservation(step, actor, false, "BLOCKED", "EXPANDED_REQUEST_OUT_OF_SCOPE");
  if (step.request.stateChanging) {
    try { await journal.append({ ...journalEntry(testCase, journalCaseId, cleanupDuty ? "ROLLBACK_SENT" : "MUTATION_ARMED"), requestMethod: step.request.method, requestUrl: safeRequestUrl(url), ...(body ? { requestBodyAttestation: journal.attestBody(body) } : {}) }); }
    catch { return stepObservation(step, actor, false, "BLOCKED", "MUTATION_INTENT_JOURNAL_FAILED"); }
  }
  let response: HttpResponse;
  try { response = await transport.send({ url, method: step.request.method, headers, ...(body !== undefined ? { body } : {}), streamLimitBytes: maxResponseBytes, maxStreamContentLength: maxResponseBytes, retainBodyPreview: true, disableRetries: true, disableRedirects: true, skipCache: true }); }
  catch {
    if (step.request.stateChanging) await journal.append({ ...journalEntry(testCase, journalCaseId, cleanupDuty ? "ROLLBACK_SENT" : "MUTATION_SENT"), requestMethod: step.request.method, requestUrl: safeRequestUrl(url), note: "Transport threw after mutation intent was armed; target state is uncertain." }).catch(() => undefined);
    return stepObservation(step, actor, step.request.stateChanging, "INCONCLUSIVE", "TRANSPORT_ERROR");
  }
  const potentiallyTransmitted = requestPotentiallyTransmitted(response);
  if (step.request.stateChanging) {
    try {
      await journal.append({ ...journalEntry(testCase, journalCaseId, potentiallyTransmitted ? (cleanupDuty ? "ROLLBACK_SENT" : "MUTATION_SENT") : "SEALED"), requestMethod: step.request.method, requestUrl: safeRequestUrl(url), ...(response.statusCode ? { responseStatus: response.statusCode } : {}), ...(potentiallyTransmitted ? {} : { outcome: "BLOCKED_BY_SAFETY" as const }) });
    } catch { return stepObservation(step, actor, potentiallyTransmitted, "INCONCLUSIVE", "POST_REQUEST_JOURNAL_FAILED"); }
  }
  if (response.error) return stepObservation(step, actor, potentiallyTransmitted, potentiallyTransmitted ? "INCONCLUSIVE" : "BLOCKED", transportReason(response));
  const snapshot = snapshotFor(response);
  snapshots.set(step.id, snapshot);
  for (const capture of step.captures) {
    const value = captureValue(capture, response, snapshot.json);
    if (value !== undefined && value.length > 0) {
      captures.set(capture.name, value);
      capturedNames.push(capture.name);
    }
  }
  const assertions = step.assertions.map((assertion) => evaluateAssertion(assertion, response, snapshot, snapshots, captures, secrets));
  const outcome = assertions.some((item) => !item.matched) ? "FAIL" as const : "PASS" as const;
  return {
    stepId: step.id,
    phase: step.phase,
    actorAlias: actor.safeAlias,
    method: step.request.method,
    url: redactLifecycleUrl(url, secrets, captures),
    stateChanging: step.request.stateChanging,
    transmitted: potentiallyTransmitted,
    ...(response.statusCode ? { statusCode: response.statusCode } : {}),
    ...(response.contentType ? { contentType: response.contentType } : {}),
    responseLengthBand: lengthBand(snapshot.bodyLength),
    responseShapeFingerprint: createHash("sha256").update(snapshot.shape).digest("hex"),
    capturesRecorded: capturedNames,
    assertions,
    outcome
  };
}

function evaluateAssertion(assertion: LifecycleAssertionPlan, response: HttpResponse, current: TransientSnapshot, snapshots: Map<string, TransientSnapshot>, captures: Map<string, string>, secrets: Record<string, string>): LifecycleAssertionObservation {
  let matched = false;
  let reasonCode = "EXPECTATION_MISMATCH";
  if (assertion.kind === "STATUS_IN") matched = response.statusCode !== undefined && assertion.values.includes(response.statusCode);
  else if (assertion.kind === "STATUS_NOT_IN") matched = response.statusCode !== undefined && !assertion.values.includes(response.statusCode);
  else if (assertion.kind === "HEADER_PRESENT") matched = header(response, assertion.header) !== undefined;
  else if (assertion.kind === "HEADER_ABSENT") matched = header(response, assertion.header) === undefined;
  else if (assertion.kind === "JSON_EQUALS") matched = deepEqual(valueAt(current.json, assertion.path), assertion.expected);
  else if (assertion.kind === "JSON_EQUALS_SECRET") matched = secrets[assertion.secretRef] !== undefined && String(valueAt(current.json, assertion.path)) === secrets[assertion.secretRef];
  else if (assertion.kind === "REDIRECT_LOCATION_ALLOWED") {
    const location = header(response, "location");
    try { const parsed = new URL(location ?? "", response.finalUrl); matched = assertion.allowedOrigins.includes(parsed.origin) && assertion.allowedPathPrefixes.some((prefix) => parsed.pathname === prefix || parsed.pathname.startsWith(`${prefix}/`)); } catch { matched = false; }
  }
  else if (assertion.kind === "REDIRECT_QUERY_EQUALS_SECRET") {
    const location = header(response, "location");
    try { const parsed = new URL(location ?? "", response.finalUrl); matched = secrets[assertion.secretRef] !== undefined && parsed.searchParams.get(assertion.parameter) === secrets[assertion.secretRef]; } catch { matched = false; }
  }
  else if (assertion.kind === "CAPTURE_ROTATED" || assertion.kind === "CAPTURE_UNCHANGED") {
    const left = captures.get(assertion.capture);
    const right = assertion.comparedTo.source === "SECRET" ? secrets[assertion.comparedTo.ref] : captures.get(assertion.comparedTo.ref);
    matched = left !== undefined && right !== undefined && (assertion.kind === "CAPTURE_ROTATED" ? left !== right : left === right);
  } else {
    const prior = snapshots.get(assertion.stepId);
    if (prior) {
      const sameStatus = !assertion.compareStatus || prior.statusCode === current.statusCode;
      const sameShape = !assertion.compareShape || prior.shape === current.shape;
      const sameBody = !assertion.compareBodyDigest || prior.bodyDigest === current.bodyDigest;
      const similarTiming = !assertion.compareTiming || Math.abs(prior.responseTimeMs - current.responseTimeMs) <= assertion.maxResponseTimeDeltaMs;
      const similarLength = Math.abs(prior.bodyLength - current.bodyLength) <= assertion.maxLengthDelta;
      const similar = sameStatus && sameShape && sameBody && similarTiming && similarLength;
      matched = assertion.kind === "RESPONSE_SIMILAR" ? similar : !similar;
    }
  }
  if (matched) reasonCode = "EXPECTATION_MATCHED";
  return { kind: assertion.kind, matched, reasonCode };
}

function captureValue(capture: LifecycleStepPlan["captures"][number], response: HttpResponse, json: unknown): string | undefined {
  if (capture.source === "JSON") { const value = valueAt(json, capture.path); return value === undefined || value === null || typeof value === "object" ? undefined : String(value); }
  if (capture.source === "HEADER") return header(response, capture.header);
  const setCookie = Object.entries(headersForAnalysis(response)).find(([name]) => name.toLowerCase() === "set-cookie")?.[1];
  const lines = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  for (const line of lines) { const match = line.match(new RegExp(`(?:^|,\\s*)${escapeRegex(capture.cookie)}=([^;]*)`, "i")); if (match?.[1] !== undefined) return match[1]; }
  return undefined;
}

function snapshotFor(response: HttpResponse): TransientSnapshot {
  const body = bodyPreviewForAnalysis(response) ?? "";
  let json: unknown;
  try { json = JSON.parse(body); } catch { json = undefined; }
  const shape = json === undefined ? `text:${response.contentType ?? "unknown"}` : JSON.stringify(jsonShape(json));
  return { ...(response.statusCode ? { statusCode: response.statusCode } : {}), bodyLength: response.contentLength ?? body.length, bodyDigest: createHash("sha256").update(body).digest("hex"), responseTimeMs: response.responseTimeMs, shape, ...(json !== undefined ? { json } : {}) };
}

function jsonShape(value: unknown): unknown {
  if (Array.isArray(value)) return [value.length ? jsonShape(value[0]) : "empty"];
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value as Record<string, unknown>).sort().map((key) => [key, jsonShape((value as Record<string, unknown>)[key])]));
  return value === null ? "null" : typeof value;
}

function profileForActor(context: ScanContext, actor: LifecycleActorPlan): AuthProfile | undefined {
  if (actor.authSlot === "anonymous") return undefined;
  if (actor.authSlot === "primary") return context.options.authProfile;
  return actor.authSlot === "account_a" ? context.options.authProfileSet?.accountA : context.options.authProfileSet?.accountB;
}

function authorizationValid(testCase: AuthenticationLifecycleCasePlan): boolean {
  const auth = testCase.authorization;
  return auth.mode === "CONTROLLED_LIFECYCLE" && Boolean(auth.authorizedAt && auth.expiresAt && auth.authorizationIdentityConfirmed && auth.changeTicketConfirmed && auth.confirmationAccepted && auth.disposableAccounts && new Date(auth.authorizedAt!).getTime() <= Date.now() && new Date(auth.expiresAt!).getTime() > Date.now() && (auth.environment !== "PRODUCTION" || auth.productionAcknowledged));
}

function testCaseOrigin(testCase: AuthenticationLifecycleCasePlan): string { return new URL(testCase.steps[0]!.request.url).origin; }
function expandRecord(record: Readonly<Record<string, string>>, secrets: Record<string, string>, captures: Map<string, string>): Record<string, string> { return Object.fromEntries(Object.entries(record).map(([key, value]) => [key, expandString(value, secrets, captures)])); }
function expandValue(value: unknown, secrets: Record<string, string>, captures: Map<string, string>): unknown { if (Array.isArray(value)) return value.map((entry) => expandValue(entry, secrets, captures)); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, expandValue(entry, secrets, captures)])); return typeof value === "string" ? expandString(value, secrets, captures) : value; }
function expandString(value: string, secrets: Record<string, string>, captures: Map<string, string>): string { return value.replace(/\{\{(SECRET|CAPTURE):([A-Za-z0-9._-]+)\}\}/g, (_match, kind: string, name: string) => { const resolved = kind === "SECRET" ? secrets[name] : captures.get(name); if (resolved === undefined) throw new Error("missing reference"); return resolved; }); }
function expandUrlString(value: string, secrets: Record<string, string>, captures: Map<string, string>): string { return value.replace(/\{\{(SECRET|CAPTURE):([A-Za-z0-9._-]+)\}\}/g, (_match, kind: string, name: string) => { const resolved = kind === "SECRET" ? secrets[name] : captures.get(name); if (resolved === undefined) throw new Error("missing reference"); return encodeURIComponent(resolved); }); }
function redactLifecycleUrl(value: string, secrets: Readonly<Record<string, string>>, captures: ReadonlyMap<string, string>): string { let redacted = redactSensitiveUrl(value); for (const secret of [...Object.values(secrets), ...captures.values()].filter(Boolean).sort((left, right) => right.length - left.length)) { redacted = redacted.split(secret).join("<redacted>").split(encodeURIComponent(secret)).join("%3Credacted%3E"); } return redacted; }
function header(response: HttpResponse, name: string): string | undefined { const value = Object.entries(headersForAnalysis(response)).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1]; return typeof value === "string" ? value : value?.join(", "); }
function findHeader(headers: Record<string, string>, name: string): string | undefined { return Object.keys(headers).find((key) => key.toLowerCase() === name); }
function valueAt(value: unknown, path: string): unknown { let current = value; for (const part of path.replace(/\[(\d+)\]/g, ".$1").split(".")) { if (current === null || current === undefined || (typeof current !== "object" && !Array.isArray(current))) return undefined; current = (current as Record<string, unknown>)[part]; } return current; }
function deepEqual(left: unknown, right: unknown): boolean { return JSON.stringify(left) === JSON.stringify(right); }
function escapeRegex(value: string): string { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function lengthBand(length: number): string { if (length === 0) return "0"; if (length <= 64) return "1-64"; if (length <= 256) return "65-256"; if (length <= 1024) return "257-1024"; if (length <= 8192) return "1025-8192"; return ">8192"; }
function transportReason(response: HttpResponse): string { return response.error?.name === "DeclaredContentLengthExceeded" ? "RESPONSE_LIMIT_EXCEEDED" : "TRANSPORT_ERROR"; }
function abortableDelay(ms: number, signal?: AbortSignal): Promise<void> { return new Promise((resolve, reject) => { if (signal?.aborted) return reject(new Error("aborted")); const timer = setTimeout(resolve, ms); signal?.addEventListener("abort", () => { clearTimeout(timer); reject(new Error("aborted")); }, { once: true }); }); }
function stepObservation(step: LifecycleStepPlan, actor: LifecycleActorPlan, transmitted: boolean, outcome: LifecycleStepObservation["outcome"], reasonCode: string): LifecycleStepObservation { return { stepId: step.id, phase: step.phase, actorAlias: actor.safeAlias, method: step.request.method, url: redactSensitiveUrl(step.request.url), stateChanging: step.request.stateChanging, transmitted, capturesRecorded: [], assertions: [], outcome, reasonCode }; }
function caseChangesState(testCase: AuthenticationLifecycleCasePlan): boolean { return testCase.steps.some((step) => step.request.stateChanging); }
function requestPotentiallyTransmitted(response: HttpResponse): boolean { return !["RequestBudgetExceeded", "OutOfScopeRequest", "ControlledMutationBlocked"].includes(response.error?.name ?? ""); }
function journalEntry(testCase: AuthenticationLifecycleCasePlan, caseId: string, stage: MutationJournalStage, outcome?: MutationOutcome) { return { caseId, stage, mode: "CONTROLLED_MUTATION" as const, targetOrigin: testCaseOrigin(testCase), targetIdentityFingerprint: testCase.comparisonFingerprint, ...(outcome ? { outcome } : {}), note: "Authentication lifecycle entry; credentials, tokens, captures, account identifiers, and response bodies omitted." }; }
function blockedObservation(testCase: AuthenticationLifecycleCasePlan, reason: string): AuthenticationLifecycleCaseObservation { return { caseId: testCase.id, label: testCase.label, category: testCase.category, actorModel: testCase.actors.map((actor) => ({ safeAlias: actor.safeAlias, authSlot: actor.authSlot, requestAuthentication: actor.requestAuthentication, relationship: actor.relationship, declaredState: actor.declaredState, ...(actor.tenantAlias ? { tenantAlias: actor.tenantAlias } : {}) })), outcome: "BLOCKED", cleanupOutcome: testCase.cleanupRequired ? "CLEANUP_NOT_REACHED" : "NOT_REQUIRED", comparisonFingerprint: testCase.comparisonFingerprint, steps: [], notes: [reason] }; }
function findingsFromReport(report: AuthenticationLifecycleReport): Finding[] {
  const scorer = new RiskScorer();
  return report.observations.filter((item) => item.outcome === "FAIL").map((item) => {
    const severity = severityFor(item.category);
    const first = item.steps.find((step) => step.outcome === "FAIL");
    const base = { id: `finding-${createHash("sha1").update(`auth-lifecycle:${item.comparisonFingerprint}`).digest("hex").slice(0, 12)}`, title: titleFor(item.category), type: "Authentication Lifecycle Issue" as const, severity, confidence: "High" as const, url: first?.url ?? "redacted://authentication-lifecycle", method: first?.method ?? "N/A", ...(first?.statusCode ? { statusCode: first.statusCode } : {}), evidence: { url: first?.url ?? "redacted://authentication-lifecycle", method: first?.method ?? "N/A", ...(first?.statusCode ? { statusCode: first.statusCode } : {}), source: "authentication-lifecycle", severityReason: `Explicit ${item.category} lifecycle expectation was contradicted.`, reproductionNotes: [`Case ${item.caseId}; comparison fingerprint ${item.comparisonFingerprint}.`, "Credential and token values are intentionally absent from evidence."] }, impact: impactFor(item.category), recommendation: recommendationFor(item.category), manualTestingSuggestions: ["Review the disposable test account and the redacted lifecycle step evidence.", "Re-run the same explicit case after remediation."], tags: ["authentication", "session-lifecycle", item.category.toLowerCase()], falsePositiveStatus: "likely-valid" as const, workflowCase: { id: item.caseId, comparisonFingerprint: item.comparisonFingerprint, cleanupOutcome: item.cleanupOutcome }, sourceModule: "authentication-lifecycle", timestamp: new Date().toISOString() };
    return { ...base, riskScore: scorer.score(base) };
  });
}
function severityFor(category: AuthenticationLifecycleCategory): "Medium" | "High" { return ["LOGIN_ENUMERATION_RESISTANCE", "IDLE_EXPIRATION", "ABSOLUTE_EXPIRATION"].includes(category) ? "Medium" : "High"; }
function titleFor(category: AuthenticationLifecycleCategory): string { return `Authentication lifecycle expectation failed: ${category.toLowerCase().replace(/_/g, " ")}`; }
function impactFor(category: AuthenticationLifecycleCategory): string { return `The configured ${category.toLowerCase().replace(/_/g, " ")} boundary did not behave as required, which may permit account discovery, session persistence, token replay, identity confusion, or unauthorized account control.`; }
function recommendationFor(category: AuthenticationLifecycleCategory): string { return `Enforce the ${category.toLowerCase().replace(/_/g, " ")} lifecycle server-side, invalidate superseded credentials atomically, bind tokens to the intended account and transaction, and add regression coverage for this exact case.`; }
function disabledReport(): AuthenticationLifecycleReport { return { enabled: false, plannedCases: 0, executedCases: 0, passedCases: 0, failedCases: 0, inconclusiveCases: 0, blockedCases: 0, cleanupRequired: 0, cleanupFailed: 0, fixtures: { inboxAdapters: 0, totpProfiles: 0, webauthnAuthenticators: 0, oidcHarnesses: 0, providerAdapters: [], secretsStored: false }, observations: [], coverage: Object.fromEntries(authenticationLifecycleCategories.map((category) => [category, { planned: 0, executed: 0, passed: 0, failed: 0 }])) as AuthenticationLifecycleReport["coverage"], notes: ["Authentication lifecycle testing was not configured."] }; }
function emptyFixtures(): NonNullable<NonNullable<ScanContext["options"]["plan"]["authenticationLifecycle"]>["fixtures"]> { return { inboxes: [], totp: [], webauthn: [], oidc: [], providers: [] }; }
