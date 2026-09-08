import { createHash } from "node:crypto";
import { join } from "node:path";
import type { HttpRequest, HttpResponse } from "../http/HttpTypes.js";
import { bodyPreviewForAnalysis } from "../http/TransientResponseAnalysis.js";
import type { TargetAuthorization } from "../authorization/TargetAuthorization.js";
import { securityContractFingerprint } from "../comparisons/SecurityContractFingerprint.js";
import { authorizeControlledMutation, MutationSafetyError } from "./MutationPolicy.js";
import { GlobalMutationLock, MutationJournal, safeRequestUrl } from "./MutationJournal.js";
import { MutationRecoveryVault } from "./MutationRecoveryVault.js";
import type { ControlledMutationBrowserObserver, ControlledMutationContract, ControlledMutationResult, MutationAssertion, MutationJournalStage, MutationRecoveryBundle, MutationTransport, MutationVerification, OffensiveExecutionMode } from "./ControlledMutationTypes.js";

export interface ControlledMutationExecutorOptions { journalDirectory: string; checkpointReport?: () => Promise<void>; globalLockPath?: string; sleep?: (milliseconds: number) => Promise<void>; cleanupSleep?: (milliseconds: number) => Promise<void>; cleanupTransport?: MutationTransport; browserObserver?: ControlledMutationBrowserObserver; targetAuthorization?: TargetAuthorization }
type CleanupOutcome = "ROLLBACK_VERIFIED" | "CLEANUP_FAILED";

export class ControlledMutationExecutor {
  private readonly journal: MutationJournal;
  private readonly vault: MutationRecoveryVault;
  private readonly lock: GlobalMutationLock;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly cleanupTransport: MutationTransport;
  private readonly cleanupSleep: (milliseconds: number) => Promise<void>;
  private readonly browserObserver: ControlledMutationBrowserObserver | undefined;
  private readonly targetAuthorization: TargetAuthorization | undefined;

  public constructor(private readonly transport: MutationTransport, options: ControlledMutationExecutorOptions) {
    this.journal = new MutationJournal(join(options.journalDirectory, "mutation-journal.json"), undefined, async () => { await options.checkpointReport?.(); });
    this.vault = new MutationRecoveryVault(options.journalDirectory);
    this.lock = new GlobalMutationLock(options.globalLockPath ?? join(options.journalDirectory, "global-mutation.lock"));
    this.sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    this.cleanupTransport = options.cleanupTransport ?? transport;
    this.cleanupSleep = options.cleanupSleep ?? this.sleep;
    this.browserObserver = options.browserObserver;
    this.targetAuthorization = options.targetAuthorization;
  }

  public async execute(contract: ControlledMutationContract): Promise<ControlledMutationResult> {
    const notes: string[] = [];
    try { authorizeControlledMutation(contract); }
    catch (error) {
      if (!(error instanceof MutationSafetyError)) throw error;
      const note = `${error.safetyCode}: ${error.message}`;
      // A rejected retry must not overwrite the unresolved state of an earlier
      // execution with the same case ID. Its blocked result is sufficient.
      try {
        await this.lock.acquire(contract.caseId);
        await this.journal.append({ ...base(contract, "SEALED"), outcome: "BLOCKED_BY_SAFETY", note });
      } catch { /* Existing obligations take precedence over a rejection audit. */ }
      finally { await this.lock.release(); }
      return simpleResult(contract.caseId, "BLOCKED_BY_SAFETY", "BLOCKED_BY_SAFETY", "NOT_REQUIRED", this.journal.path, [note], comparisonIdentity(contract));
    }

    try { await this.lock.acquire(contract.caseId); }
    catch { return simpleResult(contract.caseId, "BLOCKED_BY_SAFETY", "BLOCKED_BY_SAFETY", "NOT_REQUIRED", this.journal.path, ["Shared mutation coordination is unavailable or prior cleanup is unresolved."], comparisonIdentity(contract)); }
    let mutationArmed = false;
    let recoveryRef: string | undefined;
    let actorIdentityResponseHash: string | undefined;
    let targetIdentityResponseHash: string | undefined;
    let preStateHash: string | undefined;
    let attackResponseHash: string | undefined;
    let protectedActionResponseHash: string | undefined;
    let protectedActionVerified = false;
    let browserProtectedActionVerified: boolean | undefined;
    let securityOutcome: ControlledMutationResult["securityOutcome"] = "INCONCLUSIVE";
    try {
      const pendingCleanup = await this.journal.unresolvedCaseIds();
      if (pendingCleanup.length > 0) {
        const note = `New mutations are blocked until cleanup is verified for: ${pendingCleanup.join(", ")}.`;
        return simpleResult(contract.caseId, "BLOCKED_BY_SAFETY", "BLOCKED_BY_SAFETY", "NOT_REQUIRED", this.journal.path, [note], comparisonIdentity(contract));
      }
      await this.journal.append(base(contract, "AUTHORIZED"));
      if (contract.identity) {
        const actorIdentity = await this.verify(contract.identity);
        notes.push(...actorIdentity.notes.map((note) => `Actor identity: ${note}`));
        if (!actorIdentity.matched || !actorIdentity.response.bodyHash) {
          await this.journal.append({ ...base(contract, "SEALED"), outcome: "INCONCLUSIVE", note: "Actor identity verification failed; no precondition or mutation request was sent." });
          return simpleResult(contract.caseId, "INCONCLUSIVE", "INCONCLUSIVE", "NOT_REQUIRED", this.journal.path, notes, comparisonIdentity(contract));
        }
        actorIdentityResponseHash = actorIdentity.response.bodyHash;
        await this.journal.append({ ...base(contract, "ACTOR_IDENTITY_VERIFIED"), requestMethod: "GET", requestUrl: safeRequestUrl(contract.identity.request.url), responseStatus: actorIdentity.response.statusCode, responseHash: actorIdentityResponseHash });
      }
      const preState = await this.verify(contract.precondition);
      notes.push(...preState.notes.map((note) => `Disposable target precondition: ${note}`));
      if (!preState.matched || !preState.response.bodyHash) {
        await this.journal.append({ ...base(contract, "SEALED"), outcome: "INCONCLUSIVE", note: "Precondition verification failed; no mutation was sent." });
        return simpleResult(contract.caseId, "INCONCLUSIVE", "INCONCLUSIVE", "NOT_REQUIRED", this.journal.path, notes, comparisonIdentity(contract));
      }
      preStateHash = preState.response.bodyHash;
      targetIdentityResponseHash = preState.response.bodyHash;
      await this.journal.append({ ...base(contract, "TARGET_IDENTITY_VERIFIED"), requestMethod: "GET", requestUrl: safeRequestUrl(contract.precondition.request.url), responseStatus: preState.response.statusCode, responseHash: targetIdentityResponseHash });
      await this.journal.append({ ...base(contract, "PRE_STATE_CAPTURED"), responseStatus: preState.response.statusCode, responseHash: preStateHash });
      const recovery: MutationRecoveryBundle = {
        caseId: contract.caseId,
        intent: contract.intent,
        securityCategory: contract.securityCategory,
        targetOrigin: contract.targetOrigin,
        targetIdentityFingerprint: contract.target.identityFingerprint,
        authorizationExpiresAt: contract.authorization.expiresAt,
        contractDigest: comparisonIdentity(contract),
        ...(contract.actor ? { actorBinding: contract.actor } : {}),
        ...(contract.identity && actorIdentityResponseHash ? { actorIdentityVerification: contract.identity, actorIdentityResponseHash } : {}),
        targetIdentityVerification: { request: contract.precondition.request, assertions: [contract.target.identityAssertion], attempts: contract.precondition.attempts, delayMs: contract.precondition.delayMs },
        targetIdentityResponseHash,
        ...(contract.approvalBinding ? { approvalBinding: contract.approvalBinding } : {}),
        ...(this.targetAuthorization ? { targetAuthorization: this.targetAuthorization } : {}),
        rollbackRequest: contract.rollback.request as HttpRequest,
        rollbackVerification: contract.rollback.verification,
        preStateHash
      };
      recoveryRef = await this.vault.seal(recovery);
      await this.journal.append({ ...base(contract, "MUTATION_ARMED"), requestMethod: contract.attack.request.method, requestUrl: safeRequestUrl(contract.attack.request.url), requestBodyAttestation: this.journal.attestBody(contract.attack.request.body), recoveryBundleRef: recoveryRef, note: "Encrypted recovery material and mutation intent were durably flushed before network transmission." });
      mutationArmed = true;

      const attack = await this.transport.send(contract.attack.request as HttpRequest);
      attackResponseHash = attack.bodyHash;
      await this.journal.append({ ...base(contract, "MUTATION_SENT"), requestMethod: contract.attack.request.method, requestUrl: safeRequestUrl(contract.attack.request.url), requestBodyAttestation: this.journal.attestBody(contract.attack.request.body), responseStatus: attack.statusCode, responseHash: attack.bodyHash, recoveryBundleRef: recoveryRef });

      const impact = await this.verify(contract.impact);
      notes.push(...impact.notes);
      securityOutcome = impact.matched
        ? contract.intent === "SECURITY_NEGATIVE" ? "EXPLOIT_PROVEN" : "EXPECTED_MUTATION_VERIFIED"
        : rejected(attack)
          ? contract.intent === "SECURITY_NEGATIVE" ? "SECURE_FOR_CASE" : "EXPECTED_MUTATION_REJECTED"
          : "INCONCLUSIVE";
      await this.journal.append({ ...base(contract, "IMPACT_VERIFIED"), responseStatus: impact.response.statusCode, responseHash: impact.response.bodyHash, outcome: securityOutcome });
      if (contract.protectedAction) {
        const protectedAction = await this.verify(contract.protectedAction);
        protectedActionResponseHash = protectedAction.response.bodyHash;
        protectedActionVerified = protectedAction.matched;
        notes.push(...protectedAction.notes);
        if (!protectedAction.matched) securityOutcome = "INCONCLUSIVE";
      }

      if (this.browserObserver) {
        const browserProof = await this.browserObserver.verifyProtectedAction(contract);
        if (browserProof.configured) {
          browserProtectedActionVerified = browserProof.matched;
          notes.push(...browserProof.notes);
          if (!browserProof.matched) securityOutcome = "INCONCLUSIVE";
        }
      }

      const cleanup = await this.rollback(contract.rollback.request as HttpRequest, contract.rollback.verification, preStateHash, contract, recoveryRef);
      notes.push(...cleanup.notes);
      return {
        caseId: contract.caseId,
        outcome: cleanup.outcome === "ROLLBACK_VERIFIED" ? securityOutcome : cleanup.outcome,
        securityOutcome,
        cleanupOutcome: cleanup.outcome,
        ...(actorIdentityResponseHash ? { actorIdentityResponseHash } : {}),
        ...(targetIdentityResponseHash ? { targetIdentityResponseHash } : {}),
        preStateHash,
        ...(attackResponseHash ? { attackResponseHash } : {}),
        ...(impact.response.bodyHash ? { verificationResponseHash: impact.response.bodyHash } : {}),
        ...(protectedActionResponseHash ? { protectedActionResponseHash } : {}),
        protectedActionVerified,
        ...(browserProtectedActionVerified !== undefined ? { browserProtectedActionVerified } : {}),
        ...(cleanup.browserVerified !== undefined ? { browserRollbackVerified: cleanup.browserVerified } : {}),
        ...(cleanup.responseHash ? { rollbackResponseHash: cleanup.responseHash } : {}),
        journalPath: this.journal.path,
        comparisonIdentity: comparisonIdentity(contract),
        notes
      };
    } catch (error) {
      notes.push(error instanceof Error ? error.message : "Unknown controlled mutation failure.");
      if (mutationArmed && recoveryRef) {
        const cleanup = await this.rollback(contract.rollback.request as HttpRequest, contract.rollback.verification, preStateHash, contract, recoveryRef).catch((rollbackError: unknown) => ({ outcome: "CLEANUP_FAILED" as CleanupOutcome, notes: [rollbackError instanceof Error ? rollbackError.message : "Rollback failed."], responseHash: undefined }));
        notes.push(...cleanup.notes);
        return { caseId: contract.caseId, outcome: cleanup.outcome, securityOutcome, cleanupOutcome: cleanup.outcome, ...(actorIdentityResponseHash ? { actorIdentityResponseHash } : {}), ...(targetIdentityResponseHash ? { targetIdentityResponseHash } : {}), ...(preStateHash ? { preStateHash } : {}), ...(attackResponseHash ? { attackResponseHash } : {}), journalPath: this.journal.path, comparisonIdentity: comparisonIdentity(contract), notes };
      }
      await this.journal.append({ ...base(contract, "SEALED"), outcome: "INCONCLUSIVE", note: notes.at(-1) });
      return simpleResult(contract.caseId, "INCONCLUSIVE", "INCONCLUSIVE", "NOT_REQUIRED", this.journal.path, notes, comparisonIdentity(contract));
    } finally { await this.lock.release(); }
  }

  public async recover(bundlePath: string, caseId: string): Promise<ControlledMutationResult> {
    const bundle = await this.vault.open(bundlePath, caseId);
    if (bundle.caseId !== caseId) throw new MutationSafetyError("Recovery case binding mismatch.", "RECOVERY_CASE_MISMATCH");
    if (bundle.authorizationExpiresAt && Date.parse(bundle.authorizationExpiresAt) <= Date.now()) throw new MutationSafetyError("Recovery authorization has expired.", "RECOVERY_AUTHORIZATION_EXPIRED");
    if (bundle.targetOrigin !== new URL(bundle.rollbackRequest.url).origin) throw new MutationSafetyError("Recovery rollback endpoint does not match the bound target origin.", "RECOVERY_ORIGIN_MISMATCH");
    for (const verification of [bundle.actorIdentityVerification, bundle.targetIdentityVerification, bundle.rollbackVerification]) {
      if (verification && new URL(verification.request.url).origin !== bundle.targetOrigin) throw new MutationSafetyError("A recovery verification endpoint does not match the bound target origin.", "RECOVERY_ORIGIN_MISMATCH");
    }
    if (bundle.actorBinding && !bundle.actorIdentityVerification) throw new MutationSafetyError("Recovery actor binding is missing its identity verification.", "RECOVERY_ACTOR_BINDING_INCOMPLETE");
    await this.lock.acquire(caseId, true);
    try {
      const bindingNotes: string[] = [];
      if (bundle.actorBinding && bundle.actorIdentityVerification) {
        const actor = await this.verify(bundle.actorIdentityVerification, undefined, this.cleanupTransport);
        bindingNotes.push(...actor.notes.map((note) => `Recovery actor identity: ${note}`));
        const expectedFingerprint = valueFingerprint(bundle.actorBinding.identityAssertion.expectedValue);
        if (!actor.matched || expectedFingerprint !== bundle.actorBinding.identityFingerprint) return await this.recoveryBindingFailure(bundle, bundlePath, actor.response, bindingNotes, "Recovery actor identity did not match; rollback was not sent to an unverified principal.");
        await this.journal.append({ ...recoveryBase(bundle, "ACTOR_IDENTITY_VERIFIED"), requestMethod: "GET", requestUrl: safeRequestUrl(bundle.actorIdentityVerification.request.url), responseStatus: actor.response.statusCode, responseHash: actor.response.bodyHash, recoveryBundleRef: bundlePath });
      }
      if (bundle.targetIdentityVerification) {
        const target = await this.verify(bundle.targetIdentityVerification, undefined, this.cleanupTransport);
        bindingNotes.push(...target.notes.map((note) => `Recovery disposable target identity: ${note}`));
        const assertion = bundle.targetIdentityVerification.assertions?.find((item) => item.operator === "EQUALS");
        if (!target.matched || !assertion || !bundle.targetIdentityFingerprint || valueFingerprint(assertion.expectedValue) !== bundle.targetIdentityFingerprint) return await this.recoveryBindingFailure(bundle, bundlePath, target.response, bindingNotes, "Recovery disposable object identity did not match; rollback was not sent to an unverified object.");
        await this.journal.append({ ...recoveryBase(bundle, "TARGET_IDENTITY_VERIFIED"), requestMethod: "GET", requestUrl: safeRequestUrl(bundle.targetIdentityVerification.request.url), responseStatus: target.response.statusCode, responseHash: target.response.bodyHash, recoveryBundleRef: bundlePath });
      }
      const response = await this.cleanupTransport.send(bundle.rollbackRequest);
      await this.journal.append({ ...recoveryBase(bundle, "ROLLBACK_SENT"), requestMethod: bundle.rollbackRequest.method, requestUrl: safeRequestUrl(bundle.rollbackRequest.url), requestBodyAttestation: this.journal.attestBody(bundle.rollbackRequest.body), responseStatus: response.statusCode, responseHash: response.bodyHash, recoveryBundleRef: bundlePath });
      const verified = await this.verify(bundle.rollbackVerification, bundle.preStateHash, this.cleanupTransport);
      const cleanup: CleanupOutcome = verified.matched ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED";
      await this.journal.append({ ...recoveryBase(bundle, cleanup), outcome: cleanup, responseStatus: verified.response.statusCode, responseHash: verified.response.bodyHash, recoveryBundleRef: verified.matched ? undefined : bundlePath, note: verified.notes.join(" ") });
      if (verified.matched) await this.vault.remove(bundlePath);
      return simpleResult(caseId, cleanup, "INCONCLUSIVE", cleanup, this.journal.path, [...bindingNotes, ...verified.notes], bundle.contractDigest ?? createHash("sha256").update(`recovery:${bundle.targetOrigin}:${caseId}`).digest("hex"));
    } finally { await this.lock.release(); }
  }

  private async recoveryBindingFailure(bundle: MutationRecoveryBundle, bundlePath: string, response: HttpResponse, notes: string[], reason: string): Promise<ControlledMutationResult> {
    notes.push(reason);
    await this.journal.append({ ...recoveryBase(bundle, "CLEANUP_FAILED"), outcome: "CLEANUP_FAILED", responseStatus: response.statusCode, responseHash: response.bodyHash, recoveryBundleRef: bundlePath, note: reason });
    return simpleResult(bundle.caseId, "CLEANUP_FAILED", "INCONCLUSIVE", "CLEANUP_FAILED", this.journal.path, notes, bundle.contractDigest);
  }

  private async rollback(request: HttpRequest, verification: MutationVerification, preStateHash: string | undefined, contract: ControlledMutationContract, recoveryRef: string): Promise<{ outcome: CleanupOutcome; notes: string[]; responseHash?: string; browserVerified?: boolean }> {
    const response = await this.cleanupTransport.send(request);
    await this.journal.append({ ...base(contract, "ROLLBACK_SENT"), requestMethod: request.method, requestUrl: safeRequestUrl(request.url), requestBodyAttestation: this.journal.attestBody(request.body), responseStatus: response.statusCode, responseHash: response.bodyHash, recoveryBundleRef: recoveryRef });
    const verified = await this.verify(verification, preStateHash, this.cleanupTransport);
    const browserProof = this.browserObserver ? await this.browserObserver.verifyRollback(contract) : { configured: false, matched: true, notes: [] };
    const outcome: CleanupOutcome = verified.matched && (!browserProof.configured || browserProof.matched) ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED";
    verified.notes.push(...browserProof.notes);
    await this.journal.append({ ...base(contract, outcome), outcome, responseStatus: verified.response.statusCode, responseHash: verified.response.bodyHash, recoveryBundleRef: verified.matched ? undefined : recoveryRef, note: verified.notes.join(" ") });
    if (outcome === "ROLLBACK_VERIFIED") await this.vault.remove(recoveryRef);
    return { outcome, notes: verified.notes, ...(verified.response.bodyHash ? { responseHash: verified.response.bodyHash } : {}), ...(browserProof.configured ? { browserVerified: browserProof.matched } : {}) };
  }

  private async verify(verification: MutationVerification, preStateHash?: string, transport: MutationTransport = this.transport): Promise<{ matched: boolean; response: HttpResponse; notes: string[] }> {
    let response = await transport.send({ ...(verification.request as HttpRequest), skipCache: true });
    for (let attempt = 1; attempt <= verification.attempts; attempt += 1) {
      const assertionsOk = verification.assertions ? assertionsMatch(response, verification.assertions) : true;
      const hashOk = verification.matchPreStateHash ? Boolean(preStateHash && response.bodyHash === preStateHash) : true;
      if (!response.error && assertionsOk && hashOk) return { matched: true, response, notes: [`Verification matched on attempt ${attempt}.`] };
      if (attempt < verification.attempts) { await (transport === this.cleanupTransport ? this.cleanupSleep : this.sleep)(verification.delayMs); response = await transport.send({ ...(verification.request as HttpRequest), skipCache: true }); }
    }
    return { matched: false, response, notes: [response.error ? `Verification request failed: ${response.error.name}.` : "Verification assertions did not match within the bounded polling window."] };
  }
}

function assertionsMatch(response: HttpResponse, assertions: MutationAssertion[]): boolean {
  const analysisBody = bodyPreviewForAnalysis(response);
  if (!analysisBody) return false;
  let body: unknown;
  try { body = JSON.parse(analysisBody); } catch { return false; }
  return assertions.every((assertion) => {
    const lookup = valueAt(body, assertion.path);
    if (assertion.operator === "PRESENT") return lookup.found;
    if (assertion.operator === "ABSENT") return !lookup.found;
    if (!lookup.found) return false;
    const equal = JSON.stringify(lookup.value) === JSON.stringify(assertion.expectedValue);
    return assertion.operator === "EQUALS" ? equal : !equal;
  });
}

function valueAt(value: unknown, path: string): { found: boolean; value?: unknown } {
  let current = value;
  for (const segment of path.split(".")) {
    if (!current || typeof current !== "object" || !(segment in current)) return { found: false };
    current = (current as Record<string, unknown>)[segment];
  }
  return { found: true, value: current };
}

function rejected(response: HttpResponse): boolean { return typeof response.statusCode === "number" && [400, 401, 403, 404, 405, 409, 422].includes(response.statusCode); }
function base(contract: ControlledMutationContract, stage: MutationJournalStage) { return { caseId: contract.caseId, stage, mode: contract.mode, intent: contract.intent, securityCategory: contract.securityCategory, targetOrigin: contract.targetOrigin, targetIdentityFingerprint: contract.target.identityFingerprint }; }
function recoveryBase(bundle: MutationRecoveryBundle, stage: MutationJournalStage) { return { caseId: bundle.caseId, stage, mode: "CONTROLLED_MUTATION" as OffensiveExecutionMode, ...(bundle.intent ? { intent: bundle.intent } : {}), ...(bundle.securityCategory ? { securityCategory: bundle.securityCategory } : {}), targetOrigin: bundle.targetOrigin, targetIdentityFingerprint: bundle.targetIdentityFingerprint ?? "recovery" }; }
function simpleResult(caseId: string, outcome: ControlledMutationResult["outcome"], securityOutcome: ControlledMutationResult["securityOutcome"], cleanupOutcome: ControlledMutationResult["cleanupOutcome"], journalPath: string, notes: string[], identity?: string): ControlledMutationResult { return { caseId, outcome, securityOutcome, cleanupOutcome, journalPath, comparisonIdentity: identity ?? createHash("sha256").update(`blocked:${caseId}`).digest("hex"), notes }; }
function comparisonIdentity(contract: ControlledMutationContract): string {
  const verification = (value: MutationVerification) => ({ ...value, request: semanticRequest(value.request) });
  return securityContractFingerprint("controlled-mutation", {
    schemaVersion: contract.schemaVersion,
    caseId: contract.caseId,
    targetOrigin: contract.targetOrigin,
    mode: contract.mode,
    intent: contract.intent,
    securityCategory: contract.securityCategory,
    environment: contract.environment,
    actor: contract.actor,
    identity: contract.identity ? verification(contract.identity) : undefined,
    target: contract.target,
    attack: { ...contract.attack, request: semanticRequest(contract.attack.request) },
    precondition: verification(contract.precondition),
    impact: verification(contract.impact),
    protectedAction: contract.protectedAction ? verification(contract.protectedAction) : undefined,
    rollback: { request: semanticRequest(contract.rollback.request), verification: verification(contract.rollback.verification) }
  });
}
function semanticRequest(request: { url: string; method: string; headers?: Record<string, string> | undefined; body?: string | undefined; skipCache?: boolean | undefined }): unknown {
  const semanticHeaders = Object.fromEntries(Object.entries(request.headers ?? {}).filter(([name]) => ["accept", "content-type"].includes(name.toLowerCase())).map(([name, value]) => [name.toLowerCase(), value]));
  return { url: request.url, method: request.method, ...(Object.keys(semanticHeaders).length > 0 ? { headers: semanticHeaders } : {}), ...(request.body !== undefined ? { body: request.body } : {}) };
}
function valueFingerprint(value: unknown): string { return createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
