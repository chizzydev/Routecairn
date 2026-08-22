import { createHash } from "node:crypto";
import { join } from "node:path";
import type { HttpRequest, HttpResponse } from "../http/HttpTypes.js";
import { authorizeControlledMutation, MutationSafetyError } from "./MutationPolicy.js";
import { GlobalMutationLock, MutationJournal, safeRequestUrl } from "./MutationJournal.js";
import { MutationRecoveryVault } from "./MutationRecoveryVault.js";
import type { ControlledMutationContract, ControlledMutationResult, MutationAssertion, MutationJournalStage, MutationRecoveryBundle, MutationTransport, MutationVerification, OffensiveExecutionMode } from "./ControlledMutationTypes.js";

export interface ControlledMutationExecutorOptions { journalDirectory: string; globalLockPath?: string; sleep?: (milliseconds: number) => Promise<void>; cleanupTransport?: MutationTransport }
type CleanupOutcome = "ROLLBACK_VERIFIED" | "CLEANUP_FAILED";

export class ControlledMutationExecutor {
  private readonly journal: MutationJournal;
  private readonly vault: MutationRecoveryVault;
  private readonly lock: GlobalMutationLock;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly cleanupTransport: MutationTransport;

  public constructor(private readonly transport: MutationTransport, options: ControlledMutationExecutorOptions) {
    this.journal = new MutationJournal(join(options.journalDirectory, "mutation-journal.json"));
    this.vault = new MutationRecoveryVault(options.journalDirectory);
    this.lock = new GlobalMutationLock(options.globalLockPath ?? join(options.journalDirectory, "global-mutation.lock"));
    this.sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    this.cleanupTransport = options.cleanupTransport ?? transport;
  }

  public async execute(contract: ControlledMutationContract): Promise<ControlledMutationResult> {
    const notes: string[] = [];
    try { authorizeControlledMutation(contract); }
    catch (error) {
      if (!(error instanceof MutationSafetyError)) throw error;
      const note = `${error.safetyCode}: ${error.message}`;
      await this.journal.append({ ...base(contract, "SEALED"), outcome: "BLOCKED_BY_SAFETY", note });
      return simpleResult(contract.caseId, "BLOCKED_BY_SAFETY", "BLOCKED_BY_SAFETY", "NOT_REQUIRED", this.journal.path, [note], comparisonIdentity(contract));
    }

    await this.lock.acquire(contract.caseId);
    let mutationArmed = false;
    let recoveryRef: string | undefined;
    let preStateHash: string | undefined;
    let attackResponseHash: string | undefined;
    let securityOutcome: ControlledMutationResult["securityOutcome"] = "INCONCLUSIVE";
    try {
      const pendingCleanup = await this.journal.unresolvedCaseIds();
      if (pendingCleanup.length > 0) {
        const note = `New mutations are blocked until cleanup is verified for: ${pendingCleanup.join(", ")}.`;
        return simpleResult(contract.caseId, "BLOCKED_BY_SAFETY", "BLOCKED_BY_SAFETY", "NOT_REQUIRED", this.journal.path, [note], comparisonIdentity(contract));
      }
      await this.journal.append(base(contract, "AUTHORIZED"));
      const preState = await this.verify(contract.precondition);
      notes.push(...preState.notes);
      if (!preState.matched || !preState.response.bodyHash) {
        await this.journal.append({ ...base(contract, "SEALED"), outcome: "INCONCLUSIVE", note: "Precondition verification failed; no mutation was sent." });
        return simpleResult(contract.caseId, "INCONCLUSIVE", "INCONCLUSIVE", "NOT_REQUIRED", this.journal.path, notes, comparisonIdentity(contract));
      }
      preStateHash = preState.response.bodyHash;
      await this.journal.append({ ...base(contract, "PRE_STATE_CAPTURED"), responseStatus: preState.response.statusCode, responseHash: preStateHash });
      const recovery: MutationRecoveryBundle = {
        caseId: contract.caseId,
        targetOrigin: contract.targetOrigin,
        targetIdentityFingerprint: contract.target.identityFingerprint,
        authorizationExpiresAt: contract.authorization.expiresAt,
        contractDigest: comparisonIdentity(contract),
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
      securityOutcome = impact.matched ? "EXPLOIT_PROVEN" : rejected(attack) ? "SECURE_FOR_CASE" : "INCONCLUSIVE";
      await this.journal.append({ ...base(contract, "IMPACT_VERIFIED"), responseStatus: impact.response.statusCode, responseHash: impact.response.bodyHash, outcome: securityOutcome });

      const cleanup = await this.rollback(contract.rollback.request as HttpRequest, contract.rollback.verification, preStateHash, contract, recoveryRef);
      notes.push(...cleanup.notes);
      return {
        caseId: contract.caseId,
        outcome: cleanup.outcome === "ROLLBACK_VERIFIED" ? securityOutcome : cleanup.outcome,
        securityOutcome,
        cleanupOutcome: cleanup.outcome,
        preStateHash,
        ...(attackResponseHash ? { attackResponseHash } : {}),
        ...(impact.response.bodyHash ? { verificationResponseHash: impact.response.bodyHash } : {}),
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
        return { caseId: contract.caseId, outcome: cleanup.outcome, securityOutcome, cleanupOutcome: cleanup.outcome, ...(preStateHash ? { preStateHash } : {}), ...(attackResponseHash ? { attackResponseHash } : {}), journalPath: this.journal.path, comparisonIdentity: comparisonIdentity(contract), notes };
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
    await this.lock.acquire(caseId);
    try {
      const response = await this.cleanupTransport.send(bundle.rollbackRequest);
      await this.journal.append({ ...recoveryBase(bundle, "ROLLBACK_SENT"), requestMethod: bundle.rollbackRequest.method, requestUrl: safeRequestUrl(bundle.rollbackRequest.url), requestBodyAttestation: this.journal.attestBody(bundle.rollbackRequest.body), responseStatus: response.statusCode, responseHash: response.bodyHash, recoveryBundleRef: bundlePath });
      const verified = await this.verify(bundle.rollbackVerification, bundle.preStateHash, this.cleanupTransport);
      const cleanup: CleanupOutcome = verified.matched ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED";
      await this.journal.append({ ...recoveryBase(bundle, cleanup), outcome: cleanup, responseStatus: verified.response.statusCode, responseHash: verified.response.bodyHash, recoveryBundleRef: verified.matched ? undefined : bundlePath, note: verified.notes.join(" ") });
      if (verified.matched) await this.vault.remove(bundlePath);
      return simpleResult(caseId, cleanup, "INCONCLUSIVE", cleanup, this.journal.path, verified.notes, createHash("sha256").update(`recovery:${bundle.targetOrigin}:${caseId}`).digest("hex"));
    } finally { await this.lock.release(); }
  }

  private async rollback(request: HttpRequest, verification: MutationVerification, preStateHash: string | undefined, contract: ControlledMutationContract, recoveryRef: string): Promise<{ outcome: CleanupOutcome; notes: string[]; responseHash?: string }> {
    const response = await this.cleanupTransport.send(request);
    await this.journal.append({ ...base(contract, "ROLLBACK_SENT"), requestMethod: request.method, requestUrl: safeRequestUrl(request.url), requestBodyAttestation: this.journal.attestBody(request.body), responseStatus: response.statusCode, responseHash: response.bodyHash, recoveryBundleRef: recoveryRef });
    const verified = await this.verify(verification, preStateHash, this.cleanupTransport);
    const outcome: CleanupOutcome = verified.matched ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED";
    await this.journal.append({ ...base(contract, outcome), outcome, responseStatus: verified.response.statusCode, responseHash: verified.response.bodyHash, recoveryBundleRef: verified.matched ? undefined : recoveryRef, note: verified.notes.join(" ") });
    if (verified.matched) await this.vault.remove(recoveryRef);
    return { outcome, notes: verified.notes, ...(verified.response.bodyHash ? { responseHash: verified.response.bodyHash } : {}) };
  }

  private async verify(verification: MutationVerification, preStateHash?: string, transport: MutationTransport = this.transport): Promise<{ matched: boolean; response: HttpResponse; notes: string[] }> {
    let response = await transport.send(verification.request as HttpRequest);
    for (let attempt = 1; attempt <= verification.attempts; attempt += 1) {
      const assertionsOk = verification.assertions ? assertionsMatch(response, verification.assertions) : true;
      const hashOk = verification.matchPreStateHash ? Boolean(preStateHash && response.bodyHash === preStateHash) : true;
      if (!response.error && assertionsOk && hashOk) return { matched: true, response, notes: [`Verification matched on attempt ${attempt}.`] };
      if (attempt < verification.attempts) { await this.sleep(verification.delayMs); response = await transport.send({ ...(verification.request as HttpRequest), skipCache: true }); }
    }
    return { matched: false, response, notes: [response.error ? `Verification request failed: ${response.error.name}.` : "Verification assertions did not match within the bounded polling window."] };
  }
}

function assertionsMatch(response: HttpResponse, assertions: MutationAssertion[]): boolean {
  if (!response.bodyPreview) return false;
  let body: unknown;
  try { body = JSON.parse(response.bodyPreview); } catch { return false; }
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
function base(contract: ControlledMutationContract, stage: MutationJournalStage) { return { caseId: contract.caseId, stage, mode: contract.mode, targetOrigin: contract.targetOrigin, targetIdentityFingerprint: contract.target.identityFingerprint }; }
function recoveryBase(bundle: MutationRecoveryBundle, stage: MutationJournalStage) { return { caseId: bundle.caseId, stage, mode: "CONTROLLED_MUTATION" as OffensiveExecutionMode, targetOrigin: bundle.targetOrigin, targetIdentityFingerprint: "recovery" }; }
function simpleResult(caseId: string, outcome: ControlledMutationResult["outcome"], securityOutcome: ControlledMutationResult["securityOutcome"], cleanupOutcome: ControlledMutationResult["cleanupOutcome"], journalPath: string, notes: string[], identity?: string): ControlledMutationResult { return { caseId, outcome, securityOutcome, cleanupOutcome, journalPath, comparisonIdentity: identity ?? createHash("sha256").update(`blocked:${caseId}`).digest("hex"), notes }; }
function comparisonIdentity(contract: ControlledMutationContract): string {
  const endpoint = new URL(contract.attack.request.url);
  return createHash("sha256").update(JSON.stringify({ schemaVersion: contract.schemaVersion, caseId: contract.caseId, origin: contract.targetOrigin, method: contract.attack.request.method, path: endpoint.pathname, semanticEffect: contract.attack.semanticEffect, fields: [...contract.attack.allowedFields].sort(), target: contract.target.identityFingerprint })).digest("hex");
}
