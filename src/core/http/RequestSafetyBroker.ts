import { createHmac, randomBytes } from "node:crypto";
import { redactBodyPreview, redactHeaders } from "../evidence/EvidenceBuilder.js";
import { ValuePresenceAttestor, redactSensitiveUrl, scrubObservedValues, type TransientValueObservation, type ValuePresenceAttestation } from "../evidence/ValuePresenceAttestation.js";
import { ScanCancelledError } from "../engine/ScanEvents.js";
import type { ScopeMatcher } from "../scope/ScopeMatcher.js";
import { HttpClient } from "./HttpClient.js";
import { RateLimiter } from "./RateLimiter.js";
import { RequestQueue } from "./RequestQueue.js";
import { RetryPolicy } from "./RetryPolicy.js";
import { attachTransientResponseAnalysis, copyTransientResponseAnalysis } from "./TransientResponseAnalysis.js";
import type { RequestLedgerLane, ScanRequestLedger, ScanRequestLedgerSnapshot } from "./ScanRequestLedger.js";
import type { BrowserBrokerDecision, BrowserBrokerRequest, HttpRequest, HttpResponse, RedirectHop, RequestAuditEntry, RequestBrokerOptions, SynchronizedMutationBatchResult } from "./HttpTypes.js";

export type RequestAuditRecorder = (entry: RequestAuditEntry) => void;

export interface RequestBrokerCoordination {
  ledger: ScanRequestLedger;
  lane: RequestLedgerLane;
}

const maxRedirects = 5;

export class RequestSafetyBroker {
  private readonly transport: HttpClient;
  private readonly rateLimiter: RateLimiter;
  private readonly queue: RequestQueue;
  private readonly retryPolicy: RetryPolicy;
  private readonly requestCache = new Map<string, Promise<HttpResponse>>();
  private readonly auditFingerprintSalt = randomBytes(32);
  private readonly valueAttestor = new ValuePresenceAttestor();
  private sentRequestCount = 0;
  private browserPolicyEventCount = 0;
  private browserPolicyEventLimit = 0;
  private readonly maxRequests: number;
  private readonly abortSignal: AbortSignal | undefined;
  private readonly controlledMutationEnabled: boolean;
  private readonly controlledDeletionEnabled: boolean;
  private readonly controlledRaceEnabled: boolean;

  public constructor(
    options: RequestBrokerOptions,
    private readonly scopeMatcher: ScopeMatcher,
    private readonly recordAudit: RequestAuditRecorder,
    private readonly coordination?: RequestBrokerCoordination
  ) {
    this.abortSignal = options.abortSignal;
    this.controlledMutationEnabled = options.controlledMutationEnabled === true;
    this.controlledDeletionEnabled = options.controlledDeletionEnabled === true;
    this.controlledRaceEnabled = options.controlledRaceEnabled === true;
    this.transport = new HttpClient({
      userAgent: options.userAgent,
      timeoutMs: options.timeoutMs,
      bodyPreviewBytes: options.bodyPreviewBytes,
      maxResponseBytes: options.maxResponseBytes,
      allowedPrivateOrigins: [this.scopeMatcher.targetOrigin(), ...(options.allowedPrivateOrigins ?? [])],
      ...(options.dnsResolver ? { dnsResolver: options.dnsResolver } : {}),
      ...(typeof options.dnsTimeoutMs === "number" ? { dnsTimeoutMs: options.dnsTimeoutMs } : {}),
      ...(typeof options.maxDnsAnswers === "number" ? { maxDnsAnswers: options.maxDnsAnswers } : {}),
      ...(options.abortSignal ? { abortSignal: options.abortSignal } : {})
    });
    this.rateLimiter = new RateLimiter(options.rateLimitPerSecond);
    this.queue = new RequestQueue(options.concurrency);
    this.retryPolicy = new RetryPolicy(options.retry);
    this.maxRequests = options.maxRequests;
  }

  public setBrowserPolicyEventLimit(limit: number): void {
    this.browserPolicyEventLimit = limit;
  }

  private authorizeBrowserTransmission(request: BrowserBrokerRequest, login: boolean): string | undefined {
    const authorization = this.scopeMatcher.authorization;
    const program = authorization?.plan.bugBounty;
    if (!program) return;
    if (["websocket", "eventsource"].includes(request.resourceType)) return "authorization-streaming-prohibited";
    let url: URL;
    try { url = new URL(request.url); } catch { return "authorization-invalid-url"; }
    const rule = program.requests.find((item) => item.origin === url.origin && item.path === url.pathname && item.method === request.method.toUpperCase());
    if (login && (!program.authenticationPermitted || rule?.effect !== "AUTHENTICATION")) return "authorization-login-not-approved";
    if (!login && rule && rule.effect !== "READ") return "authorization-browser-write-requires-case";
    return authorization!.check(request.url, request.method);
  }

  public async send(requestInput: HttpRequest): Promise<HttpResponse> {
    return this.sendRequest(requestInput, false);
  }

  public async sendSynchronizedMutations(requests: readonly HttpRequest[]): Promise<SynchronizedMutationBatchResult> {
    if (this.scopeMatcher.authorization?.plan.bugBounty && !this.scopeMatcher.authorization.plan.bugBounty.racePermitted) throw new Error("TARGET_RACE_TESTING_PROHIBITED");
    if (!this.controlledRaceEnabled) throw new Error("Synchronized mutation groups require a dedicated controlled-race broker.");
    if (requests.length < 2 || requests.length > 5) throw new Error("Synchronized mutation groups require exactly two to five requests.");
    if (requests.some((request) => !isMutationMethod(request.method))) throw new Error("Every synchronized group member must be state-changing.");
    this.scopeMatcher.authorization?.requireRemainingBudget(requests.length);
    await this.scopeMatcher.authorization?.waitForRate(this.abortSignal, requests.length);
    if (this.coordination) await this.coordination.ledger.waitForBurst(this.abortSignal, requests.length);
    else await this.rateLimiter.wait(this.abortSignal, requests.length);

    let releaseBarrier: (() => void) | undefined;
    const dispatchBarrier = new Promise<void>((resolve) => { releaseBarrier = resolve; });
    const dispatchTimes: number[] = [];
    const pendingResponses = requests.map((request) => this.sendRequest(
      { ...request, skipCache: true, disableRetries: true, disableRedirects: true },
      true,
      (time) => dispatchTimes.push(time),
      dispatchBarrier
    ));

    // Every request has now been prepared and placed in the dedicated broker's
    // bounded queue. Releasing this single gate is the synchronized group start.
    releaseBarrier?.();
    const responses = await Promise.all(pendingResponses);
    const dispatchSkewMs = dispatchTimes.length > 1 ? Math.max(...dispatchTimes) - Math.min(...dispatchTimes) : 0;
    return { responses, dispatchSkewMs };
  }

  private async sendRequest(requestInput: HttpRequest, bypassRateLimit: boolean, onDispatch?: (timeMs: number) => void, dispatchBarrier?: Promise<void>): Promise<HttpResponse> {
    this.throwIfAborted();
    const observation = this.valueAttestor.observe(requestInput.url, requestInput.headers);
    if ((requestInput.method === "DELETE" && !this.controlledDeletionEnabled) || ((requestInput.method === "PATCH" || requestInput.method === "PUT") && !this.controlledMutationEnabled)) {
      const reason = requestInput.method === "DELETE" ? "controlled-deletion-mode-required" : "controlled-mutation-mode-required";
      const baseResponse = sanitizeResponse(skippedResponse(requestInput, "ControlledMutationBlocked", `Request blocked by scan-wide broker: ${reason}.`), observation);
      const response = this.finalizeResponse(baseResponse, observation, "policy-blocked");
      this.recordAudit(auditEntry(requestInput, response, "scope-skipped", [], reason, this.auditFingerprintSalt));
      return response;
    }
    const scopeDecision = this.scopeMatcher.decide(requestInput.url, requestInput.method);

    if (!scopeDecision.allowed || !scopeDecision.normalizedUrl) {
      const baseResponse = sanitizeResponse(
        skippedResponse(requestInput, "OutOfScopeRequest", `Request skipped by scan-wide broker: ${scopeDecision.reason}.`),
        observation
      );
      const response = this.finalizeResponse(baseResponse, observation, "policy-blocked");
      this.recordAudit(auditEntry(requestInput, response, "scope-skipped", [], scopeDecision.reason, this.auditFingerprintSalt));
      return response;
    }

    const scopedRequest = { ...requestInput, url: scopeDecision.normalizedUrl };
    const key = requestKey(scopedRequest, this.auditFingerprintSalt);

    const cacheable = (scopedRequest.method === "GET" || scopedRequest.method === "HEAD" || scopedRequest.method === "OPTIONS") && !scopedRequest.skipCache;
    if (cacheable) {
      const cached = this.requestCache.get(key);
      if (cached) {
        const response = this.finalizeResponse(cloneResponse(await cached), observation, "cache-reused");
        this.recordAudit(auditEntry(scopedRequest, response, "duplicate-skipped", response.redirectChain, undefined, this.auditFingerprintSalt));
        return response;
      }
    }

    const responsePromise = this.queue.run(async () => {
      this.throwIfAborted();
      if (!bypassRateLimit && !this.coordination) await this.rateLimiter.wait(this.abortSignal);
      if (dispatchBarrier) await dispatchBarrier;
      this.throwIfAborted();
      const rawResponse = scopedRequest.disableRetries || isMutationMethod(scopedRequest.method)
        ? await this.sendWithRedirects(scopedRequest, scopedRequest.url, [], bypassRateLimit, onDispatch)
        : await this.retryPolicy.run(() => this.sendWithRedirects(scopedRequest, scopedRequest.url, [], false, onDispatch));
      return attachTransientResponseAnalysis(sanitizeResponse(rawResponse, observation), rawResponse);
    });

    if (cacheable) this.requestCache.set(key, responsePromise);
    const response = cloneResponse(await responsePromise);
    const finalizedResponse = this.finalizeResponse(response, observation, transportOutcomeFor(response));
    this.recordAudit(auditEntry(scopedRequest, finalizedResponse, auditOutcome(finalizedResponse), finalizedResponse.redirectChain, undefined, this.auditFingerprintSalt));
    return finalizedResponse;
  }

  public evaluateBrowserRequest(requestInput: BrowserBrokerRequest): BrowserBrokerDecision {
    const authorizationBlock = this.authorizeBrowserTransmission(requestInput, false);
    if (authorizationBlock) return this.recordBrowserPolicyBlock(requestInput, authorizationBlock);
    const observation = this.valueAttestor.observe(requestInput.url);
    const policyEventCount = this.consumeBrowserPolicyEvent();
    if (typeof policyEventCount !== "number") {
      const baseAudit = this.browserAuditBase(requestInput, observation, this.browserPolicyEventCount, this.sentRequestCount, "policy-blocked");
      this.recordAudit({
        ...baseAudit,
        outcome: "browser-policy-budget-skipped",
        browserPolicyReason: "browser-attempt-budget-exceeded",
        error: `Browser request blocked because policy event budget (${this.browserPolicyEventLimit}) was exhausted.`
      });
      return {
        allowed: false,
        reason: "browser-attempt-budget-exceeded",
        policyEventCount: this.browserPolicyEventCount,
        transmittedRequestCount: this.sentRequestCount
      };
    }
    const blockedAudit = this.browserAuditBase(requestInput, observation, policyEventCount, this.sentRequestCount, "policy-blocked");

    const method = requestInput.method.toUpperCase();
    if (!isSafeBrowserMethod(method)) {
      this.recordAudit({
        ...blockedAudit,
        outcome: "browser-policy-blocked",
        browserPolicyReason: "mutating-method-blocked",
        error: `Browser request blocked before network transmission because method ${method} is not in the safe-method allowlist.`
      });
      return {
        allowed: false,
        reason: "mutating-method-blocked",
        policyEventCount,
        transmittedRequestCount: this.sentRequestCount
      };
    }

    const scopeDecision = this.scopeMatcher.decide(scopeUrlForBrowserRequest(requestInput), method);
    if (!scopeDecision.allowed || !scopeDecision.normalizedUrl) {
      this.recordAudit({
        ...blockedAudit,
        ...(scopeDecision.normalizedUrl ? { finalUrl: redactSensitiveUrl(scopeDecision.normalizedUrl) } : {}),
        outcome: "browser-policy-blocked",
        scopeReason: scopeDecision.reason,
        browserPolicyReason: `scope-${scopeDecision.reason}`,
        error: `Browser request blocked before network transmission: ${scopeDecision.reason}.`
      });
      return {
        allowed: false,
        ...(scopeDecision.normalizedUrl ? { normalizedUrl: scopeDecision.normalizedUrl } : {}),
        reason: `scope-${scopeDecision.reason}`,
        policyEventCount,
        transmittedRequestCount: this.sentRequestCount
      };
    }

    const authorizationDenied = this.scopeMatcher.authorization?.reserve(scopeDecision.normalizedUrl, method);
    if (authorizationDenied) return this.recordBrowserPolicyBlock(requestInput, authorizationDenied);
    if (!this.consumeTransmissionBudget()) {
      this.recordAudit({
        ...blockedAudit,
        finalUrl: redactSensitiveUrl(scopeDecision.normalizedUrl),
        outcome: "budget-skipped",
        browserPolicyReason: "network-request-budget-exceeded",
        error: `Browser request blocked because scan network request budget (${this.maxRequests}) was exhausted.`
      });
      return {
        allowed: false,
        normalizedUrl: scopeDecision.normalizedUrl,
        reason: "network-request-budget-exceeded",
        policyEventCount,
        transmittedRequestCount: this.sentRequestCount
      };
    }

    this.recordAudit({
      ...this.browserAuditBase(requestInput, observation, policyEventCount, this.sentRequestCount, "network-approved", scopeDecision.normalizedUrl),
      finalUrl: redactSensitiveUrl(scopeDecision.normalizedUrl),
      outcome: "browser-network-scheduled",
      browserPolicyReason: requestInput.isRedirect ? "redirect-hop-allowed" : "allowed",
      transmittedRequests: this.sentRequestCount
    });
    return {
      allowed: true,
      normalizedUrl: scopeDecision.normalizedUrl,
      reason: "allowed",
      policyEventCount,
      transmittedRequestCount: this.sentRequestCount
    };
  }

  /**
   * Allows only an explicitly configured browser login POST through the same
   * scope and request budgets. This is intentionally separate from ordinary
   * browser traffic so learned writes can never inherit login authority.
   */
  public evaluateBrowserLoginRequest(requestInput: BrowserBrokerRequest): BrowserBrokerDecision {
    const method = requestInput.method.toUpperCase();
    if (method !== "POST") return this.evaluateBrowserRequest(requestInput);
    const authorizationBlock = this.authorizeBrowserTransmission(requestInput, true);
    if (authorizationBlock) return this.recordBrowserPolicyBlock(requestInput, authorizationBlock);
    const observation = this.valueAttestor.observe(requestInput.url);
    const policyEventCount = this.consumeBrowserPolicyEvent();
    if (typeof policyEventCount !== "number") {
      this.recordAudit({
        ...this.browserAuditBase(requestInput, observation, this.browserPolicyEventCount, this.sentRequestCount, "policy-blocked"),
        outcome: "browser-policy-budget-skipped",
        browserPolicyReason: "browser-attempt-budget-exceeded",
        error: "Explicit browser login POST was blocked because the browser policy-event budget was exhausted."
      });
      return { allowed: false, reason: "browser-attempt-budget-exceeded", policyEventCount: this.browserPolicyEventCount, transmittedRequestCount: this.sentRequestCount };
    }
    const scopeDecision = this.scopeMatcher.decide(scopeUrlForBrowserRequest(requestInput), method);
    const audit = this.browserAuditBase(requestInput, observation, policyEventCount, this.sentRequestCount, "policy-blocked");
    if (!scopeDecision.allowed || !scopeDecision.normalizedUrl) {
      this.recordAudit({ ...audit, outcome: "browser-policy-blocked", scopeReason: scopeDecision.reason, browserPolicyReason: `scope-${scopeDecision.reason}`, error: `Explicit browser login POST blocked before transmission: ${scopeDecision.reason}.` });
      return { allowed: false, ...(scopeDecision.normalizedUrl ? { normalizedUrl: scopeDecision.normalizedUrl } : {}), reason: `scope-${scopeDecision.reason}`, policyEventCount, transmittedRequestCount: this.sentRequestCount };
    }
    const authorizationDenied = this.scopeMatcher.authorization?.reserve(scopeDecision.normalizedUrl, method);
    if (authorizationDenied) return this.recordBrowserPolicyBlock(requestInput, authorizationDenied);
    if (!this.consumeTransmissionBudget()) {
      this.recordAudit({ ...audit, finalUrl: redactSensitiveUrl(scopeDecision.normalizedUrl), outcome: "budget-skipped", browserPolicyReason: "network-request-budget-exceeded", error: "Explicit browser login POST blocked because the network request budget was exhausted." });
      return { allowed: false, normalizedUrl: scopeDecision.normalizedUrl, reason: "network-request-budget-exceeded", policyEventCount, transmittedRequestCount: this.sentRequestCount };
    }
    this.recordAudit({
      ...this.browserAuditBase(requestInput, observation, policyEventCount, this.sentRequestCount, "network-approved", scopeDecision.normalizedUrl),
      finalUrl: redactSensitiveUrl(scopeDecision.normalizedUrl),
      outcome: "browser-network-scheduled",
      browserPolicyReason: "explicit-authenticated-login-post",
      transmittedRequests: this.sentRequestCount
    });
    return { allowed: true, normalizedUrl: scopeDecision.normalizedUrl, reason: "allowed", policyEventCount, transmittedRequestCount: this.sentRequestCount };
  }

  public recordBrowserPolicyBlock(requestInput: BrowserBrokerRequest, reason: string): BrowserBrokerDecision {
    const observation = this.valueAttestor.observe(requestInput.url);
    const policyEventCount = this.consumeBrowserPolicyEvent();
    if (typeof policyEventCount !== "number") {
      const baseAudit = this.browserAuditBase(requestInput, observation, this.browserPolicyEventCount, this.sentRequestCount, "policy-blocked");
      this.recordAudit({
        ...baseAudit,
        outcome: "browser-policy-budget-skipped",
        browserPolicyReason: "browser-attempt-budget-exceeded",
        error: `Browser action blocked because policy event budget (${this.browserPolicyEventLimit}) was exhausted.`
      });
      return {
        allowed: false,
        reason: "browser-attempt-budget-exceeded",
        policyEventCount: this.browserPolicyEventCount,
        transmittedRequestCount: this.sentRequestCount
      };
    }
    const baseAudit = this.browserAuditBase(requestInput, observation, policyEventCount, this.sentRequestCount, "policy-blocked");

    this.recordAudit({
      ...baseAudit,
      outcome: "browser-policy-blocked",
      browserPolicyReason: reason,
      error: `Browser action blocked by policy: ${reason}.`
    });
    return {
      allowed: false,
      reason,
      policyEventCount,
      transmittedRequestCount: this.sentRequestCount
    };
  }

  public budgetSnapshot(): { transmittedRequests: number; maxRequests: number; browserPolicyEvents: number; browserPolicyEventLimit: number } {
    return {
      transmittedRequests: this.sentRequestCount,
      maxRequests: this.maxRequests,
      browserPolicyEvents: this.browserPolicyEventCount,
      browserPolicyEventLimit: this.browserPolicyEventLimit
    };
  }

  public sharedBudgetSnapshot(): ScanRequestLedgerSnapshot | undefined {
    return this.coordination?.ledger.snapshot();
  }

  /** Browser traffic is dispatched by Playwright rather than HttpClient. This
   * hook applies the same scan-wide rate and concurrency gate after routing has
   * synchronously reserved the shared request budget. */
  public async dispatchApprovedBrowserRequest<T>(operation: () => Promise<T>): Promise<T> {
    if (this.coordination) return this.coordination.ledger.dispatchReserved(this.coordination.lane, this.abortSignal, operation);
    return this.queue.run(async () => {
      await this.rateLimiter.wait(this.abortSignal);
      this.throwIfAborted();
      return operation();
    });
  }

  public attestTransientResponseValue(input: {
    rawValue: string;
    location: "body" | "source-map";
    name: string;
    classification: "secret-material" | "private-data";
    response: HttpResponse;
  }): ValuePresenceAttestation {
    return this.valueAttestor.attestTransientValue({
      rawValue: input.rawValue,
      location: input.location,
      name: input.name,
      classification: input.classification,
      safeUrl: redactSensitiveUrl(input.response.finalUrl),
      requestId: input.response.requestId ?? `response-${input.response.bodyHash?.slice(0, 24) ?? "unidentified"}`,
      ...(typeof input.response.statusCode === "number" ? { statusCode: input.response.statusCode } : {}),
      ...(input.response.bodyHash ? { responseHash: input.response.bodyHash } : {})
    });
  }

  private async sendWithRedirects(requestInput: HttpRequest, currentUrl: string, redirectChain: RedirectHop[], synchronized = false, onDispatch?: (timeMs: number) => void): Promise<HttpResponse> {
    this.throwIfAborted();
    const authorization = this.scopeMatcher.authorization;
    if (!synchronized) await authorization?.waitForRate(this.abortSignal);
    if (authorization?.plan.bugBounty && !authorization.plan.bugBounty.authenticationPermitted && Object.keys(requestInput.headers ?? {}).some((name) => !["accept", "content-type", "user-agent", "range", "cache-control", "if-none-match", "if-modified-since"].includes(name.toLowerCase()))) return skippedResponse(requestInput, "TargetAuthorizationDenied", "authorization-authentication-prohibited");
    const denied = authorization?.reserve(currentUrl, requestInput.method, requestInput.body);
    if (denied) return skippedResponse(requestInput, "TargetAuthorizationDenied", denied);
    if (this.sentRequestCount >= this.maxRequests) {
      return skippedResponse(requestInput, "RequestBudgetExceeded", `Request skipped because broker request budget (${this.maxRequests}) was exhausted.`);
    }

    let response: HttpResponse;
    if (this.coordination) {
      const dispatched = await this.coordination.ledger.transmit(
        this.coordination.lane,
        this.abortSignal,
        () => this.transport.send(requestInput, currentUrl, redirectChain),
        { rateAlreadyReserved: synchronized, onReserved: () => { this.sentRequestCount += 1; onDispatch?.(Number(process.hrtime.bigint()) / 1_000_000); } }
      );
      if (!dispatched.accepted) {
        const shared = this.coordination.ledger.snapshot();
        const capacity = this.coordination.lane === "CLEANUP" ? shared.cleanupReservedRequests : shared.scanCapacity;
        return skippedResponse(requestInput, "RequestBudgetExceeded", `Request skipped because the scan-wide ${this.coordination.lane.toLowerCase()} request capacity (${capacity}) was exhausted.`);
      }
      response = dispatched.value;
    } else {
      if (!this.consumeBudget()) {
        return skippedResponse(requestInput, "RequestBudgetExceeded", `Request skipped because scan request budget (${this.maxRequests}) was exhausted.`);
      }
      onDispatch?.(Number(process.hrtime.bigint()) / 1_000_000);
      response = await this.transport.send(requestInput, currentUrl, redirectChain);
    }
    const redirectLocation = response.redirectLocation;

    if (requestInput.disableRedirects && isRedirect(response.statusCode) && redirectLocation) {
      return response;
    }

    if (isMutationMethod(requestInput.method) && isRedirect(response.statusCode) && redirectLocation) {
      return {
        ...response,
        error: {
          name: "ControlledMutationRedirectBlocked",
          message: "State-changing redirects are not followed; authorize the exact final endpoint instead."
        }
      };
    }

    if (!isRedirect(response.statusCode) || !redirectLocation || redirectChain.length >= maxRedirects) {
      return response;
    }

    let nextUrl: string;
    try {
      nextUrl = new URL(redirectLocation, currentUrl).toString();
    } catch {
      return response;
    }

    const redirectDecision = this.scopeMatcher.decide(nextUrl, requestInput.method);
    const nextHop = { statusCode: response.statusCode as number, location: nextUrl };
    const nextChain = [...redirectChain, nextHop];

    if (!redirectDecision.allowed || !redirectDecision.normalizedUrl) {
      const statusCode = response.statusCode as number;
      return {
        requestedUrl: requestInput.url,
        finalUrl: currentUrl,
        method: requestInput.method,
        statusCode,
        headers: response.headers,
        responseTimeMs: response.responseTimeMs,
        redirectChain: nextChain,
        ...(response.contentType ? { contentType: response.contentType } : {}),
        ...(typeof response.contentLength === "number" ? { contentLength: response.contentLength } : {}),
        ...(response.title ? { title: response.title } : {}),
        ...(response.bodyHash ? { bodyHash: response.bodyHash } : {}),
        ...(response.bodyPreview ? { bodyPreview: response.bodyPreview } : {}),
        redirectLocation: nextUrl,
        error: {
          name: "OutOfScopeRedirect",
          message: `Redirect blocked by scan-wide broker: ${redirectDecision.reason}.`
        }
      };
    }

    return this.sendWithRedirects(requestInput, redirectDecision.normalizedUrl, nextChain, false);
  }

  private consumeBudget(): boolean {
    if (this.sentRequestCount >= this.maxRequests) {
      return false;
    }

    this.sentRequestCount += 1;
    return true;
  }

  private consumeTransmissionBudget(): boolean {
    if (this.sentRequestCount >= this.maxRequests) return false;
    if (this.coordination && !this.coordination.ledger.tryReserve(this.coordination.lane)) return false;
    this.sentRequestCount += 1;
    return true;
  }

  private consumeBrowserPolicyEvent(): number | undefined {
    if (this.browserPolicyEventLimit > 0 && this.browserPolicyEventCount >= this.browserPolicyEventLimit) {
      return undefined;
    }

    this.browserPolicyEventCount += 1;
    return this.browserPolicyEventCount;
  }

  private throwIfAborted(): void {
    if (this.abortSignal?.aborted) {
      throw new ScanCancelledError();
    }
  }

  private finalizeResponse(
    response: HttpResponse,
    observation: TransientValueObservation,
    transportOutcome: ValuePresenceAttestation["transportOutcome"]
  ): HttpResponse {
    const attestations = this.valueAttestor.finalize(observation, {
      safeUrl: redactSensitiveUrl(response.finalUrl),
      transportOutcome,
      ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
      ...(response.bodyHash ? { responseHash: response.bodyHash } : {})
    });
    const finalized = {
      ...response,
      requestId: observation.requestId,
      ...(attestations.length > 0 ? { valueAttestations: attestations } : {})
    };
    return copyTransientResponseAnalysis(response, finalized);
  }

  private browserAuditBase(
    requestInput: BrowserBrokerRequest,
    observation: TransientValueObservation,
    policyEventCount: number,
    transmittedRequests: number,
    transportOutcome: ValuePresenceAttestation["transportOutcome"],
    finalUrl = requestInput.url
  ): Omit<RequestAuditEntry, "outcome"> {
    const valueAttestations = this.valueAttestor.finalize(observation, {
      safeUrl: redactSensitiveUrl(finalUrl),
      transportOutcome
    });
    return {
      requestId: observation.requestId,
      requestedUrl: redactSensitiveUrl(requestInput.url),
      method: requestInput.method.toUpperCase(),
      requestHeaders: {},
      redirectChain: [],
      source: "browser",
      resourceType: requestInput.resourceType,
      ...(requestInput.pageUrl ? { pageUrl: redactSensitiveUrl(requestInput.pageUrl) } : {}),
      browserPolicyEvents: policyEventCount,
      transmittedRequests,
      ...(valueAttestations.length > 0 ? { valueAttestations } : {})
    };
  }
}

function isMutationMethod(method: HttpRequest["method"]): boolean {
  return method === "POST" || method === "PATCH" || method === "PUT" || method === "DELETE";
}

function requestKey(requestInput: HttpRequest, key: Buffer): string {
  const headers = Object.entries(requestInput.headers ?? {})
    .map(([name, value]) => `${name.toLowerCase()}:${keyedFingerprint(value, key)}`)
    .sort()
    .join("|");

  const body = requestInput.body ? keyedFingerprint(requestInput.body, key) : "";
  return `${requestInput.method} url:${keyedFingerprint(requestInput.url, key)} headers:${headers} body:${body}`;
}

function keyedFingerprint(value: string, key: Buffer): string {
  return createHmac("sha256", key).update(value).digest("hex");
}

function skippedResponse(requestInput: HttpRequest, name: string, message: string): HttpResponse {
  return {
    requestedUrl: requestInput.url,
    finalUrl: requestInput.url,
    method: requestInput.method,
    headers: {},
    responseTimeMs: 0,
    redirectChain: [],
    error: { name, message }
  };
}

function cloneResponse(response: HttpResponse): HttpResponse {
  const cloned: HttpResponse = {
    ...response,
    headers: { ...response.headers },
    redirectChain: response.redirectChain.map((hop) => ({ ...hop })),
    ...(response.error ? { error: { ...response.error } } : {}),
    ...(response.valueAttestations ? { valueAttestations: response.valueAttestations.map((attestation) => ({ ...attestation, reproductionSteps: [...attestation.reproductionSteps] })) } : {})
  };
  return copyTransientResponseAnalysis(response, cloned);
}

function sanitizeResponse(response: HttpResponse, observation: TransientValueObservation): HttpResponse {
  const scrubbedHeaders = Object.fromEntries(
    Object.entries(response.headers).map(([name, value]) => [
      name,
      Array.isArray(value) ? value.map((item) => scrubObservedValues(item, observation)) : scrubObservedValues(value, observation)
    ])
  );
  return {
    ...response,
    requestedUrl: redactSensitiveUrl(response.requestedUrl),
    finalUrl: redactSensitiveUrl(response.finalUrl),
    headers: redactHeaders(scrubbedHeaders),
    redirectChain: response.redirectChain.map((hop) => ({ ...hop, location: redactSensitiveUrl(hop.location) })),
    ...(response.redirectLocation ? { redirectLocation: redactSensitiveUrl(response.redirectLocation) } : {}),
    ...(response.bodyPreview
      ? { bodyPreview: redactBodyPreview(scrubObservedValues(response.bodyPreview, observation), response.bodyPreview.length) }
      : {}),
    ...(response.error ? { error: { ...response.error, message: scrubObservedValues(response.error.message, observation) } } : {})
  };
}

function auditEntry(
  requestInput: HttpRequest,
  response: HttpResponse,
  outcome: RequestAuditEntry["outcome"],
  redirectChain: RedirectHop[],
  scopeReason?: string,
  fingerprintSalt?: Buffer
): RequestAuditEntry {
  const redacted = redactHeaders(requestInput.headers ?? {});
  return {
    ...(response.requestId ? { requestId: response.requestId } : {}),
    requestedUrl: redactSensitiveUrl(requestInput.url),
    finalUrl: redactSensitiveUrl(response.finalUrl),
    method: requestInput.method,
    outcome,
    ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    requestHeaders: Object.fromEntries(Object.entries(redacted).map(([name, value]) => [name, Array.isArray(value) ? value.join(", ") : value])),
    ...(requestInput.body && fingerprintSalt ? { requestBodyHash: keyedFingerprint(requestInput.body, fingerprintSalt) } : {}),
    redirectChain: redirectChain.map((hop) => ({ ...hop, location: redactSensitiveUrl(hop.location) })),
    ...(scopeReason ? { scopeReason } : {}),
    ...(response.error ? { error: response.error.message } : {}),
    ...(response.valueAttestations?.length
      ? { valueAttestations: response.valueAttestations.map((attestation) => ({ ...attestation, reproductionSteps: [...attestation.reproductionSteps] })) }
      : {})
  };
}

function scopeUrlForBrowserRequest(requestInput: BrowserBrokerRequest): string {
  if (requestInput.resourceType !== "websocket") {
    return requestInput.url;
  }

  try {
    const parsed = new URL(requestInput.url);
    if (parsed.protocol === "ws:") {
      parsed.protocol = "http:";
      return parsed.toString();
    }
    if (parsed.protocol === "wss:") {
      parsed.protocol = "https:";
      return parsed.toString();
    }
  } catch {
    return requestInput.url;
  }

  return requestInput.url;
}

function auditOutcome(response: HttpResponse): RequestAuditEntry["outcome"] {
  if (response.error?.name === "RequestBudgetExceeded") {
    return "budget-skipped";
  }

  return response.error?.name === "OutOfScopeRedirect" ? "redirect-scope-skipped" : "sent";
}

function transportOutcomeFor(response: HttpResponse): ValuePresenceAttestation["transportOutcome"] {
  return response.error?.name === "RequestBudgetExceeded" || response.error?.name === "OutOfScopeRedirect" || response.error?.name === "OutOfScopeRequest"
    ? "policy-blocked"
    : "transmitted";
}

function isRedirect(statusCode: number | undefined): boolean {
  return typeof statusCode === "number" && statusCode >= 300 && statusCode < 400;
}

function isSafeBrowserMethod(method: string): boolean {
  return method === "GET" || method === "HEAD" || method === "OPTIONS";
}
