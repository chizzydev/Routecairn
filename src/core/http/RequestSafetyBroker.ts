import { createHash, createHmac, randomBytes } from "node:crypto";
import { redactBodyPreview, redactHeaders } from "../evidence/EvidenceBuilder.js";
import { ValuePresenceAttestor, redactSensitiveUrl, scrubObservedValues, type TransientValueObservation, type ValuePresenceAttestation } from "../evidence/ValuePresenceAttestation.js";
import { ScanCancelledError } from "../engine/ScanEvents.js";
import type { ScopeMatcher } from "../scope/ScopeMatcher.js";
import { HttpClient } from "./HttpClient.js";
import { normalizeUrl } from "../urls/UrlNormalizer.js";
import { claimTrustedDiscoveryOperation, discoveryFacts, type TrustedDiscoveryFacts } from "../../dashboard/execution/TrustedDiscoveryBinding.js";
import { TrustedDiscoveryDenial } from "../../dashboard/execution/TrustedDiscoverySource.js";
import { RateLimiter } from "./RateLimiter.js";
import { RequestQueue } from "./RequestQueue.js";
import { RetryPolicy } from "./RetryPolicy.js";
import { attachTransientResponseAnalysis, copyTransientResponseAnalysis } from "./TransientResponseAnalysis.js";
import { sendRawHttp1, type RawHttp1Request, type RawHttp1Response } from "./RawHttp1Transport.js";
import type { RequestLedgerLane, ScanRequestLedger, ScanRequestLedgerSnapshot } from "./ScanRequestLedger.js";
import type { BrowserBrokerDecision, BrowserBrokerRequest, HttpRequest, HttpResponse, RedirectHop, RequestAuditEntry, RequestBrokerOptions, SynchronizedMutationBatchResult } from "./HttpTypes.js";

export type RequestAuditRecorder = (entry: RequestAuditEntry) => void;

export interface RequestBrokerCoordination {
  ledger: ScanRequestLedger;
  lane: RequestLedgerLane;
}

/** Structural native adapter only; the browser layer owns SDK construction. */
export interface NativeBrowserRoute {
  request(): { url(): string; method(): string; postDataBuffer(): Buffer | null };
  continue(options: { headers: Record<string, string> }): Promise<void>;
  abort(errorCode?: string): Promise<void>;
}
interface NativeBrowserSource { route: NativeBrowserRoute; session: object; headers: Record<string, string>; onInitiated?: () => void; onDenied?: () => void }
interface BoundBrowserOperation {
  permit?: object;
  initiation: Promise<boolean>; finishInitiation: (initiated: boolean) => void;
  route: NativeBrowserRoute; request: object; session: object; url: string; method: string; headers: Readonly<Record<string, string>>; body: Buffer; login: boolean;
  registered: boolean; continued: boolean; consumed: boolean; onInitiated?: () => void; onDenied?: () => void;
}
const maxRedirects = 5;
class BrowserDispatchDenied extends Error { public constructor(public readonly stage: "BROWSER_BINDING_INVALID" | "BROWSER_FINAL_SCOPE_DENIED" | "BROWSER_NATIVE_IDENTITY_CHANGED" | "BROWSER_HEADER_PERMISSION_DENIED") { super(stage); } }
class StopTransportRetry extends Error { public constructor(public readonly response: HttpResponse) { super("TERMINAL_TRANSPORT_RESULT"); } }
class DispatchPolicyDenied extends Error { public constructor(reason?: string) { super(fixedDispatchDenial(reason)); this.name = "TargetAuthorizationDenied"; } }

// Scan-local intent history includes pending/cache/error requests, not just
// completion audit. Native peers share the original ledger object identity.
// The register carries no raw routes and never changes ordinary GET permits.
interface PrivateGetHistory { salt: Buffer; identities: Set<string>; saturated: boolean }
const privateGetHistories = new WeakMap<object, PrivateGetHistory>();
const maximumGetIdentities = 10_000;
function privateGetIdentity(history: PrivateGetHistory, url: string): string {
  return createHmac("sha256", history.salt).update("GET\n").update(normalizeUrl(url)).digest("hex");
}

export class RequestSafetyBroker {
  private readonly transport: HttpClient;
  private readonly rateLimiter: RateLimiter;
  private readonly queue: RequestQueue;
  private readonly retryPolicy: RetryPolicy;
  private readonly browserBindings = new WeakMap<BrowserBrokerDecision, BoundBrowserOperation>();
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
  private readonly userAgent: string;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly dnsResolver: RequestBrokerOptions["dnsResolver"];
  private readonly tlsCa: string | undefined;

  public constructor(
    options: RequestBrokerOptions,
    private readonly scopeMatcher: ScopeMatcher,
    private readonly recordAudit: RequestAuditRecorder,
    private readonly coordination?: RequestBrokerCoordination
  ) {
    this.abortSignal = options.abortSignal;
    this.userAgent = options.userAgent;
    this.timeoutMs = options.timeoutMs;
    this.maxResponseBytes = options.maxResponseBytes;
    this.dnsResolver = options.dnsResolver;
    this.tlsCa = options.connectionPool?.settings.trustedCaPem ?? options.transport?.trustedCaPem;
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
      ...(options.transport ? { transport: options.transport } : {}),
      ...(options.connectionPool ? { connectionPool: options.connectionPool } : {}),
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

  /** Releases a transport pool owned by this broker. Scan-scoped brokers use
   * the shared pool owned by ScanContext, so closing one cannot disrupt peers. */
  public async close(): Promise<void> {
    await this.transport.close();
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

  /** Internal read-only refusal signal; this never grants dispatch authority. */
  public hasTrustedDiscoveryGetConflict(url: string): boolean {
    const history = privateGetHistories.get(this.coordination?.ledger ?? this);
    if (!history) return false;
    if (history.saturated) return true;
    try { return history.identities.has(privateGetIdentity(history, url)); }
    catch { return true; }
  }

  private recordOrdinaryGetIntent(method: string, url: string): void {
    if (method.toUpperCase() !== "GET") return;
    const owner = this.coordination?.ledger ?? this;
    let history = privateGetHistories.get(owner);
    if (!history) { history = { salt: randomBytes(32), identities: new Set(), saturated: false }; privateGetHistories.set(owner, history); }
    if (history.saturated) return;
    if (url.length > 8192) { history.saturated = true; return; }
    try {
      const identity = privateGetIdentity(history, url);
      if (history.identities.has(identity)) return;
      if (history.identities.size >= maximumGetIdentities) { history.saturated = true; return; }
      history.identities.add(identity);
    } catch { history.saturated = true; }
  }

  /** Internal, unregistered owned-fixture seam. Public request fields cannot
   * construct its private native binding. All ordinary P0C paths are unchanged. */
  public async dispatchTrustedDiscoveryGet(token: unknown): Promise<TrustedDiscoveryFacts> {
    if (this.coordination?.lane !== "SCAN") return discoveryFacts("DENIED_OPERATOR_BINDING");
    let operation: ReturnType<typeof claimTrustedDiscoveryOperation>;
    try { operation = claimTrustedDiscoveryOperation(token, this, this.scopeMatcher, this.coordination.ledger); }
    catch (error) { return discoveryFacts(error instanceof TrustedDiscoveryDenial ? error.code : "DENIED_OPERATOR_BINDING"); }
    let code: TrustedDiscoveryFacts["code"] = "ATTEMPTED", responseObserved = 0, auditEvents = 0;
    const request: HttpRequest = { url: operation.url, method: "GET", skipCache: true, disableRedirects: true, disableRetries: true, retainBodyPreview: false, streamLimitBytes: 4096 };
    const verify = () => {
      this.throwIfAborted();
      try { operation.verify(); }
      catch (error) { operation.failure = error instanceof TrustedDiscoveryDenial ? error.code : "DENIED_SOURCE_STALE"; throw new DispatchPolicyDenied(); }
    };
    try {
      const url = new URL(operation.url);
      if (url.origin !== this.scopeMatcher.targetOrigin() || url.protocol !== "http:" || !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) || this.userAgent !== "RouteCairn/0.1" || this.hasExpiringAuthority()) throw new TrustedDiscoveryDenial("DENIED_SCOPE");
      verify();
      const dispatched = await this.queue.run(() => this.coordination!.ledger.transmit("SCAN", this.abortSignal, () => this.transport.send(request, operation.url, [], {
        expiringAuthority: false,
        loopbackOnly: true,
        begin: () => { verify(); this.commitHttpInitiation(request, operation.url); operation.initiated = true; }
      }), { reserveAtInitiation: true }));
      if (!dispatched.accepted) code = "DENIED_CAPACITY";
      else {
        responseObserved = typeof dispatched.value.statusCode === "number" ? 1 : 0;
        code = operation.failure ?? (responseObserved ? "RESPONSE_OBSERVED" : operation.initiated ? "INCONCLUSIVE" : dispatched.value.error?.name === "RequestBudgetExceeded" ? "DENIED_CAPACITY" : "INCONCLUSIVE");
      }
    } catch (error) {
      code = error instanceof ScanCancelledError || this.abortSignal?.aborted ? "DENIED_CANCELLED" : operation.failure ?? (error instanceof TrustedDiscoveryDenial ? error.code : "INCONCLUSIVE");
    }
    try {
      this.recordAudit({ requestedUrl: "redacted://trusted-discovery", finalUrl: "redacted://trusted-discovery", method: "GET", outcome: operation.initiated ? "sent" : "scope-skipped", requestHeaders: {}, redirectChain: [], source: "http", transmittedRequests: this.sentRequestCount });
      auditEvents = 1;
    } catch { /* Observer errors never expose route material or change initiation facts. */ }
    return discoveryFacts(code, 1, operation.initiated ? 1 : 0, responseObserved, auditEvents);
  }

  /** Dedicated raw HTTP/1 lane for proof-gated desynchronization cases. It
   * keeps the same origin, authorization, rate, concurrency, ledger, and
   * audit controls as ordinary requests, while allowing the transport to
   * preserve an explicitly generated ambiguous framing pair. */
  public async sendRawHttp1(requestInput: Omit<RawHttp1Request, "timeoutMs" | "maxResponseBytes" | "userAgent" | "abortSignal" | "targetOrigin" | "dnsResolver">): Promise<RawHttp1Response> {
    this.throwIfAborted();
    requestInput = { ...requestInput, headers: { ...requestInput.headers }, body: requestInput.body.replace(/[\r\n\0]/g, " ").slice(0, 4096) };
    const scopeDecision = this.scopeMatcher.decide(requestInput.url, requestInput.method, requestInput.body);
    const sentinelUrl = new URL(requestInput.sentinelPath, new URL(requestInput.url).origin).toString();
    const sentinelDecision = this.scopeMatcher.decide(sentinelUrl, "GET");
    if (!scopeDecision.allowed || !scopeDecision.normalizedUrl || !sentinelDecision.allowed || !sentinelDecision.normalizedUrl) return blockedRawResponse("redacted://raw-policy-denied", "RAW_HTTP1_SCOPE_BLOCKED");
    // The generated sentinel uses the POST Host. Permission for another origin
    // cannot authorize that path on the actual connected origin.
    if (new URL(sentinelDecision.normalizedUrl).origin !== new URL(scopeDecision.normalizedUrl).origin) return blockedRawResponse("redacted://raw-policy-denied", "RAW_HTTP1_SENTINEL_ORIGIN_BLOCKED");
    if ((requestInput.marker && !/^[A-Za-z0-9._:-]{1,128}$/.test(requestInput.marker)) || Object.entries(requestInput.headers).some(([name, value]) => /[\r\n]/.test(name) || /[\r\n]/.test(value) || ["host", "content-length", "transfer-encoding", "connection", "proxy-connection", "expect", "upgrade", "trailer"].includes(name.toLowerCase()))) return blockedRawResponse("redacted://raw-policy-denied", "RAW_HTTP1_FRAMING_HEADER_BLOCKED");
    const url = scopeDecision.normalizedUrl;
    const pair = [{ url, method: "POST", body: requestInput.body }, { url: sentinelDecision.normalizedUrl, method: "GET" }];
    const begin = () => {
      this.throwIfAborted();
      if (this.sentRequestCount + 2 > this.maxRequests || (this.coordination && !this.coordination.ledger.hasCapacity(this.coordination.lane, 2))) { const error = new Error("RAW_HTTP1_BUDGET_EXHAUSTED"); error.name = "RequestBudgetExceeded"; throw error; }
      const postDenied = this.authorizeFinalHttpAttempt({ url, method: "POST", headers: requestInput.headers, body: requestInput.body }, url, false);
      const getDenied = this.authorizeFinalHttpAttempt({ url: pair[1]!.url, method: "GET" }, pair[1]!.url, false);
      if (postDenied || getDenied) throw new DispatchPolicyDenied();
      const denied = this.scopeMatcher.authorization?.reserveBatch(pair); if (denied) throw new DispatchPolicyDenied(denied);
      if (this.coordination && !this.coordination.ledger.tryReserve(this.coordination.lane, 2)) throw new DispatchPolicyDenied();
      this.sentRequestCount += 2;
    };
    const operation = () => sendRawHttp1({ ...requestInput, ...(this.tlsCa ? { tlsCa: this.tlsCa } : {}), url, sentinelPath: pair[1]!.url, timeoutMs: this.timeoutMs, maxResponseBytes: this.maxResponseBytes, userAgent: this.userAgent, ...(this.abortSignal ? { abortSignal: this.abortSignal } : {}), targetOrigin: this.scopeMatcher.targetOrigin(), ...(this.dnsResolver ? { dnsResolver: this.dnsResolver } : {}) }, begin);
    const response = await this.queue.run(async () => {
      await this.scopeMatcher.authorization?.waitForRate(this.abortSignal, 2);
      if (this.coordination) {
        const dispatched = await this.coordination.ledger.transmit(this.coordination.lane, this.abortSignal, operation, { reserveAtInitiation: true, reservationCount: 2 });
        return dispatched.accepted ? dispatched.value : blockedRawResponse("redacted://raw-policy-denied", "RequestBudgetExceeded");
      }
      await this.rateLimiter.wait(this.abortSignal, 2); this.throwIfAborted();
      return operation();
    });
    if (!response.transmittedRequests) response.requestedUrl = "redacted://raw-policy-denied";
    this.recordAudit({ requestedUrl: "redacted://raw-operation", finalUrl: "redacted://raw-operation", method: requestInput.method, outcome: response.transmittedRequests ? "sent" : response.error?.name === "RequestBudgetExceeded" ? "budget-skipped" : "scope-skipped", requestHeaders: {}, transmittedRequests: response.transmittedRequests, ...(response.statusCodes[0] !== undefined ? { statusCode: response.statusCodes[0] } : {}), ...(response.error ? { error: response.error.message } : {}), redirectChain: [], source: "http" });
    return response;
  }

  public async sendSynchronizedMutations(requests: readonly HttpRequest[]): Promise<SynchronizedMutationBatchResult> {
    requests = requests.map(request => ({ ...request, ...(request.headers ? { headers: { ...request.headers } } : {}) }));
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
    // Freeze actual method/body/header values before any queue wait.
    requestInput = { ...requestInput, ...(requestInput.headers ? { headers: { ...requestInput.headers } } : {}) };
    this.throwIfAborted();
    const observation = this.valueAttestor.observe(requestInput.url, requestInput.headers);
    if ((requestInput.method === "DELETE" && !this.controlledDeletionEnabled) || ((requestInput.method === "PATCH" || requestInput.method === "PUT") && !this.controlledMutationEnabled)) {
      const reason = requestInput.method === "DELETE" ? "controlled-deletion-mode-required" : "controlled-mutation-mode-required";
      const baseResponse = sanitizeResponse(skippedResponse(requestInput, "ControlledMutationBlocked", `Request blocked by scan-wide broker: ${reason}.`), observation);
      const response = this.finalizeResponse(baseResponse, observation, "policy-blocked");
      this.recordAudit(auditEntry(requestInput, response, "scope-skipped", [], reason, this.auditFingerprintSalt));
      return response;
    }
    const scopeDecision = this.scopeMatcher.decide(requestInput.url, requestInput.method, requestInput.body);

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
    this.recordOrdinaryGetIntent(scopedRequest.method, scopedRequest.url);
    const key = requestKey(scopedRequest, this.auditFingerprintSalt);

    const cacheable = (scopedRequest.method === "GET" || scopedRequest.method === "HEAD" || scopedRequest.method === "OPTIONS") && !scopedRequest.skipCache;
    if (cacheable) {
      const cached = this.requestCache.get(key);
      if (cached) {
        let reused: HttpResponse;
        try { reused = cloneResponse(await cached); }
        catch (error) {
          this.requestCache.delete(key);
          if (error instanceof StopTransportRetry) reused = sanitizeResponse(cloneResponse(error.response), observation);
          else { if (!(error instanceof DispatchPolicyDenied)) throw error; reused = dispatchDeniedResponse(scopedRequest.method, error.message); }
        }
        if (reused.error?.name === "TargetAuthorizationDenied") {
          this.requestCache.delete(key);
          const denied = dispatchDeniedResponse(scopedRequest.method, reused.error.message);
          this.recordAudit({ requestedUrl: denied.requestedUrl, finalUrl: denied.finalUrl, method: scopedRequest.method, outcome: "scope-skipped", requestHeaders: {}, redirectChain: [], error: denied.error!.message, source: "http", transmittedRequests: this.sentRequestCount });
          return denied;
        }
        const response = this.finalizeResponse(reused, observation, "cache-reused");
        this.recordAudit(auditEntry(scopedRequest, response, "duplicate-skipped", response.redirectChain, undefined, this.auditFingerprintSalt));
        return response;
      }
    }

    const responsePromise = this.queue.run(async () => {
      this.throwIfAborted();
      if (dispatchBarrier) await dispatchBarrier;
      this.throwIfAborted();
      const rawResponse = scopedRequest.disableRetries || isMutationMethod(scopedRequest.method)
        ? await this.sendWithRedirects(scopedRequest, scopedRequest.url, [], bypassRateLimit, onDispatch)
        : await this.retryPolicy.run(async () => {
          const value = await this.sendWithRedirects(scopedRequest, scopedRequest.url, [], false, onDispatch);
          // A final policy denial is terminal, not a retriable transport error.
          if (value.error?.name === "TargetAuthorizationDenied") throw new DispatchPolicyDenied(value.error.message);
          if (value.error?.name === "TransportReplayBlocked") throw new StopTransportRetry(value);
          return value;
        });
      if (scopedRequest.transientBodyConsumer && rawResponse.bodyPreview !== undefined) {
        scopedRequest.transientBodyConsumer(rawResponse.bodyPreview);
      }
      scopedRequest.transientResponseConsumer?.({ ...(rawResponse.statusCode !== undefined ? { statusCode: rawResponse.statusCode } : {}), headers: rawResponse.headers, ...(rawResponse.redirectLocation ? { redirectLocation: rawResponse.redirectLocation } : {}) });
      return attachTransientResponseAnalysis(sanitizeResponse(rawResponse, observation), rawResponse);
    });

    if (cacheable) this.requestCache.set(key, responsePromise);
    let response: HttpResponse;
    try { response = cloneResponse(await responsePromise); }
    catch (error) {
      if (cacheable) this.requestCache.delete(key);
      if (error instanceof StopTransportRetry) response = sanitizeResponse(cloneResponse(error.response), observation);
      else { if (!(error instanceof DispatchPolicyDenied)) throw error; response = dispatchDeniedResponse(scopedRequest.method, error.message); }
    }
    if (response.error?.name === "TargetAuthorizationDenied") {
      if (cacheable) this.requestCache.delete(key);
      const denied = dispatchDeniedResponse(scopedRequest.method, response.error.message);
      this.recordAudit({ requestedUrl: denied.requestedUrl, finalUrl: denied.finalUrl, method: scopedRequest.method, outcome: "scope-skipped", requestHeaders: {}, redirectChain: [], error: denied.error!.message, source: "http", transmittedRequests: this.sentRequestCount });
      return denied;
    }
    const finalizedResponse = this.finalizeResponse(response, observation, transportOutcomeFor(response));
    this.recordAudit(auditEntry(scopedRequest, finalizedResponse, auditOutcome(finalizedResponse), finalizedResponse.redirectChain, undefined, this.auditFingerprintSalt));
    return finalizedResponse;
  }

  public evaluateBrowserRequest(requestInput: BrowserBrokerRequest, source?: NativeBrowserSource): BrowserBrokerDecision {
    const captured = source ? this.captureBrowserSource(requestInput, source, false) : undefined;
    if (source && !captured) return this.fixedBrowserDenial();
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

    const scopeDecision = this.scopeMatcher.decide(scopeUrlForBrowserRequest(requestInput), method, captured?.body);
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

    const reservation = captured ? this.scopeMatcher.authorization?.reserveBrowserAttempt(captured.url, method, captured.body) : undefined;
    const authorizationDenied = captured ? reservation?.denied : this.scopeMatcher.authorization?.reserve(scopeDecision.normalizedUrl, method);
    if (captured && reservation?.permit) captured.permit = reservation.permit;
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
    const approved: BrowserBrokerDecision = { allowed: true, normalizedUrl: scopeDecision.normalizedUrl, reason: "allowed", policyEventCount, transmittedRequestCount: this.sentRequestCount };
    if (captured) this.browserBindings.set(approved, captured);
    return approved;
  }

  /**
   * Allows only an explicitly configured browser login POST through the same
   * scope and request budgets. This is intentionally separate from ordinary
   * browser traffic so learned writes can never inherit login authority.
   */
  public evaluateBrowserLoginRequest(requestInput: BrowserBrokerRequest, source?: NativeBrowserSource): BrowserBrokerDecision {
    const captured = source ? this.captureBrowserSource(requestInput, source, true) : undefined;
    if (source && !captured) return this.fixedBrowserDenial();
    const method = requestInput.method.toUpperCase();
    if (method !== "POST") return this.evaluateBrowserRequest(requestInput, source);
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
    const scopeDecision = this.scopeMatcher.decide(scopeUrlForBrowserRequest(requestInput), method, captured?.body);
    const audit = this.browserAuditBase(requestInput, observation, policyEventCount, this.sentRequestCount, "policy-blocked");
    if (!scopeDecision.allowed || !scopeDecision.normalizedUrl) {
      this.recordAudit({ ...audit, outcome: "browser-policy-blocked", scopeReason: scopeDecision.reason, browserPolicyReason: `scope-${scopeDecision.reason}`, error: `Explicit browser login POST blocked before transmission: ${scopeDecision.reason}.` });
      return { allowed: false, ...(scopeDecision.normalizedUrl ? { normalizedUrl: scopeDecision.normalizedUrl } : {}), reason: `scope-${scopeDecision.reason}`, policyEventCount, transmittedRequestCount: this.sentRequestCount };
    }
    const reservation = captured ? this.scopeMatcher.authorization?.reserveBrowserAttempt(captured.url, method, captured.body) : undefined;
    const authorizationDenied = captured ? reservation?.denied : this.scopeMatcher.authorization?.reserve(scopeDecision.normalizedUrl, method);
    if (captured && reservation?.permit) captured.permit = reservation.permit;
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
    const approved: BrowserBrokerDecision = { allowed: true, normalizedUrl: scopeDecision.normalizedUrl, reason: "allowed", policyEventCount, transmittedRequestCount: this.sentRequestCount };
    if (captured) this.browserBindings.set(approved, captured);
    return approved;
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
    if (this.hasExpiringAuthority()) throw new DispatchPolicyDenied();
    if (this.coordination) return this.coordination.ledger.dispatchReserved(this.coordination.lane, this.abortSignal, operation);
    return this.queue.run(async () => {
      await this.rateLimiter.wait(this.abortSignal);
      this.throwIfAborted();
      return operation();
    });
  }

  /** Private native route identity stays in process; a JSON decision has no binding. */
  public registerBrowserDecision(decision: BrowserBrokerDecision, route: NativeBrowserRoute, session: object): void {
    const bound = this.browserBindings.get(decision);
    if (!bound || bound.route !== route || bound.request !== route.request() || bound.session !== session || bound.registered || bound.consumed) throw new DispatchPolicyDenied();
    bound.registered = true;
  }

  public cancelBrowserDecision(decision: BrowserBrokerDecision): void { this.browserBindings.get(decision)?.finishInitiation(false); this.browserBindings.delete(decision); }

  public hasPendingBrowserDecision(decision: BrowserBrokerDecision): boolean { return this.browserBindings.has(decision); }

  public matchesBrowserProxyRequest(decision: BrowserBrokerDecision, session: object, actual: { url: string; method: string; headers: Record<string, string | string[]>; body: Buffer }): boolean {
    const bound = this.browserBindings.get(decision);
    return Boolean(bound && bound.registered && bound.continued && !bound.consumed && bound.session === session && bound.url === actual.url && bound.method === actual.method.toUpperCase() && bound.body.equals(actual.body) && browserHeadersMatch(bound.headers, actual.headers));
  }

  public beginBrowserProxyRequest(decision: BrowserBrokerDecision, session: object, actual: { url: string; method: string; headers: Record<string, string | string[]>; body: Buffer }): void {
    const bound = this.browserBindings.get(decision);
    if (!bound || !this.matchesBrowserProxyRequest(decision, session, actual)) throw new DispatchPolicyDenied();
    bound.consumed = true;
    try {
      this.checkBoundBrowserOperation(bound, actual.body);
      if (this.scopeMatcher.authorization?.beginReservedBrowserAttempt(bound.permit, bound.url, bound.method, actual.body)) throw new DispatchPolicyDenied();
      // Reservation happened at policy preflight; do not reserve twice. It is an ATTEMPTED count.
    } catch (error) { bound.onDenied?.(); this.fixedBrowserDenial(); this.cancelBrowserDecision(decision); throw error instanceof ScanCancelledError ? error : new DispatchPolicyDenied(); }
  }

  public observeBrowserInitiation(decision: BrowserBrokerDecision): void {
    const bound = this.browserBindings.get(decision); if (!bound || !bound.consumed) return;
    this.browserBindings.delete(decision);
    bound.finishInitiation(true);
    this.recordAudit({ requestedUrl: "redacted://browser-initiation", finalUrl: "redacted://browser-initiation", method: bound.method, outcome: "sent", requestHeaders: {}, redirectChain: [], source: "browser", transmittedRequests: this.sentRequestCount });
    bound.onInitiated?.();
  }

  public async dispatchBrowserRoute(decision: BrowserBrokerDecision, route: NativeBrowserRoute, session: object): Promise<boolean> {
    let continued = false;
    const operation = async () => {
      const bound = this.browserBindings.get(decision);
      if (!bound || bound.route !== route || bound.request !== route.request() || bound.session !== session || !bound.registered || bound.continued || bound.consumed) throw new BrowserDispatchDenied("BROWSER_BINDING_INVALID");
      this.checkBoundBrowserOperation(bound, bound.body);
      const native = route.request();
      if (native.url() !== bound.url || native.method().toUpperCase() !== bound.method || !(native.postDataBuffer() ?? Buffer.alloc(0)).equals(bound.body)) throw new BrowserDispatchDenied("BROWSER_NATIVE_IDENTITY_CHANGED");
      bound.continued = true; continued = true;
      await route.continue({ headers: { ...bound.headers } });
      if (new URL(bound.url).protocol === "https:" && !this.hasExpiringAuthority()) { bound.consumed = true; this.observeBrowserInitiation(decision); }
      // Chromium acknowledgement precedes proxy DNS/connect. Retain the shared
      // slot through that final boundary, with bounded cancellation/timeout.
      await this.waitForBrowserInitiation(bound);
    };
    try {
      if (this.coordination) await this.coordination.ledger.dispatchReserved(this.coordination.lane, this.abortSignal, operation);
      else await this.queue.run(async () => { await this.rateLimiter.wait(this.abortSignal); this.throwIfAborted(); await operation(); });
      return continued;
    } catch (error) {
      this.browserBindings.get(decision)?.onDenied?.();
      this.cancelBrowserDecision(decision); this.fixedBrowserDenial(error instanceof BrowserDispatchDenied ? error.stage : "BROWSER_ROUTE_CONTINUATION_FAILED");
      await route.abort("blockedbyclient").catch(() => undefined);
      if (error instanceof ScanCancelledError || this.abortSignal?.aborted) throw new ScanCancelledError();
      return false;
    }
  }

  private captureBrowserSource(input: BrowserBrokerRequest, source: NativeBrowserSource, login: boolean): BoundBrowserOperation | undefined {
    try {
      const native = source.route.request(); const url = native.url(); const method = native.method().toUpperCase(); const body = Buffer.from(native.postDataBuffer() ?? Buffer.alloc(0));
      if (url !== input.url || method !== input.method.toUpperCase() || body.length > 1024 * 1024 || Object.entries(source.headers).reduce((n, [k,v]) => n + k.length + v.length, 0) > 16384) return;
      if (this.hasExpiringAuthority() && new URL(url).protocol !== "http:") return;
      let finishInitiation!: (initiated: boolean) => void;
      const initiation = new Promise<boolean>(resolve => { finishInitiation = resolve; });
      return { initiation, finishInitiation, route: source.route, request: native, session: source.session, url, method, body, headers: Object.freeze({ ...source.headers }), login, registered: false, continued: false, consumed: false, ...(source.onInitiated ? { onInitiated: source.onInitiated } : {}), ...(source.onDenied ? { onDenied: source.onDenied } : {}) };
    } catch { return; }
  }

  private async waitForBrowserInitiation(bound: BoundBrowserOperation): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let abort: (() => void) | undefined;
    try {
      await new Promise<void>((resolve, reject) => {
        abort = () => reject(new ScanCancelledError());
        this.abortSignal?.addEventListener("abort", abort, { once: true });
        timer = setTimeout(() => reject(new DispatchPolicyDenied()), this.timeoutMs);
        if (this.abortSignal?.aborted) { abort(); return; }
        void bound.initiation.then(initiated => initiated ? resolve() : reject(new DispatchPolicyDenied()));
      });
    } finally { clearTimeout(timer); if (abort) this.abortSignal?.removeEventListener("abort", abort); }
  }

  private checkBoundBrowserOperation(bound: BoundBrowserOperation, body: Buffer): void {
    this.throwIfAborted();
    const scope = this.scopeMatcher.decide(bound.url, bound.method, body);
    if (!scope.allowed || !scope.normalizedUrl || new URL(scope.normalizedUrl).origin !== new URL(bound.url).origin || new URL(scope.normalizedUrl).pathname !== new URL(bound.url).pathname || this.authorizeBrowserTransmission({ url: bound.url, method: bound.method, resourceType: "document" }, bound.login) || this.scopeMatcher.authorization?.check(bound.url, bound.method, body)) throw new BrowserDispatchDenied("BROWSER_FINAL_SCOPE_DENIED");
    if (this.scopeMatcher.authorization?.plan.bugBounty && !this.scopeMatcher.authorization.plan.bugBounty.authenticationPermitted && Object.keys(bound.headers).some(name => !isPublicBrowserHeader(name))) throw new BrowserDispatchDenied("BROWSER_HEADER_PERMISSION_DENIED");
  }

  private fixedBrowserDenial(reason = "REQUEST_DISPATCH_POLICY_DENIED"): BrowserBrokerDecision {
    if (!["BROWSER_BINDING_INVALID", "BROWSER_FINAL_SCOPE_DENIED", "BROWSER_NATIVE_IDENTITY_CHANGED", "BROWSER_HEADER_PERMISSION_DENIED", "BROWSER_ROUTE_CONTINUATION_FAILED"].includes(reason)) reason = "REQUEST_DISPATCH_POLICY_DENIED";
    this.recordAudit({ requestedUrl: "redacted://browser-policy-denied", finalUrl: "redacted://browser-policy-denied", method: "GET", outcome: "browser-policy-blocked", requestHeaders: {}, redirectChain: [], source: "browser", browserPolicyReason: reason, error: reason, transmittedRequests: this.sentRequestCount });
    return { allowed: false, reason, policyEventCount: this.browserPolicyEventCount, transmittedRequestCount: this.sentRequestCount };
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
    this.recordOrdinaryGetIntent(requestInput.method, currentUrl);
    const authorization = this.scopeMatcher.authorization;
    if (!synchronized) await authorization?.waitForRate(this.abortSignal);
    if (this.sentRequestCount >= this.maxRequests) {
      return skippedResponse(requestInput, "RequestBudgetExceeded", `Request skipped because broker request budget (${this.maxRequests}) was exhausted.`);
    }

    let response: HttpResponse;
    if (this.coordination) {
      let brokerBudgetDenied = false;
      let policyDenial: string | undefined;
      const dispatched = await this.coordination.ledger.transmit(
        this.coordination.lane,
        this.abortSignal,
        () => this.transport.send(requestInput, currentUrl, redirectChain, { expiringAuthority: this.hasExpiringAuthority(), begin: () => this.commitHttpInitiation(requestInput, currentUrl, onDispatch) }),
        { rateAlreadyReserved: synchronized, reserveAtInitiation: true,
          beforeTransmit: () => { if (this.sentRequestCount >= this.maxRequests) { brokerBudgetDenied = true; return false; } policyDenial = this.authorizeFinalHttpAttempt(requestInput, currentUrl, false); return policyDenial === undefined; },
          onReserved: () => undefined }
      );
      if (!dispatched.accepted) {
        if (dispatched.reason === "POLICY_DENIED" && !brokerBudgetDenied) return dispatchDeniedResponse(requestInput.method, policyDenial);
        const shared = this.coordination.ledger.snapshot();
        const capacity = this.coordination.lane === "CLEANUP" ? shared.cleanupReservedRequests : shared.scanCapacity;
        return skippedResponse(requestInput, "RequestBudgetExceeded", `Request skipped because the scan-wide ${this.coordination.lane.toLowerCase()} request capacity (${capacity}) was exhausted.`);
      }
      response = dispatched.value;
    } else {
      if (!synchronized) await this.rateLimiter.wait(this.abortSignal);
      this.throwIfAborted();
      if (this.sentRequestCount >= this.maxRequests) return skippedResponse(requestInput, "RequestBudgetExceeded", "BROKER_REQUEST_BUDGET_EXHAUSTED");
      const policyDenial = this.authorizeFinalHttpAttempt(requestInput, currentUrl, false);
      if (policyDenial) return dispatchDeniedResponse(requestInput.method, policyDenial);
      response = await this.transport.send(requestInput, currentUrl, redirectChain, { expiringAuthority: this.hasExpiringAuthority(), begin: () => this.commitHttpInitiation(requestInput, currentUrl, onDispatch) });
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

    const redirectDecision = this.scopeMatcher.decide(nextUrl, requestInput.method, requestInput.body);
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

  /** Broker-owned synchronous refusal gate; no request-supplied approval callback. */
  private authorizeFinalHttpAttempt(request: HttpRequest, currentUrl: string, reserve = true): string | undefined {
    this.throwIfAborted();
    try {
      const decision = this.scopeMatcher.decide(currentUrl, request.method, request.body);
      if (!decision.allowed || decision.normalizedUrl !== currentUrl) return "REQUEST_DISPATCH_POLICY_DENIED";
      const authorization = this.scopeMatcher.authorization;
      if (authorization?.plan.bugBounty && !authorization.plan.bugBounty.authenticationPermitted && Object.keys(request.headers ?? {}).some((name) => !["accept", "content-type", "user-agent", "range", "cache-control", "if-none-match", "if-modified-since"].includes(name.toLowerCase()))) return "REQUEST_DISPATCH_POLICY_DENIED";
      const denied = reserve ? authorization?.reserve(currentUrl, request.method, request.body) : authorization?.check(currentUrl, request.method, request.body);
      return denied === undefined ? undefined : fixedDispatchDenial(denied);
    } catch (error) { if (error instanceof ScanCancelledError) throw error; return "REQUEST_DISPATCH_POLICY_DENIED"; }
  }

  public hasExpiringAuthority(): boolean { return Boolean(this.scopeMatcher.authorization?.plan.bugBounty); }

  private commitHttpInitiation(request: HttpRequest, url: string, onDispatch?: (timeMs: number) => void): void {
    this.throwIfAborted();
    if (this.sentRequestCount >= this.maxRequests || (this.coordination && !this.coordination.ledger.hasCapacity(this.coordination.lane))) {
      const error = new Error("REQUEST_INITIATION_BUDGET_EXHAUSTED"); error.name = "RequestBudgetExceeded"; throw error;
    }
    const denied = this.authorizeFinalHttpAttempt(request, url);
    if (denied) throw new DispatchPolicyDenied(denied);
    if (this.coordination && !this.coordination.ledger.tryReserve(this.coordination.lane)) throw new DispatchPolicyDenied();
    this.sentRequestCount += 1;
    onDispatch?.(Number(process.hrtime.bigint()) / 1_000_000);
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

function fixedDispatchDenial(reason?: string): string {
  return reason === "authorization-budget-exhausted" ? reason : "REQUEST_DISPATCH_POLICY_DENIED";
}

function dispatchDeniedResponse(method: HttpRequest["method"], reason?: string): HttpResponse {
  return { requestedUrl: "redacted://dispatch-policy-denied", finalUrl: "redacted://dispatch-policy-denied", method, headers: {}, responseTimeMs: 0, redirectChain: [], error: { name: "TargetAuthorizationDenied", message: fixedDispatchDenial(reason) } };
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

function blockedRawResponse(url: string, reason: string): RawHttp1Response {
  return { requestedUrl: url, statusCodes: [], responseCount: 0, bodyPreview: "", bodyHash: createHash("sha256").update("").digest("hex"), responseTimeMs: 0, transmittedRequests: 0, markerObserved: false, error: { name: reason === "RequestBudgetExceeded" ? "RequestBudgetExceeded" : "RawHttp1PolicyBlocked", message: reason } };
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
      Array.isArray(value) ? value.map((item) => scrubObservedValues(["location", "content-location"].includes(name.toLowerCase()) ? redactSensitiveUrl(item) : item, observation)) : scrubObservedValues(["location", "content-location"].includes(name.toLowerCase()) ? redactSensitiveUrl(value) : value, observation)
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

function canonicalBrowserHeaders(headers: Readonly<Record<string, string | string[]>>): string {
  const ignored = new Set(["host", "connection", "proxy-connection", "proxy-authorization", "content-length", "transfer-encoding"]);
  return JSON.stringify(Object.entries(headers).map(([name,value]) => [name.toLowerCase(), Array.isArray(value) ? value.join(", ") : value.trim()]).filter(([name]) => !ignored.has(name!)).sort((a,b) => a[0]!.localeCompare(b[0]!)));
}
function isPublicBrowserHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return lower.startsWith("sec-") || ["accept", "accept-language", "accept-encoding", "user-agent", "content-type", "content-length", "host", "connection", "origin", "referer", "cache-control", "pragma", "priority", "upgrade-insecure-requests", "range", "if-none-match", "if-modified-since"].includes(lower);
}

function browserHeadersMatch(expected: Readonly<Record<string, string>>, actual: Record<string, string | string[]>): boolean {
  // Chromium adds these public transport metadata headers after Fetch interception.
  // Original headers (especially cookie/auth/origin) still match exactly; unknown additions deny.
  const generated = new Set(["pragma", "cache-control", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding"]);
  const normalizedExpected = Object.fromEntries(Object.entries(expected).map(([name,value]) => [name.toLowerCase(), value]));
  const selected = Object.fromEntries(Object.entries(actual).filter(([name]) => name.toLowerCase() in normalizedExpected || !generated.has(name.toLowerCase())));
  return canonicalBrowserHeaders(normalizedExpected) === canonicalBrowserHeaders(selected);
}
