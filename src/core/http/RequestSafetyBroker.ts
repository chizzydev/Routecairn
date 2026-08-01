import { createHash } from "node:crypto";
import { redactHeaders } from "../evidence/EvidenceBuilder.js";
import type { ScopeMatcher } from "../scope/ScopeMatcher.js";
import { HttpClient } from "./HttpClient.js";
import { RateLimiter } from "./RateLimiter.js";
import { RequestQueue } from "./RequestQueue.js";
import { RetryPolicy } from "./RetryPolicy.js";
import type { BrowserBrokerDecision, BrowserBrokerRequest, HttpRequest, HttpResponse, RedirectHop, RequestAuditEntry, RequestBrokerOptions } from "./HttpTypes.js";

export type RequestAuditRecorder = (entry: RequestAuditEntry) => void;

const maxRedirects = 5;

export class RequestSafetyBroker {
  private readonly transport: HttpClient;
  private readonly rateLimiter: RateLimiter;
  private readonly queue: RequestQueue;
  private readonly retryPolicy: RetryPolicy;
  private readonly requestCache = new Map<string, Promise<HttpResponse>>();
  private sentRequestCount = 0;
  private browserPolicyEventCount = 0;
  private browserPolicyEventLimit = 0;
  private readonly maxRequests: number;

  public constructor(
    options: RequestBrokerOptions,
    private readonly scopeMatcher: ScopeMatcher,
    private readonly recordAudit: RequestAuditRecorder
  ) {
    this.transport = new HttpClient({
      userAgent: options.userAgent,
      timeoutMs: options.timeoutMs,
      bodyPreviewBytes: options.bodyPreviewBytes,
      maxResponseBytes: options.maxResponseBytes
    });
    this.rateLimiter = new RateLimiter(options.rateLimitPerSecond);
    this.queue = new RequestQueue(options.concurrency);
    this.retryPolicy = new RetryPolicy(options.retry);
    this.maxRequests = options.maxRequests;
  }

  public setBrowserPolicyEventLimit(limit: number): void {
    this.browserPolicyEventLimit = limit;
  }

  public async send(requestInput: HttpRequest): Promise<HttpResponse> {
    const scopeDecision = this.scopeMatcher.decide(requestInput.url, requestInput.method);

    if (!scopeDecision.allowed || !scopeDecision.normalizedUrl) {
      const response = skippedResponse(requestInput, "OutOfScopeRequest", `Request skipped by scan-wide broker: ${scopeDecision.reason}.`);
      this.recordAudit(auditEntry(requestInput, response, "scope-skipped", [], scopeDecision.reason));
      return response;
    }

    const scopedRequest = { ...requestInput, url: scopeDecision.normalizedUrl };
    const key = requestKey(scopedRequest);

    const cached = this.requestCache.get(key);
    if (cached) {
      const response = cloneResponse(await cached);
      this.recordAudit(auditEntry(scopedRequest, response, "duplicate-skipped", response.redirectChain));
      return response;
    }

    const responsePromise = this.queue.run(async () => {
      await this.rateLimiter.wait();
      const response = await this.retryPolicy.run(() => this.sendWithRedirects(scopedRequest, scopedRequest.url, []));
      this.recordAudit(auditEntry(scopedRequest, response, auditOutcome(response), response.redirectChain));
      return response;
    });

    this.requestCache.set(key, responsePromise);
    return responsePromise;
  }

  public evaluateBrowserRequest(requestInput: BrowserBrokerRequest): BrowserBrokerDecision {
    const policyEventCount = this.consumeBrowserPolicyEvent();
    if (typeof policyEventCount !== "number") {
      const baseAudit = browserAuditBase(requestInput, this.browserPolicyEventCount, this.sentRequestCount);
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
    const baseAudit = browserAuditBase(requestInput, policyEventCount, this.sentRequestCount);

    const method = requestInput.method.toUpperCase();
    if (!isSafeBrowserMethod(method)) {
      this.recordAudit({
        ...baseAudit,
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
        ...baseAudit,
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

    if (!this.consumeBudget()) {
      this.recordAudit({
        ...baseAudit,
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
      ...baseAudit,
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

  public recordBrowserPolicyBlock(requestInput: BrowserBrokerRequest, reason: string): BrowserBrokerDecision {
    const policyEventCount = this.consumeBrowserPolicyEvent();
    if (typeof policyEventCount !== "number") {
      const baseAudit = browserAuditBase(requestInput, this.browserPolicyEventCount, this.sentRequestCount);
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
    const baseAudit = browserAuditBase(requestInput, policyEventCount, this.sentRequestCount);

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

  private async sendWithRedirects(requestInput: HttpRequest, currentUrl: string, redirectChain: RedirectHop[]): Promise<HttpResponse> {
    if (!this.consumeBudget()) {
      return skippedResponse(requestInput, "RequestBudgetExceeded", `Request skipped because scan request budget (${this.maxRequests}) was exhausted.`);
    }

    const response = await this.transport.send(requestInput, currentUrl, redirectChain);
    const redirectLocation = response.redirectLocation;

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

    return this.sendWithRedirects(requestInput, redirectDecision.normalizedUrl, nextChain);
  }

  private consumeBudget(): boolean {
    if (this.sentRequestCount >= this.maxRequests) {
      return false;
    }

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
}

function requestKey(requestInput: HttpRequest): string {
  const headers = Object.entries(requestInput.headers ?? {})
    .map(([key, value]) => `${key.toLowerCase()}:${safeValueFingerprint(value)}`)
    .sort()
    .join("|");

  return `${requestInput.method} ${requestInput.url} ${headers}`;
}

function safeValueFingerprint(value: string): string {
  return createHash("sha256").update(value).digest("hex");
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
  return {
    ...response,
    headers: { ...response.headers },
    redirectChain: response.redirectChain.map((hop) => ({ ...hop })),
    ...(response.error ? { error: { ...response.error } } : {})
  };
}

function auditEntry(
  requestInput: HttpRequest,
  response: HttpResponse,
  outcome: RequestAuditEntry["outcome"],
  redirectChain: RedirectHop[],
  scopeReason?: string
): RequestAuditEntry {
  const redacted = redactHeaders(requestInput.headers ?? {});
  return {
    requestedUrl: requestInput.url,
    finalUrl: response.finalUrl,
    method: requestInput.method,
    outcome,
    ...(typeof response.statusCode === "number" ? { statusCode: response.statusCode } : {}),
    requestHeaders: Object.fromEntries(Object.entries(redacted).map(([name, value]) => [name, Array.isArray(value) ? value.join(", ") : value])),
    redirectChain,
    ...(scopeReason ? { scopeReason } : {}),
    ...(response.error ? { error: response.error.message } : {})
  };
}

function browserAuditBase(requestInput: BrowserBrokerRequest, policyEventCount: number, transmittedRequests: number): Omit<RequestAuditEntry, "outcome"> {
  return {
    requestedUrl: redactSensitiveUrl(requestInput.url),
    method: requestInput.method.toUpperCase(),
    requestHeaders: {},
    redirectChain: [],
    source: "browser",
    resourceType: requestInput.resourceType,
    ...(requestInput.pageUrl ? { pageUrl: redactSensitiveUrl(requestInput.pageUrl) } : {}),
    browserPolicyEvents: policyEventCount,
    transmittedRequests
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

function isRedirect(statusCode: number | undefined): boolean {
  return typeof statusCode === "number" && statusCode >= 300 && statusCode < 400;
}

function isSafeBrowserMethod(method: string): boolean {
  return method === "GET" || method === "HEAD" || method === "OPTIONS";
}

function redactSensitiveUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const sensitive = /(?:token|secret|session|cookie|auth|password|pass|key|jwt)/i;
    for (const key of [...parsed.searchParams.keys()]) {
      if (sensitive.test(key)) {
        parsed.searchParams.set(key, "<redacted>");
      }
    }
    parsed.username = "";
    parsed.password = "";
    return parsed.toString();
  } catch {
    return url.replace(/([?&][^=]*(?:token|secret|session|cookie|auth|password|pass|key|jwt)[^=]*=)[^&\s]+/gi, "$1<redacted>");
  }
}
