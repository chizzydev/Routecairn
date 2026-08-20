import type { ValuePresenceAttestation } from "../evidence/ValuePresenceAttestation.js";

export type HttpMethod = "GET" | "HEAD" | "OPTIONS" | "POST";

export interface HttpClientOptions {
  userAgent: string;
  timeoutMs: number;
  bodyPreviewBytes: number;
  maxResponseBytes: number;
  allowedPrivateOrigins?: readonly string[];
  dnsResolver?: DnsResolver;
  dnsTimeoutMs?: number;
  maxDnsAnswers?: number;
  abortSignal?: AbortSignal;
}

export interface RequestBrokerOptions extends HttpClientOptions {
  rateLimitPerSecond: number;
  concurrency: number;
  maxRequests: number;
  retry: RetryPolicyOptions;
}

export interface RetryPolicyOptions {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  retryStatusCodes: number[];
}

export interface DnsAddress {
  address: string;
  family: 4 | 6;
}

export type DnsResolver = (hostname: string) => Promise<readonly (string | DnsAddress)[]>;

export interface HttpRequest {
  url: string;
  method: HttpMethod;
  headers?: Record<string, string>;
  body?: string;
  skipCache?: boolean;
  streamLimitBytes?: number;
  maxStreamContentLength?: number;
  retainBodyPreview?: boolean;
  disableRetries?: boolean;
}

export interface RedirectHop {
  statusCode: number;
  location: string;
}

export interface HttpResponse {
  requestId?: string;
  requestedUrl: string;
  finalUrl: string;
  method: HttpMethod;
  statusCode?: number;
  headers: Record<string, string | string[]>;
  contentType?: string;
  contentLength?: number;
  title?: string;
  bodyPreview?: string;
  bodyHash?: string;
  responseTimeMs: number;
  redirectChain: RedirectHop[];
  redirectLocation?: string;
  bytesRead?: number;
  streamTruncated?: boolean;
  rangeIgnored?: boolean;
  valueAttestations?: readonly ValuePresenceAttestation[];
  error?: {
    name: string;
    message: string;
    code?: string;
  };
}

export type RequestAuditOutcome =
  | "sent"
  | "duplicate-skipped"
  | "scope-skipped"
  | "redirect-scope-skipped"
  | "budget-skipped"
  | "browser-policy-blocked"
  | "browser-network-scheduled"
  | "browser-policy-budget-skipped";

export interface RequestAuditEntry {
  requestId?: string;
  requestedUrl: string;
  finalUrl?: string;
  method: string;
  outcome: RequestAuditOutcome;
  statusCode?: number;
  requestHeaders: Record<string, string>;
  requestBodyHash?: string;
  redirectChain: RedirectHop[];
  scopeReason?: string;
  error?: string;
  source?: "http" | "browser";
  resourceType?: string;
  pageUrl?: string;
  browserPolicyReason?: string;
  browserPolicyEvents?: number;
  transmittedRequests?: number;
  valueAttestations?: readonly ValuePresenceAttestation[];
}

export interface BrowserBrokerRequest {
  url: string;
  method: string;
  resourceType: string;
  pageUrl?: string;
  isRedirect?: boolean;
}

export type BrowserBrokerDecision =
  | {
      allowed: true;
      normalizedUrl: string;
      reason: "allowed";
      policyEventCount: number;
      transmittedRequestCount: number;
    }
  | {
      allowed: false;
      normalizedUrl?: string;
      reason: string;
      policyEventCount: number;
      transmittedRequestCount: number;
    };
