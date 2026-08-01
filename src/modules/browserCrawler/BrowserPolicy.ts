import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { BrowserResourceType, EvidencePolicy, ModuleSettings, ScanLimits } from "../../core/planning/ScanPlan.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";

export type BrowserPolicyDecision =
  | { allowed: true; normalizedUrl: string; reason: "allowed" }
  | { allowed: false; normalizedUrl?: string; reason: BrowserPolicyBlockReason };

export type BrowserPolicyBlockReason =
  | "invalid-url"
  | "prohibited-protocol"
  | "third-party-blocked"
  | "resource-type-blocked"
  | "download-blocked"
  | "upload-blocked"
  | "popup-blocked"
  | "websocket-blocked"
  | "service-worker-blocked"
  | "browser-attempt-budget-exceeded"
  | "private-destination-blocked"
  | "internal-hostname-blocked"
  | "page-request-budget-exceeded";

export interface BrowserPolicy {
  maxDepth: number;
  maxPages: number;
  maxLinksPerPage: number;
  maxPolicyEvents: number;
  maxRequestsPerPage: number;
  navigationTimeoutMs: number;
  pageLifetimeMs: number;
  blockThirdParty: boolean;
  allowedResourceTypes: readonly BrowserResourceType[];
  captureScreenshot: boolean;
  allowPopups: boolean;
  allowDownloads: boolean;
  allowUploads: boolean;
  allowServiceWorkers: boolean;
  allowWebSockets: boolean;
  allowPrivateNetwork: boolean;
  allowedPrivateOrigins: readonly string[];
  allowedThirdPartyOrigins: readonly string[];
  evidence: EvidencePolicy;
}

export interface BrowserRequestPolicyInput {
  url: string;
  pageUrl: string;
  resourceType: string;
  requestsSeenForPage: number;
  isNavigationDownload?: boolean;
}

export type BrowserDnsResolver = (hostname: string) => Promise<readonly string[]>;

export function browserPolicyFromSettings(settings: Readonly<ModuleSettings>, limits: Readonly<ScanLimits>, evidence: EvidencePolicy): BrowserPolicy {
  return {
    maxDepth: limits.maxDepth,
    maxPages: settings.browserMaxPages ?? 3,
    maxLinksPerPage: settings.browserMaxLinksPerPage ?? 25,
    maxPolicyEvents: settings.browserMaxPolicyEvents ?? 200,
    maxRequestsPerPage: settings.browserMaxRequestsPerPage ?? 80,
    navigationTimeoutMs: limits.requestTimeoutMs,
    pageLifetimeMs: Math.min(limits.requestTimeoutMs * 2, 30000),
    blockThirdParty: settings.browserBlockThirdParty ?? true,
    allowedResourceTypes: settings.browserAllowedResourceTypes ?? ["document", "stylesheet", "script", "xhr", "fetch", "manifest"],
    captureScreenshot: evidence.level !== "minimal" && (settings.browserCaptureScreenshot ?? true),
    allowPopups: settings.browserAllowPopups ?? false,
    allowDownloads: settings.browserAllowDownloads ?? false,
    allowUploads: settings.browserAllowUploads ?? false,
    allowServiceWorkers: settings.browserAllowServiceWorkers ?? false,
    allowWebSockets: settings.browserAllowWebSockets ?? false,
    allowPrivateNetwork: settings.browserAllowPrivateNetwork ?? false,
    allowedPrivateOrigins: settings.browserAllowedPrivateOrigins ?? [],
    allowedThirdPartyOrigins: settings.browserAllowedThirdPartyOrigins ?? [],
    evidence
  };
}

export class BrowserPolicyEngine {
  private readonly target: URL;
  private readonly allowedResourceTypes: ReadonlySet<string>;

  public constructor(
    targetUrl: string,
    private readonly policy: BrowserPolicy,
    private readonly resolveHostname: BrowserDnsResolver = defaultResolveHostname
  ) {
    this.target = new URL(normalizeUrl(targetUrl));
    this.allowedResourceTypes = new Set(policy.allowedResourceTypes);
  }

  public async evaluateRequest(input: BrowserRequestPolicyInput): Promise<BrowserPolicyDecision> {
    let normalizedUrl: string;
    let parsed: URL;
    try {
      normalizedUrl = normalizeBrowserUrlPreservingQuery(input.url, input.pageUrl);
      parsed = new URL(normalizedUrl);
    } catch {
      return { allowed: false, reason: "invalid-url" };
    }

    if (!isPermittedBrowserProtocol(parsed.protocol)) {
      return { allowed: false, normalizedUrl, reason: "prohibited-protocol" };
    }

    const isWebSocket = parsed.protocol === "ws:" || parsed.protocol === "wss:";
    if (isWebSocket && !this.policy.allowWebSockets) {
      return { allowed: false, normalizedUrl, reason: "websocket-blocked" };
    }

    const destinationDecision = await this.evaluateDestination(parsed);
    if (!destinationDecision.allowed) {
      return { allowed: false, normalizedUrl, reason: destinationDecision.reason };
    }

    if (!isWebSocket && !this.allowedResourceTypes.has(input.resourceType)) {
      return { allowed: false, normalizedUrl, reason: "resource-type-blocked" };
    }

    if (!this.policy.allowDownloads && (input.isNavigationDownload || looksLikeDownloadUrl(parsed))) {
      return { allowed: false, normalizedUrl, reason: "download-blocked" };
    }

    if (this.policy.blockThirdParty && !sameBrowserOrigin(parsed, this.target) && !this.policy.allowedThirdPartyOrigins.includes(parsed.origin)) {
      return { allowed: false, normalizedUrl, reason: "third-party-blocked" };
    }

    if (input.requestsSeenForPage > this.policy.maxRequestsPerPage) {
      return { allowed: false, normalizedUrl, reason: "page-request-budget-exceeded" };
    }

    return { allowed: true, normalizedUrl, reason: "allowed" };
  }

  public async shouldQueueUrl(url: string, depth: number): Promise<{ allowed: boolean; normalizedUrl?: string; reason?: string }> {
    if (depth > this.policy.maxDepth) {
      return { allowed: false, reason: "max-depth-exceeded" };
    }

    const decision = await this.evaluateRequest({
      url,
      pageUrl: this.target.toString(),
      resourceType: "document",
      requestsSeenForPage: 0
    });

    return decision.allowed ? { allowed: true, normalizedUrl: decision.normalizedUrl } : { allowed: false, ...(decision.normalizedUrl ? { normalizedUrl: decision.normalizedUrl } : {}), reason: decision.reason };
  }

  private async evaluateDestination(url: URL): Promise<{ allowed: true } | { allowed: false; reason: "private-destination-blocked" | "internal-hostname-blocked" }> {
    const hostname = url.hostname.replace(/\.$/, "").toLowerCase();
    if (isInternalHostname(hostname)) {
      return this.privateOriginAllowed(url) ? { allowed: true } : { allowed: false, reason: "internal-hostname-blocked" };
    }

    const literal = normalizeIpLiteral(hostname);
    if (literal && isProhibitedAddress(literal)) {
      return this.privateOriginAllowed(url) ? { allowed: true } : { allowed: false, reason: "private-destination-blocked" };
    }

    if (!literal) {
      const addresses = await this.resolveHostname(hostname).catch(() => undefined);
      if (!addresses) {
        return { allowed: false, reason: "private-destination-blocked" };
      }
      if (addresses.some((address) => isProhibitedAddress(address))) {
        return this.privateOriginAllowed(url) ? { allowed: true } : { allowed: false, reason: "private-destination-blocked" };
      }
    }

    return { allowed: true };
  }

  private privateOriginAllowed(url: URL): boolean {
    return this.policy.allowPrivateNetwork && this.policy.allowedPrivateOrigins.includes(url.origin);
  }
}

export function canonicalBrowserUrl(url: string, baseUrl: string): string {
  return normalizeBrowserUrlPreservingQuery(url, baseUrl);
}

export function normalizeBrowserUrlPreservingQuery(input: string, base?: URL | string): string {
  const url = base ? new URL(input, base) : new URL(ensureProtocol(input));
  url.hash = "";
  url.hostname = url.hostname.toLowerCase();

  if ((url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80")) {
    url.port = "";
  }

  if (url.pathname === "") {
    url.pathname = "/";
  } else {
    url.pathname = url.pathname.replace(/\/{2,}/g, "/");
  }

  return url.toString();
}

function isPermittedBrowserProtocol(protocol: string): boolean {
  return protocol === "http:" || protocol === "https:" || protocol === "ws:" || protocol === "wss:";
}

function looksLikeDownloadUrl(url: URL): boolean {
  return /\.(?:zip|tar|gz|tgz|7z|rar|pdf|docx?|xlsx?|pptx?|exe|dmg|pkg|iso|apk|bin)$/i.test(url.pathname);
}

function sameBrowserOrigin(left: URL, right: URL): boolean {
  return browserOrigin(left) === browserOrigin(right);
}

function browserOrigin(url: URL): string {
  const protocol = url.protocol === "ws:" ? "http:" : url.protocol === "wss:" ? "https:" : url.protocol;
  return `${protocol}//${url.host}`;
}

function ensureProtocol(input: string): string {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) {
    return input;
  }

  return `https://${input}`;
}

async function defaultResolveHostname(hostname: string): Promise<readonly string[]> {
  const results = await lookup(hostname, { all: true, verbatim: false });
  return results.map((result) => result.address);
}

function isInternalHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal") || !hostname.includes(".");
}

function normalizeIpLiteral(hostname: string): string | undefined {
  const unbracketed = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  if (isIP(unbracketed)) {
    return unbracketed;
  }

  if (/^0x[0-9a-f]+$/i.test(unbracketed)) {
    const parsed = Number.parseInt(unbracketed.slice(2), 16);
    return Number.isFinite(parsed) ? intToIpv4(parsed) : undefined;
  }

  if (/^\d+$/.test(unbracketed)) {
    const parsed = Number.parseInt(unbracketed, 10);
    return Number.isFinite(parsed) ? intToIpv4(parsed) : undefined;
  }

  const parts = unbracketed.split(".");
  if (parts.length === 4 && parts.every((part) => /^0[0-7]+$/.test(part))) {
    return parts.map((part) => Number.parseInt(part, 8)).join(".");
  }

  return undefined;
}

function intToIpv4(value: number): string | undefined {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    return undefined;
  }
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".");
}

export function isProhibitedAddress(address: string): boolean {
  const normalized = normalizeIpLiteral(address) ?? address;
  if (normalized.includes(":")) {
    const value = normalized.toLowerCase();
    return value === "::1" || value.startsWith("fc") || value.startsWith("fd") || value.startsWith("fe80:") || value === "::" || value.startsWith("::ffff:127.") || value.startsWith("::ffff:10.") || value.startsWith("::ffff:192.168.");
  }

  const octets = normalized.split(".").map((part) => Number.parseInt(part, 10));
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return false;
  }

  const [first, second] = octets as [number, number, number, number];
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 100 && second >= 64 && second <= 127)
  );
}
