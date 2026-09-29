import { createHash } from "node:crypto";
import { z } from "zod";
import { TargetAuthorizationGuard } from "../authorization/TargetAuthorization.js";
import { redactBodyPreview, redactHeaders } from "../evidence/EvidenceBuilder.js";
import { redactSensitiveUrl } from "../evidence/ValuePresenceAttestation.js";
import { RequestSafetyBroker } from "../http/RequestSafetyBroker.js";
import type { RequestAuditEntry } from "../http/HttpTypes.js";
import { ScopeMatcher } from "../scope/ScopeMatcher.js";
import type { ThirdPartyModuleBrokerBinding, ThirdPartyModuleManifest } from "../../dashboard/contracts/OperationalScaleSchemas.js";

const headerValue = z.string().max(4096).refine((value) => !/[\r\n\0]/.test(value), "Header values cannot contain control characters.");
export const moduleRequestProposalSchema = z.object({
  url: z.string().min(1).max(4096),
  method: z.enum(["GET", "HEAD", "OPTIONS", "POST"]).default("GET"),
  headers: z.record(headerValue).default({}).refine((value) => Object.keys(value).length <= 32, "At most 32 request headers are allowed."),
  body: z.string().max(256 * 1024).optional(),
  nonMutating: z.boolean().default(false),
  purpose: z.string().min(1).max(240)
}).strict();

export interface ModuleBrokerResponse {
  schemaVersion: 1;
  outcome: "TRANSMITTED" | "POLICY_BLOCKED" | "BUDGET_BLOCKED";
  safeUrl: string;
  method: "GET" | "HEAD" | "OPTIONS" | "POST";
  statusCode?: number;
  statusClass?: string;
  headers: Record<string, string | string[]>;
  bodyPreview?: string;
  bodySha256?: string;
  bytesRead?: number;
  truncated?: boolean;
  responseTimeMs: number;
  redirectCount: number;
  errorCode?: string;
}

export interface ModuleCapabilitySummary {
  enabled: boolean;
  riskClass?: "LOW" | "MODERATE";
  proposedRequests: number;
  transmittedRequests: number;
  policyBlockedRequests: number;
  budgetBlockedRequests: number;
  maxRequests: number;
  auditDigest: string;
}

export class ModuleCapabilityBroker {
  private readonly broker: RequestSafetyBroker;
  private readonly audits: RequestAuditEntry[] = [];
  private proposed = 0;
  private policyBlocked = 0;
  private budgetBlocked = 0;
  private readonly decisions: Array<{ method: string; outcome: string; statusClass?: string; errorCode?: string }> = [];

  public constructor(private readonly declaration: NonNullable<ThirdPartyModuleManifest["capabilities"]["requestBroker"]>, private readonly binding: ThirdPartyModuleBrokerBinding, packageDigest: string, private readonly now: () => number = Date.now) {
    validateApproval(binding, packageDigest, now());
    const target = new URL(binding.target);
    const authorization = binding.targetAuthorization ? new TargetAuthorizationGuard(binding.targetAuthorization) : undefined;
    if (authorization && authorization.plan.targetOrigin !== target.origin) throw new Error("SDK_BROKER_AUTHORIZATION_ORIGIN_MISMATCH");
    const scopeMatcher = new ScopeMatcher(binding.target, binding.scope, authorization);
    for (const method of declaration.methods) if (!binding.scope.allowedMethods.includes(method)) throw new Error(`SDK_BROKER_METHOD_OUTSIDE_SCOPE:${method}`);
    this.broker = new RequestSafetyBroker({
      userAgent: binding.scope.userAgent,
      timeoutMs: declaration.timeoutMs,
      rateLimitPerSecond: binding.scope.rateLimitPerSecond,
      concurrency: Math.min(binding.scope.concurrency, declaration.concurrency),
      bodyPreviewBytes: declaration.bodyPreviewBytes,
      maxResponseBytes: declaration.maxResponseBytes,
      maxRequests: declaration.maxRequests,
      retry: { maxAttempts: 0, baseDelayMs: 1, maxDelayMs: 1, retryStatusCodes: [] }
    }, scopeMatcher, (entry) => this.audits.push(entry));
  }

  public async execute(input: unknown): Promise<ModuleBrokerResponse> {
    this.proposed += 1;
    if (this.proposed > this.declaration.maxRequests) return this.blocked("BUDGET_BLOCKED", "SDK_BROKER_REQUEST_BUDGET_EXHAUSTED", "redacted://module-request", "GET");
    if (this.now() < Date.parse(this.binding.approval.authorizedAt) || this.now() >= Date.parse(this.binding.approval.expiresAt)) return this.blocked("POLICY_BLOCKED", "SDK_BROKER_APPROVAL_INACTIVE", "redacted://module-request", "GET");
    let proposal: z.infer<typeof moduleRequestProposalSchema>;
    try { proposal = moduleRequestProposalSchema.parse(input); }
    catch { return this.blocked("POLICY_BLOCKED", "SDK_BROKER_PROPOSAL_INVALID", "redacted://module-request", "GET"); }
    let url: URL;
    try { url = new URL(proposal.url, this.binding.target); }
    catch { return this.blocked("POLICY_BLOCKED", "SDK_BROKER_URL_INVALID", "redacted://module-request", proposal.method); }
    const safeUrl = redactSensitiveUrl(url.toString());
    const denied = this.validateProposal(proposal, url);
    if (denied) return this.blocked("POLICY_BLOCKED", denied, safeUrl, proposal.method);
    let response: Awaited<ReturnType<RequestSafetyBroker["send"]>>;
    try { response = await this.broker.send({ url: url.toString(), method: proposal.method, headers: proposal.headers, ...(proposal.body !== undefined ? { body: proposal.body } : {}), retainBodyPreview: this.declaration.bodyPreviewBytes > 0, disableRetries: true, disableRedirects: true, skipCache: true }); }
    catch { this.decisions.push({ method: proposal.method, outcome: "TRANSMITTED", errorCode: "SDK_BROKER_TRANSPORT_FAILURE" }); return Object.freeze({ schemaVersion: 1, outcome: "TRANSMITTED", safeUrl, method: proposal.method, headers: {}, responseTimeMs: 0, redirectCount: 0, errorCode: "SDK_BROKER_TRANSPORT_FAILURE" }); }
    const outcome = response.error?.name === "RequestBudgetExceeded" ? "BUDGET_BLOCKED" : response.error && isPolicyError(response.error.name) ? "POLICY_BLOCKED" : "TRANSMITTED";
    if (outcome === "BUDGET_BLOCKED") this.budgetBlocked += 1;
    else if (outcome === "POLICY_BLOCKED") this.policyBlocked += 1;
    this.decisions.push({ method: proposal.method, outcome, ...(response.statusCode !== undefined ? { statusClass: `${Math.floor(response.statusCode / 100)}xx` } : {}), ...(response.error ? { errorCode: safeCode(response.error.name) } : {}) });
    const headers = safeResponseHeaders(redactHeaders(response.headers));
    return Object.freeze({
      schemaVersion: 1 as const,
      outcome,
      safeUrl: redactSensitiveUrl(response.finalUrl),
      method: proposal.method,
      ...(response.statusCode !== undefined ? { statusCode: response.statusCode, statusClass: `${Math.floor(response.statusCode / 100)}xx` } : {}),
      headers,
      ...(response.bodyPreview && this.declaration.bodyPreviewBytes > 0 ? { bodyPreview: redactModuleBodyPreview(response.bodyPreview, this.declaration.bodyPreviewBytes) } : {}),
      ...(response.bodyHash ? { bodySha256: response.bodyHash } : {}),
      ...(response.bytesRead !== undefined ? { bytesRead: response.bytesRead } : {}),
      ...(response.streamTruncated !== undefined ? { truncated: response.streamTruncated } : {}),
      responseTimeMs: Math.max(0, Math.round(response.responseTimeMs)),
      redirectCount: response.redirectChain.length,
      ...(response.error ? { errorCode: safeCode(response.error.name) } : {})
    });
  }

  public summary(): ModuleCapabilitySummary {
    const snapshot = this.broker.budgetSnapshot();
    const canonicalAudit = this.audits.map((entry) => ({ method: entry.method, outcome: entry.outcome, statusClass: entry.statusCode === undefined ? undefined : `${Math.floor(entry.statusCode / 100)}xx`, scopeReason: entry.scopeReason, error: entry.error ? safeCode(entry.error) : undefined }));
    return Object.freeze({ enabled: true, riskClass: this.declaration.riskClass, proposedRequests: this.proposed, transmittedRequests: snapshot.transmittedRequests, policyBlockedRequests: this.policyBlocked, budgetBlockedRequests: this.budgetBlocked, maxRequests: this.declaration.maxRequests, auditDigest: createHash("sha256").update(JSON.stringify({ decisions: this.decisions, brokerAudit: canonicalAudit })).digest("hex") });
  }

  public async close(): Promise<void> { await this.broker.close(); }

  private validateProposal(proposal: z.infer<typeof moduleRequestProposalSchema>, url: URL): string | undefined {
    if (!this.declaration.methods.includes(proposal.method)) return "SDK_BROKER_METHOD_NOT_DECLARED";
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) return "SDK_BROKER_URL_FORBIDDEN";
    if (!matchesPrefix(url.pathname, this.declaration.pathPrefixes)) return "SDK_BROKER_PATH_NOT_DECLARED";
    if (proposal.method === "POST" && (!this.declaration.allowNonMutatingPost || this.declaration.riskClass !== "MODERATE" || !proposal.nonMutating)) return "SDK_BROKER_POST_ATTESTATION_REQUIRED";
    if (proposal.method === "POST") { const approved = this.binding.approval.nonMutatingPosts.find((item) => item.path === url.pathname); if (url.origin !== this.binding.approval.targetOrigin || url.search || !approved || approved.bodySha256 !== createHash("sha256").update(proposal.body ?? "").digest("hex") || approved.headersSha256 !== headersDigest(proposal.headers)) return "SDK_BROKER_POST_APPROVAL_MISMATCH"; }
    if (proposal.method !== "POST" && proposal.nonMutating) return "SDK_BROKER_ATTESTATION_INVALID";
    if (proposal.method !== "POST" && proposal.body !== undefined) return "SDK_BROKER_BODY_METHOD_FORBIDDEN";
    if (Buffer.byteLength(proposal.body ?? "") > this.declaration.maxRequestBytes) return "SDK_BROKER_REQUEST_BODY_LIMIT_EXCEEDED";
    const normalizedNames = new Set<string>(); for (const [name, value] of Object.entries(proposal.headers)) {
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /[\r\n\0]/.test(value)) return "SDK_BROKER_HEADER_INVALID";
      if (normalizedNames.has(name.toLowerCase())) return "SDK_BROKER_HEADER_DUPLICATED"; normalizedNames.add(name.toLowerCase());
      if (forbiddenRequestHeader(name)) return "SDK_BROKER_HEADER_FORBIDDEN";
    }
    return undefined;
  }

  private blocked(outcome: "POLICY_BLOCKED" | "BUDGET_BLOCKED", code: string, safeUrl: string, method: "GET" | "HEAD" | "OPTIONS" | "POST"): ModuleBrokerResponse {
    if (outcome === "BUDGET_BLOCKED") this.budgetBlocked += 1; else this.policyBlocked += 1;
    this.decisions.push({ method, outcome, errorCode: code });
    return Object.freeze({ schemaVersion: 1, outcome, safeUrl, method, headers: {}, responseTimeMs: 0, redirectCount: 0, errorCode: code });
  }
}

function validateApproval(binding: ThirdPartyModuleBrokerBinding, packageDigest: string, now: number): void {
  const target = new URL(binding.target);
  if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password || target.hash) throw new Error("SDK_BROKER_TARGET_INVALID");
  if (binding.approval.packageDigest !== packageDigest) throw new Error("SDK_BROKER_APPROVAL_DIGEST_MISMATCH");
  if (binding.approval.targetOrigin !== target.origin) throw new Error("SDK_BROKER_APPROVAL_ORIGIN_MISMATCH");
  if (now < Date.parse(binding.approval.authorizedAt) || now >= Date.parse(binding.approval.expiresAt)) throw new Error("SDK_BROKER_APPROVAL_INACTIVE");
}
function matchesPrefix(pathname: string, prefixes: readonly string[]): boolean { return prefixes.some((value) => { const prefix = value.replace(/\/$/, ""); return !prefix || pathname === prefix || pathname.startsWith(`${prefix}/`); }); }
function forbiddenRequestHeader(name: string): boolean { return /^(?:host|connection|proxy-connection|upgrade|expect|trailer|transfer-encoding|content-length|authorization|proxy-authorization|cookie|set-cookie|apikey|api-key|x-api-key|x-auth-token|x-csrf-token|forwarded|x-forwarded-.+|x-real-ip|x-http-method|x-http-method-override|x-method-override|x-original-url|x-rewrite-url|sec-websocket-.+|te)$/i.test(name); }
function headersDigest(headers: Readonly<Record<string, string>>): string { const canonical = Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value] as const).sort(([left], [right]) => left.localeCompare(right)); return createHash("sha256").update(JSON.stringify(canonical)).digest("hex"); }
function safeResponseHeaders(headers: Record<string, string | string[]>): Record<string, string | string[]> { const allow = /^(?:content-type|content-length|content-encoding|cache-control|etag|last-modified|location|vary|allow|accept-ranges|content-range|server|x-powered-by|x-content-type-options|content-security-policy|cross-origin-.+|access-control-.+|strict-transport-security)$/i; return Object.fromEntries(Object.entries(headers).filter(([name]) => allow.test(name)).map(([name, value]) => [name.toLowerCase(), name.toLowerCase() === "location" ? (Array.isArray(value) ? value.map(redactSensitiveUrl) : redactSensitiveUrl(value)) : value])); }
function redactModuleBodyPreview(value: string, maxBytes: number): string { const bounded = value.slice(0, maxBytes); try { const parsed = JSON.parse(bounded); const walk = (item: unknown, depth: number): unknown => { if (depth > 20) return "<redacted-depth>"; if (Array.isArray(item)) return item.map((child) => walk(child, depth + 1)); if (item && typeof item === "object") return Object.fromEntries(Object.entries(item as Record<string, unknown>).map(([key, child]) => [key, secretField(key) ? "<redacted>" : walk(child, depth + 1)])); return item; }; return JSON.stringify(walk(parsed, 0)).slice(0, maxBytes); } catch { return redactBodyPreview(bounded, maxBytes); } }
function secretField(value: string): boolean { return /(?:password|passwd|pwd|secret|token|cookie|authorization|private[_-]?key|api[_-]?key|credential|session|jwt|signature|signed|ssn|socialSecurityNumber|taxId|privateEmail|privatePhone|privateAddress|passwordHash)/i.test(value); }
function isPolicyError(name: string): boolean { return /(?:OutOfScope|TargetAuthorization|ControlledMutation|Policy|Blocked|Forbidden)/i.test(name); }
function safeCode(value: string): string { return value.toUpperCase().replace(/[^A-Z0-9_]+/g, "_").slice(0, 100) || "SDK_BROKER_FAILURE"; }
