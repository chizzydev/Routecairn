import { Resolver } from "node:dns/promises";
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { z } from "zod";
import { OastClient } from "./OastClient.js";
import { exchangeOastDns } from "./OastDnsTransport.js";
import { runBoundedHttp } from "../modules/protocolSecurity/ProtocolTransports.js";
import type { OastLeaseIdentity } from "./OastTypes.js";

const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/), hex = z.string().regex(/^[a-f0-9]{64}$/);
const hostname = z.string().max(253).regex(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/);
const domain = hostname.refine((value) => value.length <= 187);
export const oastDeploymentVerificationSchema = z.object({
  schemaVersion: z.literal(1), baseDomain: domain, apiBaseUrl: z.string().url(), apiTokenEnv: z.string().regex(/^[A-Z][A-Z0-9_]{2,80}$/), tenantId: id, workerId: id, jobId: id,
  nameservers: z.array(hostname).min(1).max(4), serverAddresses: z.array(z.string().ip().refine(isPublicOastAddress, "Public unicast server addresses are required.")).min(1).max(4),
  protocols: z.array(z.enum(["DNS", "HTTP", "HTTPS"])).min(2).max(3).refine((value) => value.includes("DNS") && value.includes("HTTPS") && new Set(value).size === value.length),
  authorization: z.object({ ownerApproved: z.literal(true), baseDomain: domain, expiresAt: z.string().datetime(), referenceSha256: hex }).strict(),
  deployment: z.object({ releaseArtifactSha256: hex, serviceConfigSha256: hex }).strict()
}).strict().superRefine((value, ctx) => {
  const api = new URL(value.apiBaseUrl); if (api.protocol !== "https:" || api.username || api.password || api.pathname !== "/" || api.search || api.hash || !(api.hostname === value.baseDomain || api.hostname.endsWith(`.${value.baseDomain}`))) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Management requires an HTTPS origin within the authorized zone." });
  if (value.authorization.baseDomain !== value.baseDomain || Date.parse(value.authorization.expiresAt) <= Date.now()) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "A current owner authorization for this zone is required." });
  if (new Set(value.nameservers).size !== value.nameservers.length || new Set(value.serverAddresses).size !== value.serverAddresses.length || value.nameservers.some((name) => !name.endsWith(`.${value.baseDomain}`))) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Supply unique nameservers and addresses bound to this zone." });
});
export type OastDeploymentVerificationPlan = z.infer<typeof oastDeploymentVerificationSchema>;

/** Owner-operated public verification. Never claims an independent signature or
 * a release attestation: supplied artifact digests bind the operator's inputs. */
export async function verifyOastDeployment(input: unknown) {
  const plan = oastDeploymentVerificationSchema.parse(input), checks: Array<{ id: string; passed: boolean; responseSha256?: string }> = [];
  const resolver = new Resolver({ timeout: 3000, tries: 1 }); let lease: OastLeaseIdentity | undefined; let cleanup = "NOT_REQUIRED"; let failure: string | undefined;
  const client = new OastClient({ mode: "HOSTED", apiBaseUrl: plan.apiBaseUrl, apiTokenEnv: plan.apiTokenEnv, tenantId: plan.tenantId, workerId: plan.workerId, jobId: plan.jobId, leaseSeconds: 60, pollIntervalMs: 500, maxPolls: 6, protocols: plan.protocols }, 5000);
  const check = (id: string, passed: boolean, responseSha256?: string) => { checks.push({ id, passed, ...(responseSha256 ? { responseSha256 } : {}) }); if (!passed) throw new Error("OAST_DEPLOYMENT_CHECK_FAILED"); };
  try {
    const resolvedNs = (await resolver.resolveNs(plan.baseDomain)).map((value) => value.toLowerCase().replace(/\.$/, "")).sort();
    check("recursive-delegation-ns", JSON.stringify(resolvedNs) === JSON.stringify([...plan.nameservers].sort()));
    const nsAddresses: string[] = []; for (const name of plan.nameservers) { const v4 = await resolver.resolve4(name).catch(() => []), v6 = await resolver.resolve6(name).catch(() => []); nsAddresses.push(...v4, ...v6); }
    check("nameserver-address-bindings", plan.serverAddresses.every((value) => nsAddresses.includes(value)) && nsAddresses.length > 0 && nsAddresses.every(isPublicOastAddress));
    const ready = await runBoundedHttp(new URL("/readyz", plan.apiBaseUrl).toString(), "GET", {}, undefined, { allowedPrivateOrigins: [], timeoutMs: 5000, maxBytes: 4096 });
    check("public-https-ready", ready.statusCode === 200 && JSON.parse(ready.body.toString()).ready === true, sha256(ready.body));
    check("service-config-digest", JSON.parse(ready.body.toString()).serviceConfigSha256 === plan.deployment.serviceConfigSha256);
    for (const address of plan.serverAddresses) for (const tcp of [false, true]) { const ns = await exchangeOastDns(plan.baseDomain, address, 53, tcp, 2); check(`authoritative-${tcp ? "tcp" : "udp"}-${sha256(address).slice(0, 12)}`, ns.authoritative && !ns.recursionAvailable && ns.rcode === 0 && ((!tcp && ns.truncated) || (!ns.truncated && JSON.stringify(ns.nameservers.sort()) === JSON.stringify([...plan.nameservers].sort())))); const soa = await exchangeOastDns(plan.baseDomain, address, 53, tcp, 6); check(`soa-${tcp ? "tcp" : "udp"}-${sha256(address).slice(0, 12)}`, soa.authoritative && !soa.recursionAvailable && soa.rcode === 0 && ((!tcp && soa.truncated) || (!soa.truncated && soa.answerTypes.includes(6)))); }
    lease = await client.lease("deployment", "public-callbacks"); check("lease-zone-binding", lease.dnsName.endsWith(`.${plan.baseDomain}`));
    for (const protocol of plan.protocols) {
      if (protocol === "DNS") { for (const tcp of [false, true]) { const response = await exchangeOastDns(lease.dnsName, plan.serverAddresses[0]!, 53, tcp); check(`dns-callback-${tcp ? "tcp" : "udp"}`, response.authoritative && !response.recursionAvailable && response.rcode === 0 && ((!tcp && response.truncated) || (!response.truncated && response.answerTypes.includes(1)))); } }
      else { const callback = protocol === "HTTPS" ? lease.httpsUrl : lease.httpUrl; if (!callback) throw new Error("OAST_CALLBACK_UNAVAILABLE"); const url = new URL(callback); check(`${protocol.toLowerCase()}-callback-zone`, url.hostname === plan.baseDomain || url.hostname.endsWith(`.${plan.baseDomain}`)); const response = await runBoundedHttp(callback, "GET", {}, undefined, { allowedPrivateOrigins: [], timeoutMs: 5000, maxBytes: 4096 }); check(`${protocol.toLowerCase()}-callback`, response.statusCode === 202); const replay = await runBoundedHttp(callback, "GET", {}, undefined, { allowedPrivateOrigins: [], timeoutMs: 5000, maxBytes: 4096 }); check(`${protocol.toLowerCase()}-replay`, replay.statusCode === 409); }
      const event = await client.waitForEvent(lease, protocol); check(`${protocol.toLowerCase()}-signed-correlation`, !!event && event.bindingFingerprint === lease.bindingFingerprint, event ? sha256(JSON.stringify(event)) : undefined);
    }
    // This execution's unique identity must resolve through the ordinary
    // recursive path, proving more than a direct-port smoke test.
    check("recursive-callback-a", (await resolver.resolve4(lease.dnsName)).length > 0);
  } catch { failure = checks.at(-1)?.passed === false ? checks.at(-1)!.id : "TRANSPORT_OR_DEPLOYMENT_FAILURE"; }
  finally { resolver.cancel(); if (lease) { try { cleanup = await client.revoke(lease) ? "CONFIRMED" : "FAILED"; } catch { cleanup = "FAILED"; } } }
  return { schemaVersion: 1, generatedAt: new Date().toISOString(), status: !failure && cleanup === "CONFIRMED" ? "COMPLETED" : "FAILED", provenance: "OWNER_OPERATED_PUBLIC_DEPLOYMENT", externalTargetsTested: checks.some((value) => value.id === "public-https-ready" && value.passed), independentlyOperated: false, baseDomain: plan.baseDomain, inputSha256: sha256(JSON.stringify(plan)), operatorSuppliedDeployment: plan.deployment, deploymentArtifactAttested: false, authorizationReferenceSha256: plan.authorization.referenceSha256, checks, cleanup, ...(failure ? { failure } : {}) };
}
function sha256(value: string | Buffer) { return createHash("sha256").update(value).digest("hex"); }
export function isPublicOastAddress(value: string): boolean {
  if (isIP(value) === 4) { const [a, b, c] = value.split(".").map(Number); return !(a === 0 || a === 10 || a === 127 || a! >= 224 || (a === 100 && b! >= 64 && b! <= 127) || (a === 169 && b === 254) || (a === 172 && b! >= 16 && b! <= 31) || (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99))) || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113)); }
  // Global-unicast-only: reject mapped IPv4, link-local, private, multicast and
  // documentation IPv6 rather than silently treating them as public evidence.
  if (isIP(value) === 6) return /^[23][a-f0-9]{0,3}:/i.test(value) && !/^2001:(?:0db8|db8|0|0000|2|0002|10|0010|20|0020):/i.test(value);
  return false;
}
