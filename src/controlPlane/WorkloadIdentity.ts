import { createHmac, timingSafeEqual } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { TLSSocket } from "node:tls";
import { createRemoteJWKSet, decodeJwt, jwtVerify, type JWTVerifyGetKey } from "jose";
import type { ControlPlaneConfig } from "./ControlPlaneConfig.js";
import type { WorkerRow } from "../dashboard/operations/RemoteWorkerService.js";
import { workerIdentityBindingSchema } from "../dashboard/contracts/OperationalScaleSchemas.js";

interface Discovery { issuer?: unknown; jwks_uri?: unknown }

export class WorkloadIdentityVerifier {
  private readonly keys = new Map<string, Promise<JWTVerifyGetKey>>();
  public constructor(private readonly policy: ControlPlaneConfig["workloadIdentity"]) {}
  public async verify(request: IncomingMessage, worker: WorkerRow): Promise<{ kind: "ed25519" | "mtls" | "oidc"; subject?: string }> {
    const direct = this.policy.directMtls?directMtlsIdentity(request, worker):undefined;
    if (direct) return direct;
    const proxied = this.proxyMtlsIdentity(request, worker);
    if (proxied) return proxied;
    const bearer = bearerToken(request);
    if (bearer) {
      try {
        if(bearer.length>16*1024)throw new WorkloadIdentityError("WORKLOAD_IDENTITY_TOKEN_REJECTED");const claims = decodeJwt(bearer); const issuer = typeof claims.iss === "string" ? claims.iss : "";
        if (!this.policy.trustedIssuers.includes(issuer)) throw new WorkloadIdentityError("WORKLOAD_IDENTITY_ISSUER_REJECTED");
        const key = await this.keyForIssuer(issuer);
        const result = await jwtVerify(bearer, key, { issuer, ...(this.policy.audience ? { audience: this.policy.audience } : {}), requiredClaims:["iss","sub","aud","iat","exp"],algorithms:["RS256","RS384","RS512","PS256","PS384","PS512","ES256","ES384","ES512","EdDSA"], clockTolerance: 30, maxTokenAge: "10m" });
        if (!result.payload.sub || result.payload.sub.length > 500) throw new WorkloadIdentityError("WORKLOAD_IDENTITY_SUBJECT_REJECTED");
        const boundWorker = result.payload["routecairn_worker_id"];
        const binding=worker.workload_identity?workerIdentityBindingSchema.parse(JSON.parse(worker.workload_identity)):undefined;
        if(binding){if(binding.kind!=="oidc"||binding.issuer!==issuer||binding.subject!==result.payload.sub)throw new WorkloadIdentityError("WORKLOAD_IDENTITY_WORKER_MISMATCH");}
        else if(boundWorker!==worker.id)throw new WorkloadIdentityError("WORKLOAD_IDENTITY_WORKER_MISMATCH");
        return { kind: "oidc", subject: result.payload.sub };
      } catch(error) { if(error instanceof WorkloadIdentityError)throw error;throw new WorkloadIdentityError("WORKLOAD_IDENTITY_TOKEN_REJECTED"); }
    }
    if (this.policy.required) throw new WorkloadIdentityError("WORKLOAD_IDENTITY_REQUIRED");
    return { kind: "ed25519" };
  }
  private proxyMtlsIdentity(request: IncomingMessage, worker: WorkerRow): { kind: "mtls"; subject: string } | undefined {
    if (!this.policy.mtlsProxySecret) return undefined;
    const fingerprint = singleHeader(request, "x-routecairn-client-cert-fingerprint"); const proof = singleHeader(request, "x-routecairn-mtls-proof"); const timestamp = singleHeader(request, "x-routecairn-timestamp");
    if (!fingerprint && !proof) return undefined;
    if (!fingerprint || !proof || !timestamp || !/^[0-9a-f]{64}$/i.test(fingerprint)) throw new WorkloadIdentityError("MTLS_PROXY_PROOF_REJECTED");
    if(!Number.isFinite(Date.parse(timestamp))||Math.abs(Date.now()-Date.parse(timestamp))>300_000)throw new WorkloadIdentityError("MTLS_PROXY_PROOF_REJECTED");
    const expected = createHmac("sha256", this.policy.mtlsProxySecret).update(`${timestamp}\n${worker.id}\n${fingerprint.toLowerCase()}`).digest();
    let supplied: Buffer; try { supplied = Buffer.from(proof, "base64url"); } catch { throw new WorkloadIdentityError("MTLS_PROXY_PROOF_REJECTED"); }
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) throw new WorkloadIdentityError("MTLS_PROXY_PROOF_REJECTED");
    verifyCertificateBinding(worker,fingerprint.toLowerCase());
    return { kind: "mtls", subject: fingerprint.toLowerCase() };
  }
  private async keyForIssuer(issuer: string): Promise<JWTVerifyGetKey> {
    let existing = this.keys.get(issuer); if (existing) return existing;
    existing = discoverKeys(issuer); this.keys.set(issuer, existing);
    try { return await existing; } catch (error) { this.keys.delete(issuer); throw error; }
  }
}

export class WorkloadIdentityError extends Error { public constructor(message: string) { super(message); this.name = "WorkloadIdentityError"; } }

async function discoverKeys(issuer: string): Promise<JWTVerifyGetKey> {
  const discoveryUrl = new URL(`${issuer.replace(/\/$/,"")}/.well-known/openid-configuration`);
  if (discoveryUrl.protocol !== "https:") throw new WorkloadIdentityError("WORKLOAD_IDENTITY_DISCOVERY_REJECTED");
  const response = await fetch(discoveryUrl, { redirect: "error", signal: AbortSignal.timeout(5_000) });
  if (!response.ok || Number(response.headers.get("content-length") ?? 0) > 64 * 1024) throw new WorkloadIdentityError("WORKLOAD_IDENTITY_DISCOVERY_FAILED");
  const discovery = JSON.parse(await boundedResponseText(response,64*1024)) as Discovery;
  if (discovery.issuer !== issuer || typeof discovery.jwks_uri !== "string") throw new WorkloadIdentityError("WORKLOAD_IDENTITY_DISCOVERY_REJECTED");
  const jwks = new URL(discovery.jwks_uri); if (jwks.protocol !== "https:") throw new WorkloadIdentityError("WORKLOAD_IDENTITY_JWKS_REJECTED");
  return createRemoteJWKSet(jwks, { timeoutDuration: 5_000, cooldownDuration: 30_000, cacheMaxAge: 300_000 });
}
function directMtlsIdentity(request: IncomingMessage, worker: WorkerRow): { kind: "mtls"; subject: string } | undefined {
  const socket = request.socket as TLSSocket; if (!socket.encrypted || !socket.authorized) return undefined;
  const certificate = socket.getPeerCertificate(); const fingerprint = certificate.fingerprint256?.replace(/:/g, "").toLowerCase();
  if (!fingerprint) throw new WorkloadIdentityError("MTLS_CERTIFICATE_REJECTED");
  verifyCertificateBinding(worker,fingerprint);
  return { kind: "mtls", subject: `${worker.id}:${fingerprint}` };
}
function bearerToken(request: IncomingMessage): string | undefined { const authorization=singleHeader(request,"authorization");return authorization?.startsWith("Bearer ")?authorization.slice(7):undefined; }
function singleHeader(request: IncomingMessage,name:string):string|undefined{const value=request.headers[name];if(Array.isArray(value))throw new WorkloadIdentityError("WORKLOAD_IDENTITY_HEADER_REJECTED");return value;}
function verifyCertificateBinding(worker:WorkerRow,fingerprint:string):void{try{const binding=workerIdentityBindingSchema.parse(JSON.parse(worker.workload_identity??"null"));if(binding.kind!=="mtls"||binding.fingerprint!==fingerprint)throw new Error();}catch{throw new WorkloadIdentityError("WORKLOAD_IDENTITY_WORKER_MISMATCH");}}
async function boundedResponseText(response:Response,limit:number):Promise<string>{if(!response.body)return"";const reader=response.body.getReader();const chunks:Uint8Array[]=[];let size=0;try{while(true){const item=await reader.read();if(item.done)break;size+=item.value.byteLength;if(size>limit)throw new WorkloadIdentityError("WORKLOAD_IDENTITY_DISCOVERY_TOO_LARGE");chunks.push(item.value);}}finally{reader.releaseLock();}return Buffer.concat(chunks.map((item)=>Buffer.from(item))).toString("utf8");}
