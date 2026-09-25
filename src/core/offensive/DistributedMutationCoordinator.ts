import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { readFileSync, realpathSync, statSync } from "node:fs";
import { HttpClient } from "../http/HttpClient.js";

export interface DistributedMutationCoordinatorConfig {
  endpoint: string;
  namespace: string;
  sharedSecret: string;
  clientId?: string;
  timeoutMs?: number;
}

export interface DistributedMutationLease {
  leaseId: string;
  leaseToken: string;
  expiresAt: string;
  caseId: string;
  recovery: boolean;
}

export interface DistributedMutationReleaseState {
  state: "CLEAN" | "UNRESOLVED" | "UNKNOWN";
  stage?: string;
  obligations?: Array<{ caseId: string; stage: string }>;
}

export class DistributedMutationCoordinatorClient {
  private readonly endpoint: URL;
  private readonly clientId: string;
  private readonly timeoutMs: number;

  public constructor(private readonly config: DistributedMutationCoordinatorConfig) {
    this.endpoint = validateEndpoint(config.endpoint);
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,199}$/.test(config.namespace)) throw new Error("MUTATION_COORDINATOR_NAMESPACE_INVALID");
    if (Buffer.byteLength(config.sharedSecret) < 32) throw new Error("MUTATION_COORDINATOR_SECRET_INVALID");
    this.clientId = config.clientId ?? randomUUID();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,199}$/.test(this.clientId)) throw new Error("MUTATION_COORDINATOR_CLIENT_ID_INVALID");
    this.timeoutMs = Math.min(Math.max(config.timeoutMs ?? 10_000, 1_000), 60_000);
  }

  public acquire(caseId: string, holderId: string, recovery: boolean): Promise<DistributedMutationLease> {
    return this.call<DistributedMutationLease>("acquire", { namespace: this.config.namespace, caseId, holderId, recovery });
  }

  public renew(lease: DistributedMutationLease, holderId: string): Promise<{ expiresAt: string }> {
    return this.call("renew", { namespace: this.config.namespace, leaseId: lease.leaseId, leaseToken: lease.leaseToken, holderId });
  }

  public async release(lease: DistributedMutationLease, holderId: string, cleanup: DistributedMutationReleaseState): Promise<void> {
    await this.call("release", { namespace: this.config.namespace, leaseId: lease.leaseId, leaseToken: lease.leaseToken, holderId, cleanup });
  }

  private async call<T>(operation: "acquire" | "renew" | "release", body: Record<string, unknown>): Promise<T> {
    const path = `/api/mutation-coordination/${operation}`;
    const raw = canonical(body);
    const timestamp = new Date().toISOString();
    const nonce = randomBytes(24).toString("base64url");
    const bodyHash = createHash("sha256").update(raw).digest("hex");
    const signature = createHmac("sha256", this.config.sharedSecret).update(["routecairn-mutation-coordinator-v1", "POST", path, timestamp, nonce, bodyHash].join("\n")).digest("base64url");
    const http = new HttpClient({ userAgent: "RouteCairn-Mutation-Coordinator/1", timeoutMs: this.timeoutMs, bodyPreviewBytes: 64 * 1024, maxResponseBytes: 64 * 1024, allowedPrivateOrigins: [this.endpoint.origin] });
    try {
      const response = await http.send({ url: new URL(path, this.endpoint).toString(), method: "POST", headers: { "content-type": "application/json", accept: "application/json", "x-routecairn-coordinator-client": this.clientId, "x-routecairn-timestamp": timestamp, "x-routecairn-nonce": nonce, "x-routecairn-signature": signature }, body: raw, retainBodyPreview: true, disableRetries: true, disableRedirects: true, skipCache: true });
      if (response.error) throw new Error("MUTATION_COORDINATOR_UNAVAILABLE");
      let parsed: unknown;
      try { parsed = JSON.parse(response.bodyPreview ?? "{}"); } catch { throw new Error("MUTATION_COORDINATOR_INVALID_RESPONSE"); }
      if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) {
        const code = parsed && typeof parsed === "object" && "code" in parsed && typeof parsed.code === "string" ? parsed.code : "MUTATION_COORDINATOR_REJECTED";
        throw new Error(code);
      }
      return parsed as T;
    } finally { await http.close(); }
  }
}

export function distributedMutationCoordinatorFromEnvironment(): DistributedMutationCoordinatorClient | undefined {
  const endpoint = process.env.ROUTECAIRN_MUTATION_COORDINATOR_URL?.trim();
  if (!endpoint) return undefined;
  const namespace = process.env.ROUTECAIRN_MUTATION_COORDINATOR_NAMESPACE?.trim();
  const sharedSecret = environmentSecret("ROUTECAIRN_MUTATION_COORDINATOR_SECRET");
  if (!namespace) throw new Error("MUTATION_COORDINATOR_NAMESPACE_REQUIRED");
  if (!sharedSecret) throw new Error("MUTATION_COORDINATOR_SECRET_REQUIRED");
  return new DistributedMutationCoordinatorClient({ endpoint, namespace, sharedSecret, ...(process.env.ROUTECAIRN_MUTATION_COORDINATOR_CLIENT_ID ? { clientId: process.env.ROUTECAIRN_MUTATION_COORDINATOR_CLIENT_ID } : {}) });
}

function validateEndpoint(value: string): URL {
  let endpoint: URL;
  try { endpoint = new URL(value); } catch { throw new Error("MUTATION_COORDINATOR_URL_INVALID"); }
  const loopback = endpoint.hostname === "localhost" || endpoint.hostname === "127.0.0.1" || endpoint.hostname === "::1" || endpoint.hostname === "[::1]";
  if (endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && loopback)) throw new Error("MUTATION_COORDINATOR_HTTPS_REQUIRED");
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash || !["", "/"].includes(endpoint.pathname)) throw new Error("MUTATION_COORDINATOR_URL_INVALID");
  return new URL(endpoint.origin);
}

function environmentSecret(name: string): string | undefined {
  const inline = process.env[name]; const file = process.env[`${name}_FILE`]?.trim();
  if (inline && file) throw new Error("MUTATION_COORDINATOR_SECRET_SOURCE_CONFLICT");
  if (!file) return inline;
  const canonicalPath = realpathSync(file); const details = statSync(canonicalPath);
  if (!details.isFile() || details.size > 65_536) throw new Error("MUTATION_COORDINATOR_SECRET_FILE_INVALID");
  return readFileSync(canonicalPath, "utf8").replace(/[\r\n]+$/, "") || undefined;
}

function canonical(value: unknown): string { return JSON.stringify(sort(value)); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => [key, sort(item)])); return value; }
