import { request } from "undici";
import { createHash } from "node:crypto";
import type { HttpClientOptions, HttpRequest, HttpResponse, RedirectHop } from "./HttpTypes.js";
import { connectorOptionsForUrl, resolvePinnedDestination, type DestinationPolicyOptions, type PinnedDestination } from "./PinnedHttpTransport.js";
import { PinnedOriginPool } from "./PinnedOriginPool.js";

const defaultHeaders = {
  accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
};

export class HttpClient {
  private readonly pool: PinnedOriginPool;
  private readonly ownsPool: boolean;
  private readonly policy: DestinationPolicyOptions;
  private readonly dnsCache = new Map<string, { expiresAt: number; value: Promise<PinnedDestination> }>();

  public constructor(private readonly options: HttpClientOptions) {
    this.ownsPool = options.connectionPool === undefined;
    this.pool = options.connectionPool ?? new PinnedOriginPool(options.transport);
    this.policy = { allowedPrivateOrigins: options.allowedPrivateOrigins ?? [], dnsTimeoutMs: options.dnsTimeoutMs ?? Math.min(options.timeoutMs, 3000), maxDnsAnswers: options.maxDnsAnswers ?? 16, ...(options.dnsResolver ? { dnsResolver: options.dnsResolver } : {}) };
  }

  public async close(): Promise<void> {
    if (this.ownsPool) await this.pool.close();
  }

  public async send(requestInput: HttpRequest, currentUrl = requestInput.url, redirectChain: RedirectHop[] = []): Promise<HttpResponse> {
    const startedAt = performance.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs);
    const abortFromParent = () => controller.abort();
    let release: (() => Promise<void>) | undefined;
    if (this.options.abortSignal?.aborted) {
      controller.abort();
    } else {
      this.options.abortSignal?.addEventListener("abort", abortFromParent, { once: true });
    }

    try {
      const pin = await this.resolveDestination(new URL(currentUrl));
      const lease = this.pool.acquire(pin); release = lease.release;
      const response = await request(currentUrl, {
        method: requestInput.method,
        headers: {
          ...defaultHeaders,
          "user-agent": this.options.userAgent,
          ...requestInput.headers
        },
        ...(requestInput.body !== undefined ? { body: requestInput.body } : {}),
        dispatcher: lease.dispatcher,
        signal: controller.signal,
        bodyTimeout: this.options.timeoutMs,
        headersTimeout: this.options.timeoutMs
      });

      const headers = normalizeHeaders(response.headers);
      const redirectLocation = headerValue(headers, "location");

      const declaredLength = numericHeader(headers, "content-length");
      if (requestInput.maxStreamContentLength !== undefined && declaredLength !== undefined && declaredLength > requestInput.maxStreamContentLength) {
        controller.abort();
        return {
          requestedUrl: requestInput.url,
          finalUrl: currentUrl,
          method: requestInput.method,
          statusCode: response.statusCode,
          headers,
          responseTimeMs: Math.round(performance.now() - startedAt),
          redirectChain,
          contentLength: declaredLength,
          error: {
            name: "DeclaredContentLengthExceeded",
            message: `Declared Content-Length ${declaredLength} exceeds configured stream cap ${requestInput.maxStreamContentLength}.`
          }
        };
      }

      const streamLimit = requestInput.streamLimitBytes ?? this.options.maxResponseBytes;
      const streamed = requestInput.method !== "HEAD" ? await readBoundedStream(response.body, streamLimit, controller, requestInput.retainBodyPreview !== false ? this.options.bodyPreviewBytes : 0) : undefined;
      const body = streamed?.body ?? Buffer.alloc(0);
      const bodyPreview = streamed?.bodyPreview ?? "";
      const responseTimeMs = Math.round(performance.now() - startedAt);
      const contentType = headerValue(headers, "content-type");
      const contentLength = declaredLength ?? streamed?.bytesRead ?? 0;
      const title = extractTitle(bodyPreview);

      return {
        requestedUrl: requestInput.url,
        finalUrl: currentUrl,
        method: requestInput.method,
        statusCode: response.statusCode,
        headers,
        ...(bodyPreview ? { bodyPreview } : {}),
        bodyHash: streamed?.bodyHash ?? createHash("sha256").update(body).digest("hex"),
        responseTimeMs,
        redirectChain,
        contentLength,
        ...(streamed ? { bytesRead: streamed.bytesRead, streamTruncated: streamed.truncated, rangeIgnored: Boolean(requestInput.headers?.Range && response.statusCode === 200) } : {}),
        ...(contentType ? { contentType } : {}),
        ...(title ? { title } : {}),
        ...(redirectLocation ? { redirectLocation } : {})
      };
    } catch (error) {
      return {
        requestedUrl: requestInput.url,
        finalUrl: requestInput.url,
        method: requestInput.method,
        headers: {},
        responseTimeMs: Math.round(performance.now() - startedAt),
        redirectChain: [],
        error: safeError(error)
      };
    } finally {
      clearTimeout(timeout);
      this.options.abortSignal?.removeEventListener("abort", abortFromParent);
      await release?.();
    }
  }

  private async resolveDestination(url: URL): Promise<PinnedDestination> {
    const ttl = this.pool.settings.dnsCacheTtlMs; const key = url.origin; const cached = this.dnsCache.get(key);
    if (ttl > 0 && cached && cached.expiresAt > Date.now()) { this.pool.recordDnsCacheHit(); return cached.value; }
    this.pool.recordDnsResolution();
    const value = resolvePinnedDestination(connectorOptionsForUrl(url), this.policy).catch((error) => { this.pool.recordBlockedResolution(); this.dnsCache.delete(key); throw error; });
    if (ttl > 0) { this.pruneDnsCache(); this.dnsCache.set(key, { expiresAt: Date.now() + ttl, value }); }
    return value;
  }

  private pruneDnsCache(): void {
    const now = Date.now(); for (const [key, entry] of this.dnsCache) if (entry.expiresAt <= now) this.dnsCache.delete(key);
    while (this.dnsCache.size >= this.pool.settings.maxOrigins) { const oldest = this.dnsCache.keys().next().value as string | undefined; if (!oldest) break; this.dnsCache.delete(oldest); }
  }
}

async function readBoundedStream(body: AsyncIterable<Uint8Array>, limitBytes: number, controller: AbortController, previewBytes: number): Promise<{ body: Buffer; bodyHash: string; bodyPreview: string; bytesRead: number; truncated: boolean }> {
  const chunks: Buffer[] = [];
  const hash = createHash("sha256");
  let bytesRead = 0;
  let truncated = false;
  for await (const chunk of body) {
    const buffer = Buffer.from(chunk);
    const remaining = limitBytes - bytesRead;
    if (remaining <= 0) {
      truncated = true;
      controller.abort();
      break;
    }
    if (buffer.length > remaining) {
      const kept = buffer.subarray(0, remaining);
      if (previewBytes > 0) chunks.push(kept);
      hash.update(kept);
      bytesRead += remaining;
      truncated = true;
      controller.abort();
      break;
    }
    if (previewBytes > 0) chunks.push(buffer);
    hash.update(buffer);
    bytesRead += buffer.length;
  }
  const bodyBuffer = previewBytes > 0 ? Buffer.concat(chunks).subarray(0, previewBytes) : Buffer.alloc(0);
  return { body: bodyBuffer, bodyHash: hash.digest("hex"), bodyPreview: bodyBuffer.toString("utf8"), bytesRead, truncated };
}

function normalizeHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string | string[]> {
  const normalized: Record<string, string | string[]> = {};

  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === "string" || Array.isArray(value)) {
      normalized[key.toLowerCase()] = value;
    }
  }

  return normalized;
}

function headerValue(headers: Record<string, string | string[]>, name: string): string | undefined {
  const value = headers[name.toLowerCase()];

  if (Array.isArray(value)) {
    return value.join(", ");
  }

  return value;
}

function numericHeader(headers: Record<string, string | string[]>, name: string): number | undefined {
  const value = headerValue(headers, name);
  if (!value) {
    return undefined;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function extractTitle(bodyPreview: string): string | undefined {
  const match = /<title[^>]*>(?<title>[\s\S]*?)<\/title>/i.exec(bodyPreview);
  const title = match?.groups?.title?.replace(/\s+/g, " ").trim();
  return title || undefined;
}

function safeError(error: unknown): { name: string; message: string; code?: string } {
  if (error instanceof Error) {
    const candidate = error as Error & { code?: unknown };
    const code = typeof candidate.code === "string" ? candidate.code : undefined;
    return {
      name: error.name,
      message: error.message,
      ...(code ? { code } : {})
    };
  }

  return {
    name: "UnknownError",
    message: "Unknown HTTP error"
  };
}
