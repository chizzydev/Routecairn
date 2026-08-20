import { Agent, request } from "undici";
import { createHash } from "node:crypto";
import type { HttpClientOptions, HttpRequest, HttpResponse, RedirectHop } from "./HttpTypes.js";
import { createPinnedConnector } from "./PinnedHttpTransport.js";

const defaultHeaders = {
  accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
};

export class HttpClient {
  private readonly dispatcher: Agent;

  public constructor(private readonly options: HttpClientOptions) {
    this.dispatcher = new Agent({
      connect: createPinnedConnector({
        allowedPrivateOrigins: options.allowedPrivateOrigins ?? [],
        dnsTimeoutMs: options.dnsTimeoutMs ?? Math.min(options.timeoutMs, 3000),
        maxDnsAnswers: options.maxDnsAnswers ?? 16,
        ...(options.dnsResolver ? { dnsResolver: options.dnsResolver } : {})
      }),
      keepAliveTimeout: 1,
      keepAliveMaxTimeout: 1
    });
  }

  public async send(requestInput: HttpRequest, currentUrl = requestInput.url, redirectChain: RedirectHop[] = []): Promise<HttpResponse> {
    const startedAt = performance.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs);
    const abortFromParent = () => controller.abort();
    if (this.options.abortSignal?.aborted) {
      controller.abort();
    } else {
      this.options.abortSignal?.addEventListener("abort", abortFromParent, { once: true });
    }

    try {
      const response = await request(currentUrl, {
        method: requestInput.method,
        headers: {
          ...defaultHeaders,
          "user-agent": this.options.userAgent,
          ...requestInput.headers
        },
        ...(requestInput.body !== undefined ? { body: requestInput.body } : {}),
        dispatcher: this.dispatcher,
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

      const streamed = requestInput.streamLimitBytes !== undefined && requestInput.method !== "HEAD" ? await readBoundedStream(response.body, requestInput.streamLimitBytes, controller, requestInput.retainBodyPreview !== false ? this.options.bodyPreviewBytes : 0) : undefined;
      const bodyBuffer = streamed
        ? streamed.body
        : Buffer.from(new Uint8Array(requestInput.method === "HEAD" ? Buffer.alloc(0) : await response.body.arrayBuffer()));
      const body = bodyBuffer.subarray(0, streamed ? bodyBuffer.length : this.options.maxResponseBytes);
      const bodyPreview = streamed ? streamed.bodyPreview : body.subarray(0, this.options.bodyPreviewBytes).toString("utf8");
      const responseTimeMs = Math.round(performance.now() - startedAt);
      const contentType = headerValue(headers, "content-type");
      const contentLength = declaredLength ?? body.length;
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
    }
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
