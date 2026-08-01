import { request } from "undici";
import { createHash } from "node:crypto";
import type { HttpClientOptions, HttpRequest, HttpResponse, RedirectHop } from "./HttpTypes.js";

const defaultHeaders = {
  accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
};

export class HttpClient {
  public constructor(private readonly options: HttpClientOptions) {}

  public async send(requestInput: HttpRequest, currentUrl = requestInput.url, redirectChain: RedirectHop[] = []): Promise<HttpResponse> {
    const startedAt = performance.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs);

    try {
      const response = await request(currentUrl, {
        method: requestInput.method,
        headers: {
          ...defaultHeaders,
          "user-agent": this.options.userAgent,
          ...requestInput.headers
        },
        signal: controller.signal,
        bodyTimeout: this.options.timeoutMs,
        headersTimeout: this.options.timeoutMs
      });

      const headers = normalizeHeaders(response.headers);
      const redirectLocation = headerValue(headers, "location");

      const bodyBytes = requestInput.method === "HEAD" ? Buffer.alloc(0) : await response.body.arrayBuffer();
      const bodyBuffer = Buffer.isBuffer(bodyBytes) ? bodyBytes : Buffer.from(new Uint8Array(bodyBytes));
      const body = bodyBuffer.subarray(0, this.options.maxResponseBytes);
      const bodyPreview = body.subarray(0, this.options.bodyPreviewBytes).toString("utf8");
      const responseTimeMs = Math.round(performance.now() - startedAt);
      const contentType = headerValue(headers, "content-type");
      const contentLength = numericHeader(headers, "content-length") ?? body.length;
      const title = extractTitle(bodyPreview);

      return {
        requestedUrl: requestInput.url,
        finalUrl: currentUrl,
        method: requestInput.method,
        statusCode: response.statusCode,
        headers,
        bodyPreview,
        bodyHash: createHash("sha256").update(body).digest("hex"),
        responseTimeMs,
        redirectChain,
        contentLength,
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
    }
  }
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
