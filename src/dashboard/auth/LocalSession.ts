import { randomBytes, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

export class LocalSessionManager {
  private bootstrapToken = token();
  private bootstrapExpiresAt: number;
  private sessionId: string | undefined;
  private csrfTokens: string[] = [];

  public constructor(bootstrapTtlMs = 10 * 60 * 1000) {
    this.bootstrapExpiresAt = Date.now() + bootstrapTtlMs;
  }

  public bootstrapUrl(baseUrl: string): string {
    return `${baseUrl}/#bootstrap=${this.bootstrapToken}`;
  }

  public exchange(candidate: string | undefined, response: ServerResponse): { csrfToken: string } {
    if (!candidate || Date.now() > this.bootstrapExpiresAt || !constantEqual(candidate, this.bootstrapToken)) {
      throw new SessionError("Invalid or expired bootstrap credential.");
    }
    this.bootstrapToken = token();
    this.bootstrapExpiresAt = 0;
    this.sessionId = token();
    const csrfToken = token();
    this.csrfTokens = [csrfToken];
    response.setHeader("Set-Cookie", `routecairn_session=${this.sessionId}; HttpOnly; SameSite=Strict; Path=/`);
    return { csrfToken };
  }

  public requireSession(request: IncomingMessage): void {
    const cookie = parseCookies(request.headers.cookie ?? "").get("routecairn_session");
    if (!cookie || !this.sessionId || !constantEqual(cookie, this.sessionId)) {
      throw new SessionError("Dashboard session required.");
    }
  }

  public requireMutation(request: IncomingMessage, csrfToken: string | undefined): void {
    this.requireSession(request);
    if (!isSafeOrigin(request)) {
      throw new SessionError("Origin rejected.");
    }
    const contentType = request.headers["content-type"] ?? "";
    if (!String(contentType).toLowerCase().startsWith("application/json")) {
      throw new SessionError("JSON content type required.");
    }
    if (!csrfToken || !this.csrfTokens.some((candidate) => constantEqual(csrfToken, candidate))) {
      throw new SessionError("CSRF token rejected.");
    }
  }

  public refreshCsrf(request: IncomingMessage): string {
    this.requireSession(request);
    if (!isSafeOrigin(request)) throw new SessionError("Origin rejected.");
    const contentType = request.headers["content-type"] ?? "";
    if (!String(contentType).toLowerCase().startsWith("application/json")) {
      throw new SessionError("JSON content type required.");
    }
    const csrfToken = token();
    this.csrfTokens = [csrfToken, ...this.csrfTokens].slice(0, 20);
    return csrfToken;
  }

  public destroy(response: ServerResponse): void {
    this.sessionId = undefined;
    this.csrfTokens = [];
    response.setHeader("Set-Cookie", "routecairn_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
  }
}

export class SessionError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "SessionError";
  }
}

function token(): string {
  return randomBytes(32).toString("base64url");
}

function constantEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function parseCookies(header: string): Map<string, string> {
  const result = new Map<string, string>();
  for (const pair of header.split(";")) {
    const [key, ...value] = pair.trim().split("=");
    if (key) result.set(key, value.join("="));
  }
  return result;
}

function isSafeOrigin(request: IncomingMessage): boolean {
  const origin = request.headers.origin;
  const host = request.headers.host;
  if (!origin || !host) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}
