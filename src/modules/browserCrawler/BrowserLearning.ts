import { createHash, randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { BrowserContext, Page, Request, Response } from "playwright";
import type { AuthProfile } from "../../core/auth/AuthProfile.js";
import type {
  BrowserAuthenticationReport,
  BrowserFieldObservation,
  BrowserIdentityCorrelation,
  BrowserLearnedTestCase,
  BrowserStorageObservation,
  BrowserTrafficEntry
} from "../../reports/ReportTypes.js";
import { classifyTransientSecret } from "../secretBoundary/SecretBoundaryClassifier.js";

const sensitiveName = /(?:token|secret|session|cookie|auth|password|pass|key|jwt|csrf|xsrf)/i;
const adminPath = /(?:^|\/)(?:admin|administrator|manage|management|staff|console|backoffice)(?:\/|$)/i;
const writeMethods = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export interface BrowserLoginWriteGate {
  active: boolean;
  allowedPaths: ReadonlySet<string>;
  allowed: number;
  blocked: number;
}

export class BrowserLearningCollector {
  private readonly traffic: BrowserTrafficEntry[] = [];
  private readonly byRequest = new WeakMap<Request, BrowserTrafficEntry>();
  private readonly storage = new Map<string, BrowserStorageObservation>();
  private readonly fields = new Map<string, BrowserFieldObservation>();
  private readonly adminRoutes = new Set<string>();
  private readonly identity: BrowserIdentityCorrelation = { principal: "NOT_CONFIGURED", tenant: "NOT_CONFIGURED", role: "NOT_CONFIGURED", rawIdentityStored: false };
  private readonly valueDigestSalt = randomBytes(32);

  public constructor(private readonly profile: AuthProfile, private readonly targetOrigin: string) {}

  public recordRequest(request: Request, pageUrl: string, metadata: { transmitted: boolean; authorizationContext: BrowserTrafficEntry["authorizationContext"]; blockedReason?: string }): void {
    if (this.traffic.length >= 1000) return;
    const bodyFormat = requestBodyFormat(request);
    const entry: BrowserTrafficEntry = {
      startedAt: new Date().toISOString(),
      pageUrl: redactUrl(pageUrl),
      url: redactUrl(request.url()),
      method: request.method(),
      resourceType: request.resourceType(),
      requestHeaderNames: Object.keys(request.headers()).map((name) => name.toLowerCase()).filter((name) => !sensitiveName.test(name)).sort(),
      requestFieldNames: requestFieldNames(request),
      ...(bodyFormat ? { requestBodyFormat: bodyFormat } : {}),
      requestSecretBindings: requestSecretBindings(request, this.profile.browserBootstrap?.loginSecrets ?? {}),
      transmitted: metadata.transmitted,
      authorizationContext: metadata.authorizationContext,
      ...(metadata.blockedReason ? { blockedReason: metadata.blockedReason } : {}),
      redactionApplied: true
    };
    this.traffic.push(entry);
    this.byRequest.set(request, entry);
  }

  public recordResponse(response: Response): void {
    const entry = this.byRequest.get(response.request());
    if (!entry) return;
    const headers = response.headers();
    entry.responseStatus = response.status();
    const contentType = safeContentType(headers["content-type"]);
    if (contentType) entry.responseContentType = contentType;
    entry.responseHeaderNames = Object.keys(headers).map((name) => name.toLowerCase()).filter((name) => !sensitiveName.test(name)).sort();
    entry.responseCookieNames = setCookieNames(headers["set-cookie"]);
    const length = Number(headers["content-length"]);
    if (Number.isSafeInteger(length) && length >= 0) entry.responseBodyBytes = length;
  }

  public async inspectPage(page: Page): Promise<void> {
    const pageUrl = redactUrl(page.url());
    const observations = await page.locator("input, textarea, select, [contenteditable='true']").evaluateAll((elements) => elements.slice(0, 300).map((element, index) => {
      const input = element as unknown as { name?: string; id?: string; type?: string; disabled?: boolean; readOnly?: boolean; tagName: string; getAttribute(name: string): string | null };
      const name = input.name || input.getAttribute("aria-label") || input.id || `unnamed-${index + 1}`;
      const disabled = Boolean(input.disabled);
      const readOnly = Boolean(input.readOnly);
      return { name, controlType: input.type || input.tagName.toLowerCase(), access: (disabled ? "disabled" : readOnly ? "read-only" : "writable") as "writable" | "read-only" | "disabled" };
    })).catch(() => [] as Array<{ name: string; controlType: string; access: "writable" | "read-only" | "disabled" }>);
    for (const observation of observations) {
      const safe: BrowserFieldObservation = { pageUrl, name: sanitizeName(observation.name), controlType: sanitizeName(observation.controlType), access: observation.access };
      this.fields.set(`${safe.pageUrl}:${safe.name}:${safe.controlType}`, safe);
    }

    const hrefs = await page.locator("a[href]").evaluateAll((elements) => elements.slice(0, 500).map((element) => (element as unknown as { href: string }).href)).catch(() => [] as string[]);
    for (const href of hrefs) {
      try {
        const parsed = new URL(href);
        if (parsed.origin === this.targetOrigin && adminPath.test(parsed.pathname)) this.adminRoutes.add(`${parsed.origin}${parsed.pathname}`);
      } catch { /* malformed links are ignored */ }
    }
    await this.inspectIdentity(page);
  }

  public async inspectStorage(context: BrowserContext, page: Page | undefined): Promise<void> {
    for (const cookie of await context.cookies()) {
      const observation: BrowserStorageObservation = {
        origin: cookie.domain,
        storage: "cookie",
        name: sanitizeName(cookie.name),
        valueLength: cookie.value.length,
        valueDigest: this.secretDigest(cookie.value),
        classification: classifyStorage(cookie.name),
        httpOnly: cookie.httpOnly,
        secure: cookie.secure,
        sameSite: cookie.sameSite,
        secretBoundary: classifyTransientSecret({ name: cookie.name, value: cookie.value, surface: "COOKIE", publicExposure: false, cookie: { httpOnly: cookie.httpOnly, secure: cookie.secure, sameSite: cookie.sameSite } })
      };
      this.storage.set(`cookie:${cookie.domain}:${cookie.name}`, observation);
    }
    if (!page || page.isClosed()) return;
    const origin = new URL(page.url()).origin;
    const values = await page.evaluate(() => ({
      local: Object.entries(localStorage).map(([name, value]) => ({ name, value })),
      session: Object.entries(sessionStorage).map(([name, value]) => ({ name, value }))
    })).catch(() => ({ local: [] as Array<{ name: string; value: string }>, session: [] as Array<{ name: string; value: string }> }));
    for (const [storage, entries] of [["localStorage", values.local], ["sessionStorage", values.session]] as const) {
      for (const entry of entries.slice(0, 200)) {
        const surface = storage === "localStorage" ? "BROWSER_LOCAL_STORAGE" : "BROWSER_SESSION_STORAGE";
        const observation: BrowserStorageObservation = { origin, storage, name: sanitizeName(entry.name), valueLength: entry.value.length, valueDigest: this.secretDigest(entry.value), classification: classifyStorage(entry.name), secretBoundary: classifyTransientSecret({ name: entry.name, value: entry.value, surface, publicExposure: false }) };
        this.storage.set(`${storage}:${origin}:${entry.name}`, observation);
      }
    }
  }

  public async writeRedactedHar(outputDir: string): Promise<string> {
    const path = join(outputDir, "browser-traffic.redacted.har.json");
    await mkdir(outputDir, { recursive: true });
    const entries = this.traffic.map((entry) => ({
      startedDateTime: entry.startedAt,
      time: 0,
      request: {
        method: entry.method,
        url: entry.url,
        httpVersion: "",
        headers: entry.requestHeaderNames.map((name) => ({ name, value: "<redacted>" })),
        queryString: queryNames(entry.url).map((name) => ({ name, value: "<redacted>" })),
        cookies: [],
        headersSize: -1,
        bodySize: -1,
        _routecairnFieldNames: entry.requestFieldNames,
        _routecairnTransmitted: entry.transmitted,
        _routecairnAuthorizationContext: entry.authorizationContext
      },
      response: {
        status: entry.responseStatus ?? 0,
        statusText: "",
        httpVersion: "",
        headers: (entry.responseHeaderNames ?? []).map((name) => ({ name, value: "<redacted>" })),
        cookies: [],
        content: { size: entry.responseBodyBytes ?? 0, mimeType: entry.responseContentType ?? "application/octet-stream", text: "" },
        redirectURL: "",
        headersSize: -1,
        bodySize: entry.responseBodyBytes ?? -1
      },
      cache: {},
      timings: { send: -1, wait: -1, receive: -1 },
      pageref: entry.pageUrl,
      _routecairnResourceType: entry.resourceType
    }));
    await writeFile(path, `${JSON.stringify({ log: { version: "1.2", creator: { name: "RouteCairn", version: "0.1.0" }, pages: [], entries, _routecairn: { schemaVersion: 1, redactionApplied: true, secretsStored: false, bodiesStored: false } } }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    return path;
  }

  public async writeLifecycleLearningBundle(outputDir: string): Promise<{ path: string; cases: BrowserLearnedTestCase[] }> {
    const path = join(outputDir, "authentication-lifecycle.learning.json");
    const cases = learnedCases(this.traffic);
    await mkdir(outputDir, { recursive: true });
    await writeFile(path, `${JSON.stringify({
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      targetOrigin: this.targetOrigin,
      candidates: cases,
      identityCorrelation: this.identity,
      storageNames: [...this.storage.values()].map(({ storage, origin, name, classification, httpOnly, secure, sameSite }) => ({ storage, origin, name, classification, ...(httpOnly !== undefined ? { httpOnly } : {}), ...(secure !== undefined ? { secure } : {}), ...(sameSite ? { sameSite } : {}) })),
      redaction: { applied: true, secretsStored: false, bodiesStored: false, rawIdentityStored: false }
    }, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    return { path, cases };
  }

  public report(input: { mode: BrowserAuthenticationReport["mode"]; bootstrapSucceeded: boolean; loginStepsExecuted: number; formsSubmitted: number; gate: BrowserLoginWriteGate; restartCount: number; harPath?: string; learningBundlePath: string; learnedCases: BrowserLearnedTestCase[] }): BrowserAuthenticationReport {
    return {
      mode: input.mode,
      bootstrapSucceeded: input.bootstrapSucceeded,
      sessionIsolated: true,
      sessionSecretsPersisted: false,
      loginStepsExecuted: input.loginStepsExecuted,
      loginWriteRequestsAllowed: input.gate.allowed,
      loginWriteRequestsBlocked: input.gate.blocked,
      browserRestartCount: input.restartCount,
      ...(input.harPath ? { redactedHarPath: input.harPath } : {}),
      storage: [...this.storage.values()],
      fields: [...this.fields.values()],
      adminRoutes: [...this.adminRoutes].sort(),
      learnedTestCases: input.learnedCases,
      lifecycleLearningBundle: {
        schemaVersion: 1,
        artifactPath: input.learningBundlePath,
        candidateCount: input.learnedCases.length,
        loginCandidateCount: input.learnedCases.filter((item) => item.authorizationContext === "EXPLICIT_LOGIN").length,
        mutationHypothesisCount: input.learnedCases.filter((item) => item.classification === "MUTATION_HYPOTHESIS").length,
        automaticallyCompilableCategories: input.learnedCases.some((item) => item.authorizationContext === "EXPLICIT_LOGIN") ? ["LOGIN_ENUMERATION_RESISTANCE", "SESSION_ROTATION_AFTER_LOGIN", "SESSION_FIXATION"] : [],
        secretsStored: false
      },
      identityCorrelation: this.identity,
      protectedActionProof: (this.profile.browserBootstrap?.proofCases?.length ?? 0) > 0 ? "BOUND_TO_APPROVED_CASE_ONLY" : "REQUIRES_APPROVED_OPERATOR_CASE",
      rollbackVerification: (this.profile.browserBootstrap?.proofCases?.length ?? 0) > 0 ? "BOUND_TO_APPROVED_CASE_ONLY" : "REQUIRES_APPROVED_OPERATOR_CASE"
    };
  }

  private async inspectIdentity(page: Page): Promise<void> {
    const selectors = this.profile.browserBootstrap?.identitySelectors;
    if (!selectors) return;
    for (const [key, selector, expected] of [
      ["principal", selectors.principal, this.profile.principalId],
      ["tenant", selectors.tenant, this.profile.tenantId],
      ["role", selectors.role, this.profile.role]
    ] as const) {
      if (!selector || !expected) continue;
      const actual = await page.locator(selector).first().textContent().catch(() => null);
      this.identity[key] = actual === null ? "MISMATCH" : this.secretDigest(actual.trim()) === this.secretDigest(expected) ? "MATCHED" : "MISMATCH";
    }
  }

  private secretDigest(value: string): string { return createHash("sha256").update(this.valueDigestSalt).update(value).digest("hex"); }
}

export async function applyBrowserCredentials(context: BrowserContext, profile: AuthProfile, targetUrl: string): Promise<void> {
  const target = new URL(targetUrl);
  if (profile.cookies.length === 0) return;
  await context.addCookies(profile.cookies.map((cookie) => ({
    name: cookie.name,
    value: cookie.value,
    domain: cookie.domain ?? target.hostname,
    path: cookie.path ?? "/",
    secure: target.protocol === "https:",
    sameSite: "Lax" as const
  })));
}

export async function executeLogin(page: Page, profile: AuthProfile, gate: BrowserLoginWriteGate, assertUrlAllowed: (url: string) => void): Promise<{ steps: number; formsSubmitted: number }> {
  const bootstrap = profile.browserBootstrap;
  const login = bootstrap?.login;
  if (!bootstrap || !login) return { steps: 0, formsSubmitted: 0 };
  gate.active = true;
  let formsSubmitted = 0;
  try {
    assertUrlAllowed(login.startUrl);
    await page.goto(login.startUrl, { waitUntil: "domcontentloaded" });
    for (const step of login.steps) {
      if (step.action === "navigate") {
        assertUrlAllowed(step.url);
        await page.goto(step.url, { waitUntil: "domcontentloaded" });
      } else if (step.action === "fill") {
        await page.locator(step.selector).fill(bootstrap.loginSecrets[step.valueRef]!);
      } else if (step.action === "click") {
        const locator = page.locator(step.selector).first();
        const submits = await locator.evaluate((element) => {
          const candidate = element as unknown as { tagName: string; getAttribute(name: string): string | null };
          const tag = candidate.tagName.toLowerCase();
          const type = (candidate.getAttribute("type") ?? (tag === "button" ? "submit" : "")).toLowerCase();
          return (tag === "button" || tag === "input") && type === "submit";
        }).catch(() => false);
        if (submits) formsSubmitted += 1;
        await locator.click();
      } else if (step.action === "waitForUrl") {
        assertUrlAllowed(step.urlPrefix);
        await page.waitForURL((url) => url.toString().startsWith(step.urlPrefix), { timeout: 15_000 });
      } else {
        await page.locator(step.selector).first().waitFor({ state: "visible", timeout: 15_000 });
      }
    }
    if (!page.url().startsWith(login.successUrlPrefix)) throw new Error("Authenticated browser bootstrap did not reach the configured success URL boundary.");
    return { steps: login.steps.length, formsSubmitted };
  } finally {
    gate.active = false;
  }
}

export async function executeJourneys(page: Page, profile: AuthProfile, assertUrlAllowed: (url: string) => void, inspect: (page: Page) => Promise<void>): Promise<void> {
  for (const journey of profile.browserBootstrap?.journeys ?? []) {
    for (const step of journey.steps) {
      if (step.action === "navigate") {
        assertUrlAllowed(step.url);
        await page.goto(step.url, { waitUntil: "networkidle" });
      } else if (step.action === "clickLink") {
        const locator = page.locator(step.selector).first();
        const href = await locator.getAttribute("href");
        const tagName = await locator.evaluate((element) => element.tagName);
        if (tagName !== "A" || !href) throw new Error(`Journey ${journey.id} may click only an anchor with an href.`);
        const destination = new URL(href, page.url()).toString();
        assertUrlAllowed(destination);
        await locator.click();
        await page.waitForLoadState("domcontentloaded");
      } else {
        await page.locator(step.selector).first().waitFor({ state: "visible", timeout: 15_000 });
      }
      await inspect(page);
    }
  }
}

export function browserExtraHeaders(profile: AuthProfile): Record<string, string> {
  return Object.fromEntries(Object.entries(profile.headers).filter(([name]) => name.toLowerCase() !== "cookie"));
}

export function isExplicitLoginWriteAllowed(url: string, gate: BrowserLoginWriteGate): boolean {
  if (!gate.active) return false;
  try {
    const path = new URL(url).pathname;
    return [...gate.allowedPaths].some((allowed) => path === allowed || path.startsWith(`${allowed.replace(/\/$/, "")}/`));
  } catch { return false; }
}

export function isWriteMethod(method: string): boolean { return writeMethods.has(method.toUpperCase()); }

function learnedCases(entries: readonly BrowserTrafficEntry[]): BrowserLearnedTestCase[] {
  const cases = new Map<string, BrowserLearnedTestCase>();
  for (const entry of entries) {
    if (!["xhr", "fetch", "document"].includes(entry.resourceType)) continue;
    const url = new URL(entry.url);
    const key = `${entry.method}:${url.origin}${url.pathname}:${entry.authorizationContext}:${entry.requestBodyFormat ?? "NONE"}:${entry.requestFieldNames.join(",")}`;
    const existing = cases.get(key);
    if (existing) {
      if (entry.responseStatus !== undefined && !existing.observedStatusCodes.includes(entry.responseStatus)) existing.observedStatusCodes.push(entry.responseStatus);
      existing.responseCookieNames = [...new Set([...existing.responseCookieNames, ...(entry.responseCookieNames ?? [])])].sort();
      continue;
    }
    const mutating = writeMethods.has(entry.method.toUpperCase());
    cases.set(key, {
      id: `browser-${digest(key).slice(0, 16)}`,
      source: "browser-learned-traffic",
      method: entry.method,
      endpoint: `${url.origin}${url.pathname}`,
      observedFieldNames: entry.requestFieldNames,
      ...(entry.requestBodyFormat ? { requestBodyFormat: entry.requestBodyFormat } : {}),
      requestSecretBindings: entry.requestSecretBindings ?? {},
      observedStatusCodes: entry.responseStatus === undefined ? [] : [entry.responseStatus],
      responseCookieNames: entry.responseCookieNames ?? [],
      authorizationContext: entry.authorizationContext,
      transmitted: entry.transmitted,
      suggestedLifecycleCategories: suggestedCategories(entry, url.pathname),
      classification: mutating ? "MUTATION_HYPOTHESIS" : "READ_ONLY_OBSERVATION",
      state: "DRAFT_REQUIRES_OPERATOR_CASE",
      executable: false,
      operatorApprovalRequired: mutating
    });
  }
  return [...cases.values()];
}

function suggestedCategories(entry: BrowserTrafficEntry, path: string): string[] {
  if (entry.authorizationContext === "EXPLICIT_LOGIN") return ["LOGIN_ENUMERATION_RESISTANCE", "SESSION_ROTATION_AFTER_LOGIN", "SESSION_FIXATION"];
  const signal = `${path} ${entry.requestFieldNames.join(" ")}`.toLowerCase();
  const suggestions: string[] = [];
  if (/logout|signout|revoke/.test(signal)) suggestions.push("LOGOUT_INVALIDATION", "SESSION_REVOCATION");
  if (/refresh/.test(signal)) suggestions.push("REFRESH_TOKEN_ROTATION");
  if (/reset|forgot/.test(signal)) suggestions.push("PASSWORD_RESET_TOKEN_BINDING", "PASSWORD_RESET_TOKEN_REPLAY", "PASSWORD_RESET_ACCOUNT_CONFUSION");
  if (/verify.*email|email.*verify/.test(signal)) suggestions.push("EMAIL_VERIFICATION_BYPASS");
  if (/oauth|oidc|callback/.test(signal)) suggestions.push("OAUTH_OIDC_STATE_REDIRECT_VALIDATION", "ACCOUNT_LINKING_CONFUSION");
  if (/mfa|totp|2fa/.test(signal)) suggestions.push("MFA_ENROLLMENT_REMOVAL");
  if (/passkey|webauthn/.test(signal)) suggestions.push("PASSKEY_ENROLLMENT_REMOVAL");
  if (/recovery/.test(signal)) suggestions.push("RECOVERY_CODE_LIFECYCLE");
  if (/invite/.test(signal)) suggestions.push(/tenant|organization|workspace/.test(signal) ? "TENANT_INVITATION_LIFECYCLE" : "ADMIN_INVITATION_LIFECYCLE");
  return [...new Set(suggestions)];
}

function requestFieldNames(request: Request): string[] {
  const postData = request.postData();
  if (!postData) return [];
  const contentType = request.headers()["content-type"] ?? "";
  try {
    if (contentType.includes("application/json")) return jsonPaths(JSON.parse(postData)).slice(0, 200);
    if (contentType.includes("application/x-www-form-urlencoded")) return [...new URLSearchParams(postData).keys()].map(sanitizeName).slice(0, 200);
  } catch { return []; }
  return [];
}

function requestBodyFormat(request: Request): "JSON" | "FORM" | undefined {
  const contentType = request.headers()["content-type"] ?? "";
  if (contentType.includes("application/json")) return "JSON";
  if (contentType.includes("application/x-www-form-urlencoded")) return "FORM";
  return undefined;
}

function requestSecretBindings(request: Request, secrets: Record<string, string>): Record<string, string> {
  const postData = request.postData();
  if (!postData) return {};
  let values: Record<string, unknown> = {};
  try {
    if (requestBodyFormat(request) === "JSON") values = flattenJson(JSON.parse(postData));
    else if (requestBodyFormat(request) === "FORM") values = Object.fromEntries(new URLSearchParams(postData));
  } catch { return {}; }
  const bindings: Record<string, string> = {};
  for (const [field, value] of Object.entries(values)) {
    if (typeof value !== "string") continue;
    const matches = Object.entries(secrets).filter(([, secret]) => secret === value);
    if (matches.length === 1) bindings[sanitizeName(field)] = matches[0]![0];
  }
  return bindings;
}

function flattenJson(value: unknown, prefix = "", output: Record<string, unknown> = {}): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) { if (prefix) output[prefix] = value; return output; }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) flattenJson(child, prefix ? `${prefix}.${sanitizeName(key)}` : sanitizeName(key), output);
  return output;
}

function setCookieNames(value: string | undefined): string[] {
  if (!value) return [];
  return [...new Set([...value.matchAll(/(?:^|,\s*)([!#$%&'*+.^_`|~0-9A-Za-z-]+)=/g)].map((match) => sanitizeName(match[1]!)))].sort();
}

function jsonPaths(value: unknown, prefix = "", depth = 0): string[] {
  if (depth > 5 || !value || typeof value !== "object") return prefix ? [prefix] : [];
  if (Array.isArray(value)) return value.length > 0 ? jsonPaths(value[0], `${prefix}[]`, depth + 1) : [prefix];
  return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => jsonPaths(child, prefix ? `${prefix}.${sanitizeName(key)}` : sanitizeName(key), depth + 1));
}

function redactUrl(value: string): string {
  try {
    const url = new URL(value);
    url.username = ""; url.password = "";
    for (const key of [...url.searchParams.keys()]) url.searchParams.set(key, "<redacted>");
    url.hash = "";
    return url.toString();
  } catch { return "about:invalid"; }
}
function classifyStorage(name: string): BrowserStorageObservation["classification"] { return /csrf|xsrf/i.test(name) ? "csrf" : /session|auth|token|jwt|sid/i.test(name) ? "authentication" : /theme|locale|language|preference/i.test(name) ? "preference" : "application"; }
function digest(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function sanitizeName(value: string): string { return value.replace(/[\r\n\0|]/g, "_").slice(0, 200); }
function safeContentType(value: string | undefined): string | undefined { return value ? value.split(";", 1)[0]!.slice(0, 120) : undefined; }
function queryNames(value: string): string[] { try { return [...new Set(new URL(value).searchParams.keys())].map(sanitizeName); } catch { return []; } }
