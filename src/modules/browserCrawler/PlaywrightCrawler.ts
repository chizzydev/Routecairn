import { chromium, type ConsoleMessage, type Page, type Request, type Route, type WebSocketRoute } from "playwright";
import type {
  BrowserConsoleError,
  BrowserCrawlReport,
  BrowserNetworkRequest,
  BrowserPolicyEvent,
  PathCandidate
} from "../../reports/ReportTypes.js";
import type { RequestSafetyBroker } from "../../core/http/RequestSafetyBroker.js";
import type { AuthProfile } from "../../core/auth/AuthProfile.js";
import { normalizeUrl } from "../../core/urls/UrlNormalizer.js";
import { BrowserPolicyEngine, canonicalBrowserUrl, type BrowserPolicy } from "./BrowserPolicy.js";
import {
  applyBrowserCredentials,
  browserExtraHeaders,
  BrowserLearningCollector,
  executeJourneys,
  executeLogin,
  isExplicitLoginWriteAllowed,
  isWriteMethod,
  type BrowserLoginWriteGate
} from "./BrowserLearning.js";
import { Screenshotter } from "./Screenshotter.js";

export interface PlaywrightCrawlerOptions {
  targetUrl: string;
  outputDir: string;
  userAgent: string;
  timeoutMs: number;
  sameOriginOnly: boolean;
  policy: BrowserPolicy;
  requestBroker: RequestSafetyBroker;
  authProfile?: AuthProfile;
  browserRestartCount?: number;
  abortSignal?: AbortSignal;
}

interface CrawlEntry {
  url: string;
  depth: number;
  parentUrl?: string;
}

export class PlaywrightCrawler {
  private readonly screenshotter = new Screenshotter();

  public async crawl(options: PlaywrightCrawlerOptions): Promise<BrowserCrawlReport> {
    const networkRequests: BrowserNetworkRequest[] = [];
    const policyEvents: BrowserPolicyEvent[] = [];
    const consoleErrors: BrowserConsoleError[] = [];
    const renderedLinks = new Map<string, PathCandidate>();
    const requestsByPage = new Map<string, number>();
    const visitedPages: Array<{ url: string; depth: number }> = [];
    const policyEngine = new BrowserPolicyEngine(options.targetUrl, options.policy);
    const targetOrigin = new URL(options.targetUrl).origin;
    const bootstrap = options.authProfile?.browserBootstrap;
    const writeGate: BrowserLoginWriteGate = {
      active: false,
      allowedPaths: new Set(bootstrap?.login?.allowedWritePaths ?? []),
      allowed: 0,
      blocked: 0
    };
    const learning = options.authProfile ? new BrowserLearningCollector(options.authProfile, targetOrigin) : undefined;
    const browser = await chromium.launch({ headless: true });
    const openWebSockets: WebSocketRoute[] = [];
    let attemptBudgetExceeded = false;
    options.requestBroker.setBrowserPolicyEventLimit(options.policy.maxPolicyEvents);

    try {
      const abortBrowser = () => void browser.close().catch(() => undefined);
      options.abortSignal?.addEventListener("abort", abortBrowser, { once: true });
      const context = await browser.newContext({
        userAgent: options.userAgent,
        ...(options.authProfile && Object.keys(browserExtraHeaders(options.authProfile)).length > 0 ? { extraHTTPHeaders: browserExtraHeaders(options.authProfile) } : {}),
        ignoreHTTPSErrors: true,
        acceptDownloads: false,
        serviceWorkers: options.policy.allowServiceWorkers ? "allow" : "block"
      });
      if (options.authProfile) await applyBrowserCredentials(context, options.authProfile, options.targetUrl);
      context.on("response", (response) => learning?.recordResponse(response));
      await context.exposeBinding("__routeCairnPolicyEvent", (_source, event: { url?: string; reason?: string }) => {
        const decision = options.requestBroker.recordBrowserPolicyBlock({
          url: event.url ?? "about:blank",
          method: "GET",
          resourceType: "other"
        }, event.reason ?? "browser-policy-blocked");
        attemptBudgetExceeded = attemptBudgetExceeded || decision.reason === "browser-attempt-budget-exceeded";
        addPolicyEvent(policyEvents, options.policy, {
          url: redactSensitiveUrl(event.url ?? "about:blank"),
          reason: decision.reason,
          transmitted: false
        });
      });
      if (!options.policy.allowServiceWorkers) {
        await context.addInitScript(`
          (() => {
            if (!navigator.serviceWorker) return;
            const blockedRegistration = () => {
              void globalThis.__routeCairnPolicyEvent?.({
                url: globalThis.location.href,
                reason: "service-worker-blocked"
              });
              return Promise.reject(new Error("RouteCairn blocked service worker registration"));
            };
            try {
              Object.defineProperty(navigator.serviceWorker, "register", {
                configurable: true,
                value: blockedRegistration
              });
            } catch {
              navigator.serviceWorker.register = blockedRegistration;
            }
          })();
        `);
      }
      if (!options.policy.allowUploads) {
        await context.addInitScript(`
          (() => {
          const originalClick = HTMLInputElement.prototype.click;
          HTMLInputElement.prototype.click = function click() {
            if (this.type === "file") {
              void globalThis.__routeCairnPolicyEvent?.({
                url: globalThis.location.href,
                reason: "upload-blocked"
              });
              return;
            }
            return originalClick.call(this);
          };
          })();
        `);
      }
      if (!options.policy.allowPopups) {
        await context.addInitScript(`
          (() => {
            const originalOpen = window.open;
            window.open = function routeCairnBlockedWindowOpen(url) {
              void globalThis.__routeCairnPolicyEvent?.({
                url: typeof url === "string" ? url : globalThis.location.href,
                reason: "popup-blocked"
              });
              return null;
            };
            Object.defineProperty(window.open, "toString", {
              configurable: true,
              value: () => originalOpen.toString()
            });
          })();
        `);
      }
      await context.route("**/*", async (route) => {
        if (attemptBudgetExceeded) {
          await route.abort("blockedbyclient").catch(() => undefined);
          return;
        }
        const decision = await this.handleRoute(route, options, policyEngine, networkRequests, policyEvents, requestsByPage, writeGate, learning);
        attemptBudgetExceeded = attemptBudgetExceeded || decision === "browser-attempt-budget-exceeded";
      });
      await context.routeWebSocket("**", async (webSocket) => {
        const decision = await this.handleWebSocket(webSocket, options, policyEngine, policyEvents, openWebSockets);
        attemptBudgetExceeded = attemptBudgetExceeded || decision === "browser-attempt-budget-exceeded";
      });
      let creatingManagedPage = false;
      context.on("page", (page) => {
        if (creatingManagedPage || options.policy.allowPopups) {
          return;
        }

        const decision = options.requestBroker.recordBrowserPolicyBlock({
          url: page.url() || "about:blank",
          method: "GET",
          resourceType: "document"
        }, "popup-blocked");
        attemptBudgetExceeded = attemptBudgetExceeded || decision.reason === "browser-attempt-budget-exceeded";
        addPolicyEvent(policyEvents, options.policy, {
          url: redactSensitiveUrl(page.url() || "about:blank"),
          reason: decision.reason,
          transmitted: false
        });
        void page.close().catch(() => undefined);
      });
      let screenshotPath: string | undefined;
      const frontier: CrawlEntry[] = [{ url: options.targetUrl, depth: 0 }];
      const queued = new Set<string>([canonicalBrowserUrl(options.targetUrl, options.targetUrl)]);
      const visited = new Set<string>();
      let formsDetected = 0;
      let formsSubmitted = 0;
      let loginStepsExecuted = 0;
      let bootstrapSucceeded = !bootstrap?.login;
      let journeysExecuted = false;
      let lastPage: Page | undefined;

      while (frontier.length > 0 && visited.size < options.policy.maxPages && !attemptBudgetExceeded) {
        if (options.abortSignal?.aborted) {
          break;
        }
        const next = frontier.shift();
        if (!next) break;

        const canonical = canonicalBrowserUrl(next.url, options.targetUrl);
        if (visited.has(canonical)) continue;
        visited.add(canonical);
        visitedPages.push({ url: options.authProfile ? redactAllQueryValues(canonical) : canonical, depth: next.depth });

        creatingManagedPage = true;
        const page = await context.newPage().finally(() => {
          creatingManagedPage = false;
        });
        lastPage = page;
        attachDiagnostics(page, consoleErrors, policyEvents, next.depth, options);

        try {
          if (options.abortSignal?.aborted) {
            break;
          }
          if (options.authProfile && bootstrap?.login && !bootstrapSucceeded) {
            const loginResult = await executeLogin(page, options.authProfile, writeGate, (url) => assertSameOrigin(url, targetOrigin));
            loginStepsExecuted = loginResult.steps;
            formsSubmitted += loginResult.formsSubmitted;
            bootstrapSucceeded = true;
          }
          await page.goto(canonical, {
            waitUntil: "networkidle",
            timeout: options.timeoutMs
          });

          await learning?.inspectPage(page);
          if (options.authProfile && !journeysExecuted) {
            journeysExecuted = true;
            await executeJourneys(page, options.authProfile, (url) => assertSameOrigin(url, targetOrigin), async (journeyPage) => learning?.inspectPage(journeyPage));
          }

          const hrefs = await page.$$eval("a[href]", (anchors) =>
            anchors.map((anchor) => anchor.getAttribute("href")).filter((href): href is string => typeof href === "string" && href.length > 0)
          );
          formsDetected += await page.$$eval("form", (forms) => forms.length);
          await learning?.inspectStorage(context, page);

          for (const candidate of toPathCandidates(hrefs.slice(0, options.policy.maxLinksPerPage), canonical, options.sameOriginOnly)) {
            const safeCandidate = options.authProfile ? { ...candidate, path: candidate.path.split("?", 1)[0] || "/" } : candidate;
            renderedLinks.set(`${safeCandidate.source}:${safeCandidate.path}`, safeCandidate);
          }

          for (const href of hrefs.slice(0, options.policy.maxLinksPerPage)) {
            const childDepth = next.depth + 1;
            const queueDecision = await policyEngine.shouldQueueUrl(href, childDepth);
            if (!queueDecision.allowed || !queueDecision.normalizedUrl) {
              const decision = options.requestBroker.recordBrowserPolicyBlock({
                url: resolveUrlForEvent(href, canonical),
                method: "GET",
                resourceType: "document",
                pageUrl: canonical
              }, queueDecision.reason ?? "link-not-queued");
              attemptBudgetExceeded = attemptBudgetExceeded || decision.reason === "browser-attempt-budget-exceeded";
              addPolicyEvent(policyEvents, options.policy, {
                url: redactSensitiveUrl(resolveUrlForEvent(href, canonical)),
                pageUrl: redactSensitiveUrl(canonical),
                depth: childDepth,
                reason: decision.reason,
                transmitted: false
              });
              continue;
            }

            if (!queued.has(queueDecision.normalizedUrl) && !visited.has(queueDecision.normalizedUrl) && queued.size < options.policy.maxPages) {
              queued.add(queueDecision.normalizedUrl);
              frontier.push({ url: queueDecision.normalizedUrl, depth: childDepth, parentUrl: canonical });
            }
          }

          if (!screenshotPath && options.policy.captureScreenshot) {
            screenshotPath = await this.screenshotter.capture(page, options.outputDir);
          }
        } catch (error) {
          if (bootstrap?.login && !bootstrapSucceeded) throw error;
          consoleErrors.push({
            type: "navigation",
            text: error instanceof Error ? error.message : "Unknown browser navigation error"
          });
        } finally {
          await page.close().catch(() => undefined);
        }
      }

      await learning?.inspectStorage(context, lastPage);
      const redactedHarPath = learning ? await learning.writeRedactedHar(options.outputDir) : undefined;
      const lifecycleLearning = learning ? await learning.writeLifecycleLearningBundle(options.outputDir) : undefined;

      await Promise.all(openWebSockets.map((webSocket) => webSocket.close({ code: 1000, reason: "routecairn-scan-complete" }).catch(() => undefined)));
      await context.close();
      options.abortSignal?.removeEventListener("abort", abortBrowser);

      const brokerSnapshot = options.requestBroker.budgetSnapshot();
      return {
        startUrl: options.authProfile ? redactAllQueryValues(options.targetUrl) : options.targetUrl,
        renderedLinks: [...renderedLinks.values()],
        networkRequests: options.policy.evidence.level === "minimal" ? [] : networkRequests,
        policyEvents,
        policyEventCount: brokerSnapshot.browserPolicyEvents,
        transmittedRequestCount: networkRequests.filter((request) => request.transmitted).length,
        blockedRequestCount: policyEvents.filter((event) => !event.transmitted).length,
        visitedPages,
        consoleErrors,
        ...(screenshotPath ? { screenshotPath } : {}),
        formsDetected,
        formsSubmitted,
        ...(learning && options.authProfile ? {
          authentication: learning.report({
            mode: bootstrap?.login ? "learned-login-flow" : "header-cookie-bootstrap",
            bootstrapSucceeded,
            loginStepsExecuted,
            formsSubmitted,
            gate: writeGate,
            restartCount: options.browserRestartCount ?? 0,
            ...(redactedHarPath ? { harPath: redactedHarPath } : {}),
            learningBundlePath: lifecycleLearning!.path,
            learnedCases: lifecycleLearning!.cases
          })
        } : {}),
        notes: [
          `Rendered links discovered: ${renderedLinks.size}.`,
          `Browser policy events: ${brokerSnapshot.browserPolicyEvents}.`,
          `Browser network requests transmitted: ${networkRequests.filter((request) => request.transmitted).length}.`,
          `Browser requests blocked before network transmission: ${policyEvents.filter((event) => !event.transmitted).length}.`,
          "Blocked browser requests consume policy-event budget, not network request budget.",
          ...(attemptBudgetExceeded ? ["Browser crawl stopped because the browser attempt budget was exhausted."] : []),
          ...(formsSubmitted > 0 ? [`Submitted ${formsSubmitted} explicitly configured authentication form(s); no learned application form was submitted.`] : ["Forms were detected but not submitted."]),
          ...(learning ? ["Browser traffic was stored as redacted metadata; request bodies, response bodies, cookies, storage values, and identity values were not persisted.", "Learned mutation hypotheses are non-executable drafts and require a separate explicit operator case and approval."] : [])
        ]
      };
    } finally {
      await browser.close();
    }
  }

  private async handleRoute(
    route: Route,
    options: PlaywrightCrawlerOptions,
    policyEngine: BrowserPolicyEngine,
    networkRequests: BrowserNetworkRequest[],
    policyEvents: BrowserPolicyEvent[],
    requestsByPage: Map<string, number>,
    writeGate: BrowserLoginWriteGate,
    learning?: BrowserLearningCollector
  ): Promise<string> {
    const request = route.request();
    const pageUrl = pageUrlForRequest(request, options.targetUrl);
    const requestsSeenForPage = (requestsByPage.get(pageUrl) ?? 0) + 1;
    requestsByPage.set(pageUrl, requestsSeenForPage);
    if (options.authProfile && isWriteMethod(request.method()) && !isExplicitLoginWriteAllowed(request.url(), writeGate)) {
      writeGate.blocked += 1;
      const brokerDecision = options.requestBroker.recordBrowserPolicyBlock({ url: request.url(), method: request.method(), resourceType: request.resourceType(), pageUrl }, "browser-write-requires-explicit-operator-case");
      addPolicyEvent(policyEvents, options.policy, policyEvent(request, pageUrl, brokerDecision.reason, false));
      networkRequests.push(networkRequest(request, "blocked", brokerDecision.reason, false));
      learning?.recordRequest(request, pageUrl, { transmitted: false, authorizationContext: "BLOCKED_MUTATION_HYPOTHESIS", blockedReason: brokerDecision.reason });
      await route.abort("blockedbyclient").catch(() => undefined);
      return brokerDecision.reason;
    }
    const policyDecision = await policyEngine.evaluateRequest({
      url: request.url(),
      pageUrl,
      resourceType: request.resourceType(),
      requestsSeenForPage,
      isNavigationDownload: routeIsDownloadLike(request)
    });

    if (!policyDecision.allowed) {
      const brokerDecision = options.requestBroker.recordBrowserPolicyBlock({
        url: request.url(),
        method: request.method(),
        resourceType: request.resourceType(),
        pageUrl
      }, policyDecision.reason);
      const event = policyEvent(request, pageUrl, brokerDecision.reason, false);
      addPolicyEvent(policyEvents, options.policy, event);
      networkRequests.push(networkRequest(request, "blocked", brokerDecision.reason, false));
      await route.abort("blockedbyclient").catch(() => undefined);
      return brokerDecision.reason;
    }

    const brokerInput = {
      url: policyDecision.normalizedUrl,
      method: request.method(),
      resourceType: request.resourceType(),
      pageUrl,
      isRedirect: request.redirectedFrom() !== null
    };
    const explicitLoginWrite = isWriteMethod(request.method()) && isExplicitLoginWriteAllowed(request.url(), writeGate);
    const brokerDecision = explicitLoginWrite ? options.requestBroker.evaluateBrowserLoginRequest(brokerInput) : options.requestBroker.evaluateBrowserRequest(brokerInput);

    if (!brokerDecision.allowed) {
      addPolicyEvent(policyEvents, options.policy, policyEvent(request, pageUrl, brokerDecision.reason, false));
      networkRequests.push(networkRequest(request, "blocked", brokerDecision.reason, false));
      await route.abort("blockedbyclient").catch(() => undefined);
      return brokerDecision.reason;
    }

    networkRequests.push(networkRequest(request, "allowed", "allowed", true));
    if (explicitLoginWrite) writeGate.allowed += 1;
    learning?.recordRequest(request, pageUrl, { transmitted: true, authorizationContext: explicitLoginWrite ? "EXPLICIT_LOGIN" : "READ_ONLY" });
    await options.requestBroker.dispatchApprovedBrowserRequest(
      () => route.continue({ headers: browserContinuationHeaders(request, options.authProfile, new URL(options.targetUrl).origin) }).catch(() => undefined)
    );
    return "allowed";
  }

  private async handleWebSocket(
    webSocket: WebSocketRoute,
    options: PlaywrightCrawlerOptions,
    policyEngine: BrowserPolicyEngine,
    policyEvents: BrowserPolicyEvent[],
    openWebSockets: WebSocketRoute[]
  ): Promise<string> {
    if (options.authProfile && browserNetworkOrigin(webSocket.url()) !== browserNetworkOrigin(options.targetUrl)) {
      const brokerDecision = options.requestBroker.recordBrowserPolicyBlock({ url: webSocket.url(), method: "GET", resourceType: "websocket", pageUrl: options.targetUrl }, "authenticated-third-party-websocket-blocked");
      addPolicyEvent(policyEvents, options.policy, { url: redactSensitiveUrl(webSocket.url()), method: "GET", resourceType: "websocket", pageUrl: redactSensitiveUrl(options.targetUrl), reason: brokerDecision.reason, transmitted: false });
      await webSocket.close({ code: 1008, reason: "routecairn-auth-boundary" }).catch(() => undefined);
      return brokerDecision.reason;
    }
    const policyDecision = await policyEngine.evaluateRequest({
      url: webSocket.url(),
      pageUrl: options.targetUrl,
      resourceType: "websocket",
      requestsSeenForPage: 1
    });

    if (!policyDecision.allowed) {
      const brokerDecision = options.requestBroker.recordBrowserPolicyBlock({
        url: webSocket.url(),
        method: "GET",
        resourceType: "websocket",
        pageUrl: options.targetUrl
      }, policyDecision.reason);
      addPolicyEvent(policyEvents, options.policy, {
        url: redactSensitiveUrl(webSocket.url()),
        method: "GET",
        resourceType: "websocket",
        pageUrl: redactSensitiveUrl(options.targetUrl),
        reason: brokerDecision.reason,
        transmitted: false
      });
      await webSocket.close({ code: 1008, reason: "routecairn-policy-blocked" }).catch(() => undefined);
      return brokerDecision.reason;
    }

    const brokerDecision = options.requestBroker.evaluateBrowserRequest({
      url: policyDecision.normalizedUrl,
      method: "GET",
      resourceType: "websocket",
      pageUrl: options.targetUrl
    });

    if (!brokerDecision.allowed) {
      addPolicyEvent(policyEvents, options.policy, {
        url: redactSensitiveUrl(webSocket.url()),
        method: "GET",
        resourceType: "websocket",
        pageUrl: redactSensitiveUrl(options.targetUrl),
        reason: brokerDecision.reason,
        transmitted: false
      });
      await webSocket.close({ code: 1008, reason: "routecairn-policy-blocked" }).catch(() => undefined);
      return brokerDecision.reason;
    }

    const server = await options.requestBroker.dispatchApprovedBrowserRequest(async () => webSocket.connectToServer());
    openWebSockets.push(webSocket, server);
    return "allowed";
  }
}

export function toPathCandidates(hrefs: string[], baseUrl: string, sameOriginOnly: boolean): PathCandidate[] {
  const base = new URL(baseUrl);
  const candidates = new Map<string, PathCandidate>();

  for (const href of hrefs) {
    if (href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:") || href.startsWith("javascript:")) {
      continue;
    }

    try {
      const normalized = normalizeUrl(href, baseUrl);
      const url = new URL(normalized);

      if (sameOriginOnly && url.origin !== base.origin) {
        continue;
      }

      const path = `${url.pathname}${url.search}`;
      candidates.set(path, {
        path,
        source: "browser:rendered-link"
      });
    } catch {
      // Ignore malformed browser hrefs.
    }
  }

  return [...candidates.values()];
}

function attachDiagnostics(page: Page, consoleErrors: BrowserConsoleError[], policyEvents: BrowserPolicyEvent[], depth: number, options: PlaywrightCrawlerOptions): void {
  page.on("console", (message) => {
    if (message.type() === "error" || message.type() === "warning") {
      consoleErrors.push(consoleError(message));
    }
  });
  page.on("pageerror", (error) => {
    consoleErrors.push({
      type: "pageerror",
      text: error.message
    });
  });
  page.on("download", async (download) => {
    const decision = options.requestBroker.recordBrowserPolicyBlock({
      url: download.url(),
      method: "GET",
      resourceType: "document",
      pageUrl: page.url()
    }, "download-blocked");
    addPolicyEvent(policyEvents, options.policy, {
      url: redactSensitiveUrl(download.url()),
      depth,
      reason: decision.reason,
      transmitted: true
    });
    await download.cancel().catch(() => undefined);
  });
  page.on("filechooser", (fileChooser) => {
    const decision = options.requestBroker.recordBrowserPolicyBlock({
      url: fileChooser.page().url(),
      method: "GET",
      resourceType: "other",
      pageUrl: fileChooser.page().url()
    }, "upload-blocked");
    addPolicyEvent(policyEvents, options.policy, {
      url: redactSensitiveUrl(fileChooser.page().url()),
      depth,
      reason: decision.reason,
      transmitted: false
    });
  });
  page.on("popup", (popup) => {
    if (!options.policy.allowPopups) {
      const decision = options.requestBroker.recordBrowserPolicyBlock({
        url: popup.url() || "about:blank",
        method: "GET",
        resourceType: "document",
        pageUrl: page.url()
      }, "popup-blocked");
      addPolicyEvent(policyEvents, options.policy, {
        url: popup.url() || "about:blank",
        depth,
        reason: decision.reason,
        transmitted: false
      });
      void popup.close().catch(() => undefined);
    }
  });
}

function networkRequest(request: Request, decision: "allowed" | "blocked", reason: string, transmitted: boolean): BrowserNetworkRequest {
  return {
    url: redactSensitiveUrl(request.url()),
    method: request.method(),
    resourceType: request.resourceType(),
    decision,
    reason,
    transmitted
  };
}

function policyEvent(request: Request, pageUrl: string, reason: string, transmitted: boolean): BrowserPolicyEvent {
  return {
    url: redactSensitiveUrl(request.url()),
    method: request.method(),
    resourceType: request.resourceType(),
    pageUrl: redactSensitiveUrl(pageUrl),
    reason,
    transmitted
  };
}

function addPolicyEvent(events: BrowserPolicyEvent[], policy: BrowserPolicy, event: BrowserPolicyEvent): void {
  if (events.length < policy.maxPolicyEvents) {
    events.push(event);
  }
}

function consoleError(message: ConsoleMessage): BrowserConsoleError {
  const location = message.location();

  return {
    type: message.type(),
    text: message.text(),
    ...(location.url ? { location: `${redactSensitiveUrl(location.url)}:${location.lineNumber}:${location.columnNumber}` } : {})
  };
}

function pageUrlForRequest(request: Request, fallbackUrl: string): string {
  try {
    const frameUrl = request.frame().url();
    return frameUrl && frameUrl !== "about:blank" ? frameUrl : fallbackUrl;
  } catch {
    return fallbackUrl;
  }
}

function routeIsDownloadLike(request: Request): boolean {
  try {
    return /\.(?:zip|tar|gz|tgz|7z|rar|pdf|docx?|xlsx?|pptx?|exe|dmg|pkg|iso|apk|bin)$/i.test(new URL(request.url()).pathname);
  } catch {
    return true;
  }
}

function resolveUrlForEvent(url: string, baseUrl: string): string {
  try {
    return normalizeUrl(url, baseUrl);
  } catch {
    return url;
  }
}

function redactSensitiveUrl(url: string): string {
  try {
    const parsed = new URL(url);
    for (const key of [...parsed.searchParams.keys()]) {
      parsed.searchParams.set(key, "<redacted>");
    }
    parsed.hash = "";
    parsed.username = "";
    parsed.password = "";
    return parsed.toString();
  } catch {
    return url.replace(/([?&][^=]*(?:token|secret|session|cookie|auth|password|pass|key|jwt)[^=]*=)[^&\s]+/gi, "$1<redacted>");
  }
}

function redactAllQueryValues(value: string): string {
  try {
    const url = new URL(value);
    for (const key of [...url.searchParams.keys()]) url.searchParams.set(key, "<redacted>");
    url.hash = "";
    url.username = "";
    url.password = "";
    return url.toString();
  } catch { return "about:invalid"; }
}

function assertSameOrigin(url: string, targetOrigin: string): void {
  const parsed = new URL(url);
  if (parsed.origin !== targetOrigin) throw new Error(`Authenticated browser workflow URL is outside the target origin: ${parsed.origin}.`);
}

function browserContinuationHeaders(request: Request, profile: AuthProfile | undefined, targetOrigin: string): Record<string, string> {
  const headers = { ...request.headers() };
  if (!profile || new URL(request.url()).origin === targetOrigin) return headers;
  const profileHeaderNames = new Set(Object.keys(profile.headers).map((name) => name.toLowerCase()));
  for (const name of Object.keys(headers)) if (profileHeaderNames.has(name.toLowerCase())) delete headers[name];
  return headers;
}

function browserNetworkOrigin(value: string): string {
  const url = new URL(value);
  if (url.protocol === "ws:") url.protocol = "http:";
  if (url.protocol === "wss:") url.protocol = "https:";
  return url.origin;
}
