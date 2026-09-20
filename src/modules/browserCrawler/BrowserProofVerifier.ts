import { chromium } from "playwright";
import type { AuthProfile } from "../../core/auth/AuthProfile.js";
import type { RequestSafetyBroker } from "../../core/http/RequestSafetyBroker.js";
import type { ControlledMutationBrowserObserver, ControlledMutationContract } from "../../core/offensive/ControlledMutationTypes.js";
import type { BrowserPolicy } from "./BrowserPolicy.js";
import { BrowserPolicyEngine } from "./BrowserPolicy.js";
import { applyBrowserCredentials, browserExtraHeaders, executeLogin, isExplicitLoginWriteAllowed, isWriteMethod, type BrowserLoginWriteGate } from "./BrowserLearning.js";

export class BrowserProofVerifier implements ControlledMutationBrowserObserver {
  public constructor(private readonly options: { authProfile: AuthProfile; policy: BrowserPolicy; requestBroker: RequestSafetyBroker; cleanupRequestBroker?: RequestSafetyBroker; abortSignal?: AbortSignal; cleanupSignal?: () => AbortSignal; targetUrl: string; timeoutMs: number; userAgent: string }) {}

  public verifyProtectedAction(contract: ControlledMutationContract) {
    return this.verify(contract, "protectedAction");
  }

  public verifyRollback(contract: ControlledMutationContract) {
    return this.verify(contract, "rollback");
  }

  private async verify(contract: ControlledMutationContract, phase: "protectedAction" | "rollback", restartAttempt = 0): Promise<{ configured: boolean; matched: boolean; notes: string[] }> {
    const proof = this.options.authProfile.browserBootstrap?.proofCases.find((item) => item.caseId === contract.caseId);
    if (!proof) return { configured: false, matched: true, notes: [] };
    const assertion = proof[phase];
    if (new URL(assertion.url).origin !== contract.targetOrigin || contract.targetOrigin !== new URL(this.options.targetUrl).origin) {
      return { configured: true, matched: false, notes: [`Browser ${phase} proof was blocked because its origin did not match the approved mutation contract.`] };
    }
    const requestBroker = phase === "rollback" ? this.options.cleanupRequestBroker ?? this.options.requestBroker : this.options.requestBroker;
    const signal = phase === "rollback" ? this.options.cleanupSignal?.() : this.options.abortSignal;
    if (signal?.aborted) return { configured: true, matched: false, notes: ["Browser proof deadline or cancellation reached."] };
    const browser = await chromium.launch({ headless: true, timeout: this.options.timeoutMs });
    const closeOnAbort = () => { void browser.close().catch(() => undefined); };
    signal?.addEventListener("abort", closeOnAbort, { once: true });
    if (signal?.aborted) closeOnAbort();
    const gate: BrowserLoginWriteGate = { active: false, allowedPaths: new Set(this.options.authProfile.browserBootstrap?.login?.allowedWritePaths ?? []), allowed: 0, blocked: 0 };
    try {
      const context = await browser.newContext({
        userAgent: this.options.userAgent,
        ignoreHTTPSErrors: true,
        acceptDownloads: false,
        serviceWorkers: "block",
        ...(Object.keys(browserExtraHeaders(this.options.authProfile)).length > 0 ? { extraHTTPHeaders: browserExtraHeaders(this.options.authProfile) } : {})
      });
      await applyBrowserCredentials(context, this.options.authProfile, this.options.targetUrl);
      const policy = new BrowserPolicyEngine(this.options.targetUrl, this.options.policy);
      await context.route("**/*", async (route) => {
        const request = route.request();
        const pageUrl = safePageUrl(request, this.options.targetUrl);
        const write = isWriteMethod(request.method());
        const explicitLogin = write && isExplicitLoginWriteAllowed(request.url(), gate);
        if (write && !explicitLogin) {
          gate.blocked += 1;
          requestBroker.recordBrowserPolicyBlock({ url: request.url(), method: request.method(), resourceType: request.resourceType(), pageUrl }, "browser-proof-is-read-only");
          await route.abort("blockedbyclient").catch(() => undefined);
          return;
        }
        const policyDecision = await policy.evaluateRequest({ url: request.url(), pageUrl, resourceType: request.resourceType(), requestsSeenForPage: 1 });
        if (!policyDecision.allowed) {
          requestBroker.recordBrowserPolicyBlock({ url: request.url(), method: request.method(), resourceType: request.resourceType(), pageUrl }, policyDecision.reason);
          await route.abort("blockedbyclient").catch(() => undefined);
          return;
        }
        const brokerInput = { url: policyDecision.normalizedUrl, method: request.method(), resourceType: request.resourceType(), pageUrl, isRedirect: request.redirectedFrom() !== null };
        const decision = explicitLogin ? requestBroker.evaluateBrowserLoginRequest(brokerInput) : requestBroker.evaluateBrowserRequest(brokerInput);
        if (!decision.allowed) { await route.abort("blockedbyclient").catch(() => undefined); return; }
        if (explicitLogin) gate.allowed += 1;
        await requestBroker.dispatchApprovedBrowserRequest(
          () => route.continue({ headers: proofContinuationHeaders(request.headers(), request.url(), this.options.authProfile, contract.targetOrigin) })
        );
      });
      const page = await context.newPage();
      page.setDefaultTimeout(this.options.timeoutMs);
      page.setDefaultNavigationTimeout(this.options.timeoutMs);
      await executeLogin(page, this.options.authProfile, gate, (url) => assertOrigin(url, contract.targetOrigin));
      // Network idleness is unrelated to application readiness (polling and blocked
      // learned writes can keep it busy indefinitely). Bind proof to an explicit
      // authenticated DOM readiness marker and a successful document response.
      const document = await page.goto(assertion.url, { waitUntil: "domcontentloaded", timeout: this.options.timeoutMs });
      const principalSelector = this.options.authProfile.browserBootstrap?.identitySelectors?.principal;
      const readiness = assertion.readySelector ?? principalSelector;
      if (!document?.ok() || !readiness || !principalSelector || !this.options.authProfile.principalId) return { configured: true, matched: false, notes: [`Browser ${phase} proof requires a successful document, readiness marker and verified principal selector.`] };
      await page.locator(readiness).first().waitFor({ state: "visible" });
      if ((await page.locator(principalSelector).first().textContent())?.trim() !== this.options.authProfile.principalId) return { configured: true, matched: false, notes: [`Browser ${phase} proof principal did not match the approved actor.`] };
      const locator = page.locator(assertion.selector).first();
      await locator.waitFor({ state: assertion.expected === "visible" ? "visible" : "hidden" });
      const count = await locator.count();
      const visible = count > 0 && await locator.isVisible();
      const matched = assertion.expected === "visible" ? visible : count === 0 || !visible;
      await context.close();
      return { configured: true, matched, notes: [`Browser ${phase} proof ${matched ? "matched" : "did not match"} the approved selector-state assertion in a fresh isolated session.`] };
    } catch (error) {
      if (restartAttempt === 0 && !signal?.aborted) {
        await browser.close().catch(() => undefined);
        const retried = await this.verify(contract, phase, 1);
        return { ...retried, notes: [`Browser ${phase} proof restarted one isolated Chromium session after an infrastructure failure.`, ...retried.notes] };
      }
      return { configured: true, matched: false, notes: [`Browser ${phase} proof failed safely: ${safeError(error)}`] };
    } finally {
      signal?.removeEventListener("abort", closeOnAbort);
      await browser.close();
    }
  }
}

/** Executes returned markup in an offline, credential-free browser context.
 * This stays in the hardened browser layer so active validation cannot create
 * an unsupervised Playwright session. */
export async function verifyOfflineXssExecution(html: string, nonce: string, timeoutMs: number): Promise<"EXECUTED" | "NOT_EXECUTED" | "UNAVAILABLE"> {
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  try {
    browser = await chromium.launch({ headless: true, timeout: Math.min(timeoutMs, 15_000) });
    const context = await browser.newContext({ offline: true, serviceWorkers: "block", javaScriptEnabled: true, acceptDownloads: false });
    await context.route("**/*", (route) => route.abort("blockedbyclient"));
    const page = await context.newPage();
    await page.setContent(html, { waitUntil: "domcontentloaded", timeout: Math.min(timeoutMs, 10_000) });
    const observed = await page.evaluate(() => (globalThis as typeof globalThis & { __routeCairnActiveProof?: string }).__routeCairnActiveProof);
    await context.close();
    return observed === nonce ? "EXECUTED" : "NOT_EXECUTED";
  } catch { return "UNAVAILABLE"; }
  finally { await browser?.close().catch(() => undefined); }
}

function assertOrigin(url: string, origin: string): void { if (new URL(url).origin !== origin) throw new Error("Browser proof bootstrap left the approved origin."); }
function safePageUrl(request: import("playwright").Request, fallback: string): string { try { return request.frame().url() || fallback; } catch { return fallback; } }
function safeError(error: unknown): string { return error instanceof Error ? error.message.replace(/([?&][^=]+=)[^&\s]+/g, "$1<redacted>").slice(0, 300) : "unknown browser error"; }
function proofContinuationHeaders(headers: Record<string, string>, url: string, profile: AuthProfile, targetOrigin: string): Record<string, string> {
  const copy = { ...headers };
  if (new URL(url).origin === targetOrigin) return copy;
  const profileNames = new Set(Object.keys(profile.headers).map((name) => name.toLowerCase()));
  for (const name of Object.keys(copy)) if (profileNames.has(name.toLowerCase())) delete copy[name];
  return copy;
}
