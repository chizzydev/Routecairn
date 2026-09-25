import { chromium, type Browser, type BrowserContext, type CDPSession, type Page } from "playwright";

export interface VirtualWebAuthnOptions {
  protocol?: "ctap2" | "u2f";
  transport?: "usb" | "nfc" | "ble" | "internal";
  hasResidentKey?: boolean;
  hasUserVerification?: boolean;
  isUserVerified?: boolean;
  automaticPresenceSimulation?: boolean;
}

export type VirtualWebAuthnBrowserStep =
  | { action: "fill"; selector: string; value: string }
  | { action: "click"; selector: string }
  | { action: "check"; selector: string }
  | { action: "uncheck"; selector: string }
  | { action: "press"; selector: string; key: string }
  | { action: "selectOption"; selector: string; value: string }
  | { action: "waitForTimeout"; milliseconds: number }
  | { action: "waitForUrl"; urlPrefix: string }
  | { action: "assertVisible"; selector: string }
  | { action: "assertHidden"; selector: string }
  | { action: "assertText"; selector: string; text: string };

/** Owns an isolated Chromium context and its CDP virtual authenticators. */
export class VirtualWebAuthnManager {
  private browser: Browser | undefined;
  private context: BrowserContext | undefined;
  private session: CDPSession | undefined;
  private page: Page | undefined;
  private lastPageError: string | undefined;
  private readonly authenticators = new Map<string, string>();
  private readonly browserAllowedOrigins = new Set<string>();

  public async create(id: string, options: VirtualWebAuthnOptions = {}): Promise<void> {
    if (this.authenticators.has(id)) throw new Error("WEBAUTHN_AUTHENTICATOR_EXISTS");
    const session = await this.ensureSession();
    const result = await session.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: options.protocol ?? "ctap2", transport: options.transport ?? "internal", hasResidentKey: options.hasResidentKey ?? true, hasUserVerification: options.hasUserVerification ?? true, isUserVerified: options.isUserVerified ?? true, automaticPresenceSimulation: options.automaticPresenceSimulation ?? true } });
    this.authenticators.set(id, result.authenticatorId);
  }

  public async addCredential(id: string, credential: { credentialId: string; privateKey: string; rpId: string; userHandle?: string; signCount?: number; isResidentCredential?: boolean }): Promise<void> {
    const authenticatorId = this.authenticators.get(id);
    if (!authenticatorId) throw new Error("WEBAUTHN_AUTHENTICATOR_MISSING");
    await (await this.ensureSession()).send("WebAuthn.addCredential", { authenticatorId, credential: { credentialId: credential.credentialId, isResidentCredential: credential.isResidentCredential ?? true, rpId: credential.rpId, privateKey: credential.privateKey, signCount: credential.signCount ?? 0, ...(credential.userHandle ? { userHandle: credential.userHandle } : {}) } });
  }

  public async credentials(id: string): Promise<Array<{ credentialId: string; rpId?: string; signCount: number }>> {
    const authenticatorId = this.authenticators.get(id);
    if (!authenticatorId) throw new Error("WEBAUTHN_AUTHENTICATOR_MISSING");
    const result = await (await this.ensureSession()).send("WebAuthn.getCredentials", { authenticatorId });
    return result.credentials.map((credential) => ({ credentialId: credential.credentialId, ...(credential.rpId ? { rpId: credential.rpId } : {}), signCount: credential.signCount }));
  }

  /** Runs a complete browser ceremony on an explicit set of HTTPS or loopback origins.
   * Cross-origin browser traffic outside that set is aborted before transmission. */
  public async runBrowserFlow(input: { startUrl: string; steps: readonly VirtualWebAuthnBrowserStep[]; timeoutMs?: number; clearCookies?: boolean; allowedOrigins?: readonly string[] }): Promise<{ finalUrl: string }> {
    const start = safeBrowserOrigin(input.startUrl);
    const page = await this.ensurePage();
    this.browserAllowedOrigins.clear();
    this.browserAllowedOrigins.add(start.origin);
    for (const value of input.allowedOrigins ?? []) this.browserAllowedOrigins.add(safeBrowserOrigin(value).origin);
    if (input.clearCookies) await this.context!.clearCookies();
    const timeout = Math.min(Math.max(input.timeoutMs ?? 15_000, 100), 120_000);
    this.lastPageError = undefined;
    try {
      await page.goto(start.toString(), { waitUntil: "domcontentloaded", timeout });
      for (const step of input.steps) {
        if (step.action === "fill") await page.locator(validSelector(step.selector)).fill(step.value, { timeout });
        else if (step.action === "click") await page.locator(validSelector(step.selector)).click({ timeout });
        else if (step.action === "check") await page.locator(validSelector(step.selector)).check({ timeout });
        else if (step.action === "uncheck") await page.locator(validSelector(step.selector)).uncheck({ timeout });
        else if (step.action === "press") await page.locator(validSelector(step.selector)).press(validKey(step.key), { timeout });
        else if (step.action === "selectOption") await page.locator(validSelector(step.selector)).selectOption(step.value, { timeout });
        else if (step.action === "waitForTimeout") await page.waitForTimeout(Math.min(Math.max(step.milliseconds, 0), 5_000));
        else if (step.action === "waitForUrl") {
          const expected = safeBrowserOrigin(step.urlPrefix);
          if (!this.browserAllowedOrigins.has(expected.origin)) throw new Error("WEBAUTHN_BROWSER_CROSS_ORIGIN_BLOCKED");
          await page.waitForURL((url) => url.toString().startsWith(expected.toString()), { timeout });
        } else if (step.action === "assertVisible") await page.locator(validSelector(step.selector)).waitFor({ state: "visible", timeout });
        else if (step.action === "assertHidden") await page.locator(validSelector(step.selector)).waitFor({ state: "hidden", timeout });
        else await page.locator(validSelector(step.selector)).filter({ hasText: step.text }).waitFor({ state: "visible", timeout });
      }
    } catch (error) {
      if (this.lastPageError) throw new Error(`WEBAUTHN_BROWSER_PAGE_ERROR:${this.lastPageError}`);
      throw error;
    }
    return { finalUrl: page.url() };
  }

  public async clear(id: string): Promise<void> { const authenticatorId = this.authenticators.get(id); if (authenticatorId) await (await this.ensureSession()).send("WebAuthn.clearCredentials", { authenticatorId }); }
  public async remove(id: string): Promise<void> { const authenticatorId = this.authenticators.get(id); if (!authenticatorId) return; await (await this.ensureSession()).send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }); this.authenticators.delete(id); }
  public async close(): Promise<void> { this.authenticators.clear(); this.browserAllowedOrigins.clear(); await this.context?.close().catch(() => undefined); await this.browser?.close().catch(() => undefined); this.session = undefined; this.page = undefined; this.context = undefined; this.browser = undefined; }

  private async ensureSession(): Promise<CDPSession> {
    if (this.session) return this.session;
    this.browser = await chromium.launch({ headless: true });
    this.context = await this.browser.newContext({ acceptDownloads: false, serviceWorkers: "block" });
    this.page = await this.context.newPage();
    this.page.on("pageerror", (error) => { this.lastPageError = error.message.slice(0, 500); });
    await this.page.route("**/*", async (route) => {
      const requestUrl = route.request().url();
      try {
        const url = new URL(requestUrl);
        if (!["http:", "https:"].includes(url.protocol) || !this.browserAllowedOrigins.has(url.origin)) return route.abort("blockedbyclient");
      } catch { return route.abort("blockedbyclient"); }
      return route.continue();
    });
    this.session = await this.context.newCDPSession(this.page);
    await this.session.send("WebAuthn.enable", { enableUI: false });
    return this.session;
  }

  private async ensurePage(): Promise<Page> { await this.ensureSession(); return this.page!; }
}

function safeBrowserOrigin(value: string): URL {
  const url = new URL(value);
  if (url.username || url.password || url.hash || (url.protocol !== "https:" && !(url.protocol === "http:" && ["127.0.0.1", "localhost", "::1", "[::1]"].includes(url.hostname)))) throw new Error("WEBAUTHN_BROWSER_URL_INVALID");
  return url;
}

function validSelector(value: string): string { if (!value || value.length > 500 || /[\r\n\0]/.test(value)) throw new Error("WEBAUTHN_BROWSER_SELECTOR_INVALID"); return value; }
function validKey(value: string): string { if (!value || value.length > 50 || /[\r\n\0]/.test(value)) throw new Error("WEBAUTHN_BROWSER_KEY_INVALID"); return value; }
