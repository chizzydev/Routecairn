import { chromium, type Browser, type BrowserContext, type CDPSession } from "playwright";

export interface VirtualWebAuthnOptions {
  protocol?: "ctap2" | "u2f";
  transport?: "usb" | "nfc" | "ble" | "internal";
  hasResidentKey?: boolean;
  hasUserVerification?: boolean;
  isUserVerified?: boolean;
  automaticPresenceSimulation?: boolean;
}

/** Owns an isolated Chromium context and its CDP virtual authenticators. */
export class VirtualWebAuthnManager {
  private browser: Browser | undefined;
  private context: BrowserContext | undefined;
  private session: CDPSession | undefined;
  private readonly authenticators = new Map<string, string>();

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

  public async clear(id: string): Promise<void> { const authenticatorId = this.authenticators.get(id); if (authenticatorId) await (await this.ensureSession()).send("WebAuthn.clearCredentials", { authenticatorId }); }
  public async remove(id: string): Promise<void> { const authenticatorId = this.authenticators.get(id); if (!authenticatorId) return; await (await this.ensureSession()).send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }); this.authenticators.delete(id); }
  public async close(): Promise<void> { this.authenticators.clear(); await this.context?.close().catch(() => undefined); await this.browser?.close().catch(() => undefined); this.session = undefined; this.context = undefined; this.browser = undefined; }

  private async ensureSession(): Promise<CDPSession> {
    if (this.session) return this.session;
    this.browser = await chromium.launch({ headless: true });
    this.context = await this.browser.newContext({ acceptDownloads: false, serviceWorkers: "block" });
    const page = await this.context.newPage();
    this.session = await this.context.newCDPSession(page);
    await this.session.send("WebAuthn.enable", { enableUI: false });
    return this.session;
  }
}
