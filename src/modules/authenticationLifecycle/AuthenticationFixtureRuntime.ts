import type { AuthenticationFixturesPlan, LifecycleFixtureActionPlan } from "./AuthenticationLifecycleTypes.js";
import { generateTotp, LocalTestInboxHarness, MailHogTestInboxAdapter, MailpitTestInboxAdapter, OidcTestHarness, type TestInboxAdapter } from "./AuthenticationFixtures.js";
import { VirtualWebAuthnManager } from "../browserCrawler/VirtualWebAuthnManager.js";

export class AuthenticationFixtureRuntime {
  private readonly inboxes = new Map<string, TestInboxAdapter>();
  private readonly oidc = new Map<string, OidcTestHarness>();
  private webauthn: VirtualWebAuthnManager | undefined;

  public constructor(private readonly fixtures: AuthenticationFixturesPlan, private readonly signal?: AbortSignal, private readonly requestJson?: (url: string, signal?: AbortSignal) => Promise<unknown>) {}

  public async execute(action: LifecycleFixtureActionPlan, captures: Map<string, string>, secrets: Readonly<Record<string, string>>): Promise<string[]> {
    this.throwIfAborted();
    if (action.kind === "TOTP_GENERATE") {
      const profile = this.fixtures.totp.find((item) => item.id === action.profileId)!;
      const seed = action.seed?.source === "CAPTURE" ? captures.get(action.seed.ref) : action.seed?.source === "SECRET" ? secrets[action.seed.ref] : profile.secretRef ? secrets[profile.secretRef] : undefined;
      if (!seed) throw new Error("TOTP_SEED_UNAVAILABLE");
      captures.set(action.capture, generateTotp({ secret: seed, encoding: profile.encoding, algorithm: profile.algorithm, digits: profile.digits, periodSeconds: profile.periodSeconds, epochSeconds: profile.epochSeconds }).code);
      return [action.capture];
    }
    if (action.kind === "INBOX_START") {
      const inbox = this.inbox(action.adapterId);
      if (!(inbox instanceof LocalTestInboxHarness)) throw new Error("TEST_INBOX_START_UNSUPPORTED");
      const started = await inbox.start();
      captures.set(action.captureEndpoint, started.endpoint);
      return [action.captureEndpoint];
    }
    if (action.kind === "INBOX_WAIT") {
      const after = action.afterCapture ? captures.get(action.afterCapture) : undefined;
      const message = await this.inbox(action.adapterId).waitForMessage({ channel: action.channel, recipient: this.secret(secrets, action.recipientSecretRef), ...(after ? { after } : {}) }, { timeoutMs: action.timeoutMs, ...(this.signal ? { signal: this.signal } : {}) });
      const value = extractInboxValue(message, action.value);
      if (!value) throw new Error(`TEST_INBOX_${action.value}_MISSING`);
      captures.set(action.capture, value);
      return [action.capture];
    }
    if (action.kind === "INBOX_CLEAR") {
      const inbox = this.inbox(action.adapterId); if (!inbox.clear) throw new Error("TEST_INBOX_CLEAR_UNSUPPORTED");
      await inbox.clear({ channel: action.channel, recipient: this.secret(secrets, action.recipientSecretRef) });
      return [];
    }
    if (action.kind === "WEBAUTHN_CREATE") {
      const definition = this.fixtures.webauthn.find((item) => item.id === action.authenticatorId)!;
      await this.webAuthn().create(action.authenticatorId, definition);
      return [];
    }
    if (action.kind === "WEBAUTHN_ADD_CREDENTIAL") {
      await this.webAuthn().addCredential(action.authenticatorId, { credentialId: this.secret(secrets, action.credentialIdSecretRef), privateKey: this.secret(secrets, action.privateKeySecretRef), rpId: action.rpId, ...(action.userHandleSecretRef ? { userHandle: this.secret(secrets, action.userHandleSecretRef) } : {}), signCount: action.signCount });
      return [];
    }
    if (action.kind === "WEBAUTHN_CLEAR") { await this.webAuthn().clear(action.authenticatorId); return []; }
    if (action.kind === "WEBAUTHN_REMOVE") { await this.webAuthn().remove(action.authenticatorId); return []; }
    if (action.kind === "OIDC_START") {
      const harness = this.oidcHarness(action.harnessId, secrets);
      const started = await harness.start();
      const names = [action.captureIssuer]; captures.set(action.captureIssuer, started.issuer);
      if (action.captureAuthorizationEndpoint) { captures.set(action.captureAuthorizationEndpoint, started.authorizationEndpoint); names.push(action.captureAuthorizationEndpoint); }
      if (action.captureTokenEndpoint) { captures.set(action.captureTokenEndpoint, started.tokenEndpoint); names.push(action.captureTokenEndpoint); }
      if (action.captureCallbackEndpoint) { captures.set(action.captureCallbackEndpoint, started.callbackEndpoint); names.push(action.captureCallbackEndpoint); }
      return names;
    }
    const callback = await this.oidcHarness(action.harnessId, secrets).waitForCallback({ timeoutMs: action.timeoutMs, ...(this.signal ? { signal: this.signal } : {}) });
    const value = callback[action.parameter];
    if (!value) throw new Error("OIDC_CALLBACK_PARAMETER_MISSING");
    captures.set(action.capture, value);
    return [action.capture];
  }

  public async close(): Promise<void> {
    await Promise.all([...this.inboxes.values()].map((inbox) => inbox instanceof LocalTestInboxHarness ? inbox.close().catch(() => undefined) : Promise.resolve()));
    await Promise.all([...this.oidc.values()].map((harness) => harness.close().catch(() => undefined)));
    await this.webauthn?.close().catch(() => undefined);
    this.inboxes.clear(); this.oidc.clear(); this.webauthn = undefined;
  }

  private inbox(id: string): TestInboxAdapter {
    let inbox = this.inboxes.get(id);
    if (!inbox) {
      const fixture = this.fixtures.inboxes.find((item) => item.id === id)!;
      inbox = fixture.kind === "LOCAL_HTTP" ? new LocalTestInboxHarness() : fixture.kind === "MAILPIT" ? new MailpitTestInboxAdapter(fixture.baseUrl, this.requestJson) : new MailHogTestInboxAdapter(fixture.baseUrl, this.requestJson);
      this.inboxes.set(id, inbox);
    }
    return inbox;
  }

  private webAuthn(): VirtualWebAuthnManager { this.webauthn ??= new VirtualWebAuthnManager(); return this.webauthn; }

  private oidcHarness(id: string, secrets: Readonly<Record<string, string>>): OidcTestHarness {
    let harness = this.oidc.get(id);
    if (harness) return harness;
    const fixture = this.fixtures.oidc.find((item) => item.id === id)!;
    harness = new OidcTestHarness({ clientId: this.secret(secrets, fixture.clientIdSecretRef), ...(fixture.clientSecretRef ? { clientSecret: this.secret(secrets, fixture.clientSecretRef) } : {}), redirectUris: [...fixture.redirectUris], subject: this.secret(secrets, fixture.subjectSecretRef), port: fixture.port, accessTokenLifetimeSeconds: fixture.accessTokenLifetimeSeconds });
    this.oidc.set(id, harness);
    return harness;
  }

  private secret(secrets: Readonly<Record<string, string>>, name: string): string { const value = secrets[name]; if (value === undefined) throw new Error("FIXTURE_SECRET_UNAVAILABLE"); return value; }
  private throwIfAborted(): void { if (this.signal?.aborted) throw new Error("FIXTURE_ABORTED"); }
}

function extractInboxValue(message: Awaited<ReturnType<LocalTestInboxHarness["waitForMessage"]>>, value: "TEXT" | "HTML" | "SUBJECT" | "CODE" | "LINK"): string | undefined {
  if (value === "TEXT") return message.text;
  if (value === "HTML") return message.html;
  if (value === "SUBJECT") return message.subject;
  const source = `${message.text}\n${message.html ?? ""}`;
  if (value === "CODE") return source.match(/(?:^|\D)(\d{4,10})(?:\D|$)/)?.[1];
  return source.match(/https?:\/\/[^\s<>"']{1,2048}/i)?.[0];
}
