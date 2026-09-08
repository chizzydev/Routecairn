import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { clamp, nowIso } from "../db/DashboardDatabase.js";
import { TargetRepository, type TargetSummary } from "../db/DashboardRepositories.js";
import type { CredentialVault, CredentialVaultKey } from "../credentials/CredentialVault.js";
import { credentialVaultAlgorithm } from "../credentials/CredentialVault.js";
import type { ScanExecutionService } from "./ScanExecutionService.js";
import { providerAdapterBindingSchema, providerAdapterInputSchema, type ProviderAdapterBinding, type ProviderAdapterInput } from "../contracts/ProviderAdapterSchemas.js";
import { advancedEngineCatalog, validateAdvancedEngineInput, type AdvancedEngineId } from "../contracts/AdvancedEngineSchemas.js";
import { dashboardScanCreateSchema } from "../contracts/DashboardSchemas.js";
import type { DashboardScanCreateRequest, PlanPreviewResponse } from "../types/DashboardTypes.js";
import { scopeSchema } from "../../config/ConfigSchema.js";

const maximumEncryptedBytes = 2 * 1024 * 1024;
const engineCapability: Record<AdvancedEngineId, string> = {
  "supabase-authorization": "DATA_AUTHORIZATION",
  "authentication-lifecycle": "AUTHENTICATION_LIFECYCLE",
  "authentication-lifecycle-automation": "AUTHENTICATION_LIFECYCLE",
  "business-invariant": "BUSINESS_INVARIANT",
  "controlled-race": "CONTROLLED_RACE",
  "api-graphql-authorization": "API_GRAPHQL_AUTHORIZATION",
  "link-portal-export-security": "CAPABILITY_LINKS",
  "operational-endpoint-security": "OPERATIONAL_ENDPOINTS",
  "billing-entitlement-security": "SYNTHETIC_BILLING",
  "assisted-review": "ASSISTED_REVIEW",
  "pre-handover-assault": "PRE_HANDOVER",
  "bug-bounty-authorization": "BUG_BOUNTY_SCOPE"
};

export interface ProviderAdapterPreview {
  adapterDigest: string;
  target: { id: string; origin: string; rowVersion: number };
  credentialBindings: Array<{ role: string; profileId: string; safeAlias: string; secretVersion: number; health: string }>;
  engine: { id: AdvancedEngineId; moduleId?: string; capability: string; provider: string };
  plan?: PlanPreviewResponse;
  blockers: string[];
  warnings: string[];
}

export class ProviderAdapterService {
  private readonly targets: TargetRepository;
  public constructor(private readonly database: DashboardDatabase, private readonly execution: ScanExecutionService, private readonly vault: CredentialVault, private readonly key?: CredentialVaultKey) { this.targets = new TargetRepository(database); }

  public available(): boolean { return Boolean(this.key); }

  public async preview(value: unknown): Promise<ProviderAdapterPreview> {
    const input = providerAdapterInputSchema.parse(value);
    const target = this.targets.get(input.targetId);
    if (!target) throw new Error("PROVIDER_ADAPTER_TARGET_NOT_FOUND");
    const blockers: string[] = [];
    const warnings: string[] = [];
    const validation = validateAdvancedEngineInput(input.engineId, input.engineConfiguration);
    if (!validation.valid) blockers.push(...validation.diagnostics.map((item) => `${item.path.join(".") || "engineConfiguration"}: ${item.message}`));
    const requiredCapability = engineCapability[input.engineId];
    if (!input.capabilities.includes(requiredCapability as never)) blockers.push(`Engine ${input.engineId} requires capability ${requiredCapability}.`);
    this.validateProvider(input, blockers);
    this.validateEnvironment(input, target, blockers);
    this.validateOrigins(input.engineConfiguration, target, blockers);
    this.validateFixturePaths(input, blockers);
    this.validateRecommendation(input, blockers);
    const credentialBindings = this.credentials(input, target, blockers, warnings);
    const adapterDigest = digest({ input, target: { id: target.id, origin: target.baseOrigin, rowVersion: target.rowVersion }, credentials: credentialBindings.map(({ role, profileId, secretVersion }) => ({ role, profileId, secretVersion })) });
    let plan: PlanPreviewResponse | undefined;
    if (blockers.length === 0 && validation.valid) {
      try { plan = await this.execution.preview(this.request(input, target, validation.value, { profileId: "00000000-0000-0000-0000-000000000000", versionId: "00000000-0000-0000-0000-000000000000", adapterDigest })); }
      catch (error) { blockers.push(safeError(error)); }
    }
    const moduleId = advancedEngineCatalog.find((item) => item.id === input.engineId)?.moduleId;
    return { adapterDigest, target: { id: target.id, origin: target.baseOrigin, rowVersion: target.rowVersion }, credentialBindings, engine: { id: input.engineId, ...(moduleId ? { moduleId } : {}), capability: requiredCapability, provider: input.provider }, ...(plan ? { plan } : {}), blockers, warnings };
  }

  public async create(value: unknown, actor: string): Promise<Record<string, unknown>> {
    this.requireKey();
    const input = providerAdapterInputSchema.parse(value);
    const preview = await this.preview(input);
    if (preview.blockers.length) throw new Error(`PROVIDER_ADAPTER_INVALID: ${preview.blockers.join(" ")}`);
    const profileId = randomUUID(); const versionId = randomUUID(); const now = nowIso(); const encrypted = this.encrypt(profileId, versionId, input);
    this.database.transaction(() => {
      this.database.db.prepare(`INSERT INTO provider_adapters (id,name,description,target_id,provider,engine_id,enabled,pending_version_id,created_by,created_at,updated_at) VALUES (?,?,?,?,?,?,1,?,?,?,?)`).run(profileId, input.name, input.description || null, input.targetId, input.provider, input.engineId, versionId, actor, now, now);
      this.insertVersion(profileId, versionId, 1, preview, encrypted, actor, now);
    });
    return this.get(profileId);
  }

  public async update(profileId: string, value: unknown, actor: string): Promise<Record<string, unknown>> {
    this.requireKey();
    const profile = this.profile(profileId);
    const input = providerAdapterInputSchema.parse(value);
    if (input.targetId !== profile.target_id) throw new Error("PROVIDER_ADAPTER_TARGET_IMMUTABLE");
    const preview = await this.preview(input);
    if (preview.blockers.length) throw new Error(`PROVIDER_ADAPTER_INVALID: ${preview.blockers.join(" ")}`);
    const latest = this.database.db.prepare("SELECT COALESCE(MAX(revision),0) AS revision FROM provider_adapter_versions WHERE profile_id=?").get(profileId) as { revision: number };
    const versionId = randomUUID(); const now = nowIso(); const encrypted = this.encrypt(profileId, versionId, input);
    this.database.transaction(() => {
      this.database.db.prepare("UPDATE provider_adapter_versions SET status='SUPERSEDED' WHERE profile_id=? AND status='DRAFT'").run(profileId);
      this.insertVersion(profileId, versionId, latest.revision + 1, preview, encrypted, actor, now);
      this.database.db.prepare("UPDATE provider_adapters SET name=?,description=?,provider=?,engine_id=?,pending_version_id=?,updated_at=?,row_version=row_version+1 WHERE id=?").run(input.name, input.description || null, input.provider, input.engineId, versionId, now, profileId);
    });
    return this.get(profileId);
  }

  public async review(profileId: string, versionId: string, adapterDigest: string, actor: string): Promise<Record<string, unknown>> {
    const row = this.version(profileId, versionId); if (row.status !== "DRAFT") throw new Error("PROVIDER_ADAPTER_DRAFT_REQUIRED");
    const input = this.decrypt(row); const preview = await this.preview(input);
    if (preview.blockers.length) throw new Error(`PROVIDER_ADAPTER_REVIEW_BLOCKED: ${preview.blockers.join(" ")}`);
    if (adapterDigest !== row.adapter_digest || adapterDigest !== preview.adapterDigest) throw new Error("PROVIDER_ADAPTER_BINDING_CHANGED");
    this.database.transaction(() => {
      this.database.db.prepare("UPDATE provider_adapter_versions SET status='SUPERSEDED' WHERE profile_id=? AND status='REVIEWED'").run(profileId);
      const changed = this.database.db.prepare("UPDATE provider_adapter_versions SET status='REVIEWED',reviewed_by=?,reviewed_at=? WHERE id=? AND profile_id=? AND status='DRAFT'").run(actor, nowIso(), versionId, profileId);
      if (changed.changes !== 1) throw new Error("PROVIDER_ADAPTER_REVIEW_CONFLICT");
      this.database.db.prepare("UPDATE provider_adapters SET active_version_id=?,pending_version_id=NULL,updated_at=?,row_version=row_version+1 WHERE id=?").run(versionId, nowIso(), profileId);
    });
    if (input.recommendationId) this.bindRecommendation(profileId, input.recommendationId, actor);
    return this.get(profileId);
  }

  public list(targetId?: string): Record<string, unknown>[] {
    const rows = (targetId ? this.database.db.prepare("SELECT * FROM provider_adapters WHERE target_id=? AND deleted_at IS NULL ORDER BY updated_at DESC").all(targetId) : this.database.db.prepare("SELECT * FROM provider_adapters WHERE deleted_at IS NULL ORDER BY updated_at DESC LIMIT 200").all()) as ProfileRow[];
    return rows.map((row) => this.summary(row));
  }

  public get(id: string): Record<string, unknown> {
    const profile = this.profile(id);
    const versions = this.database.db.prepare("SELECT * FROM provider_adapter_versions WHERE profile_id=? ORDER BY revision DESC").all(id) as VersionRow[];
    return { ...this.summary(profile), versions: versions.map(versionSummary), ...(profile.pending_version_id ? { pendingInput: this.decrypt(versions.find((item) => item.id === profile.pending_version_id)!) } : {}), ...(profile.active_version_id ? { activeInput: this.decrypt(versions.find((item) => item.id === profile.active_version_id)!) } : {}) };
  }

  public materialize(id: string): { target: TargetSummary; input: ProviderAdapterInput; binding: ProviderAdapterBinding } {
    const profile = this.profile(id); if (!profile.enabled || !profile.active_version_id) throw new Error("PROVIDER_ADAPTER_REVIEWED_VERSION_REQUIRED");
    const version = this.version(id, profile.active_version_id); const input = this.decrypt(version); const target = this.targets.get(profile.target_id);
    if (!target) throw new Error("PROVIDER_ADAPTER_TARGET_NOT_FOUND");
    return { target, input, binding: { profileId: id, versionId: version.id, adapterDigest: version.adapter_digest } };
  }

  /** Materializes the exact reviewed adapter as the same request Scan Studio would submit. */
  public materializeScanRequest(id: string): DashboardScanCreateRequest {
    const materialized = this.materialize(id);
    const validation = validateAdvancedEngineInput(materialized.input.engineId, materialized.input.engineConfiguration);
    if (!validation.valid) throw new Error("PROVIDER_ADAPTER_ACTIVE_CONFIGURATION_INVALID");
    return this.request(materialized.input, materialized.target, validation.value, materialized.binding);
  }

  public async assertExecutionBinding(request: DashboardScanCreateRequest): Promise<void> {
    if (!request.providerAdapterBinding) return;
    const binding = providerAdapterBindingSchema.parse(request.providerAdapterBinding); const materialized = this.materialize(binding.profileId);
    if (binding.versionId !== materialized.binding.versionId || binding.adapterDigest !== materialized.binding.adapterDigest) throw new Error("PROVIDER_ADAPTER_EXECUTION_BINDING_MISMATCH");
    if (request.targetId !== materialized.target.id || new URL(request.target).origin !== materialized.target.baseOrigin) throw new Error("PROVIDER_ADAPTER_EXECUTION_TARGET_MISMATCH");
    const field = requestField(materialized.input.engineId); const configured = (request as unknown as Record<string, unknown>)[field];
    if (digest(configured) !== digest(validateAdvancedEngineInput(materialized.input.engineId, materialized.input.engineConfiguration).value)) throw new Error("PROVIDER_ADAPTER_EXECUTION_CONFIGURATION_MISMATCH");
    if (digest(request.studio?.authentication) !== digest(authentication(materialized.input.authentication))) throw new Error("PROVIDER_ADAPTER_EXECUTION_ACTOR_MISMATCH");
    const expected = this.request(materialized.input, materialized.target, validateAdvancedEngineInput(materialized.input.engineId, materialized.input.engineConfiguration).value, binding);
    if (digest(executionContract(request)) !== digest(executionContract(expected))) throw new Error("PROVIDER_ADAPTER_EXECUTION_CONTRACT_MISMATCH");
    const fresh = await this.preview(materialized.input); if (fresh.adapterDigest !== binding.adapterDigest || fresh.blockers.length) throw new Error("PROVIDER_ADAPTER_EXECUTION_STALE");
  }

  public bindScan(scanId: string, binding: ProviderAdapterBinding): void { this.database.db.prepare("INSERT INTO scan_provider_adapter_bindings (scan_id,profile_id,version_id,adapter_digest,created_at) VALUES (?,?,?,?,?)").run(scanId, binding.profileId, binding.versionId, binding.adapterDigest, nowIso()); }

  public bindRecommendation(profileId: string, recommendationId: string, actor: string): void {
    const profile = this.profile(profileId); if (!profile.active_version_id) throw new Error("PROVIDER_ADAPTER_REVIEWED_VERSION_REQUIRED");
    const recommendation = this.database.db.prepare("SELECT target_id,engine_id,status,source_fingerprint FROM adaptive_security_recommendations WHERE id=?").get(recommendationId) as { target_id: string; engine_id: string; status: string; source_fingerprint: string } | undefined;
    if (!recommendation || recommendation.status !== "APPROVED") throw new Error("PROVIDER_ADAPTER_APPROVED_RECOMMENDATION_REQUIRED");
    const activeInput = this.decrypt(this.version(profileId, profile.active_version_id));
    if (recommendation.target_id !== profile.target_id || recommendation.engine_id !== activeInput.engineId) throw new Error("PROVIDER_ADAPTER_RECOMMENDATION_MISMATCH");
    this.database.db.prepare(`INSERT INTO provider_adapter_recommendation_bindings (recommendation_id,profile_id,version_id,source_fingerprint,bound_by,bound_at) VALUES (?,?,?,?,?,?) ON CONFLICT(recommendation_id) DO UPDATE SET profile_id=excluded.profile_id,version_id=excluded.version_id,source_fingerprint=excluded.source_fingerprint,bound_by=excluded.bound_by,bound_at=excluded.bound_at`).run(recommendationId, profileId, profile.active_version_id, recommendation.source_fingerprint, actor, nowIso());
  }

  public impact(id: string): Record<string, unknown> {
    const recommendationBindings = (this.database.db.prepare("SELECT COUNT(*) AS count FROM provider_adapter_recommendation_bindings WHERE profile_id=?").get(id) as { count: number }).count;
    const scanBindings = (this.database.db.prepare("SELECT COUNT(*) AS count FROM scan_provider_adapter_bindings WHERE profile_id=?").get(id) as { count: number }).count;
    const activeScans = (this.database.db.prepare("SELECT COUNT(*) AS count FROM scan_provider_adapter_bindings b JOIN scans s ON s.id=b.scan_id WHERE b.profile_id=? AND s.status IN ('QUEUED','PLANNING','RUNNING','CANCEL_REQUESTED')").get(id) as { count: number }).count;
    const value = { recommendationBindings, scanBindings, activeScans }; return { ...value, canDisable: activeScans === 0, impactDigest: digest({ id, ...value }) };
  }

  public setEnabled(id: string, enabled: boolean, impactDigest: string): Record<string, unknown> { const impact = this.impact(id); if (impact.impactDigest !== impactDigest) throw new Error("PROVIDER_ADAPTER_IMPACT_CHANGED"); if (!enabled && !impact.canDisable) throw new Error("PROVIDER_ADAPTER_ACTIVE_SCAN_DEPENDENCY"); this.database.db.prepare("UPDATE provider_adapters SET enabled=?,updated_at=?,row_version=row_version+1 WHERE id=? AND deleted_at IS NULL").run(enabled ? 1 : 0, nowIso(), id); return this.get(id); }

  private request(input: ProviderAdapterInput, target: TargetSummary, configuration: unknown, binding: ProviderAdapterBinding): DashboardScanCreateRequest {
    const metadata = advancedEngineCatalog.find((item) => item.id === input.engineId)!; const modules = metadata.moduleId ? [metadata.moduleId] : [];
    return dashboardScanCreateSchema.parse({ target: target.baseOrigin, targetId: target.id, ...(target.projectId ? { projectId: target.projectId } : {}), profile: input.authentication.mode === "public" ? "full" : "authenticated", authorizationDeclaration: `Reviewed reusable provider adapter ${binding.adapterDigest.slice(0, 12)}`, rateLimitPerSecond: input.limits.rateLimitPerSecond, concurrency: input.limits.concurrency, maxRequests: input.limits.maxRequests, cleanupReservedRequests: input.limits.cleanupReservedRequests, includeModules: modules, providerAdapterBinding: binding, [requestField(input.engineId)]: configuration, studio: { version: 1, scanName: input.name, authorization: { category: target.authorizationType === "BUG_BOUNTY" ? "BUG_BOUNTY" : target.authorizationType === "CONTROLLED_LAB" ? "CONTROLLED_LAB" : "OWNED", confirmed: true, note: "Reviewed reusable fixture/provider adapter." }, scope: scopeSchema.parse(target.approvedScope), authentication: authentication(input.authentication), evidenceLevel: input.limits.evidenceLevel, outputs: { json: true, markdown: true, html: true }, moduleSettings: {}, workflows: [], workflowSummary: [] } });
  }

  private credentials(input: ProviderAdapterInput, target: TargetSummary, blockers: string[], warnings: string[]): ProviderAdapterPreview["credentialBindings"] {
    const refs = input.authentication.mode === "public" ? [] : input.authentication.mode === "primary" ? [["primary", input.authentication.credentialProfileId] as const] : [["account_a", input.authentication.accountAProfileId] as const, ["account_b", input.authentication.accountBProfileId] as const];
    return refs.flatMap(([role, id]) => { const profile = this.vault.getSummary(id); if (!profile) { blockers.push(`${role}: credential profile is unavailable.`); return []; } if (profile.targetId && profile.targetId !== target.id) blockers.push(`${role}: credential belongs to another target.`); if (["DISABLED","EXPIRED","INVALID","IDENTITY_MISMATCH"].includes(profile.health.classification)) blockers.push(`${role}: credential is ${profile.health.classification}.`); else if (profile.health.classification !== "HEALTHY") warnings.push(`${role}: credential is ${profile.health.classification}; scan readiness will verify it again.`); return [{ role, profileId: id, safeAlias: profile.safeAlias, secretVersion: profile.secretVersion, health: profile.health.classification }]; });
  }

  private validateProvider(input: ProviderAdapterInput, blockers: string[]): void { if (input.provider === "SUPABASE" && input.engineId !== "supabase-authorization") blockers.push("SUPABASE provider requires the Supabase authorization engine."); if (/_(?:TEST|SANDBOX)$/.test(input.provider) && input.engineId !== "billing-entitlement-security") blockers.push("Payment providers require the synthetic billing engine."); if (input.engineId === "billing-entitlement-security") { if (!["STRIPE_TEST","ADYEN_TEST","BRAINTREE_SANDBOX","PAYPAL_SANDBOX","PADDLE_SANDBOX","CUSTOM_SYNTHETIC"].includes(input.provider)) blockers.push("Synthetic billing requires an explicit test, sandbox, or custom-synthetic provider."); const configured = (input.engineConfiguration as { provider?: { kind?: unknown } } | null)?.provider?.kind; if (typeof configured === "string" && configured !== input.provider) blockers.push(`Adapter provider ${input.provider} does not match billing configuration provider ${configured}.`); } }
  private validateEnvironment(input: ProviderAdapterInput, target: TargetSummary, blockers: string[]): void { if (input.environment === "PRODUCTION" && target.classification !== "PRODUCTION") blockers.push("Production adapters require a production-classified target."); if (input.environment !== "PRODUCTION" && target.classification === "PRODUCTION") blockers.push("A production target requires an explicitly production-bound adapter."); }
  private validateOrigins(value: unknown, target: TargetSummary, blockers: string[]): void { for (const candidate of absoluteUrls(value)) { try { const url = new URL(candidate); if (url.username || url.password) blockers.push("Engine URLs cannot contain embedded credentials."); else if (url.origin !== target.baseOrigin) blockers.push(`Engine URL ${safeUrl(candidate)} is outside the registered target origin.`); } catch { blockers.push("Engine configuration contains a malformed absolute URL."); } } }
  private validateFixturePaths(input: ProviderAdapterInput, blockers: string[]): void { for (const path of executablePaths(input.engineConfiguration)) if (!input.fixture.allowedPathPrefixes.some((prefix) => path === prefix || path.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`))) blockers.push(`Engine request path ${path.slice(0,300)} is outside the adapter fixture path prefixes.`); if (configurationNeedsCleanup(input.engineConfiguration) && !input.fixture.cleanupRequired) blockers.push("State-changing engine configuration requires fixture cleanup and cleanup evidence."); }
  private validateRecommendation(input: ProviderAdapterInput, blockers: string[]): void { if (!input.recommendationId) return; const recommendation = this.database.db.prepare("SELECT target_id,engine_id,status FROM adaptive_security_recommendations WHERE id=?").get(input.recommendationId) as { target_id: string; engine_id: string; status: string } | undefined; if (!recommendation || recommendation.status !== "APPROVED") blockers.push("Adapter recommendation binding requires an approved 51C recommendation."); else if (recommendation.target_id !== input.targetId || recommendation.engine_id !== input.engineId) blockers.push("Adapter recommendation target or engine does not match the adapter."); }
  private insertVersion(profileId: string, versionId: string, revision: number, preview: ProviderAdapterPreview, encrypted: Encrypted, actor: string, now: string): void { this.database.db.prepare(`INSERT INTO provider_adapter_versions (id,profile_id,revision,status,adapter_digest,target_row_version,credential_binding_json,algorithm,key_version,nonce,ciphertext,auth_tag,created_by,created_at) VALUES (?,?,?,'DRAFT',?,?,?,?,?,?,?,?,?,?)`).run(versionId, profileId, revision, preview.adapterDigest, preview.target.rowVersion, JSON.stringify(preview.credentialBindings.map(({ role, profileId, secretVersion }) => ({ role, profileId, secretVersion }))), credentialVaultAlgorithm, this.key!.version, encrypted.nonce, encrypted.ciphertext, encrypted.authTag, actor, now); }
  private profile(id: string): ProfileRow { const row = this.database.db.prepare("SELECT * FROM provider_adapters WHERE id=? AND deleted_at IS NULL").get(id) as ProfileRow | undefined; if (!row) throw new Error("PROVIDER_ADAPTER_NOT_FOUND"); return row; }
  private version(profileId: string, id: string): VersionRow { const row = this.database.db.prepare("SELECT * FROM provider_adapter_versions WHERE id=? AND profile_id=?").get(id, profileId) as VersionRow | undefined; if (!row) throw new Error("PROVIDER_ADAPTER_VERSION_NOT_FOUND"); return row; }
  private summary(row: ProfileRow): Record<string, unknown> { return { id: row.id, name: row.name, description: row.description, targetId: row.target_id, provider: row.provider, engineId: row.engine_id, enabled: Boolean(row.enabled), activeVersionId: row.active_version_id, pendingVersionId: row.pending_version_id, rowVersion: row.row_version, createdAt: row.created_at, updatedAt: row.updated_at, impact: this.impact(row.id) }; }
  private encrypt(profileId: string, versionId: string, value: ProviderAdapterInput): Encrypted { this.requireKey(); const plaintext = Buffer.from(JSON.stringify(value)); if (plaintext.length > maximumEncryptedBytes) throw new Error("PROVIDER_ADAPTER_TOO_LARGE"); const nonce = randomBytes(12); const cipher = createCipheriv(credentialVaultAlgorithm, this.key!.bytes, nonce); cipher.setAAD(this.aad(profileId, versionId, this.key!.version)); const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]); return { nonce: nonce.toString("base64url"), ciphertext: ciphertext.toString("base64url"), authTag: cipher.getAuthTag().toString("base64url") }; }
  private decrypt(row: VersionRow): ProviderAdapterInput { this.requireKey(); if (row.algorithm !== credentialVaultAlgorithm || row.key_version !== this.key!.version) throw new Error("PROVIDER_ADAPTER_KEY_UNAVAILABLE"); const decipher = createDecipheriv(credentialVaultAlgorithm, this.key!.bytes, Buffer.from(row.nonce,"base64url")); decipher.setAAD(this.aad(row.profile_id,row.id,row.key_version)); decipher.setAuthTag(Buffer.from(row.auth_tag,"base64url")); const plaintext = Buffer.concat([decipher.update(Buffer.from(row.ciphertext,"base64url")),decipher.final()]); if (plaintext.length > maximumEncryptedBytes) throw new Error("PROVIDER_ADAPTER_TOO_LARGE"); return providerAdapterInputSchema.parse(JSON.parse(plaintext.toString("utf8"))); }
  private aad(profileId: string, versionId: string, keyVersion: string): Buffer { const installation = this.database.db.prepare("SELECT value FROM dashboard_meta WHERE key='installation_id'").get() as { value: string } | undefined; return Buffer.from(JSON.stringify({ purpose: "routecairn-provider-adapter", profileId, versionId, installationId: installation?.value ?? "unknown", keyVersion })); }
  private requireKey(): void { if (!this.key) throw new Error("PROVIDER_ADAPTER_VAULT_REQUIRED"); }
}

export function rotateProviderAdapterKey(database: DashboardDatabase, currentKey: CredentialVaultKey, nextKey: CredentialVaultKey): number {
  const installation = database.db.prepare("SELECT value FROM dashboard_meta WHERE key='installation_id'").get() as { value: string } | undefined;
  const rows = database.db.prepare("SELECT id,profile_id,key_version,nonce,ciphertext,auth_tag,algorithm FROM provider_adapter_versions ORDER BY id").all() as Array<Pick<VersionRow,"id"|"profile_id"|"key_version"|"nonce"|"ciphertext"|"auth_tag"|"algorithm">>;
  for (const row of rows) {
    if (row.algorithm !== credentialVaultAlgorithm || row.key_version !== currentKey.version) throw new Error(`Provider adapter version ${row.id} is not encrypted with the current key version.`);
    const aad = (version: string) => Buffer.from(JSON.stringify({ purpose: "routecairn-provider-adapter", profileId: row.profile_id, versionId: row.id, installationId: installation?.value ?? "unknown", keyVersion: version }));
    const decipher = createDecipheriv(credentialVaultAlgorithm,currentKey.bytes,Buffer.from(row.nonce,"base64url")); decipher.setAAD(aad(currentKey.version)); decipher.setAuthTag(Buffer.from(row.auth_tag,"base64url"));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(row.ciphertext,"base64url")),decipher.final()]); if (plaintext.length > maximumEncryptedBytes) throw new Error("PROVIDER_ADAPTER_TOO_LARGE"); providerAdapterInputSchema.parse(JSON.parse(plaintext.toString("utf8")));
    const nonce = randomBytes(12); const cipher = createCipheriv(credentialVaultAlgorithm,nextKey.bytes,nonce); cipher.setAAD(aad(nextKey.version)); const ciphertext = Buffer.concat([cipher.update(plaintext),cipher.final()]);
    database.db.prepare("UPDATE provider_adapter_versions SET key_version=?,nonce=?,ciphertext=?,auth_tag=? WHERE id=?").run(nextKey.version,nonce.toString("base64url"),ciphertext.toString("base64url"),cipher.getAuthTag().toString("base64url"),row.id);
  }
  return rows.length;
}

function requestField(id: AdvancedEngineId): string { return advancedEngineCatalog.find((item) => item.id === id)!.requestField; }
function authentication(value: ProviderAdapterInput["authentication"]): NonNullable<DashboardScanCreateRequest["studio"]>["authentication"] { return value.mode === "public" ? { mode: "public" } : value.mode === "primary" ? { mode: "primary", primary: { source: "saved", credentialProfileId: value.credentialProfileId } } : { mode: "account-pair", accountA: { source: "saved", credentialProfileId: value.accountAProfileId }, accountB: { source: "saved", credentialProfileId: value.accountBProfileId } }; }
function absoluteUrls(value: unknown): string[] { const output: string[] = []; const visit = (item: unknown): void => { if (typeof item === "string" && /^https?:\/\//i.test(item)) output.push(item); else if (Array.isArray(item)) item.forEach(visit); else if (item && typeof item === "object") Object.values(item as Record<string,unknown>).forEach(visit); }; visit(value); return output; }
function executablePaths(value: unknown): string[] { const output = new Set<string>(); const visit = (item: unknown): void => { if (Array.isArray(item)) { item.forEach(visit); return; } if (!item || typeof item !== "object") return; for (const [key,child] of Object.entries(item as Record<string,unknown>)) { if (typeof child === "string" && /^(?:url|pathTemplate|urlTemplate|endpoint)$/.test(key)) { try { output.add(child.startsWith("http") ? new URL(child).pathname : child.split("?")[0]!); } catch { /* URL validation reports malformed values separately */ } } else visit(child); } }; visit(value); return [...output].filter((path) => path.startsWith("/")); }
function configurationNeedsCleanup(value: unknown): boolean { if (Array.isArray(value)) return value.some(configurationNeedsCleanup); if (!value || typeof value !== "object") return false; const item = value as Record<string,unknown>; if (item.stateChanging === true || item.cleanupRequired === true) return true; return Object.values(item).some(configurationNeedsCleanup); }
function executionContract(request: DashboardScanCreateRequest): unknown { const advanced = Object.fromEntries(advancedEngineCatalog.map((item) => [item.requestField,(request as unknown as Record<string,unknown>)[item.requestField] ?? null])); return { target: new URL(request.target).origin, targetId: request.targetId, projectId: request.projectId, profile: request.profile, rateLimitPerSecond: request.rateLimitPerSecond, concurrency: request.concurrency, maxRequests: request.maxRequests, cleanupReservedRequests: request.cleanupReservedRequests, includeModules: [...(request.includeModules ?? [])].sort(), advanced, scope: request.studio?.scope, authentication: request.studio?.authentication, evidenceLevel: request.studio?.evidenceLevel, outputs: request.studio?.outputs, workflows: request.studio?.workflows ?? [] }; }
function safeUrl(value: string): string { try { const url = new URL(value); return `${url.origin}${url.pathname}`.slice(0,500); } catch { return "<invalid-url>"; } }
function safeError(error: unknown): string { return error instanceof Error ? clamp(error.message,800) : "Provider adapter preview failed."; }
function digest(value: unknown): string { return createHash("sha256").update(JSON.stringify(sort(value))).digest("hex"); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (!value || typeof value !== "object") return value; return Object.fromEntries(Object.entries(value as Record<string,unknown>).sort(([a],[b]) => a.localeCompare(b)).map(([key,child]) => [key,sort(child)])); }
function versionSummary(row: VersionRow): Record<string, unknown> { return { id: row.id, revision: row.revision, status: row.status, adapterDigest: row.adapter_digest, targetRowVersion: row.target_row_version, reviewedAt: row.reviewed_at, createdAt: row.created_at }; }
interface Encrypted { nonce: string; ciphertext: string; authTag: string }
interface ProfileRow { id: string; name: string; description: string | null; target_id: string; provider: string; engine_id: AdvancedEngineId; enabled: number; active_version_id: string | null; pending_version_id: string | null; row_version: number; created_at: string; updated_at: string; deleted_at: string | null }
interface VersionRow { id: string; profile_id: string; revision: number; status: string; adapter_digest: string; target_row_version: number; credential_binding_json: string; algorithm: string; key_version: string; nonce: string; ciphertext: string; auth_tag: string; reviewed_at: string | null; created_at: string }
