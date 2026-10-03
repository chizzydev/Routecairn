import type { Command } from "commander";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { buildModulePayload, canonicalModuleJson, installModuleEnvelope, moduleKeyId, moduleTrustSchema, readModuleJson, signModulePayload, verifyModuleEnvelope } from "../../core/plugins/ModuleDistribution.js";
import { ModuleRegistry, moduleRegistryConfigSchema, moduleRegistryRequest } from "../../core/plugins/ModuleRegistry.js";

export function registerModulesCommand(program: Command): void {
  const modules = program.command("modules").description("Build, sign, review and distribute capability-mediated detectors.");
  modules.command("keygen").requiredOption("--private-key <path>").requiredOption("--public-key <path>").action((options) => {
    const keys = generateKeyPairSync("ed25519");
    writeFileSync(resolve(options.privateKey), keys.privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "wx", mode: 0o600 });
    writeFileSync(resolve(options.publicKey), keys.publicKey.export({ type: "spki", format: "pem" }), { flag: "wx", mode: 0o644 });
    print({ keyId: moduleKeyId(keys.publicKey), privateKeyWritten: true, publicKeyWritten: true });
  });
  modules.command("build").requiredOption("--directory <path>").requiredOption("--publisher <id>").requiredOption("--expires-at <iso>").requiredOption("--output <path>").action((options) => {
    const payload = buildModulePayload(options.directory, options.publisher, options.expiresAt); save(options.output, payload); print({ moduleId: payload.moduleId, version: payload.version, packageDigest: payload.packageDigest, signed: false });
  });
  modules.command("sign").requiredOption("--payload <path>").requiredOption("--private-key <path>").requiredOption("--output <path>").action((options) => {
    const envelope = signModulePayload(readModuleJson(options.payload), readFileSync(options.privateKey, "utf8")); save(options.output, envelope); print({ keyId: envelope.signatures[0]!.keyid, signed: true });
  });
  modules.command("review").requiredOption("--bundle <path>").requiredOption("--trust <path>").action((options) => {
    const payload = verifyModuleEnvelope(readModuleJson(options.bundle), readModuleJson(options.trust, 1024 * 1024));
    const manifest = JSON.parse(Buffer.from(payload.files.find((file) => file.path === "routecairn.module.json")!.content, "base64").toString("utf8"));
    print({ publisher: payload.publisher, moduleId: payload.moduleId, version: payload.version, packageDigest: payload.packageDigest, expiresAt: payload.expiresAt, manifest, files: payload.files.map((file) => ({ path: file.path, bytes: Buffer.from(file.content, "base64").length })), packageApproval: "REQUIRED", targetApproval: "REQUIRED_FOR_REQUESTS" });
  });
  modules.command("install").requiredOption("--bundle <path>").requiredOption("--trust <path>").requiredOption("--root <path>").requiredOption("--digest <sha256>").action((options) => {
    const envelope = readModuleJson(options.bundle), trust = readModuleJson(options.trust, 1024 * 1024); const payload = verifyModuleEnvelope(envelope, trust);
    if (payload.packageDigest !== options.digest) throw new Error("MODULE_REVIEWED_DIGEST_MISMATCH");
    const installed = installModuleEnvelope(envelope, trust, options.root); print({ directory: installed.directory, packageDigest: payload.packageDigest, approved: false, bundlePath: resolve(options.bundle) });
  });
  modules.command("index").requiredOption("--registry <origin>").action(async (options) => { print(await moduleRegistryRequest(options.registry, "/v1/index")); });
  modules.command("fetch").requiredOption("--registry <origin>").requiredOption("--module <id>").requiredOption("--version <semver>").requiredOption("--digest <sha256>").requiredOption("--trust <path>").requiredOption("--output <path>").action(async (options) => {
    if (!/^[a-z][a-z0-9-]{2,79}$/.test(options.module) || !/^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$/.test(options.version) || !/^[a-f0-9]{64}$/.test(options.digest)) throw new Error("MODULE_REGISTRY_IDENTITY_INVALID");
    const envelope = await moduleRegistryRequest(options.registry, `/v1/packages/${options.module}/${options.version}/${options.digest}`);
    const payload = verifyModuleEnvelope(envelope, readModuleJson(options.trust, 1024 * 1024));
    if (payload.moduleId !== options.module || payload.version !== options.version || payload.packageDigest !== options.digest) throw new Error("MODULE_REGISTRY_DIGEST_MISMATCH");
    save(options.output, envelope); print({ packageDigest: payload.packageDigest, verified: true });
  });
  modules.command("publish").requiredOption("--registry <origin>").requiredOption("--bundle <path>").requiredOption("--trust <path>").requiredOption("--credential-env <name>").action(async (options) => {
    const envelope = readModuleJson(options.bundle); verifyModuleEnvelope(envelope, readModuleJson(options.trust, 1024 * 1024)); print(await moduleRegistryRequest(options.registry, "/v1/publish", envelope, credential(options.credentialEnv)));
  });
  modules.command("request-signature").requiredOption("--registry <origin>").requiredOption("--payload <path>").requiredOption("--trust <path>").requiredOption("--credential-env <name>").requiredOption("--output <path>").action(async (options) => {
    const payload = readModuleJson(options.payload); const envelope = await moduleRegistryRequest(options.registry, "/v1/sign", payload, credential(options.credentialEnv)); const verified = verifyModuleEnvelope(envelope, readModuleJson(options.trust, 1024 * 1024));
    if (canonicalModuleJson(verified) !== canonicalModuleJson(payload)) throw new Error("MODULE_SIGNING_PAYLOAD_CHANGED"); save(options.output, envelope); print({ signed: true, packageDigest: verified.packageDigest });
  });
  modules.command("serve").requiredOption("--config <path>").action(async (options) => {
    const configPath = resolve(options.config); const config = moduleRegistryConfigSchema.parse(readModuleJson(configPath, 1024 * 1024)); const path = (value: string) => resolve(dirname(configPath), value);
    moduleTrustSchema.parse(readModuleJson(path(config.trustPath), 1024 * 1024));
    const registry = new ModuleRegistry({ directory: path(config.directory), trustPath: path(config.trustPath), publishToken: credential(config.publishTokenEnv), ...(config.tls ? { tls: { cert: readFileSync(path(config.tls.certificatePath)), key: readFileSync(path(config.tls.privateKeyPath)), minVersion: "TLSv1.2" as const } } : {}), ...(config.signing ? { signing: { token: credential(config.signing.tokenEnv), privateKeyPem: readFileSync(path(config.signing.privateKeyPath), "utf8"), publisher: config.signing.publisher, approvedDigests: config.signing.approvedDigests } } : {}) });
    await new Promise<void>((done, reject) => { registry.server.once("error", reject); registry.server.listen(config.port, config.host, done); });
    print({ status: "READY", host: config.host, port: config.port, tls: Boolean(config.tls), signingEnabled: Boolean(config.signing) });
    let closing = false; const close = () => { if (closing) return; closing = true; void registry.close().then(() => { process.exitCode = 0; }); }; process.once("SIGTERM", close); process.once("SIGINT", close);
  });
}
function credential(name: string): string { if (!/^[A-Z][A-Z0-9_]{1,126}$/.test(name)) throw new Error("MODULE_CREDENTIAL_ENV_INVALID"); const value = process.env[name]; if (!value || value.length < 32 || /[\r\n\0]/.test(value)) throw new Error("MODULE_CREDENTIAL_UNAVAILABLE"); return value; }
function save(path: string, value: unknown): void { writeFileSync(resolve(path), `${canonicalModuleJson(value)}\n`, { flag: "wx", mode: 0o600 }); }
function print(value: unknown): void { process.stdout.write(`${JSON.stringify(value, null, 2)}\n`); }
