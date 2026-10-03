import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { moduleKeyId, type ModuleTrust } from "../../src/core/plugins/ModuleDistribution.js";

export function moduleSigningFixture(now = Date.now()) {
  const keys = generateKeyPairSync("ed25519"); const publicKeyPem = keys.publicKey.export({ format: "pem", type: "spki" }).toString(); const privateKeyPem = keys.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const trust: ModuleTrust = { schemaVersion: 1, publishers: [{ publisher: "fixture-publisher", modulePrefixes: ["reference", "fixture"], publicKeyPem, keyId: moduleKeyId(keys.publicKey), notBefore: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 86400_000).toISOString() }], revokedKeyIds: [], revokedPackageDigests: [] };
  return { privateKeyPem, publicKeyPem, trust, publisher: "fixture-publisher", expiresAt: new Date(now + 3600_000).toISOString() };
}
export function writeModuleFixture(directory: string, source = "export async function analyze(){ return { observations: [], findings: [], notes: [] }; }") {
  mkdirSync(directory, { recursive: true });
  const manifest = { schemaVersion: 1, moduleId: "fixture-detector", version: "1.0.0", entrypoint: "index.mjs", description: "Distribution fixture", permissions: { network: false, childProcess: false, filesystem: "PACKAGE_READ_ONLY", maxRuntimeMs: 5000, maxMemoryMb: 32 }, inputSchema: { type: "object", additionalProperties: false }, outputLimit: 10 };
  writeFileSync(join(directory, "routecairn.module.json"), JSON.stringify(manifest)); writeFileSync(join(directory, "index.mjs"), source); return manifest;
}
