import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import fc from "fast-check";
import { assertModulePath, buildModulePayload, canonicalModuleJson, installModuleEnvelope, moduleKeyId, moduleTrustSchema, signModulePayload, verifyModuleEnvelope } from "../../src/core/plugins/ModuleDistribution.js";
import { SandboxedModuleHost } from "../../src/core/plugins/SandboxedModuleHost.js";
import { moduleSigningFixture, writeModuleFixture } from "../helpers/module-distribution.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function fixture() { const root = mkdtempSync(join(tmpdir(), "routecairn-distribution-unit-")); roots.push(root); const directory = join(root, "source"); writeModuleFixture(directory); const now = Date.now(), signer = moduleSigningFixture(now); const payload = buildModulePayload(directory, signer.publisher, signer.expiresAt, now); const envelope = signModulePayload(payload, signer.privateKeyPem, now); return { root, directory, now, signer, payload, envelope }; }

describe("signed module distribution boundaries", () => {
  it("signs exact canonical bytes, retains approval digests and installs without modifying the signed package", () => {
    const f = fixture(); mkdirSync(join(f.directory, "a")); writeFileSync(join(f.directory, "a", "fixture.json"), "{}"); writeFileSync(join(f.directory, "a.txt"), "data");
    const payload = buildModulePayload(f.directory, f.signer.publisher, f.signer.expiresAt, f.now), envelope = signModulePayload(payload, f.signer.privateKeyPem, f.now);
    expect(verifyModuleEnvelope(envelope, f.signer.trust, f.now)).toEqual(payload);
    expect(Buffer.from(envelope.payload, "base64").toString()).toBe(canonicalModuleJson(payload));
    const installed = installModuleEnvelope(envelope, f.signer.trust, join(f.root, "install"), f.now);
    expect(new SandboxedModuleHost().validatePackage(installed.directory, JSON.parse(Buffer.from(payload.files.find((file) => file.path === "routecairn.module.json")!.content, "base64").toString())).digest).toBe(payload.packageDigest);
    expect(() => installModuleEnvelope(envelope, f.signer.trust, join(f.root, "install"), f.now)).toThrow("MODULE_INSTALL_ALREADY_EXISTS");
    expect(readdirSync(join(f.root, "install")).filter((file) => file.startsWith(".module-stage-"))).toHaveLength(0);
  });
  it("rejects content and signature replacement before any extraction", () => {
    const f = fixture(); const altered = { ...f.payload, publisher: "other-publisher" };
    expect(() => verifyModuleEnvelope({ ...f.envelope, payload: Buffer.from(canonicalModuleJson(altered)).toString("base64") }, f.signer.trust, f.now)).toThrow("MODULE_SIGNATURE_INVALID");
    expect(() => verifyModuleEnvelope({ ...f.envelope, signatures: [{ ...f.envelope.signatures[0]!, sig: Buffer.alloc(64).toString("base64") }] }, f.signer.trust, f.now)).toThrow("MODULE_SIGNATURE_INVALID");
    expect(() => verifyModuleEnvelope({ ...f.envelope, payloadType: "application/json" }, f.signer.trust, f.now)).toThrow();
  });
  it.each(["revokedKey", "revokedPackage", "unknownKey", "expiredKey", "futureKey", "namespace", "publisher", "fingerprint", "runtime"])("rejects %s trust violations", (kind) => {
    const f = fixture(), trust = structuredClone(f.signer.trust);
    if (kind === "revokedKey") trust.revokedKeyIds = [f.envelope.signatures[0]!.keyid];
    if (kind === "revokedPackage") trust.revokedPackageDigests = [f.payload.packageDigest];
    if (kind === "unknownKey") trust.publishers[0]!.keyId = "0".repeat(64);
    if (kind === "expiredKey") trust.publishers[0]!.expiresAt = new Date(f.now).toISOString();
    if (kind === "futureKey") trust.publishers[0]!.notBefore = new Date(f.now + 1000).toISOString();
    if (kind === "namespace") trust.publishers[0]!.modulePrefixes = ["unrelated"];
    if (kind === "publisher") trust.publishers[0]!.publisher = "other-publisher";
    if (kind === "fingerprint") trust.publishers[0]!.publicKeyPem = moduleSigningFixture().publicKeyPem;
    expect(() => verifyModuleEnvelope(f.envelope, trust, f.now, kind === "runtime" ? 18 : 24)).toThrow();
  });
  it("rejects expired and overly long package leases", () => {
    const f = fixture(); expect(() => verifyModuleEnvelope(f.envelope, f.signer.trust, f.now + 3600_000)).toThrow("MODULE_LEASE_INVALID");
    expect(() => signModulePayload({ ...f.payload, expiresAt: new Date(f.now + 91 * 86400_000).toISOString() }, f.signer.privateKeyPem, f.now)).toThrow("MODULE_LEASE_INVALID");
  });
  it.each(["../escape", "/absolute", "dir\\file", "con.txt", "nul/fixture", "a/../b", "a./b", "node_modules/a", ".git/config", ".env", "key.pem", "addon.node", "a//b", "a:b", "a%2fb"])("rejects portable extraction hazard %s", (path) => { expect(() => assertModulePath(path)).toThrow("MODULE_FILE_PATH_REJECTED"); });
  it("property-checks traversal and drive/stream paths before signing", () => {
    fc.assert(fc.property(fc.string({ maxLength: 80 }), (suffix) => { expect(() => assertModulePath(`../${suffix}`)).toThrow(); expect(() => assertModulePath(`C:/${suffix}`)).toThrow(); }), { numRuns: 100, seed: 27001 });
  });
  it("rejects duplicate paths and a changed digest", () => {
    const f = fixture(); expect(() => signModulePayload({ ...f.payload, files: [...f.payload.files, f.payload.files[0]] }, f.signer.privateKeyPem, f.now)).toThrow("MODULE_FILE_DUPLICATE");
    expect(() => signModulePayload({ ...f.payload, packageDigest: "0".repeat(64) }, f.signer.privateKeyPem, f.now)).toThrow("MODULE_PAYLOAD_DIGEST_MISMATCH");
    expect(moduleKeyId(f.signer.publicKeyPem)).toBe(f.signer.trust.publishers[0]!.keyId);
  });
  it("rejects manifest substitution and unpinned container images", () => {
    const f = fixture(); expect(() => new SandboxedModuleHost().validatePackage(f.directory, { ...writeModuleFixture(f.directory), description: "replacement" })).toThrow("SDK_MANIFEST_MISMATCH");
    expect(() => new SandboxedModuleHost("node:24")).toThrow("SDK_CONTAINER_IMAGE_DIGEST_REQUIRED");
  });
  it("permits same-publisher key rotation but rejects overlapping ownership", () => {
    const f = fixture(), next = moduleSigningFixture(f.now).trust.publishers[0]!;
    expect(moduleTrustSchema.parse({ ...f.signer.trust, publishers: [...f.signer.trust.publishers, next] }).publishers).toHaveLength(2);
    expect(() => moduleTrustSchema.parse({ ...f.signer.trust, publishers: [...f.signer.trust.publishers, { ...next, publisher: "other-publisher", modulePrefixes: ["reference-child"] }] })).toThrow(/overlapping namespaces/);
  });
});
