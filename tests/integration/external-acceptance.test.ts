import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { afterAll, describe, expect, it } from "vitest";
import { externalAcceptanceManifestSchema, externalAcceptanceLaneKinds, generateExternalAcceptanceKeyPair, loadExternalAcceptanceManifest, runExternalAcceptance, verifyExternalAcceptanceBundle, type ExternalAcceptanceSemantic } from "../../src/validation/ExternalAcceptance.js";

describe("external acceptance attestations", () => {
  const servers: Array<ReturnType<typeof createServer>> = [];
  afterAll(async () => { for (const server of servers) await new Promise<void>((done) => server.close(() => done())); });

  it("executes all external lanes and verifies a release-bound DSSE attestation", async () => {
    const server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => { response.statusCode = /denied|unauthorized|invalid|replay|fixed[_-]rerun|foreign/i.test(request.url ?? "") ? 403 : 200; response.setHeader("content-type", "application/json"); response.end(JSON.stringify({ ok: true, path: request.url, bytes: Buffer.concat(chunks).byteLength })); });
    });
    servers.push(server);
    await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
    const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const directory = await mkdtemp(join(tmpdir(), "routecairn-external-acceptance-"));
    const releaseArtifact = join(directory, "routecairn-0.1.0.tgz");
    const releaseBytes = npmArtifact("accepted");
    await writeFile(releaseArtifact, releaseBytes);
    const privateKey = join(directory, "operator.private.pem");
    const publicKey = join(directory, "operator.public.pem");
    const generated = await generateExternalAcceptanceKeyPair(privateKey, publicKey);
    const privatePem = await readFile(privateKey, "utf8");
    const now = Date.now();
    const laneSemantics: Record<(typeof externalAcceptanceLaneKinds)[number], ExternalAcceptanceSemantic[]> = {
      MULTI_TENANT_SAAS: ["TENANT_OWNER_ALLOWED", "TENANT_FOREIGN_DENIED"],
      SUPABASE_RLS_STORAGE_RPC: ["SUPABASE_TABLE_OWNER_ALLOWED", "SUPABASE_TABLE_FOREIGN_DENIED", "SUPABASE_STORAGE_OWNER_ALLOWED", "SUPABASE_STORAGE_FOREIGN_DENIED", "SUPABASE_RPC_OWNER_ALLOWED", "SUPABASE_RPC_FOREIGN_DENIED"],
      GRAPHQL_APPLICATION: ["GRAPHQL_QUERY_OWNER_ALLOWED", "GRAPHQL_QUERY_FOREIGN_DENIED", "GRAPHQL_MUTATION_OWNER_ALLOWED", "GRAPHQL_MUTATION_FOREIGN_DENIED", "GRAPHQL_SUBSCRIPTION_OWNER_ALLOWED", "GRAPHQL_SUBSCRIPTION_FOREIGN_DENIED"],
      AUTH_PROVIDER_MFA_PASSKEY: ["OIDC_LIFECYCLE", "MFA_LIFECYCLE", "PASSKEY_LIFECYCLE"],
      SIGNED_PORTAL_EXPORT: ["SIGNED_PORTAL_OWNER_ALLOWED", "SIGNED_PORTAL_FOREIGN_DENIED", "SIGNED_EXPORT_OWNER_ALLOWED", "SIGNED_EXPORT_FOREIGN_DENIED"],
      SYNTHETIC_PAYMENT: ["SYNTHETIC_CHECKOUT", "SYNTHETIC_PROVIDER_EVENT", "SYNTHETIC_PROVIDER_REPLAY_REJECTED", "SYNTHETIC_PAYMENT_CLEANUP"],
      WEBHOOK_CRON: ["WEBHOOK_VALID_SIGNATURE", "WEBHOOK_INVALID_SIGNATURE", "WEBHOOK_REPLAY", "CRON_AUTHORIZED", "CRON_UNAUTHORIZED"],
      REMEDIATION_LIFECYCLE: ["REMEDIATION_VULNERABLE_BASELINE", "REMEDIATION_FIXED_RERUN", "REMEDIATION_IDENTITY_MATCH"]
    };
    const stateful = new Set<ExternalAcceptanceSemantic>(["GRAPHQL_MUTATION_OWNER_ALLOWED", "MFA_LIFECYCLE", "PASSKEY_LIFECYCLE", "SYNTHETIC_CHECKOUT", "SYNTHETIC_PROVIDER_EVENT", "SYNTHETIC_PAYMENT_CLEANUP", "WEBHOOK_VALID_SIGNATURE", "CRON_AUTHORIZED"]);
    const lanes = externalAcceptanceLaneKinds.map((kind) => {
      const remediationIdentity = sha(`remediation\0same-case`);
      const actions = laneSemantics[kind].map((semantic, index) => ({
        id: `${kind.toLowerCase()}-${index}`,
        phase: semantic === "SYNTHETIC_PAYMENT_CLEANUP" ? "CLEANUP" as const : "EXERCISE" as const,
        semantic,
        caseIdentity: kind === "REMEDIATION_LIFECYCLE" ? remediationIdentity : sha(`${kind}\0${semantic}`),
        request: { origin: "fixture", method: stateful.has(semantic) ? "POST" as const : "GET" as const, path: `/${kind.toLowerCase()}/${semantic.toLowerCase()}/${index}`, headers: {}, ...(stateful.has(semantic) ? { body: { fixture: true } } : {}), timeoutMs: 2_000 },
        assertions: { statuses: [/DENIED|UNAUTHORIZED|INVALID|REPLAY|FIXED_RERUN/.test(semantic) ? 403 : 200], jsonEquals: { ok: true }, jsonPresent: ["path"], jsonAbsent: [], headerPresent: ["content-type"], headerAbsent: [] },
        captures: {}, synthetic: kind === "SYNTHETIC_PAYMENT", stateChange: stateful.has(semantic)
      }));
      if (kind !== "SYNTHETIC_PAYMENT" && actions.some((action) => action.stateChange)) actions.push({ id: `${kind.toLowerCase()}-cleanup`, phase: "CLEANUP", semantic: laneSemantics[kind][0]!, caseIdentity: sha(`${kind}\0cleanup`), request: { origin: "fixture", method: "DELETE", path: `/${kind.toLowerCase()}/cleanup`, headers: {}, timeoutMs: 2_000 }, assertions: { statuses: [200], jsonEquals: { ok: true }, jsonPresent: ["path"], jsonAbsent: [], headerPresent: ["content-type"], headerAbsent: [] }, captures: {}, synthetic: false, stateChange: true });
      return { id: kind.toLowerCase(), kind, targetProduct: `External ${kind}`, targetVersion: "2026.9", ...(kind === "AUTH_PROVIDER_MFA_PASSKEY" ? { authProvider: "AUTH0" as const } : {}), ...(kind === "SYNTHETIC_PAYMENT" ? { paymentProvider: "STRIPE" as const } : {}), environment: "SANDBOX" as const, independentlyReproducible: true as const, reproductionReference: `https://example.test/reproduce/${kind.toLowerCase()}`, reproductionSha256: sha(`reproduce:${kind}`), targetFingerprint: sha(`target:${kind}:2026.9`), actions };
    });
    const manifest = externalAcceptanceManifestSchema.parse({
      schemaVersion: 1,
      name: "Independent full-grid acceptance",
      operator: { organization: "Independent Security Lab", contact: "lab@example.test", independentOfRouteCairnAuthors: true, publicKeyId: generated.keyId },
      release: { name: "routecairn", version: "0.1.0", gitCommit: "a".repeat(40), artifactSha256: sha(releaseBytes), sourceRepository: "https://github.com/example/routecairn" },
      authorization: { proofReference: "LAB-AUTH-1", proofSha256: "b".repeat(64), authorizedBy: "target owner", startsAt: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), disposableAccountsOnly: true, syntheticPaymentsOnly: true, controlledStateChangesAllowed: true, destructiveAdministrationAllowed: false, allowedOrigins: { fixture: origin }, secretEnvironment: {}, maxRequests: 100, rateLimitPerSecond: 50 },
      lanes
    });
    const manifestPath = join(directory, "external-acceptance-manifest.json");
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    const bundle = await runExternalAcceptance(manifest, { releaseArtifact, signingKey: privatePem, outputDirectory: join(directory, "evidence") });
    expect(bundle.summary).toMatchObject({ status: "PASSED", requestCount: 36 });
    expect(bundle.summary.lanes).toHaveLength(8);
    expect(bundle.summary.lanes.every((lane) => lane.status === "PASSED")).toBe(true);
    const bundlePath = join(bundle.summary.outputDirectory, "external-acceptance-bundle.json");
    await expect(verifyExternalAcceptanceBundle(bundlePath, releaseArtifact, publicKey, manifestPath)).resolves.toMatchObject({ verified: true, keyId: generated.keyId, status: "PASSED", laneCount: 8 });
    const failing = structuredClone(manifest);
    const graphql = failing.lanes.find((lane) => lane.kind === "GRAPHQL_APPLICATION")!;
    graphql.actions[0]!.assertions.jsonEquals = { ok: false };
    const failedBundle = await runExternalAcceptance(failing, { releaseArtifact, signingKey: privatePem, outputDirectory: join(directory, "failed-evidence") });
    const failedGraphql = failedBundle.summary.lanes.find((lane) => lane.kind === "GRAPHQL_APPLICATION")!;
    expect(failedBundle.summary.status).toBe("FAILED");
    expect(failedGraphql.cleanup).toBe("VERIFIED");
    expect(failedGraphql.actions.at(-1)).toMatchObject({ phase: "CLEANUP", status: "PASSED" });
    await writeFile(releaseArtifact, npmArtifact("different"));
    await expect(verifyExternalAcceptanceBundle(bundlePath, releaseArtifact, publicKey, manifestPath)).rejects.toThrow("RELEASE_SUBJECT_MISMATCH");
  }, 30_000);

  it("rejects manifests with missing semantic coverage and uncleaned state changes", () => {
    const parsed = externalAcceptanceManifestSchema.safeParse({ schemaVersion: 1, name: "Incomplete", operator: { organization: "Lab", contact: "lab@example.test", independentOfRouteCairnAuthors: true, publicKeyId: "a".repeat(64) }, release: { name: "routecairn", version: "0.1.0", gitCommit: "a".repeat(40), artifactSha256: "b".repeat(64), sourceRepository: "https://example.test/repo" }, authorization: { proofReference: "AUTH", proofSha256: "c".repeat(64), authorizedBy: "owner", startsAt: "2026-01-01T00:00:00.000Z", expiresAt: "2027-01-01T00:00:00.000Z", disposableAccountsOnly: true, syntheticPaymentsOnly: true, controlledStateChangesAllowed: true, destructiveAdministrationAllowed: false, allowedOrigins: { target: "https://example.test" }, secretEnvironment: {}, maxRequests: 20, rateLimitPerSecond: 5 }, lanes: [] });
    expect(parsed.success).toBe(false);
  });

  it("keeps the shipped independent-lab manifest schema-valid", async () => {
    const manifest = await loadExternalAcceptanceManifest(join(process.cwd(), "examples", "external-acceptance.example.json"));
    expect(manifest.lanes.map((lane) => lane.kind)).toEqual(externalAcceptanceLaneKinds);
  });
});

function sha(value: string | Buffer): string { return createHash("sha256").update(value).digest("hex"); }

function npmArtifact(marker: string): Buffer {
  const metadata = Buffer.from(JSON.stringify({ name: "routecairn", version: "0.1.0", bin: { routecairn: "./dist/cli/index.js" }, marker }));
  const header = Buffer.alloc(512);
  header.write("package/package.json", 0, "utf8");
  header.write("0000644\0", 100, "ascii");
  header.write("0000000\0", 108, "ascii");
  header.write("0000000\0", 116, "ascii");
  header.write(`${metadata.byteLength.toString(8).padStart(11, "0")}\0`, 124, "ascii");
  header.write("00000000000\0", 136, "ascii");
  header.fill(0x20, 148, 156);
  header.write("0", 156, "ascii");
  header.write("ustar\0", 257, "ascii");
  let checksum = 0; for (const value of header) checksum += value;
  header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
  const padding = Buffer.alloc(Math.ceil(metadata.byteLength / 512) * 512 - metadata.byteLength);
  return gzipSync(Buffer.concat([header, metadata, padding, Buffer.alloc(1024)]));
}
