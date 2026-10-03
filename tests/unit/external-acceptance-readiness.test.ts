import { createHash, createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it, vi } from "vitest";
import { lookup } from "node:dns/promises";
import { runBoundedHttp, runSse, runWebSocket } from "../../src/modules/protocolSecurity/ProtocolTransports.js";
import { externalAcceptanceManifestSchema, loadExternalAcceptanceManifest, runExternalAcceptance, verifyExternalAcceptanceBundle } from "../../src/validation/ExternalAcceptance.js";
import { acceptanceCanonical, acceptanceDigest, externalAcceptanceTrustSchema, prepareExternalAcceptance, trustedAcceptanceOperator } from "../../src/validation/ExternalAcceptanceReadiness.js";
import { retainOwnedDecideAcceptance } from "../../src/validation/OwnedAcceptanceHistory.js";

vi.mock("node:dns/promises", () => ({ lookup: vi.fn() }));
vi.mock("../../src/modules/protocolSecurity/ProtocolTransports.js", () => ({ runBoundedHttp: vi.fn(), runSse: vi.fn(), runWebSocket: vi.fn() }));
const directories: string[] = [];
afterEach(async () => { vi.resetAllMocks(); await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });
const hash = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");

async function harness() {
  // Entirely synthetic verifier inputs. These tests never contact external providers.
  const directory = await mkdtemp(join(tmpdir(), "routecairn-acceptance-trust-test-")); directories.push(directory);
  const manifest = await loadExternalAcceptanceManifest(join(process.cwd(), "examples/external-acceptance.example.json"));
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }).toString(); const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString(); const keyId = hash(publicKey.export({ type: "spki", format: "der" }));
  manifest.operator = { organization: "Synthetic verifier harness", contact: "harness@security-lab.org", independentOfRouteCairnAuthors: true, publicKeyId: keyId };
  const artifact = npmArtifact(); const artifactPath = join(directory, "release.tgz"); await writeFile(artifactPath, artifact);
  manifest.release.gitCommit = hash("fixture source").slice(0, 40); manifest.release.artifactSha256 = hash(artifact);
  const proof = Buffer.from("fixture-only authorization proof"); const proofPath = join(directory, "proof.txt"); await writeFile(proofPath, proof);
  manifest.authorization.proofSha256 = hash(proof); manifest.authorization.authorizedBy = "Fixture owner"; manifest.authorization.proofReference = "HARNESS-APPROVAL";
  manifest.authorization.startsAt = new Date(Date.now() - 10000).toISOString(); manifest.authorization.expiresAt = new Date(Date.now() + 300000).toISOString(); manifest.authorization.rateLimitPerSecond = 50;
  manifest.authorization.secretEnvironment = {};
  for (const alias of Object.keys(manifest.authorization.allowedOrigins)) manifest.authorization.allowedOrigins[alias] = `https://${alias}.security-lab.org`;
  const bindings = { schemaVersion: 1 as const, authorizationProof: { path: proofPath, sha256: hash(proof) }, lanes: [] as Array<{ id: string; reproduction: { path: string; sha256: string }; deployment: { path: string; sha256: string } }> };
  for (const lane of manifest.lanes) {
    lane.targetProduct = `Fixture ${lane.kind}`; lane.targetVersion = "test-harness-1"; lane.reproductionReference = `https://security-lab.org/procedure/${lane.id}`;
    const reproduction = Buffer.from(`procedure ${lane.id}`); const deployment = Buffer.from(`deployment ${lane.id}`);
    const reproductionPath = join(directory, `${lane.id}-procedure.txt`); const deploymentPath = join(directory, `${lane.id}-deployment.txt`);
    await writeFile(reproductionPath, reproduction); await writeFile(deploymentPath, deployment);
    lane.reproductionSha256 = hash(reproduction); lane.targetFingerprint = hash(deployment);
    bindings.lanes.push({ id: lane.id, reproduction: { path: reproductionPath, sha256: hash(reproduction) }, deployment: { path: deploymentPath, sha256: hash(deployment) } });
    for (const action of lane.actions) {
      action.request.headers = {}; action.request.path = `/${action.semantic.includes("DENIED") || action.semantic.includes("REPLAY") || action.semantic.includes("INVALID") || action.semantic.includes("UNAUTHORIZED") || action.semantic.includes("FIXED_RERUN") ? "deny" : "allow"}/${action.id}`;
      delete action.request.body; action.captures = {};
      action.assertions = { statuses: [action.request.path.startsWith("/deny") ? 403 : 200], jsonEquals: { ok: true }, jsonPresent: [], jsonAbsent: [], headerPresent: [], headerAbsent: [] };
      if (action.semantic.startsWith("GRAPHQL_SUBSCRIPTION")) { action.request.method = "GET"; action.request.transport = { kind: "GRAPHQL_SSE", maxEvents: 1 }; action.assertions.jsonEquals = {}; }
    }
  }
  const parsed = externalAcceptanceManifestSchema.parse(manifest);
  const trust = externalAcceptanceTrustSchema.parse({ schemaVersion: 1, operators: [{ keyId, organization: parsed.operator.organization, publicKeyPem: publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z", revoked: false, independentlyVetted: true, vettingReference: "FIXTURE_ONLY_NOT_REAL_VETTING" }] });
  const bindingsPath = join(directory, "bindings.json"); const trustPath = join(directory, "trust.json"); const manifestPath = join(directory, "manifest.json"); const publicKeyPath = join(directory, "public.pem");
  await writeFile(bindingsPath, JSON.stringify(bindings)); await writeFile(trustPath, JSON.stringify(trust)); await writeFile(manifestPath, JSON.stringify(parsed)); await writeFile(publicKeyPath, publicPem);
  return { directory, manifest: parsed, bindings, trust, bindingsPath, trustPath, artifactPath, manifestPath, publicKeyPath, privatePem };
}

describe("external acceptance readiness and trust", () => {
  it("blocks the shipped template without transmitting and reports each missing dependency", async () => {
    const manifest = await loadExternalAcceptanceManifest(join(process.cwd(), "examples/external-acceptance.example.json"));
    const result = await prepareExternalAcceptance(manifest, { environment: {} });
    expect(result.status).toBe("BLOCKED"); expect(result.externalAcceptancePerformed).toBe(false); expect(result.lanes.every((lane) => lane.status === "BLOCKED")).toBe(true);
    expect(result.issues.map((issue) => issue.code)).toEqual(expect.arrayContaining(["PLACEHOLDER_VALUE", "PLACEHOLDER_DIGEST", "INDEPENDENT_OPERATOR_TRUST_REQUIRED", "AUTHORIZATION_AND_REPRODUCTION_BINDINGS_REQUIRED", "CREDENTIAL_ENVIRONMENT_UNAVAILABLE", "NATIVE_SUBSCRIPTION_TRANSPORT_REQUIRED"]));
    expect(lookup).not.toHaveBeenCalled(); expect(runBoundedHttp).not.toHaveBeenCalled();
  });

  it("checks actual file commitments, native subscription contracts and independently trusted keys", async () => {
    const h = await harness();
    expect((await prepareExternalAcceptance(h.manifest, { bindings: h.bindings, trust: h.trust })).status).toBe("READY");
    const revoked = { ...h.trust, operators: h.trust.operators.map((operator) => ({ ...operator, revoked: true })) };
    expect(() => trustedAcceptanceOperator(revoked, h.manifest.operator.publicKeyId, h.manifest.operator.organization, new Date().toISOString())).toThrow("UNTRUSTED");
    await writeFile(h.bindings.lanes[0]!.reproduction.path, "tampered");
    const result = await prepareExternalAcceptance(h.manifest, { bindings: h.bindings, trust: h.trust });
    expect(result.issues.some((issue) => issue.code === "LANE_ARTIFACT_DIGEST_MISMATCH")).toBe(true);
  });

  it("rejects inline credentials and unbound captures before any provider request", async () => {
    const h = await harness(); h.manifest.lanes[0]!.actions[0]!.request.headers.authorization = "Bearer DO_NOT_PERSIST_THIS";
    const result = await prepareExternalAcceptance(h.manifest, { bindings: h.bindings, trust: h.trust });
    expect(JSON.stringify(result)).not.toContain("DO_NOT_PERSIST_THIS"); expect(result.issues.some((issue) => issue.code === "INLINE_CREDENTIAL_FORBIDDEN")).toBe(true);
    await expect(runExternalAcceptance(h.manifest, { releaseArtifact: h.artifactPath, signingKey: h.privatePem, mode: "INDEPENDENT_EXTERNAL", trustPath: h.trustPath, bindingsPath: h.bindingsPath })).rejects.toThrow("INLINE_CREDENTIAL_FORBIDDEN");
    expect(runBoundedHttp).not.toHaveBeenCalled();
  });

  it("signs and verifies a complete mocked exercise, rejects revoked trust and prevents data-bearing subscription denial", async () => {
    const h = await harness(); vi.mocked(lookup).mockResolvedValue([{ address: "192.0.2.1", family: 4 }] as never);
    vi.mocked(runBoundedHttp).mockImplementation(async (url) => ({ statusCode: url.includes("/deny/") ? 403 : 200, headers: {}, body: Buffer.from('{"ok":true}') }));
    vi.mocked(runSse).mockImplementation(async (url) => ({ statusCode: url.includes("/deny/") ? 403 : 200, contentType: "text/event-stream", eventCount: 1, body: `event: next\ndata: ${url.includes("/deny/") ? '{"errors":[{"message":"denied"}]}' : '{"data":{"id":"fixture"}}'}\n\n` }));
    const bundle = await runExternalAcceptance(h.manifest, { releaseArtifact: h.artifactPath, signingKey: h.privatePem, mode: "INDEPENDENT_EXTERNAL", trustPath: h.trustPath, bindingsPath: h.bindingsPath, outputDirectory: h.directory });
    expect(bundle.summary.status).toBe("PASSED");
    const path = join(bundle.summary.outputDirectory, "external-acceptance-bundle.json");
    const options = { trustPath: h.trustPath, bindingsPath: h.bindingsPath };
    await expect(verifyExternalAcceptanceBundle(path, h.artifactPath, h.publicKeyPath, h.manifestPath, options)).resolves.toMatchObject({ verified: true, independentAcceptanceVerified: true });
    const replay = JSON.parse(await readFile(path, "utf8")); replay.summary.lanes[0].actions[1] = structuredClone(replay.summary.lanes[0].actions[0]);
    for (const lane of replay.summary.lanes) { const { evidenceSha256: _digest, ...core } = lane; lane.evidenceSha256 = hash(acceptanceCanonical(core)); }
    const { evidenceSha256: _summaryHash, outputDirectory: _directory, ...replayCore } = replay.summary; replay.summary.evidenceSha256 = hash(acceptanceCanonical(replayCore));
    replay.statement.predicate.evidenceSha256 = replay.summary.evidenceSha256;
    for (const lane of replay.statement.predicate.lanes) lane.evidenceSha256 = replay.summary.lanes.find((item: { id: string }) => item.id === lane.id).evidenceSha256;
    resign(replay, h.privatePem); const replayPath = join(h.directory, "replayed-actions.json"); await writeFile(replayPath, JSON.stringify(replay));
    await expect(verifyExternalAcceptanceBundle(replayPath, h.artifactPath, h.publicKeyPath, h.manifestPath, options)).rejects.toThrow("ACTION_REPLAY");
    const legacyManifest = JSON.parse(JSON.stringify(h.manifest)); for (const name of ["maxRequestBytes", "maxDurationMs", "cleanupGraceMs"]) delete legacyManifest.authorization[name];
    const legacy = JSON.parse(await readFile(path, "utf8")); delete legacy.summary.provenance;
    legacy.summary.manifestSha256 = hash(acceptanceCanonical(legacyManifest));
    const { evidenceSha256: _legacyHash, outputDirectory: _legacyDirectory, ...legacyCore } = legacy.summary; legacy.summary.evidenceSha256 = hash(acceptanceCanonical(legacyCore));
    legacy.statement.predicate.evidenceSha256 = legacy.summary.evidenceSha256; legacy.statement.predicate.manifestSha256 = legacy.summary.manifestSha256;
    resign(legacy, h.privatePem);
    const legacyPath = join(h.directory, "legacy.json"); const legacyManifestPath = join(h.directory, "legacy-manifest.json"); await writeFile(legacyPath, JSON.stringify(legacy)); await writeFile(legacyManifestPath, JSON.stringify(legacyManifest));
    await expect(verifyExternalAcceptanceBundle(legacyPath, h.artifactPath, h.publicKeyPath, legacyManifestPath)).resolves.toMatchObject({ verified: true, independentAcceptanceVerified: false });
    const changed = JSON.parse(await readFile(path, "utf8")); changed.statement.predicate.lanes[0].targetVersion = "changed";
    const changedPath = join(h.directory, "tampered-bundle.json"); await writeFile(changedPath, JSON.stringify(changed));
    await expect(verifyExternalAcceptanceBundle(changedPath, h.artifactPath, h.publicKeyPath, h.manifestPath, options)).rejects.toThrow("PAYLOAD_MISMATCH");
    await writeFile(h.trustPath, JSON.stringify({ ...h.trust, operators: h.trust.operators.map((operator) => ({ ...operator, revoked: true })) }));
    await expect(verifyExternalAcceptanceBundle(path, h.artifactPath, h.publicKeyPath, h.manifestPath, options)).rejects.toThrow("UNTRUSTED");
    await writeFile(h.trustPath, JSON.stringify(h.trust));
    vi.mocked(runSse).mockResolvedValue({ statusCode: 200, contentType: "text/event-stream", eventCount: 1, body: 'data: {"data":{"id":"foreign-secret"}}\n\n' });
    const failed = await runExternalAcceptance(h.manifest, { releaseArtifact: h.artifactPath, signingKey: h.privatePem, mode: "INDEPENDENT_EXTERNAL", trustPath: h.trustPath, bindingsPath: h.bindingsPath, outputDirectory: h.directory });
    expect(failed.summary.status).toBe("FAILED"); expect(failed.summary.lanes.find((lane) => lane.kind === "GRAPHQL_APPLICATION")?.cleanup).toBe("VERIFIED");
    expect(JSON.stringify(failed.summary)).not.toContain("foreign-secret");
  }, 30000);

  it("requires native WebSocket data and preserves secure foreign denial", async () => {
    const h = await harness(); vi.mocked(lookup).mockResolvedValue([{ address: "192.0.2.1", family: 4 }] as never);
    vi.mocked(runBoundedHttp).mockImplementation(async (url) => ({ statusCode: url.includes("/deny/") ? 403 : 200, headers: {}, body: Buffer.from('{"ok":true}') }));
    for (const lane of h.manifest.lanes) for (const action of lane.actions) if (action.request.transport) { action.request.transport = { kind: "GRAPHQL_WS", protocol: "graphql-transport-ws", document: "subscription { fixture { id } }", variables: {}, maxMessages: 3 }; action.assertions.statuses = [action.request.path.startsWith("/deny") ? 403 : 101]; }
    vi.mocked(runWebSocket).mockImplementation(async (url, _headers, _protocols, outbound) => url.includes("/deny/") ? { statusCode: 403, messages: [] } : { statusCode: 101, protocol: "graphql-transport-ws", messages: [{ type: "connection_ack", value: { type: "connection_ack" } }, { type: "next", value: { id: (outbound[1] as { id: string }).id, type: "next", payload: { data: { id: "fixture" } } } }] });
    const result = await runExternalAcceptance(h.manifest, { releaseArtifact: h.artifactPath, signingKey: h.privatePem, mode: "INDEPENDENT_EXTERNAL", trustPath: h.trustPath, bindingsPath: h.bindingsPath, outputDirectory: h.directory });
    expect(result.summary.status).toBe("PASSED"); expect(runWebSocket).toHaveBeenCalledTimes(2);
    vi.mocked(runWebSocket).mockResolvedValue({ statusCode: 101, protocol: "graphql-transport-ws", messages: [{ type: "connection_ack", value: { type: "connection_ack" } }, { type: "next", value: { id: "unrelated-subscription", type: "next", payload: { data: { id: "foreign" } } } }] });
    const mismatched = await runExternalAcceptance(h.manifest, { releaseArtifact: h.artifactPath, signingKey: h.privatePem, mode: "INDEPENDENT_EXTERNAL", trustPath: h.trustPath, bindingsPath: h.bindingsPath, outputDirectory: h.directory });
    expect(mismatched.summary.lanes.find((lane) => lane.kind === "GRAPHQL_APPLICATION")?.status).toBe("FAILED");
  }, 30000);

  it("keeps owned historical evidence partial and rejects source path traversal", async () => {
    const h = await harness();
    const scanId = "21484cb5-ffe5-4032-a599-e1ec7c96d84b";
    const source = { schemaVersion: 1, generatedAt: new Date().toISOString(), product: "Decide", targets: { web: "https://www.decide.com.ng", api: "https://decide-api-production-8aa7.up.railway.app" }, assessment: { webhook: { outcome: "NOT_ASSESSED" }, recovery: { outcome: "ASSESSED", scanId, findingCount: 0 } }, cleanup: { allDisposableUsersDeleted: true, sessionsRemaining: 0, controlledMutationStateRestored: true, credentialsRemovedAfterRuns: true } };
    await mkdir(join(h.directory, "reports", scanId), { recursive: true });
    await writeFile(join(h.directory, "reports", scanId, "report.json"), JSON.stringify({ execution: { status: "INTERRUPTED", partial: true, cleanup: { state: "REQUIRED" } }, findings: [] }));
    await mkdir(join(h.directory, "controlled-mutations"));
    await writeFile(join(h.directory, "controlled-mutations", "mutation-journal.json"), JSON.stringify([
      { caseId: "private-case", stage: "ROLLBACK_VERIFIED", timestamp: "2026-09-06T22:33:13.718Z" },
      { caseId: "private-case", stage: "MUTATION_APPLIED", timestamp: "2026-09-06T22:30:00.000Z" }
    ]));
    await writeFile(join(h.directory, "decide-acceptance-summary.json"), JSON.stringify(source));
    const result = await retainOwnedDecideAcceptance({ sourceDirectory: h.directory, outputDirectory: join(h.directory, "retained") });
    expect(result).toMatchObject({ status: "PARTIAL_EXTERNAL_EVIDENCE", independentOperatorVerified: false, fullEightLaneAcceptance: false, publicChecks: 0 });
    const retained = JSON.parse(await readFile(result.outputPath, "utf8"));
    expect(retained.assessments[1]).toMatchObject({ executionStatus: "INTERRUPTED", partial: true, reportCleanupState: "REQUIRED", assessment: "REVIEW_REQUIRED" });
    expect(retained.recoveryJournal.latestStages).toEqual([{ caseIdSha256: hash("private-case"), stage: "ROLLBACK_VERIFIED", timestamp: "2026-09-06T22:33:13.718Z" }]);
    expect(await readFile(join(h.directory, "retained", "owned-decide-report.md"), "utf8")).toContain("INTERRUPTED; partial: yes; report cleanup: REQUIRED; REVIEW_REQUIRED");
    expect(runBoundedHttp).not.toHaveBeenCalled();
    await writeFile(join(h.directory, "decide-acceptance-summary.json"), JSON.stringify({ ...source, assessment: { arbitrary: { outcome: "ASSESSED", scanId: "../../secret" } } }));
    await expect(retainOwnedDecideAcceptance({ sourceDirectory: h.directory, outputDirectory: h.directory })).rejects.toThrow();
  });
});

function npmArtifact(): Buffer {
  const metadata = Buffer.from(JSON.stringify({ name: "routecairn", version: "0.1.0", bin: { routecairn: "./dist/cli/index.js" } }));
  const header = Buffer.alloc(512); header.write("package/package.json"); header.write(`${metadata.length.toString(8).padStart(11, "0")}\0`, 124, "ascii");
  return gzipSync(Buffer.concat([header, metadata, Buffer.alloc(Math.ceil(metadata.length / 512) * 512 - metadata.length), Buffer.alloc(1024)]));
}

function resign(bundle: { statement: unknown; envelope: { payloadType: string; payload: string; signatures: Array<{ sig: string }> } }, key: string) {
  const payload = Buffer.from(acceptanceCanonical(bundle.statement)); bundle.envelope.payload = payload.toString("base64");
  const type = bundle.envelope.payloadType;
  bundle.envelope.signatures[0]!.sig = sign(null, Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${payload.length} ${payload.toString("utf8")}`), createPrivateKey(key)).toString("base64");
}
