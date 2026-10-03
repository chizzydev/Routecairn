import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import type { Duplex } from "node:stream";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { afterAll, describe, expect, it } from "vitest";
import { externalAcceptanceManifestSchema, externalAcceptanceLaneKinds, generateExternalAcceptanceKeyPair, loadExternalAcceptanceManifest, runExternalAcceptance, verifyExternalAcceptanceBundle, type ExternalAcceptanceSemantic } from "../../src/validation/ExternalAcceptance.js";

describe("external acceptance attestations", () => {
  const servers: Array<ReturnType<typeof createServer>> = [];
  const upgradedSockets = new Set<Duplex>();
  afterAll(async () => { for (const socket of upgradedSockets) socket.destroy(); for (const server of servers) { server.closeAllConnections(); await new Promise<void>((done) => server.close(() => done())); } });

  it("executes all external lanes and verifies a release-bound DSSE attestation", async () => {
    const server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      if (request.url?.startsWith("/native/subscription")) {
        const denied = request.url.includes("foreign"); response.statusCode = denied ? 403 : 200; response.setHeader("content-type", "text/event-stream");
        response.end(`event: next\ndata: ${JSON.stringify(denied ? { errors: [{ message: "denied" }] } : { data: { viewer: { id: "fixture-user" } } })}\n\n`); return;
      }
      request.on("end", () => { response.statusCode = /denied|unauthorized|invalid|replay|fixed[_-]rerun|foreign/i.test(request.url ?? "") ? 403 : 200; response.setHeader("content-type", "application/json"); response.end(JSON.stringify({ ok: true, path: request.url, bytes: Buffer.concat(chunks).byteLength })); });
    });
    servers.push(server);
    server.on("upgrade", (request, socket) => {
      upgradedSockets.add(socket); socket.once("close", () => upgradedSockets.delete(socket));
      const key = String(request.headers["sec-websocket-key"] ?? ""); const accept = createHash("sha1").update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
      socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\nSec-WebSocket-Protocol: graphql-transport-ws\r\n\r\n`);
      const frame = (value: unknown) => { const body = Buffer.from(JSON.stringify(value)); const head = Buffer.alloc(body.length < 126 ? 2 : 4); head[0] = 0x81; head[1] = body.length < 126 ? body.length : 126; if (body.length >= 126) head.writeUInt16BE(body.length, 2); return Buffer.concat([head, body]); };
      let pending = Buffer.alloc(0);
      socket.on("data", (chunk: Buffer) => {
        pending = Buffer.concat([pending, chunk]);
        while (pending.length >= 6) {
          const marker = pending[1]! & 0x7f; if (marker === 127) { socket.destroy(); return; }
          const offset = marker === 126 ? 4 : 2; if (pending.length < offset + 4) return;
          const length = marker === 126 ? pending.readUInt16BE(2) : marker; if (pending.length < offset + 4 + length) return;
          const opcode = pending[0]! & 0x0f; const mask = pending.subarray(offset, offset + 4); const payload = Buffer.from(pending.subarray(offset + 4, offset + 4 + length));
          for (let index = 0; index < payload.length; index++) payload[index] = payload[index]! ^ mask[index % 4]!;
          pending = pending.subarray(offset + 4 + length);
          if (opcode === 8) { socket.end(); return; }
          const message = JSON.parse(payload.toString("utf8")) as { type: string; id?: string };
          if (message.type === "connection_init") socket.write(frame({ type: "connection_ack" }));
          else if (message.type === "subscribe") {
            const next = request.url?.includes("foreign") ? { id: message.id, type: "error", payload: [{ message: "denied" }] } : { id: message.id, type: "next", payload: { data: { viewer: { id: "fixture-user" } } } };
            socket.write(Buffer.concat([frame(next), Buffer.from([0x88, 0])]));
          }
        }
      });
      socket.on("error", () => socket.destroy()); socket.on("end", () => socket.end());
    });
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
    expect(bundle.summary.provenance).toMatchObject({ mode: "FIXTURE", externalTargetsTested: false, independentlyTrustedOperator: false });
    const bundlePath = join(bundle.summary.outputDirectory, "external-acceptance-bundle.json");
    await expect(verifyExternalAcceptanceBundle(bundlePath, releaseArtifact, publicKey, manifestPath)).resolves.toMatchObject({ verified: true, independentAcceptanceVerified: false, keyId: generated.keyId, status: "PASSED", laneCount: 8 });
    const native = structuredClone(manifest);
    for (const lane of native.lanes) for (const action of lane.actions) if (action.semantic.startsWith("GRAPHQL_SUBSCRIPTION")) {
      const denied = action.semantic.endsWith("FOREIGN_DENIED"); action.request.path = `/native/subscription/${denied ? "foreign" : "owner"}`; action.request.method = "GET";
      action.request.transport = { kind: "GRAPHQL_SSE", maxEvents: 1 }; action.assertions.jsonEquals = {}; action.assertions.jsonPresent = [denied ? "events.0.errors.0" : "events.0.data.viewer.id"];
    }
    const nativeSse = await runExternalAcceptance(native, { releaseArtifact, signingKey: privatePem, outputDirectory: join(directory, "native-sse") });
    expect(nativeSse.summary.status).toBe("PASSED");
    for (const lane of native.lanes) for (const action of lane.actions) if (action.request.transport) {
      action.request.transport = { kind: "GRAPHQL_WS", protocol: "graphql-transport-ws", document: "subscription { viewer { id } }", variables: {}, maxMessages: 3 };
      action.assertions.statuses = [101]; action.assertions.jsonPresent = action.semantic.endsWith("FOREIGN_DENIED") ? ["messages.1.payload.0.message"] : ["messages.1.payload.data.viewer.id"]; action.assertions.headerPresent = [];
    }
    const nativeWs = await runExternalAcceptance(native, { releaseArtifact, signingKey: privatePem, outputDirectory: join(directory, "native-ws") });
    expect(nativeWs.summary.status).toBe("PASSED");
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
