import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { createProtocolSemanticsLab } from "../helpers/protocol-semantics-lab.js";
import { createActiveProxyLab } from "../helpers/active-proxy-lab.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { routeCairnConfigSchema, scopeSchema } from "../../src/config/ConfigSchema.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";
import { planProtocolSecurity, protocolSecurityInputSchema } from "../../src/modules/protocolSecurity/ProtocolSecurityPlanner.js";
import { ProtocolSecurityModule } from "../../src/modules/protocolSecurity/ProtocolSecurityModule.js";
import { runWebTransportDatagrams } from "../../src/modules/protocolSecurity/ProtocolTransports.js";
import { testPlan } from "../helpers/plan.js";

const allow = { decision: "ALLOW", allowedStatuses: [200], deniedStatuses: [401, 403], minMessages: 0 };
const actors = [{ id: "owner", safeAlias: "fixture-owner", authSlot: "primary", relationship: "owned" }];
const approval = () => ({ environment: "LOCAL", operator: "fixture-owner", ticket: "owned-lab", authorizedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 600000).toISOString(), disposableResources: true, confirmation: "I_AUTHORIZE_PROTOCOL_STATE_CHANGES" });
async function contextFor(origin: string, ca: string, cases: unknown[], directory: string, secrets: Record<string, string> = {}, headers: Record<string, string> = {}) {
  const scope = scopeSchema.parse({ ...exampleScope, allowedDomains: ["localhost"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "PUT", "CONNECT"], rateLimitPerSecond: 50 });
  const config = routeCairnConfigSchema.parse({ ...defaultConfig, transport: { ...defaultConfig.transport, trustedCaPem: ca } });
  const profile = authProfileSchema.parse({ label: "fixture-owner", headers, lifecycleSecrets: secrets });
  const protocolSecurity = planProtocolSecurity(protocolSecurityInputSchema.parse({ maxRequests: 100, maxDurationMs: 4000, actors, cases }), { target: origin, scope, authProfile: profile });
  const plan = testPlan("quick", { scope, config, overrides: { maxRequests: 160, cleanupReservedRequests: 20 } });
  return new ScanContext({ target: origin, scope, config, authProfile: profile, plan: { ...plan, protocolSecurity }, outputDir: directory, mutationJournalDir: join(directory, "journal") });
}
async function retain(name: string, value: unknown) { if (!process.env.ROUTECAIRN_PROTOCOL_LAB_OUTPUT) return; const directory = resolve(process.env.ROUTECAIRN_PROTOCOL_LAB_OUTPUT); await mkdir(directory, { recursive: true }); await writeFile(join(directory, name), `${JSON.stringify(value, null, 2)}\n`, { flag: "wx" }); }

describe("full protocol module runtime", () => {
  it("executes advanced contracts through real TLS/H2/H3/WebTransport with controls and cleanup", async () => {
    const lab = await createProtocolSemanticsLab(); const directory = await mkdtemp(join(tmpdir(), "routecairn-protocol-module-")); let context: ScanContext | undefined;
    const base = (id: string, kind: string, path: string, extra: Record<string, unknown> = {}) => ({ id, label: id, kind, actorId: "owner", requireVerifiedIdentity: false, url: lab.origin + path, headers: {}, expectation: allow, ...extra });
    const wsStates = [{ send: { type: "read" }, expectType: "error" }, { send: { type: "login", payload: { authorization: "{{SECRET:session}}" } }, expectType: "authenticated" }, { send: { type: "read" }, expectType: "data" }, { send: { type: "logout" }, expectType: "logged_out" }, { send: { type: "read" }, expectType: "error" }];
    const cases = [
      base("client-stream", "GRPC_CLIENT_STREAM", "/fixture.Service/Client", { payloadSecretRefs: ["one", "two"], maxMessages: 4, readOnly: true, expectation: { ...allow, minMessages: 1 } }),
      base("bidi-stream", "GRPC_BIDI_STREAM", "/fixture.Service/Bidi", { payloadSecretRefs: ["one", "two"], interMessageDelayMs: 20, maxMessages: 4, readOnly: true, expectation: { ...allow, minMessages: 2 } }),
      base("incremental", "GRAPHQL_INCREMENTAL", "/graphql", { document: "query Feed { feed @stream(initialCount: 0) { id } }", variables: {}, maxParts: 4, expectedPaths: ["feed.0"], expectation: { ...allow, minMessages: 2 } }),
      base("persisted", "GRAPHQL_PERSISTED_QUERY", "/graphql", { document: lab.document, variables: {}, sha256Hash: lab.persistedHash, negotiation: "REGISTER_THEN_HASH", expectation: { ...allow, jsonPath: "data.viewer.id" } }),
      base("entities", "GRAPHQL_FEDERATION", "/graphql", { operation: "ENTITIES", representations: [{ __typename: "OwnedObject", id: "fixture" }], expectation: { ...allow, jsonPath: "data._entities.0.__typename", equals: "OwnedObject" } }),
      ...["GRAPHQL_TRANSPORT_WS", "LEGACY_GRAPHQL_WS"].map((transport, index) => base(`reauth-${index}`, "GRAPHQL_SUBSCRIPTION_REAUTH", "/graphql", { url: lab.origin.replace("https:", "wss:") + "/graphql", transport, document: "subscription Watch { events { __typename } }", variables: {}, initialConnectionPayload: { authorization: "{{SECRET:old}}" }, reauthConnectionPayload: { authorization: "{{SECRET:session}}" }, initialDecision: "DENY", maxMessages: 3, expectation: { ...allow, allowedStatuses: [101], messageType: index ? "data" : "next", minMessages: 1 } })),
      base("ws-state", "WEBSOCKET_AUTH_STATE_MACHINE", "/state", { url: lab.origin.replace("https:", "wss:") + "/state", subprotocols: ["fixture"], states: wsStates, maxMessages: 5, readOnly: true, expectation: { ...allow, allowedStatuses: [101], minMessages: 5 } }),
      base("upload-interrupt", "STREAMING_UPLOAD_INTERRUPT", "/upload", { method: "PUT", bodySecretRef: "upload", chunkBytes: 128, interruptAfterBytes: 512, verificationUrl: lab.origin + "/upload/state", verificationMethod: "GET", authorization: approval(), cleanup: { url: lab.origin + "/cleanup", method: "POST", headers: {}, statusIn: [204] }, expectation: { ...allow, jsonPath: "partial", equals: true } }),
      ...["gzip", "deflate", "br"].flatMap((encoding) => [base(`compression-${encoding}`, "COMPRESSION_BOUNDARY", `/compressed/${encoding}/small`, { method: "GET", encoding, maxExpandedBytes: 1024, readOnly: true }), base(`expansion-${encoding}`, "COMPRESSION_BOUNDARY", `/compressed/${encoding}/large`, { method: "GET", encoding, maxExpandedBytes: 1024, readOnly: true })]),
      base("identity-parity", "CROSS_PROTOCOL_IDENTITY", "/identity", { legs: [{ protocol: "HTTP1", url: lab.origin + "/identity", method: "GET", headers: {}, jsonPath: "subject" }, { protocol: "HTTP2", url: lab.origin + "/identity", method: "GET", headers: {}, jsonPath: "subject" }, { protocol: "HTTP3", url: lab.origin + "/identity", method: "GET", headers: {}, jsonPath: "subject" }], readOnly: true }),
      base("identity-missing", "CROSS_PROTOCOL_IDENTITY", "/identity", { legs: [{ protocol: "HTTP1", url: lab.origin + "/identity/missing", method: "GET", headers: {}, jsonPath: "subject" }, { protocol: "HTTP2", url: lab.origin + "/identity/missing", method: "GET", headers: {}, jsonPath: "subject" }], readOnly: true }),
      base("identity-mismatch", "CROSS_PROTOCOL_IDENTITY", "/identity", { legs: [{ protocol: "HTTP1", url: lab.origin + "/identity/mismatch", method: "GET", headers: {}, jsonPath: "subject" }, { protocol: "HTTP2", url: lab.origin + "/identity", method: "GET", headers: {}, jsonPath: "subject" }], readOnly: true }),
      base("wt-allow", "WEBTRANSPORT_DATAGRAM", "/datagrams", { authenticationMode: "DATAGRAM", datagramSecretRefs: ["session"], maxDatagrams: 2, readOnly: true, expectation: { ...allow, minMessages: 1, jsonPath: "authorized", equals: true } }),
      base("wt-denied", "WEBTRANSPORT_DATAGRAM", "/datagrams/denied", { authenticationMode: "DATAGRAM", datagramSecretRefs: ["session"], maxDatagrams: 1, readOnly: true, expectation: { ...allow, decision: "DENY", minMessages: 1 } }),
      base("wt-application-denied", "WEBTRANSPORT_DATAGRAM", "/datagrams", { authenticationMode: "DATAGRAM", datagramSecretRefs: ["old"], maxDatagrams: 1, readOnly: true, expectation: { ...allow, minMessages: 1, jsonPath: "authorized", equals: false } })
    ];
    let report: unknown;
    try {
      context = await contextFor(lab.origin, lab.ca, cases, directory, { one: "base64:CAE=", two: "base64:CAI=", session: "protocol-fixture-session", old: "expired-fixture-session", upload: "A".repeat(8192) }, { Authorization: "Bearer protocol-fixture-session" });
      const result = await new ProtocolSecurityModule().run(context); report = result.protocolSecurity; const observations = result.protocolSecurity!.observations;
      for (const item of observations) expect(item.outcome, `${item.caseId}: ${item.reason}`).toBe(item.caseId === "identity-missing" ? "INCONCLUSIVE" : item.caseId === "identity-mismatch" ? "FAIL" : "PASS");
      expect(observations.find((item) => item.caseId === "upload-interrupt")?.cleanupOutcome).toBe("ROLLBACK_VERIFIED");
      expect(observations.find((item) => item.caseId === "identity-parity")?.structuralCount).toBe(3);
      expect(observations.find((item) => item.caseId === "wt-allow")?.negotiatedProtocol).toBe("h3-webtransport");
      expect(lab.counters["bidi-before-half-close"]).toBe(2); expect(lab.counters["persisted-register"]).toBe(1); expect(lab.counters["persisted-hit"]).toBe(1); expect(lab.counters["federation-entities"]).toBe(1);
      expect(lab.state()).toMatchObject({ dirty: false, partialBytes: 0, aborted: true, cleanupCount: 1 });
      const bytes = JSON.stringify(report); for (const secret of ["protocol-fixture-session", "expired-fixture-session", "protocol-private-subject", "protocol-private-tenant", "private-id"]) expect(bytes).not.toContain(secret);
      await expect(runWebTransportDatagrams(lab.origin + "/datagrams", [Buffer.from("safe")], 1, { allowedPrivateOrigins: [lab.origin], timeoutMs: 1500, maxBytes: 4096 })).rejects.toThrow();
      await expect(runWebTransportDatagrams(lab.origin + "/datagrams/large", [Buffer.from("safe"), Buffer.from("safe")], 2, { allowedPrivateOrigins: [lab.origin], tlsCa: lab.ca, timeoutMs: 2000, maxBytes: 1024 })).rejects.toThrow(/LIMIT/);
    } finally { await context?.dispose(); await lab.close(); await rm(directory, { recursive: true, force: true }); }
    await retain("module-runtime.json", { schemaVersion: 1, generatedAt: new Date().toISOString(), provenance: "SELF_MAINTAINED_LOOPBACK_REAL_PROTOCOLS", externalTargetsTested: false, independentlyOperated: false, cleanup: "CONFIRMED", report, counters: lab.counters, checks: ["full-module", "grpc-client", "grpc-bidi", "incremental", "persisted", "federation", "modern-reauth", "legacy-reauth", "ws-login-read-logout-denial", "upload-interruption-restoration", "three-compression-encodings", "H1-H2-H3-identity", "missing-identity-inconclusive", "identity-mismatch-detected", "native-WebTransport", "CONNECT-denial", "datagram-authentication", "untrusted-certificate-rejected", "aggregate-datagram-limit", "secret-free-evidence"] });
  }, 120000);
});

describe.runIf(Boolean(process.env.ROUTECAIRN_CADDY_BINARY && process.env.ROUTECAIRN_NGINX_BINARY))("native multi-proxy module deployment", () => {
  for (const upstream of ["H1", "H2"] as const) it(`runs H1/H2/H3 framing cells with ${upstream} upstream`, async () => {
    const lab = await createActiveProxyLab(process.env.ROUTECAIRN_CADDY_BINARY!, process.env.ROUTECAIRN_NGINX_BINARY!, upstream); const directory = await mkdtemp(join(tmpdir(), "routecairn-protocol-chain-")); let context: ScanContext | undefined; let report: unknown;
    try {
      const cases = ["CL_TE", "TE_CL", "H2", "H3"].map((cell) => ({ id: `chain-${cell}`, label: `chain-${cell}`, kind: "PROXY_CHAIN_DESYNCHRONIZATION", actorId: "owner", requireVerifiedIdentity: false, url: lab.origin + "/probe", method: "POST", headers: {}, bodySecretRef: "fixture", framing: cell === "H2" || cell === "H3" ? "CONTENT_LENGTH_DELTA" : cell, declaredLengthDelta: 1, sentinelPath: "/sentinel", frontendProtocols: [cell === "H2" || cell === "H3" ? cell : "H1"], proxyChain: [{ origin: lab.origin, protocol: upstream }, { origin: lab.origin, protocol: "H1" }], topologyProof: { url: lab.origin + "/proof", deploymentSha256: lab.deploymentSha256, hopIds: lab.hopIds, traceHeader: "x-routecairn-hop-trace" }, authorization: { ...Object.fromEntries(Object.entries(approval()).filter(([key]) => key !== "disposableResources")), confirmation: "I_AUTHORIZE_BOUNDED_PROTOCOL_DESYNCHRONIZATION" }, expectation: { ...allow, decision: "OBSERVE", deniedStatuses: [400, 401, 403] } }));
      context = await contextFor(lab.origin, lab.ca, cases, directory, { fixture: "bounded-fixture" });
      const result = await new ProtocolSecurityModule().run(context); report = result.protocolSecurity;
      expect(result.protocolSecurity!.executedCases).toBe(4);
      for (const item of result.protocolSecurity!.observations) { expect(item.outcome, `${item.caseId}: ${item.reason}`).toBe(["chain-H2", "chain-H3"].includes(item.caseId) ? "PASS" : "INCONCLUSIVE"); expect(item.structuralCount).toBe(1); }
    } finally { await context?.dispose(); await lab.stop(); await rm(directory, { recursive: true, force: true }); }
    await retain(`proxy-${upstream}-module-runtime.json`, { schemaVersion: 1, generatedAt: new Date().toISOString(), provenance: "SELF_MAINTAINED_LOOPBACK_NATIVE_CADDY_NGINX", externalTargetsTested: false, independentlyOperated: false, deploymentSha256: lab.deploymentSha256, binaries: lab.binaries, hopIds: lab.hopIds, frontendProtocols: ["H1", "H2", "H3"], upstreamProtocols: [upstream, "H1"], cleanup: "CONFIRMED", report });
  }, 60000);
});
