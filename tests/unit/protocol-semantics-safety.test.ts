import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { protocolSecurityInputSchema, planProtocolSecurity } from "../../src/modules/protocolSecurity/ProtocolSecurityPlanner.js";
import { exampleScope, defaultConfig } from "../../src/config/defaults.js";
import { runInterruptedUpload, runWebTransportDatagrams } from "../../src/modules/protocolSecurity/ProtocolTransports.js";
import { routeCairnConfigSchema } from "../../src/config/ConfigSchema.js";
import { parseGraphqlParts } from "../../src/modules/protocolSecurity/ProtocolGraphqlMultipart.js";

import { decodeGrpcFrames } from "../../src/modules/protocolSecurity/ProtocolGrpcFrames.js";

const origin = "https://example.test";
const actor = { id: "anon", safeAlias: "anon", authSlot: "anonymous", relationship: "untrusted" };
const expectation = { decision: "ALLOW", allowedStatuses: [200], deniedStatuses: [403], minMessages: 1 };
describe("protocol safety contracts", () => {
  for (const [body, reason] of [[Buffer.from([0, 0]), "GRPC_FRAME_TRUNCATED"], [Buffer.from([2, 0, 0, 0, 0]), "GRPC_FRAME_FLAG_INVALID"], [Buffer.from([1, 0, 0, 0, 0]), "GRPC_MESSAGE_COMPRESSION_UNSUPPORTED"], [Buffer.from([0, 0, 0, 0, 0, 0]), "GRPC_FRAME_TRUNCATED"]] as const) it(`classifies ${reason} without accepting a partial frame prefix`, () => { expect(decodeGrpcFrames(body, 2)).toEqual({ frames: [], errorCode: reason }); });
  it("enforces the gRPC message count bound", () => { expect(decodeGrpcFrames(Buffer.alloc(10), 1)).toEqual({ frames: [], errorCode: "GRPC_MESSAGE_LIMIT_EXCEEDED" }); });
  for (const mode of ["truncated", "overflow", "invalid-json", "missing-headers"] as const) it(`rejects ${mode} incremental delivery`, () => {
    const part = mode === "missing-headers" ? "\r\n\r\n{}\r\n" : `\r\ncontent-type: application/json\r\n\r\n${mode === "invalid-json" ? "{" : '{"hasNext":false}'}\r\n`;
    const payload = `--fixture${part}${mode === "overflow" ? `--fixture${part}` : ""}${mode === "truncated" ? "" : "--fixture--\r\n"}`;
    expect(() => parseGraphqlParts({ statusCode: 200, headers: { "content-type": "multipart/mixed; boundary=fixture" }, body: Buffer.from(payload) }, 1)).toThrow(/GRAPHQL_INCREMENTAL/);
  });
  for (const document of ['query Read { viewer(input: "#") { id } } mutation Write { erase }', 'query Read { viewer { id } } subscription Watch { events }', 'query Read { viewer(input: "unterminated) { id } }']) it(`rejects mixed or malformed persisted operations ${document.slice(0, 20)}`, () => {
    const input = protocolSecurityInputSchema.parse({ actors: [actor], cases: [{ id: "query", label: "query", kind: "GRAPHQL_PERSISTED_QUERY", actorId: "anon", requireVerifiedIdentity: false, url: origin + "/graphql", document, variables: {}, sha256Hash: createHash("sha256").update(document).digest("hex"), negotiation: "HASH_ONLY", expectation }] });
    expect(() => planProtocolSecurity(input, { target: origin, scope: { ...exampleScope, allowedDomains: ["example.test"], allowedMethods: ["GET", "POST"] } })).toThrow(/read-only/);
  });
  it("requires CONNECT permission for Extended CONNECT", () => {
    const input = protocolSecurityInputSchema.parse({ actors: [actor], cases: [{ id: "wt", label: "wt", kind: "WEBTRANSPORT_DATAGRAM", actorId: "anon", requireVerifiedIdentity: false, url: origin + "/wt", datagramSecretRefs: ["ping"], maxDatagrams: 1, readOnly: true, expectation }] });
    const scope = { ...exampleScope, allowedDomains: ["example.test"], allowedMethods: ["GET", "POST"] as const };
    expect(() => planProtocolSecurity(input, { target: origin, scope: { ...scope, allowedMethods: [...scope.allowedMethods] } })).toThrow(/out of scope/);
    expect(planProtocolSecurity(input, { target: origin, scope: { ...scope, allowedMethods: [...scope.allowedMethods, "CONNECT"] } }).cases).toHaveLength(1);
  });
  it("rejects datagrams above the conservative MTU bound before DNS or transmission", async () => {
    await expect(runWebTransportDatagrams(origin, [Buffer.alloc(1201)], 1, { allowedPrivateOrigins: [], timeoutMs: 1000, maxBytes: 4096 })).rejects.toThrow("WEBTRANSPORT_DATAGRAM_LIMIT_EXCEEDED");
  });
  it("requires a strictly partial upload and valid chunk bounds before transmission", async () => {
    for (const [chunk, interruption] of [[0, 1], [1, 4], [1, 5]]) await expect(runInterruptedUpload(origin, "PUT", {}, Buffer.alloc(4), chunk!, interruption!, { allowedPrivateOrigins: [], timeoutMs: 1000, maxBytes: 4096 })).rejects.toThrow(/PARTIAL_BODY/);
  });
  it("rejects certificate configuration that contains private key material", () => {
    expect(() => routeCairnConfigSchema.parse({ ...defaultConfig, transport: { trustedCaPem: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----" } })).toThrow();
  });
});
