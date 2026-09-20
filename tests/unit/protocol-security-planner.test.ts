import { describe, expect, it } from "vitest";
import { planProtocolSecurity, protocolSecurityInputSchema } from "../../src/modules/protocolSecurity/ProtocolSecurityPlanner.js";

const target = "https://app.example.com";
const actor = { id: "anon", safeAlias: "anonymous", authSlot: "anonymous" as const, relationship: "untrusted" };
const expectation = { decision: "DENY" as const, allowedStatuses: [200], deniedStatuses: [401, 403], minMessages: 0 };
const defaultScope = { program: "test", allowedDomains: ["app.example.com"], disallowedPaths: [], allowedMethods: ["GET", "POST"] as Array<"GET" | "POST">, rateLimitPerSecond: 10, concurrency: 2, maxDepth: 2, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn-Test" };

describe("protocol security planner", () => {
  it("plans bounded streaming, gRPC, multipart, HTTP/2, and HTTP/3 cases", () => {
    const now = Date.now();
    const input = protocolSecurityInputSchema.parse({
      schemaVersion: 1, maxRequests: 20, actors: [actor], cases: [
        { id: "ws", label: "ws", kind: "WEBSOCKET", actorId: "anon", requireVerifiedIdentity: false, url: "wss://app.example.com/socket", headers: {}, subprotocols: [], messages: [{ type: "ping" }], maxMessages: 2, expectation },
        { id: "sse", label: "sse", kind: "SSE", actorId: "anon", requireVerifiedIdentity: false, url: `${target}/events`, headers: {}, method: "GET", maxEvents: 2, expectation },
        { id: "sub", label: "sub", kind: "GRAPHQL_SUBSCRIPTION", actorId: "anon", requireVerifiedIdentity: false, url: "wss://app.example.com/graphql", headers: {}, transport: "GRAPHQL_TRANSPORT_WS", document: "subscription Watch { events { __typename } }", variables: {}, maxMessages: 2, expectation },
        { id: "grpc", label: "grpc", kind: "GRPC_UNARY", actorId: "anon", requireVerifiedIdentity: false, url: `${target}/svc/Get`, headers: {}, payloadSecretRef: "grpc_fixture", maxMessages: 1, expectation },
        { id: "upload", label: "upload", kind: "MULTIPART_UPLOAD", actorId: "anon", requireVerifiedIdentity: false, url: `${target}/inspect-upload`, headers: {}, fields: {}, files: [{ fieldName: "file", fileName: "fixture.txt", contentType: "text/plain", contentSecretRef: "upload_fixture" }], readOnly: true, expectation },
        { id: "h2", label: "h2", kind: "HTTP2_AUTHORIZATION", actorId: "anon", requireVerifiedIdentity: false, url: `${target}/private`, headers: {}, method: "GET", expectation },
        { id: "h3", label: "h3", kind: "HTTP3_AUTHORIZATION", actorId: "anon", requireVerifiedIdentity: false, url: `${target}/private`, headers: {}, method: "GET", expectation },
        { id: "h3-desync", label: "h3 desync", kind: "HTTP3_DESYNCHRONIZATION", actorId: "anon", requireVerifiedIdentity: false, url: `${target}/probe`, headers: {}, method: "POST", bodySecretRef: "probe_body", declaredLengthDelta: 1, sentinelPath: "/sentinel", authorization: { environment: "TEST", operator: "test", ticket: "T-2", authorizedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), confirmation: "I_AUTHORIZE_BOUNDED_PROTOCOL_DESYNCHRONIZATION" }, expectation }
      ]
    });
    const plan = planProtocolSecurity(input, { target, scope: { ...defaultScope, allowedMethods: ["GET", "POST"] } });
    expect(plan.cases).toHaveLength(8);
    expect(plan.cases.every((item) => item.comparisonFingerprint.length === 64)).toBe(true);
    expect(Object.isFrozen(plan.cases)).toBe(true);
  });

  it("requires active non-production authorization and cleanup for GraphQL mutations", () => {
    const now = Date.now();
    const input = protocolSecurityInputSchema.parse({ schemaVersion: 1, actors: [actor], cases: [{
      id: "mutation", label: "mutation", kind: "GRAPHQL_MUTATION", actorId: "anon", requireVerifiedIdentity: false, url: `${target}/graphql`, headers: {}, document: "mutation Update { updateFixture { ok } }", variables: {}, expectation: { ...expectation, decision: "ALLOW", minMessages: 0 },
      authorization: { environment: "TEST", operator: "test", ticket: "T-1", authorizedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), confirmation: "I_AUTHORIZE_PROTOCOL_STATE_CHANGES", disposableResources: true },
      cleanup: { url: `${target}/fixtures/reset`, method: "POST", headers: {}, body: { fixture: true }, statusIn: [204] }
    }] });
    expect(planProtocolSecurity(input, { target, scope: { ...defaultScope, allowedMethods: ["GET", "POST"] } }).cases[0]?.kind).toBe("GRAPHQL_MUTATION");
  });

  it("rejects query documents in the mutation lane and state-changing multipart without cleanup", () => {
    const base = { schemaVersion: 1 as const, actors: [actor], maxRequests: 5 };
    expect(() => planProtocolSecurity(protocolSecurityInputSchema.parse({ ...base, cases: [{ id: "bad", label: "bad", kind: "GRAPHQL_MUTATION", actorId: "anon", requireVerifiedIdentity: false, url: `${target}/graphql`, headers: {}, document: "query Read { viewer { id } }", variables: {}, expectation, authorization: { environment: "TEST", operator: "x", ticket: "x", authorizedAt: new Date(Date.now() - 100).toISOString(), expiresAt: new Date(Date.now() + 10000).toISOString(), confirmation: "I_AUTHORIZE_PROTOCOL_STATE_CHANGES", disposableResources: true }, cleanup: { url: `${target}/cleanup`, method: "POST", headers: {}, statusIn: [204] } }] }), { target, scope: { ...defaultScope, allowedMethods: ["GET", "POST"] } })).toThrow(/explicit mutation/i);
    expect(() => planProtocolSecurity(protocolSecurityInputSchema.parse({ ...base, cases: [{ id: "bad-upload", label: "bad", kind: "MULTIPART_UPLOAD", actorId: "anon", requireVerifiedIdentity: false, url: `${target}/upload`, headers: {}, fields: {}, files: [{ fieldName: "file", fileName: "x", contentType: "text/plain", contentSecretRef: "x" }], readOnly: false, expectation }] }), { target, scope: { ...defaultScope, allowedMethods: ["GET", "POST"] } })).toThrow(/requires authorization and cleanup/i);
  });

  it("applies the effective subscription method and confines desync sentinels to scope", () => {
    const base = { schemaVersion: 1 as const, actors: [actor], maxRequests: 5 };
    const subscription = protocolSecurityInputSchema.parse({ ...base, cases: [{ id: "sub", label: "sub", kind: "GRAPHQL_SUBSCRIPTION", actorId: "anon", requireVerifiedIdentity: false, url: `${target}/graphql`, headers: {}, transport: "SSE", document: "subscription Watch { events { __typename } }", variables: {}, maxMessages: 2, expectation }] });
    expect(() => planProtocolSecurity(subscription, { target, scope: { ...defaultScope, allowedMethods: ["GET"] } })).toThrow(/out of scope/i);

    const now = Date.now();
    const desync = protocolSecurityInputSchema.parse({ ...base, cases: [{ id: "h2", label: "h2", kind: "HTTP2_DESYNCHRONIZATION", actorId: "anon", requireVerifiedIdentity: false, url: `${target}/probe`, headers: {}, method: "POST", bodySecretRef: "fixture", declaredLengthDelta: 1, sentinelPath: "//other.example/sentinel", authorization: { environment: "TEST", operator: "test", ticket: "T-3", authorizedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), confirmation: "I_AUTHORIZE_BOUNDED_PROTOCOL_DESYNCHRONIZATION" }, expectation }] });
    expect(() => planProtocolSecurity(desync, { target, scope: { ...defaultScope, allowedMethods: ["GET", "POST"] } })).toThrow(/sentinel.*target origin/i);
  });

  it.each(["WEBSOCKET", "GRPC_UNARY"] as const)("requires authorization and cleanup for state-changing %s cases", (kind) => {
    const value = kind === "WEBSOCKET"
      ? { id: "stateful-ws", label: "stateful ws", kind, actorId: "anon", requireVerifiedIdentity: false, url: "wss://app.example.com/socket", headers: {}, subprotocols: [], messages: [{ type: "change" }], maxMessages: 1, readOnly: false, expectation }
      : { id: "stateful-grpc", label: "stateful grpc", kind, actorId: "anon", requireVerifiedIdentity: false, url: `${target}/service/Change`, headers: {}, payloadSecretRef: "fixture", maxMessages: 1, readOnly: false, expectation };
    const input = protocolSecurityInputSchema.parse({ schemaVersion: 1, actors: [actor], cases: [value] });
    expect(() => planProtocolSecurity(input, { target, scope: { ...defaultScope, allowedMethods: ["GET", "POST"] } })).toThrow(/requires authorization and cleanup/i);
  });
});
