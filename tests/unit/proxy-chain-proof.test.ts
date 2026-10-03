import { describe, expect, it, vi } from "vitest";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";
import { protocolSecurityInputSchema, planProtocolSecurity } from "../../src/modules/protocolSecurity/ProtocolSecurityPlanner.js";
import { executeProtocolSecurity } from "../../src/modules/protocolSecurity/ProtocolSecurityModule.js";
import { testPlan } from "../helpers/plan.js";
import type { HttpRequest } from "../../src/core/http/HttpTypes.js";

describe("proxy-chain proof threshold", () => {
  for (const mode of ["absent", "wrong-trace", "wrong-digest", "stale", "accepted-clean", "rejected", "proven"] as const) it(mode, async () => {
    const origin = "http://127.0.0.1:43119"; const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "POST"] as const };
    const profile = authProfileSchema.parse({ label: "lab", headers: {}, lifecycleSecrets: { fixture: "bounded" } });
    const contract = { url: `${origin}/proof`, deploymentSha256: "a".repeat(64), hopIds: ["front", "back"], traceHeader: "x-hop-trace" };
    const input = protocolSecurityInputSchema.parse({ maxRequests: 4, actors: [{ id: "actor", safeAlias: "lab", authSlot: "primary", relationship: "owned" }], cases: [{ id: "chain", label: "chain", actorId: "actor", requireVerifiedIdentity: false, kind: "PROXY_CHAIN_DESYNCHRONIZATION", url: `${origin}/probe`, method: "POST", bodySecretRef: "fixture", framing: "CL_TE", declaredLengthDelta: 1, sentinelPath: "/sentinel", frontendProtocols: ["H1"], proxyChain: [{ origin, protocol: "H1" }, { origin, protocol: "H1" }], ...(mode !== "absent" ? { topologyProof: contract } : {}), authorization: { environment: "LOCAL", operator: "owner", ticket: "test", authorizedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString(), confirmation: "I_AUTHORIZE_BOUNDED_PROTOCOL_DESYNCHRONIZATION" }, expectation: { decision: "OBSERVE", allowedStatuses: [200], deniedStatuses: [400], minMessages: 0 } }] });
    const protocol = planProtocolSecurity(input, { target: origin, scope, authProfile: profile }); const context = new ScanContext({ target: origin, scope, config: defaultConfig, authProfile: profile, plan: { ...testPlan("quick", { scope }), protocolSecurity: protocol }, outputDir: ".routecairn-active-lab" });
    const broker = context.createApiGraphqlHttpClient(4, 4096); let readCount = 0;
    const send = vi.spyOn(broker, "send").mockImplementation(async (request: HttpRequest) => { readCount++; const value = { deploymentSha256: mode === "wrong-digest" ? "b".repeat(64) : contract.deploymentSha256, canary: mode === "stale" ? "stale" : new URL(request.url).searchParams.get("routecairn_canary"), hopIds: contract.hopIds, sentinel: readCount === 2, violation: mode === "proven" && readCount === 2 }; const text = JSON.stringify(value); return { requestedUrl: request.url, finalUrl: request.url, method: "GET", statusCode: 200, headers: { "x-hop-trace": mode === "wrong-trace" ? "front" : "front,back" }, bodyPreview: text, responseTimeMs: 0, redirectChain: [] }; });
    const raw = vi.spyOn(broker, "sendRawHttp1").mockResolvedValue({ requestedUrl: `${origin}/probe`, statusCodes: mode === "rejected" ? [400] : [200, 200], responseCount: mode === "rejected" ? 1 : 2, bodyPreview: "", bodyHash: "a".repeat(64), responseTimeMs: 1, transmittedRequests: 2, markerObserved: true });
    vi.spyOn(context, "createApiGraphqlHttpClient").mockReturnValue(broker);
    try { const report = await executeProtocolSecurity(context); const observation = report.observations[0]!; expect(observation.outcome).toBe(mode === "proven" ? "FAIL" : mode === "rejected" ? "PASS" : "INCONCLUSIVE"); if (["absent", "wrong-trace", "wrong-digest", "stale"].includes(mode)) expect(raw).not.toHaveBeenCalled(); if (mode === "absent") expect(send).not.toHaveBeenCalled(); } finally { await context.dispose(); }
  });
});
