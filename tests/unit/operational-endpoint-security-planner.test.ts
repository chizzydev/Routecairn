import { describe, expect, it } from "vitest";
import type { AuthProfile } from "../../src/core/auth/AuthProfile.js";
import { exampleScope } from "../../src/config/defaults.js";
import { operationalEndpointSecurityInputSchema, planOperationalEndpointSecurity } from "../../src/modules/operationalEndpointSecurity/OperationalEndpointSecurityPlanner.js";

const service: AuthProfile = { label: "service", safeAlias: "service", principalId: "service-principal", headers: { Authorization: "Bearer service-credential-private" }, cookies: [], identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, lifecycleSecrets: { webhook_secret: "webhook-hmac-private", timestamp: "1700000000", event_id: "event-private", expected_amount: "1250", expected_currency: "USD", expected_product: "premium-plan" }, notes: [] };
const context = { target: "https://ops.example.test/", scope: { ...exampleScope, allowedDomains: ["ops.example.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST", "DELETE"] as const }, authProfile: service, now: new Date("2026-08-30T12:00:00.000Z") };

describe("operational endpoint security planner", () => {
  it("plans exact-body HMAC validation without retaining credentials or HMAC output", () => {
    const plan = planOperationalEndpointSecurity(operationalEndpointSecurityInputSchema.parse(validInput()), context);
    expect(plan).toMatchObject({ enabled: true, actors: [{ authSlot: "anonymous" }], endpoints: [{ kind: "WEBHOOK" }], cases: [{ category: "WEBHOOK_SIGNATURE_REJECTION" }] });
    expect(plan.cases[0]?.comparisonFingerprint).toHaveLength(64);
    expect(JSON.stringify(plan)).not.toContain("webhook-hmac-private");
    expect(JSON.stringify(plan)).not.toContain("service-credential-private");
  });

  it("rejects manual sensitive fields, unmatched signature pairs, and unapproved mutations", () => {
    const literal: any = validInput(); literal.cases[0].steps[0].request.fields.amount = "1250";
    expect(() => planOperationalEndpointSecurity(operationalEndpointSecurityInputSchema.parse(literal), context)).toThrow(/must use a secret reference/i);

    const mismatch: any = validInput(); mismatch.cases[0].steps[1].request.fields.event = "different-event";
    expect(() => planOperationalEndpointSecurity(operationalEndpointSecurityInputSchema.parse(mismatch), context)).toThrow(/same request/i);

    const authorization: any = validInput(); authorization.cases[0].authorization = { mode: "OBSERVE_ONLY", environment: "TEST", disposableTarget: true };
    expect(() => planOperationalEndpointSecurity(operationalEndpointSecurityInputSchema.parse(authorization), context)).toThrow(/controlled authorization/i);
  });

  it("requires exact replay, authoritative idempotency bounds, and complete payload verification", () => {
    const replay: any = validInput(); replay.cases[0].category = "WEBHOOK_REPLAY_PROTECTION"; replay.cases[0].steps[1].request.fields.event = "other"; replay.cases[0].steps[1].request.hmac.tamper = false;
    expect(() => planOperationalEndpointSecurity(operationalEndpointSecurityInputSchema.parse(replay), context)).toThrow(/identical ordered attempts/i);

    const idempotency: any = validInput(); idempotency.cases[0].category = "WEBHOOK_IDEMPOTENCY"; idempotency.cases[0].steps[1].request.hmac.tamper = false;
    expect(() => planOperationalEndpointSecurity(operationalEndpointSecurityInputSchema.parse(idempotency), context)).toThrow(/numeric-delta/i);

    const payload: any = validInput(); payload.cases[0].category = "WEBHOOK_PAYLOAD_INTEGRITY"; payload.cases[0].steps = [payload.cases[0].steps[0], { id: "verify", phase: "VERIFY", actorId: "public", endpointId: "webhook", request: { method: "GET", urlTemplate: "https://ops.example.test/state", secretSource: "anonymous" }, assertions: [{ kind: "JSON_EQUALS_SECRET", path: "amount", secretSource: "primary", secretRef: "expected_amount" }] }];
    expect(() => planOperationalEndpointSecurity(operationalEndpointSecurityInputSchema.parse(payload), context)).toThrow(/amount, currency, and product/i);
  });

  it("rejects Account A/B aliasing before an authorization matrix can execute", () => {
    const account = { ...service, principalId: "same-principal" };
    const input: any = validInput();
    input.actors.push({ id: "owner", safeAlias: "owner", authSlot: "account_a", relationship: "OWNER" }, { id: "foreign", safeAlias: "foreign", authSlot: "account_b", relationship: "FOREIGN" });
    expect(() => planOperationalEndpointSecurity(operationalEndpointSecurityInputSchema.parse(input), { ...context, authProfileSet: { accountA: account, accountB: account } })).toThrow(/different principals|different authentication material/i);
  });

  it("changes the contract fingerprint when an operational decision changes", () => {
    const before = planOperationalEndpointSecurity(operationalEndpointSecurityInputSchema.parse(validInput()), context).cases[0]!.comparisonFingerprint;
    const changed: any = validInput(); changed.cases[0].steps[1].assertions[0].expected = "ALLOW";
    const after = planOperationalEndpointSecurity(operationalEndpointSecurityInputSchema.parse(changed), context).cases[0]!.comparisonFingerprint;
    expect(after).not.toBe(before);
  });
});

function validInput(): unknown {
  const authorization = { mode: "CONTROLLED_OPERATIONAL_FLOW", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_OPERATIONAL_ENDPOINT_TESTING", authorizedBy: "operator", changeTicket: "OPS-1", authorizedAt: "2026-08-30T11:00:00.000Z", expiresAt: "2026-08-30T13:00:00.000Z", disposableTarget: true };
  const request = (tamper: boolean) => ({ method: "POST", urlTemplate: "https://ops.example.test/webhooks/payments", stateChanging: true, secretSource: "primary", bodyFormat: "JSON", fields: { event: "payment.updated", eventId: "{{SECRET:event_id}}", amount: "{{SECRET:expected_amount}}" }, hmac: { kind: "HMAC", algorithm: "sha256", secretSource: "primary", secretRef: "webhook_secret", header: "X-Signature", encoding: "HEX", prefix: "sha256=", messageFormat: "TIMESTAMP_DOT_BODY", timestampHeader: "X-Timestamp", timestampSecretRef: "timestamp", tamper } });
  return { schemaVersion: 1, maxRequests: 10, actors: [{ id: "public", safeAlias: "public", authSlot: "anonymous", relationship: "WEBHOOK_SENDER" }], endpoints: [{ id: "webhook", safeAlias: "payment-webhook", kind: "WEBHOOK", pathTemplate: "/webhooks/payments", allowedOrigins: ["https://ops.example.test"] }], cases: [{ id: "signature", label: "signature rejection", category: "WEBHOOK_SIGNATURE_REJECTION", authorization, steps: [{ id: "valid", phase: "ACTION", actorId: "public", endpointId: "webhook", request: request(false), assertions: [{ kind: "DECISION", expected: "ALLOW" }] }, { id: "tampered", phase: "VERIFY", actorId: "public", endpointId: "webhook", request: request(true), assertions: [{ kind: "DECISION", expected: "DENY" }] }] }] };
}
