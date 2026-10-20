import { it, expect } from "vitest";
import { generateKeyPairSync, createHash, sign, randomUUID } from "node:crypto";
import { buildTransitionEvidence } from "../../src/dashboard/execution/ApplicationTransitionEvidence.js";
import {
  transitionDeclarationSchema,
  type TransitionDeclaration
} from "../../src/dashboard/contracts/ApplicationTransitionContracts.js";
import { observedMarkerFingerprint } from "../../src/modules/apiGraphql/ObservedMarker.js";
type Source = Parameters<typeof buildTransitionEvidence>[0];
const fp = (v: string) =>
  createHash("sha256")
    .update("routecairn-identity-v1\0" + v)
    .digest("hex")
    .slice(0, 16);
function fixture() {
  const keys = generateKeyPairSync("ed25519"),
    der = keys.publicKey.export({ format: "der", type: "spki" });
  const event: TransitionDeclaration["event"] = {
    eventId: randomUUID(),
    targetOrigin: "http://127.0.0.1:3456",
    routeId: "source",
    actorId: "primary" as const,
    principalId: "actor-1",
    actorTenantId: "red",
    role: "reviewer",
    resourceValue: 42,
    tenantValue: "red",
    statePath: "business.phase",
    beforeState: "DRAFT",
    afterState: "APPROVED",
    revisionPath: "record.revision",
    fromRevision: 1,
    toRevision: 2,
    occurredAt: "2026-10-18T01:00:02.000Z"
  };
  const make = (side: "BEFORE" | "AFTER") =>
    ({
      row: { id: side, request_json: JSON.stringify({ credentialProfileId: "credential" }) },
      contextDigest: "same-context",
      input: {
        targetId: "target",
        credentials: { primary: "credential" },
        routes: [
          {
            id: "source",
            kind: "OBJECT",
            method: "GET",
            pathTemplate: "/record/42",
            url: event.targetOrigin + "/record/42",
            identityPath: "record.id",
            tenantPath: "record.tenant",
            statePaths: [event.statePath, event.revisionPath]
          }
        ]
      },
      sourceBinding: { mapRevisionId: side },
      status: "COMPLETED",
      scanId: side,
      report: {
        metadata: {
          startedAt: side === "BEFORE" ? "2026-10-18T01:00:00.000Z" : "2026-10-18T01:00:03.000Z",
          completedAt: side === "BEFORE" ? "2026-10-18T01:00:01.000Z" : "2026-10-18T01:00:04.000Z"
        },
        scanPlan: {
          apiGraphql: {
            actors: [
              {
                id: "primary",
                safeAlias: "Primary",
                relationship: "DECLARED_PRIMARY",
                authSlot: "primary",
                principalFingerprint: fp(event.principalId),
                tenantFingerprint: fp(event.actorTenantId),
                role: event.role
              }
            ],
            routes: [
              {
                id: "source",
                safeAlias: "source",
                url: "redacted://source",
                urlFingerprint: createHash("sha256")
                  .update(event.targetOrigin + "/record/42")
                  .digest("hex"),
                path: "/record/42",
                protocol: "REST"
              }
            ],
            checks: [
              {
                id: "source-observe-primary",
                actorId: "primary",
                routeId: "source",
                kind: "OBJECT_AUTHORIZATION",
                requireVerifiedIdentity: true,
                comparisonFingerprint: "a".repeat(64),
                request: { method: "GET" },
                response: {
                  expectedDecision: "OBSERVE",
                  observationPaths: ["record.id", "record.tenant", "business.phase", "record.revision"]
                }
              }
            ]
          }
        },
        identityVerification: {
          primary: {
            verified: true,
            principalMatched: true,
            roleMatched: true,
            tenantMatched: true,
            principalHash: fp(event.principalId),
            tenantHash: fp(event.actorTenantId),
            roleHash: fp(event.role)
          }
        },
        apiGraphql: {
          checks: [
            {
              checkId: "source-observe-primary",
              actorId: "primary",
              authSlot: "primary",
              routeIds: ["source"],
              actorAlias: "Primary",
              actorRelationship: "DECLARED_PRIMARY",
              routeAliases: ["source"],
              kind: "OBJECT_AUTHORIZATION",
              comparisonFingerprint: "a".repeat(64),
              outcome: "PASS",
              requests: [{ decision: "ALLOWED", method: "GET", statusCode: 200 }],
              observedMarkers: Object.entries({
                "record.id": 42,
                "record.tenant": "red",
                "business.phase": side === "BEFORE" ? "DRAFT" : "APPROVED",
                "record.revision": side === "BEFORE" ? 1 : 2
              }).map(([path, v]) => ({ path, scalarType: typeof v, valueFingerprint: observedMarkerFingerprint(v) }))
            }
          ]
        }
      }
    }) as unknown as Source;
  const before = make("BEFORE"),
    after = make("AFTER");
  const seal = (e = event) => {
    // Independent flat-event encoder: no product signing helper is called here.
    const bytes = Buffer.from(
      "routecairn-target-transition-event-v1\n" +
        JSON.stringify(
          Object.fromEntries(
            Object.keys(e)
              .sort()
              .map((k) => [k, e[k as keyof typeof e]])
          )
        )
    );
    return {
      beforeMapRevisionId: randomUUID(),
      policy: "LEGITIMATE" as const,
      purpose: "Explicit synthetic operator state observation review",
      authorityKeySha256: createHash("sha256").update(der).digest("hex"),
      publicKeySpki: der.toString("base64"),
      signature: sign(null, bytes, keys.privateKey).toString("base64"),
      event: e
    };
  };
  return { before, after, event, seal };
}
it("binds an independently encoded Ed25519 event without promoting a self-signature to authority or findings", () => {
  const f = fixture(),
    r = buildTransitionEvidence(f.before, f.after, transitionDeclarationSchema.parse(f.seal()));
  expect(r.signatureVerified).toBe(true);
  expect(r.eligibility).toBe("EVIDENCE_READY_FOR_POLICY_REVIEW");
  expect(r.eventEvidence).toBe("SIGNATURE_VALID_AUTHORITY_UNCONFIRMED");
  expect(r.policyOutcome).toBe("PROPOSED_LEGITIMATE_REQUIRES_AUTHORITY_REVIEW");
  expect(r.findingsInferred).toBe(false);
  expect(r.stateChangingExecution).toBe("HOLD");
});
for (const scenario of [
  "wrong-tenant",
  "concurrent-revision",
  "stale-revision",
  "precondition-mismatch",
  "incomplete-identity",
  "role-reassignment",
  "contradictory-type",
  "tampered-signature",
  "wrong-authority-key",
  "unbracketed-event"
])
  it("abstains on " + scenario, () => {
    const f = fixture();
    let declaration = f.seal();
    const primary = f.after.report!.apiGraphql!.checks[0]!;
    const marker = (p: string, v: string | number) => {
      const m = primary.observedMarkers!.find((m) => m.path === p)!;
      m.valueFingerprint = observedMarkerFingerprint(v);
      m.scalarType = typeof v as "string" | "number";
    };
    if (scenario === "wrong-tenant") marker("record.tenant", "blue");
    if (scenario === "concurrent-revision") marker("record.revision", 3);
    if (scenario === "stale-revision") f.after.row.id = f.before.row.id!;
    if (scenario === "precondition-mismatch")
      f.before.report!.apiGraphql!.checks[0]!.observedMarkers!.find(
        (m) => m.path === "business.phase"
      )!.valueFingerprint = observedMarkerFingerprint("OTHER");
    if (scenario === "incomplete-identity")
      primary.observedMarkers = primary.observedMarkers!.filter((m) => m.path !== "record.id");
    if (scenario === "role-reassignment") f.after.report!.scanPlan.apiGraphql!.actors[0]!.role = "other";
    if (scenario === "contradictory-type") marker("business.phase", 1);
    if (scenario === "tampered-signature")
      declaration = { ...declaration, event: { ...f.event, afterState: "TAMPERED" } };
    if (scenario === "wrong-authority-key") declaration = { ...declaration, authorityKeySha256: "0".repeat(64) };
    if (scenario === "unbracketed-event") declaration = f.seal({ ...f.event, occurredAt: "2026-10-18T01:00:05.000Z" });
    const r = buildTransitionEvidence(f.before, f.after, declaration);
    expect(r.eligibility).toBe("ABSTAIN");
    expect(r.missingControls.length).toBeGreaterThan(0);
    expect(r.policyOutcome).toBe("INCONCLUSIVE");
    expect(r.findingsInferred).toBe(false);
  });

it("abstains when signed numeric states differ only by JSON-canonical negative zero", () => {
  const f = fixture(),
    declaration = f.seal({ ...f.event, beforeState: 0, afterState: -0 });
  for (const source of [f.before, f.after]) {
    const marker = source.report!.apiGraphql!.checks[0]!.observedMarkers!.find((m) => m.path === "business.phase")!;
    marker.scalarType = "number";
    marker.valueFingerprint = observedMarkerFingerprint(0);
  }
  expect(JSON.stringify(declaration.event.afterState)).toBe("0");
  expect(observedMarkerFingerprint(0)).toBe(observedMarkerFingerprint(-0));
  const r = buildTransitionEvidence(f.before, f.after, declaration);
  expect(r.signatureVerified).toBe(true);
  expect(r.eligibility).toBe("ABSTAIN");
  expect(r.missingControls).toContain("SINGLE_DISTINCT_MONOTONIC_TRANSITION_REQUIRED");
});
