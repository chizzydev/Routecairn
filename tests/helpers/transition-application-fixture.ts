import { generateKeyPairSync, createHash, sign } from "node:crypto";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { roleflowApplicationFixture } from "./roleflow-application-fixture.js";
import { transitionEventBytes } from "../../src/dashboard/execution/ApplicationTransitionEvidence.js";
import type { TransitionDeclaration } from "../../src/dashboard/contracts/ApplicationTransitionContracts.js";
export async function transitionApplicationFixture(application: "procurement" | "membership") {
  const control: {
    revision: number;
    values: Record<string, string | number>;
    events: Map<string, unknown>;
    resourceTenant?: string;
    actorRoles?: Record<string, string>;
    actorValues?: Record<string, Record<string, string | number>>;
    delayBusinessResponseMs?: number;
  } = { revision: 1, values: {}, events: new Map() };
  const f = await roleflowApplicationFixture(application, "vulnerable", undefined, control),
    keys = generateKeyPairSync("ed25519"),
    der = keys.publicKey.export({ format: "der", type: "spki" }),
    publicKeySpki = der.toString("base64"),
    authorityKeySha256 = createHash("sha256").update(der).digest("hex");
  f.mappingInput.routes = f.mappingInput.routes.filter((r) => f.workflow.routeIds.includes(r.id));
  writeFileSync(
    join(f.root, "TARGET_AUTHORITY_BEFORE_REQUESTS.json"),
    JSON.stringify({
      application,
      publicKeySpki,
      authorityKeySha256,
      wireRequestsAtRegistration: f.wire.length,
      authority: "Owned fixture operator provisioned public-key trust; independent of uploaded event content",
      privateKeyPersisted: false
    }),
    { flag: "wx" }
  );
  const apply = async (actorId: TransitionDeclaration["event"]["actorId"] = "primary") => {
    const route = f.mappingInput.routes.find((r) => r.id === (application === "procurement" ? "source" : "consent"))!,
      statePath = route.statePaths![0]!,
      beforeState = application === "procurement" ? 1 : "ENDORSED",
      afterState = application === "procurement" ? 2 : "WITHDRAWN",
      slot = actorId.replaceAll("-", "_") as keyof typeof f.credentials,
      identity = f.vault.getSummary(f.credentials[slot], f.org)!.safeIdentitySummary;
    const event: TransitionDeclaration["event"] = {
      eventId: randomUUID(),
      targetOrigin: f.origin,
      routeId: route.id,
      actorId,
      principalId: String(identity.principalId),
      actorTenantId: String(identity.tenantId),
      role: String(identity.role),
      resourceValue: application === "procurement" ? 42 : "member-7",
      tenantValue: "workspace-red",
      statePath,
      beforeState,
      afterState,
      revisionPath: "record.revision",
      fromRevision: control.revision,
      toRevision: control.revision + 1,
      occurredAt: new Date().toISOString()
    };
    control.values[statePath] = afterState;
    control.revision++;
    const signed = {
      publicKeySpki,
      signature: sign(null, transitionEventBytes(event), keys.privateKey).toString("base64"),
      event
    };
    const endpoint = "/target-events/" + event.eventId;
    control.events.set(endpoint, signed);
    const response = await fetch(f.origin + endpoint, { headers: { authorization: "Bearer numeric-primary" } }),
      bytes = await response.text();
    if (response.status !== 200) throw Error("TARGET_EVENT_FIXTURE_UNAVAILABLE");
    writeFileSync(join(f.root, "TARGET_EVENT_" + event.eventId + ".json"), bytes, { flag: "wx" });
    writeFileSync(
      join(f.root, "TARGET_HTTP_EVENT_RECEIPT_" + event.eventId + ".json"),
      JSON.stringify({
        endpoint,
        method: "GET",
        status: response.status,
        at: new Date().toISOString(),
        sha256: createHash("sha256").update(bytes).digest("hex"),
        applicationMutation: "DIRECT_OWNED_FIXTURE_MODEL_ONLY_OUTSIDE_PRODUCT_DISPATCH",
        productRequestsDuringModelChange: 0
      }),
      { flag: "wx" }
    );
    return { signed: JSON.parse(bytes) as typeof signed, authorityKeySha256 };
  };
  const declaration = (
    beforeMapRevisionId: string,
    signed: Awaited<ReturnType<typeof apply>>,
    policy: "LEGITIMATE" | "FORBIDDEN" = "LEGITIMATE"
  ) => ({
    beforeMapRevisionId,
    ...signed.signed,
    authorityKeySha256: signed.authorityKeySha256,
    policy,
    purpose:
      "Review the exact owner-controlled state change and bounded role observations without executing a transition."
  });
  const reviewFor = (p: Parameters<typeof f.reviewFor>[0] & { transition?: unknown }) => ({
    ...f.reviewFor(p),
    transitionReview: {
      authorityConfirmed: true,
      authorityKeySha256,
      checks: f.workflow.routeIds.flatMap((routeId) =>
        ["primary", "account-a", "account-b", "anonymous"].map((actorId) => ({
          routeId,
          actorId,
          purpose:
            "Observe the pinned postcondition of " + routeId + " as " + actorId + " under declared target policy.",
          consent: true
        }))
      )
    }
  });
  return { ...f, control, apply, declaration, transitionReviewFor: reviewFor, authorityKeySha256, publicKeySpki };
}
