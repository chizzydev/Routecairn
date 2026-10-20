import { businessFlowApplication, type BusinessMode } from "./businessflow-application.js";
import { businessFlowPythonFixture } from "./businessflow-python-fixture.js";
import { heldOutApplicationFixture } from "./heldout-application-fixture.js";
import type { ApplicationMappingInput } from "../../src/dashboard/contracts/ApplicationMappingContracts.js";
export async function businessFlowFixture(kind: "orders" | "care", mode: BusinessMode = "vulnerable", prepare = true) {
  const node = kind === "orders" ? businessFlowApplication(mode) : undefined;
  const python = kind === "care" ? await businessFlowPythonFixture(mode) : undefined;
  const f = python ?? (await heldOutApplicationFixture("ledger", prepare, () => node!));
  const input: ApplicationMappingInput = {
    targetId: f.targetId,
    credentials: f.credentials,
    identityContextConfirmed: true,
    readOnlyRoutesConfirmed: true,
    routes: f.cases.map((c, i) => ({
      id: c.id,
      url: f.origin + c.path,
      pathTemplate: c.path,
      kind: "OBJECT",
      method: "GET",
      identityPath: f.identityPath,
      tenantPath: f.tenantPath,
      statePaths: i ? ["record.parent", "record.version"] : ["record.version", "record.phase"]
    }))
  };
  const workflow = {
    name: kind === "orders" ? "Order approval to invoice preview" : "Care episode to claim document",
    routeIds: ["source", "consumer"],
    relationships: [
      {
        name: kind === "orders" ? "Invoice references approved order" : "Claim references care episode",
        producer: "source",
        consumer: "consumer",
        identifier: "record.id",
        reference: "record.parent",
        producerVersion: "record.version",
        consumerVersion: "record.version"
      }
    ]
  };
  const reviewFor = (p: { digest: string; flow?: { flowId: string } }) => ({
    action: "REVIEW_FLOW" as const,
    digest: p.digest,
    candidateId: p.flow!.flowId,
    policyConfirmed: true as const,
    ownershipConfirmed: true as const,
    relationshipExplanation:
      "Owner declares these owned test entities are linked and the declared roles may access this exact consumer under these immutable versions.",
    expectations: input.routes.map((r, i) => ({
      routeId: r.id,
      url: r.url,
      kind: "TENANT_ISOLATION" as const,
      explanation: "Owner declares the exact read-only entity, tenant, role and version access policy.",
      decisions: {
        primary: "ALLOW" as const,
        "account-a": !i || mode === "shared" ? ("ALLOW" as const) : ("DENY" as const),
        "account-b": !i || mode === "shared" ? ("ALLOW" as const) : ("DENY" as const),
        anonymous: "DENY" as const
      },
      identity: { path: r.identityPath, expectedValue: i ? 44 : 17 },
      tenant: { path: r.tenantPath!, expectedValue: "north" },
      states: i
        ? [
            { path: "record.parent", expectedValue: 17 },
            { path: "record.version", expectedValue: 3 }
          ]
        : [
            { path: "record.version", expectedValue: 1 },
            { path: "record.phase", expectedValue: "APPROVED" }
          ],
      dependsOn: i ? ["source"] : []
    }))
  });
  return {
    ...f,
    input,
    workflow,
    reviewFor,
    async fix() {
      if (python) await python.setFixedAsync();
      else f.setFixed();
    },
    async close() {
      try {
        await f.close();
      } finally {
        node?.retainDomain();
      }
    }
  };
}
