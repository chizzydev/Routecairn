import { createServer } from "node:http";
import { heldOutApplicationFixture } from "./heldout-application-fixture.js";
import type { ApplicationMappingInput } from "../../src/dashboard/contracts/ApplicationMappingContracts.js";
export type DeepMode =
  | "vulnerable"
  | "shared"
  | "missing-producer"
  | "stale-version"
  | "tenant-drift"
  | "typed-disagreement"
  | "missing-reference"
  | "duplicate-reference";
export async function deepBusinessFixture(steps: 3 | 4 = 4, mode: DeepMode = "vulnerable", prepare = true) {
  const ids = ["request", "quote", "invoice", "receipt"].slice(0, steps),
    prefix = "/business/";
  const actors = {
    primary: { principal: "request-owner", tenant: "north", role: "owner" },
    account_a: { principal: "billing-reviewer", tenant: "north", role: "reviewer" },
    account_b: { principal: "other-reviewer", tenant: "south", role: "reviewer" }
  };
  const cases = ids.map((id, i) => ({
    id,
    suffix: id + "/" + (i + 1) * 10,
    path: prefix + id + "/" + (i + 1) * 10,
    ref: String((i + 1) * 10),
    policy: i === steps - 1 ? ["primary"] : ["primary", "account_a", "account_b"],
    kind: "OBJECT"
  }));
  const wire: { method: string; path: string; actor: string; status: number; at: number }[] = [];
  let fixed = false;
  const server = createServer((req, res) => {
    const path = req.url ?? "/",
      actor =
        Object.keys(actors).find((a) => req.headers.authorization === "Bearer heldout-ledger-" + a) ?? "anonymous",
      person = actors[actor as keyof typeof actors],
      i = cases.findIndex((c) => c.path === path);
    let status = 200;
    let body: unknown = { application: "Owned four-stage procurement review" };
    if (req.method !== "GET") status = 405;
    else if (path === "/identity") {
      status = person ? 200 : 401;
      body = person ?? {};
    } else if (i >= 0) {
      if (!person) status = 401;
      else if (
        (mode === "missing-producer" && i === 1 && actor === "primary") ||
        (fixed && i === steps - 1 && actor !== "primary")
      )
        status = 403;
      else {
        const record: Record<string, unknown> = {
          id: (i + 1) * 10,
          tenant: "north",
          version: i + 1,
          ...(i ? { parent: i * 10 } : { phase: "REVIEWED" })
        };
        if (actor !== "primary" && i === 2) {
          if (mode === "stale-version") record.version = 0;
          if (mode === "tenant-drift") record.tenant = "south";
        }
        if (i === 2 && mode === "typed-disagreement") record.parent = String(i * 10);
        if (i === 2 && mode === "duplicate-reference") record.parent = [i * 10, i * 10];
        if (i === 2 && mode === "missing-reference") delete record.parent;
        body = { record };
      }
    } else if (path !== "/") status = 404;
    wire.push({ method: req.method ?? "", path, actor, status, at: Date.now() });
    res.writeHead(status, { "content-type": "application/json", connection: "close" });
    res.end(JSON.stringify(body));
  });
  const f = await heldOutApplicationFixture("ledger", prepare, () => ({
    server,
    wire,
    prefix,
    cases,
    actors,
    identityPath: "record.id",
    tenantPath: "record.tenant",
    marker: (ref: string) => ({ record: { id: ref, tenant: "north" } }),
    setFixed: () => {
      fixed = true;
    },
    setExpiredIdentity: () => {
      throw Error("UNSUPPORTED");
    }
  }));
  const input: ApplicationMappingInput = {
    targetId: f.targetId,
    credentials: f.credentials,
    identityContextConfirmed: true,
    readOnlyRoutesConfirmed: true,
    routes: cases.map((c, i) => ({
      id: c.id,
      kind: "OBJECT",
      method: "GET",
      url: f.origin + c.path,
      pathTemplate: c.path,
      identityPath: "record.id",
      tenantPath: "record.tenant",
      statePaths: i ? ["record.parent", "record.version"] : ["record.phase", "record.version"]
    }))
  };
  const workflow = {
    name: "Procurement review to retained receipt",
    routeIds: ids,
    relationships: ids.slice(1).map((id, i) => ({
      name: "Exact entity reference " + i,
      producer: ids[i]!,
      consumer: id,
      identifier: "record.id",
      reference: "record.parent",
      producerVersion: "record.version",
      consumerVersion: "record.version"
    }))
  };
  const reviewFor = (p: { digest: string; flow?: { flowId: string } }) => ({
    action: "REVIEW_FLOW" as const,
    digest: p.digest,
    candidateId: p.flow!.flowId,
    policyConfirmed: true as const,
    ownershipConfirmed: true as const,
    relationshipExplanation:
      "Owner separately confirms exact entity, tenant, role and reference policy; these GETs do not prove causal state transitions.",
    expectations: input.routes.map((r, i) => ({
      routeId: r.id,
      url: r.url,
      kind: "TENANT_ISOLATION" as const,
      explanation: "Owner-declared read-only procurement actor policy for this precise entity version.",
      decisions: {
        primary: "ALLOW" as const,
        "account-a": i === steps - 1 && mode !== "shared" ? ("DENY" as const) : ("ALLOW" as const),
        "account-b": i === steps - 1 && mode !== "shared" ? ("DENY" as const) : ("ALLOW" as const),
        anonymous: "DENY" as const
      },
      identity: { path: "record.id", expectedValue: (i + 1) * 10 },
      tenant: { path: "record.tenant", expectedValue: "north" },
      states: i
        ? [
            { path: "record.parent", expectedValue: i * 10 },
            { path: "record.version", expectedValue: i + 1 }
          ]
        : [
            { path: "record.phase", expectedValue: "REVIEWED" },
            { path: "record.version", expectedValue: i + 1 }
          ],
      dependsOn: i ? [ids[i - 1]!] : []
    }))
  });
  return {
    ...f,
    input,
    workflow,
    reviewFor,
    async fix() {
      f.setFixed();
    }
  };
}
