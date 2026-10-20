import { createServer } from "node:http";
import { writeFileSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { createOwnedTestDirectory, retainOwnedTestDirectory } from "./owned-test-directory.js";
export type BusinessMode =
  | "vulnerable"
  | "secure"
  | "wrong-object"
  | "stale-version"
  | "missing-positive"
  | "missing-reference"
  | "shared"
  | "type-confusion";
export function businessFlowMetadata(kind: "orders" | "care") {
  const prefix = kind === "orders" ? "/fulfilment/" : "/care/";
  return {
    prefix,
    identityPath: "record.id",
    tenantPath: "record.tenant",
    actors: {
      primary: { principal: "ledger-manager", tenant: "north", role: "manager" },
      account_a: { principal: "ledger-member", tenant: "north", role: "member" },
      account_b: { principal: "ledger-guest", tenant: "south", role: "guest" }
    },
    cases: [
      {
        id: "source",
        suffix: "source/17",
        path: prefix + "source/17",
        ref: "17",
        policy: ["primary", "account_a", "account_b"],
        kind: "OBJECT"
      },
      {
        id: "consumer",
        suffix: "consumer/44",
        path: prefix + "consumer/44",
        ref: "44",
        policy: ["primary"],
        kind: "OBJECT"
      }
    ],
    marker: (ref: string) => ({ record: { id: ref, tenant: "north" } })
  };
}
/** Independent event-log projection domain; SQL authorization is exercised in the separate Python application. */
export function businessFlowApplication(mode: BusinessMode = "vulnerable") {
  const meta = businessFlowMetadata("orders"),
    root = createOwnedTestDirectory("order-event-domain"),
    events = [
      { type: "ORDER_APPROVED", id: 17, version: 1, tenant: "north" },
      { type: "INVOICE_PREPARED", id: 44, parent: 17, version: 3, tenant: "north" }
    ];
  writeFileSync(join(root, "EVENT_LOG.jsonl"), events.map((e) => JSON.stringify(e)).join("\n") + "\n", { flag: "wx" });
  const wire: { method: string; path: string; actor: string; status: number }[] = [];
  let fixed = mode === "secure";
  const server = createServer((req, res) => {
    const path = req.url ?? "/",
      actor =
        Object.keys(meta.actors).find((a) => req.headers.authorization === "Bearer heldout-ledger-" + a) ?? "anonymous",
      person = meta.actors[actor as keyof typeof meta.actors];
    let status = 200,
      body: unknown = { application: "Event-sourced fulfilment" },
      html: string | undefined;
    if (req.method !== "GET") status = 405;
    else if (path === "/identity") {
      status = person ? 200 : 401;
      body = person ?? {};
    } else if (path === meta.prefix + "catalog/start") {
      body = { record: { id: "directory", tenant: "north" }, links: { related: meta.cases[0]!.path } };
    } else if (path !== "/") {
      const index = meta.cases.findIndex((c) => c.path === path);
      if (index < 0) status = 404;
      else if (!person) status = 401;
      else if (index === 1 && ((mode === "missing-positive" && actor === "primary") || (fixed && actor !== "primary")))
        status = 403;
      else {
        const projected = events.reduce(
            (s, e) => ({ ...s, [e.type]: e }),
            {} as Record<string, (typeof events)[number]>
          ),
          e = projected[index === 0 ? "ORDER_APPROVED" : "INVOICE_PREPARED"]!;
        const record: Record<string, unknown> = {
          id: e.id,
          tenant: e.tenant,
          version: e.version,
          ...(index === 0 ? { phase: "APPROVED" } : { parent: e.parent })
        };
        if (index === 1 && actor !== "primary") {
          if (mode === "wrong-object") {
            record.id = 99;
            record.parent = 31;
          }
          if (mode === "stale-version") record.version = 2;
        }
        if (index === 1 && mode === "missing-reference") delete record.parent;
        if (index === 1 && mode === "type-confusion") record.parent = "17";
        body = { record, links: index === 0 ? { related: meta.cases[1]!.path } : {} };
      }
    }
    wire.push({ method: req.method ?? "", path, actor, status });
    res.writeHead(status, { "content-type": html ? "text/html" : "application/json", connection: "close" });
    res.end(html ?? JSON.stringify(body));
  });
  return {
    ...meta,
    server,
    wire,
    domainRoot: root,
    events,
    setFixed: () => {
      if (mode !== "shared") {
        fixed = true;
        const event = { type: "AUTHORIZATION_REMEDIATED", id: 44, version: 3, tenant: "north" };
        events.push(event);
        appendFileSync(join(root, "EVENT_LOG.jsonl"), JSON.stringify(event) + "\n");
      }
    },
    setExpiredIdentity: () => {
      throw Error("UNSUPPORTED_OWNED_FIXTURE_CONTROL");
    },
    retainDomain: () => retainOwnedTestDirectory(root)
  };
}
