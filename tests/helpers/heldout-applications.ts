import { createServer } from "node:http";
import { ledgerRead } from "./heldout-ledger-app.js";
import { clinicRead } from "./heldout-clinic-app.js";
import { helpdeskRead } from "./heldout-helpdesk-app.js";
export const applicationFamilies = ["ledger", "clinic", "helpdesk"] as const;
export type ApplicationFamily = (typeof applicationFamilies)[number];
export function heldOutApplication(family: ApplicationFamily) {
  const prefix = family === "ledger" ? "/ledger/" : family === "clinic" ? "/clinic/" : "/desk/";
  const actors = {
    primary: { principal: family + "-manager", tenant: "north", role: "manager" },
    account_a: { principal: family + "-member", tenant: "north", role: "member" },
    account_b: { principal: family + "-guest", tenant: "south", role: "guest" }
  };
  const specs =
    family === "ledger"
      ? ["entries/41", "rates/2026", "balance/current", "reports/annual", "entries/77", "entries/draft"]
      : family === "clinic"
        ? ["patients/83", "teams/4", "schedules/mine", "roster/audit", "patients/91", "attachments/14"]
        : ["tickets/52", "articles/6", "queues/self", "reports/ops", "tickets/93", "drafts/7"];
  const ids = ["restricted", "shared", "personal", "missing", "sealed", "untyped"];
  const cases = specs.map((suffix, i) => ({
    id: ids[i]!,
    suffix,
    path: prefix + suffix,
    ref: family + "-record-" + i,
    policy:
      i === 1 ? ["primary", "account_a", "account_b", ...(family === "helpdesk" ? ["anonymous"] : [])] : ["primary"],
    kind: "OBJECT"
  }));
  const identityPath = family === "ledger" ? "record.entryId" : family === "clinic" ? "chart.number" : "ticket.ref",
    tenantPath = family === "ledger" ? "record.book" : family === "clinic" ? "chart.unit" : "ticket.workspace";
  const marker = (ref: string, tenant = "north") =>
    family === "ledger"
      ? { record: { entryId: ref, book: tenant } }
      : family === "clinic"
        ? { chart: { number: ref, unit: tenant } }
        : { ticket: { ref, workspace: tenant } };
  const wire: { method: string; path: string; actor: string; status: number }[] = [];
  let fixed = false,
    expired = false;
  const server = createServer((req, res) => {
    const path = req.url ?? "/",
      actor =
        Object.keys(actors).find((a) => req.headers.authorization === "Bearer heldout-" + family + "-" + a) ??
        "anonymous",
      person = actors[actor as keyof typeof actors];
    let status = 200,
      body: unknown = {},
      html: string | undefined;
    if (req.method !== "GET") status = 405;
    else if (path === "/identity") {
      status = person && !expired ? 200 : 401;
      body = status === 200 ? person : {};
    } else if (path === prefix + "catalog/start") {
      const links = [
        ...cases.map((c) => c.path),
        prefix + "catalog/pages/2",
        "https://external.invalid/never",
        prefix + "delete",
        prefix + "unsafe?token=x"
      ];
      if (family === "helpdesk")
        html = "<html><body>" + links.map((h) => '<a href="' + h + '">resource</a>').join("") + "</body></html>";
      else
        body =
          family === "ledger"
            ? { ...marker("directory"), accounts: links.map((href) => ({ relationships: { href } })) }
            : { ...marker("directory"), carePlan: { references: links.map((href) => ({ href, method: "GET" })) } };
    } else if (path === prefix + "catalog/pages/2")
      body = { ...marker("page-2"), next: { href: prefix + "catalog/pages/3" } };
    else if (path === prefix + "catalog/pages/3")
      body = { ...marker("page-3"), detail: { href: prefix + "workflow/summary/18" } };
    else if (path === prefix + "workflow/summary/18") body = marker("summary-18");
    else if (path === prefix + "ambiguous")
      html = '<base href="https://external.invalid/"><a href="' + cases[0]!.path + '">ambiguous</a>';
    else if (path === prefix + "redirect") {
      status = 302;
      res.setHeader("location", "https://external.invalid/never");
    } else if (path !== "/") {
      const c = cases.find((c) => c.path === path);
      if (!c) status = 404;
      else if ((!person || expired) && !(family === "helpdesk" && c.id === "shared")) status = 401;
      else if (c.id === "missing" && actor === "primary") status = 503;
      else if (c.id === "personal")
        body = marker(actor === "primary" ? c.ref : family + "-own-" + actor, person?.tenant ?? "public");
      else if (c.id === "untyped") body = { message: "No stable typed resource marker" };
      else {
        status =
          family === "ledger"
            ? ledgerRead(c.ref, actor, person?.tenant ?? "", fixed)
            : family === "clinic"
              ? clinicRead(c.ref, actor, fixed)
              : helpdeskRead(c.ref, actor, fixed);
        if (status === 200) body = marker(c.ref);
      }
    }
    wire.push({ method: req.method ?? "", path, actor, status });
    res.writeHead(status, { "content-type": html ? "text/html" : "application/json", connection: "close" });
    res.end(html ?? JSON.stringify(body));
  });
  return {
    server,
    wire,
    prefix,
    actors,
    cases,
    identityPath,
    tenantPath,
    marker,
    setFixed: () => {
      fixed = true;
    },
    setExpiredIdentity: () => {
      expired = true;
    }
  };
}
