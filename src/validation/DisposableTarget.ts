import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export interface DisposableUser { id: string; username: string; password: string; role: "member" | "admin"; balance: number }

/** Deliberately vulnerable, ephemeral validation application. It cannot bind a non-loopback address. */
export async function startDisposableTarget() {
  const users: DisposableUser[] = ["a", "b"].map((id) => ({ id: `fixture-${id}`, username: `${id}@fixture.test`, password: randomBytes(24).toString("base64url"), role: "member", balance: 100 }));
  const sessions = new Map<string, DisposableUser>();
  const calls: Array<{ method: string; path: string }> = [];
  const timers = new Set<ReturnType<typeof setTimeout>>();
  let fixed = false; let cleanupFails = false; let staleReads = 0;
  const pending = new Set<string>();
  const server = createServer((request, response) => { void handle(request, response).catch(() => { if (!response.headersSent) json(response, 400, { error: "Invalid fixture request" }); else response.end(); }); });
  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    const method = request.method ?? "GET";
    calls.push({ method, path });
    if (calls.length > 2000) { json(response, 429, { error: "Fixture request ceiling" }); return; }
    response.setHeader("cache-control", "no-store");
    if (path === "/environment") { json(response, 200, { environment: "LOCAL", disposable: true }); return; }
    if (path === "/login" && method === "GET") { html(response, '<form method="post" action="/session"><input name="username"><input name="password" type="password"><button type="submit">Sign in</button></form>'); return; }
    if (path === "/session" && method === "POST") {
      const fields = new URLSearchParams(await readBody(request));
      const user = users.find((item) => item.username === fields.get("username") && item.password === fields.get("password"));
      if (!user) { json(response, 401, { error: "Invalid credentials" }); return; }
      const session = randomBytes(32).toString("base64url"); sessions.set(session, user);
      response.writeHead(303, { location: "/app", "set-cookie": `fixture_session=${session}; HttpOnly; SameSite=Strict; Path=/` }).end(); return;
    }
    if (path === "/") { html(response, '<a href="/login">Disposable RouteCairn validation fixture</a>'); return; }
    const cookie = request.headers.cookie?.split(";").map((part) => part.trim()).find((part) => part.startsWith("fixture_session="))?.slice("fixture_session=".length);
    const user = cookie ? sessions.get(cookie) : undefined;
    if (!user) { json(response, 401, { error: "Authentication required" }); return; }
    if (path === "/me") { json(response, 200, { id: user.id, role: user.role, disposable: true }); return; }
    if (path === "/settings" && method === "GET") { if (pending.has(user.id)) staleReads++; json(response, 200, { id: `settings-${user.id}`, ownerId: user.id, role: user.role, disposable: true }); return; }
    if (path === "/settings" && method === "PATCH") {
      const body = JSON.parse(await readBody(request)) as { role?: unknown };
      if (!Object.keys(body).every((key) => key === "role") || !["member", "admin"].includes(String(body.role))) { json(response, 400, { error: "Invalid field" }); return; }
      if (body.role === "member" && cleanupFails) { json(response, 503, { error: "Injected cleanup failure" }); return; }
      pending.add(user.id);
      const timer = setTimeout(() => { user.role = body.role as "member" | "admin"; pending.delete(user.id); timers.delete(timer); }, 80);
      timers.add(timer); json(response, 202, { accepted: true }); return;
    }
    if (path === "/protected") { json(response, user.role === "admin" ? 200 : 403, { allowed: user.role === "admin" }); return; }
    if (path === "/wallet") { json(response, 200, { balance: user.balance }); return; }
    if (path === "/withdraw" && method === "POST") { const fields = JSON.parse(await readBody(request)) as { amount: number }; if (fields.amount !== 150) { json(response, 400, { accepted: false }); return; } if (fixed) { json(response, 409, { accepted: false }); return; } user.balance -= fields.amount; json(response, 200, { accepted: true }); return; }
    if (path === "/restore-wallet" && method === "POST") { user.balance = 100; response.writeHead(204).end(); return; }
    if (path === "/app" || path === "/admin") { html(response, `<span id="principal">${user.id}</span>${user.role === "admin" ? '<span id="premium">Premium capability</span>' : ""}<input name="displayName"><input name="immutableId" readonly><a id="admin-link" href="/admin">Administration</a><script>fetch('/me');fetch('/unsafe',{method:'POST'}).catch(()=>{});</script>`); return; }
    json(response, 404, { error: "Not found" });
  }
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    origin, users, calls,
    setFixed(value: boolean) { fixed = value; },
    setCleanupFailure(value: boolean) { cleanupFails = value; },
    snapshot() { return { users: users.map((user) => ({ id: user.id, role: user.role, balance: user.balance })), staleReads, pendingUpdates: pending.size }; },
    async login(index: number) {
      const user = users[index]; if (!user) throw new Error("FIXTURE_ACTOR_UNKNOWN");
      const response = await fetch(`${origin}/session`, { method: "POST", body: new URLSearchParams({ username: user.username, password: user.password }), redirect: "manual" });
      const cookie = response.headers.get("set-cookie")?.split(";")[0];
      if (response.status !== 303 || !cookie) throw new Error("FIXTURE_LOGIN_FAILED");
      return cookie;
    },
    async close() { for (const timer of timers) clearTimeout(timer); timers.clear(); pending.clear(); sessions.clear(); for (const user of users) user.password = ""; server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
  };
}

function json(response: ServerResponse, status: number, body: unknown) { response.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body)); }
function html(response: ServerResponse, body: string) { response.writeHead(200, { "content-type": "text/html" }).end(`<!doctype html><html><body>${body}</body></html>`); }
async function readBody(request: IncomingMessage): Promise<string> { const chunks: Buffer[] = []; let size = 0; for await (const chunk of request) { const bytes = Buffer.from(chunk); size += bytes.length; if (size > 8192) throw new Error("FIXTURE_BODY_LIMIT"); chunks.push(bytes); } return Buffer.concat(chunks).toString("utf8"); }
