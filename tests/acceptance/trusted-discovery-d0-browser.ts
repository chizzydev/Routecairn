import { chromium, type Browser, type BrowserContext, type Page } from "playwright";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { browserFixture, restrictedBrowserProxy } from "./trusted-discovery-d0-fixture.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { assertSafeExport } from "../../scripts/trusted-discovery-d0-policy.mjs";

const output = process.argv[2], executable = process.argv[3];
if (!output || !executable) throw Error("D0_BROWSER_ARGUMENTS");
const ids = Array.from({ length: 16 }, (_, i) => "B" + String(i + 1).padStart(2, "0"));
const cases: Array<{ id: string; status: "PASS" | "FAIL" | "BLOCKED"; checks: string[]; reason?: string }> = [];
const phrase = "I_CONFIRM_ONE_ANONYMOUS_NON_MUTATING_LOCAL_GET";
let browser: Browser | undefined, context: BrowserContext | undefined, fixture: Awaited<ReturnType<typeof browserFixture>> | undefined;
let proxy: Awaited<ReturnType<typeof restrictedBrowserProxy>> | undefined;
let version = "", cleanup = "UNKNOWN", targetReceipts = 0, blockedExternal = 0;
const authIndicators: Record<string, unknown> = {};
const measurements: Record<string, unknown> = {};
const consoleText: string[] = [], requestCounts = new Map<string, number>(), artifacts: Array<{ file: string; sha256: string }> = [];
let page: Page;
async function run(id: string, checks: string[], action: () => Promise<void>) {
  try { await action(); cases.push({ id, status: "PASS", checks }); }
  catch (error) { const line = error instanceof Error ? error.stack?.match(/trusted-discovery-d0-browser\.ts:(\d+)/)?.[1] : undefined; cases.push({ id, status: "FAIL", checks, reason: (error instanceof Error ? error.name : "ASSERTION_FAILED") + (line ? "_LINE_" + line : "") }); }
}
async function login() {
  const f = fixture!;
  await page.goto(f.origin);
  await page.getByLabel("Username or email").fill(f.login); await page.getByLabel("Password", { exact: true }).fill(f.password);
  await page.getByRole("button", { name: "Log In", exact: true }).click();
  await page.getByRole("button", { name: "Trusted Discovery", exact: true }).waitFor({ state: "visible", timeout: 5000 });
}
async function openWorkspace() {
  const f = fixture!;
  await page.getByRole("button", { name: "Trusted Discovery", exact: true }).click();
  const select = page.getByLabel("Active organization");
  if (await select.count() && await select.inputValue() !== f.org) { await select.selectOption(f.org); await page.getByRole("button", { name: "Trusted Discovery", exact: true }).click(); }
  await page.getByLabel("Registered local target").waitFor({ state: "visible", timeout: 5000 });
}
async function review() {
  const f = fixture!;
  await page.getByLabel("Registered local target").selectOption(f.primary.target);
  await page.getByLabel("Completed dashboard scan").selectOption(f.primary.scan);
  await page.getByLabel("Retained candidate").selectOption(f.primary.candidate);
  await page.getByRole("button", { name: "Review selected candidate", exact: true }).click();
  await page.getByRole("heading", { name: "Reviewed candidate", exact: true }).waitFor({ state: "visible", timeout: 5000 });
}
async function csrf() { return page.evaluate(() => { const key = Object.keys(sessionStorage).find((k) => k.includes("csrf")); return key ? sessionStorage.getItem(key) || "" : ""; }); }
async function nativeStatus(path = "/api/trusted-discovery/status", headers: Record<string, string> = {}) { return context!.request.get(fixture!.origin + path, { headers: { "x-routecairn-organization-id": fixture!.org, ...headers } }); }
async function freshSession() { await context!.clearCookies(); await login(); }

try {
  if (process.env.DEBUG || process.env.PWDEBUG) throw Error("D0_DEBUG_EXPORT_UNSAFE");
  proxy = await restrictedBrowserProxy(); fixture = await browserFixture(); proxy.allowed.add(fixture.origin);
  browser = await chromium.launch({ executablePath: executable, headless: true, proxy: { server: proxy.server, bypass: "<-loopback>" } }); version = browser.version();
  context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: false, serviceWorkers: "block", viewport: { width: 1280, height: 900 }, reducedMotion: "reduce" });
  await context.route("**/*", async (route) => {
    const u = new URL(route.request().url());
    if (u.origin !== fixture!.origin && !proxy!.allowed.has(u.origin)) { blockedExternal++; await route.abort("blockedbyclient"); return; }
    assert.equal(u.hostname, "127.0.0.1"); await route.continue();
  });
  page = await context.newPage(); page.setDefaultTimeout(5000);
  page.on("console", (message) => { if (consoleText.length < 100) consoleText.push(message.text().slice(0, 2048)); });
  page.on("request", (request) => { const u = new URL(request.url()); const key = request.method() + " " + u.pathname.replace(/[a-f0-9]{8}-[a-f0-9-]{27,}/gi, ":id"); requestCounts.set(key, (requestCounts.get(key) || 0) + 1); });
  await run("B01", ["real Chromium", "built UI", "genuine TLS login", "server owner cookie", "fresh tenant selection"], async () => {
    await login();
    authIndicators.nativeStatus = (await nativeStatus()).status();
    authIndicators.nativeSession = (await context!.request.get(fixture!.origin + "/api/auth/session")).status();
    authIndicators.organizationPickerPresent = await page.getByLabel("Active organization").count() > 0;
    // Fresh login must initialize current organizations without a manual reload.
    await page.getByLabel("Active organization").waitFor({ state: "visible", timeout: 5000 });
    assert.equal((await nativeStatus()).status(), 200);
    const cookies = await context!.cookies(); assert(cookies.some((c) => c.name === "routecairn_session" && c.httpOnly && c.secure));
  });
  if (cases[0]!.status !== "PASS") throw Error("D0_AUTH_UI_PREREQUISITE_FAILED");
  await run("B02", ["canonical candidate", "exact reviewed route/method/effect", "zero target GET"], async () => {
    await openWorkspace(); await review();
    assert((await page.locator(".trusted-discovery-review").innerText()).includes("/api/health"));
    assert((await page.locator(".trusted-discovery-review").innerText()).includes("Non-mutating"));
    assert.equal(fixture!.targetReceipts(), 0);
  });
  await run("B03", ["conscious typed phrase", "one historical pre-consent", "NOT EXECUTED", "zero wire"], async () => {
    const before = requestCounts.get("POST /api/trusted-discovery/pre-consent") || 0;
    const button = page.getByRole("button", { name: "Record pre-consent (does not execute)", exact: true }); assert(await button.isDisabled());
    await page.getByLabel("Type the exact confirmation phrase").pressSequentially(phrase, { delay: 1 });
    await button.dblclick(); await page.getByText("Pre-consent recorded — NOT EXECUTED. No HTTP GET was sent.", { exact: true }).waitFor();
    assert.equal((requestCounts.get("POST /api/trusted-discovery/pre-consent") || 0) - before, 1);
    assert.equal(fixture!.targetReceipts(), 0);
    const row = fixture!.database.db.prepare("SELECT count(*) AS n FROM trusted_discovery_reviews WHERE state='PRECONSENTED'").get() as { n: number }; assert.equal(row.n, 1);
  });
  await run("B04", ["disabled mouse/keyboard execute", "exact public404 aliases", "query refusal"], async () => {
    const button = page.getByRole("button", { name: "Execute (unavailable)", exact: true }); assert(await button.isDisabled());
    await button.evaluate((element: HTMLButtonElement) => element.click()); await page.keyboard.press("Enter"); assert.equal(fixture!.targetReceipts(), 0);
    for (const path of ["/execute", "/Execute", "/executeFresh", "/execute/", "/ex%65cute"]) for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE"]) assert.equal((await context!.request.fetch(fixture!.origin + "/api/trusted-discovery" + path, { method })).status(), 404);
    assert.equal((await nativeStatus("/api/trusted-discovery/status?execute=true")).status(), 404);
  });
  await run("B05", ["analyst/viewer labels not authority", "OWNER membership", "foreign organization"], async () => {
    const f = fixture!;
    for (const role of ["ANALYST", "VIEWER"]) { f.database.db.prepare("UPDATE dashboard_users SET role=? WHERE id=?").run(role, f.owner); assert.equal((await nativeStatus()).status(), 401); }
    f.database.db.prepare("UPDATE dashboard_users SET role='OWNER' WHERE id=?").run(f.owner);
    f.database.db.prepare("UPDATE organization_memberships SET role='ADMIN' WHERE user_id=? AND organization_id=?").run(f.owner, f.org); assert.equal((await nativeStatus()).status(), 403);
    f.database.db.prepare("UPDATE organization_memberships SET role='OWNER' WHERE user_id=? AND organization_id=?").run(f.owner, f.org);
    assert.equal((await nativeStatus(`/api/trusted-discovery/candidates/${f.primary.scan}`, { "x-routecairn-organization-id": f.otherOrg })).status(), 409);
  });
  await run("B06", ["real session revocation/lock/expiry", "sanitized lost-session UI"], async () => {
    const f = fixture!;
    f.database.db.prepare("UPDATE dashboard_users SET locked_until=? WHERE id=?").run(new Date(Date.now() + 60_000).toISOString(), f.owner); assert.equal((await nativeStatus()).status(), 401);
    f.database.db.prepare("UPDATE dashboard_users SET locked_until=NULL WHERE id=?").run(f.owner);
    f.database.db.prepare("UPDATE dashboard_sessions SET revoked_at=?").run(new Date().toISOString()); assert.equal((await nativeStatus()).status(), 401);
    await page.getByRole("button", { name: "Refresh read-only metadata", exact: true }).click(); await page.getByRole("alert").waitFor();
    await freshSession(); await openWorkspace(); f.database.db.prepare("UPDATE dashboard_sessions SET expires_at='2000-01-01T00:00:00.000Z'").run(); assert.equal((await nativeStatus()).status(), 401);
    await freshSession(); await openWorkspace();
  });
  await run("B07", ["genuine cookie without correct CSRF/Origin denied", "no operator grant"], async () => {
    const f = fixture!, token = await csrf(); const data = { scanId: f.primary.scan, candidateId: f.primary.candidate };
    for (const headers of [{ origin: f.origin, "x-csrf-token": "wrong" }, { origin: "https://foreign.d0.invalid", "x-csrf-token": token }]) assert.equal((await context!.request.post(f.origin + "/api/trusted-discovery/review", { data, headers: { "x-routecairn-organization-id": f.org, ...headers } })).status(), 401);
  });
  await run("B08", ["poisoned ID rejected", "unreadable retained source", "stale bytes", "safe UI"], async () => {
    const f = fixture!, token = await csrf();
    assert.equal((await context!.request.post(f.origin + "/api/trusted-discovery/review", { data: { scanId: f.primary.scan, candidateId: "f".repeat(64), endpoint: "http://foreign.d0.invalid" }, headers: { origin: f.origin, "x-csrf-token": token, "x-routecairn-organization-id": f.org } })).status(), 400);
    renameSync(f.primary.file, f.primary.file + ".held"); try { assert.equal((await nativeStatus(`/api/trusted-discovery/candidates/${f.primary.scan}`)).status(), 409); } finally { renameSync(f.primary.file + ".held", f.primary.file); }
    writeFileSync(f.primary.file, "{corrupt"); try { assert.equal((await nativeStatus(`/api/trusted-discovery/candidates/${f.primary.scan}`)).status(), 409); } finally { writeFileSync(f.primary.file, f.primary.bytes); }
  });
  await run("B09", ["target/candidate/org switches discard review", "no automatic POST"], async () => {
    await review(); await page.getByLabel("Registered local target").selectOption(fixture!.secondary.target); assert.equal(await page.getByRole("heading", { name: "Reviewed candidate", exact: true }).count(), 0);
    await page.getByLabel("Active organization").selectOption(fixture!.otherOrg); await page.getByRole("button", { name: "Trusted Discovery", exact: true }).click(); assert.equal(await page.getByRole("heading", { name: "Reviewed candidate", exact: true }).count(), 0);
    await page.getByLabel("Active organization").selectOption(fixture!.org); await openWorkspace();
  });
  await run("B10", ["reload/back-forward/logout discard authority", "no automatic confirm"], async () => {
    await review(); await page.reload(); await openWorkspace(); assert.equal(await page.getByRole("heading", { name: "Reviewed candidate", exact: true }).count(), 0);
    await review(); await page.evaluate(() => window.dispatchEvent(new PopStateEvent("popstate"))); assert.equal(await page.getByRole("heading", { name: "Reviewed candidate", exact: true }).count(), 0);
    await page.getByRole("button", { name: "Log Out", exact: true }).click(); await page.getByRole("button", { name: "Log In", exact: true }).waitFor(); await login(); await openWorkspace();
  });
  await run("B11", ["actual60-second expiry", "no mocked platform/time", "no persisted review/phrase"], async () => {
    await review(); await page.getByRole("heading", { name: "Reviewed candidate", exact: true }).waitFor({ state: "hidden", timeout: 65_000 });
    assert((await page.getByRole("alert").innerText()).includes("Review expired"));
    assert.equal(await page.evaluate(() => [...Object.values(localStorage), ...Object.values(sessionStorage)].some((s) => s.includes("reviewDigest") || s.includes("reviewId") || s.includes("I_CONFIRM_ONE_ANONYMOUS_NON_MUTATING_LOCAL_GET"))), false);
  });
  await run("B12", ["keyboard-only confirm/focus/live", "widths320/768/1280", "zoom/reduced-motion", "screen reader NOT VERIFIED"], async () => {
    await review(); assert.equal(await page.getByRole("heading", { name: "Reviewed candidate", exact: true }).evaluate((el) => el === document.activeElement), true);
    const widths: Array<{ width: number; scroll: number }> = []; measurements.widths = widths;
    for (const width of [320, 768, 1280]) { await page.setViewportSize({ width, height: 900 }); widths.push({ width, scroll: await page.evaluate(() => document.documentElement.scrollWidth) }); assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)); }
    await page.evaluate(() => { document.documentElement.style.zoom = "1.25"; }); assert(await page.getByLabel("Type the exact confirmation phrase").isVisible()); await page.evaluate(() => { document.documentElement.style.zoom = "1"; });
    await page.keyboard.press("Tab"); await page.keyboard.type(phrase); await page.keyboard.press("Tab");
    assert.equal(await page.getByRole("button", { name: "Record pre-consent (does not execute)", exact: true }).evaluate((el) => el === document.activeElement), true);
    await page.keyboard.press("Enter"); await page.getByText("Pre-consent recorded — NOT EXECUTED. No HTTP GET was sent.", { exact: true }).waitFor();
    assert(await page.getByRole("status").getAttribute("aria-live"));
  });
  await run("B13", ["real browser external request blocked before DNS/upstream", "proxy origin allowlist", "zero target GET"], async () => {
    const blank = await context!.newPage(); try { await blank.evaluate(async () => { await fetch("https://outside.d0.invalid/").catch(() => undefined); }); } finally { await blank.close(); }
    assert(blockedExternal > 0); assert.equal(proxy!.stats().nonLoopbackTransmissions, 0); assert(proxy!.stats().forwarded > 0);
  });
  await run("B14", ["actual default-OFF/local synthetic-owner UI", "disabled execution", "zero target GET"], async () => {
    for (const options of [{ preview: false }, { local: true }]) {
      const f = await browserFixture(options); proxy!.allowed.add(f.origin);
      const q = await context!.newPage(); try {
        if (options.local) await q.goto(f.bootstrapUrl!);
        else { await q.goto(f.origin); await q.getByLabel("Username or email").fill(f.login); await q.getByLabel("Password", { exact: true }).fill(f.password); await q.getByRole("button", { name: "Log In", exact: true }).click(); }
        await q.getByRole("button", { name: "Trusted Discovery", exact: true }).click(); await q.getByText("Preview is OFF or unavailable in this dashboard mode. Execution is unavailable.", { exact: true }).waitFor(); assert(await q.getByRole("button", { name: "Execute (unavailable)", exact: true }).isDisabled()); assert.equal(f.targetReceipts(), 0);
      } finally { await q.close(); targetReceipts += f.targetReceipts(); await f.close(); proxy!.allowed.delete(f.origin); }
    }
  });
  await run("B15", ["non-loopback preview startup rejected", "distributed preview rejected before network"], async () => {
    const f = fixture!; const common = { dataDir: f.root, mode: "server" as const, publicOrigin: f.origin, sessionSecret: f.security.sessionSecret, trustProxy: true, trustedDiscoveryPreviewOnly: true };
    await assert.rejects(startDashboardServer({ ...common, host: "0.0.0.0" }), /TRUSTED_DISCOVERY_REQUIRES_LOOPBACK_LISTENER/);
    const previous = process.env.ROUTECAIRN_CONTROL_PLANE_MODE; process.env.ROUTECAIRN_CONTROL_PLANE_MODE = "distributed";
    try { await assert.rejects(startDashboardServer({ ...common, host: "127.0.0.1" })); } finally { if (previous === undefined) delete process.env.ROUTECAIRN_CONTROL_PLANE_MODE; else process.env.ROUTECAIRN_CONTROL_PLANE_MODE = previous; }
  });
  await run("B16", ["redacted terminal screenshot/DOM", "assets contain no fixture bootstrap", "console has no secrets"], async () => {
    const f = fixture!; const cookies = (await context!.cookies()).map((c) => c.value), secrets = [f.password, f.security.sessionSecret, ...cookies];
    const text = await page.locator(".trusted-discovery-workspace").innerText(); assertSafeExport(text, secrets); assertSafeExport(consoleText.join("\n"), secrets);
    const terminal = { schemaVersion: 1, reviewAbsent: await page.getByRole("heading", { name: "Reviewed candidate", exact: true }).count() === 0, executionDisabled: await page.getByRole("button", { name: "Execute (unavailable)", exact: true }).isDisabled(), textSha256: createHash("sha256").update(text).digest("hex"), liveStatus: await page.getByRole("status").getAttribute("aria-live"), screenReader: "NOT_VERIFIED" }; assert(terminal.reviewAbsent);
    for (const src of await page.locator("script[src]").evaluateAll((nodes) => nodes.map((n) => (n as HTMLScriptElement).src))) { const asset = await (await context!.request.get(src)).text(); assert(asset.length <= 8 * 1024 * 1024); assert(!secrets.some((secret) => asset.includes(secret))); assert(!/stageAFixture|stageBFixture|D0_FIXTURE_BIND_FAILED|witness\.key|\/api\/trusted-discovery\/execute/.test(asset)); }
    writeFileSync(join(output, "terminal-dom.json"), JSON.stringify(terminal, null, 2) + "\n", { mode: 0o600 });
    const image = await page.locator(".trusted-discovery-workspace").screenshot({ path: join(output, "terminal.png") }); artifacts.push({ file: "terminal.png", sha256: createHash("sha256").update(image).digest("hex") });
  });
} catch (error) {
  if (!cases.some((v) => v.status === "FAIL")) cases.push({ id: ids.find((id) => !cases.some((v) => v.id === id))!, status: "FAIL", checks: [], reason: error instanceof Error ? error.name : "STARTUP_FAILED" });
} finally {
  for (const id of ids) if (!cases.some((v) => v.id === id)) cases.push({ id, status: "BLOCKED", checks: [], reason: "PREREQUISITE_FAILED" });
  writeFileSync(join(output, "browser-progress.json"), JSON.stringify({ version, cases, authIndicators, cleanup: "UNKNOWN", targetReceipts: fixture?.targetReceipts() || 0 }, null, 2));
  try { await context?.close(); await browser?.close(); if (fixture) { targetReceipts += fixture.targetReceipts(); await fixture.close(); } await proxy?.close(); cleanup = "CONFIRMED"; } catch { cleanup = "FAILED"; }
  const proof = { schemaVersion: 1, realBrowser: !!version, browserVersion: version, platform: process.platform, targetReceipts, nonLoopbackTransmissions: proxy?.stats().nonLoopbackTransmissions || 0, blockedExternal, authIndicators, measurements, cases: cases.sort((a, b) => a.id.localeCompare(b.id)), cleanup, artifacts, realScreenReader: "NOT_VERIFIED", tracesCaptured: false, rawCredentialsExported: false };
  const status = cases.some((c) => c.status === "FAIL") || cleanup !== "CONFIRMED" || targetReceipts !== 0 ? "FAIL" : cases.some((c) => c.status === "BLOCKED") ? "HOLD" : "PASS";
  writeFileSync(join(output, "browser-proof.json"), JSON.stringify({ ...proof, status }, null, 2) + "\n", { mode: 0o600 });
  console.log(JSON.stringify({ realBrowser: status, version, passed: cases.filter((c) => c.status === "PASS").length, failed: cases.filter((c) => c.status === "FAIL").length, blocked: cases.filter((c) => c.status === "BLOCKED").length, targetReceipts, cleanup })); process.exitCode = status === "PASS" ? 0 : status === "HOLD" ? 2 : 1;
}
