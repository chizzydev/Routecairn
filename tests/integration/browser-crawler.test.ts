import { afterEach, describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { Socket } from "node:net";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PlaywrightCrawler } from "../../src/modules/browserCrawler/PlaywrightCrawler.js";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { browserPolicyFromSettings } from "../../src/modules/browserCrawler/BrowserPolicy.js";
import { testPlan } from "../helpers/plan.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";

let server: Server | undefined;
const tempDirs: string[] = [];
let upgradedSockets: Socket[] = [];

afterEach(async () => {
  if (server) {
    for (const socket of upgradedSockets) {
      socket.destroy();
    }
    upgradedSockets = [];
    await new Promise<void>((resolve, reject) => {
      server?.close((error) => {
        if (error) {
          reject(error);
          return;
        }

        resolve();
      });
    });
    server = undefined;
  }

  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("PlaywrightCrawler", () => {
  it("captures rendered browser evidence without submitting forms", async () => {
    server = createServer((request, response) => {
      if (request.url === "/api/rendered") {
        response.writeHead(200, { "content-type": "application/json" });
        response.end('{"ok":true}');
        return;
      }

      response.writeHead(200, { "content-type": "text/html" });
      response.end(`
        <!doctype html>
        <html>
          <body>
            <a href="/rendered-link">Rendered Link</a>
            <form action="/danger" method="post"><button type="submit">Submit</button></form>
            <script>
              fetch('/api/rendered');
              fetch('/api/mutate', { method: 'POST', body: 'blocked=true' }).catch(() => {});
              console.error('client boom');
            </script>
          </body>
        </html>
      `);
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const outputDir = await mkdtemp(join(tmpdir(), "routecairn-browser-"));
    tempDirs.push(outputDir);
    const target = `http://127.0.0.1:${port}/`;
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], userAgent: "RouteCairn/Test" };
    const plan = testPlan("full", { scope });
    const context = new ScanContext({ target, scope, config: defaultConfig, plan, outputDir });
    const settings = context.moduleSettings("browser-crawler");

    const report = await new PlaywrightCrawler().crawl({
      targetUrl: target,
      outputDir,
      userAgent: "RouteCairn/Test",
      timeoutMs: 10000,
      sameOriginOnly: true,
      policy: browserPolicyFromSettings(
        { ...settings, browserAllowPrivateNetwork: true, browserAllowedPrivateOrigins: [new URL(target).origin] },
        context.options.plan.limits,
        context.options.plan.evidence
      ),
      requestBroker: context.httpClient
    });

    expect(report.screenshotPath && existsSync(report.screenshotPath)).toBe(true);
    expect(report.renderedLinks).toContainEqual({ path: "/rendered-link", source: "browser:rendered-link" });
    expect(report.networkRequests.some((request) => request.url.endsWith("/api/rendered") && request.decision === "allowed")).toBe(true);
    expect(report.networkRequests.some((request) => request.url.endsWith("/api/mutate") && request.decision === "blocked" && request.reason === "mutating-method-blocked")).toBe(true);
    expect(report.policyEvents?.some((event) => event.reason === "mutating-method-blocked")).toBe(true);
    expect(context.state.getRequestAudit().some((entry) => entry.outcome === "browser-policy-blocked" && entry.browserPolicyReason === "mutating-method-blocked")).toBe(true);
    expect(report.consoleErrors.some((error) => error.text.includes("client boom"))).toBe(true);
    expect(report.formsDetected).toBeGreaterThanOrEqual(1);
    expect(report.formsSubmitted).toBe(0);
  });

  it("blocks out-of-scope redirects, downloads, and third-party resources before completion", async () => {
    server = createServer((request, response) => {
      if (request.url === "/redirect") {
        response.writeHead(302, { location: "/forbidden" });
        response.end();
        return;
      }

      response.writeHead(200, { "content-type": "text/html" });
      response.end(`
        <!doctype html>
        <html>
          <body>
            <a href="/redirect">redirect</a>
            <a href="/forbidden">forbidden</a>
            <a href="/backup.zip">download</a>
            <script src="http://example.net/evil.js"></script>
          </body>
        </html>
      `);
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const outputDir = await mkdtemp(join(tmpdir(), "routecairn-browser-"));
    tempDirs.push(outputDir);
    const target = `http://127.0.0.1:${port}/`;
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: ["/forbidden"], userAgent: "RouteCairn/Test" };
    const plan = testPlan("full", { scope });
    const context = new ScanContext({ target, scope, config: defaultConfig, plan, outputDir });

    const report = await new PlaywrightCrawler().crawl({
      targetUrl: target,
      outputDir,
      userAgent: "RouteCairn/Test",
      timeoutMs: 10000,
      sameOriginOnly: true,
      policy: browserPolicyFromSettings(
        { ...context.moduleSettings("browser-crawler"), browserAllowPrivateNetwork: true, browserAllowedPrivateOrigins: [new URL(target).origin] },
        context.options.plan.limits,
        context.options.plan.evidence
      ),
      requestBroker: context.httpClient
    });

    expect(report.policyEvents?.map((event) => event.reason)).toEqual(
      expect.arrayContaining(["third-party-blocked", "download-blocked", "scope-disallowed-path"])
    );
    expect(report.networkRequests.some((request) => request.reason === "third-party-blocked" && request.transmitted === false)).toBe(true);
    expect(report.policyEvents?.some((event) => event.reason === "download-blocked" && event.transmitted === false)).toBe(true);
    expect(report.networkRequests.some((request) => request.reason === "scope-disallowed-path" && request.transmitted === false)).toBe(true);
  });

  it("blocks browser mutation channels from pages, frames, popups, workers, XHR, beacon, and GraphQL POST", async () => {
    const receivedMutations: string[] = [];
    server = createServer((request, response) => {
      if (request.method && !["GET", "HEAD", "OPTIONS"].includes(request.method)) {
        receivedMutations.push(`${request.method} ${request.url}`);
      }

      if (request.url === "/worker.js") {
        response.writeHead(200, { "content-type": "application/javascript" });
        response.end("fetch('/worker-post', { method: 'POST', body: 'worker' }).catch(() => {});");
        return;
      }

      if (request.url === "/frame") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end(`
          <!doctype html><html><body>
            <form action="/frame-form" method="post"></form>
            <script>
              fetch('/frame-post', { method: 'POST', body: 'frame' }).catch(() => {});
              document.forms[0].submit();
            </script>
          </body></html>
        `);
        return;
      }

      if (request.url === "/popup") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end("<!doctype html><html><body><script>fetch('/popup-post', { method: 'POST', body: 'popup' }).catch(() => {});</script></body></html>");
        return;
      }

      response.writeHead(200, { "content-type": "text/html" });
      response.end(`
        <!doctype html><html><body>
          <iframe src="/frame"></iframe>
          <script>
            fetch('/post-fetch', { method: 'POST', body: 'post' }).catch(() => {});
            fetch('/put-fetch', { method: 'PUT', body: 'put' }).catch(() => {});
            fetch('/patch-fetch', { method: 'PATCH', body: 'patch' }).catch(() => {});
            fetch('/delete-fetch', { method: 'DELETE' }).catch(() => {});
            fetch('/graphql', { method: 'POST', body: JSON.stringify({ query: '{ viewer { id } }' }) }).catch(() => {});
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/xhr-post');
            xhr.send('xhr');
            navigator.sendBeacon('/beacon', 'beacon');
            new Worker('/worker.js');
            window.open('/popup');
          </script>
        </body></html>
      `);
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const outputDir = await mkdtemp(join(tmpdir(), "routecairn-browser-"));
    tempDirs.push(outputDir);
    const target = `http://127.0.0.1:${port}/`;
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], userAgent: "RouteCairn/Test" };
    const plan = testPlan("full", { scope });
    const context = new ScanContext({ target, scope, config: defaultConfig, plan, outputDir });

    const report = await new PlaywrightCrawler().crawl({
      targetUrl: target,
      outputDir,
      userAgent: "RouteCairn/Test",
      timeoutMs: 10000,
      sameOriginOnly: true,
      policy: browserPolicyFromSettings(
        {
          ...context.moduleSettings("browser-crawler"),
          browserAllowPrivateNetwork: true,
          browserAllowedPrivateOrigins: [new URL(target).origin],
          browserAllowedResourceTypes: ["document", "stylesheet", "script", "xhr", "fetch", "manifest", "other"]
        },
        context.options.plan.limits,
        context.options.plan.evidence
      ),
      requestBroker: context.httpClient
    });

    expect(receivedMutations).toEqual([]);
    expect(report.policyEvents?.filter((event) => event.reason === "mutating-method-blocked").length).toBeGreaterThanOrEqual(8);
    expect(report.policyEvents?.some((event) => event.reason === "popup-blocked" && event.transmitted === false)).toBe(true);
    expect(report.networkRequests.some((request) => request.url.endsWith("/popup-post") && request.transmitted === true)).toBe(false);
    expect(report.networkRequests.some((request) => request.url.endsWith("/worker.js") && request.transmitted === true)).toBe(true);
    expect(report.networkRequests.some((request) => request.url.endsWith("/frame") && request.transmitted === true)).toBe(true);
  });

  it("does not persist downloads or accept local file uploads", async () => {
    const receivedBodies: string[] = [];
    server = createServer((request, response) => {
      if (request.method === "POST") {
        let body = "";
        request.setEncoding("utf8");
        request.on("data", (chunk) => {
          body += chunk;
        });
        request.on("end", () => {
          receivedBodies.push(body);
          response.writeHead(200, { "content-type": "text/plain" });
          response.end("uploaded");
        });
        return;
      }

      if (request.url === "/attachment") {
        response.writeHead(200, { "content-type": "application/octet-stream", "content-disposition": "attachment; filename=\"secret-report.txt\"" });
        response.end("download secret token should not persist");
        return;
      }

      if (request.url === "/frame-download") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end("<!doctype html><html><body><script>const a=document.createElement('a');a.href='/attachment';a.download='frame.txt';document.body.append(a);a.click();</script></body></html>");
        return;
      }

      if (request.url === "/popup-download") {
        response.writeHead(200, { "content-type": "text/html" });
        response.end("<!doctype html><html><body><script>const a=document.createElement('a');a.href='/attachment';a.download='popup.txt';document.body.append(a);a.click();</script></body></html>");
        return;
      }

      response.writeHead(200, { "content-type": "text/html" });
      response.end(`
        <!doctype html><html><body>
          <input id="file" type="file">
          <iframe src="/frame-download"></iframe>
          <script>
            document.getElementById('file').click();
            for (const href of ['/attachment', '/backup.zip']) {
              const a = document.createElement('a');
              a.href = href;
              a.download = 'downloaded.txt';
              document.body.append(a);
              a.click();
            }
            const blobUrl = URL.createObjectURL(new Blob(['blob secret'], { type: 'text/plain' }));
            const blobLink = document.createElement('a');
            blobLink.href = blobUrl;
            blobLink.download = 'blob.txt';
            document.body.append(blobLink);
            blobLink.click();
            const dataLink = document.createElement('a');
            dataLink.href = 'data:text/plain,secret-data';
            dataLink.download = 'data.txt';
            document.body.append(dataLink);
            dataLink.click();
            window.open('/popup-download');
          </script>
        </body></html>
      `);
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const outputDir = await mkdtemp(join(tmpdir(), "routecairn-browser-"));
    tempDirs.push(outputDir);
    const secretPath = join(outputDir, "local-upload-secret.txt");
    await writeFile(secretPath, "LOCAL_UPLOAD_SECRET", "utf8");
    const beforeFiles = new Set(await readdir(outputDir));
    const target = `http://127.0.0.1:${port}/`;
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], userAgent: "RouteCairn/Test" };
    const plan = testPlan("full", { scope });
    const context = new ScanContext({ target, scope, config: defaultConfig, plan, outputDir });

    const report = await new PlaywrightCrawler().crawl({
      targetUrl: target,
      outputDir,
      userAgent: "RouteCairn/Test",
      timeoutMs: 10000,
      sameOriginOnly: true,
      policy: browserPolicyFromSettings(
        {
          ...context.moduleSettings("browser-crawler"),
          browserAllowPrivateNetwork: true,
          browserAllowedPrivateOrigins: [new URL(target).origin],
          browserCaptureScreenshot: false
        },
        context.options.plan.limits,
        context.options.plan.evidence
      ),
      requestBroker: context.httpClient
    });

    const afterFiles = await readdir(outputDir);
    expect(afterFiles.filter((file) => !beforeFiles.has(file))).toEqual([]);
    expect(receivedBodies.join("\n")).not.toContain("LOCAL_UPLOAD_SECRET");
    expect(receivedBodies.join("\n")).not.toContain("local-upload-secret.txt");
    expect(report.policyEvents?.some((event) => event.reason === "upload-blocked")).toBe(true);
    expect(report.policyEvents?.some((event) => event.reason === "download-blocked")).toBe(true);
    expect(JSON.stringify(report.policyEvents)).not.toContain("secret-report");
  });

  it("blocks service worker registration before worker scripts can initiate requests", async () => {
    let serviceWorkerScriptRequests = 0;
    const serviceWorkerMutations: string[] = [];
    server = createServer((request, response) => {
      if (request.url === "/sw.js") {
        serviceWorkerScriptRequests += 1;
        response.writeHead(200, { "content-type": "application/javascript" });
        response.end(`
          self.addEventListener('activate', () => {
            fetch('/sw-post', { method: 'POST', body: 'blocked' });
            fetch('http://example.net/sw-third-party.js');
          });
        `);
        return;
      }

      if (request.method && !["GET", "HEAD", "OPTIONS"].includes(request.method)) {
        serviceWorkerMutations.push(`${request.method} ${request.url}`);
      }

      response.writeHead(200, { "content-type": "text/html" });
      response.end(`
        <!doctype html><html><body>
          <script>
            navigator.serviceWorker.register('/sw.js').catch(() => {});
          </script>
        </body></html>
      `);
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const outputDir = await mkdtemp(join(tmpdir(), "routecairn-browser-"));
    tempDirs.push(outputDir);
    const target = `http://127.0.0.1:${port}/`;
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], userAgent: "RouteCairn/Test" };
    const plan = testPlan("full", { scope });
    const context = new ScanContext({ target, scope, config: defaultConfig, plan, outputDir });

    const report = await new PlaywrightCrawler().crawl({
      targetUrl: target,
      outputDir,
      userAgent: "RouteCairn/Test",
      timeoutMs: 10000,
      sameOriginOnly: true,
      policy: browserPolicyFromSettings(
        {
          ...context.moduleSettings("browser-crawler"),
          browserAllowPrivateNetwork: true,
          browserAllowedPrivateOrigins: [new URL(target).origin],
          browserCaptureScreenshot: false
        },
        context.options.plan.limits,
        context.options.plan.evidence
      ),
      requestBroker: context.httpClient
    });

    expect(serviceWorkerScriptRequests).toBe(0);
    expect(serviceWorkerMutations).toEqual([]);
    expect(report.policyEvents?.some((event) => event.reason === "service-worker-blocked")).toBe(true);
    expect(report.networkRequests.some((request) => request.url.endsWith("/sw.js") && request.transmitted === true)).toBe(false);
  });

  it("blocks WebSockets by default through Playwright WebSocket routing without leaking payloads", async () => {
    let upgrades = 0;
    server = createServer((_request, response) => {
      response.writeHead(200, { "content-type": "text/html" });
      response.end(`
        <!doctype html><html><body>
          <script>
            const socket = new WebSocket('ws://127.0.0.1:${(server?.address() as AddressInfo | null)?.port ?? 0}/socket?token=secret-token');
            socket.addEventListener('open', () => socket.send('secret-payload'));
          </script>
        </body></html>
      `);
    });
    server.on("upgrade", (_request, socket) => {
      upgrades += 1;
      socket.destroy();
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const outputDir = await mkdtemp(join(tmpdir(), "routecairn-browser-"));
    tempDirs.push(outputDir);
    const target = `http://127.0.0.1:${port}/`;
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], userAgent: "RouteCairn/Test" };
    const plan = testPlan("full", { scope });
    const context = new ScanContext({ target, scope, config: defaultConfig, plan, outputDir });

    const report = await new PlaywrightCrawler().crawl({
      targetUrl: target,
      outputDir,
      userAgent: "RouteCairn/Test",
      timeoutMs: 10000,
      sameOriginOnly: true,
      policy: browserPolicyFromSettings(
        {
          ...context.moduleSettings("browser-crawler"),
          browserAllowPrivateNetwork: true,
          browserAllowedPrivateOrigins: [new URL(target).origin],
          browserCaptureScreenshot: false
        },
        context.options.plan.limits,
        context.options.plan.evidence
      ),
      requestBroker: context.httpClient
    });

    expect(upgrades).toBe(0);
    expect(report.policyEvents?.some((event) => event.reason === "websocket-blocked")).toBe(true);
    expect(JSON.stringify(report.policyEvents)).not.toContain("secret-token");
    expect(JSON.stringify(report.policyEvents)).not.toContain("secret-payload");
  });

  it("allows explicitly configured in-scope WebSockets and closes them during teardown", async () => {
    let upgrades = 0;
    let socketClosed = false;
    server = createServer((_request, response) => {
      const port = (server?.address() as AddressInfo | null)?.port ?? 0;
      response.writeHead(200, { "content-type": "text/html" });
      response.end(`
        <!doctype html><html><body>
          <script>
            const socket = new WebSocket('ws://127.0.0.1:${port}/socket');
            socket.addEventListener('open', () => socket.send('hello'));
          </script>
        </body></html>
      `);
    });
    server.on("upgrade", (_request, socket) => {
      upgrades += 1;
      upgradedSockets.push(socket);
      const key = String(_request.headers["sec-websocket-key"] ?? "");
      const accept = createHash("sha1")
        .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
        .digest("base64");
      socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
      socket.on("data", (data) => {
        if ((data[0] & 0x0f) === 8) {
          socket.end();
        }
      });
      socket.on("close", () => {
        socketClosed = true;
      });
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const outputDir = await mkdtemp(join(tmpdir(), "routecairn-browser-"));
    tempDirs.push(outputDir);
    const target = `http://127.0.0.1:${port}/`;
    const wsOrigin = `ws://127.0.0.1:${port}`;
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], userAgent: "RouteCairn/Test" };
    const plan = testPlan("full", { scope });
    const context = new ScanContext({ target, scope, config: defaultConfig, plan, outputDir });

    await new PlaywrightCrawler().crawl({
      targetUrl: target,
      outputDir,
      userAgent: "RouteCairn/Test",
      timeoutMs: 10000,
      sameOriginOnly: true,
      policy: browserPolicyFromSettings(
        {
          ...context.moduleSettings("browser-crawler"),
          browserAllowPrivateNetwork: true,
          browserAllowedPrivateOrigins: [new URL(target).origin, wsOrigin],
          browserAllowWebSockets: true,
          browserCaptureScreenshot: false
        },
        context.options.plan.limits,
        context.options.plan.evidence
      ),
      requestBroker: context.httpClient
    });

    await waitFor(() => socketClosed);
    expect(upgrades).toBe(1);
    expect(socketClosed).toBe(true);
  });

  it("preserves exact query order for navigation while deduplicating fragments only", async () => {
    const requestedUrls: string[] = [];
    server = createServer((request, response) => {
      requestedUrls.push(request.url ?? "");
      response.writeHead(200, { "content-type": "text/html" });
      if (request.url === "/") {
        response.end(`
          <!doctype html><html><body>
            <a href="/order?role=user&role=admin">one</a>
            <a href="/order?role=admin&role=user">two</a>
            <a href="/fragment?keep=1#one">fragment one</a>
            <a href="/fragment?keep=1#two">fragment two</a>
          </body></html>
        `);
        return;
      }
      response.end("<!doctype html><html><body>child</body></html>");
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const outputDir = await mkdtemp(join(tmpdir(), "routecairn-browser-"));
    tempDirs.push(outputDir);
    const target = `http://127.0.0.1:${port}/`;
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], userAgent: "RouteCairn/Test" };
    const plan = testPlan("full", { scope });
    const context = new ScanContext({ target, scope, config: defaultConfig, plan, outputDir });

    const report = await new PlaywrightCrawler().crawl({
      targetUrl: target,
      outputDir,
      userAgent: "RouteCairn/Test",
      timeoutMs: 10000,
      sameOriginOnly: true,
      policy: browserPolicyFromSettings(
        {
          ...context.moduleSettings("browser-crawler"),
          browserAllowPrivateNetwork: true,
          browserAllowedPrivateOrigins: [new URL(target).origin],
          browserMaxPages: 4,
          browserCaptureScreenshot: false
        },
        context.options.plan.limits,
        context.options.plan.evidence
      ),
      requestBroker: context.httpClient
    });

    expect(requestedUrls).toContain("/order?role=user&role=admin");
    expect(requestedUrls).toContain("/order?role=admin&role=user");
    expect(requestedUrls.filter((url) => url === "/fragment?keep=1")).toHaveLength(1);
    expect(report.visitedPages?.map((page) => page.depth)).toEqual(expect.arrayContaining([0, 1]));
  });

  it("bounds browser attempt floods separately from transmitted request budget", async () => {
    server = createServer((_request, response) => {
      response.writeHead(200, { "content-type": "text/html" });
      response.end(`
        <!doctype html><html><body>
          ${Array.from({ length: 50 }, (_item, index) => `<img src="/blocked-${index}.png">`).join("")}
          <iframe src="/frame"></iframe>
          <script>for (let i = 0; i < 20; i++) fetch('/post-' + i, { method: 'POST', body: String(i) }).catch(() => {});</script>
        </body></html>
      `);
    });

    await listen(server);
    const port = (server.address() as AddressInfo).port;
    const outputDir = await mkdtemp(join(tmpdir(), "routecairn-browser-"));
    tempDirs.push(outputDir);
    const target = `http://127.0.0.1:${port}/`;
    const scope = { ...exampleScope, allowedDomains: ["127.0.0.1"], disallowedPaths: [], userAgent: "RouteCairn/Test" };
    const plan = testPlan("full", { scope });
    const context = new ScanContext({ target, scope, config: defaultConfig, plan, outputDir });

    const report = await new PlaywrightCrawler().crawl({
      targetUrl: target,
      outputDir,
      userAgent: "RouteCairn/Test",
      timeoutMs: 10000,
      sameOriginOnly: true,
      policy: browserPolicyFromSettings(
        {
          ...context.moduleSettings("browser-crawler"),
          browserAllowPrivateNetwork: true,
          browserAllowedPrivateOrigins: [new URL(target).origin],
          browserMaxPolicyEvents: 6,
          browserCaptureScreenshot: false
        },
        context.options.plan.limits,
        context.options.plan.evidence
      ),
      requestBroker: context.httpClient
    });

    expect(report.policyEventCount).toBe(6);
    expect((report.policyEvents?.length ?? 0)).toBeLessThanOrEqual(6);
    expect(report.transmittedRequestCount).toBeLessThanOrEqual(1);
    expect(report.notes).toContain("Browser crawl stopped because the browser attempt budget was exhausted.");
    expect(context.httpClient.budgetSnapshot()).toMatchObject({ browserPolicyEvents: 6 });
  });
});

function listen(targetServer: Server): Promise<void> {
  return new Promise((resolve) => {
    targetServer.listen(0, "127.0.0.1", resolve);
  });
}

async function waitFor(predicate: () => boolean, timeoutMs = 1000): Promise<void> {
  const started = Date.now();
  while (!predicate() && Date.now() - started < timeoutMs) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
