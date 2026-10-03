import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { request } from "node:https";
import { createServer as tcpServer, type AddressInfo } from "node:net";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { once } from "node:events";
import { generate } from "selfsigned";

/** Starts only explicitly supplied binaries in an isolated disposable directory.
 * No installation, system trust changes, global process termination or public listener. */
export async function createActiveProxyLab(caddyPath: string, nginxPath: string, upstreamProtocol: "H1" | "H2" = "H1") {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "routecairn-proxy-lab-")));
  const children: ChildProcess[] = []; const diagnostics: string[] = []; const seen = new Map<string, { trace: string; probe: boolean; sentinel: boolean; violation: boolean }>();
  let deploymentSha256 = ""; const hopIds = ["caddy", "nginx"];
  const backend = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1"); const canary = String(req.headers["x-routecairn-chain-canary"] ?? ""); const trace = String(req.headers["x-routecairn-hop-trace"] ?? "");
    if (!/^[a-f0-9]{32}$/.test(canary)) { res.writeHead(400).end(); return; }
    const state = seen.get(canary) ?? { trace, probe: false, sentinel: false, violation: false }; state.trace = trace; seen.set(canary, state);
    if (url.pathname === "/proof") { res.writeHead(200, { "content-type": "application/json", "x-routecairn-hop-trace": trace }).end(JSON.stringify({ deploymentSha256, canary, hopIds: trace.split(","), upstreamProtocol: req.headers["x-routecairn-upstream-protocol"], violation: state.violation, probe: state.probe, sentinel: state.sentinel })); return; }
    const chunks: Buffer[] = []; let size = 0; for await (const chunk of req) { size += chunk.length; if (size > 4096) { req.destroy(); return; } chunks.push(Buffer.from(chunk)); }
    if (url.pathname === "/probe") { state.probe = true; if (Buffer.concat(chunks).includes("GET /sentinel HTTP/1.1")) state.violation = true; }
    if (url.pathname === "/sentinel") { state.sentinel = true; if (size !== 0) state.violation = true; }
    res.writeHead(200, { "content-type": "application/json", "x-routecairn-hop-trace": trace }).end(JSON.stringify({ ok: true, canary, hopIds: trace.split(",") }));
  });
  const stop = async () => {
    await Promise.all(children.map(async (child) => { if (child.exitCode !== null) return; const exited = once(child, "exit"); child.kill(); await exited; }));
    backend.closeAllConnections(); await new Promise<void>((done) => backend.close(() => done())); seen.clear(); await rm(directory, { recursive: true, force: true });
  };
  try {
    await new Promise<void>((done) => backend.listen(0, "127.0.0.1", done)); const backendPort = (backend.address() as AddressInfo).port;
    const reserve = async () => { const socket = tcpServer(); await new Promise<void>((done) => socket.listen(0, "127.0.0.1", done)); const port = (socket.address() as AddressInfo).port; await new Promise<void>((done) => socket.close(() => done())); return port; };
    const nginxPort = await reserve(), caddyPort = await reserve();
    const cert = await generate([{ name: "commonName", value: "localhost" }], { keySize: 2048, days: 1, extensions: [{ name: "basicConstraints", cA: true }, { name: "keyUsage", keyCertSign: true, digitalSignature: true, keyEncipherment: true }, { name: "subjectAltName", altNames: [{ type: 7, ip: "127.0.0.1" }, { type: 2, value: "localhost" }] }] });
    await writeFile(join(directory, "cert.pem"), cert.cert); await writeFile(join(directory, "key.pem"), cert.private, { mode: 0o600 }); await mkdir(join(directory, "logs")); await mkdir(join(directory, "temp"));
    const nginx = `daemon off; master_process off; worker_processes 1; error_log logs/error.log; pid logs/nginx.pid; events { worker_connections 32; } http { access_log off; server { listen 127.0.0.1:${nginxPort}; ${upstreamProtocol === "H2" ? "http2 on;" : ""} location / { proxy_http_version 1.1; proxy_set_header Connection ""; proxy_set_header X-RouteCairn-Upstream-Protocol "$server_protocol"; proxy_set_header X-RouteCairn-Hop-Trace "$http_x_routecairn_hop_trace,nginx"; proxy_pass http://127.0.0.1:${backendPort}; } } }`;
    const caddy = { admin: { disabled: true }, apps: { tls: { certificates: { load_files: [{ certificate: join(directory, "cert.pem"), key: join(directory, "key.pem") }] } }, http: { servers: { lab: { listen: [`127.0.0.1:${caddyPort}`], protocols: ["h1", "h2", "h3"], automatic_https: { disable: true }, tls_connection_policies: [{}], routes: [{ handle: [{ handler: "reverse_proxy", ...(upstreamProtocol === "H2" ? { transport: { protocol: "http", versions: ["h2c"] } } : {}), upstreams: [{ dial: `127.0.0.1:${nginxPort}` }], headers: { request: { set: { "X-RouteCairn-Hop-Trace": ["caddy"] } } } }] }] } } } } };
    const binaries = { caddy: createHash("sha256").update(await readFile(caddyPath)).digest("hex"), nginx: createHash("sha256").update(await readFile(nginxPath)).digest("hex") };
    deploymentSha256 = createHash("sha256").update(JSON.stringify({ binaries, nginx, caddy })).digest("hex");
    await writeFile(join(directory, "nginx.conf"), nginx); await writeFile(join(directory, "caddy.json"), JSON.stringify(caddy));
    const start = (binary: string, args: string[]) => { const child = spawn(resolve(binary), args, { cwd: directory, windowsHide: true, stdio: ["ignore", "ignore", "pipe"] }); children.push(child); child.stderr?.on("data", (value) => { if (diagnostics.join("").length < 4096) diagnostics.push(String(value)); }); child.on("error", () => undefined); return child; };
    start(nginxPath, ["-p", `${directory.replaceAll("\\", "/")}/`, "-c", "nginx.conf"]); start(caddyPath, ["run", "--config", join(directory, "caddy.json")]);
    const origin = `https://localhost:${caddyPort}`;
    const readProof = async (canary: string) => await new Promise<Record<string, unknown>>((done, reject) => { const req = request(`${origin}/proof?routecairn_canary=${canary}`, { ca: cert.cert, rejectUnauthorized: true, headers: { "X-RouteCairn-Chain-Canary": canary }, timeout: 2000 }, (res) => { let bytes = ""; res.on("data", (chunk) => { bytes += chunk; if (bytes.length > 4096) req.destroy(new Error("LAB_PROOF_TOO_LARGE")); }); res.on("end", () => { try { const value = JSON.parse(bytes); if (res.statusCode !== 200 || res.headers["x-routecairn-hop-trace"] !== hopIds.join(",") || value.deploymentSha256 !== deploymentSha256 || value.canary !== canary || value.upstreamProtocol !== (upstreamProtocol === "H2" ? "HTTP/2.0" : "HTTP/1.1")) reject(new Error("LAB_TOPOLOGY_NOT_VERIFIED")); else done(value); } catch { reject(new Error("LAB_PROOF_INVALID")); } }); }); req.on("error", reject); req.on("timeout", () => req.destroy(new Error("LAB_PROOF_TIMEOUT"))); req.end(); });
    let ready = false; for (let attempt = 0; attempt < 40; attempt++) { try { await readProof(randomBytes(16).toString("hex")); ready = true; break; } catch { if (children.some((child) => child.exitCode !== null)) throw new Error(`LAB_PROXY_PROCESS_EXITED: ${diagnostics.join("").slice(0, 4096)}`); await new Promise((done) => setTimeout(done, 100)); } }
    if (!ready) throw new Error("LAB_PROXY_STARTUP_TIMEOUT");
    return { origin, ca: cert.cert, deploymentSha256, binaries, hopIds, upstreamProtocol, readProof, stop };
  } catch (error) { await stop(); throw error; }
}
