import { createInterface } from "node:readline";
import { syncBuiltinESMExports } from "node:module";
import childProcess from "node:child_process";
import dgram from "node:dgram";
import dns from "node:dns";
import http from "node:http";
import http2 from "node:http2";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { pathToFileURL } from "node:url";

const [entrypoint, outputLimitRaw] = process.argv.slice(2);
const outputLimit = Number(outputLimitRaw);
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
const pending = new Map();
let initialize;
const initialized = new Promise((resolve, reject) => { initialize = { resolve, reject }; });

lines.on("line", (line) => {
  if (Buffer.byteLength(line) > 2 * 1024 * 1024) return initialize?.reject(new Error("SDK_RPC_MESSAGE_LIMIT_EXCEEDED"));
  let message;
  try { message = JSON.parse(line); } catch { return initialize?.reject(new Error("SDK_RPC_MESSAGE_INVALID")); }
  if (message?.type === "init" && initialize) { if (message.protocolVersion !== 1) return initialize.reject(new Error("SDK_RPC_VERSION_UNSUPPORTED")); const current = initialize; initialize = undefined; current.resolve(message); return; }
  if (message?.type !== "rpc-response" || message.protocolVersion !== 1 || typeof message.id !== "string") return;
  const waiter = pending.get(message.id); if (!waiter) return;
  pending.delete(message.id);
  if (message.ok === true) waiter.resolve(message.result);
  else waiter.reject(new Error(typeof message.errorCode === "string" ? message.errorCode : "SDK_RPC_REQUEST_FAILED"));
});
lines.on("error", (error) => initialize?.reject(error));

const init = await initialized;
const input = structuredClone(init.input ?? {});
let requestId = 0;
const active = new Set();
const request = (proposal) => {
  if (init.capabilities?.requestBroker !== true) return Promise.reject(new Error("SDK_REQUEST_BROKER_UNAVAILABLE"));
  const id = String(++requestId);
  const promise = new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    process.stdout.write(`${JSON.stringify({ protocolVersion: 1, type: "rpc-request", id, proposal: structuredClone(proposal) })}\n`);
  });
  active.add(promise); promise.finally(() => active.delete(promise)).catch(() => undefined); return promise;
};
const sdk = Object.freeze({
  schemaVersion: 2,
  hash(value) { return globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(value))).then((bytes) => Buffer.from(bytes).toString("hex")); },
  finding(inputFinding) { return Object.freeze({ ...inputFinding }); },
  request,
  capabilities: Object.freeze({ requestBroker: init.capabilities?.requestBroker === true, request })
});
for (const name of ["log", "info", "warn", "error", "debug"]) console[name] = () => undefined;
denyDirectCapabilities();
const implementation = await import(pathToFileURL(entrypoint).href);
if (typeof implementation.analyze !== "function") throw new Error("SDK_ANALYZE_EXPORT_REQUIRED");
const result = await implementation.analyze(input, sdk);
if (active.size) await Promise.allSettled([...active]);
const observations = Array.isArray(result?.observations) ? result.observations.slice(0, outputLimit) : [];
const findings = Array.isArray(result?.findings) ? result.findings.slice(0, outputLimit) : [];
lines.close();
process.stdout.write(`${JSON.stringify({ protocolVersion: 1, type: "result", result: { observations, findings, notes: Array.isArray(result?.notes) ? result.notes.slice(0, 100) : [] } })}\n`, () => process.exit(0));

function denyDirectCapabilities() {
  const denied = () => { throw new Error("SDK_DIRECT_CAPABILITY_DENIED"); };
  for (const name of ["exec", "execFile", "fork", "spawn"]) childProcess[name] = denied;
  for (const name of ["createConnection", "connect"]) net[name] = denied;
  net.Socket.prototype.connect = denied;
  tls.connect = denied;
  for (const transport of [http, https]) for (const name of ["request", "get"]) transport[name] = denied;
  http2.connect = denied;
  dgram.createSocket = denied;
  for (const name of ["bind", "connect", "send"]) if (typeof dgram.Socket.prototype[name] === "function") dgram.Socket.prototype[name] = denied;
  for (const name of ["lookup", "lookupService", "resolve", "resolve4", "resolve6", "resolveAny", "resolveCaa", "resolveCname", "resolveMx", "resolveNaptr", "resolveNs", "resolvePtr", "resolveSoa", "resolveSrv", "resolveTxt", "reverse", "setServers"]) if (typeof dns[name] === "function") dns[name] = denied;
  if (dns.Resolver?.prototype) for (const name of Object.getOwnPropertyNames(dns.Resolver.prototype)) if (name !== "constructor" && typeof dns.Resolver.prototype[name] === "function") dns.Resolver.prototype[name] = denied;
  if (dns.promises) for (const name of Object.keys(dns.promises)) if (typeof dns.promises[name] === "function") { try { dns.promises[name] = denied; } catch { /* immutable accessor */ } }
  if (dns.promises?.Resolver?.prototype) for (const name of Object.getOwnPropertyNames(dns.promises.Resolver.prototype)) if (name !== "constructor" && typeof dns.promises.Resolver.prototype[name] === "function") { try { dns.promises.Resolver.prototype[name] = denied; } catch { /* immutable accessor */ } }
  globalThis.fetch = denied;
  if ("WebSocket" in globalThis) globalThis.WebSocket = class { constructor() { denied(); } };
  syncBuiltinESMExports();
  process.binding = denied;
  process._linkedBinding = denied;
  process.dlopen = denied;
}
