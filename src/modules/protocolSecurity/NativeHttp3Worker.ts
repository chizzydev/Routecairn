import dns from "node:dns";
import { isIP } from "node:net";
import { stdin, stdout } from "node:process";
import { parentPort, workerData } from "node:worker_threads";
import quico from "quico";

interface NativeHttp3WorkerRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  bodyBase64?: string;
}

interface NativeHttp3WorkerInput {
  hostname: string;
  pinnedAddress: string;
  family: 4 | 6;
  port: number;
  timeoutMs: number;
  maxBytes: number;
  ca?: string;
  requests: NativeHttp3WorkerRequest[];
}

interface NativeHttp3WorkerResponse {
  statusCode: number;
  protocol: "h3";
  headers: Record<string, string | string[]>;
  bodyBase64: string;
}

const input = parentPort ? workerData as NativeHttp3WorkerInput : await readInput();
validateInput(input);

// QUICO currently uses node:dns directly and has no lookup hook. This worker is
// deliberately isolated so its resolver can be restricted to the address that
// RouteCairn already approved without modifying process-global DNS behavior.
if (!isIP(input.hostname) && input.hostname !== "localhost") {
  const lookup = dns.lookup.bind(dns);
  dns.lookup = ((hostname: string, options: unknown, callback?: unknown) => {
    const cb = typeof options === "function" ? options : callback;
    if (typeof cb !== "function") return lookup(hostname, options as never, callback as never);
    if (hostname.toLowerCase() !== input.hostname.toLowerCase()) {
      const error = Object.assign(new Error("HTTP3_WORKER_DNS_BLOCKED"), { code: "ENOTFOUND" });
      return process.nextTick(() => (cb as (error: Error) => void)(error));
    }
    const all = typeof options === "object" && options !== null && "all" in options && Boolean((options as { all?: boolean }).all);
    dns.lookup = lookup;
    return process.nextTick(() => all
      ? (cb as (error: null, addresses: Array<{ address: string; family: number }>) => void)(null, [{ address: input.pinnedAddress, family: input.family }])
      : (cb as (error: null, address: string, family: number) => void)(null, input.pinnedAddress, input.family));
  }) as typeof dns.lookup;
}

void main();

async function main(): Promise<void> {
  try {
    const responses: NativeHttp3WorkerResponse[] = [];
    let connection: unknown;
    let sameConnection = true;
    for (const request of input.requests) {
      responses.push(await execute(request));
      const current = (quico.globalAgent as unknown as { getH3Connection(host: string, port: number): unknown }).getH3Connection(input.hostname, input.port);
      if (connection !== undefined && current !== connection) sameConnection = false;
      connection = current;
    }
    send({ ok: true, responses, sameConnection });
  } catch (error) {
    send({ ok: false, error: safeError(error) });
  } finally {
    quico.globalAgent.destroy();
  }
}

function send(value: unknown): void {
  if (parentPort) parentPort.postMessage(value);
  else stdout.write(`${JSON.stringify(value)}\n`);
}

async function readInput(): Promise<NativeHttp3WorkerInput> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stdin) {
    const value = Buffer.from(chunk);
    size += value.length;
    if (size > 4 * 1024 * 1024) throw new Error("HTTP3_NATIVE_INPUT_LIMIT");
    chunks.push(value);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as NativeHttp3WorkerInput;
}

function execute(item: NativeHttp3WorkerRequest): Promise<NativeHttp3WorkerResponse> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let request: ReturnType<typeof quico.request>;
    const timer = setTimeout(() => finish(new Error("HTTP3_NATIVE_TIMEOUT")), input.timeoutMs);
    const finish = (error?: Error, value?: NativeHttp3WorkerResponse) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) { request?.abort(); reject(error); }
      else resolve(value!);
    };
    request = quico.request({
      hostname: input.hostname,
      port: input.port,
      path: item.path,
      method: item.method,
      headers: item.headers,
      rejectUnauthorized: true,
      ...(input.ca ? { ca: input.ca } : {}),
      http1: false,
      http2: false,
      h3Timeout: input.timeoutMs
    } as never, (response) => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => {
        const value = Buffer.from(chunk);
        size += value.length;
        if (size > input.maxBytes) finish(new Error("HTTP3_RESPONSE_LIMIT_EXCEEDED"));
        else chunks.push(value);
      });
      response.on("error", (error: Error) => finish(error));
      response.on("end", () => {
        const protocol = String(response.httpVersion ?? "");
        if (protocol !== "3.0" && protocol !== "3") return finish(new Error("HTTP3_NEGOTIATION_FAILED"));
        finish(undefined, { statusCode: Number(response.statusCode ?? 0), protocol: "h3", headers: normalizeHeaders(response.headers), bodyBase64: Buffer.concat(chunks).toString("base64") });
      });
    });
    request.on("error", (error) => finish(error));
    request.end(item.bodyBase64 ? Buffer.from(item.bodyBase64, "base64") : undefined);
  });
}

function normalizeHeaders(value: unknown): Record<string, string | string[]> {
  if (!value || typeof value !== "object") return {};
  const result: Record<string, string | string[]> = {};
  for (const [name, item] of Object.entries(value as Record<string, unknown>)) {
    if (typeof item === "string") result[name.toLowerCase()] = item;
    else if (Array.isArray(item) && item.every((entry) => typeof entry === "string")) result[name.toLowerCase()] = item as string[];
  }
  return result;
}

function validateInput(value: NativeHttp3WorkerInput): void {
  if (!value || typeof value !== "object") throw new Error("HTTP3_NATIVE_INPUT_INVALID");
  if (!value.hostname || value.hostname.length > 253 || !isIP(value.pinnedAddress)) throw new Error("HTTP3_NATIVE_DESTINATION_INVALID");
  if (isIP(value.hostname) && value.hostname !== value.pinnedAddress) throw new Error("HTTP3_NATIVE_PIN_MISMATCH");
  if (value.hostname === "localhost" && value.pinnedAddress !== "127.0.0.1") throw new Error("HTTP3_NATIVE_PIN_MISMATCH");
  if ((value.family !== 4 && value.family !== 6) || isIP(value.pinnedAddress) !== value.family) throw new Error("HTTP3_NATIVE_FAMILY_MISMATCH");
  if (!Number.isInteger(value.port) || value.port < 1 || value.port > 65535) throw new Error("HTTP3_NATIVE_PORT_INVALID");
  if (!Number.isInteger(value.timeoutMs) || value.timeoutMs < 1 || value.timeoutMs > 300_000) throw new Error("HTTP3_NATIVE_TIMEOUT_INVALID");
  if (!Number.isInteger(value.maxBytes) || value.maxBytes < 1 || value.maxBytes > 64 * 1024 * 1024) throw new Error("HTTP3_NATIVE_LIMIT_INVALID");
  if (!Array.isArray(value.requests) || value.requests.length > 4) throw new Error("HTTP3_NATIVE_REQUEST_COUNT_INVALID");
  for (const request of value.requests) {
    if (!request || typeof request !== "object" || !/^[A-Z]+$/.test(request.method) || !request.path.startsWith("/") || request.path.length > 16_384) throw new Error("HTTP3_NATIVE_REQUEST_INVALID");
    if (!request.headers || typeof request.headers !== "object" || Object.keys(request.headers).length > 128) throw new Error("HTTP3_NATIVE_HEADERS_INVALID");
  }
}

function safeError(error: unknown): string {
  const value = error instanceof Error ? error.message.toUpperCase() : "";
  const known = ["ABORT", "CERT", "DNS", "INPUT", "LIMIT", "NEGOTIATION", "PIN", "RESPONSE", "TIMEOUT"].find((code) => value.includes(code));
  return known ? `HTTP3_NATIVE_FAILURE:${known}` : "HTTP3_NATIVE_FAILURE:RUNTIME";
}
