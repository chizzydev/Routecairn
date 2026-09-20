import { pathToFileURL } from "node:url";

const [entrypoint, outputLimitRaw] = process.argv.slice(2);
const outputLimit = Number(outputLimitRaw);
let raw = "";
for await (const chunk of process.stdin) {
  raw += chunk;
  if (Buffer.byteLength(raw) > 1024 * 1024) throw new Error("SDK_INPUT_LIMIT_EXCEEDED");
}
const input = JSON.parse(raw || "{}");
const implementation = await import(pathToFileURL(entrypoint).href);
if (typeof implementation.analyze !== "function") throw new Error("SDK_ANALYZE_EXPORT_REQUIRED");
const sdk = Object.freeze({
  schemaVersion: 1,
  hash(value) { return globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(value))).then((bytes) => Buffer.from(bytes).toString("hex")); },
  finding(inputFinding) { return Object.freeze({ ...inputFinding }); }
});
const result = await implementation.analyze(structuredClone(input), sdk);
const observations = Array.isArray(result?.observations) ? result.observations.slice(0, outputLimit) : [];
const findings = Array.isArray(result?.findings) ? result.findings.slice(0, outputLimit) : [];
process.stdout.write(JSON.stringify({ observations, findings, notes: Array.isArray(result?.notes) ? result.notes.slice(0, 100) : [] }));
