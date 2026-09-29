import { readFile } from "node:fs/promises";

const inputIndex = process.argv.indexOf("--input");
const input = inputIndex >= 0 ? process.argv[inputIndex + 1] : undefined;
if (!input) throw new Error("Pass --input security-reviews/vX.Y.Z.review.json.");
const attestation = JSON.parse(await readFile(input, "utf8"));
const { signature: _signature, ...payload } = attestation;
process.stdout.write(JSON.stringify(sortObject(payload)));

function sortObject(value) {
  if (Array.isArray(value)) return value.map(sortObject);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortObject(value[key])]));
  return value;
}
