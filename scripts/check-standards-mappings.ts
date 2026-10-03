import { readFile } from "node:fs/promises";
import { validateBuiltInStandardsMappings } from "../src/standards/StandardsMappingValidation.js";
import { referencesFor, type StandardsMapping } from "../src/standards/StandardsCatalog.js";

const mappings = validateBuiltInStandardsMappings();
const source = await readFile(new URL("../src/standards/StandardsMappings.ts", import.meta.url), "utf8");
const keys = { WSTG: "wstg", "v5.0.0": "asvs", API: "api", CWE: "cwe", CAPEC: "capec" } as const;
const ids = [...new Set([...source.matchAll(/"((?:WSTG-v42-[A-Z]+-\d{2}|v5\.0\.0-\d+\.\d+\.\d+|API(?:[1-9]|10):2023|CWE-\d+|CAPEC-\d+))"/g)].map((match) => match[1]!))];
for (const id of ids) {
  const prefix = id.startsWith("API") ? "API" : id.split("-")[0]!;
  const key = keys[prefix as keyof typeof keys];
  referencesFor({ [key]: [id] } as StandardsMapping);
}
process.stdout.write(`${JSON.stringify({ status: "VERIFIED", builtInMappings: mappings.length, publishedReferences: ids.length })}\n`);
