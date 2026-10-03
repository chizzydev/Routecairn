import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { StandardsFramework, StandardsReference } from "./StandardsCoverageTypes.js";
import { officialCatalogCounts, officialCatalogSha256, officialSourceLockSha256 } from "./OfficialCatalogIdentity.js";
import { officialCatalogSchema } from "./OfficialCatalogSchema.js";

export interface StandardsMapping { wstg?: readonly string[]; asvs?: readonly string[]; api?: readonly string[]; cwe?: readonly string[]; capec?: readonly string[]; }
const bytes = readFileSync(new URL("./catalog/official-catalog.json", import.meta.url));
if (bytes.length > 4 * 1024 * 1024 || createHash("sha256").update(bytes).digest("hex") !== officialCatalogSha256) throw new Error("STANDARDS_CATALOG_INTEGRITY_FAILED");
const document = officialCatalogSchema.parse(JSON.parse(bytes.toString("utf8")));
const entries = new Map(document.entries.map((entry) => [`${entry.framework}/${entry.id}`, Object.freeze(entry)]));
export const wstgAreas = Object.freeze(document.areas.map((area) => Object.freeze(area)));
export const officialCatalogEntries = Object.freeze(document.entries.map((entry) => Object.freeze(entry)));
export const standardsCatalogIdentity = Object.freeze({
  wstg: "4.2" as const, wstgSnapshotDate: "2026-10-02", asvs: "5.0.0" as const, apiSecurityTop10: "2023" as const,
  cwe: "4.20" as const, capec: "3.9" as const, sha256: officialCatalogSha256, sourceLockSha256: officialSourceLockSha256,
  sources: document.sources.map((source) => Object.freeze({ ...source })), counts: officialCatalogCounts
});
export function referencesFor(mapping: StandardsMapping): StandardsReference[] {
  const groups: Array<[StandardsFramework, readonly string[] | undefined]> = [["OWASP_WSTG", mapping.wstg], ["OWASP_ASVS", mapping.asvs], ["OWASP_API_TOP_10", mapping.api], ["CWE", mapping.cwe], ["CAPEC", mapping.capec]];
  const values = new Map<string, StandardsReference>();
  for (const [framework, ids] of groups) for (const id of ids ?? []) {
    const entry = entries.get(`${framework}/${id}`);
    if (!entry || /deprecated|obsolete/i.test(entry.status ?? "")) throw new Error(`Unknown or retired standards reference ${framework}/${id}.`);
    values.set(`${framework}/${id}`, { framework, id: entry.id, title: entry.title, url: entry.url, strength: framework === "CWE" || framework === "CAPEC" ? "SUPPORTING" : "DIRECT" });
  }
  return [...values.values()];
}
export function assertStandardsReference(reference: StandardsReference): void {
  const mappingKey = { OWASP_WSTG: "wstg", OWASP_ASVS: "asvs", OWASP_API_TOP_10: "api", CWE: "cwe", CAPEC: "capec" } as const;
  const key = mappingKey[reference.framework];
  if (!key) throw new Error("STANDARDS_REFERENCE_FRAMEWORK_INVALID");
  const expected = referencesFor({ [key]: [reference.id] })[0]!;
  if (reference.title !== expected.title || reference.url !== expected.url || reference.strength !== expected.strength) throw new Error(`STANDARDS_REFERENCE_METADATA_MISMATCH ${reference.framework}/${reference.id}`);
}
export function wstgAreaFor(id: string): string | undefined { return /^WSTG-v42-([A-Z]+)-/.exec(id)?.[1]; }
export function assertStandardsCatalog(): void {
  for (const [framework, count] of Object.entries(officialCatalogCounts)) if (document.entries.filter((entry) => entry.framework === framework).length !== count) throw new Error("STANDARDS_CATALOG_COUNT_MISMATCH");
}
assertStandardsCatalog();
