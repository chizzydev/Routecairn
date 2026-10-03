import { z } from "zod";
import { standardsFrameworks } from "./StandardsCoverageTypes.js";

export const officialSourceSchema = z.object({
  framework: z.enum(standardsFrameworks), version: z.string().min(1).max(32),
  file: z.string().regex(/^[a-z0-9.-]+$/), url: z.string().url(),
  revision: z.string().regex(/^[a-f0-9]{40}$/).optional(), license: z.string().min(1),
  bytes: z.number().int().positive().max(32 * 1024 * 1024), sha256: z.string().regex(/^[a-f0-9]{64}$/)
}).strict();
export const officialCatalogEntrySchema = z.object({
  framework: z.enum(standardsFrameworks), id: z.string().min(1), title: z.string().min(1).max(4000), url: z.string().url(),
  level: z.enum(["1", "2", "3"]).optional(), chapter: z.string().optional(), section: z.string().optional(),
  status: z.string().optional(), variants: z.array(z.object({ title: z.string().min(1), url: z.string().url() }).strict()).min(1).optional()
}).strict();
export const officialCatalogSchema = z.object({
  schemaVersion: z.literal(1), sources: z.array(officialSourceSchema).length(5),
  areas: z.array(z.object({ id: z.string().regex(/^[A-Z]+$/), title: z.string().min(1) }).strict()).length(12),
  entries: z.array(officialCatalogEntrySchema).min(1000).max(10000)
}).strict().superRefine((document, ctx) => {
  const sources = new Set(document.sources.map((source) => source.framework));
  if (sources.size !== 5) ctx.addIssue({ code: "custom", message: "Every framework requires one official source." });
  const versions = { OWASP_WSTG: "4.2", OWASP_ASVS: "5.0.0", OWASP_API_TOP_10: "2023", CWE: "4.20", CAPEC: "3.9" };
  for (const source of document.sources) {
    const url = new URL(source.url);
    const publisher = { OWASP_WSTG: "OWASP/wstg", OWASP_ASVS: "OWASP/ASVS", OWASP_API_TOP_10: "OWASP/API-Security" };
    const github = source.framework in publisher;
    if (source.version !== versions[source.framework] || url.protocol !== "https:" || url.username || url.password || url.port ||
      (github ? !source.revision || url.hostname !== "raw.githubusercontent.com" || !url.pathname.startsWith(`/${publisher[source.framework as keyof typeof publisher]}/${source.revision}/`) : url.hostname !== `${source.framework.toLowerCase()}.mitre.org` || !url.pathname.startsWith("/data/xml/"))) ctx.addIssue({ code: "custom", message: "Source version or publisher provenance is invalid." });
  }
  const ids = new Set<string>();
  for (const entry of document.entries) {
    const key = `${entry.framework}/${entry.id}`;
    if (ids.has(key)) ctx.addIssue({ code: "custom", message: `Duplicate catalog identity ${key}.` });
    ids.add(key);
    const patterns = { OWASP_WSTG: /^WSTG-v42-[A-Z]+-\d{2}$/, OWASP_ASVS: /^v5\.0\.0-\d+\.\d+\.\d+$/, OWASP_API_TOP_10: /^API(?:[1-9]|10):2023$/, CWE: /^CWE-[1-9]\d*$/, CAPEC: /^CAPEC-[1-9]\d*$/ };
    if (!patterns[entry.framework].test(entry.id)) ctx.addIssue({ code: "custom", message: `Unversioned or invalid catalog identity ${key}.` });
    const url = new URL(entry.url);
    const hosts = { OWASP_WSTG: "wstg.owasp.org", OWASP_ASVS: "github.com", OWASP_API_TOP_10: "owasp.org", CWE: "cwe.mitre.org", CAPEC: "capec.mitre.org" };
    if (url.protocol !== "https:" || url.hostname !== hosts[entry.framework] || url.username || url.password || url.port) ctx.addIssue({ code: "custom", message: `Unofficial catalog link ${key}.` });
    if (entry.framework === "OWASP_WSTG" && !url.pathname.includes("/v4.2/")) ctx.addIssue({ code: "custom", message: "WSTG references must use released version 4.2." });
    if (entry.framework === "OWASP_ASVS" && !url.pathname.includes("/v5.0.0/")) ctx.addIssue({ code: "custom", message: "ASVS references must use released version 5.0.0." });
  }
});
export type OfficialCatalog = z.infer<typeof officialCatalogSchema>;
export type OfficialCatalogEntry = z.infer<typeof officialCatalogEntrySchema>;
export type OfficialSource = z.infer<typeof officialSourceSchema>;
