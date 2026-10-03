import { createHash } from "node:crypto";
import { load } from "cheerio";
import { unzipSync } from "fflate";
import { z } from "zod";
import { officialCatalogSchema, type OfficialCatalog, type OfficialCatalogEntry, type OfficialSource } from "./OfficialCatalogSchema.js";

const wstgSourceSchema = z.object({ categories: z.record(z.object({ id: z.string().regex(/^WSTG-[A-Z]+$/), tests: z.array(z.object({ id: z.string().regex(/^WSTG-[A-Z]+-\d{2}$/), name: z.string().min(1), reference: z.string().url(), objectives: z.array(z.string()) }).strict()).min(1) }).strict()) }).strict();
const asvsSourceSchema = z.object({ requirements: z.array(z.object({ chapter_id: z.string().regex(/^V\d+$/), chapter_name: z.string().min(1), section_id: z.string().regex(/^V\d+\.\d+$/), section_name: z.string().min(1), req_id: z.string().regex(/^V\d+\.\d+\.\d+$/), req_description: z.string().min(1), L: z.enum(["1", "2", "3"]) }).strict()).min(300) }).strict();

/** Parse only hash-verified publisher bytes. No entity expansion, scripts, or network parsing. */
export function parseOfficialCatalog(sources: readonly OfficialSource[], bytes: ReadonlyMap<string, Buffer>): OfficialCatalog {
  const entries: OfficialCatalogEntry[] = [];
  const areas: OfficialCatalog["areas"] = [];
  for (const source of sources) {
    const buffer = bytes.get(source.framework);
    if (!buffer || buffer.length !== source.bytes || createHash("sha256").update(buffer).digest("hex") !== source.sha256) throw new Error("STANDARDS_SOURCE_INTEGRITY_FAILED");
    if (source.framework === "OWASP_WSTG") {
      const document = wstgSourceSchema.parse(JSON.parse(buffer.toString("utf8")));
      for (const [title, category] of Object.entries(document.categories)) {
        areas.push({ id: category.id.slice(5), title });
        for (const test of category.tests) {
          const originalUrl = new URL(test.reference);
          const prefix = "/www-project-web-security-testing-guide/stable/";
          if (originalUrl.protocol !== "https:" || originalUrl.hostname !== "owasp.org" || !originalUrl.pathname.startsWith(prefix)) throw new Error("STANDARDS_WSTG_SOURCE_LINK_INVALID");
          // Published checklist links predate OWASP's dedicated host and directory-style URLs.
          const url = `https://wstg.owasp.org/v4.2/${originalUrl.pathname.slice(prefix.length).replace(/\.html$/, "")}/`;
          const id = test.id.replace("WSTG-", "WSTG-v42-");
          const existing = entries.find((entry) => entry.framework === source.framework && entry.id === id);
          // The released publisher checklist intentionally shares INPV-13 across two parser tests.
          if (existing) {
            if (id !== "WSTG-v42-INPV-13" || existing.variants) throw new Error("STANDARDS_SOURCE_DUPLICATE_ID");
            existing.variants = [{ title: existing.title, url: existing.url }, { title: test.name, url }];
          } else entries.push({ framework: source.framework, id, title: test.name, url });
        }
      }
    } else if (source.framework === "OWASP_ASVS") {
      for (const requirement of asvsSourceSchema.parse(JSON.parse(buffer.toString("utf8"))).requirements) {
        if (!requirement.req_id.startsWith(`${requirement.section_id}.`) || !requirement.section_id.startsWith(`${requirement.chapter_id}.`)) throw new Error("STANDARDS_ASVS_HIERARCHY_INVALID");
        entries.push({ framework: source.framework, id: `v5.0.0-${requirement.req_id.slice(1)}`, title: requirement.req_description, url: "https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json", level: requirement.L, chapter: requirement.chapter_name, section: requirement.section_name });
      }
    } else if (source.framework === "OWASP_API_TOP_10") {
      const content = buffer.toString("utf8");
      const risks = [...content.matchAll(/^\| \[(API(?:[1-9]|10):2023) - ([^\]]+)\]\[(api\d+)\]/gm)];
      if (risks.length !== 10) throw new Error("STANDARDS_API_SOURCE_INVALID");
      for (const risk of risks) {
        const file = new RegExp(`^\\[${risk[3]}\\]: ([a-z0-9-]+)\\.md$`, "m").exec(content)?.[1];
        if (!file) throw new Error("STANDARDS_API_SOURCE_LINK_INVALID");
        entries.push({ framework: source.framework, id: risk[1]!, title: risk[2]!, url: `https://owasp.org/API-Security/editions/2023/en/${file}/` });
      }
    } else {
      let xmlBytes = buffer;
      if (source.framework === "CWE") {
        const files = unzipSync(buffer, { filter: (file) => { if (file.originalSize > 32 * 1024 * 1024 || !/^cwec_v4\.20\.xml$/.test(file.name)) throw new Error("STANDARDS_ARCHIVE_INVALID"); return true; } });
        if (Object.keys(files).length !== 1) throw new Error("STANDARDS_ARCHIVE_INVALID");
        xmlBytes = Buffer.from(Object.values(files)[0]!);
      }
      const xml = xmlBytes.toString("utf8");
      if (xml.length > 32 * 1024 * 1024 || /<!DOCTYPE|<!ENTITY/i.test(xml)) throw new Error("STANDARDS_XML_UNSAFE");
      const $ = load(xml, { xml: true });
      const cwe = source.framework === "CWE";
      const root = cwe ? "Weakness_Catalog" : "Attack_Pattern_Catalog";
      if ($(root).length !== 1 || $(root).attr("Version") !== source.version) throw new Error("STANDARDS_XML_VERSION_INVALID");
      const nodes = $(`${root} > ${cwe ? "Weaknesses > Weakness" : "Attack_Patterns > Attack_Pattern"}`);
      if (nodes.length < (cwe ? 900 : 500)) throw new Error("STANDARDS_XML_INCOMPLETE");
      nodes.each((_index, node) => {
        const id = $(node).attr("ID"); const title = $(node).attr("Name"); const status = $(node).attr("Status");
        if (!id || !/^[1-9]\d*$/.test(id) || !title || !status) throw new Error("STANDARDS_XML_ENTRY_INVALID");
        entries.push({ framework: source.framework, id: `${source.framework}-${id}`, title, status, url: `https://${cwe ? "cwe" : "capec"}.mitre.org/data/definitions/${id}.html` });
      });
    }
  }
  entries.sort((a, b) => a.framework.localeCompare(b.framework, "en") || a.id.localeCompare(b.id, "en", { numeric: true }));
  return officialCatalogSchema.parse({ schemaVersion: 1, sources, areas, entries });
}
