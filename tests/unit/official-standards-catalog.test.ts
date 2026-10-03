import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { beforeAll, describe, expect, it } from "vitest";
import { parseOfficialCatalog } from "../../src/standards/OfficialCatalogParser.js";
import { officialCatalogSchema, type OfficialSource } from "../../src/standards/OfficialCatalogSchema.js";
import { officialCatalogEntries, standardsCatalogIdentity, referencesFor } from "../../src/standards/StandardsCatalog.js";
import { mappingFor } from "../../src/standards/StandardsMappings.js";

let sources: OfficialSource[];
let bytes: Map<string, Buffer>;
beforeAll(async () => {
  sources = JSON.parse(await readFile("standards/sources.lock.json", "utf8")).sources;
  bytes = new Map(await Promise.all(sources.map(async (source) => [source.framework, await readFile(`standards/sources/${source.file}`)] as const)));
});
describe("complete official standards import", () => {
  it("reproduces every retained catalog byte from the pinned publisher datasets", async () => {
    const catalog = parseOfficialCatalog(sources, bytes);
    expect(`${JSON.stringify(catalog, null, 2)}\n`).toBe(await readFile("src/standards/catalog/official-catalog.json", "utf8"));
    expect(standardsCatalogIdentity.counts).toEqual({ OWASP_WSTG: 97, OWASP_ASVS: 345, OWASP_API_TOP_10: 10, CWE: 969, CAPEC: 615 });
    expect(catalog.entries.find((entry) => entry.id === "WSTG-v42-INPV-13")?.variants).toHaveLength(2);
    expect(catalog.entries.filter((entry) => entry.framework === "OWASP_ASVS").every((entry) => entry.level && entry.chapter && entry.section)).toBe(true);
  });
  it("rejects publisher byte tampering before parsing", () => {
    const altered = new Map(bytes); const buffer = Buffer.from(altered.get("OWASP_ASVS")!); buffer[100] ^= 1; altered.set("OWASP_ASVS", buffer);
    expect(() => parseOfficialCatalog(sources, altered)).toThrow("STANDARDS_SOURCE_INTEGRITY_FAILED");
  });
  it.each(["duplicate", "hierarchy", "unknown-field"])("rejects invalid ASVS source %s at the schema boundary", (mutation) => {
    const document = JSON.parse(bytes.get("OWASP_ASVS")!.toString("utf8"));
    if (mutation === "duplicate") document.requirements.push(document.requirements[0]);
    if (mutation === "hierarchy") document.requirements[0].section_id = "V2.1";
    if (mutation === "unknown-field") document.requirements[0].unexpected = true;
    const replacement = Buffer.from(JSON.stringify(document)); const altered = new Map(bytes); altered.set("OWASP_ASVS", replacement);
    const input = sources.map((source) => source.framework === "OWASP_ASVS" ? { ...source, bytes: replacement.length, sha256: createHash("sha256").update(replacement).digest("hex") } : source);
    expect(() => parseOfficialCatalog(input, altered)).toThrow();
  });
  it("rejects XML entity declarations even when input has a matching source digest", () => {
    const replacement = Buffer.concat([Buffer.from('<!DOCTYPE x [<!ENTITY x SYSTEM "file:///secret">]>'), bytes.get("CAPEC")!]);
    const altered = new Map(bytes); altered.set("CAPEC", replacement);
    const input = sources.map((source) => source.framework === "CAPEC" ? { ...source, bytes: replacement.length, sha256: createHash("sha256").update(replacement).digest("hex") } : source);
    expect(() => parseOfficialCatalog(input, altered)).toThrow("STANDARDS_XML_UNSAFE");
  });
  it("rejects fabricated, unversioned, future-version and retired references", () => {
    for (const id of ["WSTG-APIT-99", "WSTG-v42-APIT-99", "WSTG-INJT-05", "WSTG-v42-INPV-99"]) expect(() => referencesFor({ wstg: [id] })).toThrow();
    expect(() => referencesFor({ asvs: ["v5.0.1-1.2.4"] })).toThrow();
    const retired = officialCatalogEntries.find((entry) => entry.framework === "CAPEC" && entry.status === "Deprecated")!;
    expect(() => referencesFor({ capec: [retired.id] })).toThrow();
  });
  it("corrects semantic associations without inventing missing WSTG release identifiers", () => {
    expect(mappingFor("active-vulnerability-validation", "XXE").asvs).toContain("v5.0.0-1.5.1");
    expect(mappingFor("active-vulnerability-validation", "UNSAFE_DESERIALIZATION").asvs).toContain("v5.0.0-1.5.2");
    expect(mappingFor("active-vulnerability-validation", "CRLF_INJECTION").capec).toEqual(["CAPEC-34"]);
    expect(mappingFor("authentication-lifecycle", "SESSION_FIXATION").asvs).toEqual(["v5.0.0-7.2.4"]);
    expect(mappingFor("authentication-lifecycle", "REFRESH_TOKEN_ROTATION").asvs).toEqual(["v5.0.0-10.4.5"]);
    expect(mappingFor("active-vulnerability-validation", "DOM_XSS").wstg).toEqual(["WSTG-v42-CLNT-01"]);
    expect(mappingFor("api-graphql-authorization", "OBJECT_AUTHORIZATION").wstg).not.toContain("WSTG-v42-APIT-01");
    expect(mappingFor("api-graphql-authorization", "GRAPHQL_INTROSPECTION").wstg).toContain("WSTG-v42-APIT-01");
    expect(mappingFor("active-vulnerability-validation", "SSRF").api).not.toContain("API10:2023");
    expect(mappingFor("secret-boundary", "COOKIE").asvs).toEqual(["v5.0.0-3.3.4"]);
    expect(mappingFor("secret-boundary", "ERROR_RESPONSE").asvs).toEqual(["v5.0.0-16.5.1"]);
  });
  it("validates normalized catalog version, publisher, identity and completeness", () => {
    const catalog = parseOfficialCatalog(sources, bytes);
    for (const change of ["publisher", "version", "identity", "link"]) {
      const changed = structuredClone(catalog);
      if (change === "publisher") changed.sources[0]!.url = "https://example.test/catalog.json";
      if (change === "version") changed.sources[0]!.version = "latest";
      if (change === "identity") changed.entries.push(changed.entries[0]!);
      if (change === "link") changed.entries[0]!.url = "https://example.test/";
      expect(() => officialCatalogSchema.parse(changed)).toThrow();
    }
  });
});
