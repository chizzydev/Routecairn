import { z } from "zod";
import { assertStandardsReference, officialCatalogEntries, standardsCatalogIdentity, wstgAreas, wstgAreaFor } from "./StandardsCatalog.js";
import { standardsMappingSha256 } from "./OfficialCatalogIdentity.js";
import { standardsFrameworks, type StandardsCoverageReport } from "./StandardsCoverageTypes.js";
import { priorityGaps } from "./StandardsCoverageObjectives.js";

const count = z.number().int().nonnegative();
const text = z.string().min(1).max(4000);
const outcome = z.enum(["FINDING", "NO_FINDING", "INCONCLUSIVE", "BLOCKED", "OBSERVED"]);
const reference = z.object({ framework: z.enum(standardsFrameworks), id: text, title: text, url: z.string().url(), strength: z.enum(["DIRECT", "SUPPORTING"]) }).strict();
const caseSchema = z.object({ moduleId: z.string().regex(/^[a-z][a-z0-9-]{0,100}$/), caseId: z.string().min(1).max(240), label: z.string().min(1).max(240), outcome, executed: z.literal(true), requestTransmitted: z.boolean().optional(), findingIds: z.array(text), evidenceRefs: z.array(text).min(1), references: z.array(reference).min(1) }).strict();
const reportShape = z.object({ schemaVersion: z.literal(2), generatedAt: z.string().datetime(), catalog: z.unknown(), validation: z.unknown(), frameworkTotals: z.array(z.unknown()).length(5), accounting: z.object({ plannedModules: count, executedCases: count, directlyMappedCases: count, supportingOnlyCases: count, unmappedCases: z.literal(0), findings: count, noFindings: count, inconclusive: count, blocked: count, observed: count }).strict(), cases: z.array(caseSchema), requirements: z.array(z.unknown()), wstgAreas: z.array(z.unknown()).length(12), apiRiskObjectives: z.array(z.unknown()).length(3), gaps: z.array(z.unknown()), notes: z.array(text) }).strict();

/** Reject edited, stale, unmapped, duplicated, or internally inconsistent accounting before export. */
export function validateStandardsCoverage(value: unknown): asserts value is StandardsCoverageReport {
  reportShape.parse(value);
  const report = value as StandardsCoverageReport;
  equal(report.catalog, standardsCatalogIdentity, "CATALOG_IDENTITY");
  equal(report.validation, { policy: "FAIL_ON_UNMAPPED", mappingScope: "BOUNDED_CASE_ASSOCIATION", mappingSha256: standardsMappingSha256 }, "MAPPING_IDENTITY");
  const cases = report.cases; const keys = new Set<string>();
  for (const item of cases) {
    const key = `${item.moduleId}/${item.caseId}`;
    if (keys.has(key)) throw new Error("STANDARDS_DUPLICATE_CASE"); keys.add(key);
    const refs = new Set<string>();
    for (const ref of item.references) { assertStandardsReference(ref); const id = `${ref.framework}/${ref.id}`; if (refs.has(id)) throw new Error("STANDARDS_DUPLICATE_REFERENCE"); refs.add(id); }
  }
  const direct = cases.filter((item) => item.references.some((ref) => ref.strength === "DIRECT")).length;
  equal(report.accounting, { plannedModules: report.accounting.plannedModules, executedCases: cases.length, directlyMappedCases: direct, supportingOnlyCases: cases.length - direct, unmappedCases: 0, findings: cases.filter((item) => item.outcome === "FINDING").length, noFindings: cases.filter((item) => item.outcome === "NO_FINDING").length, inconclusive: cases.filter((item) => item.outcome === "INCONCLUSIVE").length, blocked: cases.filter((item) => item.outcome === "BLOCKED").length, observed: cases.filter((item) => item.outcome === "OBSERVED").length }, "ACCOUNTING");
  const refs = new Map(cases.flatMap((item) => item.references).map((ref) => [`${ref.framework}/${ref.id}`, ref]));
  if (report.requirements.length !== refs.size) throw new Error("STANDARDS_REQUIREMENTS_MISMATCH");
  const seen = new Set<string>();
  for (const requirement of report.requirements) {
    const key = `${requirement.framework}/${requirement.id}`; const ref = refs.get(key);
    if (!ref || seen.has(key)) throw new Error("STANDARDS_REQUIREMENTS_MISMATCH"); seen.add(key);
    const linked = cases.filter((item) => item.references.some((entry) => entry.framework === ref.framework && entry.id === ref.id));
    equal(requirement, { framework: ref.framework, id: ref.id, title: ref.title, url: ref.url, directCases: ref.strength === "DIRECT" ? linked.length : 0, supportingCases: ref.strength === "SUPPORTING" ? linked.length : 0, findings: linked.filter((item) => item.outcome === "FINDING").length, noFindings: linked.filter((item) => item.outcome === "NO_FINDING").length, inconclusive: linked.filter((item) => item.outcome === "INCONCLUSIVE").length, blocked: linked.filter((item) => item.outcome === "BLOCKED").length, observed: linked.filter((item) => item.outcome === "OBSERVED").length, caseIds: linked.map((item) => `${item.moduleId}/${item.caseId}`).sort() }, "REQUIREMENT_COUNTS");
  }
  const totals = standardsCatalogIdentity.sources.map((source) => {
    const activeEntries = officialCatalogEntries.filter((entry) => entry.framework === source.framework && !/deprecated|obsolete/i.test(entry.status ?? "")).length;
    const mapped = report.requirements.filter((entry) => entry.framework === source.framework);
    const conclusiveEntries = mapped.filter((entry) => entry.findings + entry.noFindings > 0).length;
    return { framework: source.framework, catalogEntries: standardsCatalogIdentity.counts[source.framework], activeEntries, mappedEntries: mapped.length, conclusiveEntries, unassessedEntries: activeEntries - conclusiveEntries };
  });
  equal(report.frameworkTotals, totals, "FRAMEWORK_TOTALS");
  for (const [index, area] of wstgAreas.entries()) {
    const relevant = cases.filter((item) => item.references.some((ref) => ref.framework === "OWASP_WSTG" && wstgAreaFor(ref.id) === area.id));
    const mapped = report.requirements.filter((entry) => entry.framework === "OWASP_WSTG" && wstgAreaFor(entry.id) === area.id);
    const catalogRequirements = officialCatalogEntries.filter((entry) => entry.framework === "OWASP_WSTG" && wstgAreaFor(entry.id) === area.id).length;
    const conclusiveRequirements = mapped.filter((entry) => entry.findings + entry.noFindings > 0).length;
    equal(report.wstgAreas[index], { id: area.id, title: area.title, status: !relevant.length ? "NOT_ASSESSED" : conclusiveRequirements < catalogRequirements ? "PARTIAL" : "COVERED", executedCases: relevant.length, conclusiveCases: relevant.filter((item) => item.outcome === "FINDING" || item.outcome === "NO_FINDING").length, requirementIds: mapped.map((entry) => entry.id).sort((a, b) => a.localeCompare(b, undefined, { numeric: true })), catalogRequirements, mappedRequirements: mapped.length, conclusiveRequirements }, "WSTG_AREAS");
  }
  for (const [index, id] of ["API4:2023", "API6:2023", "API10:2023"].entries()) {
    const relevant = cases.filter((item) => item.references.some((ref) => ref.framework === "OWASP_API_TOP_10" && ref.id === id));
    const conclusiveCases = relevant.filter((item) => item.outcome === "FINDING" || item.outcome === "NO_FINDING").length;
    const title = officialCatalogEntries.find((entry) => entry.framework === "OWASP_API_TOP_10" && entry.id === id)!.title;
    equal(report.apiRiskObjectives[index], { id, title, engineIds: [...new Set(relevant.map((item) => item.moduleId))].sort(), executedCases: relevant.length, conclusiveCases, status: !relevant.length ? "NOT_ASSESSED" : !conclusiveCases ? "PARTIAL" : "COVERED" }, "API_OBJECTIVES");
  }
  equal(report.gaps, priorityGaps(report.requirements), "PRIORITY_GAPS");
}
function equal(actual: unknown, expected: unknown, field: string): void { if (canonical(actual) !== canonical(expected)) throw new Error(`STANDARDS_${field}_MISMATCH`); }
function canonical(value: unknown): string { if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`; if (value && typeof value === "object") return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`; return JSON.stringify(value); }
