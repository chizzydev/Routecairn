import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JSDOM } from "jsdom";
import { expect, it } from "vitest";
import { HtmlReportWriter } from "../../src/reports/HtmlReportWriter.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";

it("renders report values as text even inside badge attributes and script data", async () => {
  const directory = await mkdtemp(join(tmpdir(), "routecairn-html-safety-"));
  try {
    const report = JSON.parse(await readFile("acceptance/standards/2026-10-02/verified-windows-node24/runtime/report.json", "utf8")) as RouteCairnReport;
    const malicious = '"><img data-injected="yes" src=x onerror="window.reportInjected=true">';
    const first = report.findings[0]!;
    first.title = "</script><script>window.reportInjected=true</script>";
    first.severity = malicious as typeof first.severity;
    report.proofMode = { blocks: [{ id: "malicious-observation", source: "finding", title: first.title, severity: malicious, severityReason: malicious, targetUrl: "https://example.test/", comparisons: [], manualVerificationSteps: [], stillRequiresManualVerification: true }] } as unknown as NonNullable<RouteCairnReport["proofMode"]>;
    const path = await new HtmlReportWriter().write(directory, report);
    const dom = new JSDOM(await readFile(path, "utf8"), { runScripts: "dangerously", url: "https://report.example.test/" });
    try {
      await new Promise<void>((done) => dom.window.addEventListener("load", () => done(), { once: true }));
      expect(dom.window.document.querySelector("img[data-injected]")).toBeNull();
      expect((dom.window as unknown as { reportInjected?: boolean }).reportInjected).toBeUndefined();
      expect(dom.window.document.body.textContent).toContain(first.title);
    } finally { dom.window.close(); }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
