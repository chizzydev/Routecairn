import { readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";

const repoRoot = process.cwd();
const allowedPlaywrightFiles = new Set([
  join("src", "modules", "browserCrawler", "PlaywrightCrawler.ts"),
  join("src", "modules", "browserCrawler", "BrowserLearning.ts"),
  join("src", "modules", "browserCrawler", "BrowserProofVerifier.ts"),
  join("src", "modules", "browserCrawler", "Screenshotter.ts")
]);

describe("browser architecture invariants", () => {
  it("keeps Playwright construction inside the hardened browser layer", () => {
    const files = execFileSync("rg", ["--files", "src"], { cwd: repoRoot, encoding: "utf8" })
      .split(/\r?\n/)
      .filter((file) => file.endsWith(".ts"));

    const offenders = files.flatMap((file) => {
      const content = readFileSync(join(repoRoot, file), "utf8");
      const importsPlaywright = /from\s+["']playwright["']/.test(content);
      const createsRawBrowser = /chromium\.launch|firefox\.launch|webkit\.launch|launchPersistentContext|newContext\(|newPage\(|newCDPSession|setInputFiles|accept\(/.test(content);
      const allowed = allowedPlaywrightFiles.has(file);
      return (importsPlaywright || createsRawBrowser) && !allowed ? [file] : [];
    });

    expect(offenders).toEqual([]);
  });
});
