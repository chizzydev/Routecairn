import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("dashboard responsive containment", () => {
  it("keeps Scan Studio controls and step navigation inside the page viewport", () => {
    const css = readFileSync("apps/dashboard-ui/src/styles.css", "utf8");

    expect(css).toMatch(
      /\.studio-steps\s*\{[^}]*min-width:\s*0;[^}]*max-width:\s*100%;[^}]*overflow-x:\s*auto;/s,
    );
    expect(css).toMatch(/\.studio-panel\s*\{[^}]*min-width:\s*0;/s);
    expect(css).toMatch(
      /\.studio-panel select,[\s\S]*?\.studio-panel textarea\s*\{[^}]*width:\s*100%;[^}]*min-width:\s*0;[^}]*max-width:\s*100%;/s,
    );
  });
});
