import { describe, expect, it } from "vitest";
import { TechAwarePathGenerator } from "../../src/modules/pathDiscovery/TechAwarePathGenerator.js";

describe("TechAwarePathGenerator", () => {
  it("generates framework-specific paths from detected technologies", () => {
    const generator = new TechAwarePathGenerator();
    const paths = generator.generate([
      {
        name: "Next.js",
        category: "framework",
        confidence: "High",
        signals: ["/_next/static"]
      },
      {
        name: "WordPress",
        category: "cms",
        confidence: "High",
        signals: ["/wp-content/"]
      }
    ]);

    expect(paths).toEqual(
      expect.arrayContaining([
        { path: "/api/auth/session", source: "tech:Next.js" },
        { path: "/wp-login.php", source: "tech:WordPress" }
      ])
    );
  });
});
