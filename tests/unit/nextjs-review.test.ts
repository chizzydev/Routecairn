import { describe, expect, it } from "vitest";
import { ScanContext } from "../../src/core/engine/ScanContext.js";
import { NextJsReviewModule } from "../../src/modules/nextjsReview/NextJsReviewModule.js";
import { defaultConfig, exampleScope } from "../../src/config/defaults.js";
import { testPlan } from "../helpers/plan.js";

describe("NextJsReviewModule", () => {
  it("skips when Next.js is not detected", async () => {
    const context = new ScanContext({
      target: "https://example.test/",
      scope: exampleScope,
      config: defaultConfig,
      plan: testPlan("quick"),
      outputDir: "."
    });
    const result = await new NextJsReviewModule().run(context);
    expect(result.nextJsReview).toMatchObject({ detected: false, dataRoutes: [], sourceMaps: [] });
  });
});
