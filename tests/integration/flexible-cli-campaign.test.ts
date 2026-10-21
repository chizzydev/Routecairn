import { it, expect } from "vitest";
import { Command } from "commander";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  registerWebAssessmentCommand,
  productionCampaignDigest,
  runProductionWebCampaign
} from "../../src/cli/commands/webAssessment.js";
import { flexibleFixture } from "../helpers/flexible-assessment-fixture.js";
it("real Commander prepare/review and native V2 campaign run accept one existing test account", async () => {
  const f = await flexibleFixture(1, { noIdentity: true });
  try {
    const campaignPath = join(f.root, "cli-campaign.json"),
      program = new Command().exitOverride();
    registerWebAssessmentCommand(program);
    await program.parseAsync([
      "node",
      "routecairn",
      "web-assessment",
      "prepare",
      f.origin + "/private",
      "--reference",
      "Exact owned synthetic CLI approval",
      "--actor-registry",
      f.registryPath,
      "--organization",
      f.registry.organizationId,
      "--output",
      campaignPath
    ]);
    expect(f.wire).toEqual([]);
    const campaign = JSON.parse(readFileSync(campaignPath, "utf8"));
    expect(campaign.authorization.productionCampaign.contractVersion).toBe(2);
    expect(campaign.authorization.productionCampaign.actorIds).toEqual(["actor0"]);
    expect(campaign.authorization.productionCampaign.identities).toBeUndefined();
    campaign.authorization.productionCampaign.rateLimitPerSecond = 3;
    campaign.authorization.productionCampaign.maxRequests = 60;
    writeFileSync(campaignPath, JSON.stringify(campaign));
    const review = new Command().exitOverride();
    registerWebAssessmentCommand(review);
    await review.parseAsync(["node", "routecairn", "web-assessment", "review", "--campaign", campaignPath]);
    expect(f.wire).toEqual([]);
    await expect(
      runProductionWebCampaign(campaign, "0".repeat(64), join(f.root, "rejected"), {
        actorRegistry: f.registryPath,
        organization: f.registry.organizationId
      })
    ).rejects.toThrow("REVIEW_DIGEST_MISMATCH");
    expect(f.wire).toEqual([]);
    const result = await runProductionWebCampaign(
      campaign,
      productionCampaignDigest(campaign),
      join(f.root, "cli-native"),
      { actorRegistry: f.registryPath, organization: f.registry.organizationId }
    );
    expect(result.status).toBe("COMPLETED");
    expect(f.wire.some((w) => w.path === "/private" && w.actor === "actor0")).toBe(true);
    expect(f.wire.some((w) => w.path === "/who")).toBe(false);
    const retention = JSON.parse(readFileSync(join(result.root, "retention.json"), "utf8")),
      receipt = { result, wire: f.wire, retention, synthetic: true, independentAccuracy: false };
    writeFileSync(join(f.root, "CLI_V2_NATIVE_RECEIPT.json"), JSON.stringify(receipt, null, 2), { flag: "wx" });
    expect(JSON.stringify(receipt)).not.toContain(f.tokens[0]);
  } finally {
    await f.close();
  }
});
