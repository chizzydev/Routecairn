import { existsSync, writeFileSync } from "node:fs";
import { join, relative, isAbsolute } from "node:path";
import { afterAll, describe, it, expect } from "vitest";
import { mutationRegistryPaths } from "../../src/core/offensive/MutationJournalRegistry.js";

const recorded: Array<{ root: string; journal: string; canary: string }> = [];
afterAll(() => {
  const parent = process.env.ROUTECAIRN_WORKER_LAB ?? process.env.ROUTECAIRN_TEST_RESOURCE_ROOT;
  if (!parent && !recorded[0]) throw Error("Explicit disposable lab required");
  const truth = recorded.map(r => ({ ...r, retained: existsSync(r.canary) }));
  writeFileSync(join(parent ?? recorded[0]!.root, "isolation-retention-" + process.pid + ".json"), JSON.stringify(truth, null, 2), { flag: "wx" });
  for (const item of truth) expect(item.retained, JSON.stringify(item)).toBe(true);
});
describe("global fixture isolation", () => {
  it("contains every legacy registry within its owned retained resource", () => {
    const journal = process.env.ROUTECAIRN_MUTATION_DIR;
    if (!journal) throw Error("Isolation hook did not initialize");
    const root = process.env.ROUTECAIRN_TEST_RESOURCE_ROOT ?? journal;
    const canary = join(journal, "SYNTHETIC_CANARY.txt"); writeFileSync(canary, "GENERATED_FIXTURE\n", { flag: "wx" }); recorded.push({ root, journal, canary });
    for (const path of mutationRegistryPaths(journal)) { const rel = relative(root, path); expect(rel.startsWith("..") || isAbsolute(rel), path).toBe(false); }
  });
});
