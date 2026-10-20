import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdirSync } from "node:fs";
import { beforeEach, afterEach } from "vitest";
import { OwnedTemporaryResource } from "../../src/core/storage/OwnedTemporaryResource.js";

// Environment variables are process-global; overlapping owners are refused.
let active: { task: string; resource: OwnedTemporaryResource; previous: string | undefined; root: string | undefined } | undefined;
beforeEach(context => {
  if (active) throw Error("CONCURRENT_MUTATION_ISOLATION_REFUSED");
  const resource = OwnedTemporaryResource.create(join(tmpdir(), "routecairn-test-resources"), { purpose: "test-mutation-isolation", process: String(process.pid) });
  const primary = join(resource.directory("journals"), "primary");
  mkdirSync(primary);
  active = { task: context.task.id, resource, previous: process.env.ROUTECAIRN_MUTATION_DIR, root: process.env.ROUTECAIRN_TEST_RESOURCE_ROOT };
  process.env.ROUTECAIRN_MUTATION_DIR = primary;
  process.env.ROUTECAIRN_TEST_RESOURCE_ROOT = resource.root;
});
afterEach(context => {
  const current = active; if (!current) return;
  if (current.task !== context.task.id) return;
  active = undefined;
  if (current.previous === undefined) delete process.env.ROUTECAIRN_MUTATION_DIR; else process.env.ROUTECAIRN_MUTATION_DIR = current.previous;
  if (current.root === undefined) delete process.env.ROUTECAIRN_TEST_RESOURCE_ROOT; else process.env.ROUTECAIRN_TEST_RESOURCE_ROOT = current.root;
  const receipt = current.resource.retain("TEST_FINISHED");
  if (receipt.state !== "RETAINED") throw Error("TEST_RESOURCE_UNKNOWN_RETAINED:" + String(receipt.error));
});
