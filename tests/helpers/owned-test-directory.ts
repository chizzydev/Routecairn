import { tmpdir } from "node:os";
import { join } from "node:path";
import { OwnedTemporaryResource } from "../../src/core/storage/OwnedTemporaryResource.js";

const resources = new Map<string, OwnedTemporaryResource>();
export function createOwnedTestDirectory(purpose: string): string {
  const resource = OwnedTemporaryResource.create(process.env.ROUTECAIRN_TEST_RESOURCE_ROOT ?? join(tmpdir(), "routecairn-owned-test-resources"), { purpose, process: String(process.pid) });
  resources.set(resource.root, resource); return resource.root;
}
export function retainOwnedTestDirectory(root: string): void {
  const resource = resources.get(root); if (!resource) throw Error("TEST_DIRECTORY_UNOWNED");
  const receipt = resource.retain("TEST_FINISHED"); resources.delete(root);
  if (receipt.state !== "RETAINED") throw Error("TEST_DIRECTORY_UNKNOWN_RETAINED");
}
