import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { beforeEach, afterEach } from "vitest";

let directory: string;
let previous: string | undefined;
beforeEach(async () => {
  previous = process.env.ROUTECAIRN_MUTATION_DIR;
  directory = await mkdtemp(join(tmpdir(), "routecairn-test-coordinator-"));
  process.env.ROUTECAIRN_MUTATION_DIR = directory;
});
afterEach(async () => {
  if (previous === undefined) delete process.env.ROUTECAIRN_MUTATION_DIR;
  else process.env.ROUTECAIRN_MUTATION_DIR = previous;
  const absolute = resolve(directory);
  if (!absolute.startsWith(resolve(tmpdir()) + sep) || !absolute.includes("routecairn-test-coordinator-")) throw new Error("Invalid test cleanup directory");
  await rm(absolute, { recursive: true, force: true });
});
