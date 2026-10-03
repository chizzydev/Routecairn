import { copyFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const assets = [
  ["src/standards/catalog/official-catalog.json", "dist/standards/catalog/official-catalog.json"],
  ["src/core/plugins/ThirdPartyModuleRunner.mjs", "dist/core/plugins/ThirdPartyModuleRunner.mjs"],
  ["src/benchmark/fixtures/credibility-go.go", "dist/benchmark/fixtures/credibility-go.go"],
  ["src/benchmark/fixtures/credibility-python.py", "dist/benchmark/fixtures/credibility-python.py"]
];

for (const [sourceRelative, destinationRelative] of assets) {
  const source = resolve(packageRoot, sourceRelative);
  const destination = resolve(packageRoot, destinationRelative);
  await mkdir(dirname(destination), { recursive: true });
  await copyFile(source, destination);
}
