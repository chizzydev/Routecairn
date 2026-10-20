import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, parse, join } from "node:path";
import { minimizeOwnedHar } from "../src/dashboard/execution/OwnedHarMinimizer.js";
const [confirmation, harPath, metadataPath, output, ...rest] = process.argv.slice(2);
if (confirmation !== "--i-own-this-offline-export" || !harPath || !metadataPath || !output || rest.length)
  throw Error("USAGE_EXPLICIT_OFFLINE_OWNERSHIP_HAR_METADATA_NEW_OUTPUT");
function read(path: string) {
  const absolute = resolve(path),
    parts = absolute.slice(parse(absolute).root.length).split(/[\\/]/),
    base = parse(absolute).root;
  let current = base;
  for (const p of parts) {
    current = join(current, p);
    if (lstatSync(current).isSymbolicLink()) throw Error("OWNED_HAR_ALIAS_REFUSED");
  }
  const s = lstatSync(absolute);
  if (!s.isFile() || s.nlink !== 1 || s.size > 8388608) throw Error("OWNED_HAR_ORDINARY_FILE_BOUND");
  const b = readFileSync(absolute);
  if (b.length > 8388608) throw Error("OWNED_HAR_READ_BOUND");
  return b;
}
const artifact = minimizeOwnedHar(read(harPath), JSON.parse(read(metadataPath).toString("utf8")));
// CreateNew output; never replace a source export or existing evidence.
writeFileSync(resolve(output), JSON.stringify(artifact, null, 2) + "\n", { flag: "wx" });
console.log(
  JSON.stringify({
    offline: true,
    requestsSent: 0,
    executionAuthority: "NONE",
    origin: artifact.origin,
    routes: artifact.routes.length,
    identityStatus: "OWNER_DECLARED_NOT_NATIVE_VERIFIED"
  })
);
