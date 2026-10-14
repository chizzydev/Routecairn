import { stageAFixture } from "./trusted-discovery-stage-a.fixture.js";
import { appendFileSync } from "node:fs";

/** Test-owned native process; never imported by shipping UI/server code. */
const f = await stageAFixture({ preview: true });
process.send?.({ url: f.handle.url, org: f.org, target: f.target, scan: f.initial.scanId, candidate: f.initial.candidateId, cookie: f.auth.cookie, csrf: f.auth.csrf, origin: f.security.publicOrigin });
let closing = false;
async function close() {
  if (closing) return;
  closing = true;
  try {
    const receipts = f.wire(), preconsents = (f.db.db.prepare("SELECT count(*) AS n FROM trusted_discovery_reviews WHERE state='PRECONSENTED'").get() as { n: number }).n;
    if (process.env.ROUTECAIRN_STAGE_C_WIRE_EVIDENCE) appendFileSync(process.env.ROUTECAIRN_STAGE_C_WIRE_EVIDENCE, JSON.stringify({ fixture: "actual-ui-to-native-dashboard", targetReceipts: receipts, preconsents }) + "\n");
    process.send?.({ receipts, preconsents });
  } finally {
    await f.close();
    process.disconnect?.();
  }
}
process.on("message", (message) => { if (message === "close") void close().catch((error: unknown) => { console.error(error); process.exitCode = 1; }); });
process.on("disconnect", () => { void close().catch((error: unknown) => { console.error(error); process.exitCode = 1; }); });
