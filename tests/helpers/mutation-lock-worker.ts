import { GlobalMutationLock } from "../../src/core/offensive/MutationJournal.js";

const lock = new GlobalMutationLock(process.argv[2]!);
process.on("message", (command) => {
  void (async () => {
    if (command === "acquire") {
      try { await lock.acquire(`worker-${process.pid}`); process.send?.("ACQUIRED"); }
      catch { process.send?.("BLOCKED"); }
    } else if (command === "release") {
      await lock.release(); process.send?.("RELEASED");
    }
  })().catch(() => process.send?.("ERROR"));
});
process.send?.("READY");
