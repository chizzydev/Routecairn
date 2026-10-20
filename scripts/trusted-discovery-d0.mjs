import { setTimeout, clearTimeout } from "node:timers";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { spawn } from "node:child_process";
import { frozenParent, machineProof, sourceHead, requireHeadroom, assertBrowserAccounting, sha256 } from "./trusted-discovery-d0-policy.mjs";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const machine = machineProof(repository), head = sourceHead(repository);
if (head !== frozenParent) throw Error("D0_FROZEN_PARENT_MISMATCH");
const inventory = JSON.parse(readFileSync(join(repository, "tests/acceptance/trusted-discovery-d0-inventory.json")));
const base = { schemaVersion: 1, sourceHead: head, machine, productExecution: "UNREGISTERED", defaultDiscovery: "OFF", externalMonotonicAnchor: "HOLD", realScreenReader: "NOT_VERIFIED", independentOperator: false, externalTargetsTested: false };
if (process.argv.length === 3 && process.argv[2] === "--probe") { console.log(JSON.stringify(base)); }
else {
  if (process.argv.length !== 4 || process.argv[2] !== "--output") throw Error("Use --probe or --output FRESH_PRIVATE_DIRECTORY; no installation or production activation.");
  requireHeadroom(repository);
  const output = resolve(process.argv[3]); mkdirSync(output, { recursive: false, mode: 0o700 });
  const runId = randomUUID();
  const inputs = ["tests/acceptance/trusted-discovery-d0-browser.ts", "tests/acceptance/trusted-discovery-d0-fixture.ts", "scripts/trusted-discovery-d0-policy.mjs", "scripts/trusted-discovery-d0.mjs", "tests/acceptance/trusted-discovery-d0-inventory.json", "package.json", "package-lock.json", "npm-shrinkwrap.json", "apps/dashboard-ui/src/main.tsx", "apps/dashboard-ui/src/styles.css", "apps/dashboard-ui/src/TrustedDiscoveryWorkspace.tsx"];
  const hashes = Object.fromEntries(inputs.map((f) => [f, sha256(readFileSync(join(repository, f)))]));
  let browser = { status: "HOLD", reason: "BROWSER_BINARY_MISSING", cases: [] }, code = 2;
  if (machine.browser.available) {
    code = await new Promise((done) => {
      const child = spawn(process.execPath, ["--import", "tsx", join(repository, "tests/acceptance/trusted-discovery-d0-browser.ts"), output, machine.browser.executable], { cwd: repository, windowsHide: true, stdio: "inherit" });
      writeFileSync(join(output, "child-process.json"), JSON.stringify({ pid: child.pid, sourceHead: head, fixtureOnly: true }));
      const deadline = setTimeout(() => child.kill(), 300_000);
      child.once("error", () => { clearTimeout(deadline); done(1); }); child.once("exit", (exit) => { clearTimeout(deadline); done(exit ?? 1); });
    });
    try {
      browser = JSON.parse(readFileSync(join(output, "browser-proof.json"), "utf8"));
      const accounting = assertBrowserAccounting(browser, inventory.browserCases);
      if (accounting.status === "PASS" && code !== 0) throw Error("D0_BROWSER_EXIT_MISMATCH");
    } catch { code = 1; browser = { ...browser, status: "FAIL", reason: "BROWSER_EVIDENCE_OR_CLEANUP_FAILED" }; }
  }
  const sourceUnchanged = sourceHead(repository) === head && inputs.every((f) => sha256(readFileSync(join(repository, f))) === hashes[f]);
  const receipt = { ...base, runId, generatedAt: new Date().toISOString(), status: !sourceUnchanged || code === 1 ? "FAIL" : "HOLD_WITH_BLOCKER", browser, browserExit: code, sourceUnchanged, sources: hashes, blocked: ["REAL_LINUX_OWNER_RUN", "OPERATIONAL_PROTECTED_CUSTODY", "EXTERNAL_MONOTONIC_ANCHOR", "INDEPENDENT_OWNER_SIGNOFF"], optionalBrowserInstall: "node node_modules/playwright/cli.js install chromium (separate owner review/authorization; never automatic)" };
  writeFileSync(join(output, "acceptance-result.json"), JSON.stringify(receipt, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  writeFileSync(join(output, "acceptance-result.txt"), `D0=${receipt.status}\nOS=${machine.platform}\nREAL_BROWSER=${browser.status}\nLINUX_NATIVE=${machine.linuxNative}\nPRODUCT_EXECUTION=UNREGISTERED\nDEFAULT_DISCOVERY=OFF\nEXTERNAL_MONOTONIC_ANCHOR=HOLD\nSOURCE_UNCHANGED=${sourceUnchanged}\n`, { flag: "wx", mode: 0o600 });
  console.log(JSON.stringify({ D0: receipt.status, browser: browser.status, output })); process.exitCode = code === 1 || !sourceUnchanged ? 1 : code;
}
