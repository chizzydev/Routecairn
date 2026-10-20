import { URL } from "node:url";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statfsSync } from "node:fs";
import { homedir, hostname, platform, release, arch } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";

export const frozenParent = "8192cda2b8475306ecbec215f7c3623d74af25ee";
export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
export function isLoopbackUrl(input) {
  try { const u = new URL(input); return ["http:", "https:"].includes(u.protocol) && ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname) && !u.username && !u.password; } catch { return false; }
}
export function machineProof(repository) {
  const core = JSON.parse(readFileSync(join(repository, "node_modules/playwright-core/browsers.json"), "utf8"));
  const revision = core.browsers.find((v) => v.name === "chromium-headless-shell").revision;
  const roots = [process.env.PLAYWRIGHT_BROWSERS_PATH, platform() === "win32" ? join(homedir(), "AppData", "Local", "ms-playwright") : join(process.env.XDG_CACHE_HOME || join(homedir(), ".cache"), "ms-playwright")].filter(Boolean);
  const suffix = platform() === "win32" ? ["chrome-headless-shell-win64", "chrome-headless-shell.exe"] : ["chrome-headless-shell-linux64", "chrome-headless-shell"];
  const executable = roots.map((root) => join(root, `chromium_headless_shell-${revision}`, ...suffix)).find(existsSync);
  const disk = statfsSync(repository);
  return { platform: platform(), release: release(), arch: arch(), node: process.version, abi: process.versions.modules, machineSha256: sha256(hostname()), freeBytes: Number(disk.bavail) * Number(disk.bsize), browser: { available: !!executable, executable: executable || null, playwright: JSON.parse(readFileSync(join(repository, "node_modules/playwright/package.json"))).version }, linuxNative: platform() === "linux" ? "AVAILABLE_NOT_TESTED" : "HOLD_REAL_LINUX_REQUIRED" };
}
export function sourceHead(repository) { return execFileSync("git", ["rev-parse", "HEAD"], { cwd: repository, encoding: "utf8", windowsHide: true }).trim(); }
export function assertTestAccounting(result, required, minimum = 0) {
  if (!result || result.success !== true || result.numPendingTests !== 0 || result.numFailedTests !== 0 || result.numPassedTests !== result.numTotalTests || result.numTotalTests < minimum) throw Error("D0_TEST_ACCOUNTING_FAILED");
  const files = new Map(); let assertions = 0;
  for (const file of result.testResults || []) {
    const name = file.name.replaceAll("\\", "/");
    const cases = file.assertionResults || [];
    if (file.status !== "passed" || cases.some((test) => test.status !== "passed")) throw Error("D0_FILE_NOT_FULLY_PASSED");
    assertions += cases.length; files.set(name, cases.length);
  }
  if (assertions !== result.numTotalTests) throw Error("D0_TOTAL_ASSERTION_MISMATCH");
  for (const [name, lowerBound] of Object.entries(required)) {
    const matches = [...files].filter(([path]) => path === name || path.endsWith("/" + name));
    if (matches.length !== 1 || matches[0][1] < lowerBound) throw Error("D0_REQUIRED_FILE_OR_COUNT_MISSING");
  }
  return { tests: assertions, files: files.size, failed: 0, skipped: 0 };
}
export function assertBrowserAccounting(result, required) {
  if (!result || result.realBrowser !== true || !result.browserVersion || result.targetReceipts !== 0 || result.nonLoopbackTransmissions !== 0 || result.cleanup !== "CONFIRMED") throw Error("D0_BROWSER_FACTS_FAILED");
  const ids = new Set(result.cases.map((v) => v.id));
  if (ids.size !== required.length || result.cases.length !== required.length || required.some((id) => !ids.has(id))) throw Error("D0_BROWSER_CASE_SET_FAILED");
  const counts = { passed: 0, failed: 0, blocked: 0 };
  for (const entry of result.cases) { if (!["PASS", "FAIL", "BLOCKED"].includes(entry.status)) throw Error("D0_BROWSER_STATUS_INVALID"); counts[entry.status === "PASS" ? "passed" : entry.status === "FAIL" ? "failed" : "blocked"]++; }
  return { ...counts, status: counts.failed ? "FAIL" : counts.blocked ? "HOLD" : "PASS" };
}
export function assertSafeExport(text, secrets = []) {
  if (text.length > 256 * 1024 || secrets.some((secret) => typeof secret === "string" && secret.length >= 8 && text.includes(secret)) || /(?:BEGIN (?:RSA |EC )?PRIVATE KEY|routecairn_session=|password_hash|canonical_path|sqlite_error|<script)/i.test(text)) throw Error("D0_PRIVATE_EXPORT_REJECTED");
  return sha256(text);
}
export function requireHeadroom(directory, minimumBytes = 2 * 1024 ** 3) {
  const disk = statfsSync(resolve(directory)); const available = Number(disk.bavail) * Number(disk.bsize);
  if (available < minimumBytes) throw Error("D0_DISK_HEADROOM_HOLD");
  return available;
}
