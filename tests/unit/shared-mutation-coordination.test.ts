import { fork, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { GlobalMutationLock, MutationJournal } from "../../src/core/offensive/MutationJournal.js";
import { MutationJournalRegistry } from "../../src/core/offensive/MutationJournalRegistry.js";
import { MutationRecoveryVault } from "../../src/core/offensive/MutationRecoveryVault.js";

const root = () => process.env.ROUTECAIRN_MUTATION_DIR!;
async function worker(path: string): Promise<ChildProcess> {
  const child = fork(resolve("tests/helpers/mutation-lock-worker.ts"), [path], { execArgv: ["--import", "tsx"], stdio: ["ignore", "ignore", "pipe", "ipc"] });
  try {
    expect(await childMessage(child, "startup")).toBe("READY");
    return child;
  } catch (error) {
    await stop(child);
    throw error;
  }
}
async function command(child: ChildProcess, value: string) { const result = childMessage(child, value); child.send(value); return result; }
async function stop(child: ChildProcess) { if (child.exitCode !== null || child.signalCode !== null) return; const exited = once(child, "exit"); child.kill("SIGKILL"); await exited; }

async function childMessage(child: ChildProcess, operation: string): Promise<unknown> {
  return new Promise((resolveMessage, rejectMessage) => {
    let stderr = "";
    const timer = setTimeout(() => finish(new Error(`Mutation lock worker ${operation} timed out.${stderr ? ` ${stderr}` : ""}`)), 10_000);
    const onMessage = (message: unknown) => finish(undefined, message);
    const onError = (error: Error) => finish(error);
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => finish(new Error(`Mutation lock worker exited during ${operation} (${code ?? signal ?? "unknown"}).${stderr ? ` ${stderr}` : ""}`));
    const onStderr = (chunk: Buffer) => { stderr = `${stderr}${chunk.toString("utf8")}`.slice(-2_000); };
    const finish = (error?: Error, message?: unknown) => {
      clearTimeout(timer);
      child.off("message", onMessage); child.off("error", onError); child.off("exit", onExit); child.stderr?.off("data", onStderr);
      if (error) rejectMessage(error); else resolveMessage(message);
    };
    child.once("message", onMessage); child.once("error", onError); child.once("exit", onExit); child.stderr?.on("data", onStderr);
  });
}

describe("central mutation coordination durability", () => {
  it("allows one process at a time and recovers after an actual worker crash", async () => {
    const path = join(root(), "global-mutation.lock");
    const children = await Promise.all([worker(path), worker(path), worker(path)]);
    try {
      const results = await Promise.all(children.map((child) => command(child, "acquire")));
      expect(results.filter((result) => result === "ACQUIRED")).toHaveLength(1);
      expect(results.filter((result) => result === "BLOCKED")).toHaveLength(2);
      await stop(children[results.indexOf("ACQUIRED")]!);
      const next = new GlobalMutationLock(path);
      await next.acquire("after-crash"); await next.release();
    } finally { await Promise.all(children.map(stop)); }
  }, 45_000);

  it("recovers incomplete lock metadata without removing a live contender's lock", async () => {
    const path = join(root(), "global-mutation.lock"); await writeFile(path, "");
    const first = new GlobalMutationLock(path), second = new GlobalMutationLock(path);
    await first.acquire("first");
    try {
      await expect(second.acquire("second")).rejects.toThrow("MUTATION_LOCK_HELD");
      await second.release();
      expect(JSON.parse(await readFile(path, "utf8")).caseId).toBe("first");
    } finally { await first.release(); }
  });

  it("rejects corrupt journal stages and never treats corruption as resolved cleanup", async () => {
    await writeFile(join(root(), "mutation-journal.json"), JSON.stringify([{ sequence: 1, caseId: "interrupted", timestamp: new Date().toISOString(), stage: "UNKNOWN" }]));
    await expect(new GlobalMutationLock(join(root(), "global-mutation.lock")).acquire("next")).rejects.toThrow("MUTATION_JOURNAL_INVALID");
  });

  it("blocks orphaned checkpoints even without a corresponding journal entry", async () => {
    await new MutationRecoveryVault(root()).seal({ caseId: "orphaned", restore: "private-value" });
    await expect(new GlobalMutationLock(join(root(), "global-mutation.lock")).acquire("next")).rejects.toThrow("UNRESOLVED_RECOVERY_CHECKPOINT");
  });

  it("serializes registry updates and checks obligations in every registered directory", async () => {
    const primary = join(root(), "central"); await mkdir(primary);
    const registry = new MutationJournalRegistry(join(dirname(primary), "controlled-mutation-journals.json"));
    const directories = Array.from({ length: 8 }, (_, index) => join(root(), `legacy-${index}`));
    await Promise.all(directories.map((directory) => registry.register(directory)));
    expect((await registry.directories()).sort()).toEqual(directories.sort());
    await new MutationJournal(join(directories[0]!, "mutation-journal.json")).append({ caseId: "legacy", stage: "CLEANUP_FAILED", mode: "CONTROLLED_MUTATION", targetOrigin: "https://example.test", targetIdentityFingerprint: "test" });
    await expect(new GlobalMutationLock(join(primary, "global-mutation.lock")).acquire("next")).rejects.toThrow("UNRESOLVED_PRIOR_CLEANUP");
    await writeFile(registry.path, '{"version":1,"journals":"corrupt"}');
    await expect(new GlobalMutationLock(join(primary, "global-mutation.lock")).acquire("next")).rejects.toThrow("MUTATION_REGISTRY_INVALID");
  });

  it("atomically creates one recovery key under concurrent sealing and never replaces a missing key", async () => {
    const paths = await Promise.all(Array.from({ length: 8 }, (_, index) => new MutationRecoveryVault(root()).seal({ caseId: `case-${index}`, restore: "private-sentinel" })));
    for (const [index, path] of paths.entries()) {
      expect(await new MutationRecoveryVault(root()).open(path, `case-${index}`)).toMatchObject({ restore: "private-sentinel" });
      expect(await readFile(path, "utf8")).not.toContain("private-sentinel");
    }
    await unlink(join(root(), "recovery.key"));
    await expect(new MutationRecoveryVault(root()).open(paths[0]!, "case-0")).rejects.toThrow("RECOVERY_KEY_MISSING");
    await expect(new MutationRecoveryVault(root()).seal({ caseId: "new-case" })).rejects.toThrow("RECOVERY_KEY_MISSING");
  });
});
