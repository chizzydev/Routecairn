import { appendFileSync } from "node:fs";
import { join } from "node:path";
/** Owned fixture-only phase observation; never logs payloads, credentials or target bodies. */
export async function timedAssessmentPhase<T>(root: string, phase: string, operation: () => Promise<T>): Promise<T> {
  const started = Date.now();
  let outcome = "FAILED";
  try {
    const value = await operation();
    outcome = "RETURNED";
    return value;
  } finally {
    appendFileSync(
      join(root, "NATIVE_PHASE_TIMINGS.jsonl"),
      JSON.stringify({ phase, startedAt: new Date(started).toISOString(), elapsedMs: Date.now() - started, outcome }) +
        "\n",
      { flag: "a" }
    );
  }
}
