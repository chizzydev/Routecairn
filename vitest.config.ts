import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    setupFiles: ["tests/helpers/mutation-isolation.ts"],
    include: ["tests/**/*.test.ts", "tests/**/*.test.tsx", "apps/**/*.test.tsx"],
    // Integration files launch real browsers, child workers, HTTP servers, and SQLite stores.
    // Running files serially prevents cross-file resource starvation and teardown races.
    fileParallelism: false,
    // Browser, worker-governance, and cleanup fixtures exercise real process and
    // network teardown. Windows CI can exceed 15 seconds without a product
    // failure, especially after a long serialized run.
    testTimeout: 30000,
    hookTimeout: 30000
  }
});
