import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts", "tests/**/*.test.tsx", "apps/**/*.test.tsx"],
    // Integration files launch real browsers, child workers, HTTP servers, and SQLite stores.
    // Running files serially prevents cross-file resource starvation and teardown races.
    fileParallelism: false,
    testTimeout: 15000
  }
});
