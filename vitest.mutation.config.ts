import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    setupFiles: ["tests/helpers/mutation-isolation.ts"],
    include: [
      "tests/unit/scope.test.ts",
      "tests/unit/target-authorization.test.ts",
      "tests/offensive/controlled-mutation-kernel.test.ts",
      "tests/offensive/recovery-binding.test.ts"
    ],
    fileParallelism: false,
    testTimeout: 30000,
    hookTimeout: 30000
  }
});
