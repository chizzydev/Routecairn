import { defineConfig } from "vitest/config";
import base from "./vitest.config.js";

// Individual shards measure partial coverage. Only the merged report enforces thresholds.
export default defineConfig({ ...base, test: { ...base.test, coverage: { ...base.test?.coverage, thresholds: {} } } });
