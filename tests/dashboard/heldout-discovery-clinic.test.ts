import { it } from "vitest";
import { evaluateHeldOutFamily } from "../helpers/heldout-evaluation-run.js";
it("measures frozen clinic native observations and reviewed proof before oracle reveal", () =>
  evaluateHeldOutFamily("clinic"));
