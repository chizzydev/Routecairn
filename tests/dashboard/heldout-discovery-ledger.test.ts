import { it } from "vitest";
import { evaluateHeldOutFamily } from "../helpers/heldout-evaluation-run.js";
it("measures frozen ledger native observations and reviewed proof before oracle reveal", () =>
  evaluateHeldOutFamily("ledger"));
