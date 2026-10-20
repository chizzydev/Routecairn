import { it } from "vitest";
import { evaluateHeldOutFamily } from "../helpers/heldout-evaluation-run.js";
it("measures frozen helpdesk native observations and reviewed proof before oracle reveal", () =>
  evaluateHeldOutFamily("helpdesk"));
