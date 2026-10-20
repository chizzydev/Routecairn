import { resourceOrganization, requireSelectedResource, type ApiContext } from "./DashboardApiContext.js";
import { HttpError } from "./DashboardHttpSupport.js";
export function requireAssuranceTarget(context: ApiContext, targetId: string, write = false) {
  resourceOrganization(context, write ? "resources.use" : "org.read");
  requireSelectedResource(context, "target", targetId, write ? "resources.use" : "org.read");
}
export function requireAssurancePolicy(context: ApiContext, id: string, write = false) {
  const org = resourceOrganization(context, write ? "resources.use" : "org.read"),
    r = context.database.db
      .prepare(
        "SELECT p.target_id FROM continuous_assurance_policies p JOIN targets t ON t.id=p.target_id WHERE p.id=? AND p.deleted_at IS NULL AND t.organization_id=?"
      )
      .get(id, org) as { target_id: string } | undefined;
  if (!r) throw new HttpError(404, "Assurance policy not found in the selected organization");
  requireAssuranceTarget(context, r.target_id, write);
}
export function requireAssuranceNotification(context: ApiContext, id: string) {
  const org = resourceOrganization(context, "resources.use"),
    r = context.database.db
      .prepare(
        "SELECT r.policy_id FROM continuous_assurance_notifications n JOIN continuous_assurance_runs r ON r.id=n.run_id JOIN continuous_assurance_policies p ON p.id=r.policy_id JOIN targets t ON t.id=p.target_id WHERE n.id=? AND t.organization_id=?"
      )
      .get(id, org) as { policy_id: string } | undefined;
  if (!r) throw new HttpError(404, "Assurance notification not found in the selected organization");
  requireAssurancePolicy(context, r.policy_id, true);
}
