const memberships = new Map([
  ["primary", new Set(["care-north", "staff"])],
  ["account_a", new Set(["care-observer"])],
  ["account_b", new Set(["care-south"])]
]);
export function clinicRead(id: string, actor: string, fixed: boolean) {
  const teams = memberships.get(actor);
  if (id === "clinic-record-1") return teams ? 200 : 401;
  const assigned = id === "clinic-record-0" ? "care-north" : "staff";
  return teams?.has(assigned) || (!fixed && id === "clinic-record-0" && teams?.has("care-observer")) ? 200 : 403;
}
