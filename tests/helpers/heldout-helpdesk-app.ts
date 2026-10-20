const visibility: Record<string, { public?: boolean; owner?: string; workspace?: string }> = {
  "helpdesk-record-0": { owner: "primary", workspace: "north" },
  "helpdesk-record-1": { public: true },
  "helpdesk-record-4": { owner: "primary", workspace: "north" }
};
export function helpdeskRead(id: string, actor: string, fixed: boolean) {
  const ticket = visibility[id];
  if (!ticket) return 404;
  if (ticket.public || ticket.owner === actor) return 200;
  return !fixed && id === "helpdesk-record-0" && actor !== "anonymous" ? 200 : 403;
}
