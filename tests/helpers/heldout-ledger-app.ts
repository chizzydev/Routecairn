const books = new Map([
  ["ledger-record-0", { tenant: "north", visibility: "private" }],
  ["ledger-record-1", { tenant: "north", visibility: "shared" }],
  ["ledger-record-4", { tenant: "north", visibility: "private" }]
]);
export function ledgerRead(id: string, actor: string, tenant: string, fixed: boolean) {
  const book = books.get(id);
  if (!book) return 404;
  if (actor === "primary") return 200;
  if (book.visibility === "shared" && actor !== "anonymous") return 200;
  return !fixed && id === "ledger-record-0" && tenant === "south" ? 200 : 403;
}
