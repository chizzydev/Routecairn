export function normalizeTitle(title: string | undefined): string | undefined {
  const normalized = title?.replace(/\s+/g, " ").trim();
  return normalized || undefined;
}
