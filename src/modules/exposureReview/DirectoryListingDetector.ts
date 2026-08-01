export function isDirectoryListing(bodyPreview: string | undefined): boolean {
  if (!bodyPreview) {
    return false;
  }

  const normalized = bodyPreview.toLowerCase();
  return (
    normalized.includes("<title>index of /") ||
    normalized.includes("<h1>index of /") ||
    (normalized.includes("parent directory") && normalized.includes("<a href="))
  );
}
