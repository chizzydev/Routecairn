export function isSessionRoute(pathname: string): boolean {
  const normalized = pathname.toLowerCase().replace(/\/+$/, "");
  const segments = normalized.split("/").filter(Boolean);

  if (segments.includes("session") || segments.includes("sessions") || segments.includes("csrf") || segments.includes("me")) {
    return true;
  }

  return /(?:^|\/)api\/auth\/(?:session|csrf|me)(?:$|\/)/.test(normalized);
}
