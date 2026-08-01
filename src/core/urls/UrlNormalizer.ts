export function normalizeUrl(input: string, base?: URL | string): string {
  const url = base ? new URL(input, base) : new URL(ensureProtocol(input));

  url.hash = "";
  url.hostname = url.hostname.toLowerCase();

  if (isDefaultPort(url)) {
    url.port = "";
  }

  url.pathname = normalizePathname(url.pathname);
  url.search = normalizeSearchParams(url.searchParams);

  return url.toString();
}

function ensureProtocol(input: string): string {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) {
    return input;
  }

  return `https://${input}`;
}

function isDefaultPort(url: URL): boolean {
  return (url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80");
}

function normalizePathname(pathname: string): string {
  if (pathname === "") {
    return "/";
  }

  return pathname.replace(/\/{2,}/g, "/");
}

function normalizeSearchParams(params: URLSearchParams): string {
  const entries = [...params.entries()].sort(([leftKey, leftValue], [rightKey, rightValue]) => {
    const keyComparison = leftKey.localeCompare(rightKey);
    return keyComparison === 0 ? leftValue.localeCompare(rightValue) : keyComparison;
  });

  const sorted = new URLSearchParams();
  for (const [key, value] of entries) {
    sorted.append(key, value);
  }

  const query = sorted.toString();
  return query ? `?${query}` : "";
}
