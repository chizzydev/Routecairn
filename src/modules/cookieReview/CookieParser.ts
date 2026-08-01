export interface ParsedCookie {
  name: string;
  value: string;
  attributes: Map<string, string | true>;
}

export function parseSetCookie(header: string): ParsedCookie | undefined {
  const parts = header.split(";").map((part) => part.trim()).filter(Boolean);
  const [nameValue, ...attributeParts] = parts;

  if (!nameValue) {
    return undefined;
  }

  const separatorIndex = nameValue.indexOf("=");
  if (separatorIndex <= 0) {
    return undefined;
  }

  const attributes = new Map<string, string | true>();

  for (const attribute of attributeParts) {
    const [rawName, ...rawValue] = attribute.split("=");
    const name = rawName?.toLowerCase();

    if (!name) {
      continue;
    }

    attributes.set(name, rawValue.length > 0 ? rawValue.join("=") : true);
  }

  return {
    name: nameValue.slice(0, separatorIndex),
    value: nameValue.slice(separatorIndex + 1),
    attributes
  };
}

export function hasAttribute(cookie: ParsedCookie, name: string): boolean {
  return cookie.attributes.has(name.toLowerCase());
}

export function attributeValue(cookie: ParsedCookie, name: string): string | undefined {
  const value = cookie.attributes.get(name.toLowerCase());
  return typeof value === "string" ? value : undefined;
}
