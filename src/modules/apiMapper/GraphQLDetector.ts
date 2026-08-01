export function isGraphQlEndpoint(pathname: string): boolean {
  const normalized = pathname.toLowerCase();
  return normalized === "/graphql" || normalized.endsWith("/graphql") || normalized.includes("/graphql/");
}
