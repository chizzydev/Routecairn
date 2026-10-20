/** Advisory only: exact observed URLs are never substituted or enumerated. */
export function observedRoutePattern(path: string) {
  const segments = path.split("/");
  let n = 0;
  const template = segments
    .map((segment) =>
      /^(?:[0-9]{1,18}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/i.test(segment)
        ? "{observed" + ++n + "}"
        : segment
    )
    .join("/");
  return { suggestedTemplate: template, parameterCount: n, authority: "ADVISORY_ONLY_NO_ENUMERATION" as const };
}
